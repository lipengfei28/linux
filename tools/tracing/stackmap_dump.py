#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
stackmap_dump.py - Parse and display ftrace stack_map_bin binary export.

Usage:
    # Read straight from the device over a pipe
    adb shell cat /sys/kernel/tracing/stack_map_bin | stackmap_dump.py

    # Or pull the file first and parse it
    adb pull /sys/kernel/tracing/stack_map_bin /tmp/stack_map.bin
    python3 stackmap_dump.py /tmp/stack_map.bin

    # With vmlinux when addresses already match its link-time range
    # (for example, a nokaslr core kernel; modules are not supported)
    python3 stackmap_dump.py /tmp/stack_map.bin --vmlinux vmlinux

    # JSON output for tooling
    python3 stackmap_dump.py /tmp/stack_map.bin --json
"""

import argparse
import heapq
import io
import json
import struct
import subprocess
import sys
import tempfile

MAGIC = 0x46534D42  # 'FSMB'
BIN_VERSION = 1
HEADER_SIZE = 16  # 4 x u32
ENTRY_SIZE = 16   # 4 x u32
MAX_STACK_DEPTH = 64
MAX_STACKS = 1 << 18
SYMBOL_BATCH_RECORDS = 128
SYMBOL_BATCH_ADDRESSES = 128
SYMBOL_MAX_BATCHES = 64
SYMBOL_MAX_ADDRESSES = 8192
JSON_SPOOL_MEMORY_LIMIT = 1 << 20
COPY_BUFFER_SIZE = 64 << 10

# __ftrace_trace_stack() replaces trampoline addresses with this marker
# before storing the stack, so the binary export carries it verbatim.
FTRACE_TRAMPOLINE_MARKER = 0x7fffffff
TRAMPOLINE_LABEL = '[FTRACE TRAMPOLINE]'


def detect_endianness(data):
    """Detect byte order from magic number in header."""
    if len(data) < 4:
        raise ValueError("File too small")
    magic_le = struct.unpack_from('<I', data, 0)[0]
    if magic_le == MAGIC:
        return '<'
    magic_be = struct.unpack_from('>I', data, 0)[0]
    if magic_be == MAGIC:
        return '>'
    raise ValueError(f"Bad magic: 0x{magic_le:08x} (neither LE nor BE)")


def batch_addr2line(vmlinux, addrs):
    """Resolve multiple addresses in one addr2line invocation."""
    if not addrs:
        return {}
    try:
        # Use stdin to avoid ARG_MAX with large address sets.
        stdin = '\n'.join(hex(a) for a in addrs) + '\n'
        result = subprocess.run(
            ['addr2line', '-f', '-e', vmlinux],
            input=stdin, capture_output=True, text=True, timeout=60
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("addr2line failed: timed out") from error
    except FileNotFoundError as error:
        raise RuntimeError("addr2line failed: executable not found") from error
    except OSError as error:
        detail = error.strerror or str(error)
        raise RuntimeError(f"addr2line failed: {detail}") from error

    if result.returncode:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        raise RuntimeError(f"addr2line failed: {detail}")

    lines = result.stdout.splitlines()
    expected_lines = len(addrs) * 2
    if (len(lines) != expected_lines or
            any(not line for line in lines)):
        raise RuntimeError(
            "addr2line returned malformed output: "
            f"expected {expected_lines} non-empty lines, got {len(lines)}")

    symbols = {}
    for i, addr in enumerate(addrs):
        function = lines[i * 2]
        if function != '??':
            symbols[addr] = function
    return symbols


def read_exact(stream, size, error_message):
    """Read exactly size bytes from a stream that may return short reads."""
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise ValueError(error_message)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def parse_stackmap_stream(stream):
    """Yield (stack_id, generation, ref_count, ips) tuples from a stream.

    The generation comes from the file header and is the same for every
    record in one dump. It matches the high 32 bits of the stack_cookie
    in a TRACE_STACK_ID event.
    """
    header = read_exact(stream, HEADER_SIZE, "File too small for header")
    endian = detect_endianness(header)
    header_fmt = f'{endian}IIII'
    entry_fmt = f'{endian}IIII'

    _magic, version, nr_stacks, generation = struct.unpack(header_fmt, header)
    if version != BIN_VERSION:
        raise ValueError(f"Unsupported version: {version}")
    if nr_stacks > MAX_STACKS:
        raise ValueError(
            f"Invalid stack count {nr_stacks}: maximum is {MAX_STACKS}")

    for _ in range(nr_stacks):
        entry = read_exact(stream, ENTRY_SIZE,
                           "Truncated stack entry header")
        stack_id, nr, ref_count, _reserved = struct.unpack(entry_fmt, entry)
        if nr == 0:
            raise ValueError("Invalid stack depth 0: minimum is 1")
        if nr > MAX_STACK_DEPTH:
            raise ValueError(
                f"Invalid stack depth {nr}: maximum is {MAX_STACK_DEPTH}")

        ips_data = read_exact(
            stream, nr * 8,
            f"Truncated stack IP data for stack_id {stack_id}")
        ips = struct.unpack(f'{endian}{nr}Q', ips_data)
        yield stack_id, generation, ref_count, list(ips)

    if stream.read(1):
        raise ValueError(f"Trailing data after {nr_stacks} stack records")


def parse_stackmap_bin(data):
    """Parse in-memory binary data using the streaming parser."""
    return list(parse_stackmap_stream(io.BytesIO(data)))


def non_negative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("--top must be non-negative")
    return number


def select_top(records, limit):
    """Select the largest ref_counts stably using O(limit) space."""
    heap = []
    for order, record in enumerate(records):
        # record is (stack_id, generation, ref_count, ips).
        item = (record[2], -order, order, record)
        if len(heap) < limit:
            heapq.heappush(heap, item)
        elif item[:2] > heap[0][:2]:
            heapq.heapreplace(heap, item)

    heap.sort(key=lambda item: (-item[0], item[2]))
    return [item[3] for item in heap]


def iter_symbol_batches(records):
    """Group records without exceeding the unique-address limit."""
    batch = []
    addresses = set()
    for record in records:
        _stack_id, _generation, _ref_count, ips = record
        record_addresses = {
            ip for ip in ips if ip != FTRACE_TRAMPOLINE_MARKER
        }
        if (batch and
                (len(batch) >= SYMBOL_BATCH_RECORDS or
                 len(addresses | record_addresses) >
                 SYMBOL_BATCH_ADDRESSES)):
            yield batch, addresses
            batch.clear()
            addresses.clear()
        batch.append(record)
        addresses.update(record_addresses)
    if batch:
        yield batch, addresses


class RecordRenderer:
    """Write records incrementally without changing text or JSON formats."""

    def __init__(self, output, json_output, include_symbols):
        self.output = output
        self.json_output = json_output
        self.include_symbols = include_symbols
        self.count = 0

    @staticmethod
    def terminal_safe(text):
        """Escape terminal controls while preserving printable Unicode."""
        escaped = []
        for character in text:
            codepoint = ord(character)
            if character.isprintable():
                escaped.append(character)
            elif codepoint <= 0xff:
                escaped.append(f'\\x{codepoint:02x}')
            elif codepoint <= 0xffff:
                escaped.append(f'\\u{codepoint:04x}')
            else:
                escaped.append(f'\\U{codepoint:08x}')
        return ''.join(escaped)

    @staticmethod
    def render_ip(ip, symbols):
        if ip == FTRACE_TRAMPOLINE_MARKER:
            return TRAMPOLINE_LABEL
        return symbols.get(ip, f'0x{ip:x}')

    def emit(self, record, symbols):
        stack_id, generation, ref_count, ips = record
        if self.json_output:
            entry = {
                'stack_id': stack_id,
                'generation': generation,
                'ref_count': ref_count,
                'ips': [f'0x{ip:x}' for ip in ips]
            }
            if self.include_symbols:
                entry['symbols'] = [self.render_ip(ip, symbols)
                                    for ip in ips]
            encoded = json.dumps(entry, indent=2)
            indented = '\n'.join(f'  {line}' for line in encoded.splitlines())
            if self.count == 0:
                self.output.write('[\n')
            else:
                self.output.write(',\n')
            self.output.write(indented)
        else:
            self.output.write(
                f"stack_id {stack_id} gen {generation} "
                f"[ref {ref_count}, depth {len(ips)}]\n")
            for index, ip in enumerate(ips):
                if ip == FTRACE_TRAMPOLINE_MARKER:
                    self.output.write(
                        f"  [{index}] {TRAMPOLINE_LABEL}\n")
                    continue
                symbol = symbols.get(ip, '')
                if symbol:
                    symbol = f' {self.terminal_safe(symbol)}'
                self.output.write(f"  [{index}] 0x{ip:x}{symbol}\n")
            self.output.write('\n')
        self.count += 1

    def finish(self):
        if not self.json_output:
            return
        if self.count:
            self.output.write('\n]\n')
        else:
            self.output.write('[]\n')


def render_records(records, args, output):
    renderer = RecordRenderer(output, args.json, bool(args.vmlinux))
    if args.vmlinux:
        batch_count = 0
        address_count = 0
        for batch, addresses in iter_symbol_batches(records):
            batch_count += 1
            address_count += len(addresses)
            if (batch_count > SYMBOL_MAX_BATCHES or
                    address_count > SYMBOL_MAX_ADDRESSES):
                raise RuntimeError(
                    "symbolization work limit exceeded: "
                    f"maximum {SYMBOL_MAX_BATCHES} batches and "
                    f"{SYMBOL_MAX_ADDRESSES} addresses")
            symbols = batch_addr2line(args.vmlinux, list(addresses))
            for record in batch:
                renderer.emit(record, symbols)
    else:
        for record in records:
            renderer.emit(record, {})
    renderer.finish()
    return renderer.count


def main(argv=None, input_file=None, output=None, error=None):
    parser = argparse.ArgumentParser(description='Parse ftrace stack_map_bin')
    parser.add_argument('file', nargs='?', default='-',
                        help="Path to stack_map_bin file, or '-' for stdin "
                             "(the default)")
    parser.add_argument(
        '--vmlinux',
        help=('Path to vmlinux for symbol resolution; addresses must already '
              'match vmlinux (for example, nokaslr). KASLR runtime addresses '
              'and module addresses are not supported. Symbolization is '
              'limited to 8192 addresses in 64 batches'))
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--top', type=non_negative_int, default=0,
                        help='Show only top N stacks by ref_count; 0 is unlimited')
    args = parser.parse_args(argv)

    output = output if output is not None else sys.stdout
    error = error if error is not None else sys.stderr
    stream = input_file
    close_stream = False

    try:
        # stdin accepts a stack_map_bin stream directly from a pipe.
        if stream is None:
            if args.file == '-':
                stream = sys.stdin.buffer
            else:
                stream = open(args.file, 'rb')
                close_stream = True

        records = parse_stackmap_stream(stream)
        if args.top:
            records = select_top(records, args.top)
        if args.json:
            with tempfile.SpooledTemporaryFile(
                    max_size=JSON_SPOOL_MEMORY_LIMIT, mode='w+',
                    encoding='utf-8') as staged_output:
                count = render_records(records, args, staged_output)
                staged_output.seek(0)
                while True:
                    chunk = staged_output.read(COPY_BUFFER_SIZE)
                    if not chunk:
                        break
                    output.write(chunk)
        else:
            count = render_records(records, args, output)
    except (ValueError, OSError, RuntimeError) as exception:
        print(f"error: {exception}", file=error)
        return 1
    finally:
        if close_stream:
            stream.close()

    print(f"Total: {count} stack records", file=error)
    return 0


if __name__ == '__main__':
    sys.exit(main())
