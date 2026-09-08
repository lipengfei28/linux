#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "stackmap_dump.py"
SPEC = importlib.util.spec_from_file_location("stackmap_dump", SCRIPT)
stackmap_dump = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stackmap_dump)

MAGIC = stackmap_dump.MAGIC
VERSION = stackmap_dump.BIN_VERSION


def image(endian="<", version=VERSION, generation=1, entries=()):
    data = bytearray(struct.pack(f"{endian}IIII", stackmap_dump.MAGIC,
                                 version, len(entries), generation))
    for stack_id, ref_count, ips in entries:
        data += struct.pack(f"{endian}IIII", stack_id, len(ips),
                            ref_count, 0)
        data += struct.pack(f"{endian}{len(ips)}Q", *ips)
    return bytes(data)


class ShortReadInput(io.BytesIO):
    def read(self, size=-1):
        if size < 0:
            raise AssertionError("unbounded read() is not allowed")
        if size > stackmap_dump.MAX_STACK_DEPTH * 8:
            raise AssertionError("read() exceeds one stack")
        return super().read(min(size, 3))


class StreamingGuardInput(io.BytesIO):
    def __init__(self, data, first_record_end, output):
        super().__init__(data)
        self.first_record_end = first_record_end
        self.output = output

    def read(self, size=-1):
        if (self.tell() >= self.first_record_end and
                "stack_id 1" not in self.output.getvalue()):
            raise AssertionError("next record read before current output")
        return super().read(size)


class TrackedRecord:
    live_count = 0
    max_live_count = 0

    def __init__(self, stack_id, ip=None):
        self.stack_id = stack_id
        self.ip = 0x1000 + stack_id if ip is None else ip
        type(self).live_count += 1
        type(self).max_live_count = max(type(self).max_live_count,
                                        type(self).live_count)

    def __iter__(self):
        # (stack_id, generation, ref_count, ips)
        return iter((self.stack_id, 1, 1, [self.ip]))

    def __del__(self):
        type(self).live_count -= 1


class StackmapParserTest(unittest.TestCase):
    def test_little_endian_entry(self):
        raw = image(entries=[(7, 3, [0x1234, 0x7fffffff])])
        self.assertEqual(list(stackmap_dump.parse_stackmap_bin(raw)),
                         [(7, 1, 3, [0x1234, 0x7fffffff])])

    def test_big_endian_entry(self):
        raw = image(">", entries=[(9, 2, [0xabcdef])])
        self.assertEqual(list(stackmap_dump.parse_stackmap_bin(raw)),
                         [(9, 1, 2, [0xabcdef])])

    def test_bad_magic(self):
        with self.assertRaisesRegex(ValueError, "Bad magic"):
            list(stackmap_dump.parse_stackmap_bin(b"BAD!" + bytes(12)))

    def test_unknown_version(self):
        with self.assertRaisesRegex(ValueError, "Unsupported version"):
            list(stackmap_dump.parse_stackmap_bin(image(version=2)))

    def test_truncated_header(self):
        with self.assertRaisesRegex(ValueError, "too small for header"):
            list(stackmap_dump.parse_stackmap_bin(bytes(15)))

    def test_truncated_entry_header(self):
        raw = struct.pack("<IIII", MAGIC, VERSION, 1, 0)
        with self.assertRaisesRegex(ValueError, "Truncated stack entry header"):
            list(stackmap_dump.parse_stackmap_bin(raw))

    def test_truncated_ip_data(self):
        raw = image(entries=[(1, 1, [0x1234])])[:-1]
        with self.assertRaisesRegex(ValueError, "Truncated stack IP data"):
            list(stackmap_dump.parse_stackmap_bin(raw))

    def test_rejects_records_beyond_header_count(self):
        raw = image(entries=[(1, 1, [0x1234])])
        raw = bytearray(raw)
        struct.pack_into("<I", raw, 8, 0)
        with self.assertRaisesRegex(ValueError, "Trailing data"):
            stackmap_dump.parse_stackmap_bin(raw)

    def test_cli_reports_malformed_input_without_traceback(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "-"],
                                input=b"bad", capture_output=True)
        stderr = result.stderr.decode()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error: File too small for header", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_cli_reports_missing_file_without_traceback(self):
        missing = SCRIPT.parent / "does-not-exist.stackmap"
        result = subprocess.run([sys.executable, str(SCRIPT), str(missing)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_reports_addr2line_failure(self):
        raw = image(entries=[(1, 2, [0x1234])])
        with tempfile.TemporaryDirectory() as temp_dir:
            addr2line = Path(temp_dir) / "addr2line"
            addr2line.write_text(
                "#!/bin/sh\necho controlled addr2line failure >&2\nexit 23\n",
                encoding="utf-8")
            addr2line.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = temp_dir
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "-", "--vmlinux", "vmlinux"],
                input=raw, capture_output=True, env=env)
        stderr = result.stderr.decode()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "error: addr2line failed: controlled addr2line failure", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_cli_reports_truncated_addr2line_output(self):
        raw = image(entries=[(1, 2, [0x1234])])
        with tempfile.TemporaryDirectory() as temp_dir:
            addr2line = Path(temp_dir) / "addr2line"
            addr2line.write_text(
                "#!/bin/sh\nprintf 'resolved_function\\n'\n",
                encoding="utf-8")
            addr2line.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = temp_dir
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "-", "--vmlinux", "vmlinux"],
                input=raw, capture_output=True, env=env)
        stderr = result.stderr.decode()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error: addr2line returned malformed output", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_cli_accepts_unresolved_addr2line_output(self):
        raw = image(entries=[(1, 2, [0x1234])])
        with tempfile.TemporaryDirectory() as temp_dir:
            addr2line = Path(temp_dir) / "addr2line"
            addr2line.write_text(
                "#!/bin/sh\nprintf '??\\n??:0\\n'\n",
                encoding="utf-8")
            addr2line.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = temp_dir
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "-", "--vmlinux", "vmlinux"],
                input=raw, capture_output=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"[0] 0x1234", result.stdout)

    def test_cli_rejects_trailing_data(self):
        raw = image(entries=[(1, 1, [0x1234])]) + b"junk"
        result = subprocess.run([sys.executable, str(SCRIPT), "-"],
                                input=raw, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"error: Trailing data", result.stderr)

    def test_cli_accepts_valid_input(self):
        raw = image(entries=[(1, 2, [0x1234])])
        result = subprocess.run([sys.executable, str(SCRIPT), "-", "--json"],
                                input=raw, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'"stack_id": 1', result.stdout)

    def test_stream_parser_handles_short_reads(self):
        raw = image(entries=[(7, 3, [0x1234, 0x5678])])
        self.assertEqual(list(stackmap_dump.parse_stackmap_stream(
            ShortReadInput(raw))), [(7, 1, 3, [0x1234, 0x5678])])

    def test_rejects_stack_depth_above_limit(self):
        raw = (struct.pack("<IIII", MAGIC, VERSION, 1, 0) +
               struct.pack("<IIII", 7, 65, 1, 0))
        with self.assertRaisesRegex(ValueError, "stack depth.*64"):
            list(stackmap_dump.parse_stackmap_stream(io.BytesIO(raw)))

    def test_accepts_stack_depth_at_limit(self):
        ips = list(range(stackmap_dump.MAX_STACK_DEPTH))
        raw = image(entries=[(7, 1, ips)])
        self.assertEqual(stackmap_dump.parse_stackmap_bin(raw),
                         [(7, 1, 1, ips)])

    def test_rejects_stack_count_above_limit(self):
        raw = struct.pack("<IIII", MAGIC, VERSION,
                          (1 << 18) + 1, 0)
        with self.assertRaisesRegex(ValueError, "stack count.*262144"):
            list(stackmap_dump.parse_stackmap_stream(io.BytesIO(raw)))

    def test_accepts_stack_count_at_limit(self):
        raw = struct.pack("<IIII", MAGIC, VERSION, 1 << 18, 0)
        with self.assertRaisesRegex(ValueError,
                                    "Truncated stack entry header"):
            list(stackmap_dump.parse_stackmap_stream(io.BytesIO(raw)))

    def test_cli_rejects_negative_top(self):
        raw = image(entries=[(1, 2, [0x1234])])
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "-", "--top", "-1"],
            input=raw, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"--top must be non-negative", result.stderr)

    def test_cli_top_zero_remains_unlimited(self):
        raw = image(entries=[(1, 2, [0x1000]), (2, 1, [0x2000])])
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "-", "--json", "--top", "0"],
            input=raw, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual([entry["stack_id"] for entry in
                          json.loads(result.stdout)], [1, 2])

    def test_cli_top_n_is_descending_and_stable_for_ties(self):
        raw = image(entries=[(1, 3, [0x1000]),
                             (2, 9, [0x2000]),
                             (3, 9, [0x3000]),
                             (4, 9, [0x4000]),
                             (5, 1, [0x5000])])
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "-", "--json", "--top", "2"],
            input=raw, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual([(entry["stack_id"], entry["ref_count"])
                          for entry in json.loads(result.stdout)],
                         [(2, 9), (3, 9)])

    def test_rejects_zero_stack_depth(self):
        raw = (struct.pack("<IIII", MAGIC, VERSION, 1, 0) +
               struct.pack("<IIII", 7, 0, 1, 0))
        with self.assertRaisesRegex(ValueError, "stack depth.*minimum is 1"):
            list(stackmap_dump.parse_stackmap_stream(io.BytesIO(raw)))

    def test_cli_empty_text_output_format(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "-"],
                                input=image(), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"Total: 0 stack records\n")

    def test_cli_empty_json_output_format(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "-", "--json"],
                                input=image(), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"[]\n")
        self.assertEqual(result.stderr, b"Total: 0 stack records\n")

    def test_cli_multi_record_text_output_format(self):
        raw = image(entries=[(7, 3, [0x1234,
                                      stackmap_dump.FTRACE_TRAMPOLINE_MARKER]),
                             (9, 1, [0xabcd])])
        result = subprocess.run([sys.executable, str(SCRIPT), "-"],
                                input=raw, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            result.stdout.decode(),
            "stack_id 7 gen 1 [ref 3, depth 2]\n"
            "  [0] 0x1234\n"
            "  [1] [FTRACE TRAMPOLINE]\n\n"
            "stack_id 9 gen 1 [ref 1, depth 1]\n"
            "  [0] 0xabcd\n\n")
        self.assertEqual(result.stderr, b"Total: 2 stack records\n")

    def test_cli_multi_record_json_output_format(self):
        raw = image(entries=[(7, 3, [0x1234]), (9, 1, [0xabcd])])
        result = subprocess.run([sys.executable, str(SCRIPT), "-", "--json"],
                                input=raw, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        expected = json.dumps([
            {"stack_id": 7, "generation": 1, "ref_count": 3,
             "ips": ["0x1234"]},
            {"stack_id": 9, "generation": 1, "ref_count": 1,
             "ips": ["0xabcd"]},
        ], indent=2) + "\n"
        self.assertEqual(result.stdout.decode(), expected)
        self.assertEqual(result.stderr, b"Total: 2 stack records\n")

    def test_vmlinux_text_output_format(self):
        raw = image(entries=[(7, 3, [
            0x1000, 0x2000, stackmap_dump.FTRACE_TRAMPOLINE_MARKER])])
        output = io.StringIO()
        error = io.StringIO()
        with mock.patch.object(stackmap_dump, "batch_addr2line",
                               return_value={0x1000: "resolved"}):
            result = stackmap_dump.main(
                ["--vmlinux", "vmlinux"], input_file=io.BytesIO(raw),
                output=output, error=error)

        self.assertEqual(result, 0, error.getvalue())
        self.assertEqual(
            output.getvalue(),
            "stack_id 7 gen 1 [ref 3, depth 3]\n"
            "  [0] 0x1000 resolved\n"
            "  [1] 0x2000\n"
            "  [2] [FTRACE TRAMPOLINE]\n\n")
        self.assertEqual(error.getvalue(), "Total: 1 stack records\n")

    def test_vmlinux_json_output_format(self):
        raw = image(entries=[(7, 3, [
            0x1000, 0x2000, stackmap_dump.FTRACE_TRAMPOLINE_MARKER])])
        output = io.StringIO()
        error = io.StringIO()
        with mock.patch.object(stackmap_dump, "batch_addr2line",
                               return_value={0x1000: "resolved"}):
            result = stackmap_dump.main(
                ["--json", "--vmlinux", "vmlinux"],
                input_file=io.BytesIO(raw), output=output, error=error)

        expected = json.dumps([{
            "stack_id": 7,
            "generation": 1,
            "ref_count": 3,
            "ips": ["0x1000", "0x2000", "0x7fffffff"],
            "symbols": ["resolved", "0x2000", "[FTRACE TRAMPOLINE]"],
        }], indent=2) + "\n"
        self.assertEqual(result, 0, error.getvalue())
        self.assertEqual(output.getvalue(), expected)
        self.assertEqual(error.getvalue(), "Total: 1 stack records\n")

    def test_json_malformed_later_record_leaves_stdout_empty(self):
        raw = image(entries=[(1, 2, [0x1000]), (2, 1, [0x2000])])[:-1]
        output = io.StringIO()
        error = io.StringIO()

        result = stackmap_dump.main(["--json"], input_file=io.BytesIO(raw),
                                    output=output, error=error)

        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("error: Truncated stack IP data", error.getvalue())

    def test_json_later_addr2line_failure_leaves_stdout_empty(self):
        raw = image(entries=[(stack_id, 1, [0x1000 + stack_id])
                             for stack_id in range(129)])
        output = io.StringIO()
        error = io.StringIO()
        with mock.patch.object(
                stackmap_dump, "batch_addr2line",
                side_effect=[{}, RuntimeError("addr2line failed: later batch")]):
            result = stackmap_dump.main(
                ["--json", "--vmlinux", "vmlinux"],
                input_file=io.BytesIO(raw), output=output, error=error)

        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(error.getvalue(),
                         "error: addr2line failed: later batch\n")

    def test_text_streams_before_reading_the_next_record(self):
        raw = image(entries=[(1, 2, [0x1000]), (2, 1, [0x2000])])
        output = io.StringIO()
        first_record_end = (stackmap_dump.HEADER_SIZE +
                            stackmap_dump.ENTRY_SIZE + 8)
        input_file = StreamingGuardInput(raw, first_record_end, output)
        error = io.StringIO()

        result = stackmap_dump.main([], input_file=input_file,
                                    output=output, error=error)

        self.assertEqual(result, 0, error.getvalue())
        self.assertIn("stack_id 2", output.getvalue())

    def test_json_input_uses_only_bounded_reads(self):
        raw = image(entries=[(1, 2, [0x1000]), (2, 1, [0x2000])])
        output = io.StringIO()
        error = io.StringIO()

        result = stackmap_dump.main(
            ["--json"], input_file=ShortReadInput(raw),
            output=output, error=error)

        self.assertEqual(result, 0, error.getvalue())
        self.assertEqual([entry["stack_id"]
                          for entry in json.loads(output.getvalue())], [1, 2])

    def test_json_does_not_materialize_all_records(self):
        TrackedRecord.live_count = 0
        TrackedRecord.max_live_count = 0

        def records(_stream):
            for stack_id in range(1000):
                yield TrackedRecord(stack_id)

        output = io.StringIO()
        with mock.patch.object(stackmap_dump, "parse_stackmap_stream",
                               side_effect=records):
            result = stackmap_dump.main(
                ["--json"], input_file=io.BytesIO(), output=output,
                error=io.StringIO())

        self.assertEqual(result, 0)
        self.assertLessEqual(TrackedRecord.max_live_count, 2)
        self.assertEqual(len(json.loads(output.getvalue())), 1000)

    def test_vmlinux_symbolization_limits_unique_addresses_per_call(self):
        raw = image(entries=[
            (stack_id, 1, [0x10000 + stack_id * 4 + frame
                           for frame in range(4)])
            for stack_id in range(50)])
        calls = []

        def resolve(_vmlinux, addrs):
            calls.append(list(addrs))
            return {}

        with mock.patch.object(stackmap_dump, "batch_addr2line",
                               side_effect=resolve):
            result = stackmap_dump.main(
                ["--vmlinux", "vmlinux"], input_file=io.BytesIO(raw),
                output=io.StringIO(), error=io.StringIO())

        self.assertEqual(result, 0)
        self.assertLessEqual(max(map(len, calls)), 128)
        self.assertEqual(stackmap_dump.SYMBOL_BATCH_ADDRESSES, 128)

    def test_vmlinux_duplicate_addresses_keep_record_batches_bounded(self):
        TrackedRecord.live_count = 0
        TrackedRecord.max_live_count = 0

        def records(_stream):
            for stack_id in range(1000):
                yield TrackedRecord(stack_id, ip=0x1000)

        with mock.patch.object(stackmap_dump, "parse_stackmap_stream",
                               side_effect=records), mock.patch.object(
                                   stackmap_dump, "batch_addr2line",
                                   return_value={}):
            result = stackmap_dump.main(
                ["--json", "--vmlinux", "vmlinux"],
                input_file=io.BytesIO(), output=io.StringIO(),
                error=io.StringIO())

        self.assertEqual(result, 0)
        self.assertLessEqual(TrackedRecord.max_live_count, 130)

    def test_vmlinux_rejects_aggregate_symbolization_work_above_limit(self):
        raw = image(entries=[(stack_id, 1, [0x10000 + stack_id])
                             for stack_id in range(8193)])
        error = io.StringIO()
        with mock.patch.object(stackmap_dump, "batch_addr2line",
                               return_value={}):
            result = stackmap_dump.main(
                ["--vmlinux", "vmlinux"], input_file=io.BytesIO(raw),
                output=io.StringIO(), error=error)

        self.assertNotEqual(result, 0)
        self.assertIn("symbolization work limit", error.getvalue())

    def test_vmlinux_text_output_escapes_terminal_control_characters(self):
        raw = image(entries=[(7, 3, [0x1000])])
        output = io.StringIO()
        with mock.patch.object(
                stackmap_dump, "batch_addr2line",
                return_value={0x1000: "name\x1b[2J\rspoof\tend"}):
            result = stackmap_dump.main(
                ["--vmlinux", "vmlinux"], input_file=io.BytesIO(raw),
                output=output, error=io.StringIO())

        self.assertEqual(result, 0)
        self.assertIn(r"name\x1b[2J\x0dspoof\x09end", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())
        self.assertNotIn("\r", output.getvalue())
        self.assertNotIn("\t", output.getvalue())

    def test_help_states_vmlinux_kaslr_and_work_limits(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("KASLR", result.stdout)
        self.assertIn("module", result.stdout)
        self.assertIn("8192", result.stdout)
        self.assertIn("64 batches", result.stdout)


if __name__ == "__main__":
    unittest.main()
