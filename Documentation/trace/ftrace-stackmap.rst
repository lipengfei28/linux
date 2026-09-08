.. SPDX-License-Identifier: GPL-2.0

======================
Ftrace Stack Map
======================

:Author: Pengfei Li <lipengfei28@xiaomi.com>

Overview
========

The ftrace stack map provides stack trace deduplication for the ftrace
ring buffer. When enabled, instead of a full kernel stack trace event
(typically 80-160 bytes) for every recorded stack, ftrace writes a
fixed-size event of 20-24 bytes, depending on the architecture, that holds
a 64-bit cookie: the map generation in the high 32 bits and the slot index
in the low 32. The full stacks are maintained in a
separate hash table and exported via tracefs for userspace to resolve.

This is inspired by eBPF's ``BPF_MAP_TYPE_STACK_TRACE`` but integrated
into ftrace's infrastructure, requiring no userspace daemon.

Configuration
=============

Enable ``CONFIG_FTRACE_STACKMAP=y`` in the kernel config.

Kernel command line parameters:

- ``ftrace_stackmap_bits=N`` - Set map capacity to 2^N stack records
  (default: 14 → 16384 records; valid range: 10-18). Values outside the
  range are clamped with a warning. The upper bound limits the memory
  used by the map; the sizes are given below.

The map is allocated when the ``stackmap`` option is first enabled; if
the allocation fails, enabling the option fails with ``-ENOMEM``. The map
stays allocated while the option is turned off, so a trace can still be
resolved, until ``free`` is written to ``stack_map``. On a 64-bit kernel,
the element pool takes about 8 MiB
at the default ``bits=14`` and 130 MiB at ``bits=18``. The hash table adds
0.5 MiB and 8 MiB, plus small per-CPU counters.

Usage
=====

Enable stack deduplication for event stacks::

    echo 1 > /sys/kernel/tracing/options/stackmap
    echo 1 > /sys/kernel/tracing/options/stacktrace
    echo 1 > /sys/kernel/tracing/events/sched/sched_switch/enable

The function tracer records stacks through its own option instead of
``stacktrace``::

    echo vfs_read > /sys/kernel/tracing/set_ftrace_filter
    echo function > /sys/kernel/tracing/current_tracer
    echo 1 > /sys/kernel/tracing/options/func_stack_trace

The trace output will show ``<stack_id N gen G>`` instead of full stack
traces, where N is the slot and G the map generation::

    sh-1234 [006] d.h.. 123.456789: <stack_id 42 gen 1>

Stacks are not always replaced. A stack deeper than 64 frames, a stack
recorded before the map is published or during a reset, a stack that
another context is inserting at the same moment, and a stack the map
cannot store (element pool full, probe limit, or ring-buffer
reservation failure) fall back to a regular full stack trace. A trace
can therefore contain both ``<stack_id N gen G>`` records and full
``<stack trace>`` records.

To view the actual stacks::

    cat /sys/kernel/tracing/stack_map

Output format::

    stack_id 42 gen 1 [ref 1337, depth 8]
      [0] schedule+0x48/0xc0
      [1] schedule_timeout+0x1c/0x30
      ...

``ref`` is the number of times the stack was recorded through this
record since the last reset. It is never decremented, including when
events leave the ring buffer, and it saturates at ``INT_MAX``.

To view statistics::

    cat /sys/kernel/tracing/stack_map_stat

Output::

    entries:      2500 / 16384
    table_size:   32768
    successes:    148923
    drops:        0
    success_rate: 100%

To reset the stack map::

    echo 0 > /sys/kernel/tracing/stack_map

To release the map once the option is off::

    echo 0 > /sys/kernel/tracing/options/stackmap
    echo free > /sys/kernel/tracing/stack_map

``free`` fails with ``-EBUSY`` while the option is enabled. A stackmap
file opened before the ``free`` keeps reading the old map, and ``free``
blocks until all such files are closed, then releases the memory; a
process that still has one of them open itself must close it first. If
``free`` is written through a file that is itself open for reading, that
file is not waited for: ``free`` returns and the memory is released when
that file is closed. Like a
reset, ``free`` leaves cookies in the trace buffer that no longer resolve
against a newly opened file. The next map continues the generation, so
those cookies do not match it.

Reset clears the map and its statistics. The trace buffer is left
untouched and tracing does not have to be stopped. As a result a trace
can still contain cookies from before a reset. Reset bumps the map
generation, so such a cookie no longer matches the map and a consumer can
reject it. An id is valid only within its own generation. The generation
in a cookie is 32 bits. It only has to tell resets apart, and wraps after
2^32 resets and frees.

To resolve a trace that spans resets, dump ``stack_map_bin`` before each
reset. Each ``<stack_id N gen G>`` record names its generation and each dump
header names the
generation it covers, so records can be read against the right dump
afterwards. A dump only covers stacks inserted before it was opened. A
record whose stack was first inserted after the dump but before the
reset cannot be resolved. Stop tracing across the dump and the reset if
every record must resolve.

Boot-time activation
====================

The stackmap option can be enabled from the kernel command line::

    trace_options=stackmap,stacktrace

The map is then allocated when tracefs initializes. Stacks recorded before
that use the regular full-stack fallback. If the allocation fails, the
option is turned off and a warning is printed.

Tracefs Nodes
=============

``stack_map`` is the required resolver and reset node. The
``stack_map_stat`` and ``stack_map_bin`` files are auxiliary observability nodes.
If tracefs cannot create either auxiliary node, it emits a warning but does
not disable stackmap; ``stack_map`` remains available to resolve and reset the
map. The absence of an auxiliary node therefore does not disable stackmap.

The files are owned by root and not world-readable (``stack_map``: 0640;
``stack_map_stat`` and ``stack_map_bin``: 0440).

``stack_map``, ``stack_map_stat`` and ``stack_map_bin`` all use
``tracing_check_open_get_tr()`` in ``open()``. It rejects access under
``LOCKDOWN_TRACEFS`` or when the tracing subsystem is globally disabled
(``tracing_disabled``), and pins the owning trace array until release. The
check applies at open time, so raising lockdown after tracefs has been
populated still blocks later opens, including the ``stack_map`` reset write.

``stack_map_bin`` is additionally a raw tracing ABI: its payload contains
raw kernel instruction pointers after ``trace_adjust_address()`` and
does not apply ``kptr_restrict`` sanitization. VFS permissions restrict
the file to mode 0440.
This follows the existing trust boundary for raw tracing interfaces such as
``trace_pipe_raw`` and ``available_filter_functions_addrs``.

The files exist before the map is allocated. Each open file reads the
map that existed when it was opened. Opened without a map, ``stack_map``
is empty, ``stack_map_stat`` reports that no map is allocated, and
``stack_map_bin`` holds only a header with ``nr_stacks`` and
``generation`` both 0.

``stack_map``
    Text export of all deduplicated stacks with symbol resolution.
    Writing ``0`` or ``reset`` clears all entries; writing ``free``
    releases the map.

``stack_map_stat``
    ``entries`` is the number of element records claimed since the last reset.
    Other statistics are table_size, successes (map operations that returned a
    stack ID), drops (map capacity or probe-limit failures), and success_rate.
    A stack has at most one record per generation, so entries counts
    distinct stacks, plus records whose insertion is still in progress.
    The success_rate is ``successes / (successes + drops)``; it does not include
    bypasses that never call the map, such as deep stacks, reset windows, ring
    buffer reservation failures, or a stack that meets an insert of the same
    hash still in progress. The field is always present and reports
    0% when no success or drop has occurred. Drops accumulate once the
    element pool is exhausted. A new stack then no longer claims a table
    slot; only an insert that races for the last element can leave a slot
    claimed but empty. Reset clears such slots.

``stack_map_bin``
    Binary export for efficient userspace consumption. Format:

    - Header (16 bytes): magic(u32) + version(u32) + nr_stacks(u32) +
      generation(u32)
    - Per stack: stack_id(u32) + nr(u32) + ref_count(u32) + reserved(u32) + ips(u64 × nr)

    ``ref_count`` has the same meaning as ``ref`` in ``stack_map``.
    All fields are written in the kernel's native byte order.
    Userspace tools detect endianness by reading the magic value.
    Magic: ``0x46534D42`` ('FSMB'), Version: 1.

    ``generation`` is the map generation this dump was taken from, and
    matches the high 32 bits of the cookie in a ``<stack_id N gen G>``
    record. All stacks in one dump share it, so the per-stack
    ``stack_id`` stays 32-bit.

    Trampoline frames are exported as the sentinel value
    ``0x7fffffff`` (FTRACE_TRAMPOLINE_MARKER); all other addresses are
    passed through ``trace_adjust_address()`` so they match the
    ``stack_map`` text output's address-adjustment rules. Note this is
    the same adjustment ftrace applies to its own trace output (mainly
    relevant for persistent / last-boot buffers), not a general KASLR
    un-offset. The dump tool's ``--vmlinux`` mode is therefore valid only
    when core-kernel addresses already match that vmlinux, for example
    with ``nokaslr``. It does not resolve KASLR-slid or module addresses.

    The table is streamed rather than copied into a private payload
    buffer. At ``open()``, the kernel records the currently populated
    slot numbers in a bitmap and sets ``nr_stacks`` to that exact count.
    The bitmap is at most 64 KiB at the largest supported table size;
    stack payloads remain in the map and are emitted through
    ``seq_file``. Entries inserted after ``open()`` are not part of that
    fd's record set, so exactly ``nr_stacks`` records follow the header.

    Because the reader lock is released between ``read()`` calls, a
    reset can land part-way through reading the file. That would
    otherwise splice two generations of the map into one stream, which a
    binary consumer could not detect, so the export tracks a generation
    counter. After any data already buffered by the current ``seq_file``
    pass has been consumed, the next pass that needs to resume iteration
    detects the reset and fails with ``-ESTALE``. It never
    appends records from the new generation. A ``free`` does not
    affect an open file. ``ESTALE`` is used instead of ``EAGAIN``
    because ``seq_file`` treats ``EAGAIN`` as an internal retry during
    seeks. Reopen the file and read it again.

    A reader that has already reached the end of the export is not
    affected: the final ``read()`` returns 0 as usual even if a reset
    happened, because no data remains that could come from a different
    generation.

The text export has no generation check. It serializes each ``seq_file``
pass against reset through the same rwsem, but a ``stack_map`` reader that
spans a reset can still produce text from two generations across separate
``read()`` calls. The ``gen`` field on each record makes that visible, but
the read is not failed. Symbolized text is meant to be read rather than
parsed as a record stream, so this is deliberate. A
consumer that needs a consistent snapshot should either read ``stack_map``
completely within a window where no reset happens, or use
``stack_map_bin``, which does detect the change.

Design
======

The stack map is modeled after ``tracing_map.c`` (used by hist triggers),
using a lock-free design based on Dr. Cliff Click's non-blocking hash table
algorithm:

- **Lookup/Insert**: Lock-free via ``cmpxchg``, safe in NMI/IRQ/any context
- **Memory**: Pre-allocated element pool, zero allocation on the hot path
  (no GFP_ATOMIC failures under memory pressure)
- **Collision**: Linear probing with a 2x over-provisioned table; probe
  length is bounded so worst-case insert/lookup is O(1)
- **Scope**: Currently supports the global trace instance
- **Hash**: 32-bit jhash with a per-instance random seed; full ``memcmp``
  confirms matches

A stack has at most one record per generation. When a lookup reaches a
slot with the same hash whose element is not yet published, another
context is inserting that stack, or another stack with the same hash.
The lookup does not wait, because in NMI context it may have interrupted
that insert, and it does not add a second record. That one event is
recorded as a full stack trace instead. A context that loses the
``cmpxchg`` for a free slot re-reads the slot for the same reason.

Differences from ``tracing_map``
--------------------------------

The table, the element pool and the probing follow ``tracing_map``. The
stack map differs where its callers differ:

- ``tracing_map_clear()`` requires its caller to keep inserts out. The
  stack map does this itself: new callers are kept out and admitted ones
  are drained with RCU before the map is cleared, so a reset can be
  written to ``stack_map`` while tracing is active.
- An insert that meets an unpublished element of the same hash falls back
  to a full stack trace, which loses nothing. ``tracing_map`` spins
  instead, since dropping the insert there loses a histogram update.
- Probing stops after 64 slots, so a slot claimed without an element can
  stay claimed. ``tracing_map`` has no probe limit and releases such a
  slot, so that its loop always reaches a free slot.
