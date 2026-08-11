# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Linux-kernel crash output parsing (KASAN reports / oops / panic).

Mirrors the interface of ``asan.py`` (project_frames / top_frame /
crash_reason / kasan_excerpt) so dedup, judge, and the found_bugs.jsonl
sharing all work unchanged — ``asan.py`` delegates here when the output
looks like a kernel crash.

Kernel crash output comes from the guest serial console (dmesg). Shapes:

  BUG: KASAN: null-ptr-deref in scatterwalk_ffwd+0x43/0x150
  Read of size 4 at addr 000000000000000c by task pov/108
  Call Trace:
   <TASK>
    dump_stack_lvl+0x60/0x80
    ...
    scatterwalk_ffwd+0x43/0x150
   </TASK>

  BUG: kernel NULL pointer dereference, address: 000000000000000c
  RIP: 0010:scatterwalk_ffwd+0x30/0xc0
  Call Trace:
   ...

  Kernel panic - not syncing: ...
"""
from __future__ import annotations

import re


# A kernel stack frame: `  func+0x2b/0x60` or legacy `[<ffff...>] func+0x2b/0x60`.
_KERNEL_FRAME = re.compile(
    r"^\s*(?:\[<[0-9a-fA-F]+>\]\s*)?([A-Za-z_][\w.$]*)\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+",
    re.MULTILINE,
)
# RIP line: `RIP: 0010:func+0x2b/0x60`
_RIP = re.compile(
    r"^RIP:\s+[0-9a-fA-F]{4}:\s*([A-Za-z_][\w.$]*)\+0x[0-9a-fA-F]+",
    re.MULTILINE,
)
_KASAN_BUG = re.compile(r"BUG:\s*KASAN:\s*([A-Za-z-]+)")
_OOPS_BUG = re.compile(r"^BUG:\s*(kernel [^\n,]+)", re.MULTILINE)
_PANIC = re.compile(r"^Kernel panic - not syncing:\s*([^\n]+)", re.MULTILINE)
_READ_WRITE = re.compile(r"^\s*(Read|Write) of size \d+", re.MULTILINE)

# KASAN/oops machinery frames — the reporting code, not the bug. Skip these
# when picking the "top frame" so it lands on the actual kernel function.
_SKIP_FRAMES = {
    "dump_stack_lvl", "dump_stack", "__dump_stack",
    "print_report", "print_address_description", "print_track",
    "print_bad_address", "print_address", "print_memory_region",
    "kasan_report", "__kasan_report", "kasan_report_invalid_free",
    "kasan_check_range", "check_memory_region",
    "__kasan_check_read", "__kasan_check_write",
    "kasan_check_read", "kasan_check_write",
    "report_something", "report_hw_address",
    "panic", "die", "oops_end", "no_context", "show_regs",
    "__bad_area_nosemaphore", "bad_area_nosemaphore",
    "__do_kernel_fault", "do_kernel_fault", "do_user_addr_fault",
    "exc_page_fault", "asm_exc_page_fault", "handle_page_fault",
    "handle_mm_fault",
}


def looks_like_kernel(crash_output: str) -> bool:
    """True if the output is a kernel crash report rather than a userspace
    ASAN trace. Conservative: requires a kernel-specific marker."""
    if "BUG: KASAN" in crash_output:
        return True
    if "Kernel panic" in crash_output:
        return True
    if "general protection fault" in crash_output:
        return True
    if "BUG: kernel" in crash_output:
        return True
    return bool(_RIP.search(crash_output) and "Call Trace:" in crash_output)


def _call_trace_frames(crash_output: str) -> list[str]:
    """Function names from the FIRST Call Trace block (the faulting one, not
    the `Freed by` / `Allocated by` traces)."""
    lines = crash_output.splitlines()
    trace_start = None
    for i, line in enumerate(lines):
        if "Call Trace:" in line:
            trace_start = i + 1
            break
    if trace_start is None:
        return []
    frames: list[str] = []
    for line in lines[trace_start:]:
        stripped = line.strip()
        if not stripped or stripped in ("<TASK>", "</TASK>"):
            continue
        m = _KERNEL_FRAME.match(line)
        if not m:
            break  # end of the stack block
        frames.append(m.group(1))
    return frames


def project_frames(crash_output: str, n: int = 3) -> list[str]:
    """Top-N non-machinery kernel frames from the crash stack.

    Returns up to ``n`` function names; empty list if none parsed. Falls back
    to the RIP faulting function if there is no Call Trace."""
    out = [f for f in _call_trace_frames(crash_output) if f not in _SKIP_FRAMES][:n]
    if out:
        return out
    m = _RIP.search(crash_output)
    if m and m.group(1) not in _SKIP_FRAMES:
        return [m.group(1)]
    frames = _call_trace_frames(crash_output)
    return frames[:1] if frames else []


def top_frame(crash_output: str) -> str | None:
    """The faulting kernel function.

    Prefers the RIP site (present for oops; exact fault location); otherwise
    the first non-machinery frame of the first Call Trace."""
    m = _RIP.search(crash_output)
    if m:
        return m.group(1)
    frames = project_frames(crash_output, n=1)
    return frames[0] if frames else None


_GPF = re.compile(r"general protection fault")


def crash_reason(crash_output: str) -> dict[str, str | None]:
    """crash_type + READ/WRITE operation parsed from kernel crash output.

    Display-only: feeds found_bugs.jsonl excerpts and dedup summary. Not a
    decision input — agents judge semantic duplicates from raw KASAN."""
    crash_type: str | None = None
    m = _KASAN_BUG.search(crash_output)
    if m:
        crash_type = m.group(1)
    else:
        m = _OOPS_BUG.search(crash_output)
        if m:
            crash_type = m.group(1).strip().replace(" ", "-")
        else:
            m = _PANIC.search(crash_output)
            if m:
                crash_type = "kernel-panic"
            elif _GPF.search(crash_output):
                crash_type = "general-protection-fault"

    op = _READ_WRITE.search(crash_output)
    operation = op.group(1) if op else None
    return {"crash_type": crash_type, "operation": operation}


_CRASH_MARKERS = (
    "BUG: KASAN", "Kernel panic", "BUG: kernel",
    "general protection fault", "BUG: unable to handle",
)


def kasan_excerpt(crash_output: str, max_frames: int = 10) -> str:
    """Crash header + first N Call Trace frames, for dedup/judge context.

    ~500 bytes per excerpt — enough for a find- or judge-agent to compare
    signatures semantically without the full serial log."""
    lines = crash_output.splitlines()
    start = next((i for i, l in enumerate(lines)
                  if any(k in l for k in _CRASH_MARKERS)), None)
    if start is None:
        return "\n".join(l.strip() for l in lines if l.strip())[:3]

    out: list[str] = []
    frame_count = 0
    for line in lines[start:start + 80]:
        s = line.strip()
        if not s:
            continue
        if (s.startswith(("BUG:", "Kernel panic", "Read of size", "Write of size",
                          "RIP:", "Call Trace", "#PF", "Freed by", "Allocated by",
                          "The buggy address", "general protection fault"))):
            out.append(s)
        elif _KERNEL_FRAME.match(line):
            out.append(s)
            frame_count += 1
            if frame_count >= max_frames:
                break
    if not out:
        out = [l.strip() for l in lines if l.strip()][:3]
    return "\n".join(out)
