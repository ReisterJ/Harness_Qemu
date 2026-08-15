# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
"""LiteOS-M LMS (Lite Memory Sanitizer) crash output parsing.

Mirrors the interface of ``asan.py`` / ``kasan.py`` (project_frames /
top_frame / crash_reason / lms_excerpt) so dedup, judge, and the
found_bugs.jsonl sharing all work unchanged. ``asan.py`` delegates here when
the output looks like a LiteOS-M LMS report.

LiteOS-M has no userspace: the "crash" is the LMS runtime reporting a shadow
violation over the serial console, followed by a task/exception dump (or a
QEMU HardFault when LMS is not hit). Shapes:

  [ERR][TaskSampleEntry1]*****  Kernel Address Sanitizer Error Detected Start *****
  [ERR][TaskSampleEntry1]Heap buffer overflow error detected
  [ERR][TaskSampleEntry1]Illegal WRITE address at: [0x2102ecbc]
  [ERR][TaskSampleEntry1]Shadow memory address: [0x211e4acb : 6]  Shadow memory value: [3]
  psp, start = 2102db90, end = 2102dc80
  taskName = TaskSampleEntry1
  taskID   = 3
  ----- traceback start -----
  traceback 0 -- lr = 0x2100966a
  traceback 1 -- lr = 0x2100fbf2
  ----- traceback end -----
  [LMS] Dump info around address [0x2102ecbc]:

  ... or a HardFault when LMS is off / instrumentation missed:
  qemu: fatal: Lockup: can't escalate 3 to HardFault (current priority -1)
"""
from __future__ import annotations

import re


_LMS_START = re.compile(r"Kernel Address Sanitizer Error Detected Start")
_LMS_CLASS = re.compile(
    r"^(?:\[[^\]]*\]){0,3}\s*(Use after free error detected"
    r"|Heap buffer overflow error detected"
    r"|Illegal Double free .*?|UnKnown Error detected)",
    re.MULTILINE,
)
_LMS_ACCESS = re.compile(
    r"Illegal (READ|WRITE) address at: \[0x[0-9a-fA-F]+\]", re.MULTILINE,
)
_LMS_TRACE = re.compile(r"traceback (\d+) -- lr = 0x[0-9a-fA-F]+", re.MULTILINE)
_LMS_TASK = re.compile(r"taskName = (\S+)", re.MULTILINE)
_LMS_DOUBLE_FREE = re.compile(r"Illegal Double free address at: \[0x[0-9a-fA-F]+\]",
                              re.MULTILINE)
# QEMU HardFault escalation (LMS missed / non-LMS crash):
_HARDFAULT = re.compile(
    r"qemu: fatal: Lockup: can't escalate|R13=0x[0-9a-fA-F]+|HardFault",
    re.MULTILINE,
)


def looks_like_lms(crash_output: str) -> bool:
    """True if the output is a LiteOS-M LMS report (or HardFault)."""
    if _LMS_START.search(crash_output):
        return True
    if _LMS_CLASS.search(crash_output):
        return True
    return bool(_HARDFAULT.search(crash_output) and "R14=" in crash_output)


def project_frames(crash_output: str, n: int = 3) -> list[str]:
    """Top-N traceback entries from the LMS report.

    LiteOS-M tracebacks carry only `lr = 0x…` return addresses (no symbol
    names); address is all we have until objdump symbolization. Returns the
    raw traceback lines, newest first.
    """
    frames: list[str] = []
    for m in _LMS_TRACE.finditer(crash_output):
        frames.append(m.group(0))
        if len(frames) >= n:
            break
    if frames:
        return frames
    # HardFault fallback: R14 (LR) is the most useful register.
    m = re.search(r"R14=0x[0-9a-fA-F]+", crash_output)
    return [m.group(0)] if m else []


def top_frame(crash_output: str) -> str | None:
    """Newest LMS traceback entry, or the faulting task's name."""
    frames = project_frames(crash_output, n=1)
    if frames:
        return frames[0]
    m = _LMS_TASK.search(crash_output)
    return m.group(1) if m else None


def crash_reason(crash_output: str) -> dict[str, str | None]:
    """crash_type + READ/WRITE operation parsed from LMS output.

    Display-only: feeds found_bugs.jsonl excerpts and dedup summary.
    """
    crash_type: str | None = None
    m = _LMS_CLASS.search(crash_output)
    if m:
        crash_type = m.group(1).strip().replace(" ", "-")
    elif _LMS_DOUBLE_FREE.search(crash_output):
        crash_type = "double-free"
    elif _HARDFAULT.search(crash_output):
        crash_type = "hardfault"

    op = _LMS_ACCESS.search(crash_output)
    operation = op.group(1) if op else None
    return {"crash_type": crash_type, "operation": operation}


_CRASH_MARKERS = (
    "Kernel Address Sanitizer Error Detected",
    "error detected",
    "Illegal WRITE address",
    "Illegal READ address",
    "Illegal Double free",
    "Lockup: can't escalate",
)


def lms_excerpt(crash_output: str, max_frames: int = 10) -> str:
    """LMS header + traceback lines, for dedup/judge context (~500 bytes)."""
    lines = crash_output.splitlines()
    start = next((i for i, l in enumerate(lines)
                  if any(k in l for k in _CRASH_MARKERS)), None)
    if start is None:
        return "\n".join(l.strip() for l in lines if l.strip())[:3]

    out: list[str] = []
    frame_count = 0
    for line in lines[start:start + 60]:
        s = line.strip()
        if not s:
            continue
        if (("Kernel Address Sanitizer" in s)
                or ("error detected" in s.lower())
                or s.startswith(("Use after free", "Heap buffer overflow",
                                 "Illegal", "Shadow memory", "taskName",
                                 "taskID", "psp", "----- traceback",
                                 "traceback", "R14="))):
            out.append(s)
            if "traceback" in s and "-- lr =" in s:
                frame_count += 1
                if frame_count >= max_frames:
                    break
    if not out:
        out = [l.strip() for l in lines if l.strip()][:3]
    return "\n".join(out)
