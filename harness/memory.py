# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Exploration-memory plumbing for find runs.

Two layers, both minimal and additive:

Layer 1 (in-run): the find agent maintains ``/work/MEMORY.md`` — a
free-form, append-only exploration log. Each entry is one
"hypothesis -> evidence -> verification -> verdict" loop, tagged with a
status (DONE / REFUTED / PROMISING). The pipeline seeds an empty file and
collects it when the run ends; it never edits it while the agent runs.

Layer 2 (cross-run): the orchestrator parses each collected MEMORY.md into
structured entries and appends them to a batch-level ``exploration_memory.jsonl``.
Subsequent runs get a compact rendering of that history injected into the
find prompt (via ``render_prior_exploration``) so later agents can skip
already-refuted regions and pick up promising threads.

Everything here is pure text handling + JSON — no agent calls, no docker
(collection/parsing/rendering are done by the orchestrator host).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Memory file inside the agent container (layer 1).
MEMORY_PATH = "/work/MEMORY.md"

# Batch-level memory ledger (layer 2), relative to a results root.
BATCH_MEMORY_NAME = "exploration_memory.jsonl"

# Statuses an entry can carry (function-summary oriented).
STATUS_EXPLORED = "EXPLORED"      # function read, no issue found
STATUS_SUSPICIOUS = "SUSPICIOUS"  # function has a suspicious spot worth revisiting
STATUS_CONFIRMED = "CONFIRMED"    # function has a confirmed crash/bug
VALID_STATUSES = {STATUS_EXPLORED, STATUS_SUSPICIOUS, STATUS_CONFIRMED}

# Empty MEMORY.md content used to seed the file in the container.
EMPTY_MEMORY = (
    "# Exploration Memory — function summaries\n\n"
    "Maintained by the find agent. Append-only. Each entry is a summary of "
    "ONE function you have examined. See prompt for the exact schema.\n"
)


def seed_memory_content() -> bytes:
    """Bytes to write to /work/MEMORY.md before a find run starts."""
    return EMPTY_MEMORY.encode("utf-8")


# ──────────────────────────────────────────────────────────────────────
# Layer-1 -> layer-2: parse a MEMORY.md into structured entries
# ──────────────────────────────────────────────────────────────────────

# Entry header: ### [STATUS] file.c:function | turn=N
# (file extension: .c/.h for C targets, .java for JVM targets; the
#  file:func separator is soft — agents may use ':', ' | ' or ' ')
_ENTRY_RE = re.compile(
    r"^###\s*\[(?P<status>[A-Z_]+)\]\s*"
    r"(?P<func>[\w./-]+\.(?:c|h|java)[\s:|]+[\w]+)"
    r"(?:\s*\|\s*turn=(?P<run_turn>\d+))?"
)

# Field lines within an entry: - 字段: value
_FIELD_RE = re.compile(r"^\s*-\s*(?P<key>[\w/]+)\s*[:：]\s*(?P<val>.*)$")


def parse_memory_md(content: str, run_idx: int | None = None) -> list[dict]:
    """Parse MEMORY.md function-summary entries into structured dicts.

    Each entry: ``{"status", "func", "run_turn", "fields", "raw", "valid"}``
    where ``fields`` is {role/inputs/safety/verified/notes: str}.
    Unknown statuses are kept but flagged.
    """
    entries: list[dict] = []
    current: dict | None = None

    for line in content.splitlines():
        m = _ENTRY_RE.match(line)
        if m:
            if current is not None:
                entries.append(current)
            status = m.group("status")
            func = re.sub(r"[\s:|]+", ":", m.group("func")).strip(":")
            current = {
                "status": status,
                "func": func,
                "run_turn": int(m.group("run_turn")) if m.group("run_turn") else None,
                "fields": {},
                "raw": line.strip(),
                "valid": status in VALID_STATUSES,
            }
            continue
        if current is not None:
            fm = _FIELD_RE.match(line)
            if fm:
                key = fm.group("key").lower()
                val = fm.group("val").strip()
                if key in ("role", "作用", "inputs", "输入", "safety", "安全关注",
                           "verified", "已验证", "notes", "备注", "可疑点", "conclusion"):
                    current["fields"][key] = val
            if len(current.get("_block", "")) < 600:
                current["_block"] = current.get("_block", "") + line.strip() + "\n"

    if current is not None:
        entries.append(current)

    for e in entries:
        if run_idx is not None:
            e["run"] = run_idx
    return entries


# ──────────────────────────────────────────────────────────────────────
# Layer-2 ledger: append / read / render
# ──────────────────────────────────────────────────────────────────────


def append_entries(path: Path, entries: list[dict]) -> None:
    """Append structured entries to the batch-level ledger (one JSON per line)."""
    with open(path, "a", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")


def read_entries(path: Path) -> list[dict]:
    """Read all entries from a ledger file (tolerant of partial lines)."""
    entries: list[dict] = []
    if not path.exists():
        return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def render_prior_exploration(entries: list[dict], max_lines: int = 15) -> str:
    """Render function-summary entries into a compact prompt block.

    Groups by status (SUSPICIOUS first — most useful for continuation),
    dedups by function keeping the newest, includes the one-line role/notes,
    and truncates. Empty history renders to an empty string.
    """
    if not entries:
        return ""

    def newest_by_func(items: list[dict]) -> list[dict]:
        by_func: dict[str, dict] = {}
        for e in items:  # later entries overwrite earlier ones
            by_func[e.get("func") or "?"] = e
        return list(by_func.values())

    def line(e: dict) -> str:
        func = e.get("func") or "?"
        fields = e.get("fields") or {}
        # Prefer 可疑点/notes/role, in that order, truncated.
        snippet = fields.get("可疑点") or fields.get("notes") or fields.get("role") or ""
        snippet = snippet[:70]
        tag = {STATUS_SUSPICIOUS: "[S]", STATUS_CONFIRMED: "[C]", STATUS_EXPLORED: "[E]"}.get(
            e.get("status"), "[?]"
        )
        return f"  - {tag} {func}" + (f"  {snippet}" if snippet else "")

    parts: list[str] = []
    for status, heading in (
        (STATUS_SUSPICIOUS, "可疑 (SUSPICIOUS) — 值得继续："),
        (STATUS_CONFIRMED, "已确认 (CONFIRMED) — 有崩溃："),
        (STATUS_EXPLORED, "已探索 (EXPLORED) — 未发现问题："),
    ):
        items = newest_by_func([e for e in entries if e.get("status") == status])
        if items:
            parts.append(heading)
            parts.extend(line(e) for e in items)

    if not parts:
        return ""

    body = "\n".join(parts)
    lines = body.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines.append("  ... (截断)")

    return (
        "## 前序 run 的函数索引（只读，非 ground truth）\n\n"
        "已探索(EXPLORED)且无可疑点 = 已完成：直接采用摘要，不要重读源码。\n"
        "优先 SUSPICIOUS 条目，其次无索引的函数。\n\n"
        + "\n".join(lines)
        + "\n\n建议：优先探索无索引的函数；SUSPICIOUS 的值得先续；"
        "EXPLORED 若你发现新角度可重查。"
    )


def collect_run_memory(container: str, memory_path: str = MEMORY_PATH) -> str:
    """Read the agent's MEMORY.md out of a running (or just-finished) container.

    Returns the raw text; empty string if the file is missing.
    """
    from . import docker_ops

    try:
        raw = docker_ops.read_file(container, memory_path)
    except Exception:
        return ""
    return raw.decode("utf-8", errors="replace")
