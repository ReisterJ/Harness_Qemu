#!/usr/bin/env python3
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Exploration-path observer for find-agent transcripts.

Reads a run's find_transcript.jsonl (and optionally MEMORY.md) and renders:
  1. an ASCII path timeline (reads / writes / bash phases),
  2. process metrics (region coverage, re-entry, forks, convergence),
  3. --batch mode: per-run metric table as JSON for A/B comparison.

Usage:
  python3 tools/trace_path.py <run_dir>                 # one run, path timeline
  python3 tools/trace_path.py <run_dir> --json          # metrics only (JSON)
  python3 tools/trace_path.py <runs_dir> --batch        # table of per-run metrics
  python3 tools/trace_path.py <runs_dir> --batch --json # machine-readable

Region mapping is heuristic: file basename -> region name. Extend
REGION_RULES per target to make forks meaningful.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────
# Transcript parsing
# ──────────────────────────────────────────────────────────────────────


def iter_events(transcript_path: Path):
    """Yield (turn, kind, payload) tuples from a find_transcript.jsonl.

    turn = ordinal of step_start-separated tool call (1-based per tool_use).
    kind ∈ read | write | bash | text

    Note: find agents may read source via the `bash` tool (`cat`/`grep`)
    rather than the Read tool — we extract file reads from bash commands too.
    """
    turn = 0
    for line in transcript_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = m.get("type")
        if t == "step_start":
            turn += 1
            continue
        part = m.get("part") or {}
        if t == "tool_use" and isinstance(part, dict):
            tool = (part.get("tool") or "").lower()
            state = part.get("state") or {}
            inp = state.get("input") or {}
            if tool == "read":
                path = str(inp.get("path", ""))
                if path:  # skip empty-path read calls (agent noise)
                    yield turn, "read", {"path": path}
            elif tool == "write":
                yield turn, "write", {"path": str(inp.get("path", ""))}
            elif tool == "bash":
                cmd = str(inp.get("command", ""))
                yield turn, "bash", {"command": cmd}
                # source files read via shell: cat/grep/sed/head/tail <path>
                for f in _extract_cat_paths(cmd):
                    yield turn, "read", {"path": f, "via": "bash"}
        elif t == "text" and isinstance(part, dict):
            yield turn, "text", {"text": part.get("text", "")}


_CAT_RE = re.compile(
    r"(?:cat|grep|sed|head|tail|less|more|vim|vi|nano|wc)\s+([^|;&]+)"
)
_SRC_EXT = re.compile(r"\.(c|h|py|sh|md|gn|gni|json|txt|cfg|config)$")


def _extract_cat_paths(cmd: str):
    """Heuristically extract file paths from `cat`/`grep`-style bash commands.

    Returns source-ish paths only (extension filter) to avoid counting
    transcript/log/output files as source reads.
    """
    out = set()
    for m in _CAT_RE.finditer(cmd):
        arg = m.group(1).strip()
        # strip leading flags like -n, -A2, -rn; keep first path token
        toks = arg.split()
        for tok in toks:
            if tok.startswith("-") or tok.startswith("\\") or "|" in tok:
                continue
            # trim trailing quotes/punct
            path = tok.strip('"\'`')
            if _SRC_EXT.search(path) and "/" in path:
                out.add(path)
                break
    return out


# ──────────────────────────────────────────────────────────────────────
# Region mapping
# ──────────────────────────────────────────────────────────────────────

DEFAULT_REGION_RULES = [
    # (regex on path, region name)
    (r"cJSON\.c", "cjson/cJSON.c"),
    (r"cJSON_Utils\.c", "cjson/cJSON_Utils.c"),
    (r"cJSON_test", "cjson/tests"),
    # Kafka (Java): package paths under clients/src/main/java/...
    (r"/common/record/", "kafka/record"),
    (r"/common/protocol/", "kafka/protocol"),
    (r"/common/utils/", "kafka/utils"),
    (r"/common/memory/", "kafka/memory"),
    (r"/common/network/", "kafka/network"),
    (r"/clients/src/main/java/", "kafka/clients-other"),
    (r"\.java$", "kafka/other-java"),
    # libyaml: sources live in src/parser.c, src/scanner.c, ... (no yaml_ prefix)
    (r"/src/parser\.c$", "yaml/parser"),
    (r"/src/scanner\.c$", "yaml/scanner"),
    (r"/src/reader\.c$", "yaml/reader"),
    (r"/src/emitter\.c$", "yaml/emitter"),
    (r"/src/loader\.c$", "yaml/loader"),
    (r"/src/writer\.c$", "yaml/writer"),
    (r"/src/dumper\.c$", "yaml/dumper"),
    (r"yaml_parser\.c", "yaml/parser"),
    (r"yaml_scanner\.c", "yaml/scanner"),
    (r"yaml_emitter\.c", "yaml/emitter"),
    (r"yaml_reader\.c", "yaml/reader"),
    (r"yaml_loader\.c", "yaml/loader"),
    (r"yaml_writer\.c", "yaml/writer"),
    (r"yaml_dumper\.c", "yaml/dumper"),
    (r"api\.c", "yaml/api"),
    (r"yaml\.h|yaml_private\.h", "yaml/headers"),
    (r"los_queue\.c", "liteos/los_queue"),
    (r"los_task\.c", "liteos/los_task"),
    (r"los_memory\.c", "liteos/los_memory"),
    (r"los_sched\.c", "liteos/los_sched"),
    (r"los_membox\.c", "liteos/los_membox"),
    (r"los_signal\.c", "liteos/los_signal"),
    (r"fullpath\.c", "liteos/fullpath"),
    (r"pipe\.c", "liteos/pipe"),
    (r"poll\.c", "liteos/poll"),
    (r"cmsis_liteos2\.c", "liteos/cmsis"),
    (r"\.c$", "other/src"),
    (r"\.h$", "other/headers"),
]


def region_of(path: str, rules: list[tuple[str, str]] | None = None) -> str:
    rules = rules or DEFAULT_REGION_RULES
    for pat, name in rules:
        if re.search(pat, path):
            return name
    return "other"


# ──────────────────────────────────────────────────────────────────────
# Metric computation
# ──────────────────────────────────────────────────────────────────────


def compute_metrics(events) -> dict:
    """Compute process metrics from the event stream."""
    reads: list[tuple[int, str]] = []      # (turn, path)
    mem_read_turns: list[int] = []         # turns where MEMORY.md was read
    mem_write_turns: list[int] = []        # turns where MEMORY.md was written (tool or bash)
    bash_cmds: list[tuple[int, str]] = []

    for turn, kind, payload in events:
        if kind == "read":
            path = payload["path"]
            reads.append((turn, path))
            if "MEMORY.md" in path:
                mem_read_turns.append(turn)
        elif kind == "write":
            path = payload.get("path", "")
            if "MEMORY.md" in path:
                mem_write_turns.append(turn)
        elif kind == "bash":
            cmd = payload.get("command", "")
            bash_cmds.append((turn, cmd))
            if "MEMORY.md" in cmd:
                if "cat" in cmd or "view" in cmd:
                    mem_read_turns.append(turn)
                # append/write to MEMORY.md via shell heredoc or echo
                if re.search(r"(>>|>)\s*/work/MEMORY\.md", cmd) or re.search(r"cat\s+>>", cmd):
                    mem_write_turns.append(turn)

    total_reads = len(reads)
    regions = [region_of(p) for _, p in reads]
    unique_regions = set(regions)
    covered = len(unique_regions)

    # re-entry: same region appearing after a different region in between
    re_entries = 0
    seen_order: list[str] = []
    for r in regions:
        if r in seen_order:
            re_entries += 1
        else:
            seen_order.append(r)

    # forks: adjacent read regions differ
    forks = sum(1 for a, b in zip(regions, regions[1:]) if a != b)

    # convergence: turn span from first to last read of a region (avg)
    spans = []
    for r in unique_regions:
        turns_r = [t for t, p in reads if region_of(p) == r]
        if len(turns_r) > 1:
            spans.append(max(turns_r) - min(turns_r))
    avg_span = (sum(spans) / len(spans)) if spans else 0

    # bash classification
    def classify(cmd: str) -> str:
        c = cmd.strip()
        if re.match(r"(cd .*)?(gn|ninja|gcc|make|hb|\./rebuild|docker build)", c):
            return "build"
        if re.search(r"qemu|\./entry|/work/entry|timeout .*entry|timeout .*qemu", c):
            return "run"
        if re.search(r"grep|cat .*\.log|tail|head", c):
            return "inspect"
        return "other"

    bash_counts: dict[str, int] = {}
    for _, cmd in bash_cmds:
        k = classify(cmd)
        bash_counts[k] = bash_counts.get(k, 0) + 1

    return {
        "turns": reads[-1][0] if reads else 0,
        "total_reads": total_reads,
        "unique_files": len({p for _, p in reads}),
        "regions_covered": covered,
        "region_reentries": re_entries,
        "forks": forks,
        "avg_region_span": round(avg_span, 1),
        "mem_reads": len(mem_read_turns),
        "mem_writes": len(mem_write_turns),
        "bash": bash_counts,
    }


# ──────────────────────────────────────────────────────────────────────
# ASCII timeline
# ──────────────────────────────────────────────────────────────────────

PHASE_COLORS = {"build": "b", "run": "r", "inspect": "i"}


def render_timeline(events, memory_text: str | None = None, max_lines: int = 40) -> str:
    """Render a compact ASCII path timeline."""
    lines: list[str] = []
    reads: list[tuple[int, str]] = []
    for turn, kind, payload in events:
        if kind == "read":
            reads.append((turn, payload["path"]))

    # Bucket reads into contiguous region runs.
    runs: list[tuple[str, int, int]] = []  # (region, start_turn, end_turn)
    for t, p in reads:
        r = region_of(p)
        if runs and runs[-1][0] == r:
            runs[-1] = (r, runs[-1][1], t)
        else:
            runs.append((r, t, t))

    for i, (region, s, e) in enumerate(runs):
        span = f"{s}-{e}" if s != e else str(s)
        marker = ""
        if i > 0 and region == runs[i - 1][0]:
            marker = "  (re-entry)"
        lines.append(f"  Read {region:<22} [t{span}]{marker}")

    for line in lines[:max_lines]:
        yield line
    if len(lines) > max_lines:
        yield f"  ... ({len(lines) - max_lines} more region runs)"

    if memory_text:
        n_refuted = memory_text.count("REFUTED")
        n_done = memory_text.count("DONE")
        n_promising = memory_text.count("PROMISING")
        yield f"  MEMORY.md: {n_refuted} REFUTED / {n_done} DONE / {n_promising} PROMISING entries"


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Exploration-path observer")
    ap.add_argument("path", help="run dir (containing find_transcript.jsonl) or a runs dir with --batch")
    ap.add_argument("--batch", action="store_true", help="treat PATH as a dir of run_* dirs; emit a table")
    ap.add_argument("--json", action="store_true", help="emit JSON metrics instead of prose")
    ap.add_argument("--timeline", action="store_true", help="also render the ASCII timeline")
    args = ap.parse_args(argv)

    root = Path(args.path)

    def one_run(run_dir: Path) -> dict:
        tp = run_dir / "find_transcript.jsonl"
        events = list(iter_events(tp))
        metrics = compute_metrics(events)
        mem = None
        mp = run_dir / "MEMORY.md"
        if mp.exists():
            mem = mp.read_text(encoding="utf-8", errors="replace")
        return {"run": run_dir.name, "metrics": metrics, "memory": mem}

    if args.batch:
        runs = sorted([d for d in root.iterdir() if d.is_dir() and (d / "find_transcript.jsonl").exists()])
        if not runs:
            print(f"no run_* dirs with find_transcript.jsonl under {root}", file=sys.stderr)
            return 1
        results = [one_run(r) for r in runs]
        if args.json:
            print(json.dumps([{"run": r["run"], **r["metrics"]} for r in results], indent=2))
        else:
            hdr = f"{'run':<10}{'turns':>7}{'regions':>9}{'reentry':>9}{'forks':>7}{'span':>7}{'memR':>6}{'memW':>6}"
            print(hdr)
            for r in results:
                m = r["metrics"]
                print(f"{r['run']:<10}{m['turns']:>7}{m['regions_covered']:>9}"
                      f"{m['region_reentries']:>9}{m['forks']:>7}{m['avg_region_span']:>7}"
                      f"{m['mem_reads']:>6}{m['mem_writes']:>6}")
        return 0

    # single run
    tp = root / "find_transcript.jsonl"
    if not tp.exists():
        print(f"no find_transcript.jsonl in {root}", file=sys.stderr)
        return 1
    res = one_run(root)
    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    m = res["metrics"]
    print(f"{res['run']}: {m['turns']} turns | {m['regions_covered']} regions | "
          f"{m['region_reentries']} re-entries | {m['forks']} forks | "
          f"avg span {m['avg_region_span']} | bash {m['bash']}")
    if args.timeline:
        print("─" * 60)
        for line in render_timeline(iter_events(tp), res["memory"]):
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
