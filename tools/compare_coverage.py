#!/usr/bin/env python3
"""Compare A/B coverage on Kafka transcripts.

Extracts every source-file contact from a transcript:
  - read tool paths
  - bash commands touching files under the source root (cat/grep/sed/head/
    tail/awk/nl/less...) — parsed per-token so grep -n 'x' file works
Groups files by Kafka package (org/apache/kafka/common/<sub>) and prints
per-run unique files, per-run package coverage, cumulative coverage, and
cross-run NEW coverage (memory value: does a later run reach new packages?).
"""
import json
import re
import sys
from collections import Counter, defaultdict

SRC_ROOT = "/work/kafka"
_FILE_RE = re.compile(
    r"(?:^|[\s;\"'&=<>])(/work/kafka/[^\s;\"'|&<>()]+\.(?:java|scala|xml|gradle|properties))"
)
# read tool
def contacts(run_dir: str) -> dict:
    per_file = Counter()
    path = f"{run_dir}/find_transcript.jsonl"
    try:
        lines = open(path).read().splitlines()
    except FileNotFoundError:
        return {}
    for line in lines:
        m = json.loads(line)
        if m.get("type") != "tool_use":
            continue
        p = m.get("part", {})
        tool = p.get("tool")
        inp = p.get("state", {}).get("input", {}) or {}
        if tool == "read":
            fp = inp.get("path", "")
            if fp.startswith(SRC_ROOT):
                per_file[fp] += 1
        elif tool == "bash":
            cmd = inp.get("command", "")
            # skip writes/compiles/runs that merely reference paths
            if "run_harness.sh" in cmd or cmd.startswith("javac") or " > " in cmd:
                pass
            for fp in _FILE_RE.findall(cmd):
                per_file[fp] += 1
    return per_file


def pkg_of(fp: str) -> str:
    # /work/kafka/clients/src/main/java/org/apache/kafka/common/record/internal/X.java
    mm = re.search(r"/org/apache/kafka/(?:common|clients)/([\w./]+)/", fp)
    if mm:
        parts = mm.group(1).split("/")
        return "kafka/" + parts[0] if parts else "kafka/other"
    if "/org/apache/kafka/" in fp:
        return "kafka/other"
    return "kafka/misc"


def analyze(run_dir: str, label: str) -> list:
    print(f"===== {label} =====")
    all_files: set[str] = set()
    per_run = []
    for run in ["run_000", "run_001", "run_002"]:
        files = contacts(f"{run_dir}/{run}")
        if not files:
            continue
        pkgs = Counter(pkg_of(f) for f in files)
        uniq = set(files)
        new = uniq - all_files
        all_files |= uniq
        per_run.append((run, uniq, pkgs))
        print(f"  {run}: unique源码文件={len(uniq)}  包覆盖={dict(pkgs)}  "
              f"相对前run新文件={len(new)}")
    # 累计
    cum_pkgs = set()
    for run, uniq, pkgs in per_run:
        cum_pkgs |= set(pkgs)
    print(f"  三run累计源码文件={len(all_files)}  累计包={sorted(cum_pkgs)}")
    return per_run


if __name__ == "__main__":
    a = sys.argv[1]
    b = sys.argv[2]
    analyze(a, "A (无记忆)")
    print()
    analyze(b, "B (有记忆)")
