#!/usr/bin/env python3
"""Compare A/B Kafka agent behavior: source reading vs black-box testing."""
import json
import sys


def analyze(run_dir: str, label: str) -> None:
    for run in ["run_000", "run_001", "run_002"]:
        path = f"{run_dir}/{run}/find_transcript.jsonl"
        try:
            lines = open(path).read().splitlines()
        except FileNotFoundError:
            continue
        cat_src = 0
        harness = 0
        poc_build = 0
        ls_explore = 0
        grep_src = 0
        total = 0
        read_tool = 0
        for line in lines:
            m = json.loads(line)
            if m.get("type") != "tool_use":
                continue
            p = m.get("part", {})
            tool = p.get("tool")
            if tool == "read":
                read_tool += 1
            if tool == "bash":
                cmd = p.get("state", {}).get("input", {}).get("command", "")
                total += 1
                if "/work/kafka/clients/src" in cmd and (
                    "cat " in cmd or "sed " in cmd or "head " in cmd or "tail " in cmd
                ):
                    cat_src += 1
                if "run_harness.sh" in cmd:
                    harness += 1
                if "python3" in cmd and ("struct" in cmd or "gzip" in cmd):
                    poc_build += 1
                if cmd.startswith("ls ") or "ls /work/kafka" in cmd:
                    ls_explore += 1
                if cmd.startswith("grep") and "src" in cmd:
                    grep_src += 1
        print(
            f"{label} {run}: bash={total} read工具={read_tool} cat源码={cat_src} "
            f"grep源码={grep_src} ls探索={ls_explore} 跑harness={harness} 构造PoC={poc_build}"
        )


if __name__ == "__main__":
    a = sys.argv[1]
    b = sys.argv[2]
    analyze(a, "A")
    analyze(b, "B")
