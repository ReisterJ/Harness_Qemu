#!/usr/bin/env python3
"""Summarize a curl smoke run: memory, tools, harness use, agent text."""
import json
import sys
from collections import Counter

D = sys.argv[1]

# memory entries
try:
    md = open(f"{D}/MEMORY.md").read()
    entries = [l for l in md.splitlines() if l.startswith("###")]
    print(f"=== MEMORY.md: {len(entries)} 条目 ===")
    for e in entries:
        print(" ", e)
except FileNotFoundError:
    print("(no MEMORY.md)")

try:
    led = sum(1 for _ in open(f"{D}/exploration_memory.jsonl"))
    print(f"=== ledger: {led} 条 ===")
except FileNotFoundError:
    print("(no ledger)")

# tools + harness use + memory interaction
c = Counter()
memR = memW = harness = 0
src_cat = 0
for line in open(f"{D}/find_transcript.jsonl"):
    m = json.loads(line)
    if m.get("type") != "tool_use":
        continue
    p = m.get("part", {})
    t = p.get("tool")
    c[t] += 1
    cmd = str(p.get("state", {}).get("input", {}).get("command", ""))
    if "MEMORY" in cmd:
        if ">>" in cmd or "EOF" in cmd:
            memW += 1
        else:
            memR += 1
    if "run_curl.sh" in cmd:
        harness += 1
    if "/work/curl/lib/" in cmd and ("cat " in cmd or "sed " in cmd or "head " in cmd):
        src_cat += 1
print(f"=== 工具: {dict(c)} | 跑harness={harness} | cat源码={src_cat} | memR={memR} memW={memW} ===")

# agent reasoning text
print("=== agent 文本（前 8 条） ===")
n = 0
for line in open(f"{D}/find_transcript.jsonl"):
    m = json.loads(line)
    if m.get("type") == "text":
        t = m.get("part", {}).get("text", "")[:200]
        n += 1
        if n <= 8:
            print(f"[{n}] {t}")
