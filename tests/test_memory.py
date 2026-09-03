# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for harness.memory: function-summary parsing, ledger, rendering."""
from harness.memory import (
    parse_memory_md,
    append_entries,
    read_entries,
    render_prior_exploration,
    EMPTY_MEMORY,
)


SAMPLE_MD = """\
# Exploration Memory — function summaries

### [SUSPICIOUS] parser.c:yaml_parser_parse | turn=45
- 作用: 驱动解析状态机，从 token 队列产生 event
- 输入: yaml_parser_t* (state 栈、token queue)
- 安全关注: parser->state 栈深度、error recovery 路径
- 已验证: 深嵌套(200k)不崩；畸形 UTF-8 优雅失败
- 可疑点: parse_value 递归深度无显式上限

### [EXPLORED] scanner.c:yaml_scanner_scan | turn=60
- 作用: tokenize YAML 输入
- 输入: yaml_parser_t* buffer
- 安全关注: 引号/转义处理、unicode
- 已验证: 各类标量正常
- 可疑点: 无

### [CONFIRMED] reader.c:yaml_reader_update | turn=88
- 作用: 输入缓冲读取
- 输入: 文件流
- 安全关注: 缓冲增长
- 已验证: 超大输入触发 ASAN heap-buffer-overflow
- 可疑点: 已提交 poc
"""


def test_parse_memory_md_entries():
    entries = parse_memory_md(SAMPLE_MD)
    assert len(entries) == 3
    e0 = entries[0]
    assert e0["status"] == "SUSPICIOUS"
    assert e0["func"] == "parser.c:yaml_parser_parse"
    assert e0["run_turn"] == 45
    assert e0["valid"] is True
    assert "解析状态机" in e0["fields"]["作用"]
    assert "递归深度" in e0["fields"]["可疑点"]
    assert entries[1]["status"] == "EXPLORED"
    assert entries[2]["status"] == "CONFIRMED"
    assert entries[2]["func"] == "reader.c:yaml_reader_update"


def test_parse_memory_md_with_run_idx():
    entries = parse_memory_md(SAMPLE_MD, run_idx=3)
    assert all(e["run"] == 3 for e in entries)


def test_parse_memory_md_empty():
    assert parse_memory_md("") == []
    assert parse_memory_md("# only a header\n") == []


def test_parse_memory_md_invalid_status_flagged():
    md = "### [FOO] parser.c:yaml_foo | turn=1\n- 作用: x\n"
    entries = parse_memory_md(md)
    assert len(entries) == 1
    assert entries[0]["valid"] is False
    assert entries[0]["status"] == "FOO"


def test_append_and_read_entries_roundtrip(tmp_path):
    p = tmp_path / "exploration_memory.jsonl"
    entries = parse_memory_md(SAMPLE_MD, run_idx=1)
    append_entries(p, entries)
    append_entries(p, parse_memory_md(SAMPLE_MD, run_idx=2))
    read = read_entries(p)
    assert len(read) == 6
    assert all(e["func"] for e in read)
    assert {e["run"] for e in read} == {1, 2}


def test_read_entries_tolerates_garbage(tmp_path):
    p = tmp_path / "exploration_memory.jsonl"
    p.write_text('{"status": "SUSPICIOUS", "func": "a.c:foo"}\nnot json\n{"broken\n', encoding="utf-8")
    entries = read_entries(p)
    assert len(entries) == 1
    assert entries[0]["func"] == "a.c:foo"


def test_render_prior_exploration_groups_and_dedups():
    entries = [
        {"status": "SUSPICIOUS", "func": "a.c:foo", "fields": {"可疑点": "x"}},
        {"status": "SUSPICIOUS", "func": "a.c:foo", "fields": {"可疑点": "y"}},  # newer, same func
        {"status": "EXPLORED", "func": "b.c:bar", "fields": {"role": "reader"}},
        {"status": "CONFIRMED", "func": "c.c:baz", "fields": {}},
    ]
    rendered = render_prior_exploration(entries)
    assert "SUSPICIOUS" in rendered and "a.c:foo" in rendered
    assert "y" in rendered and "x" not in rendered  # dedup, newer wins
    assert "EXPLORED" in rendered and "b.c:bar" in rendered
    assert "CONFIRMED" in rendered and "c.c:baz" in rendered
    assert rendered.index("可疑") < rendered.index("已确认")  # SUSPICIOUS first


def test_render_prior_exploration_empty():
    assert render_prior_exploration([]) == ""
    assert render_prior_exploration([{"status": "UNKNOWN", "func": "a.c:f"}]) == ""


def test_seed_memory_has_header():
    assert b"function summaries" in EMPTY_MEMORY.encode()
