"""Tests for exact SymCC trace facts and heuristic CFG guidance."""

import json
import pytest

from harness.symbolic.feedback import (
    TRACE_EVENT,
    TRACE_FLAG_COMPLETE,
    TRACE_FLAG_TARGETS_CONFIGURED,
    TRACE_FLAG_TARGET_REACHED,
    TRACE_FLAG_TRUNCATED,
    TRACE_HEADER,
    TRACE_MAGIC,
    FeedbackMapError,
    load_json_map_files,
    parse_trace,
    resolve_target_ids,
    summarize_trace,
)


def _map():
    return load_json_map_files([json.dumps({
        "schema_version": 1,
        "module_id": "src/parser.c",
        "source_commit": "a" * 40,
        "function": "parse",
        "blocks": [
            {
                "id": 100,
                "entry": True,
                "exit": False,
                "successors": [200],
                "source_file": "src/parser.c",
                "line": 10,
                "source_locations": [{
                    "id": 1000,
                    "source_file": "src/parser.c",
                    "source_function": "parse",
                    "line": 10,
                    "column": 1,
                }],
                "calls": [],
            },
            {
                "id": 200,
                "entry": False,
                "exit": True,
                "successors": [],
                "source_file": "src/parser.c",
                "line": 20,
                "source_locations": [{
                    "id": 2000,
                    "source_file": "src/parser.c",
                    "source_function": "parse",
                    "line": 20,
                    "column": 3,
                }],
                "calls": [],
            },
        ],
    })])


def _trace(
    events, *, complete=False, target=False, truncated=False,
    targets_configured=False, capacity=None,
):
    capacity = len(events) if capacity is None else capacity
    flags = (TRACE_FLAG_COMPLETE if complete else 0) | (
        TRACE_FLAG_TARGET_REACHED if target else 0
    ) | (TRACE_FLAG_TRUNCATED if truncated else 0) | (
        TRACE_FLAG_TARGETS_CONFIGURED if targets_configured else 0
    )
    return TRACE_HEADER.pack(TRACE_MAGIC, 1, TRACE_HEADER.size, capacity,
                             len(events), flags, 0) + b"".join(
        TRACE_EVENT.pack(site_id, kind, 0) for site_id, kind in events
    )


def test_goal_anchor_resolves_precise_line_and_source_relative_path():
    graph = _map()
    marker_ids, target_blocks = resolve_target_ids(
        graph,
        {"targets": [{"file": "/checkout/src/parser.c", "line": 20,
                      "function": "parse"}]},
        source_root="/checkout",
    )
    assert marker_ids == [2000]
    assert target_blocks == [200]


def test_trace_reports_exact_hit_and_heuristic_distance_separately():
    graph = _map()
    marker_ids, target_blocks = resolve_target_ids(
        graph, {"targets": [{"source_file": "src/parser.c", "line": 20}]}
    )
    result = summarize_trace(
        graph, parse_trace(_trace([(100, 1), (1000, 2)], complete=True)),
        marker_ids=marker_ids, target_block_ids=target_blocks,
    )
    assert result["target_reached"] is False
    assert result["target_reachability"] == "this_execution_missed"
    assert result["target_block_reached"] is False
    assert result["distance"] == 1
    assert result["distance_is_heuristic"] is True
    assert result["observed_locations"] == [{
        "source_file": "src/parser.c", "source_function": "parse",
        "line": 10, "column": 1,
    }]

    hit = summarize_trace(
        graph, parse_trace(_trace([(200, 1), (2000, 2)], target=True)),
        marker_ids=marker_ids, target_block_ids=target_blocks,
    )
    assert hit["target_reached"] is True
    assert hit["target_reachability"] == "this_execution_hit"
    assert hit["distance"] == 0


def test_interrupted_run_without_target_hit_is_unknown_not_negative():
    graph = _map()
    marker_ids, target_blocks = resolve_target_ids(
        graph, {"targets": [{"source_file": "src/parser.c", "line": 20}]}
    )
    result = summarize_trace(
        graph, parse_trace(_trace([(100, 1)], complete=False)),
        marker_ids=marker_ids, target_block_ids=target_blocks,
    )
    assert result["target_reached"] is None
    assert result["target_reachability"] == "unknown"
    assert result["target_block_reached"] is None
    assert result["distance"] == 1


def test_basic_block_distance_zero_does_not_imply_exact_line_hit():
    graph = _map()
    marker_ids, target_blocks = resolve_target_ids(
        graph,
        {"targets": [{"source_file": "src/parser.c", "line": 10}]},
    )
    result = summarize_trace(
        graph,
        parse_trace(_trace([(100, 1)], complete=True)),
        marker_ids=marker_ids,
        target_block_ids=target_blocks,
    )
    assert result["target_reached"] is False
    assert result["target_block_reached"] is True
    assert result["distance"] == 0
    assert result["distance_granularity"] == "basic_block"
    assert "does not prove an exact source-line marker" in result["distance_note"]


def test_runtime_target_flag_preserves_positive_hit_when_trace_truncated():
    graph = _map()
    marker_ids, target_blocks = resolve_target_ids(
        graph, {"targets": [{"source_file": "src/parser.c", "line": 20}]}
    )
    result = summarize_trace(
        graph,
        parse_trace(_trace([(100, 1)], target=True, capacity=1)),
        marker_ids=marker_ids,
        target_block_ids=target_blocks,
    )
    assert result["target_reached"] is True


def test_truncated_trace_without_target_hit_is_unknown_not_a_false_miss():
    graph = _map()
    marker_ids, target_block_ids = resolve_target_ids(
        graph, {"targets": [{"source_file": "src/parser.c", "line": 20}]}
    )
    trace = parse_trace(_trace(
        [(100, 1)], complete=True, truncated=True, targets_configured=True,
    ))

    result = summarize_trace(
        graph, trace, marker_ids=marker_ids, target_block_ids=target_block_ids,
    )

    assert trace.target_reached is None
    assert result["target_reached"] is None
    assert result["target_reachability"] == "unknown"
    assert result["trace_truncated"] is True


def test_missing_target_and_malformed_map_fail_explicitly():
    graph = _map()
    with pytest.raises(FeedbackMapError, match="did not resolve"):
        resolve_target_ids(graph, {"targets": [{"source_file": "missing.c", "line": 5}]})
    with pytest.raises(FeedbackMapError, match="duplicate feedback site id"):
        load_json_map_files([json.dumps({
            "schema_version": 1,
            "module_id": "x",
            "function": "f",
            "blocks": [{
                "id": 1,
                "source_locations": [{
                    "id": 1, "source_file": "x.c", "line": 1,
                }],
            }],
        })])


def test_trace_parser_rejects_inconsistent_header_and_short_payload():
    valid_header = TRACE_HEADER.pack(TRACE_MAGIC, 1, TRACE_HEADER.size, 0, 1, 0, 0)
    assert parse_trace(valid_header).status == "invalid"
    header = TRACE_HEADER.pack(TRACE_MAGIC, 1, TRACE_HEADER.size, 1, 1, 0, 0)
    assert parse_trace(header).status == "incomplete"
