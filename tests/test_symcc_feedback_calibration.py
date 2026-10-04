"""Calibration cases for SymCC target-site feedback semantics."""
from __future__ import annotations

import json

from harness.symbolic.feedback import (
    TRACE_EVENT,
    TRACE_FLAG_COMPLETE,
    TRACE_FLAG_TARGETS_CONFIGURED,
    TRACE_FLAG_TRUNCATED,
    TRACE_HEADER,
    TRACE_MAGIC,
    load_json_map_files,
    parse_trace,
    resolve_target_ids,
    summarize_trace,
)


def _calibration_graph():
    return load_json_map_files([json.dumps({
        "schema_version": 1,
        "module_id": "targets/canary/entry.c",
        "source_commit": "b" * 40,
        "function": "parse_charlie",
        "blocks": [
            {
                "id": 10,
                "entry": True,
                "exit": False,
                "successors": [20],
                "source_file": "targets/canary/entry.c",
                "line": 51,
                "source_locations": [{
                    "id": 1001,
                    "source_file": "targets/canary/entry.c",
                    "source_function": "parse_charlie",
                    "line": 51,
                    "column": 1,
                }],
                "calls": [],
            },
            {
                "id": 20,
                "entry": False,
                "exit": False,
                "successors": [30],
                "source_file": "targets/canary/entry.c",
                "line": 57,
                "source_locations": [
                    {
                        "id": 2001,
                        "source_file": "targets/canary/entry.c",
                        "source_function": "parse_charlie",
                        "line": 57,
                        "column": 3,
                    },
                    {
                        "id": 2002,
                        "source_file": "targets/canary/entry.c",
                        "source_function": "parse_charlie",
                        "line": 58,
                        "column": 5,
                    },
                ],
                "calls": [],
            },
            {
                "id": 30,
                "entry": False,
                "exit": True,
                "successors": [],
                "source_file": "targets/canary/entry.c",
                "line": 61,
                "source_locations": [{
                    "id": 3001,
                    "source_file": "targets/canary/entry.c",
                    "source_function": "parse_charlie",
                    "line": 61,
                    "column": 1,
                }],
                "calls": [],
            },
        ],
    })])


def _trace(events, *, complete=True, truncated=False):
    flags = TRACE_FLAG_TARGETS_CONFIGURED
    if complete:
        flags |= TRACE_FLAG_COMPLETE
    if truncated:
        flags |= TRACE_FLAG_TRUNCATED
    return parse_trace(
        TRACE_HEADER.pack(
            TRACE_MAGIC,
            1,
            TRACE_HEADER.size,
            max(len(events), 1),
            len(events),
            flags,
            0,
        )
        + b"".join(TRACE_EVENT.pack(site_id, kind, 0) for site_id, kind in events)
    )


def _target(graph):
    return resolve_target_ids(
        graph,
        {
            "targets": [{
                "source_file": "targets/canary/entry.c",
                "function": "parse_charlie",
                "line": 58,
            }]
        },
    )


def test_calibration_function_entry_is_not_operation_reach():
    graph = _calibration_graph()
    markers, target_blocks = _target(graph)

    result = summarize_trace(
        graph,
        _trace([(10, 1), (1001, 2)]),
        marker_ids=markers,
        target_block_ids=target_blocks,
    )

    assert result["target_function_entered"] is True
    assert result["target_block_entered"] is False
    assert result["exact_target_reached"] is False
    assert result["target_reachability"] == "this_execution_missed"
    assert "entered the target function" in result["allowed_conclusion"]


def test_calibration_block_entry_is_not_operation_reach():
    graph = _calibration_graph()
    markers, target_blocks = _target(graph)

    result = summarize_trace(
        graph,
        _trace([(10, 1), (1001, 2), (20, 1), (2001, 2)]),
        marker_ids=markers,
        target_block_ids=target_blocks,
    )

    assert result["target_function_entered"] is True
    assert result["target_block_entered"] is True
    assert result["target_operation_reached"] is False
    assert result["exact_target_reached"] is False
    assert result["distance"] == 0
    assert "target block" in result["allowed_conclusion"]


def test_calibration_operation_marker_is_exact_reach():
    graph = _calibration_graph()
    markers, target_blocks = _target(graph)

    result = summarize_trace(
        graph,
        _trace([(10, 1), (20, 1), (2002, 2)]),
        marker_ids=markers,
        target_block_ids=target_blocks,
    )

    assert result["target_function_entered"] is True
    assert result["target_block_entered"] is True
    assert result["target_operation_reached"] is True
    assert result["exact_target_reached"] is True
    assert result["target_reachability"] == "this_execution_hit"
    assert "precise target operation marker was observed" in result["allowed_conclusion"]


def test_calibration_truncated_trace_without_marker_is_unknown():
    graph = _calibration_graph()
    markers, target_blocks = _target(graph)

    result = summarize_trace(
        graph,
        _trace([(10, 1), (1001, 2), (20, 1)], complete=True, truncated=True),
        marker_ids=markers,
        target_block_ids=target_blocks,
    )

    assert result["target_function_entered"] is True
    assert result["target_block_entered"] is True
    assert result["exact_target_reached"] is None
    assert result["target_reachability"] == "unknown"
    assert "unknown" in result["allowed_conclusion"]
