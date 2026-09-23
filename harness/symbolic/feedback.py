# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Decode SymCC execution traces and compute target-directed CFG guidance.

The trace only records what happened in one concrete SymCC-instrumented run.
The distance is a shortest-path estimate over an over-approximating static
interprocedural CFG and must never be treated as a reachability proof.
"""

from __future__ import annotations

import json
import struct
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping


TRACE_MAGIC = b"SYMFDB1\0"
TRACE_HEADER = struct.Struct("<8sIIQQII")
TRACE_EVENT = struct.Struct("<QII")
TRACE_FLAG_COMPLETE = 1 << 0
TRACE_FLAG_TRUNCATED = 1 << 1
TRACE_FLAG_TARGET_REACHED = 1 << 2
TRACE_FLAG_TARGETS_CONFIGURED = 1 << 3
TRACE_FLAG_TARGETS_INVALID = 1 << 4


class FeedbackMapError(ValueError):
    """A SymCC feedback map or target anchor cannot be trusted."""


@dataclass(frozen=True)
class TraceEvent:
    site_id: int
    kind: int  # 1 = basic block, 2 = source location


@dataclass(frozen=True)
class SymccTrace:
    status: str
    events: tuple[TraceEvent, ...] = ()
    complete: bool = False
    truncated: bool = False
    target_reached: bool | None = None
    target_ids_configured: bool = False
    target_ids_valid: bool = True
    error: str | None = None


def parse_trace(data: bytes) -> SymccTrace:
    """Parse the bounded binary trace emitted by the SymCC QSYM runtime."""
    if len(data) < TRACE_HEADER.size:
        return SymccTrace("missing_or_truncated", error="trace header is incomplete")
    magic, schema, header_size, capacity, count, flags, _reserved = TRACE_HEADER.unpack_from(data)
    if magic != TRACE_MAGIC:
        return SymccTrace("invalid", error="trace magic does not match")
    if schema != 1 or header_size != TRACE_HEADER.size:
        return SymccTrace("invalid", error="unsupported trace schema or header size")
    if count > capacity:
        return SymccTrace("invalid", error="trace event count exceeds its capacity")
    required_size = header_size + count * TRACE_EVENT.size
    if required_size > len(data):
        return SymccTrace("incomplete", error="trace event payload is incomplete")
    events: list[TraceEvent] = []
    for offset in range(header_size, required_size, TRACE_EVENT.size):
        site_id, kind, _padding = TRACE_EVENT.unpack_from(data, offset)
        if kind not in (1, 2):
            return SymccTrace("invalid", error=f"unknown trace event kind {kind}")
        events.append(TraceEvent(site_id, kind))
    complete = bool(flags & TRACE_FLAG_COMPLETE)
    truncated = bool(flags & TRACE_FLAG_TRUNCATED)
    target_ids_configured = bool(flags & TRACE_FLAG_TARGETS_CONFIGURED)
    target_ids_valid = not bool(flags & TRACE_FLAG_TARGETS_INVALID)
    if flags & TRACE_FLAG_TARGET_REACHED:
        target_reached: bool | None = True
    elif (
        complete and not truncated and target_ids_configured and target_ids_valid
    ):
        target_reached = False
    else:
        target_reached = None
    return SymccTrace(
        "completed" if complete else "interrupted",
        tuple(events),
        complete,
        truncated,
        target_reached,
        target_ids_configured,
        target_ids_valid,
    )


def load_feedback_maps(values: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Validate and merge per-function JSON records emitted by SymCC."""
    nodes: dict[int, dict[str, Any]] = {}
    functions: dict[str, dict[str, Any]] = {}
    by_name: dict[str, list[str]] = defaultdict(list)
    all_locations: dict[int, dict[str, Any]] = {}
    source_commits: set[str] = set()
    map_record_count = 0
    map_records_missing_commit = 0
    unresolved_calls: list[dict[str, Any]] = []

    for record in values:
        map_record_count += 1
        if record.get("schema_version") != 1:
            raise FeedbackMapError("unsupported feedback-map schema")
        module_id = record.get("module_id")
        function = record.get("function")
        blocks = record.get("blocks")
        source_commit = record.get("source_commit")
        if not isinstance(module_id, str) or not module_id:
            raise FeedbackMapError("map record is missing module_id")
        if not isinstance(function, str) or not function:
            raise FeedbackMapError("map record is missing function")
        if source_commit is not None:
            if not isinstance(source_commit, str) or not source_commit:
                raise FeedbackMapError("source_commit must be a non-empty string")
            source_commits.add(source_commit)
        else:
            map_records_missing_commit += 1
        if not isinstance(blocks, list) or not blocks:
            raise FeedbackMapError(f"map record for {function} has no blocks")
        function_key = f"{module_id}::{function}"
        block_ids: list[int] = []
        entries: list[int] = []
        exits: list[int] = []
        for block in blocks:
            if not isinstance(block, dict):
                raise FeedbackMapError(f"invalid basic-block record in {function}")
            site_id = _positive_id(block.get("id"), f"block id in {function}")
            if site_id in nodes:
                raise FeedbackMapError(f"duplicate basic-block id {site_id}")
            successors = _id_list(block.get("successors", []), "successors")
            source_locations = block.get("source_locations", [])
            if not isinstance(source_locations, list):
                raise FeedbackMapError(f"invalid source locations in block {site_id}")
            normalized_locations: list[dict[str, Any]] = []
            for location in source_locations:
                if not isinstance(location, dict):
                    raise FeedbackMapError(f"invalid source location in block {site_id}")
                location_id = _positive_id(location.get("id"), "source location id")
                if location_id in nodes or location_id in all_locations:
                    raise FeedbackMapError(f"duplicate feedback site id {location_id}")
                source_line = location.get("line")
                if isinstance(source_line, bool) or not isinstance(source_line, int) or source_line < 1:
                    raise FeedbackMapError(f"invalid source line for location {location_id}")
                file_name = location.get("source_file")
                if not isinstance(file_name, str) or not file_name:
                    raise FeedbackMapError(f"missing source file for location {location_id}")
                column = location.get("column", 0)
                if isinstance(column, bool) or not isinstance(column, int) or column < 0:
                    raise FeedbackMapError(f"invalid source column for location {location_id}")
                loc_function = location.get("source_function") or function
                if not isinstance(loc_function, str):
                    raise FeedbackMapError(f"invalid source function for location {location_id}")
                loc = {
                    "id": location_id,
                    "source_file": _normalize_path(file_name),
                    "source_function": loc_function,
                    "line": source_line,
                    "column": column,
                    "block_id": site_id,
                }
                prior = all_locations.get(location_id)
                if prior is not None and prior != loc:
                    raise FeedbackMapError(f"source-location id collision: {location_id}")
                all_locations[location_id] = loc
                normalized_locations.append(loc)

            calls = block.get("calls", [])
            if not isinstance(calls, list):
                raise FeedbackMapError(f"invalid calls in block {site_id}")
            normalized_calls: list[dict[str, Any]] = []
            for call in calls:
                if not isinstance(call, dict):
                    raise FeedbackMapError(f"invalid call edge in block {site_id}")
                callee = call.get("callee")
                if not isinstance(callee, str) or not callee:
                    unresolved_calls.append({"block_id": site_id, "reason": "indirect_call"})
                    continue
                callee_key = call.get("callee_key")
                if callee_key is not None and not isinstance(callee_key, str):
                    raise FeedbackMapError(f"invalid callee_key in block {site_id}")
                normalized_calls.append({
                    "callee": callee,
                    "callee_key": callee_key,
                    "return_to": _id_list(call.get("return_to", []), "call return_to"),
                })

            node = {
                "id": site_id,
                "module_id": module_id,
                "function": function,
                "function_key": function_key,
                "source_file": _normalize_optional_path(block.get("source_file")),
                "line": _optional_positive_line(block.get("line"), site_id),
                "successors": successors,
                "calls": normalized_calls,
                "source_locations": normalized_locations,
                "entry": _strict_bool(block.get("entry", False), "entry"),
                "exit": _strict_bool(block.get("exit", False), "exit"),
            }
            if site_id in all_locations:
                raise FeedbackMapError(f"duplicate feedback site id {site_id}")
            nodes[site_id] = node
            block_ids.append(site_id)
            if node["entry"]:
                entries.append(site_id)
            if node["exit"]:
                exits.append(site_id)

        if function_key in functions:
            raise FeedbackMapError(f"duplicate function record {function_key}")
        functions[function_key] = {
            "key": function_key,
            "name": function,
            "module_id": module_id,
            "blocks": block_ids,
            "entries": entries,
            "exits": exits,
        }
        by_name[function].append(function_key)

    for node in nodes.values():
        for call in node["calls"]:
            callee_key = call["callee_key"]
            if callee_key is not None:
                candidates = [callee_key] if callee_key in functions else []
            else:
                candidates = by_name.get(call["callee"], [])
            if len(candidates) != 1:
                unresolved_calls.append({
                    "block_id": node["id"],
                    "callee": call["callee"],
                    "reason": "unresolved_or_ambiguous_direct_call",
                })
                continue
            call["resolved_callee_key"] = candidates[0]

    successors: dict[int, set[int]] = {site_id: set() for site_id in nodes}
    for node in nodes.values():
        local_calls = [call for call in node["calls"] if call.get("resolved_callee_key")]
        # Basic CFG edges remain available as an over-approximation. A direct
        # call edge plus the caller's normal successor intentionally permits a
        # shorter path than the true call/return path; the result is guidance.
        for successor in node["successors"]:
            if successor in nodes:
                successors[node["id"]].add(successor)
        for call in local_calls:
            callee = functions[call["resolved_callee_key"]]
            for entry in callee["entries"]:
                successors[node["id"]].add(entry)
            for exit_id in callee["exits"]:
                for continuation in call["return_to"]:
                    if continuation in nodes:
                        successors[exit_id].add(continuation)

    return {
        "schema_version": 1,
        "source_commits": sorted(source_commits),
        "map_record_count": map_record_count,
        "map_records_missing_commit": map_records_missing_commit,
        "nodes": nodes,
        "functions": functions,
        "functions_by_name": dict(by_name),
        "locations": all_locations,
        "successors": successors,
        "unresolved_calls": unresolved_calls,
    }


def resolve_target_ids(
    graph: Mapping[str, Any],
    goal: Mapping[str, Any],
    *,
    source_root: str | None = None,
) -> tuple[list[int], list[int]]:
    """Return (runtime marker IDs, CFG target block IDs) for a structured goal."""
    targets = goal.get("targets")
    if not isinstance(targets, list) or not targets:
        raise FeedbackMapError("goal.targets must contain at least one target anchor")
    marker_ids: set[int] = set()
    target_blocks: set[int] = set()
    for anchor in targets:
        if not isinstance(anchor, Mapping):
            raise FeedbackMapError("each target anchor must be an object")
        function = anchor.get("function")
        source_file = anchor.get("source_file", anchor.get("file"))
        line = anchor.get("line")
        if function is not None and (not isinstance(function, str) or not function):
            raise FeedbackMapError("target function must be a non-empty string")
        if source_file is not None and (not isinstance(source_file, str) or not source_file):
            raise FeedbackMapError("target source_file must be a non-empty string")
        if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
            raise FeedbackMapError("target line must be a positive integer")
        if (source_file is None) != (line is None):
            raise FeedbackMapError("target source_file and line must be provided together")
        if function is None and source_file is None:
            raise FeedbackMapError("target anchor needs a function or source_file/line")

        if source_file is not None:
            wanted_path = _target_path(source_file, source_root)
            for location_id, location in graph["locations"].items():
                if location["line"] != line or location["source_file"] != wanted_path:
                    continue
                if function is not None and location["source_function"] != function:
                    continue
                marker_ids.add(location_id)
                target_blocks.add(location["block_id"])
        else:
            for key in graph["functions_by_name"].get(function, []):
                fn = graph["functions"][key]
                if fn["entries"]:
                    marker_ids.update(fn["entries"])
                    target_blocks.update(fn["entries"])

    if not marker_ids:
        raise FeedbackMapError("goal anchors did not resolve to any instrumented code location")
    if not target_blocks:
        raise FeedbackMapError("goal anchors resolved but have no CFG block")
    return sorted(marker_ids), sorted(target_blocks)


def summarize_trace(
    graph: Mapping[str, Any],
    trace: SymccTrace,
    *,
    marker_ids: Iterable[int] | None = None,
    target_block_ids: Iterable[int] | None = None,
) -> dict[str, Any]:
    """Combine exact per-run observations with explicitly heuristic CFG distance."""
    markers = set(marker_ids or ())
    targets = set(target_block_ids or ())
    if trace.status in {"invalid", "missing_or_truncated", "incomplete"}:
        return {
            "trace_status": trace.status,
            "target_reached": None,
            "target_reachability": "unknown",
            "distance": None,
            "distance_kind": "static_icfg_edges",
            "distance_is_heuristic": True,
            "error": trace.error,
        }

    observed_ids = {event.site_id for event in trace.events}
    unknown_ids = sorted(observed_ids - set(graph["nodes"]) - set(graph["locations"]))
    target_reached: bool | None
    if not markers:
        target_reached = None
    else:
        observed_target_marker = bool(observed_ids.intersection(markers))
        if observed_target_marker or trace.target_reached is True:
            target_reached = True
        elif (
            trace.complete
            and not trace.truncated
        ):
            # A negative is exact only after the instrumented process completed
            # normally and the event stream contains every callback. For a
            # truncated stream, the runtime's target marker flag is the only
            # valid negative oracle.
            target_reached = False
        elif (
            trace.complete
            and trace.target_ids_configured
            and trace.target_ids_valid
            and trace.target_reached is False
        ):
            target_reached = False
        else:
            target_reached = None

    distances = _reverse_distances(graph["successors"], targets)
    reached_blocks = {
        event.site_id for event in trace.events
        if event.kind == 1 and event.site_id in graph["nodes"]
    }
    best = min(
        ((distances[site_id], site_id) for site_id in reached_blocks if site_id in distances),
        default=None,
    )
    closest = None
    distance = None
    if best is not None:
        distance, best_id = best
        node = graph["nodes"][best_id]
        closest = {
            "block_id": best_id,
            "function": node["function"],
            "source_file": node["source_file"],
            "line": node["line"],
        }

    return {
        "trace_status": trace.status,
        "trace_complete": trace.complete,
        "trace_truncated": trace.truncated,
        "target_ids_configured": trace.target_ids_configured,
        "target_ids_valid": trace.target_ids_valid,
        "observed_block_count": len(reached_blocks),
        "observed_locations": _observed_locations(graph, trace.events),
        "unknown_site_ids": unknown_ids[:64],
        "target_reached": target_reached,
        "target_reachability": (
            "this_execution_hit" if target_reached is True
            else "this_execution_missed" if target_reached is False
            else "unknown"
        ),
        "closest_observed_location": closest,
        "distance": distance,
        "distance_kind": "static_icfg_edges",
        "distance_granularity": "basic_block",
        "distance_is_heuristic": True,
        "distance_note": (
            "Shortest-path estimate over an over-approximating static CFG/call graph at "
            "basic-block granularity. Intra-block instruction order is not represented, "
            "so distance 0 does not prove an exact source-line marker was hit."
        ),
        "unresolved_call_count": len(graph["unresolved_calls"]),
    }


def load_json_map_files(contents: Iterable[bytes | str]) -> dict[str, Any]:
    """Decode JSONL map files collected from a prebuilt SymCC target image."""
    records: list[Mapping[str, Any]] = []
    for content in contents:
        text = content.decode("utf-8", errors="strict") if isinstance(content, bytes) else content
        for line_no, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise FeedbackMapError(f"invalid feedback map JSONL at line {line_no}: {exc}") from exc
            if not isinstance(value, dict):
                raise FeedbackMapError("feedback map records must be JSON objects")
            records.append(value)
    if not records:
        raise FeedbackMapError("feedback map contains no records")
    return load_feedback_maps(records)


def _reverse_distances(successors: Mapping[int, set[int]], targets: set[int]) -> dict[int, int]:
    reverse: dict[int, list[int]] = defaultdict(list)
    for source, destinations in successors.items():
        for destination in destinations:
            reverse[destination].append(source)
    distances: dict[int, int] = {}
    queue: deque[int] = deque()
    for target in targets:
        if target in successors:
            distances[target] = 0
            queue.append(target)
    while queue:
        current = queue.popleft()
        for predecessor in reverse.get(current, []):
            if predecessor not in distances:
                distances[predecessor] = distances[current] + 1
                queue.append(predecessor)
    return distances


def _positive_id(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value >= 1 << 63:
        raise FeedbackMapError(f"{label} must be an integer in (0, 2^63)")
    return value


def _optional_positive_line(value: Any, site_id: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise FeedbackMapError(f"invalid source line for block {site_id}")
    return value


def _strict_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise FeedbackMapError(f"{label} must be a boolean")
    return value


def _observed_locations(
    graph: Mapping[str, Any], events: Iterable[TraceEvent]
) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    seen: set[int] = set()
    for event in events:
        if event.kind != 2 or event.site_id in seen:
            continue
        location = graph["locations"].get(event.site_id)
        if location is None:
            continue
        seen.add(event.site_id)
        locations.append({
            key: location[key]
            for key in ("source_file", "source_function", "line", "column")
        })
        if len(locations) >= 256:
            break
    return locations


def _id_list(value: Any, label: str) -> list[int]:
    if not isinstance(value, list):
        raise FeedbackMapError(f"{label} must be an array")
    return [_positive_id(item, label) for item in value]


def _normalize_path(value: str) -> str:
    normalized = str(PurePosixPath(value.replace("\\", "/")))
    return normalized.removeprefix("./")


def _normalize_optional_path(value: Any) -> str | None:
    return _normalize_path(value) if isinstance(value, str) and value else None


def _target_path(value: str, source_root: str | None) -> str:
    path = _normalize_path(value)
    if source_root:
        root = _normalize_path(source_root).rstrip("/")
        if path == root:
            return "."
        if path.startswith(root + "/"):
            return path[len(root) + 1 :]
    return path
