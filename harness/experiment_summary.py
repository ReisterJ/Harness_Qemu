"""Post-hoc summaries for dynamic-validation experiment directories."""
from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class DynamicRunSummary:
    """Compact, comparison-friendly view of one dynamic_validation.json."""

    run_dir: str
    arm: str
    target: str
    candidate_id: str
    status: str
    target_site_status: str
    poc_status: str
    grade_status: str
    additional_findings_status: str
    feedback_quality_status: str
    dynamic_validation_s: float | None
    tool_calls: int | None
    messages: int | None
    iterations: int
    additional_crashes: int
    execution_protocol_requests: int | None
    feedback_ready: int | None
    feedback_ready_manually_read: int | None
    feedback_ready_unconsumed: int | None
    first_request_tool_calls: int | None
    exact_target_hit_records: int | None
    generated_replays: int | None
    ledger_events: int
    agent_error: str | None
    outcome_category: str = "unknown"
    failure_category: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def summarize_experiment_tree(root: Path | Iterable[Path]) -> dict[str, Any]:
    """Summarize all dynamic_validation.json files below one or more roots."""
    roots = [root] if isinstance(root, Path) else list(root)
    paths: list[Path] = []
    for item in roots:
        if item.is_file() and item.name == "dynamic_validation.json":
            paths.append(item)
        elif item.is_dir():
            paths.extend(item.rglob("dynamic_validation.json"))
    unique_paths = sorted({path.resolve(): path for path in paths}.values())
    runs = [load_dynamic_run_summary(path) for path in unique_paths]
    return {
        "schema_version": 1,
        "root": str(roots[0]) if len(roots) == 1 else None,
        "roots": [str(item) for item in roots],
        "run_count": len(runs),
        "runs": [run.to_dict() for run in runs],
        "by_arm": _aggregate_by_arm(runs),
        "by_target": _aggregate_by_target(runs),
    }


def load_dynamic_run_summary(path: Path) -> DynamicRunSummary:
    payload = _read_json(path)
    run_dir = path.parent
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    candidate = (
        payload.get("candidate") if isinstance(payload.get("candidate"), dict) else {}
    )
    timings = payload.get("timings") if isinstance(payload.get("timings"), dict) else {}
    breakdown = (
        result.get("status_breakdown")
        if isinstance(result.get("status_breakdown"), dict)
        else {}
    )
    symbolic = (
        result.get("symbolic_execution")
        if isinstance(result.get("symbolic_execution"), dict)
        else _read_optional_json(run_dir / "symbolic_execution" / "summary.json")
    )
    metrics = symbolic.get("metrics") if isinstance(symbolic.get("metrics"), dict) else {}
    first_request_policy = (
        symbolic.get("first_request_policy")
        if isinstance(symbolic.get("first_request_policy"), dict)
        else {}
    )
    iterations = result.get("iterations")
    additional_crashes = result.get("additional_crashes")
    ledger_path = run_dir / "evidence_ledger.jsonl"
    target = (
        str(payload.get("target") or "")
        or _infer_target_from_path(run_dir)
    )
    candidate_id = str(
        result.get("candidate_id")
        or candidate.get("candidate_id")
        or ""
    )
    values: dict[str, Any] = {
        "run_dir": str(run_dir),
        "arm": _infer_arm(run_dir, symbolic),
        "target": target,
        "candidate_id": candidate_id,
        "status": str(result.get("status") or "unknown"),
        "target_site_status": str(breakdown.get("target_site_status") or "unknown"),
        "poc_status": str(breakdown.get("poc_status") or "unknown"),
        "grade_status": str(breakdown.get("grade_status") or "not_run"),
        "additional_findings_status": str(
            breakdown.get("additional_findings_status") or "unknown"
        ),
        "feedback_quality_status": str(
            breakdown.get("feedback_quality_status") or "unavailable"
        ),
        "dynamic_validation_s": _optional_float(timings.get("dynamic_validation")),
        "tool_calls": _optional_int(timings.get("dynamic_agent_tool_calls")),
        "messages": _optional_int(timings.get("dynamic_agent_messages")),
        "iterations": len(iterations) if isinstance(iterations, list) else 0,
        "additional_crashes": (
            len(additional_crashes) if isinstance(additional_crashes, list) else 0
        ),
        "execution_protocol_requests": _optional_int(
            timings.get("execution_protocol_requests") or symbolic.get("requests")
        ),
        "feedback_ready": _optional_int(symbolic.get("feedback_ready")),
        "feedback_ready_manually_read": _optional_int(
            symbolic.get("feedback_ready_manually_read")
        ),
        "feedback_ready_unconsumed": _optional_int(symbolic.get("feedback_ready_unconsumed")),
        "first_request_tool_calls": _optional_int(
            first_request_policy.get("first_request_tool_calls")
        ),
        "exact_target_hit_records": _optional_int(metrics.get("exact_target_hit_records")),
        "generated_replays": _optional_int(metrics.get("generated_replays")),
        "ledger_events": _count_jsonl_lines(ledger_path),
        "agent_error": (
            str(payload.get("agent_error")) if payload.get("agent_error") else None
        ),
    }
    values["outcome_category"] = _classify_outcome(values)
    values["failure_category"] = _classify_failure(values)
    return DynamicRunSummary(**values)


def render_markdown_summary(summary: dict[str, Any]) -> str:
    runs = [
        DynamicRunSummary(**item)
        for item in summary.get("runs", [])
        if isinstance(item, dict)
    ]
    lines = [
        "# Dynamic experiment summary",
        "",
        (
            f"Root: `{summary.get('root', '')}`"
            if summary.get("root") is not None
            else "Roots: " + ", ".join(f"`{item}`" for item in summary.get("roots", []))
        ),
        "",
        f"Runs: {len(runs)}",
        "",
    ]
    if not runs:
        lines.append("No dynamic_validation.json files found.")
        return "\n".join(lines) + "\n"

    lines.extend([
        "## Aggregate by arm",
        "",
        "| Arm | Runs | Validated | Avg wall s | Avg tool calls | Exact target hits | Feedback consumed | Feedback unconsumed | Additional crash runs |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for arm, stats in sorted(summary.get("by_arm", {}).items()):
        lines.append(
            "| {arm} | {runs} | {validated} | {wall} | {tools} | {exact} | {consumed} | {unconsumed} | {additional} |".format(
                arm=arm,
                runs=stats.get("runs", 0),
                validated=stats.get("validated", 0),
                wall=_format_optional(stats.get("avg_dynamic_validation_s")),
                tools=_format_optional(stats.get("avg_tool_calls")),
                exact=stats.get("exact_target_hit_runs", 0),
                consumed=stats.get("feedback_consumed_runs", 0),
                unconsumed=stats.get("feedback_unconsumed_runs", 0),
                additional=stats.get("additional_crash_runs", 0),
            )
        )

    lines.extend([
        "",
        "## Failure categories by arm",
        "",
        "| Arm | Category | Runs |",
        "| --- | --- | ---: |",
    ])
    for arm, stats in sorted(summary.get("by_arm", {}).items()):
        categories = stats.get("failure_categories")
        if not isinstance(categories, dict) or not categories:
            lines.append(f"| {arm} | none | 0 |")
            continue
        for category, count in sorted(categories.items()):
            lines.append(f"| {arm} | {category} | {count} |")

    lines.extend([
        "",
        "## Aggregate by target and arm",
        "",
        "| Target | Arm | Runs | Validated | Avg wall s | Exact target hits | Feedback consumed | Dominant failure |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ])
    by_target = summary.get("by_target")
    if isinstance(by_target, dict) and by_target:
        for target, target_stats in sorted(by_target.items()):
            by_arm = (
                target_stats.get("by_arm")
                if isinstance(target_stats, dict)
                and isinstance(target_stats.get("by_arm"), dict)
                else {}
            )
            for arm, stats in sorted(by_arm.items()):
                if not isinstance(stats, dict):
                    continue
                lines.append(
                    "| {target} | {arm} | {runs} | {validated} | {wall} | {exact} | {consumed} | {failure} |".format(
                        target=target,
                        arm=arm,
                        runs=stats.get("runs", 0),
                        validated=stats.get("validated", 0),
                        wall=_format_optional(stats.get("avg_dynamic_validation_s")),
                        exact=stats.get("exact_target_hit_runs", 0),
                        consumed=stats.get("feedback_consumed_runs", 0),
                        failure=stats.get("dominant_failure_category") or "-",
                    )
                )
    else:
        lines.append("| - | - | 0 | 0 | - | 0 | 0 | - |")

    lines.extend([
        "",
        "## Runs",
        "",
        "| Arm | Target | Status | Outcome | Failure | Target site | PoC | Additional | Feedback | Ready/Read/Unconsumed | Wall s | Tools | Requests | Ledger | Directory |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ])
    for run in runs:
        feedback_counts = "{}/{}/{}".format(
            _format_optional(run.feedback_ready),
            _format_optional(run.feedback_ready_manually_read),
            _format_optional(run.feedback_ready_unconsumed),
        )
        lines.append(
            "| {arm} | {target} | {status} | {outcome} | {failure} | {site} | {poc} | {additional} | {feedback} | {feedback_counts} | {wall} | {tools} | {requests} | {ledger} | `{run_dir}` |".format(
                arm=run.arm,
                target=run.target,
                status=run.status,
                outcome=run.outcome_category,
                failure=run.failure_category,
                site=run.target_site_status,
                poc=run.poc_status,
                additional=run.additional_findings_status,
                feedback=run.feedback_quality_status,
                feedback_counts=feedback_counts,
                wall=_format_optional(run.dynamic_validation_s),
                tools=_format_optional(run.tool_calls),
                requests=_format_optional(run.execution_protocol_requests),
                ledger=run.ledger_events,
                run_dir=run.run_dir,
            )
        )
    return "\n".join(lines) + "\n"


def _aggregate_by_arm(runs: Iterable[DynamicRunSummary]) -> dict[str, dict[str, Any]]:
    buckets: dict[str, list[DynamicRunSummary]] = {}
    for run in runs:
        buckets.setdefault(run.arm, []).append(run)
    aggregate: dict[str, dict[str, Any]] = {}
    for arm, items in buckets.items():
        aggregate[arm] = {
            "runs": len(items),
            "validated": sum(1 for run in items if run.status == "validated"),
            "target_exact_reached_runs": sum(
                1 for run in items if run.target_site_status == "exact_reached"
            ),
            "exact_target_hit_runs": sum(
                1 for run in items if (run.exact_target_hit_records or 0) > 0
            ),
            "feedback_consumed_runs": sum(
                1 for run in items
                if run.feedback_quality_status in {"useful", "consumed_no_improvement"}
            ),
            "feedback_unconsumed_runs": sum(
                1 for run in items if (run.feedback_ready_unconsumed or 0) > 0
            ),
            "additional_crash_runs": sum(
                1
                for run in items
                if run.additional_crashes > 0
                or run.additional_findings_status not in {
                    "none",
                    "unknown",
                    "not_applicable",
                }
            ),
            "failure_categories": _count_categories(
                run.failure_category for run in items
            ),
            "avg_dynamic_validation_s": _mean_optional(
                run.dynamic_validation_s for run in items
            ),
            "avg_tool_calls": _mean_optional(run.tool_calls for run in items),
        }
    return aggregate


def _aggregate_by_target(runs: Iterable[DynamicRunSummary]) -> dict[str, dict[str, Any]]:
    buckets: dict[str, list[DynamicRunSummary]] = {}
    for run in runs:
        buckets.setdefault(run.target, []).append(run)
    aggregate: dict[str, dict[str, Any]] = {}
    for target, items in buckets.items():
        by_arm = _aggregate_by_arm(items)
        for stats in by_arm.values():
            if not isinstance(stats, dict):
                continue
            categories = stats.get("failure_categories")
            stats["dominant_failure_category"] = (
                _dominant_category(categories) if isinstance(categories, dict) else None
            )
        aggregate[target] = {
            "runs": len(items),
            "arms": sorted({run.arm for run in items}),
            "by_arm": by_arm,
            "failure_categories": _count_categories(
                run.failure_category for run in items
            ),
        }
    return aggregate


def _classify_outcome(values: dict[str, Any]) -> str:
    status = str(values.get("status") or "")
    target_site = str(values.get("target_site_status") or "")
    poc_status = str(values.get("poc_status") or "")
    grade_status = str(values.get("grade_status") or "")
    additional = str(values.get("additional_findings_status") or "")
    if status == "validated" or poc_status == "validated":
        return "validated_poc"
    if grade_status not in {"", "not_run", "unknown", "passed"}:
        return "grade_issue"
    if additional not in {"", "none", "unknown", "not_applicable"}:
        return "additional_finding"
    if target_site == "exact_reached":
        return "target_reached_no_poc"
    if target_site in {"function_only", "block_only", "region_only"}:
        return "target_approach_only"
    if status in {"agent_blocked", "agent_failed", "invalid_submission"}:
        return "protocol_or_agent_failure"
    return "no_validated_poc"


def _classify_failure(values: dict[str, Any]) -> str:
    status = str(values.get("status") or "")
    outcome = str(values.get("outcome_category") or "")
    target_site = str(values.get("target_site_status") or "")
    poc_status = str(values.get("poc_status") or "")
    feedback_quality = str(values.get("feedback_quality_status") or "")
    feedback_ready = values.get("feedback_ready")
    feedback_read = values.get("feedback_ready_manually_read")
    feedback_unconsumed = values.get("feedback_ready_unconsumed")
    requests = values.get("execution_protocol_requests")
    agent_error = values.get("agent_error")

    if outcome == "validated_poc":
        return "none"
    if outcome == "additional_finding":
        return "additional_finding_not_original_candidate"
    if poc_status == "invalid_submission" or status == "invalid_submission":
        return "submission_failure"
    if status in {"agent_blocked", "agent_failed"} or agent_error:
        return "agent_blocked_or_failed"
    if requests == 0:
        return "no_protocol_input"
    if feedback_unconsumed and feedback_unconsumed > 0:
        return "feedback_ready_unconsumed"
    if feedback_quality == "unavailable" and feedback_ready == 0:
        return "feedback_unavailable_or_not_ready"
    if feedback_ready and (feedback_read or 0) == 0:
        return "feedback_ready_not_read"
    if target_site == "exact_reached":
        return "target_reached_but_no_poc"
    if target_site in {"function_only", "block_only", "region_only"}:
        return "target_approach_only"
    if status in {
        "iteration_exhausted",
        "not_reached",
        "false_positive",
        "reached_no_crash",
        "reached_no_effect",
    }:
        return "no_target_evidence"
    return "unknown"


def _count_categories(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _dominant_category(categories: dict[str, int]) -> str | None:
    if not categories:
        return None
    return sorted(categories.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _read_optional_json(path: Path) -> dict[str, Any]:
    return _read_json(path) if path.is_file() else {}


def _infer_target_from_path(run_dir: Path) -> str:
    for part in reversed(run_dir.parts):
        if part.startswith("dynamic-"):
            continue
        if part in {"off", "feedback", "symcc", "baseline", "control"}:
            continue
        return part
    return "unknown"


def _infer_arm(run_dir: Path, symbolic: dict[str, Any]) -> str:
    parts = {part.lower() for part in run_dir.parts}
    if "off" in parts or "baseline" in parts or "control" in parts:
        return "off"
    provider = str(symbolic.get("provider") or "").lower()
    if provider or "feedback" in parts or "symcc" in parts:
        if "symcc" in provider or "symcc" in parts or "feedback" in parts:
            return "feedback"
        return provider
    return "off"


def _optional_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return round(float(value), 3)


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _count_jsonl_lines(path: Path) -> int:
    try:
        with path.open() as stream:
            return sum(1 for line in stream if line.strip())
    except OSError:
        return 0


def _mean_optional(values: Iterable[int | float | None]) -> float | None:
    items = [float(value) for value in values if value is not None]
    if not items:
        return None
    return round(statistics.fmean(items), 3)


def _format_optional(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return str(value)
