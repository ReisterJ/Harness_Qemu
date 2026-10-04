import json
from pathlib import Path

from harness.experiment_summary import (
    load_dynamic_run_summary,
    render_markdown_summary,
    summarize_experiment_tree,
)


def _write_dynamic_result(
    run_dir: Path,
    *,
    status: str,
    arm: str,
    target_site_status: str,
    feedback_quality_status: str,
    dynamic_validation_s: float,
    tool_calls: int,
) -> None:
    run_dir.mkdir(parents=True)
    symbolic = {}
    if arm == "feedback":
        symbolic = {
            "provider": "symcc-prebuilt",
            "requests": 1,
            "feedback_ready": 1,
            "feedback_ready_manually_read": 1,
            "feedback_ready_unconsumed": 0,
            "first_request_policy": {"first_request_tool_calls": 20},
            "metrics": {
                "exact_target_hit_records": 0,
                "generated_replays": 8,
            },
        }
        symbolic_dir = run_dir / "symbolic_execution"
        symbolic_dir.mkdir()
        (symbolic_dir / "summary.json").write_text(
            json.dumps(symbolic, indent=2) + "\n"
        )
        (run_dir / "evidence_ledger.jsonl").write_text(
            '{"event":"execution_request_accepted"}\n'
            '{"event":"symcc_feedback_ready"}\n'
        )
    payload = {
        "phase": "dynamic_validation",
        "candidate": {"candidate_id": "candidate_001"},
        "result": {
            "candidate_id": "candidate_001",
            "status": status,
            "iterations": [{"round_id": 1}],
            "additional_crashes": [],
            "symbolic_execution": symbolic if symbolic else None,
            "status_breakdown": {
                "target_site_status": target_site_status,
                "poc_status": "no_poc",
                "grade_status": "not_run",
                "additional_findings_status": "none",
                "feedback_quality_status": feedback_quality_status,
            },
        },
        "timings": {
            "dynamic_validation": dynamic_validation_s,
            "dynamic_agent_tool_calls": float(tool_calls),
            "dynamic_agent_messages": 3.0,
        },
        "agent_error": None,
    }
    (run_dir / "dynamic_validation.json").write_text(
        json.dumps(payload, indent=2) + "\n"
    )


def test_load_dynamic_run_summary_reads_breakdown_and_symcc_metrics(tmp_path):
    run_dir = tmp_path / "feedback" / "mruby" / "dynamic-001"
    _write_dynamic_result(
        run_dir,
        status="iteration_exhausted",
        arm="feedback",
        target_site_status="function_only",
        feedback_quality_status="consumed_no_improvement",
        dynamic_validation_s=247.256,
        tool_calls=43,
    )

    summary = load_dynamic_run_summary(run_dir / "dynamic_validation.json")

    assert summary.arm == "feedback"
    assert summary.target == "mruby"
    assert summary.status == "iteration_exhausted"
    assert summary.target_site_status == "function_only"
    assert summary.feedback_quality_status == "consumed_no_improvement"
    assert summary.outcome_category == "target_approach_only"
    assert summary.failure_category == "target_approach_only"
    assert summary.execution_protocol_requests == 1
    assert summary.feedback_ready == 1
    assert summary.first_request_tool_calls == 20
    assert summary.generated_replays == 8
    assert summary.ledger_events == 2


def test_summarize_experiment_tree_groups_by_arm_and_renders_markdown(tmp_path):
    _write_dynamic_result(
        tmp_path / "off" / "mruby" / "dynamic-001",
        status="reached_no_crash",
        arm="off",
        target_site_status="unknown",
        feedback_quality_status="unavailable",
        dynamic_validation_s=342.918,
        tool_calls=70,
    )
    _write_dynamic_result(
        tmp_path / "feedback" / "mruby" / "dynamic-002",
        status="iteration_exhausted",
        arm="feedback",
        target_site_status="function_only",
        feedback_quality_status="consumed_no_improvement",
        dynamic_validation_s=247.257,
        tool_calls=43,
    )

    summary = summarize_experiment_tree(tmp_path)
    assert summary["run_count"] == 2
    assert summary["by_arm"]["off"]["runs"] == 1
    assert summary["by_arm"]["feedback"]["runs"] == 1
    assert summary["by_arm"]["feedback"]["feedback_consumed_runs"] == 1
    assert summary["by_arm"]["feedback"]["feedback_unconsumed_runs"] == 0
    assert summary["by_arm"]["feedback"]["additional_crash_runs"] == 0
    assert summary["by_arm"]["feedback"]["failure_categories"] == {
        "target_approach_only": 1
    }
    assert summary["by_arm"]["off"]["failure_categories"] == {
        "no_target_evidence": 1
    }
    assert summary["by_arm"]["off"]["avg_tool_calls"] == 70.0
    assert summary["by_target"]["mruby"]["runs"] == 2
    assert summary["by_target"]["mruby"]["arms"] == ["feedback", "off"]
    assert summary["by_target"]["mruby"]["by_arm"]["feedback"]["runs"] == 1
    assert (
        summary["by_target"]["mruby"]["by_arm"]["feedback"][
            "dominant_failure_category"
        ]
        == "target_approach_only"
    )

    markdown = render_markdown_summary(summary)
    assert "| feedback | 1 | 0 | 247.257 | 43 | 0 | 1 | 0 | 0 |" in markdown
    assert "| feedback | target_approach_only | 1 |" in markdown
    assert (
        "| feedback | mruby | iteration_exhausted | target_approach_only | "
        "target_approach_only | function_only | no_poc | none | "
        "consumed_no_improvement | 1/1/0 | 247.257 | 43 | 1 | 2 |"
    ) in markdown
    assert "`" in markdown and "dynamic_validation.json" not in markdown


def test_summarize_experiment_tree_groups_multiple_targets_by_target_and_arm(tmp_path):
    _write_dynamic_result(
        tmp_path / "mruby" / "off" / "dynamic-001",
        status="iteration_exhausted",
        arm="off",
        target_site_status="unknown",
        feedback_quality_status="unavailable",
        dynamic_validation_s=300.0,
        tool_calls=50,
    )
    _write_dynamic_result(
        tmp_path / "mruby" / "feedback" / "dynamic-002",
        status="iteration_exhausted",
        arm="feedback",
        target_site_status="function_only",
        feedback_quality_status="consumed_no_improvement",
        dynamic_validation_s=200.0,
        tool_calls=40,
    )
    _write_dynamic_result(
        tmp_path / "arvo" / "feedback" / "dynamic-003",
        status="agent_blocked",
        arm="feedback",
        target_site_status="unknown",
        feedback_quality_status="unavailable",
        dynamic_validation_s=3600.0,
        tool_calls=120,
    )

    summary = summarize_experiment_tree(tmp_path)

    assert summary["run_count"] == 3
    assert summary["by_target"]["mruby"]["runs"] == 2
    assert summary["by_target"]["arvo"]["runs"] == 1
    assert summary["by_target"]["arvo"]["arms"] == ["feedback"]
    assert (
        summary["by_target"]["arvo"]["by_arm"]["feedback"][
            "dominant_failure_category"
        ]
        == "agent_blocked_or_failed"
    )
    markdown = render_markdown_summary(summary)
    assert "## Aggregate by target and arm" in markdown
    assert "| arvo | feedback | 1 | 0 | 3600 | 0 | 0 | agent_blocked_or_failed |" in markdown
    assert "| mruby | feedback | 1 | 0 | 200 | 0 | 1 | target_approach_only |" in markdown
