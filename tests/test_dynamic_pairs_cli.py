import argparse
import json
from pathlib import Path

from harness import cli


def _write_fake_dynamic_result(root: Path, *, arm: str) -> None:
    run_dir = root / "fake-target" / f"dynamic-{arm}"
    run_dir.mkdir(parents=True)
    symbolic = None
    if arm == "feedback":
        symbolic = {
            "provider": "symcc-prebuilt",
            "requests": 1,
            "feedback_ready": 1,
            "feedback_ready_manually_read": 1,
            "feedback_ready_unconsumed": 0,
            "metrics": {"exact_target_hit_records": 0, "generated_replays": 2},
        }
        (run_dir / "symbolic_execution").mkdir()
        (run_dir / "symbolic_execution" / "summary.json").write_text(
            json.dumps(symbolic, indent=2) + "\n"
        )
    (run_dir / "dynamic_validation.json").write_text(
        json.dumps(
            {
                "phase": "dynamic_validation",
                "candidate": {"candidate_id": "candidate_001"},
                "result": {
                    "candidate_id": "candidate_001",
                    "status": "iteration_exhausted",
                    "iterations": [],
                    "additional_crashes": [],
                    "symbolic_execution": symbolic,
                    "status_breakdown": {
                        "target_site_status": "unknown",
                        "poc_status": "no_poc",
                        "grade_status": "not_run",
                        "additional_findings_status": "none",
                        "feedback_quality_status": (
                            "consumed_no_improvement"
                            if arm == "feedback" else "unavailable"
                        ),
                    },
                },
                "timings": {
                    "dynamic_validation": 10.0 if arm == "feedback" else 12.0,
                    "dynamic_agent_tool_calls": 5.0,
                },
                "agent_error": None,
            },
            indent=2,
        )
        + "\n"
    )


def test_dynamic_pairs_runs_off_and_feedback_and_writes_summary(tmp_path, monkeypatch):
    calls: list[tuple[str, str, str]] = []

    def fake_dynamic(run_args):
        arm = Path(run_args.results_dir).name
        calls.append((arm, run_args.symbolic_execution, run_args.supervisor))
        _write_fake_dynamic_result(Path(run_args.results_dir), arm=arm)
        return 2

    monkeypatch.setattr(cli, "_cmd_dynamic", fake_dynamic)
    args = argparse.Namespace(
        target="fake-target",
        static_report=tmp_path / "static_analysis.json",
        candidate_id=None,
        model="test-model",
        runs=1,
        arms=("off", "feedback"),
        max_turns=20000,
        phase_timeout=3600.0,
        max_iterations=8,
        supervisor="rules",
        results_dir=str(tmp_path),
        experiment_name="paired",
        resume=False,
        instrumentation=None,
        docker_params=None,
        dangerously_no_sandbox=True,
        engagement_context=None,
    )

    rc = cli._cmd_dynamic_pairs(args)

    assert rc == 0
    assert calls == [("off", "off", "rules"), ("feedback", "symcc", "rules")]
    manifest = json.loads((tmp_path / "paired" / "manifest.json").read_text())
    assert manifest["runs"] == 1
    assert manifest["supervisor"] == "rules"
    assert manifest["pairs"][0]["arm"] == "off"
    assert manifest["pairs"][1]["arm"] == "feedback"
    summary = json.loads((tmp_path / "paired" / "summary.json").read_text())
    assert summary["run_count"] == 2
    assert summary["by_arm"]["off"]["runs"] == 1
    assert summary["by_arm"]["feedback"]["feedback_consumed_runs"] == 1
    markdown = (tmp_path / "paired" / "summary.md").read_text()
    assert "| feedback | 1 | 0 | 10" in markdown


def test_dynamic_pairs_resume_skips_existing_arm_and_runs_missing_arm(tmp_path, monkeypatch):
    calls: list[tuple[str, str, str]] = []
    existing_off_root = tmp_path / "paired" / "pair-1" / "off"
    _write_fake_dynamic_result(existing_off_root, arm="off")

    def fake_dynamic(run_args):
        arm = Path(run_args.results_dir).name
        calls.append((arm, run_args.symbolic_execution, run_args.supervisor))
        _write_fake_dynamic_result(Path(run_args.results_dir), arm=arm)
        return 2

    monkeypatch.setattr(cli, "_cmd_dynamic", fake_dynamic)
    args = argparse.Namespace(
        target="fake-target",
        static_report=tmp_path / "static_analysis.json",
        candidate_id=None,
        model="test-model",
        runs=1,
        arms=("off", "feedback"),
        max_turns=20000,
        phase_timeout=3600.0,
        max_iterations=8,
        supervisor="rules",
        results_dir=str(tmp_path),
        experiment_name="paired",
        resume=True,
        instrumentation=None,
        docker_params=None,
        dangerously_no_sandbox=True,
        engagement_context=None,
    )

    rc = cli._cmd_dynamic_pairs(args)

    assert rc == 0
    assert calls == [("feedback", "symcc", "rules")]
    manifest = json.loads((tmp_path / "paired" / "manifest.json").read_text())
    assert manifest["resume"] is True
    assert manifest["pairs"][0]["arm"] == "off"
    assert manifest["pairs"][0]["skipped"] is True
    assert manifest["pairs"][0]["existing_dynamic_results"]
    assert manifest["pairs"][1]["arm"] == "feedback"
    assert manifest["pairs"][1]["skipped"] is False
    summary = json.loads((tmp_path / "paired" / "summary.json").read_text())
    assert summary["run_count"] == 2
    assert summary["by_arm"]["off"]["runs"] == 1
    assert summary["by_arm"]["feedback"]["runs"] == 1


def test_plan_dynamic_pairs_command_includes_supervisor(tmp_path):
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    static_report = tmp_path / "static.json"
    static_report.write_text('{"findings": []}\n')
    command, errors = cli._dynamic_pairs_command_from_matrix_item(
        {
            "id": "sample",
            "target_path": str(target_dir),
            "static_report": str(static_report),
            "experiment_name": "sample-exp",
        },
        model="deepseek-flash",
        runs=3,
        phase_timeout=3600.0,
        max_iterations=8,
        supervisor="rules",
        results_dir="results/experiments",
        resume=True,
        include_no_sandbox=True,
    )

    assert errors == []
    assert command is not None
    assert "--supervisor rules" in command
    assert "--resume" in command
    assert "--dangerously-no-sandbox" in command
