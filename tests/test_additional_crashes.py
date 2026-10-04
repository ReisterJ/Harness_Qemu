"""Independent crash submissions remain separate from the primary candidate."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from harness.agent import AgentResult
from harness.artifacts import (
    AdditionalCrashSubmission,
    AdditionalFindingResult,
    CrashArtifact,
    GraderVerdict,
    RunResult,
)
from harness.cli import _grade_additional_crashes
from harness.config import TargetConfig
from harness.dynamic_validation import _collect_additional_crashes
from harness.prompts.dynamic_validation_prompt import build_dynamic_validation_prompt
from harness.artifacts import StaticFinding


def _entry(finding_id="extra-001"):
    path = f"/work/validation/additional-crashes/{finding_id}/poc.bin"
    return {
        "finding_id": finding_id,
        "summary": "independent invalid crop-window length",
        "poc_path": path,
        "reproduction_command": f"/out/target {path}",
        "poc_kind": "file",
        "crash_type": "negative-size-param",
        "exit_code": 134,
        "crash_output": "AddressSanitizer: negative-size-param (size=-2)",
        "dup_check": "Different root cause and top frame from the primary candidate.",
    }


def test_additional_crash_parser_accepts_separate_valid_submission(monkeypatch):
    manifest = (json.dumps(_entry()) + "\n").encode()
    poc = b"reproducer input"

    def fake_exec(_container, command, **_kwargs):
        if command == "test -f /work/validation/additional-crashes.jsonl":
            return 0, "", ""
        if command == "test ! -L /work/validation/additional-crashes.jsonl":
            return 0, "", ""
        if command.startswith("stat -c %s"):
            return 0, str(len(manifest) if command.endswith("additional-crashes.jsonl") else len(poc)), ""
        if "test -f" in command and "poc.bin" in command:
            return 0, "", ""
        raise AssertionError(command)

    def fake_read(_container, path):
        if path.endswith("additional-crashes.jsonl"):
            return manifest
        if path.endswith("poc.bin"):
            return poc
        raise AssertionError(path)

    monkeypatch.setattr("harness.dynamic_validation.docker_ops.exec_sh", fake_exec)
    monkeypatch.setattr("harness.dynamic_validation.docker_ops.read_file", fake_read)

    findings, errors = _collect_additional_crashes("find-test", "asan")

    assert errors == []
    assert len(findings) == 1
    assert findings[0].finding_id == "extra-001"
    assert findings[0].crash.poc_bytes == poc
    assert findings[0].crash.crash_type == "negative-size-param"


def test_additional_crash_parser_rejects_path_escape(monkeypatch):
    entry = _entry("../outside")
    manifest = (json.dumps(entry) + "\n").encode()

    def fake_exec(_container, command, **_kwargs):
        if command == "test -f /work/validation/additional-crashes.jsonl":
            return 0, "", ""
        if command == "test ! -L /work/validation/additional-crashes.jsonl":
            return 0, "", ""
        if command.startswith("stat -c %s"):
            return 0, str(len(manifest)), ""
        raise AssertionError(command)

    monkeypatch.setattr("harness.dynamic_validation.docker_ops.exec_sh", fake_exec)
    monkeypatch.setattr(
        "harness.dynamic_validation.docker_ops.read_file", lambda *_: manifest
    )

    findings, errors = _collect_additional_crashes("find-test", "asan")
    assert findings == []
    assert any("invalid finding_id" in error for error in errors)


def test_dynamic_prompt_separates_incidental_crash_from_primary_candidate():
    finding = StaticFinding(
        candidate_id="candidate-1",
        bug_class="heap-buffer-overflow",
        location="decoder.c:10",
        static_call_chain="input -> decode",
        entry_points="file input",
        attacker_controlled_data="length",
        reachability_evidence="main calls decode",
        required_conditions="oversized length",
        root_cause="missing bounds check",
        verification_plan="submit malformed input",
        confidence=0.9,
    )
    prompt = build_dynamic_validation_prompt(
        candidate=finding,
        github_url="https://example.test/repo",
        commit="abc",
        source_root="/src",
        binary_path="/out/target",
        detector="asan",
    )
    assert "additional-crashes.jsonl" in prompt
    assert "A side finding never makes the primary candidate pass or fail" in prompt
    assert '"reproduction_command":"/out/target ' in prompt


def test_additional_crash_is_graded_independently_and_persisted(tmp_path, monkeypatch):
    target = TargetConfig.load(Path(__file__).resolve().parents[1] / "targets" / "canary")
    crash = CrashArtifact(
        poc_path="/work/validation/additional-crashes/extra-001/poc.bin",
        poc_bytes=b"input",
        reproduction_command=(
            "/work/entry /work/validation/additional-crashes/extra-001/poc.bin"
        ),
        crash_type="heap-buffer-overflow",
        crash_output="ASan trace in target source",
        exit_code=134,
        dup_check="different top frame",
    )
    submission = AdditionalCrashSubmission(
        finding_id="extra-001", summary="a separate target crash", crash=crash
    )
    calls = []

    async def fake_grade(_crash, _target, **kwargs):
        calls.append(kwargs)
        return (
            GraderVerdict(True, 1.0, {"reproduces": True}, "3/3 reproduced"),
            AgentResult(messages=[], result_message="grade"),
            12.0,
        )

    monkeypatch.setattr("harness.cli.run_grade", fake_grade)
    results = asyncio.run(_grade_additional_crashes(
        [submission],
        target=target,
        model="test-model",
        agent_env={},
        out_dir=tmp_path,
        run_idx=1,
        system_prompt=None,
        grade=True,
        found_bugs_path=None,
    ))

    assert len(results) == 1
    assert results[0].status == "crash_found"
    assert results[0].verdict is not None and results[0].verdict.passed
    assert calls[0]["static_finding"] is None
    finding_dir = tmp_path / "additional_findings" / "extra-001"
    assert (finding_dir / "poc.bin").read_bytes() == b"input"
    assert json.loads((finding_dir / "result.json").read_text())["status"] == "crash_found"


def test_additional_finding_result_roundtrip():
    crash = CrashArtifact(
        poc_path="/tmp/poc", poc_bytes=b"x", reproduction_command="/out/target /tmp/poc",
        crash_type="SEGV", crash_output="target trace", exit_code=139,
    )
    original = AdditionalFindingResult(
        finding_id="extra-1", summary="independent crash", crash=crash,
        status="crash_found", verdict=GraderVerdict(True, 1.0, {}, "reproduced"),
    )
    restored = AdditionalFindingResult.from_dict(original.to_dict())
    assert restored.crash == crash
    assert restored.verdict is not None and restored.verdict.passed


def test_run_result_roundtrip_keeps_supplemental_finding():
    crash = CrashArtifact(
        poc_path="/tmp/poc", poc_bytes=b"x", reproduction_command="/out/target /tmp/poc",
        crash_type="SEGV", crash_output="target trace", exit_code=139,
    )
    extra = AdditionalFindingResult(
        finding_id="extra-1", summary="independent crash", crash=crash,
        status="crash_found", verdict=GraderVerdict(True, 1.0, {}, "reproduced"),
    )
    result = RunResult(
        target="target", status="no_crash_found", crash=None, verdict=None,
        additional_findings=[extra],
    )
    restored = RunResult.from_json(result.to_json())
    assert restored.status == "no_crash_found"
    assert restored.additional_findings == [extra]
