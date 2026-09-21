"""Tests for provider-neutral dynamic instrumentation contracts."""
from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from harness.agent import AgentResult
from harness.artifacts import StaticFinding
from harness.config import TargetConfig
from harness.instrumentation import (
    ExecutionFeedback,
    InstrumentationReport,
    input_sha256,
    select_provider,
)
from harness.instrumentation.llvm import LLVMProvider
from harness.dynamic_validation import run_dynamic_validation
from harness.cli import _load_static_findings


def _assistant(text: str) -> dict:
    return {
        "type": "text",
        "sessionID": "s",
        "part": {"type": "text", "messageID": "m", "text": text},
    }


def _finding() -> StaticFinding:
    return StaticFinding(
        candidate_id="candidate_001",
        bug_class="heap-buffer-overflow",
        location="src/parser.c:12",
        static_call_chain="input -> parser -> sink",
        entry_points="file input",
        attacker_controlled_data="length field",
        reachability_evidence="main calls parser",
        required_conditions="malformed length",
        root_cause="missing bounds check",
        verification_plan="craft truncated input",
        confidence=0.9,
    )


def test_feedback_round_trip_is_bounded_and_provider_neutral():
    event = ExecutionFeedback(
        provider="llvm",
        run_id="probe",
        input_sha256=input_sha256(b"input"),
        status="completed",
        capabilities=("functions",),
        reached_functions=("main",),
        stdout="x" * 30_000,
    )
    decoded = ExecutionFeedback.from_dict(event.to_dict())
    assert decoded.reached_functions == ("main",)
    assert decoded.stdout.endswith("…[truncated]")
    with pytest.raises(ValueError, match="SHA-256"):
        ExecutionFeedback.from_dict({"provider": "x", "run_id": "r", "input_sha256": "bad", "status": "completed"})


def test_provider_selection_uses_manifest_and_cli_override():
    assert select_provider("off", {"default": "llvm", "providers": ["llvm"]}) is None
    assert select_provider(None, {"default": "llvm", "providers": ["llvm"]}).name == "llvm"
    assert select_provider(None, {}).name == "llvm"
    assert select_provider("llvm", {"default": "off", "providers": []}).name == "llvm"
    assert select_provider("auto", {"default": "auto", "providers": ["missing"]}) is None


def test_static_report_loader_accepts_pipeline_report(tmp_path):
    report = tmp_path / "static_analysis.json"
    report.write_text(json.dumps({"findings": [_finding().to_dict()]}))
    findings, error = _load_static_findings(report)
    assert error is None
    assert findings == [_finding()]


def test_llvm_prepare_installs_only_the_container_contract(monkeypatch):
    writes: dict[str, bytes] = {}

    monkeypatch.setattr(
        "harness.instrumentation.llvm.docker_ops.exec_sh",
        lambda *_args, **_kwargs: (0, "", ""),
    )
    monkeypatch.setattr(
        "harness.instrumentation.llvm.docker_ops.write_file",
        lambda _container, path, content: writes.__setitem__(path, content),
    )
    report = LLVMProvider().prepare(
        "container",
        source_root="/work/src",
        binary_path="/work/entry",
        candidate=_finding().to_dict(),
    )
    assert report.status == "ready"
    assert report.manifest["candidate_id"] == "candidate_001"
    assert set(writes) == {
        "/work/instrumentation/provider.json",
        "/work/instrumentation/run",
        "/work/instrumentation/normalize.py",
        "/work/instrumentation/README.md",
    }
    assert b"LLVM_PROFILE_FILE" in writes["/work/instrumentation/run"]
    assert b"does not prove a vulnerability" in writes["/work/instrumentation/README.md"]


def test_llvm_collect_normalizes_events(monkeypatch):
    event = {
        "schema_version": 1,
        "provider": "llvm",
        "run_id": "trigger",
        "input_sha256": input_sha256(b"trigger"),
        "status": "completed",
        "exit_code": 0,
        "duration_ms": 3,
        "capabilities": ["functions"],
        "reached_functions": ["xmlXIncludeLoadTxt"],
        "reached_locations": [],
        "edges": [], "branches": [], "comparisons": [],
        "stdout": "ok", "stderr": "", "errors": [],
        "raw_artifacts": ["/work/instrumentation/runs/trigger/coverage.json"],
    }
    monkeypatch.setattr(
        "harness.instrumentation.llvm.docker_ops.exec_sh",
        lambda *_args, **_kwargs: (0, "", ""),
    )
    monkeypatch.setattr(
        "harness.instrumentation.llvm.docker_ops.read_file",
        lambda *_args, **_kwargs: (json.dumps(event) + "\n").encode(),
    )
    report = LLVMProvider().collect("container", {"provider": "llvm"})
    assert report.status == "collected"
    assert report.feedback[0].reached_functions == ("xmlXIncludeLoadTxt",)


def test_dynamic_validation_persists_provider_report(tmp_path, monkeypatch):
    target = TargetConfig.load(Path(__file__).resolve().parents[1] / "targets" / "canary")
    candidate = _finding()
    event = ExecutionFeedback(
        provider="fake",
        run_id="probe",
        input_sha256=input_sha256(b"probe"),
        status="completed",
        capabilities=("functions",),
        reached_functions=("provider_parse",),
    )

    class Provider:
        name = "fake"

        def prepare(self, *_args, **_kwargs):
            return InstrumentationReport(
                provider="fake", status="ready", capabilities=("functions",),
                manifest={"provider": "fake"},
            )

        def collect(self, *_args, **_kwargs):
            return InstrumentationReport(
                provider="fake", status="collected", capabilities=("functions",),
                manifest={"provider": "fake"}, feedback=(event,),
            )

    class FakeSession:
        container = "fake-container"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    message = """<dynamic_status>validated</dynamic_status>
<candidate_id>candidate_001</candidate_id>
<reached_functions></reached_functions>
<reachability_evidence>provider report</reachability_evidence>
<poc_path>/tmp/poc.bin</poc_path>
<reproduction_command>/work/entry /tmp/poc.bin</reproduction_command>
<poc_kind>file</poc_kind><crash_type>heap-buffer-overflow</crash_type>
<exit_code>134</exit_code><crash_output>asan</crash_output>
<dup_check>unique</dup_check>"""

    monkeypatch.setattr("harness.dynamic_validation.select_provider", lambda *_args: Provider())
    monkeypatch.setattr("harness.dynamic_validation.open_runtime_session", lambda *a, **k: FakeSession())
    monkeypatch.setattr(
        "harness.dynamic_validation.run_agent",
        lambda **_kwargs: asyncio.sleep(0, result=AgentResult(messages=[_assistant(message)], result_message=message)),
    )
    monkeypatch.setattr(
        "harness.dynamic_validation.docker_ops.exec_sh",
        lambda *_args, **_kwargs: (0, "", ""),
    )
    monkeypatch.setattr(
        "harness.dynamic_validation._collect_iteration_records",
        lambda *_args: ([{
            "schema_version": 1,
            "round_id": 1,
            "candidate_id": "candidate_001",
            "observations": {
                "site_reached": True,
                "sanitizer_event": True,
                "matched_candidate": True,
            },
            "decision": "candidate_ready",
        }], []),
    )
    def fake_read_file(_container, path):
        if path.endswith("crash-result.xml"):
            return b'''<?xml version="1.0" encoding="UTF-8"?>
<crash_result schema_version="1">
  <candidate_id>candidate_001</candidate_id>
  <poc_path>/tmp/poc.bin</poc_path>
  <reproduction_command>/work/entry /tmp/poc.bin</reproduction_command>
  <poc_kind>file</poc_kind>
  <crash_type>heap-buffer-overflow</crash_type>
  <exit_code>134</exit_code>
  <crash_output>asan</crash_output>
  <dup_check>unique</dup_check>
</crash_result>
'''
        return b"poc"

    monkeypatch.setattr("harness.dynamic_validation.docker_ops.read_file", fake_read_file)
    result, _agent, _timings = asyncio.run(
        run_dynamic_validation(
            target, candidate, model="m", max_turns=2, instrumentation="llvm",
            instrumentation_result_path=str(tmp_path / "instrumentation"),
        )
    )
    assert result.instrumentation["status"] == "collected"
    assert result.crash is not None
    assert json.loads((tmp_path / "instrumentation" / "summary.json").read_text())["feedback"][0]["run_id"] == "probe"
    assert result.reachability_evidence == "provider report"
    assert result.reached_functions == ["provider_parse"]


def test_dynamic_validation_collects_bounded_iteration_records(tmp_path, monkeypatch):
    target = TargetConfig.load(Path(__file__).resolve().parents[1] / "targets" / "canary")
    candidate = _finding()
    round_record = {
        "schema_version": 1,
        "round_id": 1,
        "candidate_id": "candidate_001",
        "hypothesis": {"target_site": "src/parser.c:12"},
        "observations": {
            "site_reached": True,
            "sanitizer_event": True,
            "matched_candidate": True,
        },
        "decision": "candidate_ready",
        "reason": "matching sanitizer event",
    }
    message = """<dynamic_status>validated</dynamic_status>
<candidate_id>candidate_001</candidate_id>
<reached_functions>parse</reached_functions>
<reachability_evidence>round evidence</reachability_evidence>
<poc_path>/tmp/poc.bin</poc_path>
<reproduction_command>/work/entry /tmp/poc.bin</reproduction_command>
<poc_kind>file</poc_kind><crash_type>heap-buffer-overflow</crash_type>
<exit_code>134</exit_code><crash_output>asan</crash_output>
<dup_check>unique</dup_check>"""

    class FakeSession:
        container = "fake-container"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_read_file(_container, path):
        if path.endswith("round-001.json"):
            return (json.dumps(round_record) + "\n").encode()
        if path.endswith("crash-result.xml"):
            return b'''<?xml version="1.0" encoding="UTF-8"?>
<crash_result schema_version="1">
  <candidate_id>candidate_001</candidate_id>
  <poc_path>/tmp/poc.bin</poc_path>
  <reproduction_command>/work/entry /tmp/poc.bin</reproduction_command>
  <poc_kind>file</poc_kind>
  <crash_type>heap-buffer-overflow</crash_type>
  <exit_code>134</exit_code>
  <crash_output>asan</crash_output>
  <dup_check>unique</dup_check>
</crash_result>
'''
        return b"poc"

    monkeypatch.setattr("harness.dynamic_validation.open_runtime_session", lambda *a, **k: FakeSession())
    monkeypatch.setattr("harness.dynamic_validation.run_agent", lambda **_kwargs: asyncio.sleep(
        0, result=AgentResult(messages=[_assistant(message)], result_message=message)
    ))
    monkeypatch.setattr(
        "harness.dynamic_validation.docker_ops.exec_sh",
        lambda *_args, **_kwargs: (0, "/work/validation/iterations/round-001.json\n", ""),
    )
    monkeypatch.setattr("harness.dynamic_validation.docker_ops.write_file", lambda *_args: None)
    monkeypatch.setattr("harness.dynamic_validation.docker_ops.read_file", fake_read_file)

    result, _agent, _timings = asyncio.run(
        run_dynamic_validation(
            target,
            candidate,
            model="m",
            max_turns=2,
            instrumentation="off",
            instrumentation_result_path=str(tmp_path / "instrumentation"),
            max_iterations=4,
        )
    )

    assert result.status == "validated"
    assert result.iterations[0]["decision"] == "candidate_ready"
    assert (tmp_path / "iterations" / "round-001.json").exists()
    summary = json.loads((tmp_path / "iterations" / "summary.json").read_text())
    assert summary["count"] == 1
