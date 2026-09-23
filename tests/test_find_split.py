"""Tests for the split static-analysis/dynamic-validation find contract."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from harness.agent import AgentResult
from harness.artifacts import CrashArtifact, DynamicValidationResult, LogicArtifact, StaticFinding
from harness.config import TargetConfig
from harness.find import FindPhaseResult, run_find
from harness.dynamic_validation import (
    _bound_iteration,
    _has_candidate_ready_iteration,
    _normalize_poc_kind,
    _status_for_missing_poc_submission,
    _status_without_iteration_records,
    run_dynamic_validation,
)
from harness.prompts.dynamic_validation_prompt import build_dynamic_validation_prompt
from harness.prompts.static_analysis_prompt import build_static_analysis_prompt
from harness.static_analysis import parse_static_findings


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
        static_call_chain="input -> parse -> copy",
        entry_points="file input",
        attacker_controlled_data="length field",
        reachability_evidence="main calls parse",
        required_conditions="malformed length",
        root_cause="missing bounds check",
        verification_plan="craft truncated input",
        confidence=0.9,
    )


def _crash_result_xml() -> bytes:
    return b'''<?xml version="1.0" encoding="UTF-8"?>
<crash_result schema_version="1">
  <candidate_id>candidate_001</candidate_id>
  <poc_path>/work/poc.rb</poc_path>
  <reproduction_command>/out/mruby_fuzzer /work/poc.rb</reproduction_command>
  <poc_kind>crash</poc_kind>
  <crash_type>heap-use-after-free</crash_type>
  <exit_code>1</exit_code>
  <crash_output>AddressSanitizer: heap-use-after-free</crash_output>
  <dup_check>Distinct target candidate</dup_check>
</crash_result>
'''


def test_static_findings_parser_accepts_structured_json():
    finding = _finding().to_dict()
    parsed, error = parse_static_findings(
        "analysis\n<static_findings>\n" + json.dumps([finding]) + "\n</static_findings>"
    )
    assert error is None
    assert parsed == [_finding()]


def test_static_findings_parser_rejects_malformed_payload():
    parsed, error = parse_static_findings("<static_findings>{not-json}</static_findings>")
    assert parsed == []
    assert "invalid static findings JSON" in (error or "")


def test_dynamic_prompt_contains_candidate_and_no_static_result_is_grade_input():
    prompt = build_dynamic_validation_prompt(
        candidate=_finding(),
        github_url="https://example.test/project",
        commit="abc",
        source_root="/src",
        binary_path="/bin/target",
    )
    assert "candidate_001" in prompt
    assert "Dynamic-validation scope" in prompt
    assert "<dynamic_status>not_reached</dynamic_status>" in prompt
    assert "<poc_path>" in prompt
    assert "## Final response schema — mandatory machine interface" in prompt
    assert "<reproduction_command>exact command containing that path" in prompt
    assert "do not substitute aliases" in prompt.lower()


def test_crash_poc_kind_aliases_are_normalized_to_file():
    assert _normalize_poc_kind("ruby", "asan") == "file"
    assert _normalize_poc_kind("python", "asan") == "file"
    assert _normalize_poc_kind("ruby_source", "asan") == "file"
    assert _normalize_poc_kind("ruby_source_via_mrb_load_string", "asan") == "file"
    assert _normalize_poc_kind("shell_script", "asan") == "file"
    assert _normalize_poc_kind("raw-binary", "asan") == "file"
    assert _normalize_poc_kind("program", "asan") == "program"
    assert _normalize_poc_kind("ruby_source", "logic") == "ruby_source"
    assert _normalize_poc_kind("ruby", "logic") == "ruby"
    assert _normalize_poc_kind("ruby_source_via_mrb_load_string", "logic") == "ruby_source_via_mrb_load_string"


def test_logic_dynamic_prompt_uses_semantic_oracle_contract():
    prompt = build_dynamic_validation_prompt(
        candidate=_finding(),
        github_url="https://example.test/project",
        commit="abc",
        source_root="/src",
        binary_path="/bin/target",
        detector="logic",
    )
    assert "does NOT need to crash" in prompt
    assert "<expected_behavior>" in prompt
    assert "<observed_behavior>" in prompt
    assert "reached_no_effect" in prompt
    assert "Command lifecycle and timeout discipline" in prompt
    assert "Never run a `while True` helper" in prompt
    assert "foreground, and never leave a helper process" in prompt


def test_dynamic_prompt_blocks_history_leaks_and_unbounded_batch_scripts():
    for detector in ("asan", "logic"):
        prompt = build_dynamic_validation_prompt(
            candidate=_finding(),
            github_url="https://example.test/project",
            commit="abc",
            source_root="/src",
            binary_path="/bin/target",
            detector=detector,
        )
        assert "Do not inspect `.git` metadata" in prompt
        assert "artifacts from other" in prompt
        assert "packaged fuzzer seed corpora" in prompt
        assert "potentially long one-shot script explicitly with `timeout`" in prompt
        assert "possible helper services, even when intended as batch scripts" in prompt


def test_dynamic_prompt_requires_ready_instrumentation_checkpoint():
    prompt = build_dynamic_validation_prompt(
        candidate=_finding(),
        github_url="https://example.test/project",
        commit="abc",
        source_root="/src",
        binary_path="/bin/target",
        instrumentation_context={
            "provider": "llvm",
            "status": "ready",
            "manifest": {"run_command": "/work/instrumentation/run LABEL -- COMMAND"},
        },
    )
    assert "observation checkpoint is mandatory" in prompt
    assert "direct run of the clean binary" in prompt


def test_dynamic_prompt_requires_adaptive_round_records():
    prompt = build_dynamic_validation_prompt(
        candidate=_finding(),
        github_url="https://example.test/project",
        commit="abc",
        source_root="/src",
        binary_path="/bin/target",
        max_iterations=4,
    )
    assert "at most 4 numbered validation rounds" in prompt
    assert "/work/validation/iterations/round-NNN.json" in prompt
    assert "sanitizer event from a different function is a wrong path" in prompt


def test_iteration_normalizes_flat_agent_evidence_without_inventing_positive_flags():
    record = _bound_iteration({
        "candidate_id": "candidate_001",
        "round": 2,
        "title": "sanitizer crash reproduced",
        "site_reached": True,
        "sanitizer_event": True,
        "bad_state_observed": True,
        "bad_effect_observed": True,
        "matched_candidate": True,
        "observations": ["ASan reported UAF in the candidate path"],
    })

    assert record["round_id"] == 2
    assert record["decision"] == "candidate_ready"
    assert record["observations"] == {
        "site_reached": True,
        "sanitizer_event": True,
        "bad_state_observed": True,
        "bad_effect_observed": True,
        "matched_candidate": True,
    }
    assert _has_candidate_ready_iteration([record], "asan")
    record["observations"]["matched_candidate"] = False
    assert not _has_candidate_ready_iteration([record], "asan")


def test_missing_iteration_records_are_agent_failure_not_exhaustion():
    assert _status_without_iteration_records("iteration_exhausted", "") == (
        "agent_failed",
        "agent did not persist any validation round",
    )
    assert _status_without_iteration_records("reached_no_crash", "said so") == (
        "agent_failed",
        "said so",
    )
    assert _status_without_iteration_records("agent_blocked", "phase timeout") == (
        "agent_blocked",
        "phase timeout",
    )


def test_candidate_ready_without_final_poc_is_invalid_submission_not_no_crash():
    record = {
        "decision": "candidate_ready",
        "observations": {
            "site_reached": True,
            "matched_candidate": True,
            "sanitizer_event": True,
        },
    }
    status, reason = _status_for_missing_poc_submission(
        status="reached_no_crash",
        reason="",
        iterations=[record],
        detector="asan",
    )

    assert status == "invalid_submission"
    assert "omitted the required" in reason

def test_logic_static_prompt_requires_semantic_oracle():
    prompt = build_static_analysis_prompt(
        github_url="https://example.test/project",
        commit="abc",
        source_root="/src",
        binary_path="/bin/target",
        detector="logic",
    )
    assert "Logic-detector guidance" in prompt
    assert "semantic defects" in prompt
    assert "cannot trigger ASAN" in prompt


def test_find_phase_result_keeps_legacy_three_value_unpacking():
    agent = AgentResult(messages=[_assistant("done")])
    outcome = FindPhaseResult(
        crash=None,
        agent_result=agent,
        timings={"static_analysis": 1.0},
        static_findings=[_finding()],
    )
    crash, result, timings = outcome
    assert crash is None
    assert result is agent
    assert timings == {"static_analysis": 1.0}


def test_run_find_orchestrates_static_then_dynamic_and_writes_artifacts(tmp_path, monkeypatch):
    target = TargetConfig.load(Path(__file__).resolve().parents[1] / "targets" / "canary")
    static_agent = AgentResult(messages=[_assistant("static")])
    dynamic_agent = AgentResult(messages=[_assistant("dynamic")])
    crash = CrashArtifact(
        poc_path="/tmp/poc.bin",
        poc_bytes=b"poc",
        reproduction_command="/bin/target /tmp/poc.bin",
        crash_type="heap-buffer-overflow",
        crash_output="asan",
        exit_code=134,
        dup_check="distinct",
    )
    dynamic = DynamicValidationResult(
        candidate_id="candidate_001",
        status="validated",
        crash=crash,
    )

    async def fake_static(**kwargs):
        assert kwargs["container_name"].startswith("static_")
        return [_finding()], static_agent, {"static_analysis": 1.0}, None

    async def fake_dynamic(**kwargs):
        assert kwargs["candidate"] == _finding()
        assert kwargs["instrumentation"] == "llvm"
        assert kwargs["instrumentation_result_path"] == str(tmp_path / "instrumentation")
        return dynamic, dynamic_agent, {"dynamic_validation": 2.0}

    monkeypatch.setattr("harness.find.run_static_analysis", fake_static)
    monkeypatch.setattr("harness.find.run_dynamic_validation", fake_dynamic)
    static_path = tmp_path / "static_analysis.json"
    dynamic_path = tmp_path / "dynamic_validation.json"
    transcript_path = tmp_path / "find_transcript.jsonl"
    outcome = asyncio.run(run_find(
        target,
        model="m",
        max_turns=3,
        transcript_path=str(transcript_path),
        static_result_path=str(static_path),
        dynamic_result_path=str(dynamic_path),
        instrumentation="llvm",
        instrumentation_result_path=str(tmp_path / "instrumentation"),
    ))

    assert outcome.crash == crash
    assert outcome.dynamic_result == dynamic
    assert outcome.timings["static_analysis"] == 1.0
    assert outcome.timings["dynamic_validation"] == 2.0
    assert outcome.timings["find"] == 3.0
    assert json.loads(static_path.read_text())["candidate_count"] == 1
    assert json.loads(dynamic_path.read_text())["result"]["status"] == "validated"
    transcript = transcript_path.read_text()
    assert '"text": "static"' in transcript
    assert '"text": "dynamic"' in transcript


def test_run_find_propagates_logic_artifact(monkeypatch):
    target = TargetConfig.load(Path(__file__).resolve().parents[1] / "targets" / "canary")
    static_agent = AgentResult(messages=[_assistant("static")])
    dynamic_agent = AgentResult(messages=[_assistant("dynamic")])
    logic = LogicArtifact(
        poc_path="/tmp/poc.sh",
        poc_bytes=b"echo wrong",
        reproduction_command="sh /tmp/poc.sh",
        logic_type="incorrect-validation",
        expected_behavior="reject",
        observed_behavior="accepted",
        logic_evidence="3/3",
        exit_code=0,
        dup_check="distinct",
    )

    async def fake_static(**kwargs):
        return [_finding()], static_agent, {"static_analysis": 1.0}, None

    async def fake_dynamic(**kwargs):
        return DynamicValidationResult(
            candidate_id="candidate_001", status="validated", logic=logic
        ), dynamic_agent, {"dynamic_validation": 2.0}

    monkeypatch.setattr("harness.find.run_static_analysis", fake_static)
    monkeypatch.setattr("harness.find.run_dynamic_validation", fake_dynamic)
    outcome = asyncio.run(run_find(target, model="m", max_turns=3))
    assert outcome.crash is None
    assert outcome.logic == logic
    assert outcome.dynamic_result.logic == logic


def test_dynamic_validation_parses_logic_submission(monkeypatch):
    target = TargetConfig.load(Path(__file__).resolve().parents[1] / "targets" / "libxml2")
    candidate = _finding()
    message = """<dynamic_status>validated</dynamic_status>
<candidate_id>candidate_001</candidate_id>
<reached_functions>prompt text accidentally copied into metadata</reached_functions>
<reachability_evidence>public XML XInclude input</reachability_evidence>
<poc_path>/tmp/poc.sh</poc_path>
<reproduction_command>sh /tmp/poc.sh</reproduction_command>
<poc_kind>file</poc_kind>
<logic_type>integer-truncation</logic_type>
<expected_behavior>included text is present</expected_behavior>
<observed_behavior>included text is absent</observed_behavior>
<logic_evidence>control present, trigger absent in 3/3 runs</logic_evidence>
<exit_code>0</exit_code>
<dup_check>different candidate</dup_check>"""

    class FakeSession:
        container = "fake-container"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        "harness.dynamic_validation.open_runtime_session",
        lambda *args, **kwargs: FakeSession(),
    )
    async def fake_agent(**kwargs):
        return _fake_agent_result(message)

    monkeypatch.setattr("harness.dynamic_validation.run_agent", fake_agent)
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
                "bad_state_observed": True,
                "bad_effect_observed": True,
                "matched_candidate": True,
            },
            "decision": "candidate_ready",
        }], []),
    )
    monkeypatch.setattr(
        "harness.dynamic_validation.docker_ops.read_file",
        lambda container, path: b"#!/bin/sh\necho oracle\n",
    )
    outcome, _agent, _timings = asyncio.run(
        run_dynamic_validation(
            target, candidate, model="m", max_turns=3, instrumentation="off"
        )
    )
    assert outcome.status == "validated"
    assert outcome.crash is None
    assert outcome.logic is not None
    assert outcome.logic.logic_type == "integer-truncation"
    assert outcome.logic.exit_code == 0


def test_dynamic_validation_normalizes_crash_label_to_file_poc(monkeypatch):
    target = TargetConfig.load(Path(__file__).resolve().parents[1] / "targets" / "mruby-arvo")
    candidate = StaticFinding(
        candidate_id="candidate_001",
        bug_class="unknown",
        location="",
        static_call_chain="",
        entry_points="",
        attacker_controlled_data="",
        reachability_evidence="",
        required_conditions="",
        root_cause="A write barrier bug exists in the mrb_env_unshare function in gc.c",
        verification_plan="",
        confidence=0.5,
    )
    message = """<dynamic_status>validated</dynamic_status>
<candidate_id>candidate_001</candidate_id>
<reached_functions>quoted prompt text, not runtime evidence</reached_functions>
<poc_path>/work/poc.rb</poc_path>
<reproduction_command>/out/mruby_fuzzer /work/poc.rb</reproduction_command>
<poc_kind>crash</poc_kind>
<crash_type>heap-use-after-free</crash_type>
<exit_code>1</exit_code>
<crash_output>AddressSanitizer: heap-use-after-free</crash_output>
<dup_check>Distinct target candidate</dup_check>"""

    class FakeSession:
        container = "fake-container"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        "harness.dynamic_validation.open_runtime_session",
        lambda *args, **kwargs: FakeSession(),
    )

    async def fake_agent(**kwargs):
        return _fake_agent_result(message)

    monkeypatch.setattr("harness.dynamic_validation.run_agent", fake_agent)
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
            return _crash_result_xml()
        return b"puts 'trigger'\n"

    monkeypatch.setattr("harness.dynamic_validation.docker_ops.read_file", fake_read_file)

    outcome, _agent, _timings = asyncio.run(
        run_dynamic_validation(
            target, candidate, model="m", max_turns=3, instrumentation="off"
        )
    )
    assert outcome.status == "validated"
    assert outcome.crash is not None
    assert outcome.crash.poc_kind == "file"
    assert outcome.crash.poc_bytes == b"puts 'trigger'\n"
    assert outcome.reached_functions == []


def _fake_agent_result(message: str) -> AgentResult:
    return AgentResult(messages=[_assistant(message)], result_message=message)
