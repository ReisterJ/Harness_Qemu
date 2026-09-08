"""Tests for the split static-analysis/dynamic-validation find contract."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from harness.agent import AgentResult
from harness.artifacts import CrashArtifact, DynamicValidationResult, StaticFinding
from harness.config import TargetConfig
from harness.find import FindPhaseResult, run_find
from harness.prompts.dynamic_validation_prompt import build_dynamic_validation_prompt
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
