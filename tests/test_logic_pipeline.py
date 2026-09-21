"""Tests for semantic-logic artifacts through dynamic validation and grade."""
from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path

from harness import cli
from harness.agent import AgentResult
from harness.artifacts import GraderVerdict, LogicArtifact
from harness.config import TargetConfig
from harness.find import FindPhaseResult
from harness.grade import run_grade


def _assistant(text: str) -> dict:
    return {
        "type": "text",
        "sessionID": "s",
        "part": {"type": "text", "messageID": "m", "text": text},
    }


def test_logic_artifact_is_graded_and_persisted(tmp_path, monkeypatch):
    target = replace(
        TargetConfig.load(Path(__file__).resolve().parents[1] / "targets" / "canary"),
        name="logic-canary",
        detector="logic",
    )
    finding = {
        "candidate_id": "candidate_001",
        "bug_class": "incorrect-validation",
        "location": "src/parser.c:10",
        "static_call_chain": "file -> parser -> sink",
        "entry_points": "file argument",
        "attacker_controlled_data": "length",
        "reachability_evidence": "main calls parser",
        "required_conditions": "large input",
        "root_cause": "truncation",
        "verification_plan": "compare control and trigger",
        "confidence": 0.9,
    }
    from harness.artifacts import StaticFinding

    static_finding = StaticFinding.from_dict(finding)
    logic = LogicArtifact(
        poc_path="/tmp/poc.sh",
        poc_bytes=b"#!/bin/sh\necho wrong\n",
        reproduction_command="sh /tmp/poc.sh",
        logic_type="integer-truncation",
        expected_behavior="included text is present",
        observed_behavior="included text is absent",
        logic_evidence="control=present trigger=absent, 3/3",
        exit_code=0,
        dup_check="unique candidate",
    )
    find_result = AgentResult(messages=[_assistant("find")])

    async def fake_find(*args, **kwargs):
        return FindPhaseResult(
            crash=None,
            agent_result=find_result,
            timings={"find": 1.0},
            logic=logic,
            static_findings=[static_finding],
        )

    seen = {}

    async def fake_grade(artifact, *args, **kwargs):
        seen["artifact"] = artifact
        seen["static_finding"] = kwargs["static_finding"]
        return (
            GraderVerdict(True, 1.0, {"criterion_1": True}, "confirmed"),
            AgentResult(messages=[_assistant("grade")]),
            2.0,
        )

    monkeypatch.setattr(cli, "run_find", fake_find)
    monkeypatch.setattr(cli, "run_grade", fake_grade)
    result = asyncio.run(
        cli._run_once(
            run_idx=0,
            target=target,
            model="m",
            find_only=False,
            max_turns=3,
            agent_env={},
            out_dir=tmp_path,
            focus_area=None,
            found_bugs_path=None,
        )
    )

    assert result.status == "logic_found"
    assert result.logic == logic
    assert result.crash is None
    assert seen["artifact"] == logic
    assert seen["static_finding"] == static_finding
    on_disk = json.loads((tmp_path / "result.json").read_text())
    assert on_disk["status"] == "logic_found"
    assert on_disk["logic"]["artifact_type"] == "logic"
    assert (tmp_path / "poc.bin").read_bytes() == logic.poc_bytes


def test_logic_grade_uses_semantic_rubric_and_requires_confirmation(tmp_path, monkeypatch):
    target = replace(
        TargetConfig.load(Path(__file__).resolve().parents[1] / "targets" / "canary"),
        detector="logic",
    )
    logic = LogicArtifact(
        poc_path="/tmp/poc.sh",
        poc_bytes=b"echo oracle",
        reproduction_command="sh /tmp/poc.sh",
        logic_type="integer-truncation",
        expected_behavior="present",
        observed_behavior="absent",
        logic_evidence="3/3",
        exit_code=0,
        dup_check="unique",
    )

    class FakeSession:
        container = "grader-container"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("harness.grade.open_runtime_session", lambda *a, **k: FakeSession())
    monkeypatch.setattr("harness.grade.docker_ops.write_file", lambda *a, **k: None)
    tags = "".join(f"<criterion_{i}>PASS</criterion_{i}>" for i in range(1, 7))
    response = tags + "<overall>PASS</overall><score>1.0</score>" \
        "<root_cause>CONFIRMED</root_cause><evidence>oracle</evidence>"

    async def fake_agent(**kwargs):
        assert "semantic oracle" in kwargs["prompt"]
        return AgentResult(messages=[_assistant(response)], result_message=response)

    monkeypatch.setattr("harness.grade.run_agent", fake_agent)
    verdict, _agent, _elapsed = asyncio.run(
        run_grade(logic, target, model="m", workspace_dir=str(tmp_path))
    )
    assert verdict.passed is True
    assert verdict.criteria["criterion_6"] is True
