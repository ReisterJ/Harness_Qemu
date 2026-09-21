# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Split find loop: static hypothesis generation, then dynamic validation.

The public three-value iteration contract is retained for existing callers:
``crash, agent_result, timings = await run_find(...)``.  New callers can keep
the returned ``FindPhaseResult`` object to inspect both phase results.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .agent import AgentResult
from .artifacts import CrashArtifact, DynamicValidationResult, LogicArtifact, StaticFinding
from .config import TargetConfig
from .dynamic_validation import run_dynamic_validation
from .static_analysis import run_static_analysis


DEFAULT_FIND_MAX_TURNS = 2000
# Dynamic validation needs a high step ceiling so its wall-clock watchdog,
# rather than the agent step counter, is the effective bound for long PoC
# searches. The standalone `dynamic` CLI uses this value; the static phase and
# combined `run` command retain DEFAULT_FIND_MAX_TURNS.
DEFAULT_DYNAMIC_MAX_TURNS = 20000
DEFAULT_DYNAMIC_MAX_ITERATIONS = 8


@dataclass
class FindPhaseResult:
    """Complete split-find result with backwards-compatible tuple unpacking."""

    crash: CrashArtifact | None
    agent_result: AgentResult
    timings: dict[str, float]
    logic: LogicArtifact | None = None
    static_findings: list[StaticFinding] = field(default_factory=list)
    dynamic_result: DynamicValidationResult | None = None
    instrumentation: dict | None = None
    symbolic_execution: dict | None = None
    static_parse_error: str | None = None

    def __iter__(self):
        # Preserve the old run_find() API used by patch re-attack and tests.
        yield self.crash
        yield self.agent_result
        yield self.timings


async def run_find(
    target: TargetConfig,
    model: str,
    max_turns: int = DEFAULT_FIND_MAX_TURNS,
    agent_env: dict[str, str] | None = None,
    container_name: str = "find_target",
    focus_area: str | None = None,
    known_bugs: list[str] | None = None,
    found_bugs_path: str | None = None,
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
    accept_dos: bool = False,
    system_prompt: str | None = None,
    max_resume_attempts: int = 20,
    static_transcript_path: str | None = None,
    static_result_path: str | None = None,
    dynamic_result_path: str | None = None,
    instrumentation: str | None = None,
    instrumentation_result_path: str | None = None,
    symbolic_execution: str | None = None,
    symbolic_execution_result_path: str | None = None,
    max_iterations: int = DEFAULT_DYNAMIC_MAX_ITERATIONS,
) -> FindPhaseResult:
    """Run static analysis followed by dynamic validation.

    Only the highest-ranked static candidate is selected in this first
    implementation. The static artifact still records all candidates, so a
    future policy can validate several candidates without changing the phase
    contracts or the grade boundary.
    """
    timings: dict[str, float] = {}
    all_known_bugs = known_bugs if known_bugs is not None else target.known_bugs

    static_started = time.time()
    findings, static_agent, static_timings, parse_error = await run_static_analysis(
        target=target,
        model=model,
        max_turns=max_turns,
        agent_env=agent_env,
        container_name=f"static_{container_name}",
        focus_area=focus_area,
        known_bugs=all_known_bugs,
        transcript_path=static_transcript_path,
        progress_prefix=(f"{progress_prefix}:static" if progress_prefix else None),
        system_prompt=system_prompt,
        max_resume_attempts=max_resume_attempts,
    )
    timings.update(static_timings)
    timings.setdefault("static_analysis", time.time() - static_started)
    # The prompt asks for ranked output; confidence provides a deterministic
    # fallback when the model's textual order and numeric ranking disagree.
    findings.sort(key=lambda finding: finding.confidence, reverse=True)

    # A clean empty array is a valid static conclusion. A malformed response
    # is an agent failure, because silently treating it as "no bug" would
    # conflate protocol failure with a considered negative result.
    if parse_error and not findings and not static_agent.error:
        static_agent.error = f"static analysis output: {parse_error}"

    if static_result_path:
        _write_json(
            static_result_path,
            {
                "phase": "static_analysis",
                "target": target.name,
                "repository": target.github_url,
                "commit": target.commit,
                "source_root": target.source_root,
                "status": (
                    "agent_failed" if static_agent.error else
                    "parse_error" if parse_error and not findings else
                    "candidates_found" if findings else "no_candidates"
                ),
                "candidate_count": len(findings),
                "findings": [finding.to_dict() for finding in findings],
                "parse_error": parse_error,
                "agent_error": static_agent.error,
                "timings": static_timings,
            },
        )

    if not findings:
        timings["find"] = sum(timings.values())
        if transcript_path:
            _write_transcript(transcript_path, static_agent.transcript())
        return FindPhaseResult(
            crash=None,
            logic=None,
            agent_result=static_agent,
            timings=timings,
            static_findings=[],
            static_parse_error=parse_error,
        )

    # The static prompt ranks candidates from strongest to weakest. The MVP
    # validates one per run to keep the existing run budget and output shape
    # stable; all candidates remain available in static_analysis.json.
    candidate = findings[0]
    dynamic_result, dynamic_agent, dynamic_timings = await run_dynamic_validation(
        target=target,
        candidate=candidate,
        model=model,
        max_turns=max_turns,
        agent_env=agent_env,
        container_name=container_name,
        focus_area=focus_area,
        known_bugs=all_known_bugs,
        found_bugs_path=found_bugs_path,
        transcript_path=transcript_path,
        progress_prefix=(f"{progress_prefix}:dynamic" if progress_prefix else None),
        accept_dos=accept_dos,
        system_prompt=system_prompt,
        max_resume_attempts=max_resume_attempts,
        instrumentation=instrumentation,
        instrumentation_result_path=instrumentation_result_path,
        symbolic_execution=symbolic_execution,
        symbolic_execution_result_path=symbolic_execution_result_path,
        crash_result_path=(
            str(Path(dynamic_result_path).with_name("crash-result.xml"))
            if dynamic_result_path else None
        ),
        max_iterations=max_iterations,
    )
    timings.update(dynamic_timings)
    timings["find"] = timings.get("static_analysis", 0.0) + timings.get(
        "dynamic_validation", 0.0
    )

    if dynamic_result_path:
        _write_json(
            dynamic_result_path,
            {
                "phase": "dynamic_validation",
                "candidate": candidate.to_dict(),
                "result": dynamic_result.to_dict(),
                "timings": dynamic_timings,
            },
        )

    combined = _combine_agent_results(static_agent, dynamic_agent)
    if transcript_path:
        _write_transcript(transcript_path, combined.transcript())
    return FindPhaseResult(
        crash=dynamic_result.crash,
        logic=dynamic_result.logic,
        agent_result=combined,
        timings=timings,
        static_findings=findings,
        dynamic_result=dynamic_result,
        instrumentation=dynamic_result.instrumentation,
        symbolic_execution=dynamic_result.symbolic_execution,
        static_parse_error=parse_error,
    )


def _combine_agent_results(static: AgentResult, dynamic: AgentResult) -> AgentResult:
    """Expose both phase transcripts through the legacy find result."""
    return AgentResult(
        messages=[*static.messages, *dynamic.messages],
        result_message=dynamic.result_message or static.result_message,
        session_id=dynamic.session_id or static.session_id,
        error=dynamic.error or static.error,
        resume_count=static.resume_count + dynamic.resume_count,
        tool_call_count=static.tool_call_count + dynamic.tool_call_count,
        assistant_message_count=(
            static.assistant_message_count + dynamic.assistant_message_count
        ),
        started_at=static.started_at,
        finished_at=dynamic.finished_at or static.finished_at,
        first_poc_at=dynamic.first_poc_at or static.first_poc_at,
    )


def _write_json(path: str, value: dict) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _write_transcript(path: str, events: list[dict]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events)
    )
