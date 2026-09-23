# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Dynamic validation phase of the split find workflow."""
from __future__ import annotations

import asyncio
import hashlib
import time
import json
import re
import shlex
import tempfile
import threading
import uuid
import xml.etree.ElementTree as ET
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, Iterator
from xml.sax.saxutils import escape as xml_escape

from . import docker_ops
from .agent import AgentResult, parse_xml_tag, run_agent
from .artifacts import (
    POC_KINDS,
    CrashArtifact,
    DynamicValidationResult,
    LogicArtifact,
    StaticFinding,
)
from .config import TargetConfig
from .docker_params import DockerMount, DockerRunParams
from .execution_protocol import (
    FEEDBACK_READER_PATH,
    FEEDBACK_ROOT,
    INPUT_ROOT,
    PENDING_ROOT,
    PROCESSED_ROOT,
    README_PATH as EXECUTION_README_PATH,
    REQUEST_ROOT,
    REQUEST_TEMPLATE_PATH,
    RESPONSE_ROOT,
    RUNNER_PATH,
    SNAPSHOT_ROOT,
    ExecutionRequest,
    ExecutionRequestError,
    parse_request,
    protocol_feedback_reader_script,
    protocol_readme,
    protocol_runner_script,
    protocol_template,
    shell_argv,
    target_argv,
)
from .instrumentation import select_provider
from .instrumentation.base import InstrumentationReport
from .prompts.dynamic_validation_prompt import (
    build_dynamic_validation_prompt,
    build_poc_generation_prompt,
    build_symcc_planner_prompt,
)
from .runtimes import open_runtime_session
from .symbolic import KleeSession, SymccSession, select_symbolic_execution
from .symbolic.feedback import (
    FeedbackMapError,
    load_json_map_files,
    parse_trace,
    resolve_target_ids,
    summarize_trace,
)
from .symbolic.seed_plan import SeedPlanError, parse_seed_plan

_DYNAMIC_STATUSES = {
    "not_reached",
    "reached_no_crash",
    "reached_no_effect",
    "wrong_behavior",
    "wrong_path",
    "environment_blocked",
    "invalid_submission",
    "agent_failed",
    "agent_blocked",
    "false_positive",
    "iteration_exhausted",
}
_DEFAULT_MAX_ITERATIONS = 8
_MAX_ITERATION_RECORDS = 100
_MAX_ITERATION_BYTES = 50_000
_CRASH_RESULT_XML_PATH = "/work/validation/crash-result.xml"
_CRASH_RESULT_TEMPLATE_PATH = "/work/validation/crash-result-template.xml"
_CRASH_RESULT_FIELDS = (
    "candidate_id", "poc_path", "reproduction_command", "poc_kind",
    "crash_type", "exit_code", "crash_output", "dup_check",
)


async def run_dynamic_validation(
    target: TargetConfig,
    candidate: StaticFinding,
    model: str,
    max_turns: int,
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
    instrumentation: str | None = None,
    instrumentation_result_path: str | None = None,
    symbolic_execution: str | None = None,
    symbolic_execution_result_path: str | None = None,
    crash_result_path: str | None = None,
    max_iterations: int = _DEFAULT_MAX_ITERATIONS,
) -> tuple[DynamicValidationResult, AgentResult, dict[str, float]]:
    """Try to produce a crash or semantic-logic PoC for one static candidate."""
    timings: dict[str, float] = {}
    mounts = [(str(found_bugs_path), "/tmp/found_bugs.jsonl")] if found_bugs_path else None
    provider = select_provider(instrumentation, target.instrumentation)
    symbolic_provider = select_symbolic_execution(
        symbolic_execution, target.symbolic_execution
    )
    if symbolic_provider == "symcc" and not (
        target.symcc_runtime and target.symcc_runtime.get("binary_path")
    ):
        raise ValueError(
            "SymCC was selected, but target config has no prebuilt "
            "symbolic_execution.symcc.binary_path"
        )
    iteration_limit = max(1, min(int(max_iterations), _MAX_ITERATION_RECORDS))
    instrumentation_prepared: InstrumentationReport | None = None
    instrumentation_result: InstrumentationReport | None = None
    symbolic_result: dict | None = None
    with _open_dynamic_session(
        target,
        container_name=container_name,
        auth=agent_env,
        mounts=mounts,
        symbolic_provider=symbolic_provider,
        symbolic_result_path=symbolic_execution_result_path,
    ) as (session, symbolic_session):
        container = session.container
        _hide_source_vcs_metadata(container, target)
        _prepare_iteration_workspace(
            container, candidate, iteration_limit, target.detector
        )
        symbolic_feedback_runtime: dict[str, Any] | None = None
        symbolic_context = (
            _prepare_prebuilt_symcc_protocol(
                container, target, candidate, max_requests=iteration_limit
            )
            if symbolic_provider == "symcc"
            else symbolic_session.prepare_agent(container) if symbolic_session else None
        )
        if symbolic_context and symbolic_provider == "symcc":
            symbolic_feedback_runtime = symbolic_context.pop("_feedback_runtime", None)
        if provider is not None:
            prepare_started = time.time()
            instrumentation_prepared = provider.prepare(
                container,
                source_root=target.source_root,
                binary_path=target.binary_path,
                candidate=candidate.to_dict(),
            )
            timings["instrumentation_prepare"] = time.time() - prepare_started
            instrumentation_context = instrumentation_prepared.to_dict()
        elif instrumentation not in (None, "off") or (
            instrumentation is None
            and isinstance(target.instrumentation, dict)
            and target.instrumentation.get("default", "auto") not in {None, "off"}
        ):
            instrumentation_context = {
                "schema_version": 1,
                "provider": "none",
                "status": "disabled",
                "capabilities": [],
                "errors": ["no configured instrumentation provider is available"],
            }
        else:
            instrumentation_context = None
        started = time.time()
        if symbolic_provider == "symcc":
            prompt = build_dynamic_validation_prompt(
                candidate=candidate,
                github_url=target.github_url,
                commit=target.commit,
                source_root=target.source_root,
                binary_path=target.binary_path,
                focus_area=focus_area,
                known_bugs=known_bugs if known_bugs is not None else target.known_bugs,
                found_bugs_path="/tmp/found_bugs.jsonl" if found_bugs_path else None,
                accept_dos=accept_dos,
                reattack_harness=target.reattack_harness,
                attack_surface=target.attack_surface,
                detector=target.detector,
                runtime_context=target.runtime_context(),
                instrumentation_context=instrumentation_context,
                symbolic_context=symbolic_context,
                max_iterations=iteration_limit,
            )
            result, protocol_timings, symbolic_result = await _run_prebuilt_symcc_agent(
                prompt=prompt,
                target=target,
                container=container,
                model=model,
                max_turns=max_turns,
                system_prompt=system_prompt,
                max_resume_attempts=max_resume_attempts,
                transcript_path=transcript_path,
                progress_prefix=progress_prefix,
                result_path=symbolic_execution_result_path,
                feedback_runtime=symbolic_feedback_runtime,
                max_iterations=iteration_limit,
            )
            timings.update(protocol_timings)
        else:
            prompt = build_dynamic_validation_prompt(
                candidate=candidate,
                github_url=target.github_url,
                commit=target.commit,
                source_root=target.source_root,
                binary_path=target.binary_path,
                focus_area=focus_area,
                known_bugs=known_bugs if known_bugs is not None else target.known_bugs,
                found_bugs_path="/tmp/found_bugs.jsonl" if found_bugs_path else None,
                accept_dos=accept_dos,
                reattack_harness=target.reattack_harness,
                attack_surface=target.attack_surface,
                detector=target.detector,
                runtime_context=target.runtime_context(),
                instrumentation_context=instrumentation_context,
                symbolic_context=symbolic_context,
                max_iterations=iteration_limit,
            )
            result = await run_agent(
                prompt=prompt,
                max_turns=max_turns,
                model=model,
                container=container,
                transcript_path=transcript_path,
                progress_prefix=progress_prefix,
                system_prompt=system_prompt,
                max_resume_attempts=max_resume_attempts,
                tools=["Read", "Write", "Bash"],
            )
            timings["dynamic_validation"] = time.time() - started
        timings["dynamic_agent_tool_calls"] = float(result.tool_call_count)
        timings["dynamic_agent_messages"] = float(result.assistant_message_count)
        if symbolic_session is not None:
            symbolic_result = symbolic_session.collect()
            timings["symbolic_execution_session"] = float(
                symbolic_result.get("duration_s") or 0.0
            )
        if result.first_poc_at is not None and result.started_at is not None:
            timings["dynamic_poc_tag"] = max(
                0.0, result.first_poc_at - result.started_at
            )

        iterations, iteration_errors = _collect_iteration_records(
            container, candidate.candidate_id, iteration_limit
        )
        _persist_iteration_records(
            iterations, iteration_errors, instrumentation_result_path
        )

        if provider is not None and instrumentation_prepared is not None:
            collect_started = time.time()
            if instrumentation_prepared.status == "ready":
                instrumentation_result = provider.collect(
                    container, instrumentation_prepared.manifest
                )
            else:
                instrumentation_result = instrumentation_prepared
            timings["instrumentation_collect"] = time.time() - collect_started
        elif instrumentation_context is not None:
            instrumentation_result = InstrumentationReport(
                provider=str(instrumentation_context.get("provider", "none")),
                status=str(instrumentation_context.get("status", "disabled")),
                errors=tuple(str(x) for x in instrumentation_context.get("errors", [])),
            )
        _persist_instrumentation(instrumentation_result, instrumentation_result_path)

        observed_reached: list[str] = []
        if instrumentation_result is not None:
            for event in instrumentation_result.feedback:
                for function in event.reached_functions:
                    if function not in observed_reached:
                        observed_reached.append(function)

        def dynamic_result(**kwargs) -> DynamicValidationResult:
            if observed_reached:
                reported = list(kwargs.get("reached_functions") or [])
                kwargs["reached_functions"] = reported + [
                    function for function in observed_reached if function not in reported
                ]
            if instrumentation_result is not None:
                kwargs["instrumentation"] = instrumentation_result.to_dict()
            if symbolic_result is not None:
                kwargs["symbolic_execution"] = symbolic_result
            kwargs["iterations"] = iterations
            kwargs["iteration_errors"] = iteration_errors
            return DynamicValidationResult(**kwargs)

        text = result.find_tagged_message("poc_path")
        status_text = result.find_tagged_message("dynamic_status")
        metadata_text = (
            status_text
            if parse_xml_tag(status_text, "dynamic_status") is not None
            else text
        )
        inline_data = {
            "dynamic_status": parse_xml_tag(status_text, "dynamic_status") or "",
            "candidate_id": parse_xml_tag(metadata_text, "candidate_id") or "",
            "reached_functions": parse_xml_tag(metadata_text, "reached_functions") or "",
            "reachability_evidence": parse_xml_tag(metadata_text, "reachability_evidence") or "",
            "reason": parse_xml_tag(metadata_text, "reason") or "",
            "poc_path": parse_xml_tag(text, "poc_path") or "",
            "reproduction_command": parse_xml_tag(text, "reproduction_command") or "",
            "poc_kind": parse_xml_tag(text, "poc_kind") or "",
            "crash_type": parse_xml_tag(text, "crash_type") or "",
            "exit_code": parse_xml_tag(text, "exit_code") or "",
            "crash_output": parse_xml_tag(text, "crash_output") or "",
            "dup_check": parse_xml_tag(text, "dup_check"),
            "logic_type": parse_xml_tag(text, "logic_type") or "",
            "expected_behavior": parse_xml_tag(text, "expected_behavior") or "",
            "observed_behavior": parse_xml_tag(text, "observed_behavior") or "",
            "logic_evidence": parse_xml_tag(text, "logic_evidence") or "",
        }

        # Logic findings and negative reachability results retain the original
        # response-tag protocol.  Only a successful crash submission uses the
        # file protocol, because long sanitizer output and paths are easy for
        # the model to corrupt when embedded in its final response.
        crash_data = None
        crash_xml_error = None
        crash_xml_present = False
        if target.detector != "logic":
            crash_data, crash_xml_error, crash_xml_present = _read_crash_result_xml(
                container, candidate.candidate_id
            )
            if crash_xml_present and crash_result_path:
                _persist_crash_result(container, crash_result_path)
            if crash_xml_present and crash_data is None:
                return dynamic_result(
                    candidate_id=candidate.candidate_id,
                    status="invalid_submission",
                    reason=crash_xml_error or "invalid crash result file",
                ), result, timings
            if crash_xml_present:
                # The XML file is the authoritative crash submission. Keep
                # textual reachability evidence as context, but do not treat
                # inline reached_functions as execution evidence: a previous
                # assistant message can contain copied prompt text or stale
                # metadata. Actual instrumentation evidence is appended below.
                result_data = dict(inline_data)
                result_data.update(crash_data or {})
                result_data["reached_functions"] = ""
                result_data["dynamic_status"] = "validated"
            else:
                if inline_data["poc_path"]:
                    return dynamic_result(
                        candidate_id=candidate.candidate_id,
                        status="invalid_submission",
                        reason=(
                            "crash PoC submissions must be written to "
                            f"{_CRASH_RESULT_XML_PATH}; inline crash tags are not accepted"
                        ),
                    ), result, timings
                result_data = inline_data
        else:
            result_data = inline_data

        poc_path = result_data["poc_path"]
        reproduction_command = result_data["reproduction_command"]
        reported_id = result_data["candidate_id"]
        selected_id = (
            reported_id.strip()
            if reported_id and reported_id.strip() == candidate.candidate_id
            else candidate.candidate_id
        )
        reached = _split_functions(result_data["reached_functions"])
        reachability = result_data["reachability_evidence"]
        reason = result_data["reason"]
        if not poc_path or not reproduction_command:
            status = (
                "agent_blocked"
                if result.error and result.error.startswith("agent/")
                else "agent_failed"
                if result.error
                else result_data["dynamic_status"] or "invalid_submission"
            )
            if not result.error:
                status, reason = _status_for_missing_poc_submission(
                    status=status,
                    reason=reason,
                    iterations=iterations,
                    detector=target.detector,
                )
            if not iterations and not result.error:
                status, reason = _status_without_iteration_records(status, reason)
            if status not in _DYNAMIC_STATUSES:
                status = "reached_no_crash"
            return dynamic_result(
                candidate_id=selected_id,
                status=status,
                reached_functions=reached,
                reachability_evidence=reachability,
                reason=reason or (result.error or ""),
            ), result, timings

        # Keep the artifact contract aligned with grade.  The grader copies
        # only poc_bytes into a fresh container and substitutes poc_path in
        # reproduction_command; accepting a mismatched pair here would make
        # dynamic validation claim success for an artifact that grade must
        # reject.
        if poc_path not in reproduction_command:
            return dynamic_result(
                candidate_id=selected_id,
                status="invalid_submission",
                reached_functions=reached,
                reachability_evidence=reachability,
                reason=(
                    "poc_path must appear verbatim in reproduction_command; "
                    f"got {poc_path!r} and {reproduction_command!r}"
                ),
            ), result, timings

        # An emitted path is not enough. The file must cross the container
        # boundary and contain bytes before it becomes a CrashArtifact.
        poc_bytes = docker_ops.read_file(container, poc_path)
        if not poc_bytes:
            return dynamic_result(
                candidate_id=selected_id,
                status="invalid_submission",
                reached_functions=reached,
                reachability_evidence=reachability,
                reason="agent emitted a PoC path but the file was empty or missing",
            ), result, timings

        crash_type = result_data["crash_type"] or "unknown"
        poc_kind_value = result_data["poc_kind"] or "file"
        poc_kind = _normalize_poc_kind(poc_kind_value, target.detector)
        if poc_kind not in POC_KINDS:
            return dynamic_result(
                candidate_id=selected_id,
                status="invalid_submission",
                reached_functions=reached,
                reachability_evidence=reachability,
                reason=f"unsupported poc_kind: {poc_kind}",
            ), result, timings
        exit_code = _parse_exit_code(result_data["exit_code"])
        dup_check = result_data["dup_check"]

        if not _has_candidate_ready_iteration(iterations, target.detector):
            return dynamic_result(
                candidate_id=selected_id,
                status="invalid_submission",
                reached_functions=reached,
                reachability_evidence=reachability,
                reason=(
                    "successful PoC requires a candidate_ready iteration with "
                    "machine-observable evidence for the candidate"
                ),
            ), result, timings

        if target.detector == "logic":
            expected = result_data["expected_behavior"]
            observed = result_data["observed_behavior"]
            evidence = result_data["logic_evidence"]
            logic_type = result_data["logic_type"] or candidate.bug_class
            if not expected or not observed or not evidence or dup_check is None:
                return dynamic_result(
                    candidate_id=selected_id,
                    status="invalid_submission",
                    reached_functions=reached,
                    reachability_evidence=reachability,
                    reason=(
                        "logic submission requires expected_behavior, "
                        "observed_behavior, logic_evidence, and dup_check"
                    ),
                ), result, timings
            logic = LogicArtifact(
                poc_path=poc_path,
                poc_bytes=poc_bytes,
                reproduction_command=reproduction_command,
                logic_type=logic_type,
                expected_behavior=expected,
                observed_behavior=observed,
                logic_evidence=evidence[:10_000],
                exit_code=exit_code,
                dup_check=dup_check,
                poc_kind=poc_kind,
            )
            return dynamic_result(
                candidate_id=selected_id,
                status="validated",
                reached_functions=reached,
                reachability_evidence=reachability,
                reason=reason,
                logic=logic,
            ), result, timings

        crash_output = result_data["crash_output"][:10_000]
        crash = CrashArtifact(
            poc_path=poc_path,
            poc_bytes=poc_bytes,
            reproduction_command=reproduction_command,
            crash_type=crash_type,
            crash_output=crash_output,
            exit_code=exit_code,
            dup_check=dup_check,
            poc_kind=poc_kind,
        )
    return dynamic_result(
        candidate_id=selected_id,
        status="validated",
        reached_functions=reached,
        reachability_evidence=reachability,
        reason=reason,
        crash=crash,
    ), result, timings


async def _run_harness_managed_symcc(
    *,
    target: TargetConfig,
    candidate: StaticFinding,
    model: str,
    max_turns: int,
    container: str,
    symbolic_session: SymccSession,
    symbolic_context: dict,
    focus_area: str | None,
    known_bugs: list[str] | None,
    found_bugs_path: str | None,
    accept_dos: bool,
    instrumentation_context: dict | None,
    system_prompt: str | None,
    reattack_harness: str | None,
    attack_surface: str | None,
    detector: str,
    runtime_context: dict,
    iteration_limit: int,
    max_resume_attempts: int,
    transcript_path: str | None,
    progress_prefix: str | None,
    symbolic_result_path: str | None,
) -> tuple[AgentResult, dict[str, float]]:
    """Run the host-owned SymCC/agent feedback loop.

    The agent supplies a declarative source/seed plan.  The harness validates
    it, invokes the fixed SymCC client, replays generated files through the
    clean target, and exposes only bounded observations on the next round.
    This keeps provider invocation deterministic while retaining the agent's
    role in source understanding and hypothesis refinement.
    """
    started = time.time()
    deadline = time.monotonic() + 1800.0
    merged = AgentResult()
    feedback: dict | None = None
    rounds = 0
    time_to_site_reached: float | None = None
    # `max_turns` is deliberately not reduced for the planner.  The caller's
    # default is 20,000 and the wall-clock deadline below is the real bound;
    # reducing the step cap here caused the model to stop while it was still
    # staging a real source slice.
    planner_max_turns = max_turns

    for round_id in range(1, iteration_limit + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 15:
            merged.error = "agent/model_blocked: phase exceeded 1800s"
            break

        prompt = build_symcc_planner_prompt(
            candidate=candidate,
            github_url=target.github_url,
            commit=target.commit,
            source_root=target.source_root,
            binary_path=target.binary_path,
            detector=detector,
            runtime_context=runtime_context,
            symbolic_context=symbolic_context,
            feedback=feedback,
            round_id=round_id,
        )
        # Give the semantic planner enough time to stage a real source slice.
        # SymCC and the clean-target PoC phase still need a substantial part of
        # the fixed 1800-second budget, so this is intentionally a single
        # bounded planning turn in the normal case rather than eight short
        # turns that repeatedly rediscover the same source facts.
        agent_budget = min(600.0, max(90.0, remaining - 900.0))
        try:
            round_result = await asyncio.wait_for(
                run_agent(
                    prompt=prompt,
                    max_turns=planner_max_turns,
                    model=model,
                    container=container,
                    transcript_path=None,
                    progress_prefix=progress_prefix,
                    system_prompt=system_prompt,
                    max_resume_attempts=max_resume_attempts,
                    tools=["Read", "Write", "Bash"],
                    phase_timeout_s=agent_budget,
                    idle_timeout_s=agent_budget,
                ),
                timeout=min(agent_budget + 30.0, max(15.0, remaining - 5.0)),
            )
        except asyncio.TimeoutError:
            _terminate_agent_processes(container)
            round_result = AgentResult(
                error=f"agent/model_blocked: round exceeded {agent_budget:.0f}s"
            )
        if round_result.error and round_result.error.startswith("agent/"):
            _terminate_agent_processes(container)
        _merge_agent_result(merged, round_result)
        _append_transcript(transcript_path, round_result, role="symcc-planner")
        rounds = round_id

        # A final crash file is the original dynamic-validation contract. Do
        # not force the model to emit another plan after it has completed it.
        _crash_data, _crash_error, crash_present = _read_crash_result_xml(
            container, candidate.candidate_id
        )
        plan_text = round_result.find_tagged_message("symbolic_seed_plan")
        # A model may finish its clean-target proof and include a declarative
        # plan in the same response.  Run that plan before accepting the crash
        # so the experiment never labels a direct model result as a SymCC-aided
        # result.  If there is no plan, an already materialized crash remains
        # the original final protocol and can terminate normally.
        if crash_present and not plan_text:
            break
        if not plan_text:
            # Normal negative status tags also terminate this candidate. A
            # missing plan without a status is an agent failure, not evidence
            # that the candidate is unreachable.
            status_text = round_result.find_tagged_message("dynamic_status")
            if not round_result.error and not status_text:
                merged.error = "agent/model_blocked: no symbolic seed plan emitted"
            break
        try:
            plan = parse_seed_plan(plan_text, candidate_id=candidate.candidate_id)
        except SeedPlanError as exc:
            feedback = _seed_plan_error_feedback(round_id, str(exc))
            _persist_symcc_feedback(
                container, symbolic_result_path, round_id, feedback
            )
            continue

        symbolic_report = symbolic_session.submit_seed_plan(
            container, plan, round_id=round_id
        )
        replay_report = _replay_symcc_testcases(
            target=target,
            candidate=candidate,
            container=container,
            workspace=symbolic_session.workspace,
            plan=plan,
            symbolic_report=symbolic_report,
            round_id=round_id,
        )
        _persist_symcc_replay(
            container, symbolic_result_path, round_id, replay_report
        )
        feedback = _make_symcc_feedback(
            round_id=round_id,
            plan=plan,
            symbolic_report=symbolic_report,
            replay_report=replay_report,
            detector=detector,
        )
        if replay_report.get("site_reached"):
            time_to_site_reached = time.time() - started
            feedback["handoff"] = {
                "phase": "agent_dynamic_validation",
                "reason": (
                    "SymCC replay reached the candidate observation; stop symbolic "
                    "exploration and return control to the agent"
                ),
                "time_to_site_reached_s": round(time_to_site_reached, 3),
            }
        _persist_symcc_feedback(container, symbolic_result_path, round_id, feedback)
        _write_harness_iteration(container, candidate, feedback, round_id, detector)

        # SymCC is a constrained candidate generator, not the semantic oracle.
        # Hand off after the first usable campaign even when no textual anchor
        # was observed: a clean negative result, the original semantic seeds,
        # and the generated mutations are precisely the feedback the PoC agent
        # needs to choose a better lifecycle/state construction.  Waiting for
        # `site_reached` here made the planner loop consume the whole phase and
        # discarded the most useful LLM-produced seed information.
        if symbolic_report.get("status") in {"completed", "failed", "unavailable", "invalid_plan"}:
            remaining = deadline - time.monotonic()
            if remaining <= 15:
                merged.error = "agent/model_blocked: no time left after site reach"
                break
            handoff_budget = min(900.0, max(30.0, remaining - 15.0))
            handoff_prompt = build_poc_generation_prompt(
                candidate=candidate,
                github_url=target.github_url,
                commit=target.commit,
                source_root=target.source_root,
                binary_path=target.binary_path,
                focus_area=focus_area,
                known_bugs=known_bugs,
                found_bugs_path=found_bugs_path,
                accept_dos=accept_dos,
                reattack_harness=reattack_harness,
                attack_surface=attack_surface,
                detector=detector,
                runtime_context=runtime_context,
                instrumentation_context=instrumentation_context,
                symbolic_feedback=feedback,
                max_iterations=iteration_limit,
            )
            try:
                handoff_result = await asyncio.wait_for(
                    run_agent(
                        prompt=handoff_prompt,
                        max_turns=max_turns,
                        model=model,
                        container=container,
                        transcript_path=None,
                        progress_prefix=progress_prefix,
                        system_prompt=system_prompt,
                        max_resume_attempts=max_resume_attempts,
                        tools=["Read", "Write", "Bash"],
                        phase_timeout_s=handoff_budget,
                        idle_timeout_s=handoff_budget,
                    ),
                    timeout=min(handoff_budget + 30.0, max(15.0, remaining - 5.0)),
                )
            except asyncio.TimeoutError:
                _terminate_agent_processes(container)
                handoff_result = AgentResult(
                    error=f"agent/model_blocked: handoff exceeded {handoff_budget:.0f}s"
                )
            if handoff_result.error and handoff_result.error.startswith("agent/"):
                _terminate_agent_processes(container)
            _merge_agent_result(merged, handoff_result)
            _append_transcript(transcript_path, handoff_result, role="poc-generator")
            break

        if crash_present:
            break

        if time.monotonic() >= deadline:
            merged.error = "agent/model_blocked: phase exceeded 1800s"
            break

    merged.finished_at = time.time()
    timings = {
        "dynamic_validation": time.time() - started,
        "harness_symcc_rounds": float(rounds),
    }
    if time_to_site_reached is not None:
        timings["time_to_site_reached"] = time_to_site_reached
        timings["symcc_site_reached"] = 1.0
    else:
        timings["symcc_site_reached"] = 0.0
    return merged, timings


def _merge_agent_result(destination: AgentResult, source: AgentResult) -> None:
    """Merge per-round agent telemetry without losing structured messages."""
    destination.messages.extend(source.messages)
    destination.result_message = source.result_message or destination.result_message
    destination.session_id = source.session_id or destination.session_id
    destination.error = source.error
    destination.resume_count += source.resume_count
    destination.tool_call_count += source.tool_call_count
    destination.assistant_message_count += source.assistant_message_count
    if destination.started_at is None:
        destination.started_at = source.started_at
    destination.finished_at = source.finished_at or destination.finished_at
    if destination.first_poc_at is None:
        destination.first_poc_at = source.first_poc_at


def _append_transcript(
    path: str | None, result: AgentResult, *, role: str | None = None
) -> None:
    if not path:
        return
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a") as stream:
        for event in result.transcript():
            if role:
                event = dict(event)
                event["harness_agent_role"] = role
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")


def _terminate_agent_processes(container: str) -> None:
    """Stop only the opencode process after an orchestration hard deadline."""
    try:
        docker_ops.exec_sh(
            container,
            "pids=$(ps -eo pid=,comm= | awk '$2 == \"opencode\" {print $1}'); "
            "[ -z \"$pids\" ] || kill -TERM $pids; sleep 1; "
            "pids=$(ps -eo pid=,comm= | awk '$2 == \"opencode\" {print $1}'); "
            "[ -z \"$pids\" ] || kill -KILL $pids",
            timeout=5,
        )
    except Exception:
        return


def _seed_plan_error_feedback(round_id: int, error: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "provider": "symcc",
        "round_id": round_id,
        "status": "invalid_plan",
        "errors": [error[:2000]],
        "progress": {
            "testcase_count": 0,
            "site_reached": False,
            "matched_candidate": False,
            "distance_to_candidate": None,
        },
    }


def _persist_symcc_feedback(
    container: str,
    result_path: str | None,
    round_id: int,
    feedback: dict[str, Any],
) -> None:
    raw = json.dumps(feedback, indent=2, ensure_ascii=False).encode() + b"\n"
    guest_path = f"/work/validation/symcc-feedback-round-{round_id:03d}.json"
    try:
        docker_ops.write_file(container, guest_path, raw)
    except Exception:
        pass
    if result_path:
        root = Path(result_path)
        root.mkdir(parents=True, exist_ok=True)
        (root / f"feedback-round-{round_id:03d}.json").write_bytes(raw)


def _persist_symcc_replay(
    container: str,
    result_path: str | None,
    round_id: int,
    replay_report: dict[str, Any],
) -> None:
    """Keep the complete replay evidence outside the next model prompt."""
    raw = json.dumps(replay_report, indent=2, ensure_ascii=False).encode() + b"\n"
    guest_path = f"/work/validation/symcc-replay-round-{round_id:03d}.json"
    try:
        docker_ops.write_file(container, guest_path, raw)
    except Exception:
        pass
    if result_path:
        root = Path(result_path)
        root.mkdir(parents=True, exist_ok=True)
        (root / f"replay-round-{round_id:03d}.json").write_bytes(raw)


def _replay_symcc_testcases(
    *,
    target: TargetConfig,
    candidate: StaticFinding,
    container: str,
    workspace: Path | None,
    plan: Any,
    symbolic_report: dict[str, Any],
    round_id: int,
) -> dict[str, Any]:
    """Replay seeds and generated files through the original target container.

    A seed is not evidence of a bug by itself, but it is an important part of
    the semantic handoff: the planner may have chosen a valid lifecycle/state
    sequence that byte-level SymCC mutations immediately destroy.  The old
    implementation replayed only provider-generated files, so it threw away
    exactly that information before the PoC agent saw it.
    """
    cases: list[dict[str, Any]] = []
    if workspace is None:
        return {
            "schema_version": 1,
            "round_id": round_id,
            "status": "unavailable",
            "cases": cases,
            "testcase_count": 0,
            "site_reached": False,
            "matched_candidate": False,
            "errors": ["SymCC workspace is unavailable"],
        }
    root = workspace.resolve()
    markers = _candidate_observation_markers(candidate, plan.target_anchors)
    raw_cases = symbolic_report.get("testcases", [])
    if not isinstance(raw_cases, list):
        raw_cases = []
    try:
        rc, _out, err = docker_ops.exec_sh(
            container,
            f"mkdir -p -- {shlex.quote(f'/work/validation/symcc-replay/round-{round_id:03d}')}",
            timeout=15,
        )
        if rc:
            return {
                "schema_version": 1,
                "round_id": round_id,
                "status": "unavailable",
                "cases": cases,
                "testcase_count": 0,
                "site_reached": False,
                "matched_candidate": False,
                "errors": [f"cannot create replay directory: {err[-500:]}"]
            }
    except Exception as exc:
        return {
            "schema_version": 1,
            "round_id": round_id,
            "status": "unavailable",
            "cases": cases,
            "testcase_count": 0,
            "site_reached": False,
            "matched_candidate": False,
            "errors": [f"cannot create replay directory: {type(exc).__name__}: {exc}"]
        }
    def replay_case(
        *,
        data: bytes,
        source_path: str,
        guest_name: str,
        kind: str,
        seed_name: str | None = None,
    ) -> None:
        guest_path = f"/work/validation/symcc-replay/round-{round_id:03d}/{guest_name}"
        try:
            docker_ops.write_file(container, guest_path, data)
            argv = [
                shlex.quote(target.binary_path),
                *(
                    shlex.quote(arg.replace("{input_file}", guest_path))
                    for arg in plan.program_args
                ),
            ]
            command = f"timeout --signal=KILL {max(1, int(plan.timeout_s))}s " + " ".join(argv)
            rc, out, err = docker_ops.exec_sh(
                container, command, timeout=max(15, int(plan.timeout_s) + 15)
            )
        except Exception as exc:
            cases.append({
                "path": source_path,
                "kind": kind,
                "seed_name": seed_name,
                "status": "replay_error",
                "error": f"{type(exc).__name__}: {exc}",
            })
            return
        output = ((out or "") + "\n" + (err or ""))[-12_000:]
        sanitizer_event = bool(
            re.search(
                r"AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|"
                r"LeakSanitizer",
                output,
                re.IGNORECASE,
            )
        )
        matched_markers = [marker for marker in markers if marker in output]
        site_reached = bool(matched_markers)
        matched = site_reached and (sanitizer_event if target.detector != "logic" else True)
        cases.append({
            "path": source_path,
            "kind": kind,
            "seed_name": seed_name,
            "size": len(data),
            "exit_code": rc,
            "status": "candidate_match" if matched else "observed",
            "sanitizer_event": sanitizer_event,
            "site_reached": site_reached,
            "matched_candidate": matched,
            "matched_anchors": matched_markers[:32],
            "output_tail": output,
        })

    # Replay the concrete seeds first.  SymCC keeps input length fixed and
    # often mutates syntax or object-lifecycle setup; a valid seed therefore
    # carries semantic information that its generated variants may not retain.
    for index, seed in enumerate(plan.seeds):
        source = (root / plan.working_dir / "seeds" / seed.name).resolve()
        if not source.is_relative_to(root) or not source.is_file():
            cases.append({
                "path": f"{plan.working_dir}/seeds/{seed.name}",
                "kind": "seed",
                "seed_name": seed.name,
                "status": "missing_seed",
                "error": "seed materialization is missing from the symbolic workspace",
            })
            continue
        try:
            data = source.read_bytes()
        except OSError as exc:
            cases.append({
                "path": str(source.relative_to(root)),
                "kind": "seed",
                "seed_name": seed.name,
                "status": "read_error",
                "error": str(exc),
            })
            continue
        replay_case(
            data=data,
            source_path=str(source.relative_to(root)),
            guest_name=f"seed-{index:03d}-{seed.name}",
            kind="seed",
            seed_name=seed.name,
        )

    generated_index = 0
    for item in raw_cases[:128]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        source = (root / item["path"]).resolve()
        if not source.is_relative_to(root) or not source.is_file():
            continue
        try:
            data = source.read_bytes()
        except OSError:
            continue
        replay_case(
            data=data,
            source_path=item["path"],
            guest_name=f"generated-{generated_index:03d}",
            kind="generated",
            seed_name=str(item.get("seed") or "") or None,
        )
        generated_index += 1
    site_reached = any(bool(item.get("site_reached")) for item in cases)
    matched_candidate = any(bool(item.get("matched_candidate")) for item in cases)
    sanitizer = any(bool(item.get("sanitizer_event")) for item in cases)
    if matched_candidate:
        distance: int | None = 0
    elif site_reached:
        distance = 1
    elif sanitizer:
        distance = 2
    else:
        distance = None
    return {
        "schema_version": 1,
        "round_id": round_id,
        "status": "completed",
        "cases": cases,
        "testcase_count": len(cases),
        "seed_case_count": sum(item.get("kind") == "seed" for item in cases),
        "generated_case_count": sum(item.get("kind") == "generated" for item in cases),
        "site_reached": site_reached,
        "matched_candidate": matched_candidate,
        "sanitizer_event": sanitizer,
        "distance_to_candidate": distance,
        "anchors": markers,
    }


def _candidate_observation_markers(
    candidate: StaticFinding, anchors: tuple[str, ...]
) -> list[str]:
    values = list(anchors)
    values.extend([candidate.location, candidate.static_call_chain, candidate.root_cause])
    markers: list[str] = []
    for value in values:
        for marker in re.findall(r"[A-Za-z_][A-Za-z0-9_.:/-]{3,}", value or ""):
            if marker not in markers and len(markers) < 64:
                markers.append(marker)
    return markers


def _make_symcc_feedback(
    *,
    round_id: int,
    plan: Any,
    symbolic_report: dict[str, Any],
    replay_report: dict[str, Any],
    detector: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "provider": "symcc",
        "round_id": round_id,
        "status": symbolic_report.get("status", "unknown"),
        "plan": {
            "working_dir": plan.working_dir,
            "source_count": len(plan.sources),
            "seed_count": len(plan.seeds),
            "seed_names": [seed.name for seed in plan.seeds],
            "target_anchors": list(plan.target_anchors),
            "timeout_s": plan.timeout_s,
            "max_testcases": plan.max_testcases,
        },
        "symbolic": {
            "status": symbolic_report.get("status"),
            "duration_s": symbolic_report.get("duration_s"),
            "compile_duration_s": symbolic_report.get("compile_duration_s"),
            "testcase_count": symbolic_report.get("testcase_count", 0),
            "runs": symbolic_report.get("runs", [])[:32],
            "errors": symbolic_report.get("errors", [])[:20],
        },
        # The complete report is persisted separately.  The model receives a
        # compact, representative view so feedback remains actionable instead
        # of consuming the context window with dozens of repeated parser
        # errors or sanitizer tails.
        "replay": _summarize_replay_for_model(replay_report),
        "progress": {
            "detector": detector,
            "site_reached": bool(replay_report.get("site_reached")),
            "matched_candidate": bool(replay_report.get("matched_candidate")),
            "distance_to_candidate": replay_report.get("distance_to_candidate"),
            "phase": (
                "agent_handoff"
                if replay_report.get("site_reached")
                else "symcc_search"
            ),
            "handoff_to_agent": bool(replay_report.get("site_reached")),
            "interpretation": (
                "candidate sanitizer event matched an anchor"
                if replay_report.get("matched_candidate")
                else "candidate site reached; stop SymCC and hand off crash-condition "
                "construction to the agent"
                if replay_report.get("site_reached")
                else "generated inputs did not yet prove the candidate"
            ),
        },
    }


def _summarize_replay_for_model(replay_report: dict[str, Any]) -> dict[str, Any]:
    """Build a bounded semantic view of a replay campaign for the LLM."""
    raw_cases = replay_report.get("cases", [])
    if not isinstance(raw_cases, list):
        raw_cases = []
    seeds = [item for item in raw_cases if item.get("kind") == "seed"]
    generated = [item for item in raw_cases if item.get("kind") == "generated"]

    def compact(item: dict[str, Any]) -> dict[str, Any]:
        result = {
            key: item.get(key)
            for key in (
                "path", "kind", "seed_name", "size", "exit_code", "status",
                "sanitizer_event", "site_reached", "matched_candidate",
                "matched_anchors",
            )
            if key in item
        }
        output = item.get("output_tail")
        if isinstance(output, str) and output:
            result["output_tail"] = output[-1600:]
        if item.get("error"):
            result["error"] = str(item["error"])[:1200]
        return result

    # Always retain every concrete seed (there are at most 16), then include a
    # small representative sample of mutations.  Prefer candidates with an
    # observable event or non-zero exit, followed by the first few normal
    # cases, so the feedback explains both progress and failure modes.
    interesting = [
        item for item in generated
        if item.get("matched_candidate")
        or item.get("site_reached")
        or item.get("sanitizer_event")
        or item.get("exit_code") not in (0, None)
    ]
    examples = interesting[:12]
    if len(examples) < 20:
        examples.extend(item for item in generated if item not in examples)
        examples = examples[:20]
    status_counts: dict[str, int] = {}
    for item in raw_cases:
        status = str(item.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "status": replay_report.get("status"),
        "testcase_count": replay_report.get("testcase_count", len(raw_cases)),
        "seed_case_count": replay_report.get("seed_case_count", len(seeds)),
        "generated_case_count": replay_report.get(
            "generated_case_count", len(generated)
        ),
        "status_counts": status_counts,
        "site_reached": bool(replay_report.get("site_reached")),
        "matched_candidate": bool(replay_report.get("matched_candidate")),
        "sanitizer_event": bool(replay_report.get("sanitizer_event")),
        "distance_to_candidate": replay_report.get("distance_to_candidate"),
        "anchors": list(replay_report.get("anchors", []))[:64],
        "errors": [str(item)[:1200] for item in replay_report.get("errors", [])[:20]],
        "seed_results": [compact(item) for item in seeds],
        "generated_examples": [compact(item) for item in examples],
        "raw_report": (
            f"/work/validation/symcc-replay-round-"
            f"{int(replay_report.get('round_id', 0)):03d}.json"
        ),
    }


def _write_harness_iteration(
    container: str,
    candidate: StaticFinding,
    feedback: dict[str, Any],
    round_id: int,
    detector: str,
) -> None:
    progress = feedback.get("progress", {})
    matched = bool(progress.get("matched_candidate"))
    site = bool(progress.get("site_reached"))
    sanitizer = bool(feedback.get("replay", {}).get("sanitizer_event"))
    record = {
        "schema_version": 1,
        "round_id": round_id,
        "candidate_id": candidate.candidate_id,
        "hypothesis": {
            "target_site": ", ".join(feedback.get("plan", {}).get("target_anchors", [])),
            "source": "harness-managed SymCC replay",
        },
        "observations": {
            "site_reached": site,
            "sanitizer_event": sanitizer,
            "bad_state_observed": False,
            "bad_effect_observed": matched if detector == "logic" else sanitizer,
            "matched_candidate": matched,
        },
        "decision": "candidate_ready" if matched else "continue",
        "reason": str(feedback.get("progress", {}).get("interpretation", ""))[:2000],
        "evidence": {
            "provider": "symcc",
            "distance_to_candidate": progress.get("distance_to_candidate"),
            "testcase_count": feedback.get("replay", {}).get("testcase_count", 0),
        },
    }
    try:
        docker_ops.write_file(
            container,
            f"/work/validation/iterations/round-{round_id:03d}.json",
            json.dumps(record, indent=2, ensure_ascii=False).encode() + b"\n",
        )
    except Exception:
        return


def _symcc_hidden_path(binary_path: str, role: str) -> str:
    path = Path(shlex.split(binary_path)[0])
    return str(path.with_name(f".harness-{role}-{path.name}"))


def _symcc_sidecar_name(target_name: str) -> str:
    safe_target = re.sub(r"[^A-Za-z0-9_.-]", "-", target_name)[:20] or "target"
    return f"symcc-fb-{safe_target}-{uuid.uuid4().hex[:12]}"[:63]


def _hide_source_vcs_metadata(container: str, target: TargetConfig) -> None:
    """Remove source-control metadata before dynamic exploration in every arm.

    Commit history can disclose a fix or a reproducer and invalidate a blinded
    comparison. This is enforced in the target view rather than left as a
    prompt-only instruction.
    """
    vcs_path = f"{target.source_root.rstrip('/')}/.git"
    rc, _out, err = docker_ops.exec_sh(
        container,
        f"if [ -e {shlex.quote(vcs_path)} ]; then "
        f"rm -rf -- {shlex.quote(vcs_path)}; fi",
        timeout=30,
    )
    if rc:
        raise RuntimeError(f"cannot remove target VCS metadata: {err[-500:]}")


def _symcc_sidecar_settings(config: dict[str, Any]) -> tuple[str, str, int]:
    """Validate resource limits for the isolated SymCC worker container."""
    memory_limit = config.get("memory_limit", "4g")
    if (
        not isinstance(memory_limit, str)
        or not re.fullmatch(r"[1-9][0-9]*(?:[kmg])?", memory_limit.lower())
    ):
        raise ValueError("symbolic_execution.symcc.memory_limit must look like 4g or 2048m")

    raw_cpus = config.get("cpus", 2)
    if isinstance(raw_cpus, bool) or not isinstance(raw_cpus, (int, float, str)):
        raise ValueError("symbolic_execution.symcc.cpus must be a positive Docker CPU quota")
    cpus = str(raw_cpus)
    try:
        cpu_count = float(cpus)
    except ValueError as exc:
        raise ValueError("symbolic_execution.symcc.cpus must be numeric") from exc
    if not 0 < cpu_count <= 64:
        raise ValueError("symbolic_execution.symcc.cpus must be between 0 and 64")

    max_concurrent = config.get("max_concurrent_jobs", 1)
    if isinstance(max_concurrent, bool) or not isinstance(max_concurrent, int):
        raise ValueError("symbolic_execution.symcc.max_concurrent_jobs must be an integer")
    if not 1 <= max_concurrent <= 4:
        raise ValueError("symbolic_execution.symcc.max_concurrent_jobs must be between 1 and 4")
    return memory_limit.lower(), cpus, max_concurrent


def _prepare_prebuilt_symcc_protocol(
    container: str, target: TargetConfig, candidate: StaticFinding | None = None,
    *, max_requests: int = _DEFAULT_MAX_ITERATIONS,
) -> dict[str, Any]:
    """Validate prebuilt executables and expose the request/response client."""
    config = target.symcc_runtime or {}
    symcc_binary = str(config.get("binary_path") or "")
    if not symcc_binary.startswith("/"):
        raise ValueError("symbolic_execution.symcc.binary_path must be absolute")
    artifact_commit = config.get("commit")
    if not isinstance(artifact_commit, str) or artifact_commit != target.commit:
        raise ValueError(
            "prebuilt SymCC artifact must declare the target commit: "
            f"expected {target.commit!r}, got {artifact_commit!r}"
        )
    clean_parts = shlex.split(target.binary_path)
    symcc_parts = shlex.split(symcc_binary)
    if len(clean_parts) != 1 or len(symcc_parts) != 1:
        raise ValueError("prebuilt execution binary paths must not contain arguments")
    if clean_parts[0] == symcc_parts[0]:
        raise ValueError("clean and SymCC binary_path values must be different")
    memory_limit, sidecar_cpus, max_concurrent_symcc_jobs = _symcc_sidecar_settings(
        config
    )

    symcc_args = config.get("program_args") or ["{input_file}"]
    if (
        not isinstance(symcc_args, list)
        or not symcc_args
        or not all(isinstance(arg, str) and "\x00" not in arg for arg in symcc_args)
        or sum(str(arg).count("{input_file}") for arg in symcc_args) != 1
    ):
        raise ValueError(
            "symbolic_execution.symcc.program_args must contain {input_file} exactly once"
        )
    binary_clean_hidden = _symcc_hidden_path(clean_parts[0], "clean")
    binary_symcc_hidden = _symcc_hidden_path(symcc_parts[0], "symcc")
    paths = [
        INPUT_ROOT,
        REQUEST_ROOT,
        PENDING_ROOT,
        RESPONSE_ROOT,
        PROCESSED_ROOT,
        "/work/validation/symcc-results",
        "/work/validation/symcc-feedback",
        str(Path(binary_clean_hidden).parent),
        str(Path(binary_symcc_hidden).parent),
    ]
    command = "mkdir -p -- " + " ".join(shlex.quote(path) for path in paths)
    rc, _out, err = docker_ops.exec_sh(container, command, timeout=15)
    if rc:
        raise RuntimeError(f"cannot prepare execution protocol directories: {err[-500:]}")

    for original, hidden, label in (
        (clean_parts[0], binary_clean_hidden, "clean"),
        (symcc_parts[0], binary_symcc_hidden, "SymCC"),
    ):
        check = f"test -f {shlex.quote(original)} && test -x {shlex.quote(original)}"
        rc, _out, err = docker_ops.exec_sh(container, check, timeout=15)
        if rc:
            raise RuntimeError(
                f"prebuilt {label} executable is missing or not executable: {original}: {err[-300:]}"
            )
        stage = (
            f"test ! -e {shlex.quote(hidden)} && "
            f"mv -- {shlex.quote(original)} {shlex.quote(hidden)}"
        )
        rc, _out, err = docker_ops.exec_sh(container, stage, timeout=30)
        if rc:
            raise RuntimeError(f"cannot stage prebuilt {label} executable: {err[-500:]}")
        guard = (
            "#!/bin/sh\n"
            f"echo 'direct {label} execution is disabled; use {RUNNER_PATH}' >&2\n"
            "exit 126\n"
        ).encode()
        docker_ops.write_file(container, original, guard)
        rc, _out, err = docker_ops.exec_sh(
            container, f"chmod 0555 -- {shlex.quote(original)}", timeout=15
        )
        if rc:
            raise RuntimeError(f"cannot install {label} execution guard: {err[-300:]}")

    docker_ops.write_file(container, RUNNER_PATH, protocol_runner_script())
    rc, _out, err = docker_ops.exec_sh(
        container, f"chmod 0555 -- {shlex.quote(RUNNER_PATH)}", timeout=15
    )
    if rc:
        raise RuntimeError(f"cannot enable execution protocol client: {err[-300:]}")
    docker_ops.write_file(container, FEEDBACK_READER_PATH, protocol_feedback_reader_script())
    rc, _out, err = docker_ops.exec_sh(
        container, f"chmod 0555 -- {shlex.quote(FEEDBACK_READER_PATH)}", timeout=15
    )
    if rc:
        raise RuntimeError(f"cannot enable feedback reader: {err[-300:]}")
    rc, _out, err = docker_ops.exec_sh(
        container,
        f"mkdir -p -- {shlex.quote(FEEDBACK_ROOT)} {shlex.quote(PROCESSED_ROOT)}",
        timeout=15,
    )
    if rc:
        raise RuntimeError(f"cannot initialize execution protocol directories: {err[-300:]}")
    docker_ops.write_file(
        container, REQUEST_TEMPLATE_PATH, protocol_template(symcc_args)
    )
    docker_ops.write_file(
        container, EXECUTION_README_PATH,
        protocol_readme(
            symbolic_enabled=True,
            max_requests=max_requests,
            max_concurrent_symcc_jobs=max_concurrent_symcc_jobs,
        ),
    )
    feedback_runtime = _load_symcc_feedback_runtime(
        container=container, target=target, candidate=candidate
    )
    prompt_feedback = {
        key: value for key, value in feedback_runtime.items()
        if key not in {"graph", "marker_ids", "target_block_ids"}
    }
    return {
        "schema_version": 1,
        "provider": "symcc",
        "status": "ready",
        "orchestration": "prebuilt_protocol",
        "runner": RUNNER_PATH,
        "feedback_reader": FEEDBACK_READER_PATH,
        "input_root": INPUT_ROOT,
        "request_root": REQUEST_ROOT,
        "response_root": RESPONSE_ROOT,
        "feedback_root": FEEDBACK_ROOT,
        "prebuilt_binary": True,
        "artifact_commit": artifact_commit,
        "worker_isolated": True,
        "worker_network": "none",
        "worker_memory_limit": memory_limit,
        "worker_cpus": sidecar_cpus,
        "max_concurrent_jobs": max_concurrent_symcc_jobs,
        "symcc_program_args": symcc_args,
        "feedback": prompt_feedback,
        "_feedback_runtime": feedback_runtime,
    }


def _candidate_target_anchors(candidate: StaticFinding) -> list[dict[str, Any]]:
    """Normalize static-report observability anchors without inventing locations."""
    anchors: list[dict[str, Any]] = []
    for raw in candidate.observability_targets:
        file_name = raw.get("source_file", raw.get("file"))
        function = raw.get("function")
        line = raw.get("line")
        if file_name is not None and not isinstance(file_name, str):
            continue
        if function is not None and not isinstance(function, str):
            continue
        if isinstance(line, bool) or (line is not None and not isinstance(line, int)):
            continue
        if (file_name is None) != (line is None):
            continue
        if not file_name and not function:
            continue
        anchor: dict[str, Any] = {}
        if file_name:
            anchor["source_file"] = file_name
            anchor["line"] = line
        if function:
            anchor["function"] = function
        anchors.append(anchor)
    if anchors:
        return anchors[:50]

    # Legacy static reports encode the primary site as e.g.
    # "src/parser.c:123, function parse". Parse only explicit syntax; if it
    # does not match, leave target reachability unknown instead of guessing.
    location = candidate.location.strip()
    match = re.search(r"([^\s,]+):(\d+)", location)
    function_match = re.search(r"\bfunction\s+([A-Za-z_~][A-Za-z0-9_:~.$<>]*)", location)
    if match:
        anchor = {"source_file": match.group(1), "line": int(match.group(2))}
        if function_match:
            anchor["function"] = function_match.group(1)
        return [anchor]
    if function_match:
        return [{"function": function_match.group(1)}]
    return []


def _load_symcc_feedback_runtime(
    *, container: str, target: TargetConfig, candidate: StaticFinding | None
) -> dict[str, Any]:
    """Load and version-check the prebuilt binary's source/CFG feedback map."""
    config = target.symcc_runtime or {}
    map_path = config.get("feedback_map_path")
    base: dict[str, Any] = {
        "status": "unavailable",
        "map_path": map_path,
        "source_commit": target.commit,
        "goal": {"targets": _candidate_target_anchors(candidate) if candidate else []},
        "marker_ids": [],
        "target_block_ids": [],
    }
    if not isinstance(map_path, str) or not map_path.startswith("/"):
        base["reason"] = "SymCC image config has no absolute feedback_map_path"
        return base

    quoted = shlex.quote(map_path)
    dir_rc, _out, _err = docker_ops.exec_sh(
        container, f"test -d {quoted}", timeout=15
    )
    if dir_rc == 0:
        rc, listing, err = docker_ops.exec_sh(
            container,
            f"find {quoted} -maxdepth 1 -type f -name '*.jsonl' -print | sort",
            timeout=30,
        )
        if rc:
            base["reason"] = f"cannot enumerate feedback map directory: {err[-500:]}"
            return base
        paths = [line.strip() for line in listing.splitlines() if line.strip()]
    else:
        rc, _out, err = docker_ops.exec_sh(
            container, f"test -f {quoted}", timeout=15
        )
        if rc:
            base["reason"] = f"feedback map file/directory is missing: {err[-300:]}"
            return base
        paths = [map_path]
    if not paths:
        base["reason"] = "feedback map directory contains no JSONL files"
        return base

    contents: list[bytes] = []
    total_size = 0
    try:
        for path in paths[:20_000]:
            if not path.startswith(map_path.rstrip("/") + "/") and path != map_path:
                raise ValueError(f"map path escaped configured directory: {path}")
            _rc, size_text, _err = docker_ops.exec_sh(
                container, f"stat -c %s -- {shlex.quote(path)}", timeout=15
            )
            size = int(size_text.strip())
            total_size += size
            if size < 0 or total_size > 128 * 1024 * 1024:
                raise ValueError("feedback maps exceed the 128 MiB read limit")
            contents.append(docker_ops.read_file(container, path))
    except Exception as exc:
        base["reason"] = f"cannot read feedback maps: {type(exc).__name__}: {exc}"
        return base

    try:
        graph = load_json_map_files(contents)
    except FeedbackMapError as exc:
        base["reason"] = f"feedback map validation failed: {exc}"
        return base
    if graph["map_records_missing_commit"]:
        base["reason"] = (
            f"{graph['map_records_missing_commit']} feedback-map records do not declare "
            "their source commit"
        )
        base["map_status"] = "version_unverified"
        return base
    if graph["source_commits"] != [target.commit]:
        base["reason"] = (
            f"feedback-map commits {graph['source_commits']!r} do not match target "
            f"commit {target.commit!r}"
        )
        base["map_status"] = "version_mismatch"
        return base

    anchors = base["goal"]["targets"]
    base["map_status"] = "ready"
    base["map_record_count"] = graph["map_record_count"]
    base["node_count"] = len(graph["nodes"])
    base["source_location_count"] = len(graph["locations"])
    if not anchors:
        base["status"] = "goal_unresolved"
        base["reason"] = "static finding has no structured or parseable target anchor"
        base["graph"] = graph
        return base
    try:
        marker_ids, target_block_ids = resolve_target_ids(
            graph, base["goal"], source_root=target.source_root
        )
    except FeedbackMapError as exc:
        base["status"] = "goal_unresolved"
        base["reason"] = str(exc)
        base["graph"] = graph
        return base
    base.update({
        "status": "ready",
        "marker_ids": marker_ids,
        "target_block_ids": target_block_ids,
        "target_marker_count": len(marker_ids),
        "graph": graph,
    })
    return base


def _protocol_sanitizer_event(output: str) -> bool:
    return bool(re.search(
        r"AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|LeakSanitizer",
        output,
        re.IGNORECASE,
    ))


def _run_protocol_binary(
    *, container: str, binary: str, request: ExecutionRequest, input_path: str,
    symcc_output: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    argv = target_argv(binary, request.program_args, input_path)
    env = dict(request.env)
    if symcc_output is not None:
        env.update({"SYMCC_INPUT_FILE": input_path, "SYMCC_OUTPUT_DIR": symcc_output})
    if extra_env:
        env.update(extra_env)
    env_prefix = " ".join(
        f"{shlex.quote(key)}={shlex.quote(value)}" for key, value in env.items()
    )
    command = (
        f"timeout --signal=KILL {request.timeout_s}s "
        + (f"env {env_prefix} " if env_prefix else "")
        + shell_argv(argv)
    )
    started = time.time()
    try:
        rc, stdout, stderr = docker_ops.exec_sh(
            container, command, timeout=request.timeout_s + 15
        )
        duration = time.time() - started
        timed_out = (
            rc in {124, 137}
            and duration >= max(0, request.timeout_s - 1)
        )
        output = ((stdout or "") + "\n" + (stderr or ""))[-12_000:]
        return {
            "status": (
                "completed" if rc == 0 else "timed_out" if timed_out else "failed"
            ),
            "exit_code": rc,
            "duration_s": round(duration, 3),
            "timed_out": timed_out,
            "stdout": (stdout or "")[-12_000:],
            "stderr": (stderr or "")[-12_000:],
            "output_tail": output,
            "sanitizer_event": _protocol_sanitizer_event(output),
        }
    except Exception as exc:
        return {
            "status": "execution_error",
            "exit_code": None,
            "duration_s": round(time.time() - started, 3),
            "stdout": "",
            "stderr": "",
            "output_tail": "",
            "sanitizer_event": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _prepare_prebuilt_protocol_request(
    *, container: str, target: TargetConfig, raw: bytes, filename: str,
    round_id: int,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    try:
        request = parse_request(raw, filename=filename)
    except (ExecutionRequestError, UnicodeDecodeError) as exc:
        return {"schema_version": 1, "status": "invalid_request", "errors": [str(exc)]}, None
    try:
        rc, resolved_input, err = docker_ops.exec_sh(
            container,
            f"readlink -f -- {shlex.quote(request.input_path)}",
            timeout=15,
        )
        resolved_input = resolved_input.strip()
        if rc or not resolved_input.startswith(INPUT_ROOT + "/"):
            raise ValueError(
                f"input must resolve to a regular file below {INPUT_ROOT}: {err[-300:]}"
            )
        rc, _out, err = docker_ops.exec_sh(
            container, f"test -f {shlex.quote(resolved_input)}", timeout=15
        )
        if rc:
            raise ValueError(f"input is not a regular file: {request.input_path}: {err[-300:]}")
        rc, size_text, err = docker_ops.exec_sh(
            container,
            f"stat -c %s -- {shlex.quote(resolved_input)}",
            timeout=15,
        )
        if rc:
            raise ValueError(f"input file does not exist: {request.input_path}")
        try:
            input_size = int(size_text.strip())
        except ValueError as exc:
            raise ValueError(f"cannot determine input size: {err[-300:]}") from exc
        if input_size > 16 * 1024 * 1024:
            raise ValueError("input exceeds the 16 MiB execution-protocol limit")
        input_bytes = docker_ops.read_file(container, resolved_input)
        if len(input_bytes) != input_size:
            raise ValueError("input read was incomplete")
    except Exception as exc:
        return {
            "schema_version": 1, "status": "invalid_request",
            "request_id": request.request_id, "errors": [str(exc)],
        }, None
    digest = hashlib.sha256(input_bytes).hexdigest()
    snapshot_path = f"{SNAPSHOT_ROOT}/{request.request_id}.bin"
    try:
        rc, _out, err = docker_ops.exec_sh(
            container,
            f"mkdir -p -- {shlex.quote(SNAPSHOT_ROOT)} && "
            f"test ! -e {shlex.quote(snapshot_path)}",
            timeout=15,
        )
        if rc:
            raise RuntimeError(f"cannot reserve request snapshot: {err[-300:]}")
        docker_ops.write_file(container, snapshot_path, input_bytes)
        rc, _out, err = docker_ops.exec_sh(
            container, f"chmod 0444 -- {shlex.quote(snapshot_path)}", timeout=15
        )
        if rc:
            raise RuntimeError(f"cannot protect request snapshot: {err[-300:]}")
    except Exception as exc:
        return {
            "schema_version": 1,
            "protocol": "dynamic-execution",
            "status": "execution_error",
            "request_id": request.request_id,
            "input_sha256": digest,
            "errors": [f"{type(exc).__name__}: {exc}"],
        }, None
    clean_binary = _symcc_hidden_path(target.binary_path, "clean")
    clean = _run_protocol_binary(
        container=container, binary=clean_binary, request=request,
        input_path=snapshot_path,
    )

    immediate = {
        "schema_version": 1,
        "protocol": "dynamic-execution",
        "status": "submitted",
        "request_id": request.request_id,
        "job_id": f"symcc-{request.request_id}",
        "input_id": digest,
        "parent_input_id": request.parent_input_id,
        "target_commit": target.commit,
        "round_id": round_id,
        "input_path": request.input_path,
        "snapshot_path": snapshot_path,
        "input_size": len(input_bytes),
        "input_sha256": digest,
        "clean": clean,
        "symcc": {"status": "queued", "feedback_path": f"{FEEDBACK_ROOT}/{request.request_id}.json"},
        "generated_replays": [],
        "site_reached": None,
        "site_reachability_note": (
            "The clean target was run synchronously. SymCC execution and generated-input "
            "replays are queued asynchronously; no source-site reachability is inferred."
        ),
    }
    job = {
        "request": request,
        "round_id": round_id,
        "input_size": len(input_bytes),
        "input_sha256": digest,
        "input_id": digest,
        "input_bytes": input_bytes,
        "snapshot_path": snapshot_path,
        "clean": clean,
        "sidecar_name": _symcc_sidecar_name(target.name),
        "cancel_event": threading.Event(),
    }
    return immediate, job


def _execute_prebuilt_protocol_symcc_request(
    *, container: str, target: TargetConfig, job: dict[str, Any],
    feedback_runtime: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run concrete tracing and symbolic exploration in an isolated sidecar.

    The agent container is never used for SymCC execution. Each job receives a
    separate no-network container with an explicit memory/CPU budget and only
    a request-scoped input/output bind mount. This prevents a solver OOM from
    killing the PoC agent that is using the same target.
    """
    request: ExecutionRequest = job["request"]
    round_id = int(job["round_id"])
    symcc_cfg = target.symcc_runtime or {}
    memory_limit, sidecar_cpus, _max_concurrent = _symcc_sidecar_settings(symcc_cfg)
    clean_binary = shlex.split(target.binary_path)[0]
    symcc_binary = shlex.split(str(symcc_cfg["binary_path"]))[0]
    snapshot_path = str(job.get("snapshot_path") or request.input_path)
    input_bytes = job.get("input_bytes")
    if not isinstance(input_bytes, bytes):
        input_bytes = docker_ops.read_file(container, snapshot_path)
    if len(input_bytes) != int(job["input_size"]):
        raise RuntimeError("request snapshot bytes are unavailable or incomplete")

    sidecar_root = "/symcc-job"
    sidecar_input = f"{sidecar_root}/input.bin"
    out_dir = f"{sidecar_root}/symcc-results"
    trace_dir = f"{sidecar_root}/traces"
    with tempfile.TemporaryDirectory(prefix="harness-symcc-feedback-") as temporary:
        host_root = Path(temporary)
        (host_root / "traces").mkdir()
        (host_root / "symcc-results").mkdir()
        (host_root / "input.bin").write_bytes(input_bytes)
        sidecar_name = str(job.get("sidecar_name") or _symcc_sidecar_name(target.name))
        cancel_event = job.get("cancel_event")
        run_params = DockerRunParams(
            network="none",
            memory=memory_limit,
            cpus=sidecar_cpus,
            mounts=(DockerMount(str(host_root), sidecar_root, read_only=False),),
            entrypoint=("/bin/sh",),
            command=("-c", "while :; do sleep 3600; done"),
        )
        started_sidecar = False
        try:
            docker_ops.run(
                target.runtime_image_tag,
                sidecar_name,
                network="none",
                memory=memory_limit,
                shell="/bin/sh",
                run_params=run_params,
            )
            started_sidecar = True
            if isinstance(cancel_event, threading.Event) and cancel_event.is_set():
                raise InterruptedError("SymCC feedback job cancelled during sidecar startup")
            target_ids = (feedback_runtime or {}).get("marker_ids", [])
            symcc_args = tuple(symcc_cfg.get("program_args") or request.program_args)
            concrete_request = ExecutionRequest(
                request.request_id, sidecar_input,
                symcc_args, request.timeout_s, request.env,
            )
            trace_env = {
                "SYMCC_FEEDBACK_TRACE": f"{trace_dir}/input.trace",
                "SYMCC_FEEDBACK_CAPACITY": str(
                    symcc_cfg.get("feedback_capacity") or 1_000_000
                ),
                "SYMCC_NO_SYMBOLIC_INPUT": "1",
            }
            if target_ids:
                trace_env["SYMCC_FEEDBACK_TARGET_IDS"] = ",".join(
                    str(site_id) for site_id in target_ids
                )
            input_trace_execution = _run_protocol_binary(
                container=sidecar_name, binary=symcc_binary,
                request=concrete_request, input_path=sidecar_input,
                symcc_output=f"{out_dir}/concrete-input", extra_env=trace_env,
            )
            initial_observation = _summarize_symcc_trace_bytes(
                _read_container_trace(sidecar_name, f"{trace_dir}/input.trace"),
                feedback_runtime,
            )

            symcc_request = ExecutionRequest(
                request.request_id, sidecar_input,
                symcc_args, request.timeout_s, request.env,
            )
            symcc = _run_protocol_binary(
                container=sidecar_name, binary=symcc_binary,
                request=symcc_request, input_path=sidecar_input,
                symcc_output=out_dir,
            )
            oom_kills = _symcc_sidecar_oom_kills(sidecar_name)
            symcc["worker"] = {
                "isolated": True,
                "network": "none",
                "memory_limit": memory_limit,
                "cpus": sidecar_cpus,
                "oom_kill_count": oom_kills,
            }
            if oom_kills and symcc.get("exit_code") == 137:
                symcc["status"] = "resource_exhausted"
                symcc.setdefault("errors", []).append(
                    "isolated SymCC worker was OOM-killed; the agent container was unaffected"
                )

            seed_paths = sorted(
                (path for path in (host_root / "symcc-results").iterdir()
                 if path.is_file()),
                key=lambda path: path.name,
            )[:8]
            generated: list[dict[str, Any]] = []
            total_seed_bytes = 0
            for index, seed_path in enumerate(seed_paths):
                size = seed_path.stat().st_size
                if size <= 0 or size > 1024 * 1024 or total_seed_bytes + size > 16 * 1024 * 1024:
                    continue
                data = seed_path.read_bytes()
                if len(data) != size:
                    continue
                total_seed_bytes += size
                sidecar_seed = f"{out_dir}/{seed_path.name}"
                replay_path = f"{INPUT_ROOT}/symcc-{request.request_id}-{index:03d}.bin"
                docker_ops.write_file(container, replay_path, data)
                replay_request = ExecutionRequest(
                    request.request_id, sidecar_seed,
                    request.program_args, min(request.timeout_s, 10), request.env,
                )
                replay = _run_protocol_binary(
                    container=sidecar_name, binary=clean_binary,
                    request=replay_request, input_path=sidecar_seed,
                )
                candidate_symcc_request = ExecutionRequest(
                    request.request_id, sidecar_seed,
                    symcc_args, min(request.timeout_s, 10), request.env,
                )
                candidate_trace_run = _run_protocol_binary(
                    container=sidecar_name, binary=symcc_binary,
                    request=candidate_symcc_request,
                    input_path=sidecar_seed,
                    symcc_output=f"{out_dir}/concrete-{index:03d}",
                    extra_env={
                        "SYMCC_FEEDBACK_CAPACITY": str(
                            symcc_cfg.get("feedback_capacity") or 1_000_000
                        ),
                        **({
                            "SYMCC_FEEDBACK_TARGET_IDS": ",".join(
                                str(site_id) for site_id in target_ids
                            )
                        } if target_ids else {}),
                        "SYMCC_NO_SYMBOLIC_INPUT": "1",
                        "SYMCC_FEEDBACK_TRACE": f"{trace_dir}/generated-{index:03d}.trace",
                    },
                )
                site_feedback = _summarize_symcc_trace_bytes(
                    _read_container_trace(
                        sidecar_name, f"{trace_dir}/generated-{index:03d}.trace"
                    ),
                    feedback_runtime,
                )
                generated.append({
                    "path": replay_path,
                    "size": size,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "replay": replay,
                    "symcc_execution": candidate_trace_run,
                    "symcc_observation": site_feedback,
                })
            symcc.update({
                "testcase_count": len(generated),
                "testcases": [
                    {key: item[key] for key in ("path", "size", "sha256")}
                    for item in generated
                ],
            })
            replays = generated
        finally:
            if started_sidecar:
                docker_ops.rm(sidecar_name)

    return {
        "schema_version": 1,
        "protocol": "dynamic-execution",
        "status": "completed",
        "request_id": request.request_id,
        "round_id": round_id,
        "input_path": request.input_path,
        "snapshot_path": snapshot_path,
        "input_size": job["input_size"],
        "job_id": f"symcc-{request.request_id}",
        "input_id": job["input_id"],
        "parent_input_id": request.parent_input_id,
        "target_commit": target.commit,
        "input_sha256": job["input_sha256"],
        "clean": job["clean"],
        "input_trace_execution": input_trace_execution,
        "symcc": symcc,
        "symcc_observation": initial_observation,
        "generated_replays": replays,
        "site_reached": initial_observation.get("target_reached"),
        "site_reachability_note": (
            "site_reached describes the original submitted input's instrumented execution. "
            "Generated testcase observations are reported separately. A negative is exact "
            "only for a complete trace or a complete trace with a valid runtime target marker."
        ),
    }


def _read_container_trace(container: str, path: str) -> bytes:
    """Read private SymCC traces inside the worker container.

    SymCC creates trace files with mode 0600. The worker container commonly
    runs as root, so its files are not readable by the unprivileged host user
    through the bind mount. `docker exec cat` reads them without weakening the
    file permissions on the shared workspace.
    """
    try:
        return docker_ops.read_file(container, path)
    except Exception:
        return b""


def _symcc_sidecar_oom_kills(container: str) -> int | None:
    rc, output, _err = docker_ops.exec_sh(
        container, "cat /sys/fs/cgroup/memory.events", timeout=5
    )
    if rc:
        return None
    for line in output.splitlines():
        key, _, value = line.partition(" ")
        if key == "oom_kill":
            try:
                return int(value)
            except ValueError:
                return None
    return None


def _summarize_symcc_trace_bytes(
    raw: bytes, feedback_runtime: dict[str, Any] | None
) -> dict[str, Any]:
    trace = parse_trace(raw) if raw else None
    if trace is None:
        return {
            "status": "missing", "target_reached": None,
            "target_reachability": "unknown", "reason": "runtime trace file is missing",
        }
    if feedback_runtime is None:
        return {
            "status": "map_unavailable", "trace_status": trace.status,
            "target_reached": None, "target_reachability": "unknown",
            "reason": "source/CFG feedback runtime context is unavailable",
        }
    map_status = feedback_runtime.get("status")
    graph = feedback_runtime.get("graph")
    marker_ids = feedback_runtime.get("marker_ids", [])
    target_block_ids = feedback_runtime.get("target_block_ids", [])
    if graph is None or not marker_ids:
        return {
            "status": map_status or "unavailable",
            "trace_status": trace.status,
            "target_reached": None,
            "target_reachability": "unknown",
            "observed_event_count": len(trace.events),
            "reason": feedback_runtime.get("reason")
            or "target anchors could not be resolved through the versioned map",
        }
    result = summarize_trace(
        graph, trace, marker_ids=marker_ids, target_block_ids=target_block_ids
    )
    result["status"] = "ready" if trace.status in {"completed", "interrupted"} else trace.status
    result["map_status"] = map_status
    result["map_commit"] = feedback_runtime.get("source_commit")
    result["goal"] = feedback_runtime.get("goal")
    return result


def _read_symcc_trace_feedback(
    *, container: str, path: str, feedback_runtime: dict[str, Any] | None
) -> dict[str, Any]:
    """Read one bounded execution trace and join it with its versioned map."""
    try:
        raw = docker_ops.read_file(container, path)
    except Exception as exc:
        return {
            "status": "read_error", "target_reached": None,
            "target_reachability": "unknown",
            "reason": f"{type(exc).__name__}: {exc}",
        }
    return _summarize_symcc_trace_bytes(raw, feedback_runtime)


def _execute_prebuilt_protocol_request(
    *, container: str, target: TargetConfig, raw: bytes, filename: str,
    round_id: int, feedback_runtime: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Synchronous convenience wrapper retained for focused unit tests."""
    immediate, job = _prepare_prebuilt_protocol_request(
        container=container, target=target, raw=raw, filename=filename,
        round_id=round_id,
    )
    if job is None:
        return immediate
    return _execute_prebuilt_protocol_symcc_request(
        container=container, target=target, job=job,
        feedback_runtime=feedback_runtime,
    )


def _compact_protocol_feedback(record: dict[str, Any]) -> dict[str, Any]:
    """为下一次 agent 请求准备紧凑的异步反馈，不复制原始求解器日志。"""
    def compact_observation(
        value: Any, *, include_locations: bool = True
    ) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        keys = (
            "status", "trace_status", "trace_complete", "trace_truncated",
            "target_ids_configured", "target_ids_valid", "target_reached",
            "target_reachability", "observed_block_count", "distance",
            "distance_kind", "distance_is_heuristic", "distance_note",
            "closest_observed_location", "unresolved_call_count", "reason",
        )
        compact = {key: value[key] for key in keys if key in value}
        locations = value.get("observed_locations")
        if isinstance(locations, list):
            compact["observed_location_count"] = len(locations)
            if include_locations:
                compact["observed_locations"] = locations[:16]
        return compact

    clean = record.get("clean") if isinstance(record.get("clean"), dict) else {}
    symcc = record.get("symcc") if isinstance(record.get("symcc"), dict) else {}
    generated = record.get("generated_replays")
    compact_generated: list[dict[str, Any]] = []
    if isinstance(generated, list):
        for item in generated[:8]:
            if not isinstance(item, dict):
                continue
            replay = item.get("replay") if isinstance(item.get("replay"), dict) else {}
            compact_generated.append({
                "path": item.get("path"),
                "size": item.get("size"),
                "sha256": item.get("sha256"),
                "clean_replay": {
                    key: replay[key] for key in
                    ("status", "exit_code", "sanitizer_event") if key in replay
                },
                "symcc_observation": compact_observation(
                    item.get("symcc_observation"), include_locations=False
                ),
            })

    compact: dict[str, Any] = {
        "schema_version": 1,
        "request_id": record.get("request_id"),
        "round_id": record.get("round_id"),
        "input_id": record.get("input_id"),
        "input_sha256": record.get("input_sha256"),
        "snapshot_path": record.get("snapshot_path"),
        "parent_input_id": record.get("parent_input_id"),
        "target_commit": record.get("target_commit"),
        "feedback_status": record.get("feedback_status"),
        "clean": {
            key: clean[key] for key in
            ("status", "exit_code", "sanitizer_event") if key in clean
        },
        "symcc": {
            key: symcc[key] for key in
            ("status", "duration_s", "testcase_count", "errors") if key in symcc
        },
        "input_trace_execution": {
            key: record["input_trace_execution"][key]
            for key in ("status", "exit_code", "duration_s")
            if key in record.get("input_trace_execution", {})
        },
        "symcc_queue_wait_s": record.get("symcc_queue_wait_s"),
        "symcc_observation": compact_observation(
            record.get("symcc_observation")
        ),
        "generated_replays": compact_generated,
    }
    if record.get("feedback_error"):
        compact["feedback_error"] = str(record["feedback_error"])[:500]
    worker = symcc.get("worker")
    if isinstance(worker, dict):
        compact["symcc"]["worker"] = {
            key: worker[key] for key in
            ("isolated", "network", "memory_limit", "cpus", "oom_kill_count")
            if key in worker
        }
    if record.get("error"):
        compact["error"] = str(record["error"])[:500]
    return compact


async def _prebuilt_protocol_worker(
    *, container: str, target: TargetConfig, stop: asyncio.Event,
    result_path: str | None,
    feedback_runtime: dict[str, Any] | None = None,
    max_requests: int = _DEFAULT_MAX_ITERATIONS,
) -> dict[str, Any]:
    request_limit = max(1, min(int(max_requests), _MAX_ITERATION_RECORDS))
    _memory_limit, _cpus, max_inflight_symcc_jobs = _symcc_sidecar_settings(
        target.symcc_runtime or {}
    )
    symcc_slots = asyncio.Semaphore(max_inflight_symcc_jobs)
    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    jobs: set[asyncio.Task] = set()
    stats = {
        "processed": 0, "invalid": 0, "errors": 0,
        "symcc_errors": 0, "symcc_skipped_busy": 0,
        "symcc_abandoned": 0, "symcc_duration_s": 0.0,
        "symcc_queued": 0, "symcc_queue_wait_s": 0.0,
        "feedback_auto_delivered": 0,
        "iteration_limit_rejections": 0,
    }
    feedback_delivered: set[str] = set()
    command = (
        f"find {shlex.quote(PENDING_ROOT)} -maxdepth 1 -type f "
        "-name '*.json' -print | sort"
    )

    def attach_ready_feedback(response: dict[str, Any]) -> list[str]:
        """把此前完成的异步结果压缩后附加到下一次请求响应。"""
        ready = [
            record for record in records
            if record.get("request_id") not in feedback_delivered
            and record.get("feedback_status") in {"ready", "publish_error"}
        ]
        response["ready_feedback"] = [
            _compact_protocol_feedback(record) for record in ready
        ]
        return [str(record["request_id"]) for record in ready if record.get("request_id")]

    def mark_feedback_delivered(request_ids: list[str]) -> None:
        feedback_delivered.update(request_ids)
        stats["feedback_auto_delivered"] += len(request_ids)

    async def run_feedback_job(job: dict[str, Any], record: dict[str, Any]) -> None:
        request: ExecutionRequest = job["request"]
        feedback_path = f"{FEEDBACK_ROOT}/{request.request_id}.json"
        temp_path = feedback_path + ".tmp"
        started = time.monotonic()
        try:
            result = await asyncio.to_thread(
                _execute_prebuilt_protocol_symcc_request,
                container=container, target=target, job=job,
                feedback_runtime=feedback_runtime,
            )
            symcc = result.get("symcc") or {}
            stats["symcc_duration_s"] += float(symcc.get("duration_s") or 0.0)
            if symcc.get("status") != "completed":
                stats["symcc_errors"] += 1
        except Exception as exc:
            stats["symcc_errors"] += 1
            result = {
                "schema_version": 1,
                "protocol": "dynamic-execution-feedback",
                "status": "execution_error",
                "request_id": request.request_id,
                "round_id": job["round_id"],
                "input_path": request.input_path,
                "input_sha256": job["input_sha256"],
                "error": f"{type(exc).__name__}: {exc}",
                "symcc": {"status": "execution_error"},
                "generated_replays": [],
            }
        result["feedback_status"] = "ready"
        record.update(result)
        try:
            payload = (
                json.dumps(
                    _compact_protocol_feedback(result),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            ).encode()
            await asyncio.to_thread(docker_ops.write_file, container, temp_path, payload)
            rc, _out, err = await asyncio.to_thread(
                docker_ops.exec_sh,
                container,
                f"mv -- {shlex.quote(temp_path)} {shlex.quote(feedback_path)}",
                timeout=15,
            )
            if rc:
                raise RuntimeError(f"cannot publish SymCC feedback: {err[-300:]}")
        except Exception as exc:
            stats["errors"] += 1
            record["feedback_status"] = "publish_error"
            record["feedback_error"] = f"{type(exc).__name__}: {exc}"
        record["feedback_wall_time_s"] = round(time.monotonic() - started, 3)

    async def run_queued_feedback_job(
        job: dict[str, Any], record: dict[str, Any], enqueued_at: float
    ) -> None:
        try:
            async with symcc_slots:
                queue_wait = max(0.0, time.monotonic() - enqueued_at)
                record["symcc_queue_wait_s"] = round(queue_wait, 3)
                stats["symcc_queue_wait_s"] += queue_wait
                await run_feedback_job(job, record)
        except asyncio.CancelledError:
            cancel_event = job.get("cancel_event")
            if isinstance(cancel_event, threading.Event):
                cancel_event.set()
            sidecar_name = job.get("sidecar_name")
            if isinstance(sidecar_name, str):
                await asyncio.to_thread(docker_ops.rm, sidecar_name)
            raise

    while not stop.is_set():
        try:
            rc, listing, _err = await asyncio.to_thread(
                docker_ops.exec_sh, container, command, timeout=15
            )
        except Exception:
            rc, listing = 1, ""
        if rc == 0:
            for path in listing.splitlines():
                path = path.strip()
                name = Path(path).name
                if not path.startswith(PENDING_ROOT + "/") or not name.endswith(".json") or name in seen:
                    continue
                seen.add(name)
                try:
                    raw = await asyncio.to_thread(docker_ops.read_file, container, path)
                    if stats["processed"] >= request_limit:
                        request_id = name.removesuffix(".json")
                        response = {
                            "schema_version": 1,
                            "protocol": "dynamic-execution",
                            "status": "iteration_limit_reached",
                            "request_id": request_id,
                            "iteration_limit": request_limit,
                            "accepted_requests": stats["processed"],
                            "message": (
                                "The Harness-enforced dynamic iteration limit has been "
                                "reached. This input was not run by the clean target or "
                                "SymCC; stop submitting requests and report the evidence "
                                "collected so far."
                            ),
                        }
                        delivered_ids = attach_ready_feedback(response)
                        await asyncio.to_thread(
                            docker_ops.write_file, container,
                            f"{RESPONSE_ROOT}/{name}",
                            (json.dumps(response, indent=2, ensure_ascii=False) + "\n").encode(),
                        )
                        mark_feedback_delivered(delivered_ids)
                        await asyncio.to_thread(
                            docker_ops.exec_sh, container,
                            f"mv -- {shlex.quote(path)} {shlex.quote(PROCESSED_ROOT + '/' + name)}",
                            timeout=15,
                        )
                        stats["iteration_limit_rejections"] += 1
                        continue
                    response, job = await asyncio.to_thread(
                        _prepare_prebuilt_protocol_request,
                        container=container, target=target, raw=raw,
                        filename=name, round_id=stats["processed"] + 1,
                    )
                    if response.get("status") == "invalid_request":
                        stats["invalid"] += 1
                    delivered_ids = attach_ready_feedback(response)
                    records.append(response)
                    stats["processed"] += 1
                    await asyncio.to_thread(
                        docker_ops.write_file, container,
                        f"{RESPONSE_ROOT}/{name}",
                        (json.dumps(response, indent=2, ensure_ascii=False) + "\n").encode(),
                    )
                    mark_feedback_delivered(delivered_ids)
                    await asyncio.to_thread(
                        docker_ops.exec_sh, container,
                        f"mv -- {shlex.quote(path)} {shlex.quote(PROCESSED_ROOT + '/' + name)}",
                        timeout=15,
                    )
                    if job is not None:
                        enqueued_at = time.monotonic()
                        task = asyncio.create_task(
                            run_queued_feedback_job(job, response, enqueued_at)
                        )
                        jobs.add(task)
                        stats["symcc_queued"] += 1
                        task.add_done_callback(jobs.discard)
                except Exception as exc:
                    stats["errors"] += 1
                    response = {
                        "schema_version": 1,
                        "status": "execution_error",
                        "request_file": name,
                        "errors": [f"{type(exc).__name__}: {exc}"],
                    }
                    delivered_ids = attach_ready_feedback(response)
                    records.append(response)
                    try:
                        await asyncio.to_thread(
                            docker_ops.write_file, container,
                            f"{RESPONSE_ROOT}/{name}",
                            (json.dumps(response, indent=2) + "\n").encode(),
                        )
                        mark_feedback_delivered(delivered_ids)
                        await asyncio.to_thread(
                            docker_ops.exec_sh, container,
                            f"mv -- {shlex.quote(path)} {shlex.quote(PROCESSED_ROOT + '/' + name)}",
                            timeout=15,
                        )
                    except Exception:
                        pass
        try:
            await asyncio.wait_for(stop.wait(), timeout=0.25)
        except asyncio.TimeoutError:
            pass

    # No agent remains to consume feedback after exploration ends. Cancel
    # outstanding work instead of extending the dynamic phase just to wait for
    # SymCC; already-published feedback remains available in the result files.
    unfinished = [task for task in jobs if not task.done()]
    if unfinished:
        for task in unfinished:
            task.cancel()
        await asyncio.gather(*unfinished, return_exceptions=True)
        stats["symcc_abandoned"] = len(unfinished)
        for record in records:
            if (record.get("symcc") or {}).get("status") == "queued":
                record["feedback_status"] = "abandoned_agent_finished"
                record["symcc"] = {
                    "status": "abandoned",
                    "message": "agent finished before background feedback was ready",
                }
    summary = {
        "schema_version": 1, "provider": "symcc-prebuilt",
        "status": "incomplete" if unfinished else "completed",
        "iteration_limit": request_limit,
        "requests": stats["processed"], "invalid_requests": stats["invalid"],
        "iteration_limit_rejections": stats["iteration_limit_rejections"],
        "errors": stats["errors"], "symcc_errors": stats["symcc_errors"],
        "symcc_queued": stats["symcc_queued"],
        "symcc_queue_wait_s": round(stats["symcc_queue_wait_s"], 3),
        "symcc_skipped_busy": stats["symcc_skipped_busy"],
        "symcc_abandoned": stats["symcc_abandoned"],
        "feedback_auto_delivered": stats["feedback_auto_delivered"],
        "symcc_execution_s": round(stats["symcc_duration_s"], 3),
        "records": records,
    }
    if result_path:
        output = Path(result_path)
        output.mkdir(parents=True, exist_ok=True)
        (output / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
        with (output / "requests.jsonl").open("w") as stream:
            for record in records:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    return summary


async def _run_prebuilt_symcc_agent(
    *, prompt: str, target: TargetConfig, container: str, model: str,
    max_turns: int, system_prompt: str | None, max_resume_attempts: int,
    transcript_path: str | None, progress_prefix: str | None,
    result_path: str | None,
    feedback_runtime: dict[str, Any] | None = None,
    max_iterations: int = _DEFAULT_MAX_ITERATIONS,
) -> tuple[AgentResult, dict[str, float], dict[str, Any]]:
    started = time.time()
    stop = asyncio.Event()
    worker = asyncio.create_task(_prebuilt_protocol_worker(
        container=container, target=target, stop=stop, result_path=result_path,
        feedback_runtime=feedback_runtime,
        max_requests=max_iterations,
    ))
    try:
        result = await run_agent(
            prompt=prompt, max_turns=max_turns, model=model, container=container,
            transcript_path=transcript_path, progress_prefix=progress_prefix,
            system_prompt=system_prompt, max_resume_attempts=max_resume_attempts,
            tools=["Read", "Write", "Bash"], phase_timeout_s=1800.0,
            idle_timeout_s=1800.0,
        )
    finally:
        stop.set()
        try:
            summary = await asyncio.wait_for(worker, timeout=15)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            worker.cancel()
            try:
                await worker
            except (asyncio.CancelledError, Exception):
                pass
            summary = {
                "schema_version": 1, "provider": "symcc-prebuilt", "status": "incomplete",
                "errors": ["execution protocol worker did not stop cleanly"],
            }
    return result, {
        "dynamic_validation": time.time() - started,
        "execution_protocol_requests": float(summary.get("requests", 0)),
        "execution_protocol_limit_rejections": float(
            summary.get("iteration_limit_rejections", 0)
        ),
        "execution_protocol_invalid": float(summary.get("invalid_requests", 0)),
        "execution_protocol_errors": float(summary.get("errors", 0)),
        "symbolic_execution_session": float(summary.get("symcc_execution_s", 0)),
    }, summary


@contextmanager
def _open_dynamic_session(
    target: TargetConfig,
    *,
    container_name: str,
    auth: dict[str, str] | None,
    mounts: list[tuple[str, str]] | None,
    symbolic_provider: str | None,
    symbolic_result_path: str | None,
) -> Iterator[tuple[object, KleeSession | SymccSession | None]]:
    """Mount the optional symbolic bridge into the agent runtime."""
    with ExitStack() as stack:
        symbolic_session = None
        writable_mounts = None
        if symbolic_provider == "klee":
            session_type = KleeSession
            symbolic_session = stack.enter_context(
                session_type(
                    container_name=container_name,
                    result_path=symbolic_result_path,
                )
            )
            writable_mounts = [symbolic_session.mount()]
        elif symbolic_provider not in {None, "symcc"}:
            raise ValueError(
                f"symbolic-execution provider is not implemented: {symbolic_provider}"
            )
        runtime_session = stack.enter_context(
            open_runtime_session(
                target,
                container_name=container_name,
                auth=auth,
                mounts=mounts,
                writable_mounts=writable_mounts,
            )
        )
        try:
            yield runtime_session, symbolic_session
        finally:
            # The agent image may create files in the shared mount as root.
            # Reclaim the temporary workspace while the target container is
            # still alive, then let ExitStack tear down the runtime.  This
            # prevents a successful round from becoming a host-side
            # PermissionError during TemporaryDirectory cleanup.
            if symbolic_session is not None:
                try:
                    docker_ops.exec_sh(
                        runtime_session.container,
                        "chmod -R a+rwX -- /work/symbolic",
                        timeout=15,
                    )
                except Exception:
                    pass
                symbolic_session.stop()


def _split_functions(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.replace("\n", ",").split(",") if part.strip()]


def _status_without_iteration_records(status: str, reason: str) -> tuple[str, str]:
    """Do not call missing agent evidence a completed iteration exhaustion."""
    if status in {"agent_failed", "agent_blocked"}:
        return status, reason
    return "agent_failed", reason or "agent did not persist any validation round"


def _parse_exit_code(value: str | None) -> int:
    if value is None:
        return -1
    value = value.strip()
    return int(value) if value.lstrip("-").isdigit() else -1


def _crash_result_xml_template(candidate_id: str) -> bytes:
    """Return the fixed crash-submission skeleton written to the container."""
    safe_id = xml_escape(candidate_id)
    fields = []
    for field in _CRASH_RESULT_FIELDS:
        value = safe_id if field == "candidate_id" else ""
        fields.append(f"  <{field}>{value}</{field}>")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<crash_result schema_version="1">\n'
        + "\n".join(fields)
        + "\n</crash_result>\n"
    ).encode()


def _read_crash_result_xml(
    container: str, candidate_id: str
) -> tuple[dict[str, str] | None, str | None, bool]:
    """Read the optional strict XML file used only for crash submissions."""
    try:
        exists_rc, _out, _err = docker_ops.exec_sh(
            container, f"test -f {_CRASH_RESULT_XML_PATH}", timeout=15
        )
        if exists_rc:
            # Absence is the normal result for not-reached/reached-no-crash runs.
            return None, None, False
        raw = docker_ops.read_file(container, _CRASH_RESULT_XML_PATH)
    except Exception:
        # A legacy/fake runtime may not support the optional file probe. Treat
        # that as no crash submission and keep the original inline status path.
        return None, None, False
    if not raw:
        return None, f"agent crash result file is empty: {_CRASH_RESULT_XML_PATH}", True
    if len(raw) > 100_000:
        return None, "agent crash result XML exceeds 100000 bytes", True
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        return None, "agent crash result XML may not declare entities", True
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        return None, f"invalid crash result XML: {exc}", True
    if root.tag != "crash_result":
        return None, "crash result XML root must be <crash_result>", True
    if root.attrib != {"schema_version": "1"}:
        return None, "crash result XML must contain only schema_version=1", True
    children = list(root)
    names = [child.tag for child in children]
    if set(names) != set(_CRASH_RESULT_FIELDS) or len(names) != len(_CRASH_RESULT_FIELDS):
        return None, "crash result XML must contain exactly the fixed template fields", True
    if any(child.attrib or list(child) for child in children):
        return None, "crash result XML fields must contain text only", True
    data = {child.tag: (child.text or "").strip() for child in children}
    if data["candidate_id"] != candidate_id:
        return None, "crash result XML candidate_id does not match the active candidate", True
    return data, None, True


def _persist_crash_result(container: str, result_path: str) -> None:
    """Keep the agent-authored crash XML as an auditable host-side copy."""
    try:
        raw = docker_ops.read_file(container, _CRASH_RESULT_XML_PATH)
    except Exception:
        return
    if not raw:
        return
    output = Path(result_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)


def _normalize_poc_kind(value: str, detector: str) -> str:
    """Normalize the common artifact-kind label emitted by crash agents.

    Some agents use ``crash`` to mean "this is a crash PoC", although the
    field describes the input artifact's format. At this boundary, the PoC
    has already been materialized as one file at ``poc_path``; for crash
    detectors, interpret that label as the default file artifact. A source
    language label such as ``ruby`` also describes file content, not a distinct
    transport kind. Keep logic submissions strict, since they may represent
    non-file service requests.
    """
    kind = value.strip().lower()
    # Models sometimes describe the contents and how the target consumes
    # them (for example, "ruby-source-fuzzer-input") instead of the artifact
    # transport kind. Normalize separators before recognizing these generic
    # file-input descriptions. Do not apply this relaxation to logic findings:
    # their request/program/bundle distinction is semantically significant.
    normalized = re.sub(r"[-\s]+", "_", kind)
    if detector != "logic":
        tokens = set(normalized.split("_"))
        source_file_label = (
            "fuzzer" in tokens
            and bool(tokens & {"input", "seed"})
            and bool(tokens & {"source", "script", "binary"})
        )
        if (
            normalized.endswith("_source")
            or normalized.endswith("_script")
            or "_source_via_" in normalized
            or normalized in {"raw_binary", "binary", "raw_file"}
            or normalized in {
                "crash", "input", "raw_input", "ruby_source", "python_source",
                "ruby", "python", "shell", "shell_script", "script",
            }
            or source_file_label
        ):
            return "file"
    return kind


def _has_candidate_ready_iteration(
    iterations: list[dict], detector: str
) -> bool:
    """Require detector-specific runtime evidence before accepting a PoC."""
    for record in iterations:
        decision = str(record.get("decision") or "")
        if decision not in {"", "candidate_ready"}:
            continue
        observations = record.get("observations")
        if not isinstance(observations, dict):
            continue
        if not bool(observations.get("site_reached")):
            continue
        if not bool(observations.get("matched_candidate")):
            continue
        if detector == "logic":
            if bool(observations.get("bad_state_observed")) and bool(
                observations.get("bad_effect_observed")
            ):
                return True
        elif bool(observations.get("sanitizer_event")):
            return True
    return False


def _status_for_missing_poc_submission(
    *, status: str, reason: str, iterations: list[dict], detector: str
) -> tuple[str, str]:
    """Distinguish a missing final artifact from a candidate that did not crash."""
    if _has_candidate_ready_iteration(iterations, detector):
        return (
            "invalid_submission",
            "a candidate_ready iteration was recorded, but the final response "
            "omitted the required non-empty PoC path or exact reproduction command",
        )
    return status, reason


def _persist_instrumentation(
    report: InstrumentationReport | None,
    result_path: str | None,
) -> None:
    """Persist bounded provider output before the target container is removed."""
    if report is None or not result_path:
        return
    root = Path(result_path)
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(
        json.dumps(report.manifest, indent=2, ensure_ascii=False) + "\n"
    )
    (root / "summary.json").write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
    )
    with (root / "events.jsonl").open("w") as stream:
        for event in report.feedback:
            stream.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")


def _prepare_iteration_workspace(
    container: str, candidate: StaticFinding, max_iterations: int, detector: str
) -> None:
    """Create the provider-neutral iteration contract inside the agent image."""
    try:
        rc, _out, _err = docker_ops.exec_sh(
            container,
            "mkdir -p /work/validation/iterations",
            timeout=15,
        )
        if rc:
            return
        contract = {
            "schema_version": 1,
            "candidate_id": candidate.candidate_id,
            "max_iterations": max_iterations,
            "record_dir": "/work/validation/iterations",
            "observation_fields": [
                "site_reached",
                "sanitizer_event",
                "bad_state_observed",
                "bad_effect_observed",
                "matched_candidate",
            ],
            "record_example": {
                "schema_version": 1,
                "round_id": 1,
                "candidate_id": candidate.candidate_id,
                "hypothesis": {
                    "entry_point": "external input entry",
                    "target_site": "candidate site",
                    "trigger_condition": "current trigger hypothesis",
                },
                "observations": {
                    "site_reached": None,
                    "sanitizer_event": False,
                    "bad_state_observed": False,
                    "bad_effect_observed": False,
                    "matched_candidate": False,
                },
                "decision": "continue",
                "reason": "short evidence-based result",
            },
            "detector": detector,
            "candidate_ready_requires": (
                [
                    "site_reached", "matched_candidate", "bad_state_observed",
                    "bad_effect_observed",
                ]
                if detector == "logic"
                else ["site_reached", "matched_candidate", "sanitizer_event"]
            ),
        }
        readiness = (
            "`site_reached`, `matched_candidate`, `bad_state_observed`, and "
            "`bad_effect_observed`"
            if detector == "logic"
            else "`site_reached`, `matched_candidate`, and `sanitizer_event`"
        )
        candidate_kind = "logic" if detector == "logic" else "memory-safety"
        readme = (
            "# Dynamic validation iterations\n\n"
            "Write one JSON record per validation round as "
            "`/work/validation/iterations/round-NNN.json`.\n"
            "Use `round_id` (not `round`) and put the evidence fields inside "
            "the `observations` object. Four fields are boolean; `site_reached` "
            "is tri-state: true only for an exact runtime hit, false only for a "
            "complete trace proving a miss, and null when unknown. For this " + candidate_kind +
            " candidate, a successful record must set `decision` to "
            "`candidate_ready` and set " + readiness +
            " to true based on command output. The exact "
            "machine-readable template is in `iteration-contract.json`. "
            "The record does not replace the final PoC XML contract. Do not "
            "put secrets or unbounded command output in it.\n"
        )
        docker_ops.write_file(
            container,
            "/work/validation/iteration-contract.json",
            json.dumps(contract, indent=2, ensure_ascii=False).encode() + b"\n",
        )
        docker_ops.write_file(
            container, "/work/validation/README.md", readme.encode()
        )
        result_readme = (
            "\n\n## Final result file\n\n"
            "Only after a matching crash has been reproduced, copy "
            "`/work/validation/crash-result-template.xml` to "
            "`/work/validation/crash-result.xml` and fill its existing element "
            "text. Keep the root, field names, order, and attributes unchanged. "
            "This file is not needed for no-crash or unreachable outcomes; "
            "report those with the normal dynamic-status tags.\n"
        )
        docker_ops.write_file(
            container,
            _CRASH_RESULT_TEMPLATE_PATH,
            _crash_result_xml_template(candidate.candidate_id),
        )
        docker_ops.write_file(
            container, "/work/validation/README.md",
            (readme + result_readme).encode(),
        )
    except Exception:
        # Inline status/logic reporting remains usable when a legacy/fake
        # runtime cannot provide the optional workspace.
        return


def _collect_iteration_records(
    container: str, candidate_id: str, max_iterations: int
) -> tuple[list[dict], list[str]]:
    """Read bounded round records before the runtime container is removed."""
    try:
        rc, listing, err = docker_ops.exec_sh(
            container,
            "find /work/validation/iterations -maxdepth 1 -type f "
            "-name 'round-*.json' -print | sort",
            timeout=15,
        )
    except Exception as exc:
        return [], [f"iteration directory unavailable: {exc}"]
    if rc:
        return [], [f"iteration directory unavailable: {(err or listing)[-500:]}"]

    errors: list[str] = []
    records: list[dict] = []
    paths = [line.strip() for line in listing.splitlines() if line.strip()]
    for path in paths[:max_iterations]:
        if not re.match(r"^/work/validation/iterations/round-[0-9]{3}\.json$", path):
            errors.append(f"ignored unsafe iteration path: {path[:200]}")
            continue
        try:
            raw = docker_ops.read_file(container, path)
        except Exception as exc:
            errors.append(f"could not read iteration record {path}: {exc}")
            continue
        if not raw:
            errors.append(f"empty iteration record: {path}")
            continue
        if len(raw) > _MAX_ITERATION_BYTES:
            errors.append(f"iteration record too large: {path}")
            continue
        try:
            value = json.loads(raw.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            errors.append(f"invalid iteration JSON {path}: {exc.msg}")
            continue
        if not isinstance(value, dict):
            errors.append(f"iteration record is not an object: {path}")
            continue
        if str(value.get("candidate_id") or "") != candidate_id:
            errors.append(f"iteration candidate mismatch: {path}")
            continue
        value["schema_version"] = 1
        records.append(_bound_iteration(value))
    if len(paths) > max_iterations:
        errors.append(f"iteration records truncated at {max_iterations}")
    records.sort(key=lambda item: (int(item.get("round_id", 0)), str(item)))
    return records, errors


def _bound_iteration(value: dict) -> dict:
    """Keep model-authored iteration evidence safe to persist and inspect."""
    allowed = {
        "schema_version", "round_id", "candidate_id", "hypothesis",
        "observations", "decision", "reason",
    }
    bounded = {key: value.get(key) for key in allowed if key in value}
    # Early dynamic agents emitted the same fields with a shorter schema:
    # `round` instead of `round_id`, and observation booleans at the top
    # level. Normalize that shape without inventing any positive evidence.
    if "round_id" not in bounded and "round" in value:
        bounded["round_id"] = value.get("round")
    observations = bounded.get("observations")
    if not isinstance(observations, dict):
        evidence_fields = {
            "site_reached", "sanitizer_event", "bad_state_observed",
            "bad_effect_observed", "matched_candidate",
        }
        flat_observations = {
            key: value[key] for key in evidence_fields
            if isinstance(value.get(key), bool)
        }
        if flat_observations:
            bounded["observations"] = flat_observations
    observations = bounded.get("observations")
    if isinstance(observations, dict) and not bounded.get("decision"):
        if (
            observations.get("site_reached") is True
            and observations.get("matched_candidate") is True
            and (
                observations.get("sanitizer_event") is True
                or (
                    observations.get("bad_state_observed") is True
                    and observations.get("bad_effect_observed") is True
                )
            )
        ):
            # The readiness decision is derivable from the required evidence
            # flags; accept equivalent reports that omit the redundant label.
            bounded["decision"] = "candidate_ready"
    if not bounded.get("reason"):
        fallback_reason = value.get("title") or value.get("notes")
        if isinstance(fallback_reason, list):
            fallback_reason = "; ".join(str(item) for item in fallback_reason[:20])
        if fallback_reason:
            bounded["reason"] = str(fallback_reason)[:4_000]
    for key in ("hypothesis", "observations"):
        if isinstance(bounded.get(key), dict):
            bounded[key] = {
                str(k)[:100]: _bound_json_value(v)
                for k, v in list(bounded[key].items())[:50]
            }
    for key in ("reason", "decision"):
        if key in bounded:
            bounded[key] = str(bounded[key])[:4_000]
    try:
        bounded["round_id"] = int(bounded.get("round_id", 0))
    except (TypeError, ValueError):
        bounded["round_id"] = 0
    bounded["candidate_id"] = str(bounded.get("candidate_id") or "")[:80]
    return bounded


def _bound_json_value(value):
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, list):
        return [_bound_json_value(item) for item in value[:50]]
    if isinstance(value, dict):
        return {
            str(key)[:100]: _bound_json_value(item)
            for key, item in list(value.items())[:50]
        }
    return str(value)[:2_000]


def _persist_iteration_records(
    records: list[dict], errors: list[str], result_path: str | None
) -> None:
    if not result_path:
        return
    root = Path(result_path).parent / "iterations"
    root.mkdir(parents=True, exist_ok=True)
    for record in records:
        try:
            round_id = int(record.get("round_id", 0))
        except (TypeError, ValueError):
            round_id = 0
        name = f"round-{round_id:03d}.json" if round_id > 0 else "round-000.json"
        (root / name).write_text(
            json.dumps(record, indent=2, ensure_ascii=False) + "\n"
        )
    (root / "summary.json").write_text(
        json.dumps(
            {"schema_version": 1, "count": len(records), "errors": errors[:100]},
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )
