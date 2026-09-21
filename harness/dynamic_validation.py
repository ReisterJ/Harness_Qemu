# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Dynamic validation phase of the split find workflow."""
from __future__ import annotations

import time
import json
import re
import xml.etree.ElementTree as ET
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Iterator
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
from .instrumentation import select_provider
from .instrumentation.base import InstrumentationReport
from .prompts.dynamic_validation_prompt import build_dynamic_validation_prompt
from .runtimes import open_runtime_session
from .symbolic import KleeSession, SymccSession, select_symbolic_execution

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
        _prepare_iteration_workspace(
            container, candidate, iteration_limit, target.detector
        )
        symbolic_context = (
            symbolic_session.prepare_agent(container) if symbolic_session else None
        )
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
        started = time.time()
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
                result_data = dict(inline_data)
                result_data.update(crash_data or {})
                result_data["dynamic_status"] = (
                    result_data["dynamic_status"] or "validated"
                )
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
        if symbolic_provider in {"klee", "symcc"}:
            session_type = KleeSession if symbolic_provider == "klee" else SymccSession
            symbolic_session = stack.enter_context(
                session_type(
                    container_name=container_name,
                    result_path=symbolic_result_path,
                )
            )
            writable_mounts = [symbolic_session.mount()]
        elif symbolic_provider is not None:
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
        yield runtime_session, symbolic_session


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
    detectors, interpret that label as the default file artifact. Keep logic
    submissions strict, since they may represent non-file service requests.
    """
    kind = value.strip().lower()
    if detector != "logic" and (
        kind.endswith("_source")
        or kind.endswith("_script")
        or kind in {"raw-binary", "raw_binary", "binary", "raw_file"}
        or kind in {
            "crash", "input", "raw_input", "ruby_source", "python_source",
            "shell_script", "script",
        }
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
                    "site_reached": False,
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
            "Use `round_id` (not `round`) and put the five boolean evidence "
            "fields inside the `observations` object. For this " + candidate_kind +
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
