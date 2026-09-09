# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Dynamic validation phase of the split find workflow."""
from __future__ import annotations

import time

from . import docker_ops
from .agent import AgentResult, parse_xml_tag, run_agent
from .artifacts import CrashArtifact, DynamicValidationResult, StaticFinding
from .config import TargetConfig
from .prompts.dynamic_validation_prompt import build_dynamic_validation_prompt
from .runtimes import open_runtime_session

_DYNAMIC_STATUSES = {
    "not_reached",
    "reached_no_crash",
    "wrong_path",
    "environment_blocked",
    "invalid_submission",
    "agent_failed",
}


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
) -> tuple[DynamicValidationResult, AgentResult, dict[str, float]]:
    """Try to produce a ``CrashArtifact`` for one static candidate."""
    timings: dict[str, float] = {}
    mounts = [(str(found_bugs_path), "/tmp/found_bugs.jsonl")] if found_bugs_path else None
    with open_runtime_session(
        target,
        container_name=container_name,
        auth=agent_env,
        mounts=mounts,
    ) as session:
        container = session.container
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

        text = result.find_tagged_message("poc_path")
        status_text = result.find_tagged_message("dynamic_status")
        metadata_text = (
            status_text
            if parse_xml_tag(status_text, "dynamic_status") is not None
            else text
        )
        poc_path = parse_xml_tag(text, "poc_path")
        reproduction_command = parse_xml_tag(text, "reproduction_command")
        reported_id = parse_xml_tag(metadata_text, "candidate_id")
        selected_id = (
            reported_id.strip()
            if reported_id and reported_id.strip() == candidate.candidate_id
            else candidate.candidate_id
        )
        reached = _split_functions(parse_xml_tag(metadata_text, "reached_functions"))
        reachability = parse_xml_tag(metadata_text, "reachability_evidence") or ""
        reason = parse_xml_tag(metadata_text, "reason") or ""

        if not poc_path or not reproduction_command:
            status = "agent_failed" if result.error else (
                parse_xml_tag(status_text, "dynamic_status") or "reached_no_crash"
            )
            if status not in _DYNAMIC_STATUSES:
                status = "reached_no_crash"
            return DynamicValidationResult(
                candidate_id=selected_id,
                status=status,
                reached_functions=reached,
                reachability_evidence=reachability,
                reason=reason,
            ), result, timings

        # An emitted path is not enough. The file must cross the container
        # boundary and contain bytes before it becomes a CrashArtifact.
        poc_bytes = docker_ops.read_file(container, poc_path)
        if not poc_bytes:
            return DynamicValidationResult(
                candidate_id=selected_id,
                status="invalid_submission",
                reached_functions=reached,
                reachability_evidence=reachability,
                reason="agent emitted a PoC path but the file was empty or missing",
            ), result, timings

        crash_type = parse_xml_tag(text, "crash_type") or "unknown"
        crash_output = (parse_xml_tag(text, "crash_output") or "")[:10_000]
        exit_code = _parse_exit_code(parse_xml_tag(text, "exit_code"))
        dup_check = parse_xml_tag(text, "dup_check")
        crash = CrashArtifact(
            poc_path=poc_path,
            poc_bytes=poc_bytes,
            reproduction_command=reproduction_command,
            crash_type=crash_type,
            crash_output=crash_output,
            exit_code=exit_code,
            dup_check=dup_check,
        )
        return DynamicValidationResult(
            candidate_id=selected_id,
            status="validated",
            reached_functions=reached,
            reachability_evidence=reachability,
            reason=reason,
            crash=crash,
        ), result, timings


def _split_functions(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.replace("\n", ",").split(",") if part.strip()]


def _parse_exit_code(value: str | None) -> int:
    if value is None:
        return -1
    value = value.strip()
    return int(value) if value.lstrip("-").isdigit() else -1
