# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Find loop: start container, run find-agent, parse output, extract PoC.

Budget: max_turns=2000 (one run is hours, not minutes).
"""
from __future__ import annotations

import time

from . import docker_ops, sandbox
from .agent import run_agent, parse_xml_tag, AgentResult
from .artifacts import CrashArtifact
from .config import TargetConfig
from .memory import (
    seed_memory_content,
    collect_run_memory,
    MEMORY_PATH,
    PRIOR_MEMORY_PATH,
)
from .prompts.find_prompt import build_find_prompt


DEFAULT_FIND_MAX_TURNS = 2000


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
    memory_enabled: bool = False,
    prior_exploration: str | None = None,
    prior_memory: str | None = None,
    memory_out_path: str | None = None,
) -> tuple[CrashArtifact | None, AgentResult, dict[str, float]]:
    """Run one find attempt against a target.

    Returns (crash_or_none, agent_result, timings).
    crash is None if no PoC was emitted or the claimed path was empty.

    When ``memory_enabled``:
      - ``/work/MEMORY.md`` is seeded (empty) before the agent starts;
      - the find prompt gains MEMORY_SECTION (+ PRIOR_EXPLORATION_SECTION if
        ``prior_exploration`` is provided);
      - the agent's final MEMORY.md is written to ``memory_out_path`` (if
        given) right before the container is torn down.

    Assumes the image is already built (caller owns docker_ops.build).
    """
    timings: dict[str, float] = {}

    mounts = [(str(found_bugs_path), "/tmp/found_bugs.jsonl")] if found_bugs_path else None
    with sandbox.agent_container(
        target.image_tag, container_name, agent_env,
        memory=target.memory_limit, shm_size=target.shm_size, mounts=mounts,
        network=target.agent_network, devices=target.devices,
        prebuilt=target.agent_prebuilt,
    ) as container:
        if memory_enabled:
            docker_ops.write_file(container, MEMORY_PATH, seed_memory_content())
            # Queryable prior-exploration history (read-only): rebuilt from the
            # batch ledger so later agents can grep full write-ups, not just
            # the one-line index injected into the prompt.
            if prior_memory:
                docker_ops.write_file(
                    container, PRIOR_MEMORY_PATH, prior_memory.encode("utf-8")
                )

        prompt = build_find_prompt(
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
            memory_enabled=memory_enabled,
            prior_exploration=prior_exploration,
        )
        t0 = time.time()
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
        timings["find"] = time.time() - t0

        # Collect the agent's exploration memory before teardown.
        memory_text = ""
        if memory_enabled:
            memory_text = collect_run_memory(container, MEMORY_PATH)
            if memory_out_path and memory_text:
                with open(memory_out_path, "w", encoding="utf-8") as f:
                    f.write(memory_text)
            timings["memory"] = len(memory_text)

        # Parse tags — scan backwards, don't trust the last message
        text = result.find_tagged_message("poc_path")
        poc_path = parse_xml_tag(text, "poc_path")
        reproduction_command = parse_xml_tag(text, "reproduction_command")
        crash_type = parse_xml_tag(text, "crash_type")
        crash_output = parse_xml_tag(text, "crash_output") or ""
        exit_code_str = parse_xml_tag(text, "exit_code")
        dup_check = parse_xml_tag(text, "dup_check")

        if not poc_path or not reproduction_command:
            return None, result, timings

        # Empty bytes → agent narrated a path it never wrote.
        poc_bytes = docker_ops.read_file(container, poc_path)
        if not poc_bytes:
            return None, result, timings

        crash = CrashArtifact(
            poc_path=poc_path,
            poc_bytes=poc_bytes,
            reproduction_command=reproduction_command,
            crash_type=crash_type or "unknown",
            crash_output=crash_output[:10_000],  # ASAN traces are huge; top is what matters
            exit_code=_parse_exit_code(exit_code_str),
            dup_check=dup_check,
        )
        return crash, result, timings


def _parse_exit_code(s: str | None) -> int:
    if s is None:
        return -1
    s = s.strip()
    if s.lstrip("-").isdigit():
        return int(s)
    return -1
