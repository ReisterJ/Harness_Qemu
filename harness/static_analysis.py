# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Static-analysis phase of the split find workflow."""
from __future__ import annotations

import json
import re
import time

from . import sandbox
from .agent import AgentResult, parse_xml_tag, run_agent
from .artifacts import StaticFinding
from .config import TargetConfig
from .prompts.static_analysis_prompt import build_static_analysis_prompt


def parse_static_findings(text: str) -> tuple[list[StaticFinding], str | None]:
    """Parse the agent's ``<static_findings>`` JSON without trusting prose."""
    raw = parse_xml_tag(text, "static_findings")
    if raw is None:
        return [], "missing <static_findings> tag"

    payload = raw.strip()
    # Models occasionally add a fence despite the explicit contract. Accept
    # it, but never search arbitrary prose for JSON: the tag remains the
    # boundary of the agent-authored data.
    payload = re.sub(r"^```(?:json)?\s*", "", payload, flags=re.IGNORECASE)
    payload = re.sub(r"\s*```$", "", payload)
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as exc:
        return [], f"invalid static findings JSON: {exc}"

    if isinstance(decoded, dict):
        decoded = decoded.get("findings")
    if not isinstance(decoded, list):
        return [], "static findings payload must be a JSON array"

    findings: list[StaticFinding] = []
    errors: list[str] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(decoded[:5]):
        if not isinstance(item, dict):
            errors.append(f"candidate {index + 1} is not an object")
            continue
        finding = StaticFinding.from_dict(item)
        if finding.candidate_id in seen_ids:
            finding.candidate_id = f"{finding.candidate_id}_{index + 1}"
        seen_ids.add(finding.candidate_id)
        findings.append(finding)

    if errors and not findings:
        return [], "; ".join(errors)
    return findings, "; ".join(errors) if errors else None


async def run_static_analysis(
    target: TargetConfig,
    model: str,
    max_turns: int,
    agent_env: dict[str, str] | None = None,
    container_name: str = "static_target",
    focus_area: str | None = None,
    known_bugs: list[str] | None = None,
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
    system_prompt: str | None = None,
    max_resume_attempts: int = 20,
) -> tuple[list[StaticFinding], AgentResult, dict[str, float], str | None]:
    """Run source-only analysis in a separate agent container.

    The static container receives the read tool but not Bash. This makes the
    no-execution boundary explicit in addition to the prompt-level contract.
    """
    timings: dict[str, float] = {}
    with sandbox.agent_container(
        target.image_tag,
        container_name,
        agent_env,
        memory=target.memory_limit,
        shm_size=target.shm_size,
        network=target.agent_network,
        devices=target.devices,
        prebuilt=target.agent_prebuilt,
    ) as container:
        prompt = build_static_analysis_prompt(
            github_url=target.github_url,
            commit=target.commit,
            source_root=target.source_root,
            binary_path=target.binary_path,
            detector=target.detector,
            focus_area=focus_area,
            known_bugs=known_bugs if known_bugs is not None else target.known_bugs,
            attack_surface=target.attack_surface,
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
            tools=["Read"],
        )
        timings["static_analysis"] = time.time() - started

        text = result.find_tagged_message("static_findings")
        findings, parse_error = parse_static_findings(text)
        return findings, result, timings, parse_error
