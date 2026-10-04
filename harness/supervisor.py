# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Search-policy supervisor for dynamic validation agents.

This module is not a safety sandbox.  It detects low-value validation
strategies that make experiments hard to interpret, such as broad fuzzing,
background fuzzer sprawl, and blocking waits.  The supervisor records an
auditable event and can return a corrective prompt for the worker agent.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal


SupervisorDecisionName = Literal[
    "allow", "warn", "correct", "interrupt", "block_final_submission"
]


@dataclass(frozen=True)
class SupervisorDecision:
    """One strategy-level supervisor decision."""

    schema_version: int
    sequence: int
    timestamp: float
    decision: SupervisorDecisionName
    violation_type: str
    evidence: tuple[str, ...]
    reason: str
    required_next_action: str
    allowed_scope: str
    event_index: int | None = None
    call_id: str | None = None
    tool: str | None = None
    command_excerpt: str | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["evidence"] = list(self.evidence)
        return data

    def corrective_prompt(self) -> str:
        evidence = "\n".join(f"- {item}" for item in self.evidence)
        return (
            "Supervisor intervention: your current validation strategy is not "
            "serving the reported candidate.\n\n"
            f"Violation: {self.violation_type}\n"
            f"Reason: {self.reason}\n"
            f"Evidence:\n{evidence}\n\n"
            f"Required next action: {self.required_next_action}\n"
            f"Allowed scope: {self.allowed_scope}\n\n"
            "Continue the same dynamic-validation task. Do not treat this as a "
            "security restriction; it is a search-strategy correction. Focus on "
            "constructing explicit, replayable candidate inputs and validating "
            "them against the execution evidence."
        )


@dataclass
class SupervisorToolEvent:
    """Normalized opencode tool event consumed by the supervisor."""

    index: int
    call_id: str
    tool: str
    command: str
    output: str = ""


@dataclass
class SearchPolicySupervisor:
    """Rules-based supervisor for dynamic-validation search policy."""

    mode: str = "rules"
    event_path: str | Path | None = None
    max_blocking_wait_s: int = 20
    max_background_target_processes: int = 8
    _processed_calls: set[str] = field(default_factory=set, init=False)
    _sequence: int = field(default=0, init=False)

    @property
    def event_count(self) -> int:
        return self._sequence

    def review(self, messages: list[dict]) -> SupervisorDecision | None:
        """Inspect new tool events and return the first actionable decision."""
        if self.mode == "off":
            return None
        for event in _iter_tool_events(messages):
            if event.call_id in self._processed_calls:
                continue
            self._processed_calls.add(event.call_id)
            decision = self._review_tool_event(event)
            if decision is None:
                continue
            self._persist(decision)
            if decision.decision in {
                "correct", "interrupt", "block_final_submission",
            }:
                return decision
        return None

    def _review_tool_event(
        self, event: SupervisorToolEvent
    ) -> SupervisorDecision | None:
        if event.tool.lower() != "bash":
            return None
        command = event.command
        output = event.output
        if _is_background_fuzzer_command(command):
            return self._decision(
                event,
                decision="interrupt",
                violation_type="background_worker_sprawl",
                evidence=(
                    "The worker started fuzzing workers in the background.",
                    _excerpt(command),
                ),
                reason=(
                    "Background fuzzing workers can keep running after the agent "
                    "moves on, consume resources, and make the validation result "
                    "depend on an uncontrolled search farm."
                ),
                required_next_action=(
                    "Terminate background fuzzing workers, then return to bounded "
                    "concrete replay through the validation protocol."
                ),
            )
        if _is_broad_fuzzing_command(command):
            return self._decision(
                event,
                decision="correct",
                violation_type="broad_fuzzing",
                evidence=(
                    "The worker launched a fuzzing-mode target invocation "
                    "instead of replaying one explicit candidate input.",
                    _excerpt(command),
                ),
                reason=(
                    "Broad fuzzing does not produce interpretable evidence for "
                    "how the agent is validating the reported candidate."
                ),
                required_next_action=(
                    "Stop fuzzing-mode search. Submit or replay one explicit "
                    "target-format input tied to the static candidate, inspect "
                    "the concrete execution result, and iterate from that evidence."
                ),
            )
        process_count = _reported_target_process_count(command, output)
        if process_count is not None and process_count > self.max_background_target_processes:
            return self._decision(
                event,
                decision="interrupt",
                violation_type="background_worker_sprawl",
                evidence=(
                    f"The worker observed {process_count} target/fuzzer processes.",
                    _excerpt(command),
                    _excerpt(output),
                ),
                reason=(
                    "The dynamic phase is no longer a controlled PoC-generation "
                    "attempt; residual workers can distort timing and cause OOM."
                ),
                required_next_action=(
                    "Clean up residual target/fuzzer workers before continuing. "
                    "Do not start another fuzzing campaign."
                ),
            )
        wait_s = _blocking_wait_seconds(command)
        if wait_s is not None and wait_s > self.max_blocking_wait_s:
            return self._decision(
                event,
                decision="correct",
                violation_type="blocking_wait",
                evidence=(
                    f"The worker used a blocking wait of {wait_s} seconds.",
                    _excerpt(command),
                ),
                reason=(
                    "Long sleeps and polling consume the dynamic budget without "
                    "improving semantic understanding or PoC construction."
                ),
                required_next_action=(
                    "Do not wait passively. Inspect available results once, then "
                    "continue source-guided input construction or submit a final "
                    "evidence-backed status."
                ),
            )
        return None

    def _decision(
        self,
        event: SupervisorToolEvent,
        *,
        decision: SupervisorDecisionName,
        violation_type: str,
        evidence: tuple[str, ...],
        reason: str,
        required_next_action: str,
    ) -> SupervisorDecision:
        self._sequence += 1
        return SupervisorDecision(
            schema_version=1,
            sequence=self._sequence,
            timestamp=time.time(),
            decision=decision,
            violation_type=violation_type,
            evidence=evidence,
            reason=reason,
            required_next_action=required_next_action,
            allowed_scope=(
                "Concrete input construction, source reading tied to target "
                "branch conditions, execution-protocol replay, and final "
                "evidence-backed submission."
            ),
            event_index=event.index,
            call_id=event.call_id,
            tool=event.tool,
            command_excerpt=_excerpt(event.command, limit=500),
        )

    def _persist(self, decision: SupervisorDecision) -> None:
        if not self.event_path:
            return
        path = Path(self.event_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as stream:
            stream.write(json.dumps(decision.to_dict(), ensure_ascii=False) + "\n")


def make_supervisor_progress_nudge(
    supervisor: SearchPolicySupervisor | None,
    *,
    on_decision=None,
):
    """Return a run_agent progress_nudge callback for a supervisor."""
    if supervisor is None or supervisor.mode == "off":
        return None

    def _nudge(result) -> str | None:
        decision = supervisor.review(result.messages)
        if decision is not None and on_decision is not None:
            on_decision(decision)
        return decision.corrective_prompt() if decision else None

    return _nudge


def combine_progress_nudges(*callbacks):
    """Compose run_agent progress-nudge callbacks in priority order."""
    active = [callback for callback in callbacks if callback is not None]
    if not active:
        return None

    def _combined(result) -> str | None:
        for callback in active:
            nudge = callback(result)
            if nudge:
                return nudge
        return None

    return _combined


def _iter_tool_events(messages: list[dict]):
    for index, message in enumerate(messages):
        part = message.get("part") or {}
        if part.get("type") != "tool":
            continue
        tool = str(part.get("tool") or "")
        state = part.get("state") or {}
        raw_input = (
            state.get("input")
            if isinstance(state.get("input"), dict)
            else part.get("input")
            if isinstance(part.get("input"), dict)
            else {}
        )
        command = str(raw_input.get("command") or "")
        if not command:
            continue
        output = ""
        if isinstance(state.get("output"), str):
            output = state["output"]
        metadata = state.get("metadata")
        if not output and isinstance(metadata, dict) and isinstance(metadata.get("output"), str):
            output = metadata["output"]
        call_id = str(part.get("callID") or f"tool-{index}")
        yield SupervisorToolEvent(
            index=index, call_id=call_id, tool=tool, command=command, output=output
        )


def _is_broad_fuzzing_command(command: str) -> bool:
    lower = command.lower()
    if "-max_total_time" in lower:
        return True
    if "-artifact_prefix" in lower and "-runs=1" not in lower and "-runs 1" not in lower:
        return True
    libfuzzer_flags = (
        "-use_value_profile",
        "-print_final_stats",
        "-reload=",
        "-fork=",
        "-jobs=",
        "-workers=",
    )
    if any(flag in lower for flag in libfuzzer_flags):
        return "-runs=1" not in lower and "-runs 1" not in lower
    if re.search(r"\b\w*fuzzer\b", lower) and re.search(r"\s/tmp/\w+|\s/work/\w+", lower):
        if "-runs=1" not in lower and "-runs 1" not in lower:
            return any(flag in lower for flag in ("-max_len", "-timeout=", "-dict="))
    return False


def _is_background_fuzzer_command(command: str) -> bool:
    lower = command.lower()
    if not _has_shell_background_operator(command):
        return False
    if "fuzzer" not in lower:
        return False
    return any(
        marker in lower
        for marker in (
            "-max_total_time",
            "-artifact_prefix",
            "-use_value_profile",
            "for i in",
        )
    )


def _has_shell_background_operator(command: str) -> bool:
    """Return true for a shell background `&`, not redirects or `&&`.

    Examples:
    - `cmd &` and `(cmd) & done` are background execution.
    - `cmd 2>&1`, `cmd &>log`, and `cmd && next` are not.
    """
    return bool(re.search(r"(?<![&>])&(?![&0-9>])", command))


def _reported_target_process_count(command: str, output: str) -> int | None:
    lower_command = command.lower()
    process_query = (
        ("ps " in lower_command or lower_command.startswith("ps "))
        or "pgrep" in lower_command
        or "grep -c" in lower_command
    ) and any(
        marker in lower_command
        for marker in ("fuzzer", "_fuzzer", "mruby_fuzzer", "opencode")
    )
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if process_query:
        for line in lines[:5]:
            if re.fullmatch(r"\d+", line):
                return int(line)
    match = re.search(r"(?im)^\s*(\d+)\s+(?:target|fuzzer|mruby_fuzzer)\b", output)
    if match:
        return int(match.group(1))
    return None


def _blocking_wait_seconds(command: str) -> int | None:
    waits = [int(value) for value in re.findall(r"(?<![A-Za-z0-9_-])sleep\s+(\d+)", command)]
    if not waits:
        if re.search(r"(?<![A-Za-z0-9_-])watch\s+", command):
            return 999999
        return None
    return max(waits)


def _excerpt(text: str, *, limit: int = 240) -> str:
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"
