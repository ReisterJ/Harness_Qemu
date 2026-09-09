# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Data contracts for the find→grade pipeline.

CrashArtifact is the pivot: find emits it, grade consumes it.
"""
from __future__ import annotations

import base64
import json
import math
import re
from dataclasses import dataclass, field, asdict
from typing import Any


POC_KINDS = frozenset({"file", "command", "request", "program", "bundle"})


@dataclass(frozen=True)
class CrashArtifact:
    """A crash the find-agent claims to have produced. Not yet verified."""
    poc_path: str              # path inside the find-container, e.g. /tmp/poc.bin
    poc_bytes: bytes           # PoC file contents — bytes, inputs are often binary
    reproduction_command: str  # exact command, e.g. "/work/entry /tmp/poc.bin"
    crash_type: str            # agent's classification, e.g. "heap-buffer-overflow"
    crash_output: str          # ASAN trace / stderr, truncated to 10K chars
    exit_code: int             # e.g. 134 (SIGABRT from ASAN)
    dup_check: str | None = None  # agent's reasoning that this isn't a known dup
    poc_kind: str = "file"    # file, command, request, program, or bundle

    def to_dict(self) -> dict[str, Any]:
        if self.poc_kind not in POC_KINDS:
            raise ValueError(f"unsupported PoC kind: {self.poc_kind!r}")
        d = asdict(self)
        d["poc_bytes"] = base64.b64encode(self.poc_bytes).decode("ascii")
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CrashArtifact:
        poc_kind = d.get("poc_kind", "file")
        if poc_kind not in POC_KINDS:
            raise ValueError(f"unsupported PoC kind: {poc_kind!r}")
        return cls(
            poc_path=d["poc_path"],
            poc_bytes=base64.b64decode(d["poc_bytes"]),
            reproduction_command=d["reproduction_command"],
            crash_type=d["crash_type"],
            crash_output=d["crash_output"],
            exit_code=d["exit_code"],
            dup_check=d.get("dup_check"),
            poc_kind=poc_kind,
        )


@dataclass
class StaticFinding:
    """A source-level hypothesis produced by the static find phase.

    This is deliberately not a ``CrashArtifact``.  A static finding is a
    hypothesis plus evidence that an external input may reach it; it becomes
    eligible for grading only after the dynamic phase produces a PoC.
    """

    candidate_id: str
    bug_class: str
    location: str
    static_call_chain: str
    entry_points: str
    attacker_controlled_data: str
    reachability_evidence: str
    required_conditions: str
    root_cause: str
    verification_plan: str
    confidence: float
    related_candidates: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> StaticFinding:
        """Deserialize an agent-produced finding with conservative defaults.

        Static output is model-authored and may omit optional prose fields.
        Keeping the parser tolerant lets the dynamic phase decide whether a
        weak candidate is actually reachable instead of failing the whole run.
        """
        raw_confidence = d.get("confidence", 0.0)
        try:
            confidence = float(raw_confidence)
        except (TypeError, ValueError):
            confidence = 0.0
        if not math.isfinite(confidence):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))
        related = d.get("related_candidates", [])
        if isinstance(related, str):
            related = [related]
        if not isinstance(related, list):
            related = []
        candidate_id = str(d.get("candidate_id") or "candidate_unnamed").strip()
        candidate_id = re.sub(r"[^A-Za-z0-9_.-]", "_", candidate_id)[:80]
        return cls(
            candidate_id=candidate_id or "candidate_unnamed",
            bug_class=str(d.get("bug_class") or "unknown"),
            location=str(d.get("location") or "unknown"),
            static_call_chain=str(d.get("static_call_chain") or ""),
            entry_points=str(d.get("entry_points") or ""),
            attacker_controlled_data=str(d.get("attacker_controlled_data") or ""),
            reachability_evidence=str(d.get("reachability_evidence") or ""),
            required_conditions=str(d.get("required_conditions") or ""),
            root_cause=str(d.get("root_cause") or ""),
            verification_plan=str(d.get("verification_plan") or ""),
            confidence=confidence,
            related_candidates=[str(x) for x in related],
        )


@dataclass
class DynamicValidationResult:
    """Result of trying to turn one static finding into a PoC."""

    candidate_id: str
    status: str  # validated, not_reached, reached_no_crash, wrong_path,
                 # environment_blocked, invalid_submission, agent_failed
    reached_functions: list[str] = field(default_factory=list)
    reachability_evidence: str = ""
    reason: str = ""
    crash: CrashArtifact | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["crash"] = self.crash.to_dict() if self.crash else None
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DynamicValidationResult:
        reached = d.get("reached_functions", [])
        if isinstance(reached, str):
            reached = [reached]
        return cls(
            candidate_id=str(d.get("candidate_id") or ""),
            status=str(d.get("status") or "unknown"),
            reached_functions=[str(x) for x in reached] if isinstance(reached, list) else [],
            reachability_evidence=str(d.get("reachability_evidence") or ""),
            reason=str(d.get("reason") or ""),
            crash=CrashArtifact.from_dict(d["crash"]) if d.get("crash") else None,
        )


@dataclass
class GraderVerdict:
    """The grade-agent's judgment of a CrashArtifact."""
    passed: bool
    score: float               # 0.0–1.0
    criteria: dict[str, bool]  # {"criterion_1": True, ..., "criterion_5": True}
    evidence: str              # grader's summary

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> GraderVerdict:
        return cls(
            passed=d["passed"],
            score=d["score"],
            criteria=d["criteria"],
            evidence=d["evidence"],
        )


@dataclass
class PatchVerdict:
    """T0-T3 ladder result for a candidate patch. Every gating tier is an
    executable oracle (compiler/ASAN/tests); T3 is advisory-only."""
    t0_builds: bool
    t1_poc_stops: bool
    t2_tests_pass: bool | None     # None = target has no test suite
    re_attack_clean: bool | None   # None = re-attack not run (--no-reattack)
    t3_style_score: float | None   # 0-10, None when style judge not run
    evidence: dict[str, str]       # per-tier stdout/stderr excerpts
    timings: dict[str, float]

    @property
    def passed(self) -> bool:
        return (
            self.t0_builds
            and self.t1_poc_stops
            and self.t2_tests_pass is not False
            and self.re_attack_clean is not False
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["passed"] = self.passed
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PatchVerdict:
        return cls(
            t0_builds=d["t0_builds"],
            t1_poc_stops=d["t1_poc_stops"],
            t2_tests_pass=d["t2_tests_pass"],
            re_attack_clean=d["re_attack_clean"],
            t3_style_score=d.get("t3_style_score"),
            evidence=d.get("evidence", {}),
            timings=d.get("timings", {}),
        )


@dataclass
class JudgeVerdict:
    """The judge-agent's call on whether a new crash warrants a report."""
    judgment: str              # NEW, DUP_BETTER, DUP_SKIP
    bug_id: int | None         # which existing bug it matches (required for DUP_*)
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> JudgeVerdict:
        return cls(
            judgment=d["judgment"],
            bug_id=d.get("bug_id"),
            reasoning=d.get("reasoning", ""),
        )


@dataclass
class ReportVerdict:
    """The report-agent's exploitability analysis of a verified crash."""
    section_scores: dict[str, int]  # primitive, reachability, heap_layout, escalation_path, constraints → 0/1/2
    rubric_score: int               # sum of section scores, 0..10
    escalation_bonus: int           # 0..4 for escalation_attempt depth
    total_score: float              # (rubric + bonus) / 14
    severity_rating: str            # agent's CRITICAL/HIGH/MEDIUM/LOW/NOT-A-BUG/NOT_STATED
    novelty_status: str             # FIXED/UNFIXED/UNKNOWN/NOT_CHECKED
    reachability_verdict: str       # REACHABLE/HARNESS_ONLY/UNCLEAR

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ReportVerdict:
        return cls(
            section_scores=d["section_scores"],
            rubric_score=d["rubric_score"],
            escalation_bonus=d["escalation_bonus"],
            total_score=d["total_score"],
            severity_rating=d["severity_rating"],
            novelty_status=d["novelty_status"],
            reachability_verdict=d["reachability_verdict"],
        )


@dataclass
class RunResult:
    """One end-to-end run's outcome."""
    target: str
    status: str                     # crash_found, no_crash_found, crash_rejected, agent_failed, build_failed, error
    crash: CrashArtifact | None
    verdict: GraderVerdict | None
    find_transcript: list[dict] = field(default_factory=list)
    grade_transcript: list[dict] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "status": self.status,
            "crash": self.crash.to_dict() if self.crash else None,
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "find_transcript": self.find_transcript,
            "grade_transcript": self.grade_transcript,
            "timings": self.timings,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RunResult:
        return cls(
            target=d["target"],
            status=d["status"],
            crash=CrashArtifact.from_dict(d["crash"]) if d.get("crash") else None,
            verdict=GraderVerdict.from_dict(d["verdict"]) if d.get("verdict") else None,
            find_transcript=d.get("find_transcript", []),
            grade_transcript=d.get("grade_transcript", []),
            timings=d.get("timings", {}),
            error=d.get("error"),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, s: str) -> RunResult:
        return cls.from_dict(json.loads(s))
