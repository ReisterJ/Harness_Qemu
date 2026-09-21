# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Provider-neutral instrumentation contracts.

Instrumentation is an observation aid for dynamic validation.  It is kept
separate from detector selection (ASAN/logic/etc.) and from the PoC artifact
contract so providers can be added without changing grade.
"""
from __future__ import annotations

import hashlib
import json
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


INSTRUMENTATION_SCHEMA_VERSION = 1
MAX_FEEDBACK_TEXT = 20_000
MAX_FEEDBACK_ITEMS = 2_000


def input_sha256(value: bytes | str) -> str:
    """Return a stable digest for the input represented by a feedback event."""
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def _bounded_text(value: Any, limit: int = MAX_FEEDBACK_TEXT) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "…[truncated]"


def _bounded_items(value: Any) -> list[Any]:
    if not isinstance(value, list):
        return []
    return value[:MAX_FEEDBACK_ITEMS]


@dataclass(frozen=True)
class ExecutionFeedback:
    """Normalized observation for one target execution.

    Providers may support only a subset of the fields.  ``capabilities`` says
    which fields are meaningful; an unsupported field is not evidence merely
    because it is represented by an empty list.
    """

    provider: str
    run_id: str
    input_sha256: str
    status: str
    exit_code: int | None = None
    duration_ms: int | None = None
    capabilities: tuple[str, ...] = ()
    reached_functions: tuple[str, ...] = ()
    reached_locations: tuple[dict[str, Any], ...] = ()
    edges: tuple[Any, ...] = ()
    branches: tuple[Any, ...] = ()
    comparisons: tuple[Any, ...] = ()
    stdout: str = ""
    stderr: str = ""
    errors: tuple[str, ...] = ()
    raw_artifacts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": INSTRUMENTATION_SCHEMA_VERSION,
            "provider": self.provider,
            "run_id": self.run_id,
            "input_sha256": self.input_sha256,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "capabilities": list(self.capabilities),
            "reached_functions": list(self.reached_functions),
            "reached_locations": list(self.reached_locations),
            "edges": list(self.edges),
            "branches": list(self.branches),
            "comparisons": list(self.comparisons),
            "stdout": _bounded_text(self.stdout),
            "stderr": _bounded_text(self.stderr),
            "errors": [_bounded_text(e, 2_000) for e in self.errors[:100]],
            "raw_artifacts": list(self.raw_artifacts[:100]),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ExecutionFeedback":
        if not isinstance(value, dict):
            raise ValueError("execution feedback must be an object")
        version = value.get("schema_version", INSTRUMENTATION_SCHEMA_VERSION)
        if version != INSTRUMENTATION_SCHEMA_VERSION:
            raise ValueError(f"unsupported instrumentation schema: {version!r}")
        provider = str(value.get("provider") or "unknown").strip()
        run_id = str(value.get("run_id") or "unknown").strip()
        digest = str(value.get("input_sha256") or "").strip()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
            raise ValueError("input_sha256 must be a SHA-256 hex digest")
        status = str(value.get("status") or "unknown").strip()
        if not status:
            raise ValueError("feedback status must be non-empty")
        exit_code = value.get("exit_code")
        if exit_code is not None and not isinstance(exit_code, int):
            exit_code = None
        duration = value.get("duration_ms")
        if duration is not None and (
            not isinstance(duration, (int, float)) or not math.isfinite(duration)
        ):
            duration = None
        caps = value.get("capabilities", [])
        if not isinstance(caps, list):
            caps = []
        errors = value.get("errors", [])
        if not isinstance(errors, list):
            errors = []
        return cls(
            provider=provider,
            run_id=run_id,
            input_sha256=digest,
            status=status,
            exit_code=exit_code,
            duration_ms=int(duration) if duration is not None else None,
            capabilities=tuple(str(x) for x in caps[:100]),
            reached_functions=tuple(
                str(x) for x in _bounded_items(value.get("reached_functions"))
            ),
            reached_locations=tuple(
                x for x in _bounded_items(value.get("reached_locations")) if isinstance(x, dict)
            ),
            edges=tuple(_bounded_items(value.get("edges"))),
            branches=tuple(_bounded_items(value.get("branches"))),
            comparisons=tuple(_bounded_items(value.get("comparisons"))),
            stdout=_bounded_text(value.get("stdout")),
            stderr=_bounded_text(value.get("stderr")),
            errors=tuple(_bounded_text(x, 2_000) for x in errors[:100]),
            raw_artifacts=tuple(
                str(x) for x in _bounded_items(value.get("raw_artifacts"))
            ),
        )


@dataclass(frozen=True)
class InstrumentationReport:
    """Host-persisted result of one provider session."""

    provider: str
    status: str
    capabilities: tuple[str, ...] = ()
    manifest: dict[str, Any] = field(default_factory=dict)
    feedback: tuple[ExecutionFeedback, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": INSTRUMENTATION_SCHEMA_VERSION,
            "provider": self.provider,
            "status": self.status,
            "capabilities": list(self.capabilities),
            "manifest": self.manifest,
            "feedback": [item.to_dict() for item in self.feedback],
            "errors": [_bounded_text(e, 2_000) for e in self.errors[:100]],
        }

    @classmethod
    def unavailable(cls, provider: str, reason: str) -> "InstrumentationReport":
        return cls(provider=provider, status="unavailable", errors=(reason,))


class InstrumentationProvider(ABC):
    """Host-side lifecycle for a provider implemented inside a target image."""

    name: str
    capabilities: tuple[str, ...] = ()

    @abstractmethod
    def prepare(
        self,
        container: str,
        *,
        source_root: str,
        binary_path: str,
        candidate: dict[str, Any],
    ) -> InstrumentationReport:
        """Install the provider contract in an agent container."""

    @abstractmethod
    def collect(self, container: str, manifest: dict[str, Any]) -> InstrumentationReport:
        """Read and normalize provider output before the container is removed."""


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
