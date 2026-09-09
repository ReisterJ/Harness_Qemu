# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Schema for the repository classification stage.

Classification is deliberately separate from the generated Dockerfile and
runtime manifest.  It records the agent's decision about the repository before
the build agent is allowed to choose implementation details.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .manifest import RUNTIME_PROFILES


CLASSIFICATION_FILENAME = "target-classification.json"
CLASSIFICATION_SCHEMA_VERSION = 1
PROJECT_KINDS = frozenset({"cli", "library", "service", "kernel", "firmware", "unknown"})


class ClassificationError(ValueError):
    """A repository classification is missing or malformed."""


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ClassificationError(f"{path} must be a JSON object")
    return value


def _string(value: Any, path: str, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ClassificationError(f"{path} must be a non-empty string")
    return value.strip()


def _string_list(value: Any, path: str, *, required: bool = False) -> list[str]:
    if value is None and not required:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise ClassificationError(f"{path} must be a list of non-empty strings")
    return [x.strip() for x in value]


def validate_classification(value: dict[str, Any]) -> dict[str, Any]:
    """Validate a classifier result and return it unchanged."""
    _mapping(value, "classification")
    if value.get("schema_version") != CLASSIFICATION_SCHEMA_VERSION:
        raise ClassificationError(
            f"schema_version must be {CLASSIFICATION_SCHEMA_VERSION}, "
            f"got {value.get('schema_version')!r}"
        )

    project = _mapping(value.get("project"), "project")
    kind = _string(project.get("kind"), "project.kind")
    assert kind is not None
    if kind not in PROJECT_KINDS:
        raise ClassificationError(
            f"project.kind must be one of {sorted(PROJECT_KINDS)}, got {kind!r}"
        )
    _string_list(project.get("languages", []), "project.languages")
    _string(project.get("build_system"), "project.build_system")

    runtime = _mapping(value.get("runtime"), "runtime")
    profile = _string(runtime.get("profile"), "runtime.profile")
    assert profile is not None
    if profile not in RUNTIME_PROFILES:
        raise ClassificationError(
            f"runtime.profile must be one of {sorted(RUNTIME_PROFILES)}, got {profile!r}"
        )
    _string(runtime.get("rationale"), "runtime.rationale")
    _string(runtime.get("artifact_kind"), "runtime.artifact_kind")

    detection = _mapping(value.get("detection", {}), "detection")
    _string_list(detection.get("detectors", []), "detection.detectors")

    confidence = value.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ClassificationError("confidence must be a number between 0 and 1")

    _string_list(value.get("evidence", []), "evidence")
    _string_list(value.get("blockers", []), "blockers")
    return value


def load_classification(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ClassificationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ClassificationError(f"{path} must contain a JSON object")
    return validate_classification(value)
