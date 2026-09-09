# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Repository-classification schema tests."""
from __future__ import annotations

import pytest

from harness.classification import ClassificationError, validate_classification


def _classification() -> dict:
    return {
        "schema_version": 1,
        "project": {
            "kind": "service",
            "languages": ["go"],
            "build_system": "go modules",
            "rationale": "main package starts an HTTP server",
        },
        "runtime": {
            "profile": "service",
            "artifact_kind": "service",
            "rationale": "the public entry point is an HTTP listener",
        },
        "detection": {"detectors": ["asan"]},
        "confidence": 0.8,
        "evidence": ["README.md", "cmd/server/main.go"],
        "blockers": [],
    }


def test_classification_schema_accepts_service():
    assert validate_classification(_classification())["runtime"]["profile"] == "service"


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        ("project.kind", "daemon", "project.kind"),
        ("runtime.profile", "java", "runtime.profile"),
        ("confidence", 2, "confidence"),
    ],
)
def test_classification_schema_rejects_invalid_values(path, value, message):
    value_map = _classification()
    if path == "project.kind":
        value_map["project"]["kind"] = value
    elif path == "runtime.profile":
        value_map["runtime"]["profile"] = value
    else:
        value_map[path] = value
    with pytest.raises(ClassificationError, match=message):
        validate_classification(value_map)
