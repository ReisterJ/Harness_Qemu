# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Manifest and runtime-profile contract tests."""
from __future__ import annotations

import pytest

from harness.manifest import ManifestError, legacy_manifest, validate_manifest
from harness.runtimes import adapter_for, profiles
from harness.runtimes.base import RuntimeContractError


def _process_manifest() -> dict:
    return {
        "schema_version": 1,
        "identity": {"name": "demo", "repository": "local", "commit": "abc"},
        "build": {"build_steps": []},
        "runtime": {
            "profile": "process",
            "source_root": "/work/src",
            "artifact": {"kind": "executable", "path": "/work/entry"},
            "start": {"command": "/work/entry"},
            "capabilities": ["file_input"],
        },
        "workflow": {
            "static_analysis": "source",
            "dynamic_validation": "process",
            "grade": "process_replay",
        },
        "resources": {"devices": []},
    }


def test_manifest_accepts_process_profile():
    manifest = validate_manifest(_process_manifest(), require_identity=True)
    assert manifest["runtime"]["profile"] == "process"
    assert adapter_for("process").prompt_context(manifest)["profile"] == "process"


def test_manifest_rejects_host_path_and_unknown_profile():
    manifest = _process_manifest()
    manifest["runtime"]["source_root"] = "../src"
    with pytest.raises(ManifestError, match="absolute container path"):
        validate_manifest(manifest)

    manifest = _process_manifest()
    manifest["runtime"]["profile"] = "java"
    with pytest.raises(ManifestError, match="runtime.profile"):
        validate_manifest(manifest)


def test_service_requires_lifecycle_contract():
    manifest = _process_manifest()
    manifest["runtime"].update(
        {
            "profile": "service",
            "start": {"command": "/work/start"},
            "endpoint": {"scheme": "http", "host": "127.0.0.1", "port": 8080},
            "ready": {"command": "/work/ready"},
            "reset": {"command": "/work/reset"},
        }
    )
    adapter_for("service").validate(manifest)
    del manifest["runtime"]["reset"]
    with pytest.raises(RuntimeContractError, match="runtime.reset"):
        adapter_for("service").validate(manifest)


def test_legacy_config_is_projected_without_language_branches():
    manifest = legacy_manifest(
        {
            "github_url": "local",
            "commit": "n/a",
            "binary_path": "/work/entry",
            "source_root": "/work",
            "detector": "asan",
        },
        name="legacy",
    )
    assert manifest["runtime"]["profile"] == "process"
    assert set(profiles()) == {"custom", "process", "qemu", "service"}
