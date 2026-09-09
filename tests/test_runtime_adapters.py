# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Runtime adapter behavior used by the host-side build probe."""
from __future__ import annotations

import pytest

from harness.runtimes import (
    adapter_for,
    register_custom_runtime,
    unregister_custom_runtime,
)
from harness.runtimes.base import RuntimeContractError


def test_process_adapter_reports_source_and_executable_artifact():
    manifest = {
        "runtime": {
            "profile": "process",
            "source_root": "/work/src",
            "artifact": {"kind": "executable", "path": "/work/entry"},
        }
    }
    assert adapter_for("process").required_paths(manifest) == [
        ("/work/src", False),
        ("/work/entry", True),
    ]


def test_qemu_adapter_reports_kernel_and_rootfs_paths():
    manifest = {
        "runtime": {
            "profile": "qemu",
            "source_root": "/work/src",
            "artifact": {
                "kind": "qemu-guest",
                "kernel": "/work/bzImage",
                "rootfs": "/work/rootfs.img",
            },
        }
    }
    assert adapter_for("qemu").required_paths(manifest) == [
        ("/work/src", False),
        ("/work/bzImage", False),
        ("/work/rootfs.img", False),
    ]


def test_custom_probe_is_an_explicit_blocker():
    with pytest.raises(RuntimeContractError, match="not registered"):
        adapter_for("custom").probe(
            type(
                "Session",
                (),
                {"manifest": {"runtime": {"plugin": "missing"}}},
            )()
        )


def test_custom_plugin_is_host_registered_and_used():
    calls: list[str] = []

    class Plugin:
        def validate(self, manifest):
            calls.append("validate")

        def required_paths(self, manifest):
            calls.append("paths")
            return [("/work/custom-artifact", False)]

        def probe(self, session):
            calls.append("probe")

    manifest = {
        "runtime": {
            "profile": "custom",
            "plugin": "example",
            "start": {},
        }
    }
    register_custom_runtime("example", Plugin())
    try:
        adapter = adapter_for("custom")
        adapter.validate_profile(manifest)
        assert adapter.required_paths(manifest) == [("/work/custom-artifact", False)]
        adapter.probe(type("Session", (), {"manifest": manifest})())
    finally:
        unregister_custom_runtime("example")
    assert calls == ["validate", "paths", "probe"]
