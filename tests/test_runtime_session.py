# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Runtime session lifecycle tests without a Docker daemon."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import patch

from harness.config import TargetConfig
from harness.runtimes.session import open_runtime_session
from harness.runtimes.base import RuntimeContractError


def _target(manifest: dict) -> TargetConfig:
    return TargetConfig(
        name="demo",
        dockerfile_dir="targets/demo",
        image_tag="demo:latest",
        github_url="local",
        commit="abc",
        binary_path="/work/entry",
        source_root="/work/src",
        agent_network="none",
        manifest=manifest,
    )


def _service_manifest() -> dict:
    return {
        "schema_version": 1,
        "identity": {"name": "demo", "repository": "local", "commit": "abc"},
        "build": {"build_steps": []},
        "runtime": {
            "profile": "service",
            "source_root": "/work/src",
            "start": {"command": "/work/start"},
            "ready": {"command": "/work/ready"},
            "reset": {"command": "/work/reset"},
            "stop": {"command": "/work/stop"},
            "endpoint": {"scheme": "http", "host": "127.0.0.1", "port": 8080},
        },
        "workflow": {
            "static_analysis": "source",
            "dynamic_validation": "service",
            "grade": "service_replay",
        },
        "resources": {"devices": []},
    }


def test_service_session_runs_start_ready_and_stop(monkeypatch):
    calls: list[str] = []

    @contextmanager
    def fake_container(*_args, **_kwargs):
        yield "container"

    def fake_exec(container, command, timeout=None):
        calls.append(command)
        return 0, "", ""

    monkeypatch.setattr("harness.runtimes.session.sandbox.agent_container", fake_container)
    monkeypatch.setattr("harness.runtimes.session.docker_ops.exec_sh", fake_exec)

    with open_runtime_session(
        _target(_service_manifest()), container_name="demo", auth=None
    ) as session:
        assert session.container == "container"

    assert calls == ["/work/start", "/work/ready", "/work/stop"]


def test_session_translates_signal_ready_to_log_probe(monkeypatch):
    calls: list[str] = []

    @contextmanager
    def fake_container(*_args, **_kwargs):
        yield "container"

    def fake_exec(container, command, timeout=None):
        calls.append(command)
        return 0, "", ""

    monkeypatch.setattr("harness.runtimes.session.sandbox.agent_container", fake_container)
    monkeypatch.setattr("harness.runtimes.session.docker_ops.exec_sh", fake_exec)
    manifest = _service_manifest()
    manifest["runtime"]["ready"] = {
        "signal": "guest\\s+ready",
        "path": "/work/serial.log",
    }
    with open_runtime_session(
        _target(manifest), container_name="demo", auth=None
    ):
        pass
    assert calls[1] == "grep -F -- 'guest\\s+ready' /work/serial.log"


def test_legacy_session_does_not_start_target(monkeypatch):
    calls: list[str] = []

    @contextmanager
    def fake_container(*_args, **_kwargs):
        yield "container"

    monkeypatch.setattr("harness.runtimes.session.sandbox.agent_container", fake_container)
    monkeypatch.setattr(
        "harness.runtimes.session.docker_ops.exec_sh",
        lambda _container, command, timeout=None: calls.append(command) or (0, "", ""),
    )

    target = _target(None)
    with open_runtime_session(target, container_name="demo", auth=None):
        pass
    assert calls == []


def test_unsandboxed_session_uses_host_network_by_default(monkeypatch):
    observed: dict = {}

    @contextmanager
    def fake_container(*_args, **kwargs):
        observed.update(kwargs)
        yield "container"

    monkeypatch.setattr("harness.runtimes.session.sandbox.agent_container", fake_container)
    monkeypatch.setattr("harness.runtimes.session.sandbox.runtime", lambda: None)

    with open_runtime_session(
        replace(_target(None), agent_network=None), container_name="demo", auth=None
    ):
        pass

    assert observed["network"] == "host"


def test_session_stops_if_ready_check_fails(monkeypatch):
    calls: list[str] = []

    @contextmanager
    def fake_container(*_args, **_kwargs):
        yield "container"

    def fake_exec(container, command, timeout=None):
        calls.append(command)
        if command == "/work/ready":
            return 1, "", "not ready"
        return 0, "", ""

    monkeypatch.setattr("harness.runtimes.session.sandbox.agent_container", fake_container)
    monkeypatch.setattr("harness.runtimes.session.docker_ops.exec_sh", fake_exec)

    manifest = _service_manifest()
    manifest["runtime"]["ready_timeout_s"] = 0.1
    try:
        with open_runtime_session(
            _target(manifest), container_name="demo", auth=None
        ):
            raise AssertionError("session should not become ready")
    except RuntimeContractError:
        pass

    assert calls[0] == "/work/start"
    assert calls[-1] == "/work/stop"
