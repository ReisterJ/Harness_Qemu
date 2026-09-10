# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Target-agent runtime sessions.

The session owns lifecycle operations that are common to dynamic validation
and grade.  The agent still performs the actual exploratory interaction, but
service and QEMU targets are brought to a ready state before the agent starts.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator
import shlex

from .. import docker_ops, sandbox
from ..config import TargetConfig
from . import adapter_for
from .base import RuntimeContractError


def _command(spec: Any, field: str) -> str | None:
    if spec is None:
        return None
    if isinstance(spec, dict):
        value = spec.get("command")
    else:
        value = spec
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise RuntimeContractError(f"{field} must contain a command")
    return value


@dataclass
class RuntimeSession:
    container: str
    profile: str
    manifest: dict[str, Any] | None
    started: bool = False

    @property
    def runtime(self) -> dict[str, Any]:
        return (self.manifest or {}).get("runtime", {})

    def exec(self, command: str, *, timeout: int | None = None) -> tuple[int, str, str]:
        return docker_ops.exec_sh(self.container, command, timeout=timeout)

    def start(self) -> None:
        # A process target is intentionally not started here: the dynamic or
        # grade agent chooses the input and launches the artifact itself.
        if self.profile in {"legacy", "process"}:
            return
        command = _command(self.runtime.get("start"), "runtime.start")
        if not command:
            raise RuntimeContractError(f"{self.profile} runtime has no start command")
        rc, _out, err = self.exec(command, timeout=60)
        if rc:
            raise RuntimeContractError(
                f"{self.profile} runtime start failed with exit {rc}: {err[-500:]}"
            )
        self.started = True
        self.ready()

    def ready(self) -> None:
        spec = self.runtime.get("ready")
        if spec is None:
            return
        command = _command(spec, "runtime.ready")
        if command is None and isinstance(spec, dict) and spec.get("signal"):
            path = spec.get("path")
            if not path:
                raise RuntimeContractError(
                    "runtime.ready.signal requires runtime.ready.path"
                )
            command = (
                f"grep -F -- {shlex.quote(str(spec['signal']))} "
                f"{shlex.quote(path)}"
            )
        if command is None and isinstance(spec, dict) and spec.get("port"):
            endpoint = self.runtime.get("endpoint") or {}
            host = spec.get("host") or endpoint.get("host") or "127.0.0.1"
            port = spec["port"]
            scheme = endpoint.get("scheme")
            if scheme in {"http", "https"}:
                url = f"{scheme}://{host}:{port}/"
                command = (
                    f"curl -fsS --max-time 2 -o /dev/null {shlex.quote(url)}"
                )
            else:
                command = f"nc -z -w 2 {shlex.quote(host)} {port}"
        if command:
            attempts = int(self.runtime.get("ready_timeout_s", 60) * 2)
            last_error = ""
            for _ in range(max(1, attempts)):
                rc, _out, err = self.exec(command, timeout=10)
                if rc == 0:
                    return
                last_error = err.strip()[-300:]
                time.sleep(0.5)
            raise RuntimeContractError(
                f"{self.profile} runtime did not become ready: {last_error}"
            )

        if isinstance(spec, dict) and spec.get("path"):
            path = spec["path"]
            rc, _out, err = self.exec(
                f"test -e {shlex.quote(path)}", timeout=10
            )
            if rc:
                raise RuntimeContractError(
                    f"runtime.ready path is absent: {path}: {err.strip()[-300:]}"
                )
            return

        raise RuntimeContractError(
            "runtime.ready needs a command or a container path for this session"
        )

    def reset(self) -> None:
        command = _command(self.runtime.get("reset"), "runtime.reset")
        if command:
            rc, _out, err = self.exec(command, timeout=120)
            if rc:
                raise RuntimeContractError(
                    f"{self.profile} runtime reset failed with exit {rc}: {err[-500:]}"
                )
            self.ready()

    def stop(self) -> None:
        if not self.started:
            return
        command = _command(self.runtime.get("stop"), "runtime.stop")
        if command:
            self.exec(command, timeout=30)


@contextmanager
def open_runtime_session(
    target: TargetConfig,
    *,
    container_name: str,
    auth: dict[str, str] | None,
    mounts: list[tuple[str, str]] | None = None,
) -> Iterator[RuntimeSession]:
    """Create a fresh target-agent container and prepare its runtime."""
    manifest = target.manifest
    profile = "legacy"
    if manifest is not None:
        profile = manifest["runtime"]["profile"]
        adapter_for(profile).validate(manifest)
    agent_network = target.agent_network
    if agent_network is None and not sandbox.runtime():
        # In the explicitly unsandboxed development mode, a loopback proxy
        # configured on the host is otherwise unreachable from Docker's
        # bridge namespace. Keep the sandboxed default unchanged.
        agent_network = "host"
    with sandbox.agent_container(
        target.runtime_image_tag,
        container_name,
        auth,
        memory=target.memory_limit,
        shm_size=target.shm_size,
        mounts=mounts,
        network=agent_network,
        devices=target.devices,
        prebuilt=target.agent_prebuilt,
        run_params=target.docker_run_params("agent"),
        image_pull=target.runtime_image_pull,
    ) as container:
        session = RuntimeSession(container, profile, manifest)
        try:
            session.start()
            yield session
        finally:
            session.stop()
