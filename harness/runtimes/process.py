# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

from .base import RuntimeAdapter, RuntimeContractError


class ProcessRuntime(RuntimeAdapter):
    profile = "process"

    def validate_profile(self, manifest: dict[str, Any]) -> None:
        runtime = manifest["runtime"]
        artifact = runtime.get("artifact")
        if not isinstance(artifact, dict) or not artifact.get("path"):
            raise RuntimeContractError(
                "process runtime requires runtime.artifact.path"
            )
        start = runtime.get("start", {})
        if not isinstance(start, dict) or not start.get("command"):
            raise RuntimeContractError(
                "process runtime requires runtime.start.command"
            )

    def probe(self, session) -> None:
        # A process may require input and is therefore not launched blindly.
        # A generated target can opt into a safe, non-mutating probe command.
        spec = session.runtime.get("probe")
        if not spec:
            return
        command = spec.get("command") if isinstance(spec, dict) else spec
        if not isinstance(command, str) or not command.strip():
            raise RuntimeContractError("runtime.probe must contain a command")
        rc, _out, err = session.exec(command, timeout=60)
        if rc:
            raise RuntimeContractError(
                f"process runtime probe failed with exit {rc}: {err[-500:]}"
            )
