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
