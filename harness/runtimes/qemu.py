# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from .base import RuntimeAdapter, RuntimeContractError


class QemuRuntime(RuntimeAdapter):
    profile = "qemu"

    def validate_profile(self, manifest: dict) -> None:
        runtime = manifest["runtime"]
        artifact = runtime.get("artifact")
        if not isinstance(artifact, dict):
            raise RuntimeContractError("qemu runtime requires runtime.artifact")
        if not artifact.get("kernel"):
            raise RuntimeContractError("qemu runtime requires runtime.artifact.kernel")
        if not artifact.get("rootfs"):
            raise RuntimeContractError("qemu runtime requires runtime.artifact.rootfs")
        for key in ("ready", "reset", "collect"):
            if runtime.get(key) is None:
                raise RuntimeContractError(f"qemu runtime requires runtime.{key}")
