# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from .base import RuntimeAdapter, RuntimeContractError


class ServiceRuntime(RuntimeAdapter):
    profile = "service"

    def validate_profile(self, manifest: dict) -> None:
        runtime = manifest["runtime"]
        endpoint = runtime.get("endpoint")
        if not isinstance(endpoint, dict):
            raise RuntimeContractError("service runtime requires runtime.endpoint")
        ready = runtime.get("ready")
        if ready is None:
            raise RuntimeContractError("service runtime requires runtime.ready")
        if runtime.get("reset") is None:
            raise RuntimeContractError("service runtime requires runtime.reset")
