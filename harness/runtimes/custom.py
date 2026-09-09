# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from .base import RuntimeAdapter, RuntimeContractError


class CustomRuntime(RuntimeAdapter):
    profile = "custom"

    def validate_profile(self, manifest: dict) -> None:
        runtime = manifest["runtime"]
        plugin = runtime.get("plugin")
        if not isinstance(plugin, str) or not plugin.strip():
            raise RuntimeContractError(
                "custom runtime requires runtime.plugin"
            )
