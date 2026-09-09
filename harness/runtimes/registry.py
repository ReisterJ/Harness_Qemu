# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Runtime adapter registry.

Languages do not appear here.  They are build-agent concerns; only a new
execution environment needs a new adapter or plugin registration.
"""
from __future__ import annotations

from .base import RuntimeAdapter, RuntimeContractError
from .custom import CustomRuntime
from .process import ProcessRuntime
from .qemu import QemuRuntime
from .service import ServiceRuntime


_ADAPTERS: dict[str, RuntimeAdapter] = {
    "process": ProcessRuntime(),
    "service": ServiceRuntime(),
    "qemu": QemuRuntime(),
    "custom": CustomRuntime(),
}


def profiles() -> tuple[str, ...]:
    return tuple(sorted(_ADAPTERS))


def adapter_for(profile: str) -> RuntimeAdapter:
    try:
        return _ADAPTERS[profile]
    except KeyError as exc:
        raise RuntimeContractError(
            f"unknown runtime profile {profile!r}; available: {', '.join(profiles())}"
        ) from exc
