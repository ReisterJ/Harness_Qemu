# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Instrumentation provider registry."""
from __future__ import annotations

from .base import (
    ExecutionFeedback,
    InstrumentationProvider,
    InstrumentationReport,
    INSTRUMENTATION_SCHEMA_VERSION,
    input_sha256,
)
from .llvm import LLVMProvider


_PROVIDERS: dict[str, InstrumentationProvider] = {"llvm": LLVMProvider()}


def providers() -> tuple[str, ...]:
    return tuple(sorted(_PROVIDERS))


def provider_for(name: str) -> InstrumentationProvider:
    try:
        return _PROVIDERS[name]
    except KeyError as exc:
        raise ValueError(
            f"unknown instrumentation provider {name!r}; available: {', '.join(providers())}"
        ) from exc


def register_provider(name: str, provider: InstrumentationProvider) -> None:
    """Register a trusted host-side provider implementation.

    Provider code is platform code, not a repository-generated plugin.  This
    keeps future Java/Go/QEMU providers behind the same dynamic interface.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("instrumentation provider name must be non-empty")
    if not isinstance(provider, InstrumentationProvider):
        raise TypeError("provider must implement InstrumentationProvider")
    _PROVIDERS[name.strip()] = provider


def unregister_provider(name: str) -> None:
    _PROVIDERS.pop(name, None)


def select_provider(
    requested: str | None,
    specification: dict | None,
) -> InstrumentationProvider | None:
    """Resolve a CLI/manifest request without making languages pipeline code.

    ``off`` is explicit.  ``auto`` tries the providers declared by the target;
    when a target has no declaration it tries the built-in registry, allowing
    a new provider to be introduced without editing target configs.  Actual
    tool availability is checked by ``prepare`` inside the target container.
    """
    spec = specification if isinstance(specification, dict) else {}
    mode = requested or str(spec.get("default", "auto"))
    if mode == "off":
        return None
    names = spec.get("providers")
    if mode == "auto":
        candidates = [str(x) for x in names] if isinstance(names, list) and names else list(providers())
    else:
        candidates = [mode]
    for name in candidates:
        if name in _PROVIDERS:
            return _PROVIDERS[name]
    if mode == "auto":
        return None
    raise ValueError(
        f"unknown instrumentation provider {mode!r}; available: {', '.join(providers())}"
    )


__all__ = [
    "ExecutionFeedback",
    "InstrumentationProvider",
    "InstrumentationReport",
    "INSTRUMENTATION_SCHEMA_VERSION",
    "input_sha256",
    "LLVMProvider",
    "provider_for",
    "register_provider",
    "select_provider",
    "unregister_provider",
    "providers",
]
