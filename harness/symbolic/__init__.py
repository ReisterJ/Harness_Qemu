# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Dynamic symbolic-execution providers."""

from typing import Any

from .klee import KleeSession
from .symcc import SymccSession


def select_symbolic_execution(
    requested: str | None, specification: dict[str, Any] | None
) -> str | None:
    spec = specification if isinstance(specification, dict) else {}
    mode = requested or str(spec.get("default", "off"))
    if mode == "off":
        return None
    if mode == "auto":
        providers = spec.get("providers", [])
        if isinstance(providers, list):
            if "symcc" in providers:
                return "symcc"
            if "klee" in providers:
                return "klee"
        return None
    if mode in {"klee", "symcc"}:
        return mode
    raise ValueError(
        f"unknown symbolic-execution provider {mode!r}; available: off, auto, klee, symcc"
    )


__all__ = ["KleeSession", "SymccSession", "select_symbolic_execution"]
