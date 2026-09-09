# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Common runtime adapter interface.

The first implementation exposes validation and prompt metadata.  Concrete
session operations are added without changing the find/grade orchestration.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..manifest import validate_manifest


class RuntimeContractError(ValueError):
    """The manifest cannot be executed by the selected runtime."""


class RuntimeAdapter(ABC):
    profile: str

    def validate(self, manifest: dict[str, Any]) -> None:
        try:
            validate_manifest(manifest)
        except ValueError as exc:
            raise RuntimeContractError(str(exc)) from exc
        if manifest["runtime"]["profile"] != self.profile:
            raise RuntimeContractError(
                f"manifest profile is {manifest['runtime']['profile']!r}, "
                f"not {self.profile!r}"
            )
        self.validate_profile(manifest)

    @abstractmethod
    def validate_profile(self, manifest: dict[str, Any]) -> None:
        """Validate profile-specific lifecycle requirements."""

    def prompt_context(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Return safe runtime metadata for find/dynamic/grade prompts."""
        self.validate(manifest)
        runtime = manifest["runtime"]
        return {
            "profile": self.profile,
            "source_root": runtime.get("source_root"),
            "artifact": runtime.get("artifact", {}),
            "start": runtime.get("start", {}),
            "capabilities": runtime.get("capabilities", []),
            "detection": manifest.get("detection", {}),
            "workflow": manifest.get("workflow", {}),
        }
