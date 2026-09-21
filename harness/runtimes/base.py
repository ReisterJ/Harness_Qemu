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

    def required_paths(self, manifest: dict[str, Any]) -> list[tuple[str, bool]]:
        """Return container paths that must exist after the image build."""
        runtime = manifest["runtime"]
        paths: list[tuple[str, bool]] = []
        if runtime.get("source_root"):
            paths.append((runtime["source_root"], False))
        artifact = runtime.get("artifact") or {}
        for key in ("path", "kernel", "rootfs"):
            if artifact.get(key):
                paths.append((artifact[key], key == "path" and self.profile == "process"))
        return paths

    def probe(self, session: Any) -> None:
        """Run the minimum post-build lifecycle probe."""
        session.start()

    def prompt_context(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Return safe runtime metadata for find/dynamic/grade prompts."""
        self.validate(manifest)
        runtime = manifest["runtime"]
        return {
            "profile": self.profile,
            "source_root": runtime.get("source_root"),
            "artifact": runtime.get("artifact", {}),
            "lifecycle": {
                key: runtime[key]
                for key in (
                    "start",
                    "probe",
                    "ready",
                    "exec",
                    "reset",
                    "replay",
                    "collect",
                    "stop",
                )
                if key in runtime
            },
            "endpoint": runtime.get("endpoint"),
            "capabilities": runtime.get("capabilities", []),
            "detection": manifest.get("detection", {}),
            "workflow": manifest.get("workflow", {}),
            "resources": manifest.get("resources", {}),
            "instrumentation": manifest.get(
                "instrumentation", {"default": "auto", "providers": []}
            ),
        }
