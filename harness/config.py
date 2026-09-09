# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Target configuration loader.

A target is a directory under targets/ containing:
  - Dockerfile   (builds ASAN-instrumented binary)
  - config.yaml  (metadata the pipeline needs)
  - any other build-context files the Dockerfile COPYs

Adding a new target = new dir, zero pipeline code changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .manifest import MANIFEST_FILENAME, ManifestError, load_manifest


@dataclass(frozen=True)
class TargetConfig:
    name: str
    dockerfile_dir: str   # build context dir (the target dir itself)
    image_tag: str
    github_url: str
    commit: str
    binary_path: str      # path inside the built container
    source_root: str      # path inside the built container
    focus_areas: list[str] = field(default_factory=list)
    known_bugs: list[str] = field(default_factory=list)
    attack_surface: str | None = None
    detector: str = "asan"            # "asan" (userspace), "kasan" (Linux kernel), "lms" (LiteOS-M kernel), or "qemu-asan" (userspace ASAN inside a QEMU guest)
    devices: list[str] = field(default_factory=list)  # --device passthrough (e.g. /dev/kvm)
    grade_reference: str | None = None  # grade-only ground truth (official crash signature); never shown to find
    agent_prebuilt: bool = False      # image already carries the agent CLI (no agent_image.ensure layering)
    agent_network: str | None = None  # agent container network override (e.g. "host" when bridge can't reach the API)
    build_command: str | None = None  # rebuild in-container after applying a patch (T0)
    test_command: str | None = None   # regression suite for T2; None → T2 skipped
    build_timeout_s: int = 1800
    shm_size: str | None = None       # docker --shm-size
    memory_limit: str = "4g"          # docker --memory
    reattack_harness: str | None = None  # in-image script that runs every /poc/* and exits 1 on crash
    manifest: dict[str, Any] | None = field(default=None, repr=False)

    @classmethod
    def load(cls, target_dir: str | Path) -> TargetConfig:
        target_dir = Path(target_dir).resolve()
        config_path = target_dir / "config.yaml"
        if not config_path.exists():
            raise FileNotFoundError(f"No config.yaml in {target_dir}")

        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        manifest = None
        manifest_path = target_dir / MANIFEST_FILENAME
        if manifest_path.exists():
            try:
                manifest = load_manifest(manifest_path, require_identity=False)
            except ManifestError as exc:
                raise ValueError(f"invalid {MANIFEST_FILENAME}: {exc}") from exc

        if cfg.get("kind") == "dnr":
            raise ValueError(
                f"target '{target_dir.name}' is a detection & response target "
                "(kind: dnr), not a vuln-pipeline build target — see "
                f"targets/{target_dir.name}/README.md for how to run it"
            )

        return cls(
            name=target_dir.name,
            dockerfile_dir=str(target_dir),
            image_tag=cfg["image_tag"],
            github_url=cfg["github_url"],
            commit=cfg["commit"],
            binary_path=cfg["binary_path"],
            source_root=cfg["source_root"],
            focus_areas=cfg.get("focus_areas") or [],
            known_bugs=cfg.get("known_bugs") or [],
            attack_surface=cfg.get("attack_surface"),
            detector=cfg.get("detector", "asan"),
            devices=cfg.get("devices") or [],
            grade_reference=cfg.get("grade_reference"),
            agent_prebuilt=bool(cfg.get("agent_prebuilt", False)),
            agent_network=cfg.get("agent_network"),
            build_command=cfg.get("build_command"),
            test_command=cfg.get("test_command"),
            build_timeout_s=cfg.get("build_timeout_s", 1800),
            shm_size=cfg.get("shm_size"),
            memory_limit=cfg.get("memory_limit", "4g"),
            reattack_harness=cfg.get("reattack_harness"),
            manifest=manifest,
        )

    def runtime_context(self) -> dict[str, Any]:
        """Return the validated runtime view used by agent prompts.

        Existing hand-authored targets do not have a manifest yet. Their
        legacy fields are projected into a conservative view so the prompt
        migration does not change their execution behavior.
        """
        if self.manifest is not None:
            from .runtimes import adapter_for

            return adapter_for(self.manifest["runtime"]["profile"]).prompt_context(
                self.manifest
            )
        return {
            "profile": "legacy",
            "source_root": self.source_root,
            "artifact": {"kind": "executable", "path": self.binary_path},
            "start": {"command": self.binary_path},
            "capabilities": ["stdout", "stderr", "exit_code"],
            "detection": {"detectors": [self.detector]},
            "workflow": {
                "static_analysis": "source",
                "dynamic_validation": self.detector,
                "grade": f"{self.detector}_replay",
            },
        }
