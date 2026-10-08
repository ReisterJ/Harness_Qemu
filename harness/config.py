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

from .docker_params import (
    DOCKER_PARAMS_FILENAME,
    DockerBuildParams,
    DockerParams,
    DockerParamsError,
    DockerRunParams,
    load_docker_params,
)
from .manifest import MANIFEST_FILENAME, ManifestError, load_manifest


def _load_attack_surface(value: Any) -> str | None:
    """Normalize YAML's convenient string/list forms for prompt consumers.

    Hand-authored targets commonly describe an attack surface as a YAML list,
    while the prompt isolation helpers intentionally accept text.  Convert
    the list at the configuration boundary so every workflow phase sees the
    same safe, deterministic representation.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, list):
        if not all(isinstance(item, str) and item.strip() for item in value):
            raise ValueError("attack_surface must be a string or list of non-empty strings")
        return "\n".join(f"- {item.strip()}" for item in value)
    raise ValueError("attack_surface must be a string or list of non-empty strings")


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
    detector: str = "asan"            # "asan" (userspace), "logic" (semantic oracle), "kasan" (Linux kernel), "lms" (LiteOS-M kernel), or "qemu-asan" (userspace ASAN inside a QEMU guest)
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
    instrumentation: dict[str, Any] | None = field(default=None, repr=False)
    symbolic_execution: dict[str, Any] | None = field(default=None, repr=False)
    manifest: dict[str, Any] | None = field(default=None, repr=False)
    docker_params: DockerParams | None = field(default=None, repr=False)

    @classmethod
    def load(
        cls,
        target_dir: str | Path,
        *,
        docker_params_path: str | Path | None = None,
    ) -> TargetConfig:
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

        manifest_runtime = (manifest or {}).get("runtime", {})
        manifest_detection = (manifest or {}).get("detection", {})
        manifest_resources = (manifest or {}).get("resources", {})
        manifest_detectors = manifest_detection.get("detectors", [])
        manifest_detector = (
            manifest_detectors[0]
            if isinstance(manifest_detectors, list) and manifest_detectors
            else None
        )
        manifest_artifact = manifest_runtime.get("artifact") or {}
        manifest_agent_prebuilt = (manifest.get("build", {}) if manifest else {}).get(
            "agent_prebuilt", False
        )

        params_file = (
            Path(docker_params_path).resolve()
            if docker_params_path is not None
            else target_dir / DOCKER_PARAMS_FILENAME
        )
        docker_params = None
        if docker_params_path is not None and not params_file.exists():
            raise FileNotFoundError(f"Docker parameter file not found: {params_file}")
        if params_file.exists():
            try:
                docker_params = load_docker_params(params_file)
            except DockerParamsError as exc:
                raise ValueError(f"invalid {params_file.name}: {exc}") from exc

        instrumentation = (
            (manifest or {}).get("instrumentation")
            or cfg.get("instrumentation")
            or {"default": "auto", "providers": []}
        )
        if isinstance(instrumentation, dict):
            # Keep legacy/config.yaml targets consistent with validated
            # manifests. PyYAML loads an unquoted YAML 1.1 `off` as False.
            instrumentation = dict(instrumentation)
            if instrumentation.get("default") is False:
                instrumentation["default"] = "off"

        symbolic_execution = cfg.get(
            "symbolic_execution", {"default": "off", "providers": ["klee"]}
        )
        if symbolic_execution is False:
            symbolic_execution = {"default": "off", "providers": []}
        if not isinstance(symbolic_execution, dict):
            raise ValueError("symbolic_execution must be a mapping")
        symbolic_execution = dict(symbolic_execution)
        if symbolic_execution.get("default") is False:
            symbolic_execution["default"] = "off"
        symcc_config = symbolic_execution.get("symcc")
        if symcc_config is not None:
            if not isinstance(symcc_config, dict):
                raise ValueError("symbolic_execution.symcc must be a mapping")
            symcc_config = dict(symcc_config)
            symbolic_execution["symcc"] = symcc_config
            symcc_binary = symcc_config.get("binary_path")
            if symcc_binary is not None and (
                not isinstance(symcc_binary, str)
                or not symcc_binary.startswith("/")
                or "\x00" in symcc_binary
            ):
                raise ValueError(
                    "symbolic_execution.symcc.binary_path must be an absolute container path"
                )
            symcc_args = symcc_config.get("program_args")
            if symcc_args is not None and (
                not isinstance(symcc_args, list)
                or not symcc_args
                or len(symcc_args) > 64
                or not all(isinstance(arg, str) and "\x00" not in arg for arg in symcc_args)
                or any(len(arg) > 4096 for arg in symcc_args)
                or sum(arg.count("{input_file}") for arg in symcc_args) != 1
                or any("{" in arg.replace("{input_file}", "") for arg in symcc_args)
            ):
                raise ValueError(
                    "symbolic_execution.symcc.program_args must be a non-empty list "
                    "of at most 64 strings containing {input_file} exactly once"
                )

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
            binary_path=(
                cfg.get("binary_path")
                or manifest_artifact.get("path")
                or "/bin/true"
            ),
            source_root=(
                cfg.get("source_root")
                or manifest_runtime.get("source_root")
                or "/work"
            ),
            focus_areas=cfg.get("focus_areas") or [],
            known_bugs=cfg.get("known_bugs") or [],
            attack_surface=_load_attack_surface(cfg.get("attack_surface")),
            detector=cfg.get("detector") or manifest_detector or "asan",
            devices=cfg.get("devices") or manifest_resources.get("devices") or [],
            grade_reference=cfg.get("grade_reference"),
            agent_prebuilt=bool(cfg.get("agent_prebuilt", manifest_agent_prebuilt)),
            agent_network=cfg.get("agent_network"),
            build_command=cfg.get("build_command"),
            test_command=cfg.get("test_command"),
            build_timeout_s=cfg.get("build_timeout_s", 1800),
            shm_size=cfg.get("shm_size") or manifest_resources.get("shm_size"),
            memory_limit=cfg.get("memory_limit") or manifest_resources.get(
                "memory", "4g"
            ),
            reattack_harness=cfg.get("reattack_harness"),
            instrumentation=instrumentation,
            symbolic_execution=symbolic_execution,
            manifest=manifest,
            docker_params=docker_params,
        )

    @property
    def runtime_image_tag(self) -> str:
        """Image used for target containers.

        A normal target uses the image built from its Dockerfile.  A target
        with ``image.mode: prebuilt`` can point the runtime at a supplied
        QEMU/firmware image while retaining the same manifest and pipeline
        metadata.
        """
        if self.docker_params and self.docker_params.image_mode == "prebuilt":
            assert self.docker_params.image_reference is not None
            return self.docker_params.image_reference
        return self.image_tag

    def docker_run_params(self, phase: str) -> DockerRunParams:
        return self.docker_params.for_phase(phase) if self.docker_params else DockerRunParams()

    @property
    def symcc_runtime(self) -> dict[str, Any] | None:
        """Prebuilt SymCC executable contract, if the target supplies one."""
        config = (self.symbolic_execution or {}).get("symcc")
        return dict(config) if isinstance(config, dict) else None

    def docker_build_params(self) -> DockerBuildParams:
        return self.docker_params.build if self.docker_params else DockerBuildParams()

    @property
    def runtime_image_pull(self) -> bool:
        return bool(self.docker_params and self.docker_params.image_pull)

    def runtime_context(self) -> dict[str, Any]:
        """Return the validated runtime view used by agent prompts.

        Existing hand-authored targets do not have a manifest yet. Their
        legacy fields are projected into a conservative view so the prompt
        migration does not change their execution behavior.
        """
        if self.manifest is not None:
            from .runtimes import adapter_for

            context = adapter_for(self.manifest["runtime"]["profile"]).prompt_context(
                self.manifest
            )
            context["instrumentation"] = self.instrumentation or {
                "default": "auto", "providers": []
            }
            return context
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
            "instrumentation": self.instrumentation or {
                "default": "auto", "providers": []
            },
        }
