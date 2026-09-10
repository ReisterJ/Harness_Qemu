# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""User-supplied Docker build and run parameters.

The target manifest describes how an artifact behaves *inside* a container.
This module describes the host-side Docker contract needed to start that
container: devices, networking, mounts, privileges, resource limits, and an
optional pre-built image.  Keeping the two contracts separate lets a target
use the same manifest with different host hardware.

The file is deliberately structured rather than a free-form Docker command.
That keeps command construction auditable and makes it possible to validate a
configuration before a long build or QEMU boot starts.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


DOCKER_PARAMS_FILENAME = "docker-params.yaml"
DOCKER_PARAMS_SCHEMA_VERSION = 1


class DockerParamsError(ValueError):
    """A Docker parameter file is malformed or unsafe to apply."""


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise DockerParamsError(f"{path} must be a YAML mapping")
    return value


def _string(value: Any, path: str, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise DockerParamsError(f"{path} must be a non-empty string")
        return None
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise DockerParamsError(f"{path} must be a non-empty string")
    return value.strip()


def _bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise DockerParamsError(f"{path} must be a boolean")
    return value


def _strings(value: Any, path: str) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise DockerParamsError(f"{path} must be a list of non-empty strings")
    return tuple(x.strip() for x in value)


def _command(value: Any, path: str) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            result = tuple(shlex.split(value))
        except ValueError as exc:
            raise DockerParamsError(f"{path} is not a valid command: {exc}") from exc
    elif isinstance(value, list) and all(isinstance(x, str) and x for x in value):
        result = tuple(value)
    else:
        raise DockerParamsError(f"{path} must be a command string or list of strings")
    if not result or any("\x00" in x for x in result):
        raise DockerParamsError(f"{path} must contain at least one safe argument")
    return result


@dataclass(frozen=True)
class DockerMount:
    source: str
    target: str
    read_only: bool = True


@dataclass(frozen=True)
class DockerRunParams:
    """Optional values for one ``docker run`` invocation.

    ``None`` means "inherit the harness default".  Tuple fields are also
    optional so a phase can distinguish an omitted list from an intentionally
    empty list while merging with the common ``run`` section.
    """

    network: str | None = None
    memory: str | None = None
    shm_size: str | None = None
    cpus: str | None = None
    runtime: str | None = None
    privileged: bool | None = None
    cap_add: tuple[str, ...] | None = None
    cap_drop: tuple[str, ...] | None = None
    security_opt: tuple[str, ...] | None = None
    env: tuple[tuple[str, str], ...] | None = None
    mounts: tuple[DockerMount, ...] | None = None
    devices: tuple[str, ...] | None = None
    command: tuple[str, ...] | None = None
    entrypoint: tuple[str, ...] | None = None
    workdir: str | None = None
    user: str | None = None
    ipc: str | None = None
    pid: str | None = None

    def merge(self, override: "DockerRunParams") -> "DockerRunParams":
        """Return this configuration with non-None override values applied."""
        values = {}
        for field in self.__dataclass_fields__:
            value = getattr(override, field)
            values[field] = value if value is not None else getattr(self, field)
        return DockerRunParams(**values)

    def env_dict(self) -> dict[str, str]:
        return dict(self.env or ())


@dataclass(frozen=True)
class DockerBuildParams:
    network: str | None = None
    platform: str | None = None
    pull: bool | None = None
    build_args: tuple[tuple[str, str], ...] | None = None
    target: str | None = None

    def build_args_dict(self) -> dict[str, str]:
        return dict(self.build_args or ())


@dataclass(frozen=True)
class DockerParams:
    build: DockerBuildParams = DockerBuildParams()
    run: DockerRunParams = DockerRunParams()
    phases: tuple[tuple[str, DockerRunParams], ...] = ()
    image_mode: str = "generated"
    image_reference: str | None = None
    image_pull: bool = False
    path: str | None = None

    def for_phase(self, phase: str) -> DockerRunParams:
        """Return common run settings merged with a phase-specific override."""
        phase_params = dict(self.phases).get(phase)
        return self.run.merge(phase_params) if phase_params else self.run

    def phase_names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.phases)


def _parse_env(value: Any, path: str) -> tuple[tuple[str, str], ...] | None:
    if value is None:
        return None
    mapping = _mapping(value, path)
    result: list[tuple[str, str]] = []
    for key, item in mapping.items():
        if not isinstance(key, str) or not key or "=" in key or "\x00" in key:
            raise DockerParamsError(f"{path} keys must be valid environment names")
        if not isinstance(item, (str, int, float, bool)):
            raise DockerParamsError(f"{path}.{key} must be a scalar")
        result.append((key, str(item)))
    return tuple(result)


def _parse_mounts(value: Any, path: str, base_dir: Path) -> tuple[DockerMount, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise DockerParamsError(f"{path} must be a list")
    result: list[DockerMount] = []
    for index, raw in enumerate(value):
        item = _mapping(raw, f"{path}[{index}]")
        source = _string(item.get("source"), f"{path}[{index}].source", required=True)
        target = _string(item.get("target"), f"{path}[{index}].target", required=True)
        assert source is not None and target is not None
        if not target.startswith("/") or "\x00" in target:
            raise DockerParamsError(f"{path}[{index}].target must be an absolute container path")
        source_path = Path(source)
        if not source_path.is_absolute():
            source = str((base_dir / source_path).resolve())
        read_only = item.get("read_only", True)
        if not isinstance(read_only, bool):
            raise DockerParamsError(f"{path}[{index}].read_only must be a boolean")
        result.append(DockerMount(source=source, target=target, read_only=read_only))
    return tuple(result)


def _parse_run(value: Any, path: str, base_dir: Path) -> DockerRunParams:
    item = _mapping(value, path)
    kwargs: dict[str, Any] = {}
    for key in ("network", "memory", "shm_size", "cpus", "runtime", "workdir", "user", "ipc", "pid"):
        kwargs[key] = _string(item.get(key), f"{path}.{key}")
    for key in ("cap_add", "cap_drop", "security_opt", "devices"):
        kwargs[key] = _strings(item.get(key), f"{path}.{key}")
    if "privileged" in item:
        kwargs["privileged"] = _bool(item["privileged"], f"{path}.privileged")
    kwargs["env"] = _parse_env(item.get("env"), f"{path}.env")
    kwargs["mounts"] = _parse_mounts(item.get("mounts"), f"{path}.mounts", base_dir)
    kwargs["command"] = _command(item.get("command"), f"{path}.command")
    kwargs["entrypoint"] = _command(item.get("entrypoint"), f"{path}.entrypoint")
    if kwargs["entrypoint"] is not None and len(kwargs["entrypoint"]) != 1:
        raise DockerParamsError(
            f"{path}.entrypoint must contain one executable; pass arguments in command"
        )
    return DockerRunParams(**kwargs)


def _parse_build(value: Any, path: str) -> DockerBuildParams:
    item = _mapping(value, path)
    args = item.get("args")
    parsed_args: tuple[tuple[str, str], ...] | None = None
    if args is not None:
        raw = _mapping(args, f"{path}.args")
        pairs: list[tuple[str, str]] = []
        for key, value in raw.items():
            if not isinstance(key, str) or not key or "=" in key:
                raise DockerParamsError(f"{path}.args keys must be non-empty names")
            if not isinstance(value, (str, int, float, bool)):
                raise DockerParamsError(f"{path}.args.{key} must be a scalar")
            pairs.append((key, str(value)))
        parsed_args = tuple(pairs)
    pull = item.get("pull")
    if pull is not None:
        pull = _bool(pull, f"{path}.pull")
    return DockerBuildParams(
        network=_string(item.get("network"), f"{path}.network"),
        platform=_string(item.get("platform"), f"{path}.platform"),
        pull=pull,
        build_args=parsed_args,
        target=_string(item.get("target"), f"{path}.target"),
    )


def parse_docker_params(value: Any, *, base_dir: str | Path = ".", path: str = "docker-params.yaml") -> DockerParams:
    """Validate an already-loaded YAML mapping."""
    root = _mapping(value, path)
    version = root.get("schema_version", DOCKER_PARAMS_SCHEMA_VERSION)
    if version != DOCKER_PARAMS_SCHEMA_VERSION:
        raise DockerParamsError(
            f"{path}.schema_version must be {DOCKER_PARAMS_SCHEMA_VERSION}, got {version!r}"
        )
    base = Path(base_dir).resolve()
    image = _mapping(root.get("image"), f"{path}.image")
    mode = image.get("mode", "generated")
    if mode not in {"generated", "prebuilt"}:
        raise DockerParamsError(f"{path}.image.mode must be 'generated' or 'prebuilt'")
    reference = _string(image.get("reference"), f"{path}.image.reference")
    if mode == "prebuilt" and reference is None:
        raise DockerParamsError(f"{path}.image.reference is required for prebuilt mode")
    pull = image.get("pull", False)
    if not isinstance(pull, bool):
        raise DockerParamsError(f"{path}.image.pull must be a boolean")

    phases_raw = _mapping(root.get("phases"), f"{path}.phases")
    phases = tuple(
        (name, _parse_run(raw, f"{path}.phases.{name}", base))
        for name, raw in phases_raw.items()
    )
    for name, _ in phases:
        if not isinstance(name, str) or not name.strip():
            raise DockerParamsError(f"{path}.phases keys must be non-empty strings")
    return DockerParams(
        build=_parse_build(root.get("build"), f"{path}.build"),
        run=_parse_run(root.get("run"), f"{path}.run", base),
        phases=phases,
        image_mode=mode,
        image_reference=reference,
        image_pull=pull,
        path=str(Path(path).resolve()) if path else None,
    )


def load_docker_params(path: str | Path) -> DockerParams:
    """Load and validate a user-provided parameter file."""
    file_path = Path(path).resolve()
    try:
        value = yaml.safe_load(file_path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise DockerParamsError(f"cannot read {file_path}: {exc}") from exc
    return parse_docker_params(value, base_dir=file_path.parent, path=str(file_path))
