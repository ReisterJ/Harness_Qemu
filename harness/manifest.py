# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Target manifest schema and validation.

The manifest describes how a target is built and interacted with.  It is
intentionally about runtime capabilities (process, service, QEMU), not the
source language.  Existing targets may omit it and continue to use the legacy
``config.yaml`` loader; newly generated targets must provide one.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


MANIFEST_FILENAME = "target-manifest.yaml"
MANIFEST_SCHEMA_VERSION = 1
RUNTIME_PROFILES = frozenset({"process", "service", "qemu", "custom"})


class ManifestError(ValueError):
    """A target manifest is missing or violates the runtime contract."""


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{path} must be a YAML mapping")
    return value


def _string(value: Any, path: str, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{path} must be a non-empty string")
    return value.strip()


def _absolute_path(value: Any, path: str) -> str:
    result = _string(value, path)
    assert result is not None
    if not result.startswith("/") or "\x00" in result:
        raise ManifestError(f"{path} must be an absolute container path")
    return result


def _command(value: Any, path: str, *, required: bool = True) -> str | None:
    result = _string(value, path, required=required)
    if result is not None and ("\x00" in result or "\n" in result):
        raise ManifestError(f"{path} must be a single-line command")
    return result


def validate_manifest(
    manifest: dict[str, Any],
    *,
    require_identity: bool = False,
) -> dict[str, Any]:
    """Validate and return a manifest mapping.

    This checks the host/runtime boundary, not whether the commands are
    semantically correct.  The latter is covered by the post-build contract
    probe in the selected runtime adapter.
    """
    _mapping(manifest, "manifest")
    version = manifest.get("schema_version")
    if version != MANIFEST_SCHEMA_VERSION:
        raise ManifestError(
            f"schema_version must be {MANIFEST_SCHEMA_VERSION}, got {version!r}"
        )

    identity = _mapping(manifest.get("identity", {}), "identity")
    if require_identity:
        for key in ("name", "repository", "commit"):
            _string(identity.get(key), f"identity.{key}")

    build = _mapping(manifest.get("build", {}), "build")
    if "build_steps" in build and not isinstance(build["build_steps"], list):
        raise ManifestError("build.build_steps must be a list")
    if "generated_files" in build and not isinstance(build["generated_files"], list):
        raise ManifestError("build.generated_files must be a list")
    if "agent_prebuilt" in build and not isinstance(build["agent_prebuilt"], bool):
        raise ManifestError("build.agent_prebuilt must be a boolean")

    runtime = _mapping(manifest.get("runtime"), "runtime")
    profile = _string(runtime.get("profile"), "runtime.profile")
    assert profile is not None
    if profile not in RUNTIME_PROFILES:
        raise ManifestError(
            f"runtime.profile must be one of {sorted(RUNTIME_PROFILES)}, got {profile!r}"
        )

    source_root = runtime.get("source_root")
    if source_root is not None:
        _absolute_path(source_root, "runtime.source_root")

    artifact = runtime.get("artifact")
    if artifact is not None:
        artifact = _mapping(artifact, "runtime.artifact")
        _string(artifact.get("kind"), "runtime.artifact.kind")
        if artifact.get("path") is not None:
            _absolute_path(artifact["path"], "runtime.artifact.path")
        if artifact.get("kernel") is not None:
            _absolute_path(artifact["kernel"], "runtime.artifact.kernel")
        if artifact.get("rootfs") is not None:
            _absolute_path(artifact["rootfs"], "runtime.artifact.rootfs")

    start = _mapping(runtime.get("start", {}), "runtime.start")
    _command(start.get("command"), "runtime.start.command", required=profile != "custom")
    for section in ("probe", "ready", "reset", "stop", "exec", "replay", "collect"):
        value = runtime.get(section)
        if value is None:
            continue
        if isinstance(value, dict):
            if "command" in value:
                _command(value["command"], f"runtime.{section}.command")
            else:
                if "path" in value:
                    _absolute_path(value["path"], f"runtime.{section}.path")
                if "signal" in value:
                    _string(value["signal"], f"runtime.{section}.signal")
                    if section == "ready" and "path" not in value:
                        raise ManifestError(
                            "runtime.ready.signal requires runtime.ready.path"
                        )
                if "port" in value:
                    port = value["port"]
                    if not isinstance(port, int) or not 1 <= port <= 65535:
                        raise ManifestError(
                            f"runtime.{section}.port must be an integer in 1..65535"
                        )
            if section in {"ready", "collect"} and not any(
                key in value for key in ("command", "signal", "path", "port")
            ):
                # These sections may use a declarative signal/path instead of
                # a shell command, especially for QEMU serial output.
                raise ManifestError(
                    f"runtime.{section} must define command, signal, path, or port"
                )
        else:
            _command(value, f"runtime.{section}")

    endpoint = runtime.get("endpoint")
    if endpoint is not None:
        endpoint = _mapping(endpoint, "runtime.endpoint")
        _string(endpoint.get("scheme"), "runtime.endpoint.scheme")
        _string(endpoint.get("host"), "runtime.endpoint.host")
        port = endpoint.get("port")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ManifestError("runtime.endpoint.port must be an integer in 1..65535")

    detection = _mapping(manifest.get("detection", {}), "detection")
    detectors = detection.get("detectors", [])
    if not isinstance(detectors, list) or not all(
        isinstance(x, str) and x.strip() for x in detectors
    ):
        raise ManifestError("detection.detectors must be a list of non-empty strings")

    capabilities = runtime.get("capabilities", [])
    if not isinstance(capabilities, list) or not all(isinstance(x, str) for x in capabilities):
        raise ManifestError("runtime.capabilities must be a list of strings")

    ready_timeout = runtime.get("ready_timeout_s")
    if ready_timeout is not None and (
        not isinstance(ready_timeout, (int, float)) or ready_timeout <= 0
    ):
        raise ManifestError("runtime.ready_timeout_s must be positive")

    workflow = _mapping(manifest.get("workflow"), "workflow")
    for key in ("static_analysis", "dynamic_validation", "grade"):
        _string(workflow.get(key), f"workflow.{key}")

    resources = _mapping(manifest.get("resources", {}), "resources")
    devices = resources.get("devices", [])
    if not isinstance(devices, list) or not all(isinstance(x, str) for x in devices):
        raise ManifestError("resources.devices must be a list of strings")
    for key in ("memory", "shm_size"):
        if key in resources:
            _string(resources[key], f"resources.{key}")

    instrumentation = _mapping(
        manifest.get("instrumentation", {}), "instrumentation"
    )
    providers = instrumentation.get("providers", [])
    if not isinstance(providers, list) or not all(
        isinstance(x, str) and x.strip() for x in providers
    ):
        raise ManifestError(
            "instrumentation.providers must be a list of non-empty strings"
        )
    default = instrumentation.get("default", "auto")
    # PyYAML follows YAML 1.1 boolean spellings, so an unquoted `off` is
    # loaded as False. Accept that common authoring form as the explicit
    # disabled mode while keeping the normalized contract string-based.
    if default is False:
        default = "off"
    if not isinstance(default, str) or not default.strip():
        raise ManifestError("instrumentation.default must be a non-empty string")
    allowed_defaults = {"off", "auto", *[str(x) for x in providers]}
    if default not in allowed_defaults:
        raise ManifestError(
            "instrumentation.default must be off, auto, or one of instrumentation.providers"
        )
    # Keep the returned manifest canonical as well as accepting YAML 1.1's
    # boolean spelling. TargetConfig and prompt consumers should not need to
    # know whether the author quoted `off`.
    instrumentation["default"] = default
    for key in ("max_events", "max_output_bytes"):
        if key in instrumentation and (
            not isinstance(instrumentation[key], int) or instrumentation[key] <= 0
        ):
            raise ManifestError(f"instrumentation.{key} must be a positive integer")

    return manifest


def load_manifest(path: str | Path, *, require_identity: bool = False) -> dict[str, Any]:
    path = Path(path)
    try:
        value = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ManifestError(f"{path} must contain a YAML mapping")
    return validate_manifest(value, require_identity=require_identity)


def legacy_manifest(config: dict[str, Any], *, name: str) -> dict[str, Any]:
    """Project a legacy config into the process-oriented manifest shape."""
    detector = config.get("detector", "asan")
    profile = "qemu" if detector in {"kasan", "qemu-asan", "lms"} else "process"
    artifact = {"kind": "executable", "path": config.get("binary_path", "/bin/true")}
    return validate_manifest(
        {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "identity": {
                "name": name,
                "repository": config.get("github_url", ""),
                "commit": config.get("commit", ""),
            },
            "build": {"build_steps": []},
            "runtime": {
                "profile": profile,
                "source_root": config.get("source_root", "/work"),
                "artifact": artifact,
                "start": {"command": config.get("binary_path", "/bin/true")},
                "capabilities": ["stdout", "stderr", "exit_code"],
            },
            "detection": {"detectors": [detector]},
            "workflow": {
                "static_analysis": "source",
                "dynamic_validation": profile,
                "grade": f"{profile}_replay",
            },
            "resources": {"devices": config.get("devices", [])},
        },
        require_identity=True,
    )
