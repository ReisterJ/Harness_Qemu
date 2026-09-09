# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Repository-to-target build workflow.

This module deliberately keeps the trust boundary simple:

* git checkout and Docker build run on the host orchestrator;
* the planning/repair agent runs in the existing agent container, with the
  source and current build context mounted read-only;
* only files written below the agent's ``/work/out`` are copied back;
* a target is published only after Docker build and interface checks pass.

The generated target is compatible with the existing ``TargetConfig`` and
``run`` command.  No find, dynamic-validation, or grade logic belongs here.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import yaml

from . import agent_image, docker_ops, sandbox
from .agent import AgentResult, run_agent
from .classification import (
    CLASSIFICATION_FILENAME,
    ClassificationError,
    load_classification,
)
from .config import TargetConfig
from .manifest import MANIFEST_FILENAME, ManifestError, load_manifest
from .prompts.build_prompt import (
    BUILD_AGENT_SYSTEM_PROMPT,
    CLASSIFIER_AGENT_SYSTEM_PROMPT,
    build_classification_prompt,
    build_plan_prompt,
)
from .runtimes import adapter_for
from .runtimes.base import RuntimeContractError
from .runtimes.session import RuntimeSession


BUILD_MAX_TURNS = 180
DEFAULT_BUILD_RETRIES = 2
DEFAULT_BUILD_TIMEOUT_S = 1800
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_COPY_SOURCE_RE = re.compile(r"(?im)^\s*(?:COPY|ADD)\s+source(?:[/\s])")


class BuildError(RuntimeError):
    """A user-actionable failure in the target build workflow."""


@dataclass(frozen=True)
class SourceLock:
    repo: str
    branch: str | None
    ref: str | None
    commit: str
    snapshot_sha256: str

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


@dataclass(frozen=True)
class BuildOptions:
    name: str
    repo: str
    branch: str | None
    ref: str | None
    kind: str
    model: str
    targets_dir: Path
    builds_dir: Path
    max_turns: int = BUILD_MAX_TURNS
    retries: int = DEFAULT_BUILD_RETRIES
    timeout_s: int = DEFAULT_BUILD_TIMEOUT_S
    force: bool = False
    git_timeout_s: int = 900


@dataclass(frozen=True)
class InspectOptions:
    name: str
    repo: str
    branch: str | None
    ref: str | None
    model: str
    builds_dir: Path
    max_turns: int = BUILD_MAX_TURNS
    git_timeout_s: int = 900


@dataclass(frozen=True)
class ClassificationResult:
    name: str
    job_id: str
    job_dir: Path
    source_lock: SourceLock
    classification: dict


@dataclass(frozen=True)
class BuildResult:
    name: str
    job_id: str
    job_dir: Path
    target_dir: Path
    image_tag: str
    agent_image_tag: str | None
    source_lock: SourceLock
    build_attempts: int


def validate_target_name(name: str) -> None:
    if not _NAME_RE.fullmatch(name):
        raise BuildError(
            f"invalid target name {name!r}; use letters, digits, '-' or '_' "
            "and start with a letter or digit"
        )


def image_tag_for(name: str, commit: str) -> str:
    """Return the immutable image tag recorded in generated config.yaml."""
    validate_target_name(name)
    return f"vuln-pipeline-{name}:{commit[:12]}"


def _git(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int,
    what: str,
) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise BuildError(f"{what} timed out after {timeout}s") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip().replace("\n", " ")
        raise BuildError(f"{what} failed: {detail[:500]}")
    return result.stdout.strip()


def _remove_git_metadata(root: Path) -> None:
    git_dir = root / ".git"
    if git_dir.is_dir():
        shutil.rmtree(git_dir)
    elif git_dir.exists():
        git_dir.unlink()


def materialize_source(
    repo: str,
    destination: Path,
    *,
    branch: str | None = None,
    ref: str | None = None,
    timeout: int = 900,
) -> SourceLock:
    """Clone the requested revision and return its immutable source identity.

    With no ``branch`` or ``ref``, ``git clone`` follows the repository's
    default branch, so each invocation observes the current latest commit.
    ``ref`` is fetched explicitly and therefore supports tags and commit IDs.
    The checkout's ``.git`` metadata is removed before hashing and handing the
    snapshot to Docker.
    """
    if branch and ref:
        raise BuildError("--branch and --ref are mutually exclusive")
    if destination.exists():
        raise BuildError(f"source destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    if ref:
        destination.mkdir()
        _git(["init", "-q"], cwd=destination, timeout=timeout, what="git init")
        _git(["remote", "add", "origin", repo], cwd=destination,
             timeout=timeout, what="git remote add")
        _git(["fetch", "--depth", "1", "origin", ref], cwd=destination,
             timeout=timeout, what=f"fetch ref {ref}")
        _git(["checkout", "-q", "--detach", "FETCH_HEAD"], cwd=destination,
             timeout=timeout, what="checkout fetched ref")
        _git(["submodule", "update", "--init", "--recursive", "--depth", "1"],
             cwd=destination, timeout=timeout, what="initialize submodules")
    else:
        args = ["clone", "--depth", "1", "--recurse-submodules", "--shallow-submodules"]
        if branch:
            args += ["--branch", branch]
        args += [repo, str(destination)]
        _git(args, timeout=timeout, what="clone repository")

    commit = _git(["rev-parse", "HEAD"], cwd=destination, timeout=timeout,
                  what="resolve checked-out commit")
    checked_out_branch = branch
    if checked_out_branch is None and not ref:
        checked_out_branch = _git(["branch", "--show-current"], cwd=destination,
                                  timeout=timeout, what="resolve default branch") or None
    _remove_git_metadata(destination)
    snapshot_sha256 = tree_sha256(destination)
    return SourceLock(
        repo=repo,
        branch=checked_out_branch,
        ref=ref,
        commit=commit,
        snapshot_sha256=snapshot_sha256,
    )


def tree_sha256(root: Path) -> str:
    """Hash a source tree deterministically, including paths and file modes."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        stat = path.lstat()
        digest.update(b"path\0" + relative + b"\0")
        if path.is_symlink():
            digest.update(b"link\0" + os.readlink(path).encode() + b"\0")
        elif path.is_file():
            digest.update(f"file\0{stat.st_mode & 0o7777:o}\0".encode())
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        elif path.is_dir():
            digest.update(b"dir\0")
        else:
            raise BuildError(f"unsupported file type in source snapshot: {path}")
    return digest.hexdigest()


def _yaml_write(path: Path, value: dict) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False, allow_unicode=True))


def _status(path: Path, status: str, **extra: object) -> None:
    payload = {"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}
    payload.update(extra)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def _safe_output_path(raw: str) -> Path:
    # Agent output comes from a container, so normalize POSIX paths regardless
    # of the host platform and reject traversal/absolute paths.
    value = PurePosixPath(raw)
    if value.is_absolute() or ".." in value.parts or not value.parts:
        raise BuildError(f"agent wrote an unsafe output path: {raw!r}")
    return Path(*value.parts)


def _collect_agent_outputs(container: str) -> dict[Path, bytes]:
    rc, stdout, stderr = docker_ops.exec_sh(
        container, "find /work/out -type f -printf '%P\\n'"
    )
    if rc:
        raise BuildError(f"build agent output collection failed: {stderr.strip()[:500]}")
    outputs: dict[Path, bytes] = {}
    for raw in stdout.splitlines():
        relative = _safe_output_path(raw.strip())
        content = docker_ops.read_file(container, f"/work/out/{relative.as_posix()}")
        if not content:
            raise BuildError(f"build agent produced an empty or unreadable file: {relative}")
        if len(content) > 16 * 1024 * 1024:
            raise BuildError(f"build agent output is too large: {relative}")
        outputs[relative] = content
    return outputs


async def _run_build_agent(
    *,
    name: str,
    source_dir: Path,
    context_dir: Path | None,
    auth: dict[str, str],
    model: str,
    prompt: str,
    transcript_path: Path,
    max_turns: int,
    progress_prefix: str,
    tools: list[str] | None = None,
) -> tuple[dict[Path, bytes], AgentResult]:
    """Run planner/repair agent and copy only /work/out back to the host."""
    image = agent_image.ensure_base()
    mounts = [(str(source_dir), "/src")]
    if context_dir is not None:
        mounts.append((str(context_dir), "/input"))
    container_name = f"build_{name}_{uuid.uuid4().hex[:8]}"
    # In the normal sandbox, ``None`` selects the internal egress network and
    # sandbox.proxy() injects the proxy container address.  With
    # --dangerously-no-sandbox, Docker may inject the host's loopback proxy
    # (for example 127.0.0.1:7897) into the container.  A bridge container has
    # its own loopback, so use host networking in that explicitly unsandboxed
    # mode; this keeps the existing proxy configuration unchanged and makes
    # the host's proxy reachable.
    agent_network = None if sandbox.runtime() else "host"
    with sandbox.agent_container(
        image,
        container_name,
        auth,
        mounts=mounts,
        network=agent_network,
        prebuilt=True,
    ) as container:
        docker_ops.exec_sh(container, "rm -rf /work/out && mkdir -p /work/out")
        result = await run_agent(
            prompt=prompt,
            container=container,
            max_turns=max_turns,
            model=model,
            transcript_path=str(transcript_path),
            progress_prefix=progress_prefix,
            tools=tools or ["Read", "Write", "Bash"],
            system_prompt=(
                CLASSIFIER_AGENT_SYSTEM_PROMPT
                if tools == ["Read", "Write"]
                else BUILD_AGENT_SYSTEM_PROMPT
            ),
            max_resume_attempts=5,
        )
        outputs = _collect_agent_outputs(container)
    return outputs, result


async def _run_classification(
    *,
    name: str,
    source_dir: Path,
    output_dir: Path,
    auth: dict[str, str],
    model: str,
    repo: str,
    branch: str,
    commit: str,
    kind: str,
    transcript_path: Path,
    max_turns: int,
    progress_prefix: str,
) -> dict:
    outputs, result = await _run_build_agent(
        name=name,
        source_dir=source_dir,
        context_dir=None,
        auth=auth,
        model=model,
        prompt=build_classification_prompt(
            repo=repo,
            branch=branch,
            commit=commit,
            kind=kind,
        ),
        transcript_path=transcript_path,
        max_turns=max_turns,
        progress_prefix=progress_prefix,
        tools=["Read", "Write"],
    )
    if result.error:
        raise BuildError(f"classification agent failed: {result.error}")
    expected = {Path(CLASSIFICATION_FILENAME)}
    if set(outputs) != expected:
        produced = ", ".join(str(path) for path in sorted(outputs))
        raise BuildError(
            "classification agent must produce only "
            f"{CLASSIFICATION_FILENAME}; got {produced or '(nothing)'}"
        )
    _write_agent_outputs(output_dir, outputs)
    try:
        return load_classification(output_dir / CLASSIFICATION_FILENAME)
    except ClassificationError as exc:
        raise BuildError(f"invalid {CLASSIFICATION_FILENAME}: {exc}") from exc


def _write_agent_outputs(
    context_dir: Path,
    outputs: dict[Path, bytes],
    *,
    protected_paths: set[str] | None = None,
) -> None:
    if not outputs:
        raise BuildError("build agent produced no files under /work/out")
    for relative, content in outputs.items():
        relative = _safe_output_path(relative.as_posix())
        if relative.parts[0] in {
            "source",
            "source.lock.yaml",
            "build.log",
            *(protected_paths or set()),
        }:
            raise BuildError(f"agent attempted to overwrite protected build input: {relative}")
        destination = context_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)


def _load_config(path: Path) -> dict:
    try:
        value = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise BuildError(f"cannot parse generated config.yaml: {exc}") from exc
    if not isinstance(value, dict):
        raise BuildError("generated config.yaml must contain a YAML mapping")
    return value


def _normalize_config(context_dir: Path, lock: SourceLock, name: str) -> dict:
    path = context_dir / "config.yaml"
    config = _load_config(path)
    try:
        manifest = load_manifest(context_dir / MANIFEST_FILENAME)
    except ManifestError as exc:
        raise BuildError(f"cannot normalize config without valid {MANIFEST_FILENAME}: {exc}") from exc
    profile = manifest["runtime"]["profile"]
    runtime = manifest["runtime"]
    detection = manifest.get("detection") or {}
    resources = manifest.get("resources") or {}
    detectors = detection.get("detectors") or []
    # These values come from the host-side checkout, not from model output.
    # This prevents a planner from accidentally publishing a stale commit or
    # pointing the later workflow at a different repository.
    config["image_tag"] = image_tag_for(name, lock.commit)
    config["github_url"] = lock.repo
    config["commit"] = lock.commit
    if not config.get("source_root"):
        config["source_root"] = runtime.get("source_root", "/work")
    if not config.get("binary_path"):
        artifact = runtime.get("artifact") or {}
        if profile == "process" and not artifact.get("path"):
            raise BuildError("process target is missing binary_path and runtime artifact.path")
        config["binary_path"] = artifact.get("path", "/bin/true")
    if detectors:
        # The manifest is the authoritative classification. Rewrite the
        # legacy projection so an agent typo cannot select the wrong prompt
        # family for the later workflow.
        config["detector"] = detectors[0]
    if "devices" in resources:
        config["devices"] = resources["devices"]
    if "memory" in resources:
        config["memory_limit"] = resources["memory"]
    if "shm_size" in resources:
        config["shm_size"] = resources["shm_size"]
    if "agent_prebuilt" in manifest.get("build", {}):
        config["agent_prebuilt"] = manifest["build"]["agent_prebuilt"]
    _yaml_write(path, config)
    return config


def _normalize_manifest(context_dir: Path, lock: SourceLock, name: str) -> dict:
    path = context_dir / MANIFEST_FILENAME
    try:
        manifest = load_manifest(path, require_identity=False)
    except ManifestError as exc:
        raise BuildError(f"invalid generated {MANIFEST_FILENAME}: {exc}") from exc
    identity = manifest.setdefault("identity", {})
    if not isinstance(identity, dict):
        raise BuildError(f"generated {MANIFEST_FILENAME} identity must be a mapping")
    # Repository identity is authoritative on the host, just like config.yaml.
    identity.update({"name": name, "repository": lock.repo, "commit": lock.commit})
    _yaml_write(path, manifest)
    return manifest


def validate_generated_context(context_dir: Path, *, name: str, lock: SourceLock) -> dict:
    """Validate model output before giving it to Docker."""
    dockerfile = context_dir / "Dockerfile"
    config_path = context_dir / "config.yaml"
    plan_path = context_dir / "build-plan.json"
    manifest_path = context_dir / MANIFEST_FILENAME
    if not dockerfile.is_file():
        raise BuildError("generated context is missing Dockerfile")
    if not config_path.is_file():
        raise BuildError("generated context is missing config.yaml")
    if not plan_path.is_file():
        raise BuildError("generated context is missing build-plan.json")
    try:
        manifest = load_manifest(manifest_path, require_identity=True)
    except ManifestError as exc:
        raise BuildError(f"generated context has invalid {MANIFEST_FILENAME}: {exc}") from exc
    try:
        adapter_for(manifest["runtime"]["profile"]).validate(manifest)
    except RuntimeContractError as exc:
        raise BuildError(f"generated runtime contract is invalid: {exc}") from exc
    identity = manifest["identity"]
    if identity["name"] != name:
        raise BuildError(f"generated {MANIFEST_FILENAME} has incorrect identity.name")
    if identity["repository"] != lock.repo:
        raise BuildError(f"generated {MANIFEST_FILENAME} has incorrect identity.repository")
    if identity["commit"] != lock.commit:
        raise BuildError(f"generated {MANIFEST_FILENAME} has incorrect identity.commit")
    dockerfile_text = dockerfile.read_text(errors="replace")
    if not _COPY_SOURCE_RE.search(dockerfile_text):
        raise BuildError("Dockerfile must COPY source/ into the image")
    if re.search(r"(?im)\bgit\s+clone\b", dockerfile_text):
        raise BuildError("Dockerfile must build from the locked source snapshot, not git clone")
    if re.search(r"(?im)^\s*(?:COPY|ADD)\s+\.\./", dockerfile_text):
        raise BuildError("Dockerfile may not copy files outside its build context")
    config = _load_config(config_path)
    expected_tag = image_tag_for(name, lock.commit)
    for key, expected in {
        "image_tag": expected_tag,
        "github_url": lock.repo,
        "commit": lock.commit,
    }.items():
        if config.get(key) != expected:
            raise BuildError(f"generated config.yaml has incorrect {key!r}")
    for key in ("binary_path", "source_root"):
        value = config.get(key)
        if not isinstance(value, str) or not value.startswith("/"):
            raise BuildError(f"generated config.yaml {key!r} must be an absolute container path")
    profile = manifest["runtime"]["profile"]
    if not bool(config.get("agent_prebuilt", False)):
        if not config["source_root"].startswith("/work/"):
            raise BuildError(
                "generated config.yaml 'source_root' must be under /work/ "
                "so the target-agent image can inherit it"
            )
        if profile == "process" and not config["binary_path"].startswith("/work/"):
            raise BuildError(
                "generated process target config.yaml 'binary_path' must be under /work/ "
                "so the target-agent image can inherit it"
            )
    runtime = manifest["runtime"]
    manifest_source_root = runtime.get("source_root")
    if manifest_source_root and config["source_root"] != manifest_source_root:
        raise BuildError(
            "config.yaml source_root disagrees with target-manifest.yaml runtime.source_root"
        )
    artifact = runtime.get("artifact") or {}
    manifest_artifact_path = artifact.get("path")
    if profile == "process" and manifest_artifact_path:
        if config["binary_path"] != manifest_artifact_path:
            raise BuildError(
                "config.yaml binary_path disagrees with target-manifest.yaml runtime.artifact.path"
            )
    try:
        plan = json.loads(plan_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildError(f"cannot parse generated build-plan.json: {exc}") from exc
    if not isinstance(plan, dict):
        raise BuildError("generated build-plan.json must contain a JSON object")
    required_plan_keys = {
        "kind", "base_image", "build_steps", "entrypoint",
        "runtime_dependencies", "notes",
    }
    missing_plan_keys = sorted(required_plan_keys - set(plan))
    if missing_plan_keys:
        raise BuildError(
            "generated build-plan.json is missing: " + ", ".join(missing_plan_keys)
        )
    return config


def _probe_target(target: TargetConfig) -> None:
    """Run the minimum runtime-specific contract probe."""
    name = f"build_probe_{target.name}_{uuid.uuid4().hex[:8]}"
    manifest = target.manifest
    adapter = None
    if manifest is not None:
        adapter = adapter_for(manifest["runtime"]["profile"])
        adapter.validate(manifest)
    try:
        docker_ops.run(
            target.image_tag,
            name=name,
            memory=target.memory_limit,
            shell="/bin/sh",
            shm_size=target.shm_size,
            network=target.agent_network or "none",
            devices=target.devices,
        )
        if adapter is None:
            paths = [(target.source_root, False), (target.binary_path, True)]
        else:
            paths = adapter.required_paths(manifest)
        for path, executable in paths:
            test = "test -x" if executable else "test -e"
            rc, _out, err = docker_ops.exec_sh(name, f"{test} {shlex.quote(path)}")
            if rc:
                adjective = "executable" if executable else "present"
                raise BuildError(
                    f"built image does not contain {adjective} path {path!r}: {err.strip()[:300]}"
                )
        if adapter is not None:
            session = RuntimeSession(name, adapter.profile, manifest)
            try:
                adapter.probe(session)
            except RuntimeContractError as exc:
                raise BuildError(
                    f"{adapter.profile} runtime contract probe failed: {exc}"
                ) from exc
            finally:
                session.stop()
    finally:
        docker_ops.rm(name)


def _copy_source_to_context(source_dir: Path, context_dir: Path) -> None:
    destination = context_dir / "source"
    shutil.copytree(source_dir, destination, symlinks=True)


def _publish(
    *,
    context_dir: Path,
    target_dir: Path,
    source_lock: SourceLock,
    build_json: dict,
    force: bool,
) -> None:
    if target_dir.exists() and not force:
        raise BuildError(
            f"target directory already exists: {target_dir}; use --force to replace it"
        )
    staging = target_dir.parent / f".{target_dir.name}.staging-{uuid.uuid4().hex[:8]}"
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(
        context_dir,
        staging,
        symlinks=True,
        ignore=shutil.ignore_patterns("build.log"),
    )
    _yaml_write(staging / "source.lock.yaml", source_lock.to_dict())
    (staging / "build.json").write_text(
        json.dumps(build_json, indent=2, ensure_ascii=False) + "\n"
    )
    try:
        if target_dir.exists():
            if not force:  # protect against a race after the initial check
                raise BuildError(f"target directory appeared during build: {target_dir}")
            shutil.rmtree(target_dir)
        staging.rename(target_dir)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise


async def inspect_repository(
    options: InspectOptions, auth: dict[str, str]
) -> ClassificationResult:
    """Materialize a repository and run only the classification phase."""
    validate_target_name(options.name)
    if options.max_turns <= 0:
        raise BuildError("classification max turns must be positive")
    job_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    job_dir = (options.builds_dir / options.name / job_id).resolve()
    source_dir = job_dir / "source"
    status_path = job_dir / "status.json"
    job_dir.mkdir(parents=True, exist_ok=False)
    _status(status_path, "cloning", name=options.name, repo=options.repo)
    try:
        lock = materialize_source(
            options.repo,
            source_dir,
            branch=options.branch,
            ref=options.ref,
            timeout=options.git_timeout_s,
        )
        _yaml_write(job_dir / "source.lock.yaml", lock.to_dict())
        _status(status_path, "classifying", commit=lock.commit)
        classification = await _run_classification(
            name=options.name,
            source_dir=source_dir,
            output_dir=job_dir,
            auth=auth,
            model=options.model,
            repo=lock.repo,
            branch=lock.branch or options.branch or "",
            commit=lock.commit,
            kind="auto",
            transcript_path=job_dir / "classification_transcript.jsonl",
            max_turns=options.max_turns,
            progress_prefix=f"[inspect:{options.name}]",
        )
        _status(
            status_path,
            "succeeded",
            commit=lock.commit,
            runtime_profile=classification["runtime"]["profile"],
        )
        return ClassificationResult(
            name=options.name,
            job_id=job_id,
            job_dir=job_dir,
            source_lock=lock,
            classification=classification,
        )
    except Exception as exc:
        _status(status_path, "failed", error=f"{type(exc).__name__}: {exc}")
        if isinstance(exc, BuildError):
            raise
        raise BuildError(f"repository inspection failed: {type(exc).__name__}: {exc}") from exc


async def build_target(options: BuildOptions, auth: dict[str, str]) -> BuildResult:
    """Run the complete host/agent/host build workflow."""
    validate_target_name(options.name)
    if options.retries < 0:
        raise BuildError("build retries cannot be negative")
    if options.timeout_s <= 0:
        raise BuildError("build timeout must be positive")
    target_dir = (options.targets_dir / options.name).resolve()
    if target_dir.exists() and not options.force:
        raise BuildError(
            f"target directory already exists: {target_dir}; use --force to refresh it"
        )

    job_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    # Docker bind mounts require host paths, not relative paths.  The CLI
    # defaults to ``results/builds`` (relative to the repository), so resolve
    # the job root before handing source/context directories to the agent
    # container or Docker build.
    job_dir = (options.builds_dir / options.name / job_id).resolve()
    source_dir = job_dir / "source"
    context_dir = job_dir / "context"
    status_path = job_dir / "status.json"
    job_dir.mkdir(parents=True, exist_ok=False)
    context_dir.mkdir()
    _status(status_path, "cloning", name=options.name, repo=options.repo)

    try:
        lock = materialize_source(
            options.repo,
            source_dir,
            branch=options.branch,
            ref=options.ref,
            timeout=options.git_timeout_s,
        )
        _yaml_write(job_dir / "source.lock.yaml", lock.to_dict())
        _copy_source_to_context(source_dir, context_dir)
        _yaml_write(context_dir / "source.lock.yaml", lock.to_dict())
        image_tag = image_tag_for(options.name, lock.commit)
        _status(status_path, "classifying", commit=lock.commit, image_tag=image_tag)

        classification = await _run_classification(
            name=options.name,
            source_dir=source_dir,
            output_dir=context_dir,
            auth=auth,
            model=options.model,
            repo=lock.repo,
            branch=lock.branch or options.branch or "",
            commit=lock.commit,
            kind=options.kind,
            transcript_path=job_dir / "classification_transcript.jsonl",
            max_turns=options.max_turns,
            progress_prefix=f"[build:{options.name}:classify]",
        )
        _status(
            status_path,
            "planning",
            commit=lock.commit,
            image_tag=image_tag,
            project_kind=classification["project"]["kind"],
            runtime_profile=classification["runtime"]["profile"],
        )

        prompt = build_plan_prompt(
            repo=lock.repo,
            branch=lock.branch or options.branch or "",
            commit=lock.commit,
            kind=options.kind,
            image_tag=image_tag,
            classification_path=f"/input/{CLASSIFICATION_FILENAME}",
        )
        outputs, planner_result = await _run_build_agent(
            name=options.name,
            source_dir=source_dir,
            context_dir=context_dir,
            auth=auth,
            model=options.model,
            prompt=prompt,
            transcript_path=job_dir / "planner_transcript.jsonl",
            max_turns=options.max_turns,
            progress_prefix=f"[build:{options.name}:plan]",
        )
        if planner_result.error:
            raise BuildError(f"planner agent failed: {planner_result.error}")
        _write_agent_outputs(
            context_dir,
            outputs,
            protected_paths={CLASSIFICATION_FILENAME},
        )
        _normalize_manifest(context_dir, lock, options.name)
        _normalize_config(context_dir, lock, options.name)
        config = validate_generated_context(context_dir, name=options.name, lock=lock)

        build_attempts = 0
        last_error: str | None = None
        while build_attempts <= options.retries:
            if build_attempts:
                repair_number = build_attempts
                log_path = job_dir / f"build-{repair_number}.log"
                shutil.copyfile(log_path, context_dir / "build.log")
                _status(status_path, "repairing", attempt=repair_number,
                        previous_error=last_error)
                repair_prompt = build_plan_prompt(
                    repo=lock.repo,
                    branch=lock.branch or options.branch or "",
                    commit=lock.commit,
                    kind=options.kind,
                    image_tag=image_tag,
                    repair_log=str(log_path),
                    classification_path=f"/input/{CLASSIFICATION_FILENAME}",
                )
                outputs, repair_result = await _run_build_agent(
                    name=options.name,
                    source_dir=source_dir,
                    context_dir=context_dir,
                    auth=auth,
                    model=options.model,
                    prompt=repair_prompt,
                    transcript_path=job_dir / f"repair-{repair_number}-transcript.jsonl",
                    max_turns=options.max_turns,
                    progress_prefix=f"[build:{options.name}:repair-{repair_number}]",
                )
                if repair_result.error:
                    raise BuildError(f"repair agent failed: {repair_result.error}")
                _write_agent_outputs(
                    context_dir,
                    outputs,
                    protected_paths={CLASSIFICATION_FILENAME},
                )
                _normalize_manifest(context_dir, lock, options.name)
                _normalize_config(context_dir, lock, options.name)
                config = validate_generated_context(context_dir, name=options.name, lock=lock)

            build_attempts += 1
            log_path = job_dir / f"build-{build_attempts}.log"
            _status(status_path, "building", attempt=build_attempts,
                    image_tag=image_tag)
            try:
                docker_ops.build(
                    str(context_dir),
                    image_tag,
                    log_path=str(log_path),
                    timeout=options.timeout_s,
                )
                last_error = None
                break
            except subprocess.TimeoutExpired:
                last_error = f"Docker build timed out after {options.timeout_s}s"
            except subprocess.CalledProcessError as exc:
                last_error = f"Docker build failed with exit code {exc.returncode}"
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            if build_attempts > options.retries:
                raise BuildError(
                    f"Docker build failed after {build_attempts} attempt(s); "
                    f"see {job_dir / f'build-{build_attempts}.log'}"
                )

        if not docker_ops.image_exists(image_tag):
            raise BuildError(f"Docker build reported success but image is missing: {image_tag}")
        # Load once more after repair so probe settings reflect the final config.
        target = TargetConfig.load(context_dir)
        _probe_target(target)
        agent_tag: str | None = None
        if not target.agent_prebuilt:
            _status(status_path, "building_agent_image", image_tag=image_tag)
            agent_tag = agent_image.ensure(target.image_tag)

        build_json = {
            "name": options.name,
            "job_id": job_id,
            "repo": lock.repo,
            "branch": lock.branch,
            "requested_ref": lock.ref,
            "commit": lock.commit,
            "snapshot_sha256": lock.snapshot_sha256,
            "image_tag": image_tag,
            "agent_image_tag": agent_tag,
            "kind": options.kind,
            "classification": classification,
            "build_attempts": build_attempts,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        (job_dir / "build.json").write_text(
            json.dumps(build_json, indent=2, ensure_ascii=False) + "\n"
        )
        _status(status_path, "publishing", image_tag=image_tag)
        options.targets_dir.mkdir(parents=True, exist_ok=True)
        _publish(
            context_dir=context_dir,
            target_dir=target_dir,
            source_lock=lock,
            build_json=build_json,
            force=options.force,
        )
        _status(status_path, "succeeded", target_dir=str(target_dir), image_tag=image_tag)
        return BuildResult(
            name=options.name,
            job_id=job_id,
            job_dir=job_dir,
            target_dir=target_dir,
            image_tag=image_tag,
            agent_image_tag=agent_tag,
            source_lock=lock,
            build_attempts=build_attempts,
        )
    except Exception as exc:
        _status(status_path, "failed", error=f"{type(exc).__name__}: {exc}")
        if isinstance(exc, BuildError):
            raise
        raise BuildError(f"target build failed: {type(exc).__name__}: {exc}") from exc
