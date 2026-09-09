"""Unit tests for the repository-to-target build workflow."""
from __future__ import annotations

import subprocess
import asyncio
import json
from pathlib import Path

import pytest

from harness.target_builder import (
    BuildError,
    BuildOptions,
    SourceLock,
    _write_agent_outputs,
    build_target,
    image_tag_for,
    materialize_source,
    tree_sha256,
    validate_generated_context,
)


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _local_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "test")
    (repo / "README.md").write_text("build me\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "initial")
    commit = _git(repo, "rev-parse", "HEAD")
    return repo, commit


def _generated_context(tmp_path: Path, repo: str, commit: str) -> Path:
    context = tmp_path / "context"
    context.mkdir()
    (context / "Dockerfile").write_text(
        "FROM gcc:14\nWORKDIR /work\nCOPY source/ /work/src/\n"
        "COPY entry.c /work/entry.c\nRUN gcc -o /work/entry /work/entry.c\n"
    )
    (context / "config.yaml").write_text(
        "image_tag: vuln-pipeline-demo:" + commit[:12] + "\n"
        f"github_url: {repo}\n"
        f"commit: {commit}\n"
        "binary_path: /work/entry\nsource_root: /work/src\n"
    )
    (context / "build-plan.json").write_text(
        '{"kind":"cli","base_image":"gcc:14","build_steps":[],'
        '"entrypoint":"/work/entry","runtime_dependencies":[],"notes":[]}'
    )
    (context / "target-manifest.yaml").write_text(
        "schema_version: 1\n"
        "identity:\n"
        "  name: demo\n"
        f"  repository: {repo}\n"
        f"  commit: {commit}\n"
        "build:\n"
        "  build_steps: []\n"
        "runtime:\n"
        "  profile: process\n"
        "  source_root: /work/src\n"
        "  artifact:\n"
        "    kind: executable\n"
        "    path: /work/entry\n"
        "  start:\n"
        "    command: /work/entry\n"
        "  capabilities: [file_input, stdout, stderr, exit_code]\n"
        "workflow:\n"
        "  static_analysis: source\n"
        "  dynamic_validation: process\n"
        "  grade: process_replay\n"
        "resources:\n"
        "  devices: []\n"
    )
    return context


def test_materialize_source_records_latest_commit_and_hash(tmp_path):
    repo, commit = _local_repo(tmp_path)
    snapshot = tmp_path / "snapshot"
    lock = materialize_source(str(repo), snapshot, timeout=30)

    assert lock.commit == commit
    assert lock.repo == str(repo)
    assert lock.snapshot_sha256 == tree_sha256(snapshot)
    assert not (snapshot / ".git").exists()
    assert (snapshot / "README.md").read_text() == "build me\n"


def test_materialize_source_rejects_branch_and_ref(tmp_path):
    repo, _ = _local_repo(tmp_path)
    with pytest.raises(BuildError, match="mutually exclusive"):
        materialize_source(str(repo), tmp_path / "snapshot", branch="main", ref="HEAD")


def test_validate_generated_context_accepts_locked_metadata(tmp_path):
    repo, commit = _local_repo(tmp_path)
    context = _generated_context(tmp_path, str(repo), commit)
    config = validate_generated_context(context, name="demo", lock=type(
        "Lock", (), {"repo": str(repo), "commit": commit}
    )())
    assert config["binary_path"] == "/work/entry"


def test_validate_generated_context_rejects_network_clone(tmp_path):
    repo, commit = _local_repo(tmp_path)
    context = _generated_context(tmp_path, str(repo), commit)
    (context / "Dockerfile").write_text(
        "FROM gcc:14\nRUN git clone https://example.invalid/x /work/src\n"
    )
    lock = type("Lock", (), {"repo": str(repo), "commit": commit})()
    with pytest.raises(BuildError, match="COPY source"):
        validate_generated_context(context, name="demo", lock=lock)


def test_validate_generated_context_rejects_wrong_commit(tmp_path):
    repo, commit = _local_repo(tmp_path)
    context = _generated_context(tmp_path, str(repo), commit)
    (context / "config.yaml").write_text(
        "image_tag: vuln-pipeline-demo:wrong\n"
        f"github_url: {repo}\ncommit: wrong\n"
        "binary_path: /work/entry\nsource_root: /work/src\n"
    )
    lock = type("Lock", (), {"repo": str(repo), "commit": commit})()
    with pytest.raises(BuildError, match="incorrect 'image_tag'"):
        validate_generated_context(context, name="demo", lock=lock)


def test_agent_output_cannot_escape_context(tmp_path):
    with pytest.raises(BuildError, match="unsafe output path"):
        _write_agent_outputs(tmp_path, {Path("../Dockerfile"): b"bad"})


def test_image_tag_is_stable_and_name_is_validated():
    assert image_tag_for("flex", "abcdef1234567890") == "vuln-pipeline-flex:abcdef123456"
    with pytest.raises(BuildError, match="invalid target name"):
        image_tag_for("../flex", "abcdef123456")


def test_build_target_publishes_only_after_build_and_probe(tmp_path, monkeypatch):
    lock = SourceLock(
        repo="https://example.invalid/demo.git",
        branch="main",
        ref=None,
        commit="abcdef1234567890",
        snapshot_sha256="0" * 64,
    )

    def fake_materialize(_repo, destination, **_kwargs):
        destination.mkdir(parents=True)
        (destination / "README.md").write_text("snapshot\n")
        return lock

    outputs = {
        Path("Dockerfile"): (
            b"FROM gcc:14\nWORKDIR /work\nCOPY source/ /work/src/\n"
            b"COPY entry.c /work/entry.c\nRUN gcc -o /work/entry /work/entry.c\n"
        ),
        Path("entry.c"): b"int main(void) { return 0; }\n",
        Path("config.yaml"): b"binary_path: /work/entry\nsource_root: /work/src\n",
        Path("build-plan.json"): (
            b'{"kind":"cli","base_image":"gcc:14","build_steps":[],'
            b'"entrypoint":"/work/entry","runtime_dependencies":[],"notes":[]}'
        ),
        Path("target-manifest.yaml"): (
            b"schema_version: 1\n"
            b"identity:\n"
            b"  name: demo\n"
            b"  repository: https://example.invalid/demo.git\n"
            b"  commit: abcdef1234567890\n"
            b"build:\n"
            b"  build_steps: []\n"
            b"runtime:\n"
            b"  profile: process\n"
            b"  source_root: /work/src\n"
            b"  artifact:\n"
            b"    kind: executable\n"
            b"    path: /work/entry\n"
            b"  start:\n"
            b"    command: /work/entry\n"
            b"  capabilities: [file_input, stdout, stderr, exit_code]\n"
            b"workflow:\n"
            b"  static_analysis: source\n"
            b"  dynamic_validation: process\n"
            b"  grade: process_replay\n"
            b"resources:\n"
            b"  devices: []\n"
        ),
    }

    async def fake_agent(**_kwargs):
        from harness.agent import AgentResult
        return outputs, AgentResult()

    built = []
    monkeypatch.setattr("harness.target_builder.materialize_source", fake_materialize)
    monkeypatch.setattr("harness.target_builder._run_build_agent", fake_agent)
    monkeypatch.setattr("harness.target_builder._probe_target", lambda _target: None)
    monkeypatch.setattr("harness.target_builder.agent_image.ensure", lambda tag: f"{tag}-agent")
    monkeypatch.setattr(
        "harness.target_builder.docker_ops.build",
        lambda context, tag, **_kwargs: built.append((Path(context), tag)) or tag,
    )
    monkeypatch.setattr("harness.target_builder.docker_ops.image_exists", lambda _tag: True)

    result = asyncio.run(build_target(
        BuildOptions(
            name="demo",
            repo=lock.repo,
            branch="main",
            ref=None,
            kind="cli",
            model="test-model",
            targets_dir=tmp_path / "targets",
            builds_dir=tmp_path / "results" / "builds",
            timeout_s=30,
        ),
        {"ANTHROPIC_API_KEY": "test"},
    ))

    assert result.target_dir.is_dir()
    assert built and built[0][1] == "vuln-pipeline-demo:abcdef123456"
    assert (result.target_dir / "source" / "README.md").exists()
    assert (result.target_dir / "source.lock.yaml").exists()
    assert json.loads((result.target_dir / "build.json").read_text())["commit"] == lock.commit
    assert json.loads((result.job_dir / "status.json").read_text())["status"] == "succeeded"
    assert result.job_dir.is_absolute()
