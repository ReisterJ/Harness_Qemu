from __future__ import annotations

import subprocess

import pytest

from harness import docker_ops
from harness.config import TargetConfig
from harness.docker_params import (
    DockerParamsError,
    DockerRunParams,
    parse_docker_params,
)


def test_parse_qemu_params_and_phase_override(tmp_path):
    params = parse_docker_params(
        {
            "schema_version": 1,
            "image": {"mode": "prebuilt", "reference": "qemu-demo:1"},
            "build": {"network": "host", "platform": "linux/amd64", "pull": True},
            "run": {
                "network": "none",
                "memory": "2g",
                "shm_size": "128m",
                "devices": ["/dev/kvm"],
                "command": ["/bin/sh", "-c", "sleep infinity"],
                "mounts": [{"source": "artifacts", "target": "/artifacts"}],
            },
            "phases": {"probe": {"memory": "512m", "devices": []}},
        },
        base_dir=tmp_path,
    )

    assert params.image_mode == "prebuilt"
    assert params.image_reference == "qemu-demo:1"
    assert params.build.network == "host"
    assert params.for_phase("agent").memory == "2g"
    probe = params.for_phase("probe")
    assert probe.memory == "512m"
    assert probe.devices == ()
    assert probe.mounts[0].source == str((tmp_path / "artifacts").resolve())


def test_params_reject_prebuilt_image_without_reference():
    with pytest.raises(DockerParamsError, match="image.reference"):
        parse_docker_params({"image": {"mode": "prebuilt"}})


def test_params_reject_non_absolute_container_mount():
    with pytest.raises(DockerParamsError, match="absolute container path"):
        parse_docker_params(
            {"run": {"mounts": [{"source": "/tmp", "target": "relative"}]}}
        )


def test_run_applies_structured_parameters(monkeypatch, tmp_path):
    calls: list[list[str]] = []
    source = tmp_path / "input"
    source.write_text("input")

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["docker", "run", "-dit"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="container\n", stderr="")
        if cmd[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="qemu-demo:1\trunc\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(docker_ops.subprocess, "run", fake_run)
    params = DockerRunParams(
        network="host",
        memory="2g",
        shm_size="64m",
        privileged=True,
        devices=("/dev/kvm",),
        mounts=(),
        command=("/bin/sh", "-c", "sleep infinity"),
    )
    docker_ops.run(
        "qemu-demo:1",
        "qemu-demo",
        run_params=params,
        mounts=[(str(source), "/input")],
    )

    run_call = next(call for call in calls if call[:3] == ["docker", "run", "-dit"])
    assert "--privileged" in run_call
    assert run_call[run_call.index("--network") + 1] == "host"
    assert run_call[run_call.index("--memory") + 1] == "2g"
    assert run_call[run_call.index("--device") + 1] == "/dev/kvm"
    assert run_call[-4:] == ["qemu-demo:1", "/bin/sh", "-c", "sleep infinity"]


def test_build_applies_structured_parameters(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(docker_ops.subprocess, "run", fake_run)
    docker_ops.build(
        "/tmp/context",
        "demo:1",
        build_params=parse_docker_params(
            {"build": {
                "network": "host",
                "platform": "linux/amd64",
                "pull": True,
                "args": {"MODE": "debug"},
                "target": "runtime",
            }}
        ).build,
    )
    assert captured["cmd"] == [
        "docker", "build", "--network", "host", "--platform", "linux/amd64",
        "--pull", "--build-arg", "MODE=debug", "--target", "runtime",
        "-t", "demo:1", "/tmp/context",
    ]


def test_target_config_auto_loads_docker_params(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "image_tag: demo:1\ngithub_url: local\ncommit: abc\n"
        "binary_path: /work/demo\nsource_root: /work\n"
    )
    (tmp_path / "docker-params.yaml").write_text(
        "schema_version: 1\nrun:\n  network: host\n  memory: 1g\n"
    )
    target = TargetConfig.load(tmp_path)
    assert target.docker_run_params("agent").network == "host"
    assert target.docker_run_params("agent").memory == "1g"
