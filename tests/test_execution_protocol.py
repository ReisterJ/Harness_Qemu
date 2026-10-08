"""Tests for harness-owned dynamic input requests and prebuilt SymCC runs."""
import json

import pytest

from harness import docker_ops
from harness.artifacts import StaticFinding
from harness.config import TargetConfig
from harness.dynamic_validation import (
    _execute_prebuilt_protocol_request,
    _prepare_prebuilt_symcc_protocol,
)
from harness.execution_protocol import (
    INPUT_ROOT,
    ExecutionRequestError,
    parse_request,
    target_argv,
)


def _request(**changes):
    value = {
        "schema_version": 1,
        "request_id": "round-001",
        "input_path": f"{INPUT_ROOT}/candidate.bin",
        "program_args": ["--input", "{input_file}"],
        "timeout_s": 15,
        "env": {"MODE": "probe"},
    }
    value.update(changes)
    return value


def _target():
    return TargetConfig(
        name="sample",
        dockerfile_dir="/tmp/sample",
        image_tag="sample:latest",
        github_url="local",
        commit="a" * 40,
        binary_path="/out/target",
        source_root="/src/sample",
        symbolic_execution={
            "symcc": {
                "binary_path": "/out/target-symcc",
                "commit": "a" * 40,
                "program_args": ["--input", "{input_file}"],
            }
        },
    )


def test_parse_execution_request_accepts_safe_input_and_unique_id():
    parsed = parse_request(json.dumps(_request()).encode(), filename="round-001.json")
    assert parsed.request_id == "round-001"
    assert parsed.input_path == f"{INPUT_ROOT}/candidate.bin"
    assert parsed.program_args == ("--input", "{input_file}")


@pytest.mark.parametrize("changes", [
    {"input_path": "/tmp/outside.bin"},
    {"input_path": f"{INPUT_ROOT}/../outside.bin"},
    {"program_args": ["{input_file}", "{input_file}"]},
    {"timeout_s": 301},
    {"timeout_s": 1.5},
    {"request_id": "bad/id"},
])
def test_parse_execution_request_rejects_invalid_contract(changes):
    with pytest.raises(ExecutionRequestError):
        parse_request(json.dumps(_request(**changes)))


def test_parse_execution_request_binds_filename_to_request_id():
    with pytest.raises(ExecutionRequestError, match="filename"):
        parse_request(json.dumps(_request()), filename="round-002.json")


def test_target_argv_keeps_arguments_separate_and_substitutes_input():
    argv = target_argv(
        "/out/target", ("--input", "{input_file}", "--label", "two words"),
        f"{INPUT_ROOT}/seed.bin",
    )
    assert argv == [
        "/out/target", "--input", f"{INPUT_ROOT}/seed.bin",
        "--label", "two words",
    ]


def test_protocol_runs_same_input_through_both_binaries_and_replays_generated(
    monkeypatch,
):
    target = _target()
    commands = []
    writes = {}

    def fake_exec(container, command, timeout=0):
        commands.append(command)
        if command.startswith("readlink -f"):
            return 0, f"{INPUT_ROOT}/candidate.bin\n", ""
        if command.startswith("stat -c"):
            return 0, "4\n", ""
        if "find /work/validation/symcc-results/round-001" in command:
            return (
                0,
                "/work/validation/symcc-results/round-001/testcase-000\t7\n",
                "",
            )
        if ".harness-symcc-target-symcc" in command:
            return 0, "symcc run\n", ""
        if ".harness-clean-target" in command:
            return 1, "AddressSanitizer: heap-buffer-overflow\n", ""
        return 0, "", ""

    def fake_read(container, path):
        if path.endswith("candidate.bin"):
            return b"seed"
        if path.endswith("testcase-000"):
            return b"mutated"
        return b""

    def fake_write(container, path, data):
        writes[path] = data

    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(docker_ops, "read_file", fake_read)
    monkeypatch.setattr(docker_ops, "write_file", fake_write)

    response = _execute_prebuilt_protocol_request(
        container="target",
        target=target,
        raw=json.dumps(_request()).encode(),
        filename="round-001.json",
        round_id=1,
    )

    assert response["status"] == "completed"
    assert response["input_sha256"]
    assert response["clean"]["sanitizer_event"] is True
    assert response["symcc"]["status"] == "completed"
    assert response["symcc"]["testcase_count"] == 1
    assert response["generated_replays"][0]["replay"]["sanitizer_event"] is True
    assert writes[f"{INPUT_ROOT}/symcc-round-001-000.bin"] == b"mutated"
    assert sum("/out/target-symcc" in command for command in commands) == 0
    assert any("/out/.harness-symcc-target-symcc" in command for command in commands)
    assert any("/out/.harness-clean-target" in command for command in commands)


def test_prebuilt_symcc_config_is_exposed_as_runtime_contract():
    assert _target().symcc_runtime == {
        "binary_path": "/out/target-symcc",
        "commit": "a" * 40,
        "program_args": ["--input", "{input_file}"],
    }


def test_target_loader_validates_prebuilt_symcc_binary_contract(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "image_tag: sample:latest\n"
        "github_url: local\n"
        f"commit: {'a' * 40}\n"
        "binary_path: /out/target\n"
        "source_root: /src/sample\n"
        "symbolic_execution:\n"
        "  default: 'off'\n"
        "  providers: [symcc]\n"
        "  symcc:\n"
        "    binary_path: /out/target-symcc\n"
        f"    commit: {'a' * 40}\n"
        "    program_args: ['--input', '{input_file}']\n"
    )
    loaded = TargetConfig.load(tmp_path)
    assert loaded.symcc_runtime["binary_path"] == "/out/target-symcc"

    config.write_text(
        "image_tag: sample:latest\n"
        "github_url: local\n"
        f"commit: {'a' * 40}\n"
        "binary_path: /out/target\n"
        "source_root: /src/sample\n"
        "symbolic_execution:\n"
        "  symcc:\n"
        "    binary_path: relative/symcc\n"
    )
    with pytest.raises(ValueError, match="absolute container path"):
        TargetConfig.load(tmp_path)


def test_symcc_protocol_requires_prebuilt_artifact_for_same_commit():
    target = _target()
    target.symbolic_execution["symcc"]["commit"] = "b" * 40
    with pytest.raises(ValueError, match="must declare the target commit"):
        _prepare_prebuilt_symcc_protocol("unused", target)


def test_symcc_protocol_preflights_binaries_and_installs_runner(monkeypatch):
    target = _target()
    calls = []

    def fake_exec(container, command, timeout=0):
        calls.append(command)
        if command.startswith("test -f"):
            return 0, "", ""
        return 0, "", ""

    writes = {}
    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(
        docker_ops, "write_file", lambda _container, path, data: writes.__setitem__(path, data)
    )
    context = _prepare_prebuilt_symcc_protocol("target", target)

    assert context["status"] == "ready"
    assert context["orchestration"] == "prebuilt_protocol"
    assert context["artifact_commit"] == target.commit
    assert "/work/validation/run-input" in writes
    assert any(
        "mv -- /out/target /out/.harness-clean-target" in command for command in calls
    )
    assert any(
        "mv -- /out/target-symcc /out/.harness-symcc-target-symcc" in command
        for command in calls
    )
