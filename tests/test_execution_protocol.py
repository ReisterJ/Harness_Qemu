"""Tests for harness-owned dynamic input requests and prebuilt SymCC runs."""
import asyncio
import json
import threading

import pytest

from harness import docker_ops
from harness.artifacts import StaticFinding
from harness.config import TargetConfig
from harness.dynamic_validation import (
    _execute_prebuilt_protocol_request,
    _prebuilt_protocol_worker,
    _prepare_prebuilt_symcc_protocol,
)
from harness.execution_protocol import (
    FEEDBACK_ROOT,
    INPUT_ROOT,
    PENDING_ROOT,
    RESPONSE_ROOT,
    ExecutionRequestError,
    parse_request,
    protocol_feedback_reader_script,
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


def test_prebuilt_protocol_returns_clean_result_while_symcc_runs_in_background(
    monkeypatch,
):
    target = _target()
    pending_path = f"{PENDING_ROOT}/round-001.json"
    response_path = f"{RESPONSE_ROOT}/round-001.json"
    feedback_path = f"{FEEDBACK_ROOT}/round-001.json"
    writes = {}
    pending_moved = threading.Event()
    response_written = threading.Event()
    symcc_started = threading.Event()
    symcc_release = threading.Event()
    feedback_written = threading.Event()

    def fake_exec(_container, command, timeout=0):
        if command.startswith(f"find {PENDING_ROOT}"):
            return (0, "" if pending_moved.is_set() else pending_path + "\n", "")
        if command.startswith("readlink -f"):
            return 0, f"{INPUT_ROOT}/candidate.bin\n", ""
        if command.startswith("stat -c"):
            return 0, "4\n", ""
        if command.startswith("test -f"):
            return 0, "", ""
        if "find /work/validation/symcc-results/round-001" in command:
            return 0, "", ""
        if "timeout --signal=KILL" in command:
            if ".harness-symcc-target-symcc" in command:
                symcc_started.set()
                if not symcc_release.wait(timeout=5):
                    return 124, "", "test SymCC wait timed out"
                return 0, "symcc complete", ""
            return 0, "clean target complete", ""
        if command.startswith(f"mv -- {PENDING_ROOT}/"):
            pending_moved.set()
            return 0, "", ""
        if command.startswith(f"mv -- {feedback_path}.tmp "):
            writes[feedback_path] = writes.pop(feedback_path + ".tmp")
            feedback_written.set()
            return 0, "", ""
        return 0, "", ""

    def fake_read(_container, path):
        if path == pending_path:
            return json.dumps(_request()).encode()
        if path == f"{INPUT_ROOT}/candidate.bin":
            return b"seed"
        return b""

    def fake_write(_container, path, data):
        writes[path] = data
        if path == response_path:
            response_written.set()

    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(docker_ops, "read_file", fake_read)
    monkeypatch.setattr(docker_ops, "write_file", fake_write)

    async def exercise():
        stop = asyncio.Event()
        worker = asyncio.create_task(_prebuilt_protocol_worker(
            container="target", target=target, stop=stop, result_path=None,
        ))
        assert await asyncio.to_thread(response_written.wait, 3)
        immediate = json.loads(writes[response_path])
        assert immediate["status"] == "submitted"
        assert immediate["clean"]["status"] == "completed"
        assert immediate["symcc"]["status"] == "queued"

        assert await asyncio.to_thread(symcc_started.wait, 3)
        assert not feedback_written.is_set()

        symcc_release.set()
        assert await asyncio.to_thread(feedback_written.wait, 3)
        feedback = json.loads(writes[feedback_path])
        assert feedback["feedback_status"] == "ready"
        assert feedback["symcc"]["status"] == "completed"

        stop.set()
        summary = await asyncio.wait_for(worker, timeout=3)
        assert summary["requests"] == 1
        assert summary["symcc_errors"] == 0

    asyncio.run(exercise())


def test_feedback_reader_is_nonblocking_and_validates_request_id():
    script = protocol_feedback_reader_script().decode()
    assert '"status":"pending"' in script
    assert "sleep" not in script
    assert '[ "${#id}" -le 80 ]' in script
    assert "read-feedback REQUEST_ID" in script


def test_protocol_worker_does_not_wait_for_unused_symcc_after_agent_finishes(
    monkeypatch,
):
    target = _target()
    pending_path = f"{PENDING_ROOT}/round-001.json"
    response_path = f"{RESPONSE_ROOT}/round-001.json"
    pending_moved = threading.Event()
    response_written = threading.Event()
    symcc_started = threading.Event()
    symcc_release = threading.Event()
    writes = {}

    def fake_exec(_container, command, timeout=0):
        if command.startswith(f"find {PENDING_ROOT}"):
            return (0, "" if pending_moved.is_set() else pending_path + "\n", "")
        if command.startswith("readlink -f"):
            return 0, f"{INPUT_ROOT}/candidate.bin\n", ""
        if command.startswith("stat -c"):
            return 0, "4\n", ""
        if command.startswith("test -f"):
            return 0, "", ""
        if "timeout --signal=KILL" in command:
            return 0, "clean target complete", ""
        if command.startswith(f"mv -- {PENDING_ROOT}/"):
            pending_moved.set()
        return 0, "", ""

    def fake_read(_container, path):
        if path == pending_path:
            return json.dumps(_request()).encode()
        return b"seed"

    def fake_write(_container, path, data):
        writes[path] = data
        if path == response_path:
            response_written.set()

    def blocking_symcc(**_kwargs):
        symcc_started.set()
        symcc_release.wait(timeout=5)
        return {"symcc": {"status": "completed"}}

    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(docker_ops, "read_file", fake_read)
    monkeypatch.setattr(docker_ops, "write_file", fake_write)
    monkeypatch.setattr(
        "harness.dynamic_validation._execute_prebuilt_protocol_symcc_request",
        blocking_symcc,
    )

    async def exercise():
        stop = asyncio.Event()
        worker = asyncio.create_task(_prebuilt_protocol_worker(
            container="target", target=target, stop=stop, result_path=None,
        ))
        assert await asyncio.to_thread(response_written.wait, 3)
        assert await asyncio.to_thread(symcc_started.wait, 3)
        stop.set()
        summary = await asyncio.wait_for(worker, timeout=3)
        assert summary["status"] == "incomplete"
        assert summary["symcc_abandoned"] == 1
        assert summary["records"][0]["feedback_status"] == "abandoned_agent_finished"
        symcc_release.set()

    asyncio.run(exercise())


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
    assert "/work/validation/read-feedback" in writes
    assert context["feedback_reader"] == "/work/validation/read-feedback"
    assert any(
        "mv -- /out/target /out/.harness-clean-target" in command for command in calls
    )
    assert any(
        "mv -- /out/target-symcc /out/.harness-symcc-target-symcc" in command
        for command in calls
    )
