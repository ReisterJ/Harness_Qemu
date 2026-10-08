"""Tests for harness-owned dynamic input requests and prebuilt SymCC runs."""
import asyncio
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


def test_prebuilt_symcc_agent_forwards_phase_timeout_and_no_deadline(monkeypatch):
    """The symcc agent must use the caller's watchdog budget, not a constant."""
    from harness.agent import AgentResult
    from harness.dynamic_validation import _run_prebuilt_symcc_agent

    message = "<dynamic_status>iteration_exhausted</dynamic_status>"

    captured = {}

    async def fake_worker(**_kwargs):
        return {
            "schema_version": 1, "provider": "symcc-prebuilt", "status": "completed",
            "requests": 0, "invalid_requests": 0, "errors": 0,
            "symcc_execution_s": 0.0, "records": [],
        }

    async def fake_agent(**kwargs):
        captured.update(kwargs)
        return AgentResult(
            messages=[{"type": "text", "part": {"type": "text", "text": message}}],
            result_message=message,
        )

    monkeypatch.setattr("harness.dynamic_validation._prebuilt_protocol_worker", fake_worker)
    monkeypatch.setattr("harness.dynamic_validation.run_agent", fake_agent)

    target = _target()
    asyncio.run(_run_prebuilt_symcc_agent(
        prompt="p", target=target, container="c", model="m", max_turns=1,
        system_prompt=None, max_resume_attempts=1, transcript_path=None,
        progress_prefix=None, result_path=None, phase_timeout_s=7200.0,
    ))
    assert captured["phase_timeout_s"] == 7200.0
    assert captured["idle_timeout_s"] == 7200.0

    captured.clear()
    asyncio.run(_run_prebuilt_symcc_agent(
        prompt="p", target=target, container="c", model="m", max_turns=1,
        system_prompt=None, max_resume_attempts=1, transcript_path=None,
        progress_prefix=None, result_path=None,
    ))
    assert captured["phase_timeout_s"] is None
    assert captured["idle_timeout_s"] is None


# ── per-input execution coverage (agent seeds only) ───────────────────────────


def _coverage_target():
    target = _target()
    return TargetConfig(
        **{
            **target.__dict__,
            "coverage_binary_path": "/out/target-cov",
        }
    )


def _lcov(*records):
    blocks = []
    for path, lines, functions in records:
        block = [f"SF:{path}"]
        for name, hits in functions:
            block.append(f"FNDA:{hits},{name}")
        for number, count in lines:
            block.append(f"DA:{number},{count}")
        block.append("end_of_record")
        blocks.append("\n".join(block))
    return "\n".join(blocks) + "\n"


def test_coverage_summary_reports_new_lines_and_functions_per_input():
    from harness.dynamic_validation import (
        ProtocolCoverageSession,
        _summarize_lcov_coverage,
    )

    session = ProtocolCoverageSession()
    first = _summarize_lcov_coverage(
        _lcov(
            ("/src/mruby/src/vm.c", [(375, 0), (376, 42), (398, 15)],
             [("mrb_env_unshare", 42), ("unused_helper", 0)]),
            ("/src/mruby/src/gc.c", [(1158, 1)], [("incremental_sweep_phase", 1)]),
        ),
        session=session,
    )
    assert first["lines_hit"] == 3
    assert first["functions_hit"] == 2
    assert first["new_lines"] == 3
    assert {item["name"] for item in first["new_functions"]} == {
        "mrb_env_unshare", "incremental_sweep_phase",
    }
    assert first["cumulative"]["requests"] == 1
    assert first["top_new_files"][0]["file"].endswith("vm.c")
    assert first["top_new_files"][0]["sample_new_lines"] == [376, 398]
    assert first["top_new_files"][0]["new_functions"] == [
        {"name": "mrb_env_unshare", "hits": 42},
    ]

    second = _summarize_lcov_coverage(
        _lcov(
            ("/src/mruby/src/vm.c", [(376, 7), (376, 7), (500, 3)],
             [("mrb_env_unshare", 7), ("mrb_vm_exec", 9)]),
        ),
        session=session,
    )
    assert second["lines_hit"] == 2
    assert second["new_lines"] == 1
    assert [item["name"] for item in second["new_functions"]] == ["mrb_vm_exec"]
    assert second["cumulative"] == {
        "requests": 2, "files_touched": 2, "lines_hit": 4, "functions_hit": 3,
    }


def test_coverage_summary_is_empty_for_input_that_reaches_nothing_new():
    from harness.dynamic_validation import (
        ProtocolCoverageSession,
        _summarize_lcov_coverage,
    )

    session = ProtocolCoverageSession()
    payload = _lcov(("/src/mruby/src/vm.c", [(1, 1)], [("mrb_vm_exec", 1)]))
    _summarize_lcov_coverage(payload, session=session)
    repeat = _summarize_lcov_coverage(payload, session=session)
    assert repeat["new_lines"] == 0
    assert repeat["new_functions"] == []
    assert repeat["top_new_files"] == []


def test_protocol_request_attaches_coverage_for_the_agent_input(monkeypatch):
    target = _coverage_target()
    lcov = _lcov(
        ("/src/mruby/src/vm.c", [(376, 42), (398, 15)], [("mrb_env_unshare", 42)]),
    )
    commands = []

    def fake_exec(container, command, timeout=0):
        commands.append(command)
        if command.startswith("command -v llvm-profdata"):
            return 0, "/usr/bin/llvm-profdata-15\n", ""
        if command.startswith("command -v llvm-cov"):
            return 0, "/usr/bin/llvm-cov-15\n", ""
        if command.startswith("readlink -f"):
            return 0, f"{INPUT_ROOT}/candidate.bin\n", ""
        if command.startswith("stat -c"):
            return 0, "4\n", ""
        if "find /work/validation/symcc-results/round-001" in command:
            return 0, "", ""
        if ".harness-symcc-target-symcc" in command:
            return 0, "symcc run\n", ""
        if ".harness-coverage-target-cov" in command:
            return 0, "", ""
        if ".harness-clean-target" in command:
            return 0, "", ""
        return 0, "", ""

    def fake_read(container, path):
        if path.endswith("candidate.bin"):
            return b"seed"
        if path.endswith(".lcov"):
            return lcov.encode()
        return b""

    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(docker_ops, "read_file", fake_read)
    monkeypatch.setattr(docker_ops, "write_file", lambda *a, **k: None)

    response = _execute_prebuilt_protocol_request(
        container="target",
        target=target,
        raw=json.dumps(_request()).encode(),
        filename="round-001.json",
        round_id=1,
    )

    coverage = response["coverage"]
    assert coverage["status"] == "completed"
    assert coverage["lines_hit"] == 2
    assert coverage["new_lines"] == 2
    assert coverage["exit_code"] == 0
    assert coverage["new_functions"] == [{"name": "mrb_env_unshare", "hits": 42}]
    assert coverage["top_new_files"][0]["new_functions"] == [
        {"name": "mrb_env_unshare", "hits": 42},
    ]
    assert any(".harness-coverage-target-cov" in command for command in commands)
    assert any(
        "LLVM_PROFILE_FILE=/work/validation/coverage/round-001.profraw" in command
        for command in commands
    )
    assert any("llvm-profdata-15 merge -sparse" in command for command in commands)
    assert any("llvm-cov-15 export" in command for command in commands)


def test_protocol_request_omits_coverage_without_a_declared_binary(monkeypatch):
    commands = []

    def fake_exec(container, command, timeout=0):
        commands.append(command)
        if command.startswith("readlink -f"):
            return 0, f"{INPUT_ROOT}/candidate.bin\n", ""
        if command.startswith("stat -c"):
            return 0, "4\n", ""
        return 0, "", ""

    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(
        docker_ops, "read_file",
        lambda _c, path: b"seed" if path.endswith("candidate.bin") else b"",
    )
    monkeypatch.setattr(docker_ops, "write_file", lambda *a, **k: None)

    response = _execute_prebuilt_protocol_request(
        container="target",
        target=_target(),
        raw=json.dumps(_request()).encode(),
        filename="round-001.json",
        round_id=1,
    )
    assert "coverage" not in response
    assert not any("llvm-profdata" in command for command in commands)


def test_coverage_degrades_to_unavailable_when_tools_are_missing(monkeypatch):
    def fake_exec(container, command, timeout=0):
        if command.startswith("readlink -f"):
            return 0, f"{INPUT_ROOT}/candidate.bin\n", ""
        if command.startswith("test -f"):
            return 0, "", ""
        if command.startswith("stat -c"):
            return 0, "4\n", ""
        return 127, "", "not found"

    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(
        docker_ops, "read_file",
        lambda _c, path: b"seed" if path.endswith("candidate.bin") else b"",
    )
    monkeypatch.setattr(docker_ops, "write_file", lambda *a, **k: None)

    response = _execute_prebuilt_protocol_request(
        container="target",
        target=_coverage_target(),
        raw=json.dumps(_request()).encode(),
        filename="round-001.json",
        round_id=1,
    )
    assert response["status"] == "completed"
    assert response["clean"]["sanitizer_event"] is False
    assert response["coverage"]["status"] == "unavailable"


def test_coverage_binary_is_staged_and_advertised_by_the_protocol(monkeypatch):
    target = _coverage_target()
    calls = []
    writes = {}

    def fake_exec(container, command, timeout=0):
        calls.append(command)
        return 0, "", ""

    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(
        docker_ops, "write_file", lambda _container, path, data: writes.__setitem__(path, data)
    )
    context = _prepare_prebuilt_symcc_protocol("target", target)

    assert context["coverage_binary"] == "/out/.harness-coverage-target-cov"
    assert any(
        "mv -- /out/target-cov /out/.harness-coverage-target-cov" in command
        for command in calls
    )
    assert any("/work/validation/coverage" in command for command in calls)
    readme = writes["/work/validation/execution/README.md"].decode()
    assert "`coverage` block" in readme
    assert "new_lines" in readme


def test_target_config_rejects_relative_coverage_binary(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "image_tag: sample:latest\n"
        "github_url: local\n"
        "commit: " + "a" * 40 + "\n"
        "coverage_binary_path: out/target-cov\n"
    )
    with pytest.raises(ValueError, match="coverage_binary_path"):
        TargetConfig.load(tmp_path)
