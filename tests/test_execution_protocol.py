"""Tests for harness-owned dynamic input requests and prebuilt SymCC runs."""
import asyncio
import json
import threading
from pathlib import Path

import pytest

from harness import docker_ops
from harness.artifacts import StaticFinding
from harness.config import TargetConfig
from harness.dynamic_validation import (
    _compact_protocol_feedback,
    _execute_prebuilt_protocol_request,
    _prebuilt_protocol_worker,
    _prepare_prebuilt_symcc_protocol,
    _run_protocol_binary,
    _symcc_sidecar_settings,
)
from harness import dynamic_validation
from harness.execution_protocol import (
    FEEDBACK_ROOT,
    INPUT_ROOT,
    PENDING_ROOT,
    RESPONSE_ROOT,
    SNAPSHOT_ROOT,
    ExecutionRequestError,
    parse_request,
    protocol_feedback_reader_script,
    protocol_readme,
    target_argv,
)
from harness.symbolic.feedback import (
    TRACE_EVENT,
    TRACE_FLAG_COMPLETE,
    TRACE_FLAG_TARGET_REACHED,
    TRACE_FLAG_TARGETS_CONFIGURED,
    TRACE_HEADER,
    TRACE_MAGIC,
    load_json_map_files,
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


def _patch_sidecar(
    monkeypatch, *, trace_bytes=None, generated_seed=b"mutated", oom_kill_count=0
):
    """Mock Docker while exercising the real sidecar request orchestration."""
    target = _target()
    mounts = {}
    run_specs = {}
    binary_calls = []
    removed = []
    writes = {}

    def fake_run(image_tag, name, **kwargs):
        params = kwargs["run_params"]
        assert image_tag == target.runtime_image_tag
        assert params.mounts and len(params.mounts) == 1
        mounts[name] = Path(params.mounts[0].source)
        run_specs[name] = (kwargs, params)
        return name

    def fake_exec(container, command, timeout=0):
        if command == "cat /sys/fs/cgroup/memory.events":
            return 0, (
                f"low 0\nhigh 0\nmax 0\noom 0\noom_kill {oom_kill_count}\n"
            ), ""
        if command.startswith("readlink -f"):
            return 0, f"{INPUT_ROOT}/candidate.bin\n", ""
        if command.startswith("stat -c"):
            return 0, "4\n", ""
        return 0, "", ""

    def fake_read(_container, path):
        if path == f"{INPUT_ROOT}/candidate.bin":
            return b"seed"
        if path.startswith("/symcc-job/traces/"):
            root = mounts[_container]
            relative = Path(path).relative_to("/symcc-job")
            try:
                return (root / relative).read_bytes()
            except OSError:
                return b""
        return b""

    def fake_write(_container, path, data):
        writes[path] = data

    def fake_binary(*, container, binary, request, input_path,
                    symcc_output=None, extra_env=None):
        extra_env = dict(extra_env or {})
        binary_calls.append({
            "container": container, "binary": binary, "input_path": input_path,
            "symcc_output": symcc_output, "extra_env": extra_env,
        })
        if container == "target":
            is_crash = ".harness-clean-target" in binary
            input_data = b"seed"
        else:
            root = mounts[container]
            guest_input = Path(input_path).relative_to("/symcc-job")
            input_data = (root / guest_input).read_bytes()
            if "SYMCC_FEEDBACK_TRACE" in extra_env:
                trace_file = Path(extra_env["SYMCC_FEEDBACK_TRACE"])
                host_trace = root / trace_file.relative_to("/symcc-job")
                host_trace.parent.mkdir(parents=True, exist_ok=True)
                host_trace.write_bytes(trace_bytes or b"")
            if symcc_output == "/symcc-job/symcc-results":
                if oom_kill_count:
                    return {
                        "status": "failed", "exit_code": 137, "duration_s": 0.1,
                        "stdout": "", "stderr": "", "output_tail": "",
                        "sanitizer_event": False,
                    }
                output_root = root / "symcc-results"
                output_root.mkdir(parents=True, exist_ok=True)
                (output_root / "testcase-000").write_bytes(generated_seed)
            is_crash = binary == "/out/target" and input_data == generated_seed
        binary_calls[-1]["input_bytes"] = input_data
        output = "AddressSanitizer: heap-use-after-free\n" if is_crash else "ok\n"
        return {
            "status": "failed" if is_crash else "completed",
            "exit_code": 1 if is_crash else 0,
            "duration_s": 0.01,
            "stdout": "", "stderr": output, "output_tail": output,
            "sanitizer_event": is_crash,
        }

    monkeypatch.setattr(docker_ops, "run", fake_run)
    monkeypatch.setattr(docker_ops, "rm", removed.append)
    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(docker_ops, "read_file", fake_read)
    monkeypatch.setattr(docker_ops, "write_file", fake_write)
    monkeypatch.setattr(dynamic_validation, "_run_protocol_binary", fake_binary)
    return target, run_specs, binary_calls, removed, writes


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


def test_parse_execution_request_preserves_parent_input_provenance():
    value = _request(parent_input_id="round-previous")
    parsed = parse_request(json.dumps(value))
    assert parsed.parent_input_id == "round-previous"
    with pytest.raises(ExecutionRequestError, match="parent_input_id"):
        parse_request(json.dumps(_request(parent_input_id="../../bad")))


def test_target_argv_keeps_arguments_separate_and_substitutes_input():
    argv = target_argv(
        "/out/target", ("--input", "{input_file}", "--label", "two words"),
        f"{INPUT_ROOT}/seed.bin",
    )
    assert argv == [
        "/out/target", "--input", f"{INPUT_ROOT}/seed.bin",
        "--label", "two words",
    ]


@pytest.mark.parametrize(
    ("return_code", "timeout_s", "elapsed", "expected_status"),
    [
        (137, 120, 120.1, "timed_out"),
        (137, 120, 0.1, "failed"),
        (124, 2, 2.1, "timed_out"),
    ],
)
def test_protocol_binary_distinguishes_deadline_kill_from_other_failure(
    monkeypatch, return_code, timeout_s, elapsed, expected_status,
):
    clock = iter((100.0, 100.0 + elapsed))
    monkeypatch.setattr(dynamic_validation.time, "time", lambda: next(clock))
    monkeypatch.setattr(
        docker_ops,
        "exec_sh",
        lambda *_args, **_kwargs: (return_code, "", "killed"),
    )
    request = parse_request(json.dumps(_request(timeout_s=timeout_s)))

    result = _run_protocol_binary(
        container="symcc-sidecar", binary="/out/target-symcc",
        request=request, input_path=request.input_path,
    )

    assert result["status"] == expected_status
    assert result["timed_out"] is (expected_status == "timed_out")


def test_protocol_runs_same_input_through_both_binaries_and_replays_generated(
    monkeypatch,
):
    target, run_specs, binary_calls, removed, writes = _patch_sidecar(monkeypatch)

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
    assert response["input_trace_execution"]["status"] == "completed"
    assert response["snapshot_path"] == f"{SNAPSHOT_ROOT}/round-001.bin"
    assert writes[response["snapshot_path"]] == b"seed"
    assert response["generated_replays"][0]["replay"]["sanitizer_event"] is True
    assert writes[f"{INPUT_ROOT}/symcc-round-001-000.bin"] == b"mutated"
    symcc_calls = [call for call in binary_calls if call["binary"] == "/out/target-symcc"]
    assert len(symcc_calls) == 3  # submitted trace, symbolic exploration, seed trace
    assert all(call["container"] != "target" for call in symcc_calls)
    assert [call["input_bytes"] for call in symcc_calls] == [b"seed", b"seed", b"mutated"]
    assert "SYMCC_NO_SYMBOLIC_INPUT" in symcc_calls[0]["extra_env"]
    assert "SYMCC_FEEDBACK_TRACE" not in symcc_calls[1]["extra_env"]
    trace_calls = [
        call for call in symcc_calls
        if "SYMCC_FEEDBACK_TRACE" in call["extra_env"]
    ]
    assert len(trace_calls) == 2
    assert all(
        call["extra_env"]["SYMCC_FEEDBACK_CAPACITY"] == "1000000"
        for call in trace_calls
    )
    assert symcc_calls[0]["input_path"] == "/symcc-job/input.bin"
    assert any(call["binary"] == "/out/.harness-clean-target" for call in binary_calls)
    assert any(call["binary"] == "/out/target" for call in binary_calls)
    assert len(run_specs) == 1
    run_kwargs, run_params = next(iter(run_specs.values()))
    assert run_kwargs["network"] == "none"
    assert run_params.network == "none"
    assert run_params.memory == "4g"
    assert run_params.cpus == "2"
    assert run_params.mounts[0].target == "/symcc-job"
    assert run_params.mounts[0].read_only is False
    assert run_params.entrypoint == ("/bin/sh",)
    assert run_params.command[0] == "-c"
    assert removed == list(run_specs)


def test_symcc_sidecar_marks_oom_without_confusing_it_with_a_valid_miss(monkeypatch):
    target, _run_specs, _calls, _removed, _writes = _patch_sidecar(
        monkeypatch, oom_kill_count=1
    )
    response = _execute_prebuilt_protocol_request(
        container="target", target=target,
        raw=json.dumps(_request()).encode(),
        filename="round-001.json", round_id=1,
    )
    assert response["symcc"]["status"] == "resource_exhausted"
    assert response["symcc"]["worker"]["oom_kill_count"] == 1
    assert response["symcc_observation"]["target_reachability"] == "unknown"
    assert response["generated_replays"] == []


def test_symcc_sidecar_settings_have_safe_defaults_and_validate_limits():
    assert _symcc_sidecar_settings({}) == ("4g", "2", 1)
    assert _symcc_sidecar_settings({
        "memory_limit": "2048m", "cpus": 1.5, "max_concurrent_jobs": 3,
    }) == ("2048m", "1.5", 3)
    for config in (
        {"memory_limit": "0g"},
        {"cpus": 0},
        {"cpus": 65},
        {"max_concurrent_jobs": 0},
        {"max_concurrent_jobs": True},
    ):
        with pytest.raises(ValueError):
            _symcc_sidecar_settings(config)


def test_protocol_returns_exact_target_hit_and_source_distance_per_input(monkeypatch):
    target = _target()
    map_record = json.loads('''{"schema_version":1,"module_id":"src/x.c",
      "source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "function":"parse","blocks":[
      {"id":100,"entry":true,"exit":false,"successors":[200],
       "source_locations":[{"id":1000,"source_file":"src/x.c",
        "source_function":"parse","line":1,"column":1}],"calls":[]},
      {"id":200,"entry":false,"exit":true,"successors":[],
       "source_locations":[{"id":2000,"source_file":"src/x.c",
        "source_function":"parse","line":2,"column":1}],"calls":[]}]}''')
    site_map = load_json_map_files([json.dumps(map_record)])
    feedback_runtime = {
        "status": "ready", "source_commit": "a" * 40,
        "goal": {"targets": [{"source_file": "src/x.c", "line": 2}]},
        "marker_ids": [2000], "target_block_ids": [200], "graph": site_map,
    }
    target_trace = (
        TRACE_HEADER.pack(
            TRACE_MAGIC, 1, TRACE_HEADER.size, 8, 2,
            TRACE_FLAG_COMPLETE | TRACE_FLAG_TARGET_REACHED |
            TRACE_FLAG_TARGETS_CONFIGURED, 0,
        )
        + TRACE_EVENT.pack(200, 1, 0)
        + TRACE_EVENT.pack(2000, 2, 0)
    )
    target, _run_specs, binary_calls, _removed, _writes = _patch_sidecar(
        monkeypatch, trace_bytes=target_trace
    )

    response = _execute_prebuilt_protocol_request(
        container="target", target=target,
        raw=json.dumps(_request(parent_input_id="round-000")).encode(),
        filename="round-001.json", round_id=1,
        feedback_runtime=feedback_runtime,
    )
    assert response["input_id"] == response["input_sha256"]
    assert response["parent_input_id"] == "round-000"
    assert response["target_commit"] == target.commit
    assert response["site_reached"] is True
    assert response["symcc_observation"]["distance"] == 0
    assert response["generated_replays"][0]["symcc_observation"]["target_reached"] is True
    assert any(
        call["extra_env"].get("SYMCC_FEEDBACK_TARGET_IDS") == "2000"
        for call in binary_calls
    )
    assert any(
        call["extra_env"].get("SYMCC_NO_SYMBOLIC_INPUT") == "1"
        for call in binary_calls
    )


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
        if "timeout --signal=KILL" in command:
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

    def blocking_symcc(**job_args):
        symcc_started.set()
        if not symcc_release.wait(timeout=5):
            raise TimeoutError("test SymCC wait timed out")
        request = job_args["job"]["request"]
        return {
            "schema_version": 1, "protocol": "dynamic-execution-feedback",
            "request_id": request.request_id,
            "symcc": {"status": "completed", "duration_s": 0.01,
                      "testcase_count": 0},
            "symcc_observation": {"status": "missing", "target_reached": None},
            "input_trace_execution": {"status": "completed", "exit_code": 0},
            "generated_replays": [],
        }

    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(docker_ops, "read_file", fake_read)
    monkeypatch.setattr(docker_ops, "write_file", fake_write)
    monkeypatch.setattr(
        dynamic_validation, "_execute_prebuilt_protocol_symcc_request",
        blocking_symcc,
    )

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
        assert "stderr" not in feedback["symcc"]

        stop.set()
        summary = await asyncio.wait_for(worker, timeout=3)
        assert summary["requests"] == 1
        assert summary["symcc_errors"] == 0

    asyncio.run(exercise())


def test_compact_protocol_feedback_keeps_facts_and_bounds_observations():
    record = {
        "request_id": "round-001",
        "input_id": "a" * 64,
        "feedback_status": "ready",
        "clean": {"status": "completed", "exit_code": 0, "sanitizer_event": False},
        "symcc": {"status": "completed", "duration_s": 1.2, "testcase_count": 10,
                  "stderr": "large solver log"},
        "symcc_observation": {
            "trace_status": "completed", "target_reached": False,
            "target_reachability": "this_execution_missed", "distance": 7,
            "distance_is_heuristic": True,
            "observed_locations": [{"line": line} for line in range(30)],
        },
        "generated_replays": [
            {
                "path": f"/work/validation/inputs/seed-{index}",
                "size": 4,
                "sha256": str(index),
                "replay": {"status": "completed", "exit_code": 0,
                           "sanitizer_event": False, "stdout": "unbounded"},
                "symcc_observation": {
                    "trace_status": "completed", "target_reached": False,
                    "distance": 7,
                    "observed_locations": [{"line": line} for line in range(30)],
                },
            }
            for index in range(10)
        ],
    }
    compact = _compact_protocol_feedback(record)
    assert compact["symcc_observation"]["target_reached"] is False
    assert compact["symcc_observation"]["distance_is_heuristic"] is True
    assert compact["symcc_observation"]["observed_location_count"] == 30
    assert len(compact["symcc_observation"]["observed_locations"]) == 16
    assert len(compact["generated_replays"]) == 8
    assert compact["generated_replays"][0]["symcc_observation"][
        "observed_location_count"
    ] == 30
    assert "observed_locations" not in compact["generated_replays"][0][
        "symcc_observation"
    ]
    assert "stderr" not in compact["symcc"]
    assert "stdout" not in compact["generated_replays"][0]["clean_replay"]


def test_next_protocol_response_auto_delivers_completed_symcc_feedback(monkeypatch):
    target = _target()
    writes = {}
    pending_ids = ["round-001"]
    clean_runs = []
    pending_lock = threading.Lock()
    responses_written = {request_id: threading.Event() for request_id in (
        "round-001", "round-002", "round-003"
    )}
    feedback_written = {request_id: threading.Event() for request_id in (
        "round-001", "round-002"
    )}
    request_values = {
        request_id: _request(
            request_id=request_id,
            input_path=f"{INPUT_ROOT}/candidate.bin",
            parent_input_id="round-001" if request_id in {"round-002", "round-003"} else None,
        )
        for request_id in ("round-001", "round-002", "round-003")
    }

    def fake_exec(_container, command, timeout=0):
        if command.startswith(f"find {PENDING_ROOT}"):
            with pending_lock:
                listing = "".join(f"{PENDING_ROOT}/{item}.json\n" for item in pending_ids)
            return 0, listing, ""
        if command.startswith("readlink -f"):
            return 0, f"{INPUT_ROOT}/candidate.bin\n", ""
        if command.startswith("stat -c"):
            return 0, "4\n", ""
        if command.startswith("test -f"):
            return 0, "", ""
        if command.startswith("timeout --signal=KILL"):
            clean_runs.append(command)
            return 0, "clean target complete", ""
        if command.startswith(f"mv -- {PENDING_ROOT}/"):
            request_id = command.rsplit("/", 1)[-1].removesuffix(".json")
            with pending_lock:
                if request_id in pending_ids:
                    pending_ids.remove(request_id)
            return 0, "", ""
        if command.startswith("mv -- ") and ".tmp " in command:
            source, destination = command.removeprefix("mv -- ").split(" ", 1)
            writes[destination] = writes.pop(source)
            if destination.startswith(FEEDBACK_ROOT + "/"):
                request_id = destination.rsplit("/", 1)[-1].removesuffix(".json")
                feedback_written[request_id].set()
            return 0, "", ""
        return 0, "", ""

    def fake_read(_container, path):
        if path.startswith(PENDING_ROOT + "/"):
            request_id = path.rsplit("/", 1)[-1].removesuffix(".json")
            return json.dumps(request_values[request_id]).encode()
        if path == f"{INPUT_ROOT}/candidate.bin":
            return b"seed"
        return b""

    def fake_write(_container, path, data):
        writes[path] = data
        if path.startswith(RESPONSE_ROOT + "/"):
            request_id = path.rsplit("/", 1)[-1].removesuffix(".json")
            responses_written[request_id].set()

    def fake_symcc(**job_args):
        request = job_args["job"]["request"]
        return {
            "schema_version": 1,
            "protocol": "dynamic-execution",
            "status": "completed",
            "request_id": request.request_id,
            "round_id": job_args["job"]["round_id"],
            "input_id": job_args["job"]["input_id"],
            "target_commit": target.commit,
            "clean": job_args["job"]["clean"],
            "symcc": {"status": "completed", "duration_s": 1.0,
                      "testcase_count": 1},
            "symcc_observation": {
                "trace_status": "completed", "trace_complete": True,
                "target_reached": True, "target_reachability": "this_execution_hit",
                "distance": 0, "distance_is_heuristic": True,
            },
            "generated_replays": [],
        }

    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(docker_ops, "read_file", fake_read)
    monkeypatch.setattr(docker_ops, "write_file", fake_write)
    monkeypatch.setattr(
        "harness.dynamic_validation._execute_prebuilt_protocol_symcc_request",
        fake_symcc,
    )

    async def exercise():
        stop = asyncio.Event()
        worker = asyncio.create_task(_prebuilt_protocol_worker(
            container="target", target=target, stop=stop, result_path=None,
            max_requests=2,
        ))
        assert await asyncio.to_thread(responses_written["round-001"].wait, 3)
        assert await asyncio.to_thread(feedback_written["round-001"].wait, 3)

        with pending_lock:
            pending_ids.append("round-002")
        assert await asyncio.to_thread(responses_written["round-002"].wait, 3)
        response = json.loads(writes[f"{RESPONSE_ROOT}/round-002.json"])
        assert response["ready_feedback"][0]["request_id"] == "round-001"
        assert response["ready_feedback"][0]["symcc_observation"]["target_reached"] is True
        assert response["ready_feedback"][0]["symcc_observation"]["distance"] == 0
        assert await asyncio.to_thread(feedback_written["round-002"].wait, 3)

        with pending_lock:
            pending_ids.append("round-003")
        assert await asyncio.to_thread(responses_written["round-003"].wait, 3)
        limited = json.loads(writes[f"{RESPONSE_ROOT}/round-003.json"])
        assert limited["status"] == "iteration_limit_reached"
        assert limited["accepted_requests"] == 2
        assert len(clean_runs) == 2

        stop.set()
        summary = await asyncio.wait_for(worker, timeout=3)
        assert summary["feedback_auto_delivered"] == 2
        assert summary["requests"] == 2
        assert summary["iteration_limit"] == 2
        assert summary["iteration_limit_rejections"] == 1

    asyncio.run(exercise())


def test_protocol_worker_queues_all_inputs_with_bounded_symcc_concurrency(monkeypatch):
    target = _target()
    target.symbolic_execution["symcc"]["max_concurrent_jobs"] = 2
    request_ids = ["round-001", "round-002", "round-003"]
    pending_ids = list(request_ids)
    writes = {}
    pending_lock = threading.Lock()
    responses_written = {request_id: threading.Event() for request_id in request_ids}
    feedback_written = {request_id: threading.Event() for request_id in request_ids}
    symcc_started = threading.Event()
    release_symcc = threading.Event()
    active = 0
    max_active = 0
    started_ids = []
    active_lock = threading.Lock()
    request_values = {
        request_id: _request(
            request_id=request_id,
            input_path=f"{INPUT_ROOT}/candidate.bin",
            parent_input_id=None if request_id == "round-001" else request_ids[
                request_ids.index(request_id) - 1
            ],
        )
        for request_id in request_ids
    }

    def fake_exec(_container, command, timeout=0):
        if command.startswith(f"find {PENDING_ROOT}"):
            with pending_lock:
                listing = "".join(f"{PENDING_ROOT}/{item}.json\n" for item in pending_ids)
            return 0, listing, ""
        if command.startswith("readlink -f"):
            return 0, f"{INPUT_ROOT}/candidate.bin\n", ""
        if command.startswith("stat -c"):
            return 0, "4\n", ""
        if command.startswith("test -f") or command.startswith("timeout --signal=KILL"):
            return 0, "clean target complete", ""
        if command.startswith(f"mv -- {PENDING_ROOT}/"):
            request_id = command.rsplit("/", 1)[-1].removesuffix(".json")
            with pending_lock:
                if request_id in pending_ids:
                    pending_ids.remove(request_id)
            return 0, "", ""
        if command.startswith("mv -- ") and ".tmp " in command:
            source, destination = command.removeprefix("mv -- ").split(" ", 1)
            writes[destination] = writes.pop(source)
            request_id = destination.rsplit("/", 1)[-1].removesuffix(".json")
            feedback_written[request_id].set()
            return 0, "", ""
        return 0, "", ""

    def fake_read(_container, path):
        if path.startswith(PENDING_ROOT + "/"):
            request_id = path.rsplit("/", 1)[-1].removesuffix(".json")
            return json.dumps(request_values[request_id]).encode()
        if path == f"{INPUT_ROOT}/candidate.bin":
            return b"seed"
        return b""

    def fake_write(_container, path, data):
        writes[path] = data
        if path.startswith(RESPONSE_ROOT + "/"):
            request_id = path.rsplit("/", 1)[-1].removesuffix(".json")
            responses_written[request_id].set()

    def blocking_symcc(**job_args):
        nonlocal active, max_active
        request_id = job_args["job"]["request"].request_id
        with active_lock:
            active += 1
            max_active = max(max_active, active)
            started_ids.append(request_id)
            if active == 2:
                symcc_started.set()
        if not release_symcc.wait(timeout=5):
            raise TimeoutError("test SymCC job was not released")
        with active_lock:
            active -= 1
        return {
            "schema_version": 1,
            "protocol": "dynamic-execution-feedback",
            "request_id": request_id,
            "symcc": {"status": "completed", "duration_s": 0.01},
            "symcc_observation": {
                "trace_status": "completed", "trace_complete": True,
                "target_reached": False,
                "target_reachability": "this_execution_missed", "distance": 2,
            },
            "generated_replays": [],
        }

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
            max_requests=3,
        ))
        for request_id in request_ids:
            assert await asyncio.to_thread(responses_written[request_id].wait, 3)
            response = json.loads(writes[f"{RESPONSE_ROOT}/{request_id}.json"])
            assert response["status"] == "submitted"
            assert response["symcc"]["status"] == "queued"
        assert await asyncio.to_thread(symcc_started.wait, 3)
        await asyncio.sleep(0.05)
        with active_lock:
            assert len(started_ids) == 2
            assert max_active == 2
        release_symcc.set()
        for request_id in request_ids:
            assert await asyncio.to_thread(feedback_written[request_id].wait, 3)
        stop.set()
        summary = await asyncio.wait_for(worker, timeout=3)
        assert summary["requests"] == 3
        assert summary["symcc_queued"] == 3
        assert summary["symcc_skipped_busy"] == 0
        assert summary["symcc_abandoned"] == 0

    asyncio.run(exercise())


def test_feedback_reader_is_nonblocking_and_validates_request_id():
    script = protocol_feedback_reader_script().decode()
    assert '"status":"pending"' in script
    assert "sleep" not in script
    assert '[ "${#id}" -le 80 ]' in script
    assert "read-feedback REQUEST_ID" in script
    readme = protocol_readme(symbolic_enabled=True).decode()
    assert "ready_feedback" in readme
    assert "at most 8 input requests" in readme
    assert "iteration_limit_reached" in readme
    assert "Every accepted input is queued for SymCC" in readme
    assert "request-scoped copy" in readme
    assert "mandatory evidence for the next input" in readme
    assert "preserve and print a concise summary" in readme


def test_protocol_worker_does_not_wait_for_unused_symcc_after_agent_finishes(
    monkeypatch,
):
    target = _target()
    pending_path = f"{PENDING_ROOT}/round-001.json"
    response_path = f"{RESPONSE_ROOT}/round-001.json"
    pending_moved = threading.Event()
    response_written = threading.Event()
    symcc_started = threading.Event()
    symcc_cancelled = threading.Event()
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

    def blocking_symcc(**job_args):
        symcc_started.set()
        cancel_event = job_args["job"]["cancel_event"]
        assert cancel_event.wait(timeout=5)
        symcc_cancelled.set()
        return {"symcc": {"status": "completed"}}

    removed = []
    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec)
    monkeypatch.setattr(docker_ops, "read_file", fake_read)
    monkeypatch.setattr(docker_ops, "write_file", fake_write)
    monkeypatch.setattr(docker_ops, "rm", removed.append)
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
        assert await asyncio.to_thread(symcc_cancelled.wait, 2)
        assert removed and removed[0].startswith("symcc-fb-sample-")

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
