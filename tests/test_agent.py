# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""run_agent with the opencode backend: clean completion returns without
resume; opencode `error` events route through the resume path (bounded by
max_resume_attempts). No docker — the opencode process is faked at
asyncio.create_subprocess_exec."""

from __future__ import annotations

import asyncio
import json

from harness import docker_ops
from harness.agent import (
    _is_unbounded_helper_process,
    _model_config,
    _opencode_model,
    _unbounded_helper_processes,
    run_agent,
)


class _FakeStdout:
    def __init__(self, msgs: list[dict]):
        self._lines = [json.dumps(m).encode() + b"\n" for m in msgs]

    def __aiter__(self):
        async def gen():
            for line in self._lines:
                yield line

        return gen()


class _FakeProc:
    def __init__(self, msgs: list[dict], rc: int = 0):
        self.stdout = _FakeStdout(msgs)
        self.stderr = None
        self.returncode: int | None = None
        self._rc = rc

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9

    async def wait(self) -> int:
        if self.returncode is None:
            self.returncode = self._rc
        return self.returncode


def _fake_cli(monkeypatch, per_attempt_msgs: list[list[dict]]) -> list[list[str]]:
    """Each spawn serves the next message list; returns the captured argvs."""
    spawned: list[list[str]] = []

    async def fake_exec(*cmd, **kwargs):
        spawned.append(list(cmd))
        return _FakeProc(per_attempt_msgs[len(spawned) - 1])

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    async def no_sleep(_):
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)

    # No real container: the per-phase agent-file injection must be a no-op.
    monkeypatch.setattr(docker_ops, "exec_sh", lambda *a, **k: (0, "", ""))
    monkeypatch.setattr(docker_ops, "write_file", lambda *a, **k: None)
    return spawned


_STEP_START = {"type": "step_start", "sessionID": "ses-1",
               "part": {"type": "step-start"}}
_TEXT = {"type": "text", "sessionID": "ses-1",
         "part": {"type": "text", "messageID": "msg-1", "text": "done"}}
_STEP_FINISH = {"type": "step_finish", "sessionID": "ses-1",
                "part": {"type": "step-finish", "messageID": "msg-1", "reason": "stop"}}


def test_clean_completion_returns_without_resume(monkeypatch):
    spawned = _fake_cli(monkeypatch, [[_STEP_START, _TEXT, _STEP_FINISH]])
    result = asyncio.run(run_agent("go", container="c", max_turns=50, model="m"))
    assert len(spawned) == 1
    assert result.error is None
    assert result.session_id == "ses-1"
    assert "opencode" in spawned[0]
    assert "--format" in spawned[0] and "json" in spawned[0]
    assert "--auto" in spawned[0]
    # Tag not found → falls back to the last assistant message
    assert result.find_tagged_message("nothing") == "done"


def test_error_event_resumes(monkeypatch):
    err = {"type": "error", "sessionID": "ses-1",
           "error": {"name": "UnknownError", "data": {"message": "boom"}}}
    spawned = _fake_cli(
        monkeypatch,
        [[_STEP_START, err], [_STEP_START, _TEXT, _STEP_FINISH]],
    )
    result = asyncio.run(
        run_agent("go", container="c", max_turns=50, model="m", max_resume_attempts=1)
    )
    assert len(spawned) == 2  # first attempt + one resume
    assert "--session" in spawned[1] and "ses-1" in spawned[1]
    assert result.resume_count == 1
    assert result.error is None  # resumed cleanly


def test_resume_exhausted_preserves_error(monkeypatch):
    err = {"type": "error", "sessionID": "ses-1",
           "error": {"name": "UnknownError", "data": {"message": "boom"}}}
    spawned = _fake_cli(monkeypatch, [[_STEP_START, err], [_STEP_START, err]])
    result = asyncio.run(
        run_agent("go", container="c", max_turns=50, model="m", max_resume_attempts=1)
    )
    assert len(spawned) == 2
    assert result.resume_count == 1
    assert result.error and "boom" in result.error


def test_find_tagged_message_scans_open_code_events(monkeypatch):
    tagged = {"type": "text", "sessionID": "ses-1",
              "part": {"type": "text", "messageID": "msg-2",
                       "text": "prefix <poc_path>/work/x.syz</poc_path> suffix"}}
    spawned = _fake_cli(monkeypatch, [[_STEP_START, _TEXT, tagged, _STEP_FINISH]])
    result = asyncio.run(run_agent("go", container="c", max_turns=50, model="m"))
    assert result.find_tagged_message("poc_path") == "prefix <poc_path>/work/x.syz</poc_path> suffix"


def test_deepseek_flash_model_alias_config():
    assert _opencode_model("deepseek-flash") == "deepseek/deepseek-flash"
    assert _opencode_model("deepseek/deepseek-flash") == "deepseek/deepseek-flash"
    assert _model_config("deepseek/deepseek-v4-flash") is None
    config = json.loads(_model_config("deepseek/deepseek-flash"))
    assert config["provider"]["deepseek"]["models"]["deepseek-flash"]["name"] == "DeepSeek Flash"


def test_run_agent_normalizes_short_deepseek_model(monkeypatch):
    spawned = _fake_cli(monkeypatch, [[_STEP_START, _TEXT, _STEP_FINISH]])
    asyncio.run(
        run_agent("go", container="c", max_turns=1, model="deepseek-flash")
    )
    assert "-e" in spawned[0]
    assert "OPENCODE_CONFIG=/tmp/vuln-pipeline-opencode.json" in spawned[0]
    assert spawned[0][spawned[0].index("--model") + 1] == "deepseek/deepseek-flash"


class _BlockingStdout:
    def __init__(self):
        self.released = asyncio.Event()

    def __aiter__(self):
        return self

    async def __anext__(self):
        await self.released.wait()
        raise StopAsyncIteration


class _BlockingProc:
    def __init__(self):
        self.stdout = _BlockingStdout()
        self.stderr = None
        self.returncode: int | None = None

    def kill(self) -> None:
        self.returncode = -9
        self.stdout.released.set()

    def terminate(self) -> None:
        self.kill()

    async def wait(self) -> int:
        if self.returncode is None:
            await self.stdout.released.wait()
            self.returncode = -9
        return self.returncode


def _fake_blocking_cli(monkeypatch):
    spawned: list[list[str]] = []

    async def fake_exec(*cmd, **kwargs):
        spawned.append(list(cmd))
        return _BlockingProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(docker_ops, "exec_sh", lambda *a, **k: (0, "", ""))
    monkeypatch.setattr(docker_ops, "write_file", lambda *a, **k: None)
    return spawned


def test_watchdog_marks_model_blocked_when_stream_and_tools_stall(monkeypatch):
    _fake_blocking_cli(monkeypatch)
    monkeypatch.setattr(docker_ops, "process_snapshot", lambda container: [])
    result = asyncio.run(
        run_agent(
            "go",
            container="c",
            max_turns=1,
            model="m",
            max_resume_attempts=0,
            phase_timeout_s=1,
            idle_timeout_s=0.01,
            watchdog_interval_s=0.05,
        )
    )
    assert result.error and result.error.startswith("agent/model_blocked:")


def test_watchdog_marks_unbounded_helper_blocked(monkeypatch):
    _fake_blocking_cli(monkeypatch)
    monkeypatch.setattr(
        docker_ops,
        "process_snapshot",
        lambda container: ["166 1 S python3 /tmp/socks5srv.py"],
    )
    result = asyncio.run(
        run_agent(
            "go",
            container="c",
            max_turns=1,
            model="m",
            max_resume_attempts=0,
            phase_timeout_s=1,
            idle_timeout_s=1,
            helper_timeout_s=0.01,
            watchdog_interval_s=0.05,
        )
    )
    assert result.error and result.error.startswith("agent/helper_blocked:")


def test_helper_detection_does_not_flag_bounded_commands_or_qemu():
    assert _is_unbounded_helper_process("166 1 S python3 /tmp/server.py")
    assert not _is_unbounded_helper_process(
        "166 1 S timeout 60s python3 /tmp/server.py"
    )
    assert not _is_unbounded_helper_process(
        "166 1 S qemu-system-x86_64 -kernel /work/vmlinuz"
    )
    assert not _is_unbounded_helper_process(
        "166 1 R /out/mruby_fuzzer -max_total_time=1500 -timeout=5 /tmp/corpus"
    )
    assert not _is_unbounded_helper_process(
        "166 1 S /usr/bin/bash -c cd /tmp && /out/mruby_fuzzer -max_total_time=1500"
    )


def test_watchdog_does_not_misclassify_timeout_wrapped_helper_children():
    processes = [
        "100 1 S /usr/bin/bash -c cd /tmp && timeout 900 python3 scan.py | tail -10",
        "101 100 S timeout 900 python3 scan.py",
        "102 101 R python3 scan.py",
        "103 1 S python3 unbounded_server.py",
    ]
    assert _unbounded_helper_processes(processes) == [
        "103 1 S python3 unbounded_server.py"
    ]
