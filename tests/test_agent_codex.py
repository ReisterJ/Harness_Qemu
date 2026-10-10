# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""codex backend: event normalization, argv mapping and run loop — no docker.

The CLI process is faked at ``asyncio.create_subprocess_exec`` exactly like
``tests/test_agent.py``; container-side calls go through a monkeypatched
``docker_ops``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from harness import docker_ops
from harness.agent import agent_backend, run_agent
from harness.agent_codex import (
    codex_argv,
    codex_model,
    normalize_codex_event,
    run_agent_codex,
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
    spawned: list[list[str]] = []

    async def fake_exec(*cmd, **kwargs):
        spawned.append(list(cmd))
        return _FakeProc(per_attempt_msgs[len(spawned) - 1])

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    async def no_sleep(_):
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)

    calls: list[tuple[str, str]] = []

    def fake_exec_sh(container, command, timeout=0):
        calls.append((container, command))
        return 0, "", ""

    monkeypatch.setattr(docker_ops, "exec_sh", fake_exec_sh)
    monkeypatch.setattr(docker_ops, "write_file", lambda *a, **k: None)
    return spawned


THREAD = {"type": "thread.started", "thread_id": "tid-1"}
TURN_OK = {
    "type": "turn.completed",
    "usage": {"input_tokens": 10, "cached_input_tokens": 4, "output_tokens": 2},
}


def _message(text: str = "done", iid: str = "i1") -> dict:
    return {
        "type": "item.completed",
        "item": {"id": iid, "type": "agent_message", "text": text},
    }


def _command(command: str = "pwd", output: str = "/work", code: int = 0,
             iid: str = "c1") -> dict:
    return {
        "type": "item.completed",
        "item": {
            "id": iid, "type": "command_execution", "command": command,
            "aggregated_output": output, "exit_code": code, "status": "completed",
        },
    }


# ── normalization ─────────────────────────────────────────────────────────────


def test_normalize_thread_and_agent_message():
    thread = normalize_codex_event(THREAD)
    assert thread["session_id"] == "tid-1"
    assert thread["emit"] is None

    msg = normalize_codex_event(_message("hello"))
    emit = msg["emit"]
    assert emit["type"] == "text" and emit["backend"] == "codex"
    assert emit["part"]["type"] == "text"
    assert emit["part"]["text"] == "hello"
    assert msg["step"] is True


def test_normalize_command_execution_matches_opencode_shape():
    norm = normalize_codex_event(_command("id", "uid=0", 0))
    emit = norm["emit"]
    assert emit["type"] == "tool_use"
    part = emit["part"]
    # The analysis tooling reads these exact paths (see the audit scanner):
    assert part["type"] == "tool"
    assert part["tool"] == "bash"
    assert part["state"]["input"]["command"] == "id"
    assert part["state"]["output"] == "uid=0"
    assert part["state"]["metadata"]["exit_code"] == 0
    assert part["state"]["time"]["start"] <= part["state"]["time"]["end"]
    assert norm["step"] is True


def test_normalize_file_change_reasoning_and_error_item():
    change = {
        "type": "item.completed",
        "item": {
            "id": "f1", "type": "file_change",
            "changes": [{"path": "/work/poc.c", "kind": "add"}],
            "status": "completed",
        },
    }
    part = normalize_codex_event(change)["emit"]["part"]
    assert part["tool"] == "edit"
    assert part["input"]["filePath"] == "/work/poc.c"

    reasoning = {
        "type": "item.completed",
        "item": {"id": "r1", "type": "reasoning", "text": "thinking"},
    }
    emit = normalize_codex_event(reasoning)["emit"]
    assert emit["part"]["type"] == "reasoning"
    assert emit["part"]["text"] == "thinking"

    item_error = {
        "type": "item.completed",
        "item": {"id": "e1", "type": "error", "message": "tool failed"},
    }
    emit = normalize_codex_event(item_error)["emit"]
    assert emit["type"] == "error"
    assert emit["error"]["name"] == "CodexItemError"
    assert "tool failed" in emit["error"]["data"]["message"]


def test_normalize_fatal_events_and_unknown_types():
    failed = {"type": "turn.failed", "error": {"message": "context window"}}
    assert "context window" in normalize_codex_event(failed)["fatal"]

    stream_error = {"type": "error", "message": "stream broke"}
    norm = normalize_codex_event(stream_error)
    assert "stream broke" in norm["fatal"]
    assert norm["emit"]["type"] == "error"

    assert normalize_codex_event({"type": "item.delta"}).get("emit") is None
    assert normalize_codex_event("nonsense")["fatal"] is None


# ── argv / model mapping ──────────────────────────────────────────────────────


def test_codex_argv_shape(monkeypatch):
    monkeypatch.delenv("VULN_PIPELINE_CODEX_PROVIDER", raising=False)
    argv = codex_argv("c", "go", model="gpt-5-codex")
    assert argv[:4] == ["docker", "exec", "-i", "-w"]
    assert "codex" in argv and "exec" in argv
    assert "--json" in argv
    assert "--skip-git-repo-check" in argv
    assert "--dangerously-bypass-approvals-and-sandbox" in argv
    assert argv[argv.index("-m") + 1] == "gpt-5-codex"
    assert argv[-1] == "go"

    resumed = codex_argv("c", "go on", model="gpt-5-codex", resume_thread="tid-1")
    assert resumed[resumed.index("resume") + 1] == "tid-1"


def test_codex_provider_flag(monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_CODEX_PROVIDER", "deepseek")
    argv = codex_argv("c", "go", model="deepseek-flash")
    assert "model_provider=deepseek" in argv


def test_codex_model_mapping(monkeypatch, capsys):
    monkeypatch.delenv("VULN_PIPELINE_CODEX_MODEL", raising=False)
    assert codex_model("gpt-5-codex") == "gpt-5-codex"
    assert codex_model("openai/gpt-5-codex") == "gpt-5-codex"
    # luna is the backend default, both bare and as an alias.
    assert codex_model(None) == "gpt-6-luna"
    assert codex_model("") == "gpt-6-luna"
    assert codex_model("luna") == "gpt-6-luna"
    assert codex_model("gpt-6-luna") == "gpt-6-luna"
    # A provider-prefixed string codex cannot serve falls back to the default
    # with a warning instead of failing the run.
    assert codex_model("deepseek/deepseek-flash") == "gpt-6-luna"
    assert "not a codex model id" in capsys.readouterr().err
    monkeypatch.setenv("VULN_PIPELINE_CODEX_MODEL", "luna")
    assert codex_model("deepseek/deepseek-flash") == "gpt-6-luna"
    monkeypatch.setenv("VULN_PIPELINE_CODEX_MODEL", "gpt-6-astra")
    assert codex_model("deepseek/deepseek-flash") == "gpt-6-astra"


def test_backend_selection(monkeypatch):
    monkeypatch.delenv("VULN_PIPELINE_AGENT_BACKEND", raising=False)
    assert agent_backend() == "opencode"
    monkeypatch.setenv("VULN_PIPELINE_AGENT_BACKEND", "codex")
    assert agent_backend() == "codex"
    monkeypatch.setenv("VULN_PIPELINE_AGENT_BACKEND", "warp")
    with pytest.raises(ValueError, match="unknown agent backend"):
        agent_backend()


def test_run_agent_dispatches_to_codex(monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_AGENT_BACKEND", "codex")
    captured: dict = {}

    async def fake_codex(prompt, **kwargs):
        captured["prompt"] = prompt
        captured.update(kwargs)
        return "sentinel"

    monkeypatch.setattr("harness.agent_codex.run_agent_codex", fake_codex)

    async def go():
        return await run_agent("go", container="c", max_turns=7, model="m")

    assert asyncio.run(go()) == "sentinel"
    assert captured["prompt"] == "go"
    assert captured["container"] == "c"
    assert captured["max_turns"] == 7


# ── run loop ─────────────────────────────────────────────────────────────────


def test_run_codex_clean_completion(monkeypatch, tmp_path):
    spawned = _fake_cli(monkeypatch, [[THREAD, _message("hi"), TURN_OK]])
    transcript = tmp_path / "dynamic_transcript.jsonl"

    async def go():
        return await run_agent_codex(
            "go", container="c", max_turns=None, model="gpt-5-codex",
            transcript_path=str(transcript),
        )

    result = asyncio.run(go())
    assert result.error is None
    assert result.session_id == "tid-1"
    assert spawn_from(spawned[0]) == "codex"
    assert result.find_tagged_message("nothing") == "hi"
    assert result.assistant_message_count == 1 and result.tool_call_count == 0

    written = [json.loads(line) for line in transcript.read_text().splitlines()]
    assert written[0]["type"] == "text" and written[0]["backend"] == "codex"
    assert written[0]["sessionID"] == "tid-1"
    raw = Path(str(transcript).replace(".jsonl", ".raw.jsonl"))
    assert raw.exists() and '"thread.started"' in raw.read_text()


def spawn_from(argv: list[str]) -> str:
    """CLI name inside ``docker exec ... -- <container> <cli> ...``."""
    return argv[argv.index("--") + 2]


def test_run_codex_resumes_thread_on_error(monkeypatch):
    stream_error = {"type": "error", "message": "boom"}
    spawned = _fake_cli(
        monkeypatch, [[THREAD, stream_error], [_message("recovered")]],
    )

    async def go():
        return await run_agent_codex("go", container="c", max_turns=None,
                                     model="gpt-5-codex")

    result = asyncio.run(go())
    assert result.error is None
    assert result.resume_count == 1
    assert len(spawned) == 2
    assert "resume" in spawned[1]
    assert spawned[1][spawned[1].index("resume") + 1] == "tid-1"


def test_run_codex_step_cap_terminates(monkeypatch):
    events = [
        THREAD,
        _command("a", iid="c1"),
        _command("b", iid="c2"),
        _command("c", iid="c3"),
    ]
    spawned = _fake_cli(monkeypatch, [events])
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        docker_ops, "exec_sh",
        lambda container, command, timeout=0: (calls.append((container, command)) or (0, "", "")),
    )

    async def go():
        return await run_agent_codex("go", container="c", max_turns=1,
                                     model="gpt-5-codex")

    result = asyncio.run(go())
    assert result.error and "step_limit" in result.error
    kills = [cmd for _, cmd in calls if "kill" in cmd and "codex" in cmd]
    assert kills, "the step cap must terminate the codex process"


def test_run_codex_requires_auth_without_provider(monkeypatch):
    _fake_cli(monkeypatch, [[THREAD, _message("hi")]])
    monkeypatch.delenv("VULN_PIPELINE_CODEX_PROVIDER", raising=False)
    monkeypatch.setattr(docker_ops, "exec_sh",
                        lambda *a, **k: (1, "", "not logged in"))

    async def go():
        return await run_agent_codex("go", container="c", max_turns=None,
                                     model="gpt-5-codex")

    with pytest.raises(RuntimeError, match="not authenticated"):
        asyncio.run(go())


def test_run_codex_skips_auth_probe_with_provider(monkeypatch):
    _fake_cli(monkeypatch, [[THREAD, _message("hi")]])
    monkeypatch.setenv("VULN_PIPELINE_CODEX_PROVIDER", "deepseek")
    seen: list[str] = []
    monkeypatch.setattr(
        docker_ops, "exec_sh",
        lambda container, command, timeout=0: (seen.append(command) or (0, "", "")),
    )

    async def go():
        return await run_agent_codex("go", container="c", max_turns=None,
                                     model="deepseek-flash")

    result = asyncio.run(go())
    assert result.error is None
    assert not any("login status" in cmd for cmd in seen)


def test_prepare_codex_seeds_auth_file(monkeypatch, tmp_path):
    from harness.agent_codex import prepare_codex

    secret = '{"tokens": {"access_token": "x"}}'
    auth = tmp_path / "auth.json"
    auth.write_text(secret)
    monkeypatch.setenv("VULN_PIPELINE_CODEX_AUTH_FILE", str(auth))
    monkeypatch.delenv("VULN_PIPELINE_CODEX_PROVIDER", raising=False)

    written: dict = {}
    commands: list[str] = []
    monkeypatch.setattr(
        docker_ops, "write_file",
        lambda container, path, data: written.__setitem__(path, data),
    )
    monkeypatch.setattr(
        docker_ops, "exec_sh",
        lambda container, command, timeout=0: (commands.append(command) or (0, "", "")),
    )

    prepare_codex("c", "system prompt")
    assert written["/work/.codex/auth.json"].decode() == secret
    assert written["/work/.codex/AGENTS.md"].decode() == "system prompt"
    assert any("chmod 600" in cmd for cmd in commands)
    assert not any("login status" in cmd for cmd in commands)


def test_run_codex_policy_block_is_terminal(monkeypatch):
    blocked = {
        "type": "turn.failed",
        "error": {
            "message": (
                "This content was flagged for possible cybersecurity risk. "
                "If you're doing authorized security work that requires more "
                "cyber permissive safeguards, apply for Daybreak access ..."
            )
        },
    }
    spawned = _fake_cli(monkeypatch, [[THREAD, blocked]])

    async def go():
        return await run_agent_codex("go", container="c", max_turns=None,
                                     model="gpt-6-luna")

    result = asyncio.run(go())
    assert result.error and "policy_blocked" in result.error
    assert len(spawned) == 1, "a policy block must not be retried"
