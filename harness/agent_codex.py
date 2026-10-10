# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""codex `exec` backend for ``run_agent`` (feasibility).

Same contract as the opencode wrapper in ``harness.agent``: inject the
per-phase instructions into the container, run the agent CLI headlessly,
stream its JSONL events, and return an :class:`AgentResult` that the rest of
the pipeline (tag parsing, submissions, transcripts) already understands.

Design notes:

* codex emits a different event schema (``thread.started`` / ``turn.*`` /
  ``item.*``).  We **normalize** every event into the opencode message shape
  (``part.type == "text"`` / ``"tool"``) so ``AgentResult`` consumers and the
  analysis tooling keep working unchanged.  The raw codex events are written
  beside the transcript as ``<name>.raw.jsonl``.
* The agent container is the trust boundary (gVisor on the shipped path), so
  the CLI runs with ``--dangerously-bypass-approvals-and-sandbox`` — the flag
  the CLI documents for externally sandboxed environments.  codex's own
  Landlock/seccomp sandbox is not used.
* codex has no step cap.  ``max_turns`` is enforced here by counting completed
  tool/assistant items and terminating the session at the cap; the phase
  deadline keeps its existing meaning.

Environment knobs:

* ``VULN_PIPELINE_AGENT_BACKEND=codex``  select this backend (see agent.py)
* ``VULN_PIPELINE_CODEX_BIN``            CLI path inside the container
* ``VULN_PIPELINE_CODEX_MODEL``          override the model id (default
  ``gpt-6-luna`` — the fast/affordable Codex model this pipeline uses for
  bulk runs; ``luna`` is accepted as an alias)
* ``VULN_PIPELINE_CODEX_PROVIDER``       ``-c model_provider=<name>``
* ``VULN_PIPELINE_CODEX_CONFIG``         inline ``$CODEX_HOME/config.toml``
* ``VULN_PIPELINE_CODEX_CONFIG_FILE``    config.toml content from a host file
* ``VULN_PIPELINE_CODEX_AUTH_FILE``      host ``auth.json`` copied into
  ``$CODEX_HOME`` (ChatGPT-plan auth; the file is a credential — only set
  it when the containers are treated as trusted execution)
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import sys
import time
from pathlib import Path

from . import docker_ops
from .agent import (
    AgentResult,
    _agent_watchdog,
    _progress_event,
    _truncate_event,
)

CODEX_HOME = "/work/.codex"
DEFAULT_CODEX_BIN = "codex"
# codex caps project docs at 32 KiB by default; the pipeline's system prompts
# are larger, so raise the cap for the instructions file we inject.
PROJECT_DOC_MAX_BYTES = 262144
_RAW_LINE_LIMIT = 262144
_STEP_ITEM_TYPES = ("command_execution", "file_change", "agent_message")


# ──────────────────────────────────────────────────────────────────────────────
# Config / argv
# ──────────────────────────────────────────────────────────────────────────────

def codex_bin() -> str:
    return os.environ.get("VULN_PIPELINE_CODEX_BIN") or DEFAULT_CODEX_BIN


def codex_provider() -> str | None:
    value = (os.environ.get("VULN_PIPELINE_CODEX_PROVIDER") or "").strip()
    return value or None


def codex_auth_file() -> str | None:
    value = os.environ.get("VULN_PIPELINE_CODEX_AUTH_FILE")
    return value or None


def codex_config_toml() -> str | None:
    """config.toml content from VULN_PIPELINE_CODEX_CONFIG{,_FILE}."""
    inline = os.environ.get("VULN_PIPELINE_CODEX_CONFIG")
    if inline and inline.strip():
        return inline
    path = os.environ.get("VULN_PIPELINE_CODEX_CONFIG_FILE")
    if path:
        try:
            return Path(path).read_text()
        except OSError as exc:
            raise ValueError(
                f"VULN_PIPELINE_CODEX_CONFIG_FILE is not readable: {path}: {exc}"
            ) from exc
    return None


DEFAULT_CODEX_MODEL = "gpt-6-luna"
_CODEX_MODEL_ALIASES = {"luna": DEFAULT_CODEX_MODEL}


def _resolve_codex_alias(value: str) -> str:
    return _CODEX_MODEL_ALIASES.get(value, value)


def codex_model(model: str | None) -> str | None:
    """Map the pipeline's model string to a codex model id.

    ``VULN_PIPELINE_CODEX_MODEL`` wins; ``luna`` is an alias for the default
    ``gpt-6-luna``.  ``openai/`` and ``codex/`` prefixes are convenience
    aliases.  A provider-prefixed string that codex cannot serve (for example
    ``deepseek/deepseek-flash`` — codex 0.16x dropped the chat wire API) falls
    back to the default model with a warning instead of failing the run;
    point ``VULN_PIPELINE_CODEX_MODEL`` at a model id (plus
    ``VULN_PIPELINE_CODEX_PROVIDER`` for a custom Responses-API provider) to
    choose something else explicitly.
    """
    override = (os.environ.get("VULN_PIPELINE_CODEX_MODEL") or "").strip()
    if override:
        return _resolve_codex_alias(override)
    if not model or not str(model).strip():
        return DEFAULT_CODEX_MODEL
    value = str(model).strip()
    for prefix in ("openai/", "codex/"):
        if value.startswith(prefix):
            return _resolve_codex_alias(value.split("/", 1)[1])
    if value in _CODEX_MODEL_ALIASES:
        return _CODEX_MODEL_ALIASES[value]
    if "/" in value:
        print(
            f"[agent] codex backend: {value!r} is not a codex model id; using "
            f"{DEFAULT_CODEX_MODEL}. Set VULN_PIPELINE_CODEX_MODEL to override.",
            file=sys.stderr,
        )
        return DEFAULT_CODEX_MODEL
    return value


def codex_argv(container: str, prompt: str, *, model: str | None,
               resume_thread: str | None = None) -> list[str]:
    argv = [
        "docker", "exec", "-i",
        "-w", "/work",
        "-e", f"CODEX_HOME={CODEX_HOME}",
        "--", container, codex_bin(), "exec",
    ]
    if resume_thread:
        argv += ["resume", resume_thread]
    argv += [
        "--json",
        "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox",
        "-c", f"project_doc_max_bytes={PROJECT_DOC_MAX_BYTES}",
    ]
    if provider := codex_provider():
        argv += ["-c", f"model_provider={provider}"]
    if model:
        argv += ["-m", model]
    argv += [prompt]
    return argv


# ──────────────────────────────────────────────────────────────────────────────
# Event normalization (pure — unit tested)
# ──────────────────────────────────────────────────────────────────────────────

def _now_ms() -> int:
    return int(time.time() * 1000)


# Provider-side policy blocks are deterministic: retrying the same prompt on
# the same account cannot succeed and burns the resume budget instead.
_TERMINAL_ERROR_MARKERS = ("cybersecurity risk", "daybreak access")


def is_terminal_codex_error(message: str) -> bool:
    low = (message or "").lower()
    return any(marker in low for marker in _TERMINAL_ERROR_MARKERS)


def _tool_event(item_id: str, tool: str, tool_input: dict, output: str,
                exit_code: int | None, status: str) -> dict:
    state = {
        "status": status,
        "input": tool_input,
        "output": output,
        "metadata": {"exit_code": exit_code},
    }
    now = _now_ms()
    return {
        "type": "tool_use",
        "backend": "codex",
        "part": {
            "type": "tool",
            "tool": tool,
            "callID": item_id,
            "input": tool_input,
            "state": {**state, "time": {"start": now, "end": now}},
            "time": {"start": now, "end": now},
        },
    }


def normalize_codex_event(ev: object) -> dict:
    """Translate one raw codex event into the pipeline's message shape.

    Returns ``{"emit", "session_id", "fatal", "usage", "step", "in_progress"}``:
    ``emit`` is the normalized event (or None), ``step`` counts towards
    ``max_turns``, ``fatal`` marks an unrecoverable error worth a resume.
    """
    result = {"emit": None, "session_id": None, "fatal": None,
              "usage": None, "step": False, "in_progress": False}
    if not isinstance(ev, dict):
        return result
    etype = ev.get("type")

    if etype == "thread.started":
        tid = ev.get("thread_id")
        if isinstance(tid, str) and tid:
            result["session_id"] = tid
        return result

    if etype == "turn.completed":
        usage = ev.get("usage")
        result["usage"] = usage if isinstance(usage, dict) else None
        return result

    if etype == "turn.failed":
        err = ev.get("error") or {}
        msg = err.get("message") if isinstance(err, dict) else None
        result["fatal"] = f"codex turn failed: {msg or 'unknown error'}"
        return result

    if etype == "error":
        msg = str(ev.get("message") or "codex error event")
        result["fatal"] = f"codex error: {msg}"
        result["emit"] = {
            "type": "error", "backend": "codex",
            "error": {"name": "CodexError", "data": {"message": msg}},
        }
        return result

    if etype not in ("item.started", "item.updated", "item.completed"):
        return result
    item = ev.get("item")
    if not isinstance(item, dict):
        return result
    itype = item.get("type")
    iid = str(item.get("id") or "item")
    completed = etype == "item.completed"
    in_progress = not completed
    result["in_progress"] = in_progress

    if itype == "agent_message":
        if not completed:
            return result
        text = item.get("text") or ""
        now = _now_ms()
        result["emit"] = {
            "type": "text", "backend": "codex",
            "part": {
                "type": "text",
                "messageID": f"codex-{iid}",
                "text": text,
                "time": {"start": now, "end": now},
            },
        }
        result["step"] = bool(text.strip())
        return result

    if itype == "reasoning":
        if completed:
            result["emit"] = {
                "type": "reasoning", "backend": "codex",
                "part": {"type": "reasoning", "text": item.get("text") or ""},
            }
        return result

    if itype == "command_execution":
        command = str(item.get("command") or "")
        output = str(item.get("aggregated_output") or "")
        exit_code = item.get("exit_code")
        status = "completed" if completed else str(item.get("status") or "in_progress")
        result["emit"] = _tool_event(
            iid, "bash", {"command": command},
            output if completed else "", exit_code, status,
        )
        result["step"] = completed
        return result

    if itype == "file_change":
        changes = item.get("changes") if isinstance(item.get("changes"), list) else []
        path = ""
        if changes and isinstance(changes[0], dict):
            path = str(changes[0].get("path") or "")
        tool_input = {"filePath": path, "changes": changes}
        status = "completed" if completed else str(item.get("status") or "in_progress")
        result["emit"] = _tool_event(iid, "edit", tool_input, "", None, status)
        result["step"] = completed
        return result

    if itype == "error":
        # "non-fatal error surfaced as an item" per the codex event schema.
        if completed:
            msg = str(item.get("message") or "codex item error")
            result["emit"] = {
                "type": "error", "backend": "codex",
                "error": {"name": "CodexItemError", "data": {"message": msg}},
            }
        return result

    return result


# ──────────────────────────────────────────────────────────────────────────────
# Container preparation
# ──────────────────────────────────────────────────────────────────────────────

def ensure_codex_auth(container: str) -> None:
    """Bootstrap API-key auth in the container, fail with a readable message.

    Runs ``codex login status``; if logged out and ``OPENAI_API_KEY`` is set
    in the container, logs in with it (key never appears in argv).  Custom
    providers that authenticate via ``env_key`` do not need this — callers
    skip it when ``VULN_PIPELINE_CODEX_PROVIDER`` is set.
    """
    probe = (
        "if " + codex_bin() + " login status >/dev/null 2>&1; then exit 0; fi; "
        'if [ -n "$OPENAI_API_KEY" ]; then '
        "printf '%s' \"$OPENAI_API_KEY\" | " + codex_bin()
        + " login --with-api-key >/dev/null 2>&1; fi; "
        + codex_bin() + " login status >/dev/null 2>&1"
    )
    rc, _out, err = docker_ops.exec_sh(container, probe, timeout=60)
    if rc:
        raise RuntimeError(
            "codex backend: not authenticated in the agent container. Set "
            "OPENAI_API_KEY on the host (it is forwarded by resolve_auth_env), "
            "or copy auth.json into $CODEX_HOME. "
            f"stderr: {(err or '')[-300:]}"
        )


def prepare_codex(container: str, system_prompt: str | None) -> None:
    """Create $CODEX_HOME, inject instructions + optional config.toml/auth."""
    docker_ops.exec_sh(container, f"mkdir -p {CODEX_HOME}", timeout=15)
    instructions = (system_prompt or "").strip()
    if instructions:
        docker_ops.write_file(
            container, f"{CODEX_HOME}/AGENTS.md", instructions.encode()
        )
    config = codex_config_toml()
    if config is not None:
        docker_ops.write_file(
            container, f"{CODEX_HOME}/config.toml", config.encode()
        )
    auth_file = codex_auth_file()
    if auth_file:
        data = Path(auth_file).read_bytes()
        docker_ops.write_file(container, f"{CODEX_HOME}/auth.json", data)
        docker_ops.exec_sh(
            container, f"chmod 600 {CODEX_HOME}/auth.json", timeout=15
        )
        return
    if not codex_provider():
        ensure_codex_auth(container)


def _kill_codex(container: str) -> None:
    """Terminate codex processes without touching the target binary."""
    with contextlib.suppress(Exception):
        docker_ops.exec_sh(
            container,
            "pids=$(ps -eo pid=,comm= | awk '$2 == \"" + codex_bin() + "\" {print $1}'); "
            "[ -z \"$pids\" ] || kill -TERM $pids; "
            "sleep 1; "
            "pids=$(ps -eo pid=,comm= | awk '$2 == \"" + codex_bin() + "\" {print $1}'); "
            "[ -z \"$pids\" ] || kill -KILL $pids",
            timeout=10,
        )


# ──────────────────────────────────────────────────────────────────────────────
# The runner
# ──────────────────────────────────────────────────────────────────────────────

async def run_agent_codex(
    prompt: str,
    *,
    container: str,
    max_turns: int | None,
    model: str,
    max_resume_attempts: int = 20,
    transcript_path: str | None = None,
    heartbeat_every: int = 25,
    progress_prefix: str | None = None,
    tools: list[str] | None = None,
    system_prompt: str | None = None,
    phase_timeout_s: float | None = 1800.0,
    idle_timeout_s: float | None = 1800.0,
    helper_timeout_s: float = 120.0,
    watchdog_interval_s: float = 5.0,
) -> AgentResult:
    """Run a codex agent session inside ``container`` (see module docstring)."""
    result = AgentResult()
    result.started_at = time.time()
    selected_model = codex_model(model)

    # Instructions/config/auth must exist before the first spawn; a missing
    # custom provider credentials pair fails here, not mid-stream.
    await asyncio.to_thread(prepare_codex, container, system_prompt)

    raw_file = None
    if transcript_path:
        raw_path = str(Path(transcript_path).with_suffix(".raw.jsonl"))
        raw_file = open(raw_path, "w")
    transcript_file = open(transcript_path, "w") if transcript_path else None

    attempt = 0
    tool_call_count = 0
    assistant_count = 0
    step_count = 0
    last_error: str | None = None
    try:
        while True:
            spawned = codex_argv(
                container, prompt, model=selected_model,
                resume_thread=result.session_id if attempt > 0 else None,
            )
            proc = await asyncio.create_subprocess_exec(
                *spawned,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=16 * 1024 * 1024,
            )
            assert proc.stdout
            watchdog_activity = {
                "started": time.monotonic(),
                "last_event": time.monotonic(),
            }
            watchdog_state: dict[str, str | None] = {"error": None}
            watchdog_task = asyncio.create_task(
                _agent_watchdog(
                    container,
                    proc,
                    watchdog_activity,
                    watchdog_state,
                    phase_timeout_s=phase_timeout_s,
                    idle_timeout_s=idle_timeout_s,
                    helper_timeout_s=helper_timeout_s,
                    interval_s=watchdog_interval_s,
                    process_names=(codex_bin(),),
                )
            )
            try:
                fatal_error: str | None = None
                last_event: dict | None = None
                async for raw in proc.stdout:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    watchdog_activity["last_event"] = time.monotonic()
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if raw_file:
                        raw_file.write(line[:_RAW_LINE_LIMIT] + "\n")
                        raw_file.flush()

                    normalized = normalize_codex_event(event)
                    if normalized["session_id"] and result.session_id is None:
                        result.session_id = normalized["session_id"]
                    if normalized["usage"]:
                        usage = normalized["usage"]
                        print(
                            f"  [codex] tokens in={usage.get('input_tokens')} "
                            f"out={usage.get('output_tokens')} "
                            f"cached={usage.get('cached_input_tokens')}",
                            file=sys.stderr,
                        )
                    emit = normalized["emit"]
                    if emit is not None:
                        emit["sessionID"] = result.session_id
                        if normalized["in_progress"]:
                            # Started/updated items only drive the live
                            # progress line; the transcript keeps the
                            # completed form so counts match opencode.
                            if progress_prefix:
                                _progress_event(emit, progress_prefix)
                            continue
                        result.messages.append(emit)
                        last_event = emit
                        part = emit.get("part") or {}
                        if part.get("type") == "tool":
                            tool_call_count += 1
                        elif part.get("type") == "text":
                            assistant_count += 1
                            if (
                                result.first_poc_at is None
                                and "<poc_path>" in str(part.get("text") or "")
                            ):
                                result.first_poc_at = time.time()
                        result.tool_call_count = tool_call_count
                        result.assistant_message_count = assistant_count
                        if normalized["step"]:
                            step_count += 1
                        if emit.get("type") == "text" and progress_prefix:
                            _progress_event(emit, progress_prefix)
                        elif progress_prefix:
                            _progress_event(emit, progress_prefix)
                        if transcript_file:
                            transcript_file.write(
                                json.dumps(_truncate_event(emit)) + "\n"
                            )
                            transcript_file.flush()
                        if (
                            (tool_call_count + assistant_count) % heartbeat_every == 0
                            and (tool_call_count + assistant_count) > 0
                        ):
                            print(
                                f"  [agent] {tool_call_count} tool calls "
                                f"({assistant_count} msgs)"
                            )
                    if normalized["fatal"]:
                        fatal_error = normalized["fatal"]
                    if (
                        max_turns is not None
                        and step_count > max_turns
                    ):
                        watchdog_state["error"] = (
                            f"agent/step_limit: exceeded max_turns={max_turns} "
                            "(codex backend terminates the session at the cap)"
                        )
                        _kill_codex(container)
                        break

                rc = await proc.wait()
                result.result_message = last_event
                if watchdog_state["error"]:
                    raise RuntimeError(watchdog_state["error"])
                if fatal_error:
                    if is_terminal_codex_error(fatal_error):
                        result.error = f"agent/policy_blocked: {fatal_error}"
                        return result
                    last_error = fatal_error
                    raise RuntimeError(fatal_error)
                if rc != 0:
                    stderr = b""
                    if proc.stderr:
                        stderr = await proc.stderr.read()
                    raise RuntimeError(
                        f"codex exited rc={rc} without result: "
                        f"{stderr.decode(errors='replace')[:2000]}"
                    )
                return result
            except Exception as e:
                if watchdog_state["error"]:
                    result.error = watchdog_state["error"]
                    return result
                if proc.returncode is None:
                    proc.terminate()
                    await proc.wait()
                attempt += 1
                if result.session_id is None or attempt > max_resume_attempts:
                    result.error = last_error or (
                        f"{type(e).__name__} after {attempt} attempt(s): {e}"
                    )
                    return result
                backoff = min(2 ** attempt, 300)
                print(
                    f"[agent] {type(e).__name__} on attempt {attempt}, "
                    f"resuming codex thread {result.session_id} in {backoff}s: {e}",
                    file=sys.stderr,
                )
                result.resume_count = attempt
                await asyncio.sleep(backoff)
            finally:
                watchdog_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await watchdog_task
    finally:
        result.finished_at = time.time()
        if transcript_file:
            transcript_file.close()
        if raw_file:
            raw_file.close()
