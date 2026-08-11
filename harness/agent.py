# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""opencode headless CLI wrapper.

Invokes `opencode run --format json` via `docker exec` into the agent's
container and streams the raw JSON events. opencode is the agentic backend:
it owns the Read/Write/Bash tool loop and provider dispatch (DeepSeek, OpenAI,
Anthropic, ...). The pipeline owns the contract: per-phase agent configs
(system prompt + steps + permissions) injected as `.opencode/agents/*.md`,
session resume on transient failure, structured-tag parsing, and streaming
transcripts.

Key responsibilities:
  1. run_agent(): writes the per-phase agent config into the container, then
     runs `opencode run --format json --agent <name> --model <m> --auto`
  2. AgentResult.find_tagged_message(): agents often emit structured tags, then
     a short "Done!" message. Naive last-message parsing returns the prose.
     We scan backwards for the tags instead (text events grouped by message).
  3. Transcript streaming: per-event JSONL with fsync, so a mid-run kill
     leaves a readable transcript on disk.

Messages are stored as raw opencode JSON events (`step_start` / `text` /
`tool` / `step_finish` / `error`), which is also the transcript shape.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, field

from . import docker_ops


# ──────────────────────────────────────────────────────────────────────────────
# ANSI color — shared by cli.py. No dependency; gated on isatty().
# ──────────────────────────────────────────────────────────────────────────────

_ANSI = {
    # signal level
    "dim": "2;90",   # low-signal progress (tool calls) — dim + bright-black = faintest grey
    "red": "91",     # crash landed
    "bold": "1",     # verified / important finding
    # phase (start-of-phase lines so interleaved agents are scannable)
    "recon": "96",   # cyan
    "find": "94",    # blue
    "grade": "93",   # yellow
    "judge": "95",   # magenta
    "report": "92",  # green
    "patch": "92",   # green (never interleaves with report)
}


def color(text: str, name: str, stream=sys.stdout) -> str:
    """Wrap ``text`` in ANSI color ``name`` if ``stream`` is a TTY.

    dim  — low-signal progress lines (tool calls)
    red  — a crash landed
    bold — verified / important findings

    No-op when piped or redirected so grep/tee/log files stay clean.
    """
    if not getattr(stream, "isatty", lambda: False)():
        return text
    return f"\033[{_ANSI[name]}m{text}\033[0m"


# ──────────────────────────────────────────────────────────────────────────────
# Message → text extraction (stream-json dicts)
# ──────────────────────────────────────────────────────────────────────────────

def _text_by_message(events: list[dict]) -> tuple[dict[str, list[str]], list[str]]:
    """Group assistant text events by messageID, preserving order.

    opencode streams a message as many `text` events (one per part); a single
    assistant turn can span one messageID with several text parts. Returns
    (messageID -> [text parts], ordered list of messageIDs)."""
    by_msg: dict[str, list[str]] = {}
    order: list[str] = []
    for ev in events:
        part = ev.get("part") or {}
        if part.get("type") == "text" and part.get("text"):
            mid = part.get("messageID") or ev.get("sessionID") or "<no-msg>"
            if mid not in by_msg:
                by_msg[mid] = []
                order.append(mid)
            by_msg[mid].append(part["text"])
    return by_msg, order


def _truncate_event(ev: dict) -> dict:
    """Clip large text/tool/output fields for transcript persistence.

    Mutates a copy. Keeps the raw event shape (the transcript format), only
    caps the big strings — ASAN/KASAN traces and command outputs can be huge."""
    if not isinstance(ev, dict):
        return ev
    e = dict(ev)
    part = e.get("part")
    if isinstance(part, dict):
        p = dict(part)
        for k in ("text", "output"):
            if isinstance(p.get(k), str) and len(p[k]) > 5000:
                p[k] = p[k][:5000]
        e["part"] = p
    err = e.get("error")
    if isinstance(err, dict):
        er = dict(err)
        data = er.get("data")
        if isinstance(data, dict) and isinstance(data.get("message"), str):
            er["data"] = {**data, "message": data["message"][:2000]}
        e["error"] = er
    return e


def _progress_event(ev: dict, prefix: str) -> None:
    """Print a one-line summary of an opencode event to stderr.
    Tool events show name + key arg; text events show a truncated preview."""
    part = ev.get("part") or {}
    etype = ev.get("type")
    ptype = part.get("type")
    if etype == "tool" or ptype == "tool":
        inp = part.get("input") or {}
        arg = inp.get("command") or inp.get("file_path") or inp.get("pattern") or ""
        arg = str(arg).replace("\n", " ")[:120]
        line = color(f"{prefix}   → {part.get('tool')}: {arg}", "dim", sys.stderr)
        print(line, file=sys.stderr, flush=True)
    elif etype == "text" or ptype == "text":
        t = (part.get("text") or "").strip().replace("\n", " ")
        if t:
            line = color(f"{prefix}   · {t[:140]}", "dim", sys.stderr)
            print(line, file=sys.stderr, flush=True)


def _error_text(ev: dict) -> str:
    """Format an opencode `error` event into a readable string."""
    err = ev.get("error") or {}
    name = err.get("name") or "opencode-error"
    data = err.get("data") or {}
    msg = data.get("message") or data.get("ref") or ""
    return f"{name}: {msg}".strip() or "opencode error event"


# ──────────────────────────────────────────────────────────────────────────────
# XML tag parsing
# ──────────────────────────────────────────────────────────────────────────────

def parse_xml_tag(text: str, tag: str) -> str | None:
    """Extract content of <tag>...</tag>. DOTALL so multiline ASAN traces work.
    Not a real XML parser — tags are markers in prose, not well-formed XML.
    """
    m = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, re.DOTALL)
    return m.group(1).strip() if m else None


# ──────────────────────────────────────────────────────────────────────────────
# AgentResult — the find_tagged_message bugfix lives here
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentResult:
    """Collected output of one agent run."""
    messages: list[dict] = field(default_factory=list)  # raw stream-json dicts
    result_message: dict | None = None                  # terminal {"type":"result",...}
    session_id: str | None = None                       # for resume on transient failure
    error: str | None = None                            # if the agent loop died
    resume_count: int = 0                               # how many times we auto-resumed

    def find_tagged_message(self, tag: str) -> str:
        """Return the most-recent assistant message text containing <tag>.

        Agents emit structured tags, then often a short final "Done!" message.
        If you take the last message you get prose, not tags. Scan backwards
        for the newest message that actually carries the tag; fall back to the
        last assistant message.
        """
        needle = f"<{tag}>"
        by_msg, order = _text_by_message(self.messages)
        for mid in reversed(order):
            text = "\n".join(by_msg[mid])
            if needle in text:
                return text
        if order:
            return "\n".join(by_msg[order[-1]])
        return ""

    @property
    def last_assistant_message(self) -> str:
        by_msg, order = _text_by_message(self.messages)
        if not order:
            return ""
        return "\n".join(by_msg[order[-1]])

    def transcript(self) -> list[dict]:
        """JSON-serializable transcript for persistence (truncated events)."""
        return [_truncate_event(m) for m in self.messages]


# ──────────────────────────────────────────────────────────────────────────────
# The core wrapper
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_TOOLS = ["Read", "Write", "Bash"]

# Container-name prefixes → per-phase opencode agent names (vuln-<phase>).
_AGENT_PREFIXES = ("find", "grader", "recon", "report", "judge", "compare", "patch")

# opencode permission keys we control; anything not listed stays denied.
_TOOL_PERMISSIONS = (
    "read", "edit", "glob", "grep", "list", "bash",
    "task", "webfetch", "websearch", "todowrite", "lsp", "skill",
    "question", "external_directory",
)


def _agent_name(container: str) -> str:
    """Derive the per-phase opencode agent name from the container name, e.g.
    find_target → vuln-find, grader_target → vuln-grader."""
    for p in _AGENT_PREFIXES:
        if container.startswith(p):
            return f"vuln-{p}"
    return "vuln-agent"


def _permission_for_tools(tools: list[str] | None) -> dict[str, str]:
    """Map the claude-era tool allowlist (Read/Write/Bash) to opencode
    permission keys. tools=None/[] → all denied (judge/compare agents).

    Agents that get any tool also get `external_directory: allow` — opencode
    treats any path outside its workspace root (/work) as "external", and the
    pipeline's agents legitimately touch /src, /kernel, /images, /tmp, /poc.
    (The container is the trust boundary; --dangerously-no-sandbox hosts this.)
    """
    perm = {k: "deny" for k in _TOOL_PERMISSIONS}
    if not tools:
        return perm
    allowed = set(tools)
    if "Read" in allowed:
        for k in ("read", "glob", "grep", "list"):
            perm[k] = "allow"
    if "Write" in allowed:
        perm["edit"] = "allow"
    if "Bash" in allowed:
        perm["bash"] = "allow"
    # Any tool access implies reading/writing outside the /work workspace.
    perm["external_directory"] = "allow"
    return perm


def _build_agent_file(
    agent_name: str,
    system_prompt: str | None,
    max_turns: int,
    tools: list[str] | None,
) -> str:
    """Render a `.opencode/agents/<name>.md` file: frontmatter (description,
    mode, steps, permission) + body = the system prompt. opencode reads this
    as the agent definition; `--agent <name>` selects it."""
    perm_lines = "\n".join(f"  {k}: {v}" for k, v in _permission_for_tools(tools).items())
    body = (system_prompt or "").strip() or (
        "You are a security-research agent for the vuln-pipeline. "
        "Follow the user's instructions precisely and use the available tools."
    )
    return (
        f"---\n"
        f"description: vuln-pipeline {agent_name} agent\n"
        f"mode: primary\n"
        f"steps: {max_turns}\n"
        f"permission:\n{perm_lines}\n"
        f"---\n{body}\n"
    )


async def run_agent(
    prompt: str,
    *,
    container: str,
    max_turns: int,
    model: str,
    max_resume_attempts: int = 20,
    transcript_path: str | None = None,
    heartbeat_every: int = 25,
    progress_prefix: str | None = None,
    tools: list[str] | None = None,
    system_prompt: str | None = None,
) -> AgentResult:
    """Run an opencode agent session inside ``container``.

    Writes a per-phase agent config (system prompt + steps + permissions) into
    ``/work/.opencode/agents/``, then invokes
    ``opencode run --format json --model <m> --agent <name> --auto``. Provider
    API keys / runtime env are already on the container (set at docker_ops.run
    time via harness.auth.resolve_auth_env).

    ``max_turns`` maps to the agent's ``steps`` cap. When opencode hits the
    cap it forces a text response and exits cleanly (rc 0) — the pipeline then
    sees a finished run without a submitted artifact, which downstream treats
    as no-find. There is no separate "turn budget exhausted" error.

    Resilience: transient API failures surface as opencode ``error`` events or
    a non-zero exit; we resume the session (``--session <id>``) up to
    max_resume_attempts times with exponential backoff. Partial transcripts
    are always preserved.
    """
    agent_name = _agent_name(container)
    docker_ops.exec_sh(container, "mkdir -p /work/.opencode/agents")
    docker_ops.write_file(
        container,
        f"/work/.opencode/agents/{agent_name}.md",
        _build_agent_file(agent_name, system_prompt, max_turns, tools).encode(),
    )

    cli_argv = ["docker", "exec", "-i", "-w", "/work", "--",
                container, "opencode", "run"]
    result = AgentResult()
    attempt = 0
    assistant_count = 0
    tool_call_count = 0
    # Persists across resume attempts: an `error` event on a failed attempt is
    # surfaced only if we eventually give up; a clean resumed completion
    # returns with no error.
    last_error: str | None = None

    transcript_file = open(transcript_path, "w") if transcript_path else None
    try:
        while True:
            cmd = [
                *cli_argv,
                "--format", "json",
                "--model", model,
                "--agent", agent_name,
                "--auto",
            ]
            if attempt > 0 and result.session_id:
                cmd += ["--session", result.session_id]
            cmd += [prompt]

            # Prompt goes in argv, not stdin — keeps the spawn simple and
            # avoids stdin-delivery races under parallel launch. ARG_MAX
            # (~2MB) fits the largest pipeline prompts.
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Default 64KB limit trips on large tool results. opencode
                # streams one JSON event per line; a single Bash/Read result
                # can be hundreds of KB.
                limit=16 * 1024 * 1024,
            )
            assert proc.stdout

            try:
                fatal_error: str | None = None
                last_event: dict | None = None
                attempt_tool_calls = 0
                attempt_assistant_count = 0
                async for raw in proc.stdout:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    result.messages.append(ev)
                    last_event = ev
                    if result.session_id is None and ev.get("sessionID"):
                        result.session_id = ev["sessionID"]

                    part = ev.get("part") or {}
                    etype = ev.get("type")
                    if etype == "tool" or part.get("type") == "tool":
                        tool_call_count += 1
                        attempt_tool_calls += 1
                    if etype == "text" or part.get("type") == "text":
                        assistant_count += 1
                        attempt_assistant_count += 1
                    if etype == "error":
                        fatal_error = _error_text(ev)

                    if progress_prefix:
                        _progress_event(ev, progress_prefix)
                    if transcript_file:
                        transcript_file.write(
                            json.dumps(_truncate_event(ev)) + "\n"
                        )
                        transcript_file.flush()
                    if (tool_call_count + assistant_count) % heartbeat_every == 0 \
                            and (tool_call_count + assistant_count) > 0:
                        print(f"  [agent] {tool_call_count} tool calls "
                              f"({assistant_count} msgs)")

                rc = await proc.wait()
                if result.messages:
                    result.result_message = last_event

                if fatal_error:
                    last_error = fatal_error
                    raise RuntimeError(fatal_error)
                if rc != 0:
                    # Process died without a result — usually an error event we
                    # missed or a crash. Resume.
                    stderr = b""
                    if proc.stderr:
                        stderr = await proc.stderr.read()
                    raise RuntimeError(
                        f"opencode exited rc={rc} without result: "
                        f"{stderr.decode(errors='replace')[:2000]}"
                    )
                if tools and attempt_tool_calls == 0 and attempt_assistant_count <= 2:
                    # Model glitch: a clean exit after a text-only response with
                    # no tool calls. deepseek-style models occasionally emit
                    # tool calls as XML text, which opencode treats as a final
                    # answer and ends the run. Resume the session with a
                    # corrective nudge instead of treating this as finished.
                    if attempt < max_resume_attempts and result.session_id:
                        attempt += 1
                        result.resume_count = attempt
                        print(
                            f"[agent] text-only early stop (0 tool calls, "
                            f"{attempt_assistant_count} msgs) — resuming "
                            f"session {result.session_id} with corrective nudge",
                            file=sys.stderr,
                        )
                        prompt = (
                            "You stopped without using any tools. This is an "
                            "error: you must complete the task. CALL THE TOOLS "
                            "your runtime provides via native function calls "
                            "(never output tool calls as XML/text markup). "
                            "Continue now and do not stop until the task is "
                            "complete."
                        )
                        continue
                return result

            except Exception as e:
                if proc.returncode is None:
                    proc.terminate()
                    await proc.wait()
                # 429 rate-limit, upstream 5xx, or CLI crash all surface here.
                # The attempt cap bounds wasted retries on a genuine bug.
                attempt += 1
                if result.session_id is None or attempt > max_resume_attempts:
                    # Can't resume without a session_id, or retries exhausted.
                    # Preserve partial transcript; surface the opencode error
                    # text when one was emitted.
                    result.error = last_error or (
                        f"{type(e).__name__} after {attempt} attempt(s): {e}"
                    )
                    return result
                backoff = min(2 ** attempt, 300)
                print(
                    f"[agent] {type(e).__name__} on attempt {attempt}, "
                    f"resuming session {result.session_id} in {backoff}s: {e}",
                    file=sys.stderr,
                )
                result.resume_count = attempt
                await asyncio.sleep(backoff)
    finally:
        if transcript_file:
            transcript_file.close()
