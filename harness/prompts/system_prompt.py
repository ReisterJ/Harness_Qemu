# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""System-prompt construction for pipeline agents.

The prompt is two layers:

  PIPELINE_PREAMBLE   — facts about the execution environment. Always true,
                       always present; not user-overridable.
  ENGAGEMENT_CONTEXT — who authorized the work and where findings go.
                       Customers override with --engagement-context <file>.

The split keeps the sandbox/isolation framing intact even when a customer
supplies a terse org-specific authorization line. build_system_prompt is
threaded to every agent (find, recon, report, grade, judge).
"""
from __future__ import annotations

from pathlib import Path


PIPELINE_PREAMBLE = """\
## Pipeline context

This agent is part of the vuln-pipeline security-research tool. The target
under test is built at a pinned commit and runs alongside this agent in an
isolated container. The agent analyzes the target, crafts inputs, and
observes sanitizer output. Scope is narrow by construction: one target, one
commit, one focus area per agent.

## Tools

You run commands, read files, and write files with the tools your runtime
provides (bash, read, write, edit, ...).

## CRITICAL — Tool calling protocol (MANDATORY)

You MUST call tools using NATIVE FUNCTION CALLING only (the structured
function-call interface your runtime provides).

- NEVER emit tool calls as text. Absolutely forbidden: `<invoke name=...>`,
  `<tool_use>@tool ...</tool_use>`, `<execute>...</execute>`,
  `<tool_calls>...`, `<start_thought>`, DSML tags, or any XML/markup for tool
  invocation.
- When you need to run a command or read a file, invoke the bash/read/write
  function directly through the function-calling interface. The tool result
  will be returned to you automatically.
- If you find yourself writing a tag like `<invoke>` as plain text, STOP and
  call the function natively instead.
"""

DEFAULT_ENGAGEMENT_CONTEXT = """\
## Engagement context

This is authorized security research conducted as a defensive security
assessment on an open-source C/C++ target. Findings are collected for
responsible disclosure to the upstream maintainer.
"""


def load_engagement_context(path: str | Path | None, default: str | None = None) -> str:
    """Return the engagement-context block. Falls back to ``default`` (this
    module's DEFAULT_ENGAGEMENT_CONTEXT when not given) if path is None or the
    file is missing/empty. Harnesses with their own framing — e.g. the DNR
    hunt/grade agents — pass their own default block."""
    if path:
        p = Path(path)
        if p.exists():
            text = p.read_text().strip()
            if text:
                return text
    return default if default is not None else DEFAULT_ENGAGEMENT_CONTEXT


def build_system_prompt(engagement_path: str | Path | None) -> str:
    """Full system prompt: fixed pipeline preamble + engagement block.

    --engagement-context overrides only the engagement block; the preamble's
    sandbox/isolation framing is always present.
    """
    return PIPELINE_PREAMBLE + "\n" + load_engagement_context(engagement_path)
