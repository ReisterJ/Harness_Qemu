# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Runtime-specific guidance included in agent prompts."""
from __future__ import annotations

from harness.prompts.runtime_context import runtime_contract_section


def test_service_context_warns_against_process_assumptions():
    prompt = runtime_contract_section(
        {
            "profile": "service",
            "lifecycle": {"start": {"command": "/work/start"}},
            "endpoint": {"scheme": "http", "host": "127.0.0.1", "port": 8080},
        }
    )
    assert "service target" in prompt
    assert "Do not assume `/work/entry`" in prompt
    assert "127.0.0.1" in prompt


def test_qemu_context_requires_guest_lifecycle():
    prompt = runtime_contract_section(
        {"profile": "qemu", "lifecycle": {"start": {"command": "/work/boot"}}}
    )
    assert "QEMU target" in prompt
    assert "fresh guest interaction" in prompt
