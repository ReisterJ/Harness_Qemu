# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Render host-validated runtime metadata for agent prompts."""
from __future__ import annotations

import json
from typing import Any


def runtime_contract_section(context: dict[str, Any] | None) -> str:
    if not context:
        return ""
    payload = json.dumps(context, indent=2, ensure_ascii=False, sort_keys=True)
    profile = context.get("profile")
    profile_guidance = {
        "service": (
            "This is a service target. Do not assume `/work/entry` or a file-input "
            "CLI. Use the declared lifecycle and endpoint, keep the service state "
            "isolated, and represent a validated request as a self-contained PoC "
            "script when the XML contract requires a file."
        ),
        "qemu": (
            "This is a QEMU target. Do not try to execute the guest artifact as a "
            "host binary. Use the declared start/ready/exec/reset/collect lifecycle "
            "and make the PoC reproduce a fresh guest interaction."
        ),
        "process": (
            "This is a process target. The declared artifact and start command are "
            "the authoritative entry point; do not invent another launcher."
        ),
    }.get(
        profile,
        "Use the declared runtime contract as authoritative for interaction with the target.",
    )
    return f"""

## Runtime contract

The host validated the following target runtime contract. Use it to decide how
to inspect the target, exercise the external entry point, collect evidence, and
replay a PoC. Do not assume that every target has a `/work/entry` binary.
Commands and paths are inside the isolated target-agent container:

{profile_guidance}

```json
{payload}
```
"""
