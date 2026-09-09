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
    return f"""

## Runtime contract

The host validated the following target runtime contract. Use it to decide how
to inspect the target, exercise the external entry point, collect evidence, and
replay a PoC. Do not assume that every target has a `/work/entry` binary.
Commands and paths are inside the isolated target-agent container:

```json
{payload}
```
"""
