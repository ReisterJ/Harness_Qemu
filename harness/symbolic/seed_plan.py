# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Provider-neutral seed plans for harness-managed symbolic execution.

The dynamic agent proposes concrete seeds, but it never owns the symbolic
provider invocation.  The host validates this small JSON contract, materializes
the bytes, and submits a bounded provider request.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any


MAX_SEEDS = 16
MAX_SEED_BYTES = 1 * 1024 * 1024
MAX_SOURCE_FILES = 512
MAX_NAME_BYTES = 120
MAX_PLAN_BYTES = 100_000
_SAFE_RELATIVE = re.compile(r"^[A-Za-z0-9_./+-]+$")


class SeedPlanError(ValueError):
    """The agent's seed plan is not safe or internally consistent."""


@dataclass(frozen=True)
class SeedSpec:
    name: str
    data: bytes
    purpose: str = ""


@dataclass(frozen=True)
class SeedPlan:
    candidate_id: str
    working_dir: str
    sources: tuple[str, ...]
    compile_flags: tuple[str, ...]
    link_flags: tuple[str, ...]
    program_args: tuple[str, ...]
    seeds: tuple[SeedSpec, ...]
    timeout_s: int = 120
    max_testcases: int = 64
    target_anchors: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""

    def to_request(self, seed_files: list[str]) -> dict[str, Any]:
        """Return the bounded provider request after seed files are materialized."""
        return {
            "schema_version": 1,
            "working_dir": self.working_dir,
            "sources": list(self.sources),
            "compile_flags": list(self.compile_flags),
            "link_flags": list(self.link_flags),
            "seed_files": seed_files,
            "program_args": list(self.program_args),
            "timeout_s": self.timeout_s,
            "max_testcases": self.max_testcases,
        }


def parse_seed_plan(
    text: str,
    *,
    candidate_id: str,
    max_plan_bytes: int = MAX_PLAN_BYTES,
) -> SeedPlan:
    """Parse the final ``<symbolic_seed_plan>`` response from the agent."""
    if not text:
        raise SeedPlanError("agent returned no seed-plan response")
    match = re.search(
        r"<symbolic_seed_plan>\s*(.*?)\s*</symbolic_seed_plan>",
        text,
        flags=re.DOTALL,
    )
    if not match:
        raise SeedPlanError("missing <symbolic_seed_plan> response")
    raw = match.group(1).strip()
    if len(raw.encode()) > max_plan_bytes:
        raise SeedPlanError("symbolic seed plan exceeds the bounded response size")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SeedPlanError(f"seed plan is not valid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise SeedPlanError("seed plan must be a JSON object")
    if payload.get("schema_version") != 1:
        raise SeedPlanError("seed plan schema_version must be 1")
    if str(payload.get("candidate_id") or "") != candidate_id:
        raise SeedPlanError("seed plan candidate_id does not match the active candidate")

    working_dir = _relative_path(payload.get("working_dir", "jobs/agent"), "working_dir")
    sources = _relative_paths(payload.get("sources"), "sources", MAX_SOURCE_FILES)
    if not sources:
        raise SeedPlanError("seed plan must list at least one target-derived source")
    compile_flags = _string_list(payload.get("compile_flags", ["-g", "-O0"]), "compile_flags", 256)
    link_flags = _string_list(payload.get("link_flags", []), "link_flags", 128)
    program_args = _string_list(payload.get("program_args", ["{input_file}"]), "program_args", 128)
    if sum(value.count("{input_file}") for value in program_args) != 1:
        raise SeedPlanError("program_args must contain {input_file} exactly once")

    raw_seeds = payload.get("seeds")
    if not isinstance(raw_seeds, list) or not raw_seeds:
        raise SeedPlanError("seed plan must contain a non-empty seeds array")
    if len(raw_seeds) > MAX_SEEDS:
        raise SeedPlanError(f"seed plan contains more than {MAX_SEEDS} seeds")
    seeds: list[SeedSpec] = []
    names: set[str] = set()
    for index, item in enumerate(raw_seeds):
        if not isinstance(item, dict):
            raise SeedPlanError(f"seed {index} must be an object")
        name = _safe_name(item.get("name") or f"seed-{index:03d}", f"seeds[{index}].name")
        if name in names:
            raise SeedPlanError(f"duplicate seed name: {name}")
        names.add(name)
        encoding = str(item.get("encoding") or "base64").lower()
        value = item.get("data")
        if not isinstance(value, str):
            raise SeedPlanError(f"seeds[{index}].data must be a string")
        try:
            if encoding == "base64":
                data = base64.b64decode(value, validate=True)
            elif encoding == "hex":
                data = bytes.fromhex(value)
            elif encoding == "text":
                data = value.encode()
            else:
                raise SeedPlanError(
                    f"unsupported seed encoding {encoding!r}; use base64, hex, or text"
                )
        except (ValueError, binascii.Error) as exc:
            raise SeedPlanError(f"invalid data for seed {name}: {exc}") from exc
        if len(data) > MAX_SEED_BYTES:
            raise SeedPlanError(f"seed {name} exceeds {MAX_SEED_BYTES} bytes")
        seeds.append(SeedSpec(name=name, data=data, purpose=str(item.get("purpose") or "")[:2000]))

    try:
        timeout_s = int(payload.get("timeout_s", 120))
        max_testcases = int(payload.get("max_testcases", 64))
    except (TypeError, ValueError) as exc:
        raise SeedPlanError("timeout_s and max_testcases must be integers") from exc
    if not 1 <= timeout_s <= 300:
        raise SeedPlanError("timeout_s must be between 1 and 300 seconds")
    if not len(seeds) <= max_testcases <= 128:
        raise SeedPlanError(
            f"max_testcases must be between the seed count and 128 (got {max_testcases})"
        )
    anchors = tuple(
        str(value)[:300]
        for value in _string_list(payload.get("target_anchors", []), "target_anchors", 32)
    )
    return SeedPlan(
        candidate_id=candidate_id,
        working_dir=working_dir,
        sources=tuple(sources),
        compile_flags=tuple(compile_flags),
        link_flags=tuple(link_flags),
        program_args=tuple(program_args),
        seeds=tuple(seeds),
        timeout_s=timeout_s,
        max_testcases=max_testcases,
        target_anchors=anchors,
        notes=str(payload.get("notes") or "")[:4000],
    )


def _string_list(value: Any, field: str, limit: int) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise SeedPlanError(f"{field} must be a list with at most {limit} entries")
    if not all(isinstance(item, str) and "\x00" not in item for item in value):
        raise SeedPlanError(f"{field} entries must be strings without NUL bytes")
    return value


def _relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SeedPlanError(f"{field} must be a non-empty relative path")
    if value.startswith("/") or ".." in value.split("/"):
        raise SeedPlanError(f"{field} must stay inside the symbolic workspace")
    if not _SAFE_RELATIVE.fullmatch(value):
        raise SeedPlanError(f"{field} contains unsupported path characters")
    return value


def _relative_paths(value: Any, field: str, limit: int) -> list[str]:
    values = _string_list(value, field, limit)
    return [_relative_path(item, f"{field} entry") for item in values]


def _safe_name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > MAX_NAME_BYTES:
        raise SeedPlanError(f"{field} must be a short non-empty name")
    if value in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise SeedPlanError(f"{field} contains unsupported characters")
    return value
