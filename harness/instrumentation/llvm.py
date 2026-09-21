# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""LLVM source-based coverage provider.

The provider deliberately installs a small in-container contract instead of
making the orchestration layer understand CMake, Make, or a target's build
system.  The dynamic agent chooses how to build a temporary observed copy; the
provider supplies flags, a run wrapper, and a normalized report.
"""
from __future__ import annotations

import json
from typing import Any

from .. import docker_ops
from .base import (
    ExecutionFeedback,
    InstrumentationProvider,
    InstrumentationReport,
    input_sha256,
    json_bytes,
)


LLVM_CAPABILITIES = (
    "functions",
    "source_locations",
    "regions",
    "process_exit",
)


_RUNNER = r'''#!/bin/sh
set -u
root=/work/instrumentation
if [ "$#" -lt 3 ] || [ "$2" != "--" ]; then
  echo "usage: $0 LABEL -- COMMAND [ARGS...]" >&2
  exit 64
fi
label=$1
shift 2
case "$label" in
  ""|*[!A-Za-z0-9_.-]*)
    echo "invalid run label" >&2
    exit 64
    ;;
esac
run_dir="$root/runs/$label"
mkdir -p "$run_dir" "$root/report"
start=$(date +%s%N 2>/dev/null || date +%s)
set +e
LLVM_PROFILE_FILE="$run_dir/%p-%m.profraw" "$@" >"$run_dir/stdout.txt" 2>"$run_dir/stderr.txt"
rc=$?
set -e
end=$(date +%s%N 2>/dev/null || date +%s)
duration_ms=0
case "$start:$end" in
  *:* )
    s=${start%%:*}; e=${end##*:}
    case "$s:$e" in *[!0-9:]* ) ;; *) duration_ms=$(( (e - s) / 1000000 ));; esac
    ;;
esac
binary=${VULN_PIPELINE_INSTRUMENTED_BINARY:-/work/entry}
digest=${VULN_PIPELINE_INPUT_SHA256:-0000000000000000000000000000000000000000000000000000000000000000}
merged="$run_dir/merged.profdata"
coverage="$run_dir/coverage.json"
errors=""
profiles=$(find "$run_dir" -type f -name '*.profraw' -print 2>/dev/null)
find_tool() {
  direct=$(command -v "$1" 2>/dev/null || true)
  if [ -n "$direct" ]; then
    printf '%s' "$direct"
    return 0
  fi
  find /usr/bin -maxdepth 1 -perm -111 -name "$1-[0-9]*" \
    -print -quit 2>/dev/null
}
profdata=$(find_tool llvm-profdata)
cov=$(find_tool llvm-cov)
if [ -n "$profiles" ] && [ -n "$profdata" ]; then
  # shellcheck disable=SC2086
  "$profdata" merge -sparse $profiles -o "$merged" >/dev/null 2>&1 || errors="profile merge failed"
  if [ -f "$merged" ] && [ -n "$cov" ]; then
    "$cov" export "$binary" -instr-profile="$merged" -format=text >"$coverage" 2>/dev/null || errors="coverage export failed"
  fi
elif [ -z "$profiles" ]; then
  errors="no LLVM profile was produced; verify the observed binary was built with coverage flags"
else
  errors="llvm-profdata is unavailable"
fi
if command -v python3 >/dev/null 2>&1; then
  python3 "$root/normalize.py" "$label" "$digest" "$rc" "$duration_ms" "$coverage" "$errors"
else
  # The human-readable raw report remains available even in minimal images.
  printf '{"schema_version":1,"provider":"llvm","run_id":"%s","input_sha256":"%s","status":"completed","exit_code":%s,"duration_ms":%s,"capabilities":["process_exit"],"reached_functions":[],"reached_locations":[],"edges":[],"branches":[],"comparisons":[],"stdout":"","stderr":"","errors":["python3 unavailable; inspect %s manually"],"raw_artifacts":["%s"]}\n' \
    "$label" "$digest" "$rc" "$duration_ms" "$coverage" "$coverage" \
    >"$root/report/$label.json"
  cat "$root/report/$label.json" >>"$root/report/events.jsonl"
fi
exit 0
'''


_NORMALIZE = r'''#!/usr/bin/env python3
import json
import sys
from pathlib import Path

MAX_TEXT = 20000
label, digest, rc, duration, coverage_path, errors = sys.argv[1:]
run_dir = Path("/work/instrumentation/runs") / label
def read(path):
    try:
        return path.read_text(errors="replace")[:MAX_TEXT]
    except OSError:
        return ""
def bounded(value):
    return value[:MAX_TEXT] + "…[truncated]" if len(value) > MAX_TEXT else value

functions = []
locations = []
raw = Path(coverage_path)
def canonical(name):
    if not isinstance(name, str):
        return ""
    head, sep, tail = name.partition(":")
    if sep and (head.endswith((".c", ".cc", ".cpp", ".cxx")) or "/" in head):
        return tail
    return name
if raw.exists():
    try:
        exported = json.loads(raw.read_text(errors="replace"))
        data = (exported.get("data") or [{}])[0]
        for function in data.get("functions") or []:
            count = function.get("count", 0)
            if isinstance(count, (int, float)) and count > 0:
                name = function.get("name")
                name = canonical(name)
                if name and name not in functions:
                    functions.append(name)
                filenames = function.get("filenames") or []
                regions = function.get("regions") or []
                if regions and filenames:
                    region = regions[0]
                    if isinstance(region, list) and len(region) >= 5:
                        locations.append({
                            "file": filenames[0],
                            "line": region[0],
                            "function": name or "",
                            "count": count,
                        })
    except (OSError, ValueError, TypeError, KeyError):
        errors = (errors + "; " if errors else "") + "coverage JSON could not be normalized"

event = {
    "schema_version": 1,
    "provider": "llvm",
    "run_id": label,
    "input_sha256": digest if len(digest) == 64 else "0" * 64,
    "status": "completed",
    "exit_code": int(rc),
    "duration_ms": int(duration),
    "capabilities": ["functions", "source_locations", "regions", "process_exit"],
    "reached_functions": functions[:2000],
    "reached_locations": locations[:2000],
    "edges": [], "branches": [], "comparisons": [],
    "stdout": read(run_dir / "stdout.txt"),
    "stderr": read(run_dir / "stderr.txt"),
    "errors": [x for x in [errors] if x],
    "raw_artifacts": [str(raw)] if raw.exists() else [],
}
summary = Path("/work/instrumentation/report") / (label + ".json")
summary.write_text(json.dumps(event, indent=2, ensure_ascii=False) + "\n")
with (Path("/work/instrumentation/report") / "events.jsonl").open("a") as stream:
    stream.write(json.dumps(event, ensure_ascii=False) + "\n")
'''


class LLVMProvider(InstrumentationProvider):
    name = "llvm"
    capabilities = LLVM_CAPABILITIES

    def prepare(
        self,
        container: str,
        *,
        source_root: str,
        binary_path: str,
        candidate: dict[str, Any],
    ) -> InstrumentationReport:
        probe = (
            "command -v clang >/dev/null && "
            "(command -v llvm-profdata >/dev/null || "
            "find /usr/bin -maxdepth 1 -name 'llvm-profdata-[0-9]*' -print -quit | grep -q .) && "
            "(command -v llvm-cov >/dev/null || "
            "find /usr/bin -maxdepth 1 -name 'llvm-cov-[0-9]*' -print -quit | grep -q .) && "
            "find \"$(clang -print-resource-dir)\" -type f "
            "-name 'libclang_rt.profile-*.a' -print -quit 2>/dev/null | grep -q ."
        )
        rc, _out, err = docker_ops.exec_sh(container, probe, timeout=15)
        manifest = {
            "schema_version": 1,
            "provider": self.name,
            "capabilities": list(self.capabilities),
            "source_root": source_root,
            "clean_binary": binary_path,
            "candidate_id": str(candidate.get("candidate_id") or ""),
            "flags": ["-g", "-fprofile-instr-generate", "-fcoverage-mapping"],
            "run_command": "/work/instrumentation/run LABEL -- COMMAND [ARGS...]",
        }
        if rc:
            return InstrumentationReport(
                provider=self.name,
                status="unavailable",
                capabilities=self.capabilities,
                manifest=manifest,
                errors=(
                    "LLVM provider unavailable: clang, llvm-profdata, llvm-cov, "
                    "or clang profile runtime not found"
                    + (f": {err[-500:]}" if err else ""),
                ),
            )
        rc, _out, err = docker_ops.exec_sh(
            container,
            "mkdir -p /work/instrumentation/runs /work/instrumentation/report",
            timeout=15,
        )
        if rc:
            return InstrumentationReport(
                provider=self.name,
                status="prepare_failed",
                capabilities=self.capabilities,
                manifest=manifest,
                errors=(f"cannot create provider workspace: {err[-500:]}",),
            )
        for path, content in (
            ("/work/instrumentation/provider.json", json_bytes(manifest)),
            ("/work/instrumentation/run", _RUNNER.encode()),
            ("/work/instrumentation/normalize.py", _NORMALIZE.encode()),
            ("/work/instrumentation/README.md", self._readme(manifest).encode()),
        ):
            docker_ops.write_file(container, path, content)
        rc, _out, err = docker_ops.exec_sh(
            container,
            "chmod +x /work/instrumentation/run /work/instrumentation/normalize.py",
            timeout=15,
        )
        if rc:
            return InstrumentationReport(
                provider=self.name,
                status="prepare_failed",
                capabilities=self.capabilities,
                manifest=manifest,
                errors=(f"cannot initialize provider workspace: {err[-500:]}",),
            )
        return InstrumentationReport(
            provider=self.name,
            status="ready",
            capabilities=self.capabilities,
            manifest=manifest,
        )

    def collect(self, container: str, manifest: dict[str, Any]) -> InstrumentationReport:
        rc, _out, err = docker_ops.exec_sh(
            container,
            "test -f /work/instrumentation/report/events.jsonl",
            timeout=10,
        )
        raw_events = docker_ops.read_file(container, "/work/instrumentation/report/events.jsonl")
        events: list[ExecutionFeedback] = []
        errors: list[str] = []
        if raw_events:
            for line in raw_events.decode(errors="replace").splitlines()[-2000:]:
                try:
                    event = json.loads(line)
                    # The runner receives the digest through
                    # VULN_PIPELINE_INPUT_SHA256 when the agent supplies one.
                    if event.get("input_sha256") == "0" * 64:
                        event["input_sha256"] = input_sha256(event.get("run_id", ""))
                    events.append(ExecutionFeedback.from_dict(event))
                except (ValueError, json.JSONDecodeError) as exc:
                    errors.append(f"invalid LLVM feedback event: {exc}")
        if rc and err:
            errors.append(f"feedback report unavailable: {err[-500:]}")
        status = "collected" if events else ("no_report" if not errors else "collect_failed")
        return InstrumentationReport(
            provider=self.name,
            status=status,
            capabilities=self.capabilities,
            manifest=manifest,
            feedback=tuple(events),
            errors=tuple(errors),
        )

    @staticmethod
    def _readme(manifest: dict[str, Any]) -> str:
        return f"""# LLVM dynamic-observation provider

This is an optional observation layer for the current dynamic-validation run.
It does not prove a vulnerability and it must not replace the clean target
replay or the grade phase.

## Contract

- Source snapshot: `{manifest['source_root']}`
- Clean binary: `{manifest['clean_binary']}`
- Flags for the temporary observed build: `-g -fprofile-instr-generate -fcoverage-mapping`
- Run an observed binary with:
  `/work/instrumentation/run LABEL -- COMMAND [ARGS...]`
- Read normalized feedback from `/work/instrumentation/report/LABEL.json` and
  `/work/instrumentation/report/events.jsonl`.
- When the input is a file, set `VULN_PIPELINE_INPUT_SHA256` to its
  `sha256sum`; otherwise use a stable digest of the request or bundle.

Build in a separate directory or copy. Do not overwrite the clean binary. The
observed binary must include the library/object files containing the candidate,
not only the consumer harness. Set
`VULN_PIPELINE_INSTRUMENTED_BINARY=/absolute/path/to/observed-binary` when the
binary is not `/work/entry`.

The final PoC command must run against the clean `{manifest['clean_binary']}`
and must not depend on `/work/instrumentation`, a temporary observed build, or
files that will not cross the grade boundary. Coverage proves reachability only;
use the target's ASAN or semantic oracle to prove the candidate.
"""
