# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Isolated, seed-driven SymCC sidecar for dynamic concolic execution."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .. import docker_ops
from .klee import KleeSession

SYMCC_IMAGE = "eurecoms3/symcc@sha256:0795b484f1e55b83f134df0724fe88e99bc56ca58dfe29e8fd619a70b4b639c7"

_CLIENT = r'''#!/bin/sh
set -eu
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  echo "usage: /work/symbolic/symcc-submit REQUEST.json" >&2
  exit 2
fi
root=/work/symbolic
mkdir -p "$root/requests"
job=$(mktemp -d "$root/requests/job.XXXXXX")
chmod 777 "$job"
cp "$1" "$job/request.json"
if [ -d "$root/jobs" ]; then chmod -R a+rwX "$root/jobs"; fi
: > "$job/ready"
wait_seconds=$(printenv SYMCC_WAIT_SECONDS 2>/dev/null || true)
[ -n "$wait_seconds" ] || wait_seconds=1800
case "$wait_seconds" in *[!0-9]*) wait_seconds=1800 ;; esac
elapsed=0
while [ "$elapsed" -lt "$wait_seconds" ]; do
  if [ -f "$job/worker-error" ]; then
    cat "$job/summary.json" 2>/dev/null || cat "$job/worker-error"
    exit 1
  fi
  if [ -f "$job/done" ]; then
    cat "$job/summary.json"
    exit 0
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
echo "SymCC request timed out; request=$job" >&2
exit 124
'''

_README = r'''# SymCC concolic-execution helper

This isolated worker compiles target-derived C/C++ sources with SymCC and
executes the instrumented binary on concrete seed files. At runtime SymCC
tracks values read from `SYMCC_INPUT_FILE`, solves branch constraints, and
materializes alternate external inputs. A generated input is only a candidate:
replay it through the clean target binary and its sanitizer or semantic oracle.

Put a self-contained source snapshot and seed files under
`/work/symbolic/jobs/NAME`. For a real `LLVMFuzzerTestOneInput` target, use the
provided `/work/symbolic/fuzzer_file_driver.c` (or an equivalent driver) that
opens the seed path, reads its bytes, and invokes the real fuzz entry point.
The driver must not reimplement target behavior. Concrete seed length is fixed
for each concolic run, so try multiple benign seeds of useful sizes/structures.

Submit a bounded request such as:

    {
      "schema_version": 1,
      "working_dir": "jobs/project",
      "sources": ["src/target.c", "fuzzer.c", "driver.c"],
      "compile_flags": ["-g", "-O0", "-Iinclude"],
      "link_flags": ["-lm"],
      "seed_files": ["seeds/seed-01", "seeds/seed-02"],
      "program_args": ["{input_file}"],
      "timeout_s": 120,
      "max_testcases": 128
    }

Invoke `/work/symbolic/symcc-submit REQUEST.json`. The worker has no network,
accepts no shell commands, validates paths and compiler/link flags, and limits
per-seed time, generated cases, and output bytes. Raw logs and generated inputs
appear under the request's `out/`; summaries distinguish each seed run.
Concolic execution is not proof of a bug. Verify reachability and reproduce
each candidate with the original target runtime before reporting it.
'''


class SymccSession(KleeSession):
    """Owns a constrained SymCC worker and a writable job directory."""

    name = "symcc"

    def __init__(
        self,
        *,
        container_name: str,
        result_path: str | None = None,
        image: str = SYMCC_IMAGE,
        startup_timeout_s: float = 60.0,
    ) -> None:
        super().__init__(
            container_name=container_name,
            result_path=result_path,
            image=image,
            startup_timeout_s=startup_timeout_s,
        )
        self.container_name = (container_name + "_symcc")[:63]

    def start(self) -> None:
        if not docker_ops.image_exists(self.image):
            docker_ops.pull(self.image)
        self._temp = tempfile.TemporaryDirectory(prefix="vp-symcc-")
        self.workspace = Path(self._temp.name)
        (self.workspace / "requests").mkdir()
        shutil.copyfile(
            Path(__file__).with_name("symcc_worker.py"),
            self.workspace / "symcc_worker.py",
        )
        self.started_at = time.time()
        cmd = [
            "docker", "run", "-d", "--name", self.container_name,
            "--network", "none", "--memory", "6g", "--cpus", "2",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--env", "HOME=/tmp", "--env", "TMPDIR=/var/tmp",
            "--pids-limit", "128", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,nosuid,size=1g",
            "--tmpfs", "/var/tmp:rw,nosuid,size=1g",
            "--tmpfs", "/dev/shm:rw,nosuid,size=1g",
            "--mount", f"type=bind,src={self.workspace},dst=/symbolic",
            "--entrypoint", "python3", self.image, "/symbolic/symcc_worker.py",
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            self.status = "unavailable"
            detail = getattr(exc, "stderr", "") or str(exc)
            self.errors.append(f"could not start SymCC worker: {detail[-1000:]}")
            self._cleanup_temp()
            raise RuntimeError(self.errors[-1]) from exc

        deadline = time.monotonic() + self.startup_timeout_s
        while time.monotonic() < deadline:
            if (self.workspace / "worker.ready").exists():
                self.status = "ready"
                return
            state = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", self.container_name],
                capture_output=True,
                text=True,
            )
            if state.returncode or state.stdout.strip() != "true":
                logs = subprocess.run(
                    ["docker", "logs", self.container_name],
                    capture_output=True,
                    text=True,
                )
                self.errors.append(f"SymCC worker exited: {(logs.stdout + logs.stderr)[-1000:]}")
                self.stop()
                raise RuntimeError(self.errors[-1])
            time.sleep(0.2)
        self.errors.append("timed out waiting for SymCC worker readiness")
        self.stop()
        raise RuntimeError(self.errors[-1])

    def prepare_agent(self, container: str) -> dict:
        if self.status == "ready":
            files = {
                "/work/symbolic/symcc-submit": _CLIENT.encode(),
                "/work/symbolic/README.md": _README.encode(),
                "/work/symbolic/fuzzer_file_driver.c": Path(__file__)
                .with_name("fuzzer_file_driver.c")
                .read_bytes(),
            }
            for path, contents in files.items():
                docker_ops.write_file(container, path, contents)
            rc, _out, err = docker_ops.exec_sh(
                container, "chmod +x /work/symbolic/symcc-submit", timeout=15
            )
            if rc:
                self.status = "prepare_failed"
                self.errors.append(f"cannot enable SymCC client: {err[-500:]}")
        return self.to_dict()

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "provider": self.name,
            "image": self.image,
            "status": self.status,
            "capabilities": [
                "LLVM-instrumented-native-execution",
                "concrete-seed-path-constraint-solving",
                "external-file-input-materialization",
                "multi-seed-exploration",
            ],
            "client": "/work/symbolic/symcc-submit",
            "workspace": "/work/symbolic",
            "errors": list(self.errors),
        }
