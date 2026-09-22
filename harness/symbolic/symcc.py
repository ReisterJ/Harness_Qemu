# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Isolated, seed-driven SymCC sidecar for dynamic concolic execution."""

from __future__ import annotations

import os
import json
import shutil
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .. import docker_ops
from .klee import KleeSession
from .seed_plan import SeedPlan

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

    def submit_seed_plan(
        self,
        container: str,
        plan: SeedPlan,
        *,
        round_id: int,
    ) -> dict[str, Any]:
        """Materialize one validated plan and invoke SymCC from the harness.

        The agent may stage target-derived source files in the shared
        ``/work/symbolic`` workspace, but it never invokes the client.  This
        method writes the concrete seed bytes, creates the bounded worker
        request, and runs the fixed client command itself.
        """
        if self.status != "ready" or self.workspace is None:
            return {
                "schema_version": 1,
                "provider": self.name,
                "status": "unavailable",
                "round_id": round_id,
                "errors": list(self.errors) or ["SymCC worker is not ready"],
            }

        root = self.workspace.resolve()
        workdir = (root / plan.working_dir).resolve()
        if not workdir.is_relative_to(root) or not workdir.is_dir():
            return self._plan_error(round_id, "working_dir is missing in the symbolic workspace")
        # The agent container commonly runs as root while the isolated worker
        # and host harness run as the invoking user.  Normalize permissions on
        # this agent-created staging directory before the host materializes
        # seed bytes into it.
        workdir_inside = "/work/symbolic/" + plan.working_dir
        rc, _out, err = docker_ops.exec_sh(
            container,
            f"chmod -R a+rwX -- {shlex.quote(workdir_inside)}",
            timeout=15,
        )
        if rc:
            return self._plan_error(
                round_id,
                f"cannot make symbolic workspace writable: {err[-500:]}",
            )
        missing = [source for source in plan.sources
                   if not (workdir / source).resolve().is_relative_to(workdir)
                   or not (workdir / source).is_file()]
        if missing:
            return self._plan_error(
                round_id,
                "target-derived source files are missing: " + ", ".join(missing[:20]),
            )

        seed_dir_inside = "/work/symbolic/" + plan.working_dir + "/seeds"
        rc, _out, err = docker_ops.exec_sh(
            container,
            f"mkdir -p -- {shlex.quote(seed_dir_inside)} && "
            f"chmod -R a+rwX -- {shlex.quote('/work/symbolic/' + plan.working_dir)}",
            timeout=15,
        )
        if rc:
            return self._plan_error(
                round_id,
                f"cannot prepare seed directory: {err[-500:]}",
            )
        seed_files: list[str] = []
        for seed in plan.seeds:
            # Write through the target container so the agent's UID owns the
            # file.  The SymCC client then normalizes permissions for its
            # unprivileged sidecar; the host never assumes matching UIDs.
            path_inside = seed_dir_inside + "/" + seed.name
            docker_ops.write_file(container, path_inside, seed.data)
            # The worker resolves seed_files relative to working_dir.
            seed_files.append("seeds/" + seed.name)

        request = plan.to_request(seed_files)
        request["harness_round"] = round_id
        request_name = f"harness-round-{round_id:03d}.json"
        request_path = root / "requests" / request_name
        request_path.write_text(json.dumps(request, indent=2, ensure_ascii=False) + "\n")
        before = {
            path.name for path in (root / "requests").glob("job.*")
        }
        request_inside = "/work/symbolic/" + str(request_path.relative_to(root))
        wait_seconds = plan.timeout_s + 45
        command = (
            f"SYMCC_WAIT_SECONDS={wait_seconds} "
            f"/work/symbolic/symcc-submit {shlex.quote(request_inside)}"
        )
        started = time.time()
        try:
            rc, stdout, stderr = docker_ops.exec_sh(
                container, command, timeout=wait_seconds + 15
            )
        except subprocess.TimeoutExpired as exc:
            return self._plan_error(
                round_id,
                f"harness SymCC client timed out after {exc.timeout}s",
                started=started,
            )
        jobs = [
            path for path in (root / "requests").glob("job.*")
            if path.name not in before
        ]
        jobs.sort(key=lambda path: path.stat().st_mtime)
        job = jobs[-1] if jobs else None
        summary: dict[str, Any] = {}
        if job is not None and (job / "summary.json").is_file():
            try:
                summary = json.loads((job / "summary.json").read_text())
            except (OSError, json.JSONDecodeError) as exc:
                summary = {"status": "invalid_summary", "errors": [str(exc)]}
        errors = [str(item) for item in summary.get("errors", [])]
        if rc:
            errors.append((stderr or stdout or f"SymCC client exited with {rc}")[-2000:])
        report = {
            "schema_version": 1,
            "provider": self.name,
            "status": "completed" if summary.get("status") == "completed" and not rc else "failed",
            "round_id": round_id,
            "request_id": summary.get("request_id") or (job.name if job else None),
            "working_dir": plan.working_dir,
            "seed_count": len(plan.seeds),
            "seed_names": [seed.name for seed in plan.seeds],
            "target_anchors": list(plan.target_anchors),
            "compile_duration_s": summary.get("compile_duration_s"),
            "duration_s": summary.get("duration_s") or round(time.time() - started, 3),
            "testcase_count": summary.get("testcase_count", 0),
            "testcases": summary.get("testcases", [])[:128],
            "runs": summary.get("runs", [])[:32],
            "errors": errors[:100],
            "stdout_tail": (stdout or "")[-2000:],
        }
        if job is not None:
            report["job_path"] = str(job.relative_to(root))
        return report

    def _plan_error(self, round_id: int, message: str, *, started: float | None = None) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "provider": self.name,
            "status": "invalid_plan",
            "round_id": round_id,
            "testcase_count": 0,
            "testcases": [],
            "errors": [message],
            "duration_s": round(time.time() - started, 3) if started else 0.0,
        }

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
