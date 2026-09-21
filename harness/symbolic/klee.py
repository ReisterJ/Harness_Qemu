# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""A constrained KLEE sidecar that the dynamic agent can invoke on demand."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .. import docker_ops

KLEE_IMAGE = "klee/klee:v3.1"

_CLIENT = r'''#!/bin/sh
set -eu
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  echo "usage: /work/symbolic/klee-submit REQUEST.json" >&2
  exit 2
fi
root=/work/symbolic
mkdir -p "$root/requests"
job=$(mktemp -d "$root/requests/job.XXXXXX")
chmod 777 "$job"
cp "$1" "$job/request.json"
# The target container commonly runs as root and creates the source workspace
# on this bind mount. Keep those job files readable by the unprivileged KLEE
# worker and removable by the host process that owns the temporary directory.
if [ -d "$root/jobs" ]; then chmod -R a+rwX "$root/jobs"; fi
: > "$job/ready"
wait_seconds=$(printenv KLEE_WAIT_SECONDS 2>/dev/null || true)
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
echo "KLEE request timed out; request=$job" >&2
exit 124
'''

_README = r'''# KLEE symbolic-execution helper

The dynamic agent may submit bounded C/C++ jobs to an isolated KLEE v3.1
container. A KLEE testcase is only a candidate input: replay it against the
target binary and check the finding's oracle before treating it as evidence.

Put sources under /work/symbolic/jobs/NAME and write a JSON request:

    {
      "working_dir": "jobs/canary",
      "language": "c",
      "sources": ["entry.c"],
      "compile_flags": ["-g", "-O0"],
      "klee_args": ["--libc=uclibc", "--posix-runtime"],
      "program_args": ["A", "-sym-files", "1", "32"],
      "timeout_s": 120
    }

Submit it with /work/symbolic/klee-submit REQUEST.json. Source paths stay
inside the job directory. The worker compiles to LLVM bitcode, runs KLEE with
resource limits, and extracts concrete symbolic-file and symbolic-stdin
objects from .ktest
files. Inputs and raw KLEE artifacts are written below the request's out/.
The worker has no network and accepts no arbitrary shell commands.

For a target that exposes `LLVMFuzzerTestOneInput`, KLEE does not call that
entry point automatically. Compile the real fuzz entry point and its required
target code to bitcode, then add a small `main` that creates a bounded
symbolic byte buffer named `input` (via `klee_make_symbolic`) and calls the
real fuzz entry point. Keep the harness separate from the target code. The
worker materializes objects named `stdin`, `input`, `input_bytes`,
`fuzz_input`, `symbolic_input`, or `*_data` / `*_contents` as concrete files
under the testcase output directory. If a testcase has `inputs: []`, it only
contains symbolic program state; it is not an external target input and must
not be presented as a generated PoC.

Do not reimplement the candidate function or its surrounding behavior in a
standalone model and describe that as target execution. A function-level model
can be useful for hypothesis exploration, but label it as such and do not
count it as an end-to-end symbolic testcase. If the real target-derived code
cannot be compiled or modeled, preserve that compatibility failure and
continue ordinary dynamic validation.
'''

_MAX_ARCHIVE_FILES = 512
_MAX_ARCHIVE_FILE_BYTES = 8 * 1024 * 1024
_MAX_ARCHIVE_TOTAL_BYTES = 32 * 1024 * 1024


def _persist_job_source_tree(
    workspace: Path, request_path: Path, destination: Path
) -> dict[str, Any]:
    """Archive bounded, non-VCS source inputs so KLEE jobs are auditable."""
    manifest: dict[str, Any] = {
        "status": "unavailable",
        "source_files": [],
        "omitted": [],
    }
    try:
        request = json.loads(request_path.read_text())
        workdir_value = request.get("working_dir") if isinstance(request, dict) else None
        if not isinstance(workdir_value, str) or not workdir_value:
            raise ValueError("request has no working_dir")
        relative = Path(workdir_value)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("working_dir is not a safe relative path")
        root = workspace.resolve()
        source_root = (workspace / relative).resolve()
        if not source_root.is_relative_to(root) or not source_root.is_dir():
            raise ValueError("working_dir is missing or outside the KLEE workspace")

        destination.mkdir(parents=True, exist_ok=True)
        excluded_dirs = {".git", ".hg", ".svn", "__pycache__", ".venv", "node_modules"}
        copied_bytes = 0
        for current, dirs, files in os.walk(source_root, followlinks=False):
            current_path = Path(current)
            dirs[:] = [
                name for name in dirs
                if name not in excluded_dirs
                and not (current_path / name).is_symlink()
            ]
            for name in sorted(files):
                path = current_path / name
                relative_path = path.relative_to(source_root)
                if path.is_symlink():
                    manifest["omitted"].append({"path": str(relative_path), "reason": "symlink"})
                    continue
                if len(manifest["source_files"]) >= _MAX_ARCHIVE_FILES:
                    manifest["omitted"].append({"path": str(relative_path), "reason": "file_limit"})
                    continue
                try:
                    size = path.stat().st_size
                except OSError as exc:
                    manifest["omitted"].append({"path": str(relative_path), "reason": str(exc)[:200]})
                    continue
                if size > _MAX_ARCHIVE_FILE_BYTES:
                    manifest["omitted"].append({"path": str(relative_path), "reason": "file_too_large"})
                    continue
                if copied_bytes + size > _MAX_ARCHIVE_TOTAL_BYTES:
                    manifest["omitted"].append({"path": str(relative_path), "reason": "archive_size_limit"})
                    continue
                target = destination / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
                copied_bytes += size
                manifest["source_files"].append({"path": str(relative_path), "size": size})

        manifest.update({
            "status": "complete" if not manifest["omitted"] else "bounded",
            "working_dir": workdir_value,
            "file_count": len(manifest["source_files"]),
            "total_bytes": copied_bytes,
        })
    except Exception as exc:
        manifest["error"] = f"{type(exc).__name__}: {exc}"
    return manifest


class KleeSession:
    """Owns an isolated worker and a writable directory shared with the agent."""

    name = "klee"

    def __init__(
        self,
        *,
        container_name: str,
        result_path: str | None = None,
        image: str = KLEE_IMAGE,
        startup_timeout_s: float = 60.0,
    ) -> None:
        self.container_name = (container_name + "_klee")[:63]
        self.result_path = Path(result_path) if result_path else None
        self.image = image
        self.startup_timeout_s = startup_timeout_s
        self._temp: tempfile.TemporaryDirectory[str] | None = None
        self.workspace: Path | None = None
        self.started_at: float | None = None
        self.status = "not_started"
        self.errors: list[str] = []
        self._summary: dict[str, Any] | None = None

    def __enter__(self) -> "KleeSession":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.collect()
        finally:
            self.stop()

    def start(self) -> None:
        if not docker_ops.image_exists(self.image):
            docker_ops.pull(self.image)
        self._temp = tempfile.TemporaryDirectory(prefix="vp-klee-")
        self.workspace = Path(self._temp.name)
        (self.workspace / "requests").mkdir()
        shutil.copyfile(Path(__file__).with_name("worker.py"), self.workspace / "worker.py")
        self.started_at = time.time()
        cmd = [
            "docker", "run", "-d", "--name", self.container_name,
            "--network", "none", "--memory", "6g", "--cpus", "2",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--env", "HOME=/tmp",
            "--env", "TMPDIR=/var/tmp",
            "--pids-limit", "128", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/var/tmp:rw,nosuid,size=1g",
            "--tmpfs", "/dev/shm:rw,nosuid,size=1g",
            "--mount", f"type=bind,src={self.workspace},dst=/symbolic",
            "--entrypoint", "python3", self.image, "/symbolic/worker.py",
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            self.status = "unavailable"
            detail = getattr(exc, "stderr", "") or str(exc)
            self.errors.append(f"could not start KLEE worker: {detail[-1000:]}")
            self._cleanup_temp()
            raise RuntimeError(self.errors[-1]) from exc

        deadline = time.monotonic() + self.startup_timeout_s
        while time.monotonic() < deadline:
            if (self.workspace / "worker.ready").exists():
                self.status = "ready"
                return
            state = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", self.container_name],
                capture_output=True, text=True,
            )
            if state.returncode or state.stdout.strip() != "true":
                logs = subprocess.run(
                    ["docker", "logs", self.container_name],
                    capture_output=True, text=True,
                )
                self.errors.append(f"KLEE worker exited: {(logs.stdout + logs.stderr)[-1000:]}")
                self.stop()
                raise RuntimeError(self.errors[-1])
            time.sleep(0.2)
        self.errors.append("timed out waiting for KLEE worker readiness")
        self.stop()
        raise RuntimeError(self.errors[-1])

    def mount(self) -> tuple[str, str]:
        if self.workspace is None:
            raise RuntimeError("KLEE session has not started")
        return str(self.workspace), "/work/symbolic"

    def prepare_agent(self, container: str) -> dict[str, Any]:
        if self.status == "ready":
            docker_ops.write_file(container, "/work/symbolic/klee-submit", _CLIENT.encode())
            docker_ops.write_file(container, "/work/symbolic/README.md", _README.encode())
            rc, _out, err = docker_ops.exec_sh(
                container, "chmod +x /work/symbolic/klee-submit", timeout=15
            )
            if rc:
                self.status = "prepare_failed"
                self.errors.append(f"cannot enable KLEE client: {err[-500:]}")
        return self.to_dict()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "provider": self.name,
            "image": self.image,
            "status": self.status,
            "capabilities": [
                "C-and-C++-LLVM-bitcode", "POSIX-symbolic-files",
                "symbolic-arguments", "SMT-path-constraints",
                "concrete-testcase-extraction",
            ],
            "client": "/work/symbolic/klee-submit",
            "workspace": "/work/symbolic",
            "errors": list(self.errors),
        }

    def collect(self) -> dict[str, Any]:
        if self._summary is not None:
            return self._summary
        jobs: list[dict[str, Any]] = []
        if self.workspace is not None:
            for job in sorted((self.workspace / "requests").glob("job.*")):
                path = job / "summary.json"
                if path.exists():
                    try:
                        job_summary = json.loads(path.read_text())
                    except (OSError, ValueError):
                        job_summary = {"request_id": job.name, "status": "invalid_summary"}
                    jobs.append(job_summary)
        finished = time.time()
        self._summary = {
            **self.to_dict(),
            "started_at": self.started_at,
            "finished_at": finished,
            "duration_s": round(finished - self.started_at, 3) if self.started_at else 0,
            "jobs": jobs,
        }
        if self.result_path is not None:
            self.result_path.mkdir(parents=True, exist_ok=True)
            if self.workspace is not None:
                for job in sorted((self.workspace / "requests").glob("job.*")):
                    dest = self.result_path / "jobs" / job.name
                    dest.mkdir(parents=True, exist_ok=True)
                    for filename in ("request.json", "summary.json", "worker-error"):
                        source = job / filename
                        if source.is_file():
                            shutil.copy2(source, dest / filename)
                    source_manifest = _persist_job_source_tree(
                        self.workspace, job / "request.json", dest / "source-tree"
                    )
                    (dest / "source_manifest.json").write_text(
                        json.dumps(source_manifest, indent=2, ensure_ascii=False) + "\n"
                    )
                    job_summary = next(
                        (item for item in self._summary["jobs"] if item.get("request_id") == job.name),
                        None,
                    )
                    if job_summary is not None:
                        job_summary["source_archive"] = f"jobs/{job.name}/source-tree"
                        job_summary["source_archive_status"] = source_manifest["status"]
                        job_summary["source_file_count"] = source_manifest.get("file_count", 0)
                    if (job / "out").exists():
                        shutil.copytree(
                            job / "out",
                            dest / "out",
                            dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("*.bc"),
                        )
            (self.result_path / "summary.json").write_text(
                json.dumps(self._summary, indent=2, ensure_ascii=False) + "\n"
            )
        return self._summary

    def stop(self) -> None:
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            capture_output=True, text=True,
        )
        self._cleanup_temp()

    def _cleanup_temp(self) -> None:
        if self._temp is not None:
            self._temp.cleanup()
            self._temp = None
            self.workspace = None
