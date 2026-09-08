"""Persistent repository → recipe → build → acceptance jobs."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shlex
import shutil
import tempfile
import time
from pathlib import Path

import yaml

from .acceptance import validate_image
from .process import Cancelled, CommandFailed, Runner, TimedOut, error_excerpt
from .recipe import NeedsConfig, generate_plan, validate_plan
from .source import fetch_source, tree_digest, utcnow, write_json

TERMINAL = {"passed", "build_failed", "validation_failed", "planning_failed", "source_failed",
            "needs_config", "timed_out", "cancelled", "failed"}


def load(path: Path) -> dict:
    return json.loads(path.read_text())


class Job:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.options = load(root / "job.json")
        self.state = load(root / "status.json")
        self.runner = Runner(self.root, time.monotonic() + self.options["task_timeout"], self.beat)

    def update(self, **changes) -> None:
        self.state.update(changes, updated_at=utcnow())
        write_json(self.root / "status.json", self.state)

    def stage(self, name: str, **changes) -> None:
        changes.setdefault("message", "")
        changes.setdefault("error", None)
        changes.setdefault("progress", None)
        self.update(status="running", stage=name, **changes)
        print(f"[{name}] {changes.get('message', '')}", flush=True)

    def beat(self, progress: dict) -> None:
        self.update(progress=progress)
        print(f"[{self.state.get('stage')}] elapsed {progress['elapsed_s']}s; "
              f"quiet {progress['quiet_s']}s; log: {progress['log']}", flush=True)

    def execute(self) -> int:
        # One worker per job AND one publisher per target. No overwritten edits.
        target = Path(self.options["target_dir"])
        target.mkdir(parents=True, exist_ok=True)
        with (self.root / ".worker.lock").open("a") as worker_lock, (target / ".lock").open("a") as target_lock:
            try:
                fcntl.flock(worker_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("this job already has an active worker", flush=True)
                return 2
            try:
                fcntl.flock(target_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.update(status="failed", error="another job is building this target; retry later")
                return 2
            self.update(pid=os.getpid(), status="running", error=None, finished_at=None)
            try:
                return self._execute()
            except Cancelled as exc:
                self.update(status="cancelled", error=str(exc))
                return 130
            except KeyboardInterrupt:
                self.update(status="cancelled", error="interrupted by user")
                return 130
            except TimedOut as exc:
                self.update(status="timed_out", error=str(exc))
                return 124
            except NeedsConfig as exc:
                self.update(status="needs_config", error=str(exc))
                return 2
            except Exception as exc:
                status = "source_failed" if self.state.get("stage") == "source" else "failed"
                self.update(status=status, error=f"{type(exc).__name__}: {exc}")
                return 1
            finally:
                self.update(finished_at=utcnow())
                print(f"Result: {self.state['status']}\nResults: {self.root}", flush=True)
                if self.state.get("error"):
                    print(self.state["error"], flush=True)

    def _execute(self) -> int:
        o, runner = self.options, self.runner
        self.stage("preflight")
        runner.run(["docker", "info", "--format", "{{.ServerVersion}}"], log=self.root / "preflight.log")
        current = Path(o["target_dir"]) / "current.json"
        if current.exists() and load(current)["source"]["repo"] != o["repo"]:
            raise ValueError("target name is already associated with another repository")
        self.stage("source", message="fetching remote branch HEAD")
        if (self.root / "source.lock.json").exists():
            lock = load(self.root / "source.lock.json")
            if tree_digest(self.root / "source") != lock["snapshot_sha256"]:
                raise ValueError("locked source was modified; start a new job")
            print(f"Resuming locked commit {lock['commit']}; a new run checks remote HEAD.", flush=True)
        else:
            # Failed partial fetches are preserved; restart in a fresh subdirectory.
            previous = self.root / "checkout"
            if previous.exists():
                previous.rename(self.root / f"checkout-incomplete-{time.time_ns()}")
            source = self.root / "source"
            if source.exists():
                source.rename(self.root / f"source-incomplete-{time.time_ns()}")
            lock = fetch_source(o["repo"], o.get("branch"), self.root, runner, o["fetch_timeout"])
        self.update(source=lock)
        print(f"Source: {lock['branch']} → {lock['commit']}", flush=True)
        source = self.root / "source"
        previous_plan = load(self.root / "plan.json") if (self.root / "plan.json").exists() else None
        cached_plan = None
        if current.exists() and not previous_plan and not o.get("recipe") and not o.get("replan"):
            verified = load(current)
            if (verified["source"]["commit"] == lock["commit"] and
                    verified["source"]["snapshot_sha256"] == lock["snapshot_sha256"]):
                candidate = load(Path(verified["context"]) / "plan.json")
                fingerprint = hashlib.sha256(json.dumps(candidate, sort_keys=True).encode()).hexdigest()
                if fingerprint == verified["recipe_sha256"]:
                    cached_plan = candidate
        failure = self.state.get("last_failure")
        if previous_plan:
            build_logs = sorted(self.root.glob("attempt_*/build.log"))
            if build_logs:
                # A malformed repair response must not hide the original build error.
                failure = (failure or "") + "\nPrevious build diagnostics:\n" + error_excerpt(build_logs[-1].read_text())
        previous_attempts = [int(p.name.split("_")[1]) for p in self.root.glob("attempt_[0-9]*") if p.is_dir()]
        start = max(previous_attempts, default=0) + 1
        for number in range(start, start + o["build_attempts"]):
            runner.check()
            attempt = self.root / f"attempt_{number:02d}"
            attempt.mkdir()
            self.stage("planning", attempt=number)
            try:
                if o.get("recipe"):
                    plan = validate_plan(load(self.root / "input-recipe.json"), source)
                    if previous_plan and plan["acceptance"] != previous_plan["acceptance"]:
                        raise ValueError("input recipe changed frozen acceptance")
                elif cached_plan is not None:
                    print("Remote commit unchanged; reusing verified recipe and re-running acceptance.", flush=True)
                    plan, cached_plan = validate_plan(cached_plan, source), None
                else:
                    plan = generate_plan(source, lock, attempt, runner, o, previous_plan, failure)
                validate_plan(plan, source)
                if previous_plan and plan["acceptance"] != previous_plan["acceptance"]:
                    raise ValueError("repair attempted to change the frozen acceptance contract")
                write_json(attempt / "plan.json", plan)
                previous_plan = plan
                write_json(self.root / "plan.json", plan)
                (self.root / "acceptance.yaml").write_text(yaml.safe_dump(plan["acceptance"], sort_keys=False))
            except (ValueError, CommandFailed) as exc:
                failure = str(exc)
                self.update(last_failure=failure, error=failure, status="planning_failed")
                print(f"Planning failed: {failure}", flush=True)
                continue
            context = attempt / "context"
            context.mkdir()
            shutil.copytree(source, context / "source", symlinks=True)
            for name, content in plan["files"].items():
                path = context / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            if not (context / ".dockerignore").exists():
                (context / ".dockerignore").write_text("**/.git\n")
            write_json(context / "source.lock.json", lock)
            (context / "acceptance.yaml").write_text(yaml.safe_dump(plan["acceptance"], sort_keys=False))
            recipe_hash = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
            tag = f"secrun/{o['name']}:{lock['commit'][:12]}-{o['job_id'][-8:]}-{number}"
            self.stage("building", image_tag=tag)
            cmd = ["docker", "build", "--progress=plain", "--iidfile", str(attempt / "image.iid"),
                   "--label", f"org.opencontainers.image.revision={lock['commit']}",
                   "--label", f"org.opencontainers.image.source={lock['repo']}",
                   "--label", f"io.secrun.recipe={recipe_hash}", "-t", tag]
            if o.get("build_network"):
                cmd += ["--network", o["build_network"]]
            try:
                runner.run([*cmd, str(context)], log=attempt / "build.log",
                           timeout=o["build_timeout"], live=True)
            except CommandFailed as exc:
                failure = str(exc)
                self.update(status="build_failed", last_failure=failure, error=failure)
                if o.get("recipe"):
                    return 1
                continue
            image_id = (attempt / "image.iid").read_text().strip()
            if not image_id.startswith("sha256:"):
                raise ValueError("build did not return an immutable image ID")
            details = json.loads(runner.run(["docker", "image", "inspect", image_id],
                                            log=attempt / "image.log").stdout)[0]
            write_json(attempt / "image.json", details)
            if details["Config"].get("Labels", {}).get("org.opencontainers.image.revision") != lock["commit"]:
                raise ValueError("built image revision does not match locked source")
            self.stage("validating", image_id=image_id)
            report = validate_image(image_id, plan, attempt, runner, o)
            write_json(self.root / "acceptance.json", report)
            if report["status"] != "passed":
                failure = json.dumps(report, ensure_ascii=False)[-16000:]
                self.update(status="validation_failed", last_failure=failure, error=failure)
                if o.get("recipe"):
                    return 1
                continue
            runner.check()
            # Re-check untouched context before publishing provenance.
            if tree_digest(context / "source") != lock["snapshot_sha256"]:
                raise ValueError("build context source changed during the task")
            self.stage("publishing")
            destination = Path(o["target_dir"]) / "versions" / f"{o['job_id']}-{number:02d}"
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise ValueError("publication path exists; refusing to overwrite")
            staging = Path(tempfile.mkdtemp(prefix=f".publish-{o['job_id']}-", dir=destination.parent))
            shutil.copytree(context, staging, symlinks=True, dirs_exist_ok=True)
            run_command = self.run_command(tag, plan)
            summary = {"status": "passed", "source": lock, "image_id": image_id,
                       "image_tag": tag, "recipe_sha256": recipe_hash,
                       "context": str(destination), "results": str(self.root),
                       "run_command": run_command, "verified_at": utcnow()}
            write_json(staging / "image.json", summary)
            write_json(staging / "plan.json", plan)
            write_json(staging / "acceptance.json", report)
            readme = (f"# {o['name']} runnable image\n\n{plan.get('summary', '')}\n\n"
                      f"Source: `{lock['repo']}` / `{lock['branch']}` / `{lock['commit']}`\n\n"
                      f"Validated image: `{image_id}`\n\nRun:\n\n```sh\n{run_command}\n```\n\n"
                      f"Acceptance kind: `{plan['acceptance']['kind']}`; "
                      f"{len(report['cases'])} checks passed. See acceptance.json.\n\n"
                      "Rebuild this snapshot (dependencies/base images may evolve):\n\n"
                      f"```sh\ndocker build -t {shlex.quote(tag)} {shlex.quote(str(destination))}\n```\n")
            (staging / "README.md").write_text(readme)
            runner.check()
            staging.rename(destination)
            runner.check()
            write_json(current, summary)
            self.update(**summary, stage="complete", error=None)
            print(f"Image ready: {tag}\nRun: {run_command}\nFiles: {destination}", flush=True)
            return 0
        return 1

    @staticmethod
    def run_command(tag: str, plan: dict) -> str:
        contract = plan["acceptance"]
        run = contract["run"]
        cmd = ["docker", "run", "--rm", "-i"]
        for key, value in run.get("env", {}).items():
            cmd += ["-e", f"{key}={value}"]
        for key in run.get("required_env", []):
            cmd += ["-e", key]
        if contract["kind"] == "http":
            cmd += ["-p", f"127.0.0.1:{run['port']}:{run['port']}"]
        return shlex.join([*cmd, tag, *run.get("args", [])])
