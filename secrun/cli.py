"""User-facing image jobs; all commands operate independently of find/grade."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from harness.agent_image import BASE_TAG
from harness.cli import _load_dotenv

from .process import Cancelled
from .source import utcnow, validate_name, validate_repo, write_json
from .workflow import Job, TERMINAL, load


def duration(value: str) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(s|m|h)?", value)
    if not match or float(match[1]) <= 0:
        raise argparse.ArgumentTypeError("use a positive duration, e.g. 30m or 90s")
    return float(match[1]) * {None: 1, "s": 1, "m": 60, "h": 3600}[match[2]]


def positive(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def active(root: Path) -> bool:
    with (root / ".worker.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            return True


def interrupted(root: Path, state: dict) -> bool:
    if state["status"] not in {"running", "queued"} or active(root):
        return False
    timestamp = state.get("resumed_at") or state.get("created_at")
    # Allow a short interval for a newly detached worker to acquire its lock.
    return timestamp is None or (datetime.now(timezone.utc) - datetime.fromisoformat(timestamp)).total_seconds() > 5


def resolve_job(value: str, workspace: Path) -> Path:
    path = Path(value).expanduser()
    if (path / "job.json").is_file():
        return path.resolve()
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", value):
        raise ValueError("job must be an ID or a job directory")
    candidates = list((workspace / "results" / "images").glob(f"*/{value}/job.json"))
    if len(candidates) != 1:
        raise ValueError("job not found; supply its results directory or --workspace")
    return candidates[0].parent.resolve()


def launch(root: Path, detach: bool) -> int:
    if detach:
        with (root / "console.log").open("ab") as log:
            child = subprocess.Popen([sys.executable, "-m", "secrun", "_worker", str(root)],
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                     start_new_session=True)
        print(f"Job: {root.name}\nPID: {child.pid}\nResults: {root}\n"
              f"Status: secrun status {root}\nLogs: secrun logs {root} --follow")
        return 0
    return worker(root)


def worker(root: Path) -> int:
    def interrupt(signum, frame):
        raise Cancelled(f"received signal {signum}")
    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        return Job(root).execute()
    finally:
        signal.signal(signal.SIGTERM, previous)


def management(command: str, argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog=f"secrun {command}")
    parser.add_argument("job", help="job ID or results directory")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    if command == "logs":
        parser.add_argument("--follow", "-f", action="store_true")
    if command == "resume":
        parser.add_argument("--detach", action="store_true")
        parser.add_argument("--build-timeout", type=duration)
        parser.add_argument("--task-timeout", type=duration)
        parser.add_argument("--agent-timeout", type=duration)
        parser.add_argument("--build-attempts", type=positive)
    args = parser.parse_args(argv)
    root = resolve_job(args.job, args.workspace.resolve())
    state = load(root / "status.json")
    if command == "status":
        if interrupted(root, state):
            state = {**state, "status": "interrupted", "message": "worker is no longer active; resume this job"}
        print(json.dumps(state, indent=2, ensure_ascii=False))
    elif command == "cancel":
        if state["status"] in TERMINAL and not active(root):
            print(f"Job already finished: {state['status']}")
        else:
            (root / "cancel.request").touch()
            print("Cancellation requested; use status to confirm the worker has stopped and cleaned up.")
    elif command == "resume":
        if active(root):
            raise ValueError("job is still running")
        if state["status"] == "passed":
            raise ValueError("job already passed; start a new run to check the latest remote commit")
        options = load(root / "job.json")
        for key in ("build_timeout", "task_timeout", "agent_timeout", "build_attempts"):
            if getattr(args, key) is not None:
                options[key] = getattr(args, key)
        write_json(root / "job.json", options)
        (root / "cancel.request").unlink(missing_ok=True)
        write_json(root / "status.json", {**state, "status": "queued", "resumed_at": utcnow()})
        print("Resuming the original source snapshot; a NEW run fetches the latest branch commit.")
        return launch(root, args.detach)
    elif command == "logs":
        offsets: dict[Path, int] = {}
        try:
            while True:
                # Includes foreground runs, which may have no console.log.
                for path in sorted(root.rglob("*.log")):
                    if "checkout" in path.parts or "source" in path.parts or "context" in path.parts:
                        continue
                    with path.open("rb") as stream:
                        stream.seek(offsets.get(path, 0))
                        text = stream.read()
                        offsets[path] = stream.tell()
                    if text:
                        print(f"\n[{path.relative_to(root)}]\n{text.decode(errors='replace')}", end="", flush=True)
                if not args.follow:
                    break
                state = load(root / "status.json")
                if state["status"] in TERMINAL and not active(root):
                    break
                if interrupted(root, state):
                    break
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    _load_dotenv()
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if argv and argv[0] == "_worker":
            return worker(Path(argv[1]))
        if argv and argv[0] in {"status", "logs", "cancel", "resume"}:
            return management(argv[0], argv[1:])
        parser = argparse.ArgumentParser(
            prog="secrun", description="Build and verify a runnable image from the latest repository branch.",
            epilog="Manage jobs: secrun status|logs|cancel|resume <job-ID-or-directory>")
        parser.add_argument("--name", required=True, help="target name under targets/<name>/image")
        parser.add_argument("--repo", required=True, help="Git repository URL")
        parser.add_argument("--branch", help="branch; omitted = remote default branch")
        parser.add_argument("--workspace", type=Path, default=Path.cwd())
        parser.add_argument("--model", default=os.getenv("SECRUN_MODEL") or os.getenv("VULN_PIPELINE_MODEL")
                            or ("deepseek/deepseek-chat" if os.getenv("DEEPSEEK_API_KEY") else None))
        parser.add_argument("--recipe", type=Path, help="use an explicit JSON/YAML image plan instead of an agent")
        parser.add_argument("--replan", action="store_true", help="regenerate even if the remote commit is unchanged")
        parser.add_argument("--detach", action="store_true")
        parser.add_argument("--build-timeout", type=duration, default=1800)
        parser.add_argument("--task-timeout", type=duration, default=5400)
        parser.add_argument("--agent-timeout", type=duration, default=600)
        parser.add_argument("--fetch-timeout", type=duration, default=300)
        parser.add_argument("--build-attempts", type=positive, default=3)
        parser.add_argument("--agent-steps", type=positive, default=16)
        parser.add_argument("--agent-image", default=BASE_TAG)
        parser.add_argument("--agent-network", default=os.getenv("SECRUN_AGENT_NETWORK", "bridge"))
        parser.add_argument("--agent-proxy", default=os.getenv("SECRUN_AGENT_PROXY"))
        parser.add_argument("--build-network", default=os.getenv("SECRUN_BUILD_NETWORK")
                            or os.getenv("VULN_PIPELINE_DOCKER_BUILD_NETWORK"))
        parser.add_argument("--memory", default="2g", help="planner/acceptance container memory limit")
        parser.add_argument("--cpus", type=positive, default=2, help="acceptance container CPU limit")
        args = parser.parse_args(argv)
        validate_name(args.name)
        validate_repo(args.repo)
        workspace = args.workspace.resolve()
        job_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
        root = workspace / "results" / "images" / args.name / job_id
        root.mkdir(parents=True)
        options = vars(args).copy()
        options.update(workspace=str(workspace), job_id=job_id,
                       target_dir=str(workspace / "targets" / args.name / "image"),
                       recipe=str(args.recipe.resolve()) if args.recipe else None)
        if args.recipe:
            write_json(root / "input-recipe.json", yaml.safe_load(args.recipe.read_text()))
        # API credentials remain in the environment, never job.json or image args.
        write_json(root / "job.json", options)
        write_json(root / "status.json", {"status": "queued", "stage": "queued",
                                          "job_id": job_id, "created_at": utcnow()})
        if not args.detach:
            print(f"Job: {job_id}\nResults: {root}", flush=True)
        return launch(root, args.detach)
    except (ValueError, OSError, KeyError) as exc:
        print(f"secrun: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
