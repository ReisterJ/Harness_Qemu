"""Bounded subprocesses with durable logs and an independent heartbeat."""
from __future__ import annotations

import os
import re
import selectors
import shlex
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


class Cancelled(RuntimeError):
    pass


class TimedOut(RuntimeError):
    pass


@dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str


class CommandFailed(RuntimeError):
    def __init__(self, result: Result, log: Path):
        self.result = result
        super().__init__(f"command exited {result.returncode}; log: {log}\n"
                         f"{error_excerpt(result.stderr or result.stdout)}")


def error_excerpt(output: str) -> str:
    """Preserve root compiler/package errors before BuildKit's long Go traceback."""
    lines = output.splitlines()
    selected = set()
    for index, line in enumerate(lines):
        if re.search(r"error:|error |failed|not found|no such|can't exec|cannot", line, re.I):
            selected.update(range(max(0, index - 2), min(len(lines), index + 3)))
    diagnostic = "\n".join(lines[index] for index in sorted(selected))[:9000]
    return diagnostic + "\nLast output:\n" + output[-3000:]


class Runner:
    def __init__(self, root: Path, deadline: float,
                 heartbeat: Callable[[dict], None] | None = None):
        self.root = root
        self.deadline = deadline
        self.heartbeat = heartbeat or (lambda _: None)
        self.next_heartbeat = 0.0

    def check(self) -> None:
        if (self.root / "cancel.request").exists():
            raise Cancelled("cancellation requested")
        if time.monotonic() >= self.deadline:
            raise TimedOut("task time budget exhausted")

    def run(self, argv: list[str], *, log: Path, timeout: float = 60,
            cwd: Path | None = None, env: dict[str, str] | None = None,
            stdin: str | None = None, check: bool = True,
            live: bool = False, describe: str | None = None) -> Result:
        self.check()
        log.parent.mkdir(parents=True, exist_ok=True)
        started = last_output = time.monotonic()
        end = min(self.deadline, started + timeout)
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        # A file-backed stdin avoids a pipe deadlock on large test fixtures.
        with tempfile.TemporaryFile() as inp, log.open("ab") as output:
            if stdin is not None:
                inp.write(stdin.encode())
            inp.seek(0)
            output.write(("\n$ " + (describe or shlex.join(argv)) + "\n").encode())
            output.flush()
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=inp,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True)
            completed = False
            try:
                with selectors.DefaultSelector() as selector:
                    for key in buffers:
                        stream = getattr(proc, key)
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, key)
                    while selector.get_map() or proc.poll() is None:
                        self.check()
                        now = time.monotonic()
                        if now >= end:
                            raise TimedOut(f"command exceeded {timeout:g}s; log: {log}")
                        if now >= self.next_heartbeat:
                            self.heartbeat({"elapsed_s": round(now - started, 1),
                                            "quiet_s": round(now - last_output, 1),
                                            "log": str(log)})
                            self.next_heartbeat = now + 10
                        for event, _ in selector.select(0.2):
                            data = os.read(event.fileobj.fileno(), 65536)
                            if not data:
                                selector.unregister(event.fileobj)
                                continue
                            last_output = time.monotonic()
                            output.write(data)
                            output.flush()
                            buf = buffers[event.data]
                            buf.extend(data)
                            # Full output stays on disk; bound in-memory capture.
                            if len(buf) > 16 * 1024 * 1024:
                                del buf[:-16 * 1024 * 1024]
                            if live:
                                print(data.decode(errors="replace"), end="", flush=True)
                    result = Result(proc.wait(), *(buffers[k].decode(errors="replace")
                                                   for k in ("stdout", "stderr")))
                    completed = True
            finally:
                if not completed or proc.poll() is None:
                    self._stop(proc)
                for stream in (proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()
            if check and result.returncode:
                raise CommandFailed(result, log)
            return result

    @staticmethod
    def _stop(proc: subprocess.Popen) -> None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        except ProcessLookupError:
            pass
        # The leader may already have exited while a descendant still owns a
        # pipe. Always reap the entire task-owned process group on interruption.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=3)


def cleanup_container(name: str) -> str | None:
    """Cleanup still runs after the task's deadline or cancellation."""
    try:
        result = subprocess.run(["docker", "rm", "-f", name],
                                capture_output=True, text=True, timeout=20)
        if result.returncode and "No such container" not in result.stderr:
            return result.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)
    return None
