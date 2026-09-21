#!/usr/bin/env python3
"""No-network SymCC worker for bounded, concrete-seed concolic runs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

ROOT = Path("/symbolic")
MAX_JOB_TIMEOUT = 300
MAX_SOURCES = 512
MAX_SEEDS = 128
MAX_TESTCASES = 256
MAX_INPUT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def relative_path(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{field} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field} must stay inside the job directory")
    return path


def string_list(value: object, field: str, limit: int) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{field} must be a list with at most {limit} entries")
    if not all(isinstance(item, str) and "\x00" not in item for item in value):
        raise ValueError(f"{field} entries must be strings without NUL bytes")
    return value


def compiler_flags(value: object) -> list[str]:
    flags = string_list(value, "compile_flags", 256)
    for flag in flags:
        allowed = (
            flag in {"-g", "-O0", "-O1", "-O2", "-fno-builtin", "-pthread"}
            or re.fullmatch(r"-std=(c|gnu)(89|99|11|17|\+\+11|\+\+14|\+\+17)", flag)
            or re.fullmatch(r"-D[A-Za-z_][A-Za-z0-9_]*(=[A-Za-z0-9_+-]+)?", flag)
            or re.fullmatch(r"-I[A-Za-z0-9_./+-]+", flag)
        )
        if not allowed:
            raise ValueError(f"unsupported compiler flag: {flag}")
    return flags


def link_flags(value: object) -> list[str]:
    flags = string_list(value, "link_flags", 128)
    for flag in flags:
        if flag not in {"-pthread", "-static"} and not re.fullmatch(
            r"-l[A-Za-z0-9_+.-]+", flag
        ):
            raise ValueError(f"unsupported link flag: {flag}")
    return flags


def program_arguments(value: object) -> list[str]:
    values = string_list(value, "program_args", 128)
    if sum(item.count("{input_file}") for item in values) != 1:
        raise ValueError("program_args must contain {input_file} exactly once")
    if any("{" in item.replace("{input_file}", "") for item in values):
        raise ValueError("program_args contains an unsupported placeholder")
    return values


def per_seed_testcase_budget(remaining_cases: int, remaining_seeds: int) -> int:
    """Split the remaining request budget across seeds without starving later ones."""
    if remaining_seeds < 1:
        raise ValueError("remaining_seeds must be positive")
    if remaining_cases < remaining_seeds:
        raise ValueError("testcase budget must allow at least one case per remaining seed")
    return remaining_cases // remaining_seeds


def _inside(root: Path, path: Path, field: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError(f"{field} escapes the job directory")
    return resolved


def _files_below(path: Path) -> list[Path]:
    if not path.exists():
        return []
    return sorted(item for item in path.iterdir() if item.is_file())


def _stop_process(process: subprocess.Popen, *, force: bool = False) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def _execute_seed(
    *,
    binary: Path,
    seed: Path,
    workdir: Path,
    output: Path,
    args: list[str],
    timeout_s: int,
    max_testcases: int,
    output_bytes_left: int,
) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    log = output / "run.log"
    env = os.environ.copy()
    env["SYMCC_INPUT_FILE"] = str(seed)
    env["SYMCC_OUTPUT_DIR"] = str(output / "generated")
    (output / "generated").mkdir(exist_ok=True)
    argv = [str(binary), *(arg.replace("{input_file}", str(seed)) for arg in args)]
    started = time.time()
    testcase_limit_reached = False
    output_limit_reached = False
    deadline = time.monotonic() + timeout_s
    with log.open("wb") as stream:
        process = subprocess.Popen(
            argv,
            cwd=workdir,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            while process.poll() is None:
                generated = _files_below(output / "generated")
                generated_bytes = sum(item.stat().st_size for item in generated)
                if len(generated) >= max_testcases:
                    testcase_limit_reached = True
                    _stop_process(process)
                    break
                if generated_bytes >= output_bytes_left:
                    output_limit_reached = True
                    _stop_process(process)
                    break
                if time.monotonic() >= deadline:
                    _stop_process(process)
                    break
                time.sleep(0.1)
        finally:
            if process.poll() is None:
                _stop_process(process, force=True)
        return_code = process.wait()

    generated = _files_below(output / "generated")
    generated_bytes = 0
    testcases = []
    testcase_dir = output.parent.parent / "testcases" / output.name
    for source in generated[:max_testcases]:
        size = source.stat().st_size
        if size > MAX_INPUT_BYTES or generated_bytes + size > output_bytes_left:
            output_limit_reached = True
            continue
        destination = testcase_dir / source.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        data_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        testcases.append({
            "path": str(destination.relative_to(ROOT)),
            "size": size,
            "sha256": data_hash,
            "seed": str(seed.relative_to(workdir)),
        })
        generated_bytes += size

    elapsed = round(time.time() - started, 3)
    return {
        "seed": str(seed.relative_to(workdir)),
        "status": "testcase_limit" if testcase_limit_reached else
                  "output_limit" if output_limit_reached else
                  "timeout" if time.monotonic() >= deadline else
                  "completed" if return_code == 0 else "failed",
        "exit_code": return_code,
        "duration_s": elapsed,
        "generated_count": len(generated),
        "testcases": testcases,
        "log": str(log.relative_to(ROOT)),
    }


def process(job: Path) -> None:
    started = time.time()
    summary = {
        "provider": "symcc",
        "request_id": job.name,
        "status": "failed",
        "started_at": started,
        "errors": [],
        "runs": [],
        "testcases": [],
    }
    output = job / "out"
    output.mkdir(exist_ok=True)
    try:
        spec = json.loads((job / "request.json").read_text())
        if not isinstance(spec, dict) or spec.get("schema_version", 1) != 1:
            raise ValueError("request must be a schema_version 1 JSON object")

        workdir_rel = relative_path(spec.get("working_dir"), "working_dir")
        workdir = _inside(ROOT, ROOT / workdir_rel, "working_dir")
        if not workdir.is_dir():
            raise ValueError("working_dir is missing")

        source_names = string_list(spec.get("sources"), "sources", MAX_SOURCES)
        if not source_names:
            raise ValueError("at least one source file is required")
        sources = []
        for value in source_names:
            path = _inside(workdir, workdir / relative_path(value, "source"), "source")
            if not path.is_file():
                raise ValueError(f"source is missing: {value}")
            sources.append(path)

        seed_names = string_list(spec.get("seed_files"), "seed_files", MAX_SEEDS)
        if not seed_names:
            raise ValueError("at least one concrete seed file is required")
        seeds = []
        for value in seed_names:
            path = _inside(workdir, workdir / relative_path(value, "seed"), "seed")
            if not path.is_file():
                raise ValueError(f"seed file is missing: {value}")
            if path.stat().st_size > MAX_INPUT_BYTES:
                raise ValueError(f"seed exceeds {MAX_INPUT_BYTES} bytes: {value}")
            seeds.append(path)

        flags = compiler_flags(spec.get("compile_flags", ["-g", "-O0"]))
        libraries = link_flags(spec.get("link_flags", []))
        args = program_arguments(spec.get("program_args", ["{input_file}"]))
        timeout_s = spec.get("timeout_s", 120)
        if not isinstance(timeout_s, int) or not 1 <= timeout_s <= MAX_JOB_TIMEOUT:
            raise ValueError(f"timeout_s must be between 1 and {MAX_JOB_TIMEOUT}")
        max_testcases = spec.get("max_testcases", 64)
        if not isinstance(max_testcases, int) or not 1 <= max_testcases <= MAX_TESTCASES:
            raise ValueError(f"max_testcases must be between 1 and {MAX_TESTCASES}")
        if max_testcases < len(seeds):
            raise ValueError(
                "max_testcases must allow at least one case for each seed"
            )

        compiler = shutil.which("symcc")
        if not compiler:
            raise RuntimeError("SymCC compiler wrapper is unavailable")
        binary = output / "symcc-target"
        command = [compiler, *flags, *(str(path) for path in sources),
                   *libraries, "-o", str(binary)]
        summary["compiler_command"] = command
        compile_started = time.time()
        compiled = subprocess.run(
            command, cwd=workdir, capture_output=True, text=True, timeout=timeout_s,
        )
        summary["compile_duration_s"] = round(time.time() - compile_started, 3)
        summary["compile_stdout"] = compiled.stdout[-4000:]
        summary["compile_stderr"] = compiled.stderr[-8000:]
        if compiled.returncode:
            raise RuntimeError(f"SymCC compile failed ({compiled.returncode})")

        cases_used = 0
        output_bytes = 0
        for index, seed in enumerate(seeds):
            remaining_seed_count = len(seeds) - index
            remaining_cases = max_testcases - cases_used
            remaining_bytes = MAX_OUTPUT_BYTES - output_bytes
            if remaining_bytes <= 0:
                summary["errors"].append(
                    "request-wide output limit reached before all seeds were processed"
                )
                break
            seed_case_budget = per_seed_testcase_budget(
                remaining_cases, remaining_seed_count
            )
            run_dir = output / "generated" / f"seed-{index:04d}-{seed.name[:48]}"
            run_result = _execute_seed(
                binary=binary,
                seed=seed,
                workdir=workdir,
                output=run_dir,
                args=args,
                timeout_s=timeout_s,
                max_testcases=seed_case_budget,
                output_bytes_left=remaining_bytes,
            )
            summary["runs"].append({key: value for key, value in run_result.items()
                                    if key not in {"testcases"}})
            summary["testcases"].extend(run_result["testcases"])
            cases_used += len(run_result["testcases"])
            output_bytes += sum(item["size"] for item in run_result["testcases"])

        if not summary["errors"]:
            summary["status"] = "completed"
        summary["symcc_command"] = command
        summary["testcase_count"] = len(summary["testcases"])
    except subprocess.TimeoutExpired as exc:
        summary["errors"].append(f"SymCC compilation exceeded timeout: {exc.timeout}s")
    except Exception as exc:
        summary["errors"].append(f"{type(exc).__name__}: {exc}")
        (job / "worker-error").write_text(summary["errors"][-1] + "\n")

    summary["finished_at"] = time.time()
    summary["duration_s"] = round(summary["finished_at"] - started, 3)
    (job / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n"
    )
    (job / "done").touch()


def main() -> None:
    (ROOT / "worker.ready").touch()
    seen: set[str] = set()
    while True:
        for job in sorted((ROOT / "requests").glob("job.*")):
            if job.name in seen:
                continue
            try:
                ready = (job / "ready").is_file()
            except PermissionError:
                continue
            if ready:
                seen.add(job.name)
                process(job)
        time.sleep(0.2)


if __name__ == "__main__":
    main()
