#!/usr/bin/env python3
"""No-network KLEE queue worker; requests arrive through a private bind mount."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path("/symbolic")
MAX_JOB_TIMEOUT = 1800


def relative_path(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{field} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field} must stay inside the job directory")
    return path


def string_list(value: object, field: str, limit: int = 512) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{field} must be a list with at most {limit} entries")
    if not all(isinstance(item, str) and "\x00" not in item for item in value):
        raise ValueError(f"{field} entries must be strings without NUL bytes")
    return value


def compiler_flags(value: object) -> list[str]:
    flags = string_list(value, "compile_flags")
    for flag in flags:
        allowed = (
            flag in {"-g", "-O0", "-O1", "-O2", "-fno-builtin"}
            or re.fullmatch(r"-std=(c|gnu)(89|99|11|17|\+\+11|\+\+14|\+\+17)", flag)
            or re.fullmatch(r"-D[A-Za-z_][A-Za-z0-9_]*(=[A-Za-z0-9_+-]+)?", flag)
            or re.fullmatch(r"-I[A-Za-z0-9_./+-]+", flag)
        )
        if not allowed:
            raise ValueError(f"unsupported compiler flag: {flag}")
    return flags


def klee_flags(value: object) -> list[str]:
    values = string_list(value, "klee_args", 128)
    simple = {
        "--posix-runtime", "--write-smt2s", "--write-kqueries", "--write-cvcs",
        "--libc=uclibc", "--search=random-path", "--search=nurs:covnew",
        "--search=nurs:md2u", "--search=dfs", "--search=bfs",
    }
    valued = re.compile(r"--max-(forks|instructions|memory)=[0-9]+")
    result: list[str] = []
    index = 0
    while index < len(values):
        arg = values[index]
        if arg in simple or valued.fullmatch(arg):
            result.append(arg)
        else:
            raise ValueError(f"unsupported KLEE argument: {arg}")
        index += 1
    return result


def runtime_arguments(value: object) -> list[str]:
    values = string_list(value, "program_args", 128)
    arities = {
        "-sym-files": 2, "--sym-files": 2,
        "-sym-args": 3, "--sym-args": 3,
        "-sym-arg": 1, "--sym-arg": 1,
        "-sym-stdin": 1, "--sym-stdin": 1,
        "-max-fail": 1, "--max-fail": 1,
        "-sym-stdout": 0, "--sym-stdout": 0,
        "-fd-fail": 0, "--fd-fail": 0,
    }
    index = 0
    while index < len(values):
        option = values[index]
        if option.startswith(("-sym-", "--sym-", "-max-fail", "--max-fail", "-fd-fail", "--fd-fail")):
            if option not in arities:
                raise ValueError(f"unsupported POSIX symbolic-environment argument: {option}")
            count = arities[option]
            tail = values[index + 1:index + 1 + count]
            if len(tail) != count or not all(item.isdigit() for item in tail):
                raise ValueError(f"{option} requires {count} integer arguments")
            index += count + 1
        else:
            index += 1
    return values


def compiler_for(language: str) -> str | None:
    names = {
        "c": ("clang-13", "clang"),
        "c++": ("clang++-13", "clang++"),
    }.get(language)
    if names is None:
        raise ValueError("language must be c or c++")
    return next((path for name in names if (path := shutil.which(name))), None)


def parse_ktest_output(text: str) -> list[dict]:
    objects = []
    blocks = re.split(r"(?=^object [0-9]+: name:)", text, flags=re.MULTILINE)
    for block in blocks:
        name_match = re.search(r"^object [0-9]+: name: (.+)$", block, re.MULTILINE)
        data_match = re.search(r"^object [0-9]+: data: (.+)$", block, re.MULTILINE)
        size_match = re.search(r"^object [0-9]+: size: ([0-9]+)$", block, re.MULTILINE)
        if not name_match or not data_match:
            continue
        try:
            name = ast.literal_eval(name_match.group(1))
            data = ast.literal_eval(data_match.group(1))
        except (SyntaxError, ValueError):
            continue
        if isinstance(name, str) and isinstance(data, bytes):
            objects.append({
                "name": name,
                "size": int(size_match.group(1)) if size_match else len(data),
                "data": data,
            })
    return objects


def symbolic_file_objects(objects: list[dict]) -> list[dict]:
    return [
        item for item in objects
        if item["name"] in {
            "stdin", "input", "input_bytes", "fuzz_input", "symbolic_input"
        }
        or re.search(r"(?:^|[-_])(?:data|contents)$", item["name"])
    ]


def extract_testcase(path: Path, destination: Path) -> dict:
    tool = shutil.which("ktest-tool")
    if not tool:
        raise RuntimeError("ktest-tool is not available in the KLEE image")
    text = subprocess.run(
        [tool, str(path)], capture_output=True, text=True, timeout=30, check=True
    ).stdout
    objects = parse_ktest_output(text)
    inputs = symbolic_file_objects(objects)
    destination.mkdir(parents=True, exist_ok=True)
    materialized = []
    for index, item in enumerate(inputs):
        filename = f"input-{index:03d}.bin"
        output = destination / filename
        output.write_bytes(item["data"])
        materialized.append({
            "object_name": item["name"],
            "size": len(item["data"]),
            "sha256": hashlib.sha256(item["data"]).hexdigest(),
            "path": str(output.relative_to(ROOT)),
        })
    return {
        "objects": [{"name": item["name"], "size": item["size"]} for item in objects],
        "inputs": materialized,
    }


def process(job: Path) -> None:
    started = time.time()
    summary = {
        "provider": "klee", "request_id": job.name, "status": "failed",
        "started_at": started, "errors": [], "testcases": [],
    }
    output = job / "out"
    output.mkdir(exist_ok=True)
    try:
        spec = json.loads((job / "request.json").read_text())
        if not isinstance(spec, dict) or spec.get("schema_version", 1) != 1:
            raise ValueError("request must be a schema_version 1 JSON object")
        workdir = ROOT / relative_path(spec.get("working_dir"), "working_dir")
        if not workdir.resolve().is_relative_to(ROOT.resolve()) or not workdir.is_dir():
            raise ValueError("working_dir is missing or outside the shared workspace")
        sources = string_list(spec.get("sources"), "sources", 256)
        if not sources:
            raise ValueError("at least one source file is required")
        source_paths = []
        for source in sources:
            path = workdir / relative_path(source, "source")
            if not path.is_file() or not path.resolve().is_relative_to(workdir.resolve()):
                raise ValueError(f"source is missing or escapes working_dir: {source}")
            source_paths.append(path)
        language = spec.get("language", "c")
        compiler = compiler_for(language)
        linker = (
            shutil.which("llvm-link-13")
            or shutil.which("llvm-link")
            or str(Path(compiler).with_name("llvm-link")) if compiler else None
        )
        klee = shutil.which("klee")
        if not compiler or not klee:
            raise RuntimeError("KLEE or clang-13 is unavailable")
        flags = compiler_flags(spec.get("compile_flags", ["-g", "-O0"]))
        args = klee_flags(spec.get("klee_args", []))
        program_args = runtime_arguments(spec.get("program_args", []))
        timeout_s = spec.get("timeout_s", 120)
        if not isinstance(timeout_s, int) or not 1 <= timeout_s <= MAX_JOB_TIMEOUT:
            raise ValueError(f"timeout_s must be between 1 and {MAX_JOB_TIMEOUT}")

        modules = []
        compiler_commands = []
        for index, source in enumerate(source_paths):
            module = output / f"module-{index:03d}.bc"
            command = [
                compiler, *flags, "-emit-llvm", "-c", str(source), "-o", str(module)
            ]
            compiler_commands.append(command)
            compiled = subprocess.run(
                command, cwd=workdir, capture_output=True, text=True, timeout=timeout_s
            )
            if compiled.returncode:
                detail = (compiled.stdout + compiled.stderr)[-4000:]
                raise RuntimeError(f"compile failed ({compiled.returncode}): {detail}")
            modules.append(str(module))

        bitcode = output / "program.bc"
        if len(modules) == 1:
            shutil.copy2(modules[0], bitcode)
            link_output = ""
        else:
            if not linker or not Path(linker).is_file():
                raise RuntimeError("llvm-link-13 is required for multiple source files")
            linked = subprocess.run(
                [linker, *modules, "-o", str(bitcode)],
                cwd=workdir, capture_output=True, text=True, timeout=timeout_s,
            )
            if linked.returncode:
                raise RuntimeError(
                    f"llvm-link failed: {(linked.stdout + linked.stderr)[-4000:]}"
                )
            link_output = linked.stdout + linked.stderr

        command = [
            klee,
            f"--output-dir={output / 'klee-out'}",
            f"--max-time={timeout_s}s",
            "--max-memory=4096",
            *args, str(bitcode), *program_args,
        ]
        summary["compiler_commands"] = compiler_commands
        summary["klee_command"] = command
        summary["link_output"] = link_output[-4000:]
        log = output / "klee.log"
        with log.open("w") as stream:
            try:
                completed = subprocess.run(
                    command, cwd=workdir, stdout=stream, stderr=subprocess.STDOUT,
                    timeout=timeout_s + 15,
                )
                summary["exit_code"] = completed.returncode
            except subprocess.TimeoutExpired:
                summary["exit_code"] = 124
                summary["errors"].append("KLEE worker deadline expired")

        for testcase in sorted((output / "klee-out").glob("test*.ktest")):
            item = {"ktest": str(testcase.relative_to(ROOT))}
            try:
                item.update(extract_testcase(testcase, output / "testcases" / testcase.stem))
            except Exception as exc:
                item["extraction_error"] = f"{type(exc).__name__}: {exc}"
                summary["errors"].append(item["extraction_error"])
            item["errors"] = [
                {"path": str(error.relative_to(ROOT)),
                 "type": error.name[len(testcase.stem) + 1:-4]}
                for error in testcase.parent.glob(testcase.stem + ".*.err")
            ]
            summary["testcases"].append(item)
        summary["log"] = str(log.relative_to(ROOT))
        summary["status"] = "completed" if summary.get("exit_code") in {0, 1} else "failed"
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
                # The target-side client creates a private mktemp directory
                # before chmodding it for this unprivileged worker. Ignore
                # that brief window and retry on the next queue scan.
                continue
            if ready:
                seen.add(job.name)
                process(job)
        time.sleep(0.2)


if __name__ == "__main__":
    main()
