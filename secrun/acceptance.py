"""Execute a frozen acceptance contract against the final image, not agent prose."""
from __future__ import annotations

import http.client
import json
import os
import time
from pathlib import Path

from .process import Runner, TimedOut, cleanup_container
from .recipe import NeedsConfig
from .source import utcnow, write_json


def compare(expect: dict, actual: dict) -> list[str]:
    errors = []
    for key, wanted in expect.items():
        if key.endswith("_contains"):
            field = key.removesuffix("_contains")
            if wanted not in actual.get(field, ""):
                errors.append(f"{field} did not contain {wanted!r}")
        elif key in {"exit_code", "stdout", "stderr", "status", "body"}:
            if actual.get(key) != wanted:
                errors.append(f"{key}: expected {wanted!r}, got {str(actual.get(key))[:1500]!r}")
        else:
            errors.append(f"unsupported assertion {key}")
    return errors


def container_args(contract: dict, options: dict) -> tuple[list[str], dict[str, str]]:
    run = contract["run"]
    env = dict(os.environ)
    env.update(run.get("env", {}))
    required = run.get("required_env", [])
    missing = [key for key in required if not env.get(key)]
    if missing:
        raise NeedsConfig("missing runtime environment variables: " + ", ".join(missing))
    args = ["--memory", options["memory"], "--cpus", str(options.get("cpus", 2))]
    for key in dict.fromkeys([*run.get("env", {}), *required]):
        args += ["-e", key]
    # No accidental application dependence on the Docker client's proxy config.
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        if key not in run.get("env", {}) and key not in required:
            args += ["-e", f"{key}="]
    return args, env


def inspect_state(name: str, runner: Runner, log: Path) -> dict:
    template = '{"Image":{{json .Image}},"State":{{json .State}},"NetworkSettings":{{json .NetworkSettings}}}'
    return json.loads(runner.run(["docker", "inspect", "--format", template, name], log=log).stdout)


def validate_image(image_id: str, plan: dict, root: Path, runner: Runner, options: dict) -> dict:
    contract = plan["acceptance"]
    report = {"status": "running", "image_id": image_id, "started_at": utcnow(),
              "kind": contract["kind"], "cases": [], "cleanup_errors": []}
    report_path = root / "acceptance.json"
    write_json(report_path, report)
    try:
        if contract["kind"] == "http":
            _http(image_id, contract, root, runner, options, report)
        else:
            _cli(image_id, contract, root, runner, options, report)
        report["status"] = ("passed" if all(case["passed"] for case in report["cases"])
                            and not report["cleanup_errors"] else "validation_failed")
    except NeedsConfig as exc:
        report.update(status="needs_config", error=str(exc))
        raise
    except TimedOut as exc:
        report.update(status="timed_out", error=str(exc))
        raise
    except BaseException as exc:
        report.update(status="interrupted", error=str(exc))
        raise
    finally:
        report["finished_at"] = utcnow()
        write_json(report_path, report)
    return report


def _cli(image_id: str, contract: dict, root: Path, runner: Runner,
         options: dict, report: dict) -> None:
    common, env = container_args(contract, options)
    for index, case in enumerate(contract["cases"]):
        runner.check()
        name = f"secrun-test-{options['job_id']}-{index}"
        log = root / f"test-{case['name']}.log"
        started = time.monotonic()
        result = {"name": case["name"], "passed": False,
                  "args": case.get("args", []), "expect": case["expect"]}
        try:
            # No entrypoint override, no source mount, no bootstrap installation.
            runner.run(["docker", "create", "-i", "--name", name, "--network", "none",
                        *common, image_id, *case.get("args", [])], log=log, env=env)
            execution = runner.run(["docker", "start", "--attach", "--interactive", name],
                                   log=log, stdin=case.get("stdin", ""), check=False,
                                   timeout=case.get("timeout_seconds", 60))
            state = inspect_state(name, runner, log)
            actual = {"exit_code": state["State"]["ExitCode"],
                      "stdout": execution.stdout, "stderr": execution.stderr}
            errors = compare(case["expect"], actual)
            if state["Image"] != image_id:
                errors.append("container image ID differs from the built image")
            if state["State"].get("OOMKilled"):
                errors.append("container exceeded its memory limit")
            if state["State"].get("Error"):
                errors.append(state["State"]["Error"])
            result.update(actual=actual, errors=errors, passed=not errors)
        except TimedOut as exc:
            result.update(errors=[str(exc)], timed_out=True)
            raise
        finally:
            error = cleanup_container(name)
            if error:
                report["cleanup_errors"].append({"container": name, "error": error})
            result["elapsed_s"] = round(time.monotonic() - started, 2)
            report["cases"].append(result)
            write_json(root / "acceptance.json", report)


def request(port: int, path: str, timeout: float) -> dict:
    # Direct loopback connection; do not pick up host HTTP proxy settings.
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise ValueError("HTTP response exceeded 1 MiB acceptance limit")
        return {"status": response.status, "body": body.decode(errors="replace")}
    finally:
        connection.close()


def _http(image_id: str, contract: dict, root: Path, runner: Runner,
          options: dict, report: dict) -> None:
    common, env = container_args(contract, options)
    name = "secrun-http-" + options["job_id"]
    log = root / "http-container.log"
    run = contract["run"]
    try:
        runner.run(["docker", "create", "--name", name, *common,
                    "-p", f"127.0.0.1::{run['port']}", image_id, *run.get("args", [])],
                   log=log, env=env)
        runner.run(["docker", "start", name], log=log)
        state = inspect_state(name, runner, log)
        if state["Image"] != image_id:
            raise ValueError("HTTP container image ID differs from built image")
        port = int(state["NetworkSettings"]["Ports"][f"{run['port']}/tcp"][0]["HostPort"])
        # First functional response doubles as readiness; every poll is bounded.
        for index, case in enumerate(contract["cases"]):
            seconds = run.get("startup_timeout_seconds", 60) if index == 0 else case.get("timeout_seconds", 10)
            deadline = min(runner.deadline, time.monotonic() + seconds)
            actual = {}
            errors = ["application has not become ready"]
            while time.monotonic() < deadline:
                runner.check()
                state = inspect_state(name, runner, log)
                if not state["State"]["Running"]:
                    errors = [f"service exited during acceptance: {state['State']}"]
                    break
                try:
                    actual = request(port, case["path"], max(0.05, min(2, deadline - time.monotonic())))
                    errors = compare(case["expect"], actual)
                    if not errors:
                        break
                except (OSError, http.client.HTTPException, ValueError) as exc:
                    errors = [str(exc)]
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
            report["cases"].append({"name": case["name"], "expect": case["expect"],
                                    "actual": actual, "errors": errors, "passed": not errors})
            write_json(root / "acceptance.json", report)
        state = inspect_state(name, runner, log)
        if not state["State"]["Running"] or state["State"].get("OOMKilled"):
            report["cases"].append({"name": "service_lifecycle", "passed": False,
                                    "errors": ["service exited during the acceptance session"]})
    finally:
        # Capture output before removing even a failed/stopped container.
        import subprocess
        try:
            logs = subprocess.run(["docker", "logs", name], capture_output=True, timeout=10)
            (root / "service.stdout.log").write_bytes(logs.stdout)
            (root / "service.stderr.log").write_bytes(logs.stderr)
        except (OSError, subprocess.TimeoutExpired):
            pass
        error = cleanup_container(name)
        if error:
            report["cleanup_errors"].append({"container": name, "error": error})
