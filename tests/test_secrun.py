"""Repository/image job contracts; ordinary tests do not require Docker or an API."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from secrun.acceptance import compare, container_args, inspect_state, validate_image
from secrun.cli import duration, main
from secrun.process import Cancelled, CommandFailed, Result, Runner, TimedOut, error_excerpt
from secrun.recipe import NeedsConfig, parse_events, validate_plan, freeze_contract
from secrun.source import fetch_source, read_documents, tree_digest, validate_name, validate_repo, write_json
from secrun.workflow import Job, load


def run_git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repository(tmp_path):
    path = tmp_path / "repository"
    path.mkdir()
    run_git(path, "init", "-b", "trunk")
    run_git(path, "config", "user.email", "secrun-test@example.invalid")
    run_git(path, "config", "user.name", "secrun test")
    (path / "README.md").write_text("Build with cc main.c -o /app. Run /app: prints hello.\n")
    (path / "main.c").write_text('#include <stdio.h>\nint main(void) {puts("hello");}\n')
    run_git(path, "add", ".")
    run_git(path, "commit", "-m", "initial")
    return path


@pytest.fixture
def plan(repository):
    return {"version": 1, "summary": "Build the documented CLI from source",
            "evidence": [{"path": "README.md", "reason": "build and execution example"}],
            "files": {"Dockerfile": 'FROM gcc:14\nCOPY source/ /src/\nRUN cc /src/main.c -o /app\nCMD ["/app"]\n'},
            "acceptance": {"kind": "cli", "run": {"args": []}, "cases": [
                {"name": "hello", "purpose": "functional", "args": [],
                 "expect": {"exit_code": 0, "stdout": "hello\n"}}]}}


def runner(root, seconds=20):
    root.mkdir(parents=True, exist_ok=True)
    return Runner(root, time.monotonic() + seconds)


def test_new_task_fetches_updated_default_branch(repository, tmp_path):
    first = tmp_path / "first"
    one = fetch_source(str(repository), None, first, runner(first), 10)
    assert one["branch"] == "trunk"
    assert one["commit"] == run_git(repository, "rev-parse", "HEAD")
    (repository / "README.md").write_text("new documentation\n")
    run_git(repository, "commit", "-am", "update")
    second = tmp_path / "second"
    two = fetch_source(str(repository), None, second, runner(second), 10)
    assert two["commit"] != one["commit"]
    assert two["commit"] == run_git(repository, "rev-parse", "HEAD")
    assert two["snapshot_sha256"] != one["snapshot_sha256"]
    assert not (second / "source" / ".git").exists()
    assert (first / "source" / "README.md").read_text().startswith("Build")


def test_explicit_branch_and_missing_branch(repository, tmp_path):
    run_git(repository, "branch", "feature/demo")
    root = tmp_path / "job"
    lock = fetch_source(str(repository), "feature/demo", root, runner(root), 10)
    assert lock["branch"] == "feature/demo"
    missing = tmp_path / "missing"
    with pytest.raises(CommandFailed):
        fetch_source(str(repository), "not-here", missing, runner(missing), 10)
    assert not (missing / "source.lock.json").exists()


def test_documents_skip_external_symlink(repository, tmp_path):
    private = tmp_path / "private.txt"
    private.write_text("secret")
    (repository / "README-link").symlink_to(private)
    docs = read_documents(repository)
    assert "README.md" in docs
    assert "README-link" not in docs


@pytest.mark.parametrize("name", ["../x", "UPPER", "a/b", "", "-flag"])
def test_invalid_target_names(name):
    with pytest.raises(ValueError):
        validate_name(name)


@pytest.mark.parametrize("url", ["--upload-pack=bad", "https://user:secret@example.com/repo", "ext::bad", "relative/path"])
def test_invalid_repository_urls(url):
    with pytest.raises(ValueError):
        validate_repo(url)


def test_plan_validation_and_exact_expectations(plan, repository):
    assert validate_plan(plan, repository) == plan
    assert compare({"exit_code": 0, "stdout": "hello\n"}, {"exit_code": 0, "stdout": "wrong"})
    assert not compare({"stdout_contains": "hello"}, {"stdout": "hello world"})
    assert compare({"unknown": True}, {})


@pytest.mark.parametrize("mutation", [
    lambda p: p["files"].update({"../escape": "bad"}),
    lambda p: p["files"].update({"source/main.c": "replacement"}),
    lambda p: p["files"].update({"Dockerfile": "FROM gcc:14\nRUN git clone https://example.com/repo\n"}),
    lambda p: p["evidence"][0].update(path="does-not-exist.md"),
    lambda p: p["acceptance"]["cases"][0].update(purpose="version"),
    lambda p: p["acceptance"]["cases"][0].update(expect={"exit_code": 0}),
    lambda p: p["acceptance"]["cases"][0].update(args="echo hello"),
    lambda p: p["acceptance"]["cases"][0].update(timeout_seconds=-1),
    lambda p: p["acceptance"]["cases"][0].update(expect={"exit_code": 0, "stdout_contains": ""}),
    lambda p: p["acceptance"]["run"].update(args=["different-start-command"]),
])
def test_invalid_plans_are_not_success(plan, repository, mutation):
    mutation(plan)
    with pytest.raises(ValueError):
        validate_plan(plan, repository)


def test_incomplete_agent_output_and_large_artifact(plan):
    with pytest.raises(ValueError, match="complete"):
        parse_events(json.dumps({"type": "text", "part": {"type": "text", "text": "done"}}))
    plan["summary"] = "x" * 7000
    event = {"type": "text", "part": {"type": "text", "text": "<image_plan>" + json.dumps(plan) + "</image_plan>"}}
    assert parse_events(json.dumps(event)) == plan
    event["part"]["text"] = json.dumps(plan)
    assert parse_events(json.dumps(event)) == plan
    event["part"]["text"] = "```json\n" + json.dumps(plan) + "\n```"
    assert parse_events(json.dumps(event)) == plan
    with pytest.raises(ValueError, match="planner error"):
        parse_events(json.dumps({"type": "error", "error": "provider unavailable"}))


def test_repair_cannot_replace_acceptance(plan):
    repair = copy.deepcopy(plan)
    repair["files"]["Dockerfile"] += "# fixed packaging\n"
    repair["acceptance"]["cases"][0]["expect"]["stdout"] = "fake success"
    frozen = freeze_contract(repair, plan)
    assert frozen["acceptance"] == plan["acceptance"]
    assert frozen["files"] == repair["files"]
    frozen["acceptance"]["cases"].clear()
    assert plan["acceptance"]["cases"]


def test_build_error_excerpt_keeps_root_cause():
    output = "Can't exec autopoint: No such file or directory\n" + ("BuildKit traceback\n" * 2000)
    assert "Can't exec autopoint" in error_excerpt(output)


def test_runner_drains_both_streams_and_input(tmp_path):
    script = "import sys; s=sys.stdin.read(); sys.stderr.write('e'*100000); sys.stdout.write(s)"
    result = runner(tmp_path).run([sys.executable, "-c", script], stdin="hello" * 20000,
                                  log=tmp_path / "command.log")
    assert result.stdout == "hello" * 20000
    assert len(result.stderr) == 100000


def test_runner_timeout_and_cancellation(tmp_path):
    began = time.monotonic()
    with pytest.raises(TimedOut):
        runner(tmp_path).run([sys.executable, "-c", "import time; time.sleep(20)"],
                             timeout=0.1, log=tmp_path / "timeout.log")
    assert time.monotonic() - began < 5
    (tmp_path / "cancel.request").touch()
    with pytest.raises(Cancelled):
        runner(tmp_path).run(["false"], log=tmp_path / "cancel.log")


def test_timeout_stops_child_after_process_leader_exits(tmp_path):
    script = ("import subprocess,sys; "
              "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
              "print(p.pid,flush=True)")
    log = tmp_path / "descendant.log"
    with pytest.raises(TimedOut):
        runner(tmp_path).run([sys.executable, "-c", script], timeout=0.2, log=log)
    child = next(int(line) for line in log.read_text().splitlines() if line.isdigit())
    state = Path(f"/proc/{child}/stat")
    for _ in range(20):
        if not state.exists() or state.read_text().split()[2] == "Z":
            break
        time.sleep(0.01)
    else:
        pytest.fail("descendant survived its task's timeout")


def test_required_environment_not_fabricated(plan, monkeypatch):
    contract = plan["acceptance"]
    contract["run"]["required_env"] = ["SECRUN_TEST_PASSWORD"]
    monkeypatch.delenv("SECRUN_TEST_PASSWORD", raising=False)
    with pytest.raises(NeedsConfig):
        container_args(contract, {"memory": "1g"})
    monkeypatch.setenv("SECRUN_TEST_PASSWORD", "a secret")
    args, env = container_args(contract, {"memory": "1g"})
    assert "SECRUN_TEST_PASSWORD" in args
    assert "a secret" not in " ".join(args)
    assert env["SECRUN_TEST_PASSWORD"] == "a secret"


class FakeDocker:
    def __init__(self, stdout="hello\n", exit_code=0, image="sha256:abc"):
        self.calls = []
        self.stdout = stdout
        self.exit_code = exit_code
        self.image = image

    def check(self):
        pass

    def run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[1] == "inspect":
            state = {"Image": self.image, "State": {"ExitCode": self.exit_code, "OOMKilled": False}}
            return Result(0, json.dumps(state), "")
        if argv[1] == "start":
            return Result(0, self.stdout, "")
        return Result(0, "container-id\n", "")


@pytest.mark.parametrize("stdout,exit_code,image,passed", [
    ("hello\n", 0, "sha256:abc", True), ("wrong", 0, "sha256:abc", False),
    ("hello\n", 1, "sha256:abc", False), ("hello\n", 0, "sha256:other", False),
])
def test_acceptance_uses_actual_container_exit_and_output(plan, tmp_path, monkeypatch, stdout, exit_code, image, passed):
    removed = []
    monkeypatch.setattr("secrun.acceptance.cleanup_container", lambda name: removed.append(name))
    docker = FakeDocker(stdout, exit_code, image)
    report = validate_image("sha256:abc", plan, tmp_path, docker, {"job_id": "test", "memory": "1g"})
    assert (report["status"] == "passed") is passed
    assert removed == ["secrun-test-test-0"]
    create = docker.calls[0][0]
    assert "--mount" not in create and "--entrypoint" not in create
    assert create[-1] == "sha256:abc"
    inspect = next(cmd for cmd, _ in docker.calls if cmd[1] == "inspect")
    assert "--format" in inspect and ".Config" not in " ".join(inspect)


def test_cleanup_failure_prevents_publication(plan, tmp_path, monkeypatch):
    monkeypatch.setattr("secrun.acceptance.cleanup_container", lambda name: "daemon unreachable")
    report = validate_image("sha256:abc", plan, tmp_path, FakeDocker(), {"job_id": "test", "memory": "1g"})
    assert report["status"] == "validation_failed"
    assert report["cleanup_errors"]


def test_cancelled_acceptance_keeps_partial_report(plan, tmp_path, monkeypatch):
    monkeypatch.setattr("secrun.acceptance.cleanup_container", lambda name: None)
    docker = FakeDocker()
    def cancelled():
        raise Cancelled("stop")
    docker.check = cancelled
    with pytest.raises(Cancelled):
        validate_image("sha256:abc", plan, tmp_path, docker, {"job_id": "test", "memory": "1g"})
    assert load(tmp_path / "acceptance.json")["status"] == "interrupted"


def test_http_real_response_required(plan, tmp_path, monkeypatch):
    plan["acceptance"] = {"kind": "http", "run": {"args": [], "port": 8080, "startup_timeout_seconds": 0.05},
                           "cases": [{"name": "hello", "purpose": "functional", "path": "/",
                                      "expect": {"status": 200, "body": "hello"}}]}
    docker = FakeDocker()
    docker.deadline = time.monotonic() + 10
    monkeypatch.setattr("secrun.acceptance.inspect_state", lambda *a: {
        "Image": "sha256:abc", "State": {"Running": True},
        "NetworkSettings": {"Ports": {"8080/tcp": [{"HostPort": "23456"}]}}})
    monkeypatch.setattr("secrun.acceptance.request", lambda *a: {"status": 200, "body": "wrong application"})
    monkeypatch.setattr("secrun.acceptance.cleanup_container", lambda name: None)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, b"", b""))
    report = validate_image("sha256:abc", plan, tmp_path, docker, {"job_id": "test", "memory": "1g"})
    assert report["status"] == "validation_failed"
    assert "body" in report["cases"][0]["errors"][0]


def test_job_resume_rejects_modified_snapshot(repository, plan, tmp_path, monkeypatch):
    root = tmp_path / "job"
    fetch_source(str(repository), None, root, runner(root), 10)
    (root / "source" / "main.c").write_text("modified outside the job")
    write_json(root / "job.json", {"name": "test", "repo": str(repository), "job_id": "job",
                                   "task_timeout": 10, "target_dir": str(tmp_path / "target")})
    write_json(root / "status.json", {"status": "queued"})
    monkeypatch.setattr(Runner, "run", lambda *a, **k: Result(0, "29", ""))
    assert Job(root).execute() == 1
    assert "modified" in load(root / "status.json")["error"]


def test_duration_and_failed_source_cli(tmp_path):
    assert duration("30m") == 1800
    assert duration("0.5h") == 1800
    with pytest.raises(Exception):
        duration("0s")
    assert main(["--name", "../bad", "--repo", "/tmp/repo", "--workspace", str(tmp_path)]) == 2
    assert not (tmp_path / "results").exists()


def test_run_command_matches_http_and_required_env(plan):
    plan["acceptance"].update(kind="http")
    plan["acceptance"]["run"].update(port=8080, required_env=["DATABASE_URL"])
    command = Job.run_command("example:one", plan)
    assert "127.0.0.1:8080:8080" in command
    assert "-e DATABASE_URL" in command
    assert "--entrypoint" not in command


@pytest.mark.skipif(os.getenv("SECRUN_DOCKER_TESTS") != "1", reason="opt-in local Docker E2E")
def test_docker_latest_source_e2e(repository, plan, tmp_path):
    """Actual builds, execution, fresh remote HEAD, and preserved older version."""
    recipe = tmp_path / "recipe.json"
    images = []
    try:
        for expected in ("hello", "updated"):
            if expected == "updated":
                (repository / "main.c").write_text('#include <stdio.h>\nint main(void) {puts("updated");}\n')
                run_git(repository, "commit", "-am", "change program")
            plan["acceptance"]["cases"][0]["expect"]["stdout"] = expected + "\n"
            write_json(recipe, plan)
            assert main(["--name", "secrun-test", "--repo", str(repository), "--recipe", str(recipe),
                         "--workspace", str(tmp_path), "--task-timeout", "2m"]) == 0
            current = load(tmp_path / "targets/secrun-test/image/current.json")
            images.append(current["image_tag"])
            assert current["source"]["commit"] == run_git(repository, "rev-parse", "HEAD")
            report = load(Path(current["results"]) / "acceptance.json")
            assert report["cases"][0]["actual"]["stdout"] == expected + "\n"
        assert images[0] != images[1]
        assert len(list((tmp_path / "targets/secrun-test/image/versions").iterdir())) == 2
        # A new remote check failure must not replace the previous good result.
        before = load(tmp_path / "targets/secrun-test/image/current.json")
        assert main(["--name", "secrun-test", "--repo", str(repository), "--branch", "missing",
                     "--recipe", str(recipe), "--workspace", str(tmp_path)]) == 1
        assert load(tmp_path / "targets/secrun-test/image/current.json") == before
        # Same remote source: re-use the verified recipe, but still verify again.
        assert main(["--name", "secrun-test", "--repo", str(repository), "--workspace", str(tmp_path)]) == 0
        images.append(load(tmp_path / "targets/secrun-test/image/current.json")["image_tag"])
    finally:
        for image in images:
            subprocess.run(["docker", "image", "rm", image], capture_output=True, timeout=30)


@pytest.mark.skipif(os.getenv("SECRUN_DOCKER_TESTS") != "1", reason="opt-in local Docker HTTP E2E")
def test_docker_http_e2e(repository, plan, tmp_path):
    (repository / "server.c").write_text(r'''
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0), yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons(8080), .sin_addr.s_addr=0};
    if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 8)) return 1;
    for (;;) {
        int c = accept(s, 0, 0); if (c < 0) return 2;
        char buf[4096]; read(c, buf, sizeof buf);
        const char *r = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello\n";
        write(c, r, strlen(r)); close(c);
    }
}
''')
    run_git(repository, "add", "server.c")
    run_git(repository, "commit", "-m", "HTTP example")
    plan["files"]["Dockerfile"] = 'FROM gcc:14\nCOPY source/ /src/\nRUN cc /src/server.c -o /app\nCMD ["/app"]\n'
    plan["acceptance"] = {"kind": "http", "run": {"args": [], "port": 8080, "startup_timeout_seconds": 10},
                           "cases": [{"name": "hello", "purpose": "functional", "path": "/",
                                      "expect": {"status": 200, "body": "hello\n"}}]}
    recipe = tmp_path / "http-recipe.json"
    write_json(recipe, plan)
    try:
        assert main(["--name", "http-test", "--repo", str(repository), "--recipe", str(recipe),
                     "--workspace", str(tmp_path), "--task-timeout", "2m"]) == 0
        current = load(tmp_path / "targets/http-test/image/current.json")
        report = load(Path(current["results"]) / "acceptance.json")
        assert report["cases"][0]["actual"] == {"status": 200, "body": "hello\n"}
    finally:
        path = tmp_path / "targets/http-test/image/current.json"
        if path.exists():
            subprocess.run(["docker", "image", "rm", load(path)["image_tag"]], capture_output=True, timeout=30)


@pytest.mark.skipif(os.getenv("SECRUN_DOCKER_TESTS") != "1", reason="opt-in Docker build timeout")
def test_docker_build_timeout_does_not_publish(repository, plan, tmp_path):
    plan["files"]["Dockerfile"] = 'FROM gcc:14\nCOPY source/ /src/\nRUN sleep 30 && cc /src/main.c -o /app\nCMD ["/app"]\n'
    recipe = tmp_path / "slow-recipe.json"
    write_json(recipe, plan)
    assert main(["--name", "slow-test", "--repo", str(repository), "--recipe", str(recipe),
                 "--workspace", str(tmp_path), "--build-timeout", "1s", "--task-timeout", "30s"]) == 124
    states = list((tmp_path / "results/images/slow-test").glob("*/status.json"))
    assert len(states) == 1 and load(states[0])["status"] == "timed_out"
    assert not (tmp_path / "targets/slow-test/image/current.json").exists()
