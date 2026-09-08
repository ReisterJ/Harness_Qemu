"""Resolve a fresh remote branch and materialize a locked build context."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .process import Runner


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    os.replace(temp, path)


def validate_name(name: str) -> str:
    if len(name) > 63 or not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", name):
        raise ValueError("name must be a lowercase Docker-compatible name, 1–63 characters")
    return name


def validate_repo(repo: str) -> str:
    if not repo or repo.startswith("-") or "\n" in repo:
        raise ValueError("invalid repository URL")
    url = urlsplit(repo)
    if url.password:
        raise ValueError("do not put credentials in repository URLs; use Git credentials")
    if url.scheme and url.scheme not in {"https", "http", "ssh", "git", "file"}:
        raise ValueError("unsupported repository URL scheme")
    if not url.scheme and not Path(repo).is_absolute() and not re.match(r"[^/@]+@[^:]+:", repo):
        raise ValueError("use a repository URL or an absolute local repository path")
    return repo


def fetch_source(repo: str, branch: str | None, root: Path, runner: Runner,
                 timeout: float) -> dict:
    validate_repo(repo)
    log = root / "source.log"
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    if branch is None:
        result = runner.run(["git", "ls-remote", "--symref", repo, "HEAD"],
                            log=log, timeout=timeout, env=env)
        match = re.search(r"^ref: refs/heads/(.+)\tHEAD$", result.stdout, re.M)
        if not match:
            raise ValueError("remote did not advertise a default branch; specify --branch")
        branch = match.group(1)
    runner.run(["git", "check-ref-format", f"refs/heads/{branch}"], log=log)
    checkout = root / "checkout"
    # A new task always fetches; never substitute an existing local image.
    runner.run(["git", "init", str(checkout)], log=log)
    runner.run(["git", "remote", "add", "origin", repo], cwd=checkout, log=log)
    runner.run(["git", "fetch", "--depth", "1", "origin", f"refs/heads/{branch}"],
               cwd=checkout, log=log, timeout=timeout, env=env)
    commit = runner.run(["git", "rev-parse", "FETCH_HEAD"], cwd=checkout,
                        log=log).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise ValueError("invalid fetched commit")
    runner.run(["git", "checkout", "--detach", commit], cwd=checkout, log=log, env=env)
    if (checkout / ".gitmodules").is_file():
        runner.run(["git", "submodule", "update", "--init", "--recursive", "--depth", "1"],
                   cwd=checkout, log=log, env=env, timeout=timeout)
    submodules = runner.run(["git", "submodule", "status", "--recursive"],
                            cwd=checkout, log=log, env=env).stdout
    if any(line.startswith(("-", "+", "U")) for line in submodules.splitlines()):
        raise ValueError("submodule checkout does not match the superproject")
    # LFS pointers are not usable application assets. Fail explicitly for now.
    if (checkout / ".gitattributes").is_file() and "filter=lfs" in (checkout / ".gitattributes").read_text():
        runner.run(["git", "lfs", "pull"], cwd=checkout, log=log,
                   timeout=timeout, env=env)
    snapshot = root / "source"
    shutil.copytree(checkout, snapshot, symlinks=True,
                    ignore=shutil.ignore_patterns(".git"))
    lock = {"repo": repo, "branch": branch, "commit": commit,
            "checked_at": utcnow(), "submodules": submodules.splitlines(),
            "snapshot_sha256": tree_digest(snapshot)}
    write_json(root / "source.lock.json", lock)
    return lock


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            data = os.readlink(path).encode()
            kind = "link"
        elif path.is_file():
            data = path.read_bytes()
            kind = str(path.stat().st_mode & 0o777)
        else:
            continue
        digest.update(relative.encode() + b"\0" + kind.encode() + b"\0")
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def read_documents(source: Path) -> dict[str, str]:
    """Read documentation first, with strict size and path boundaries."""
    candidates = []
    for path in source.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        name = path.name.lower()
        if (name.startswith(("readme", "install", "dockerfile")) or
                name in {"compose.yaml", "docker-compose.yml", "package.json",
                         "cargo.toml", "pyproject.toml", "cmakelists.txt", "configure.ac"}):
            relative = path.relative_to(source)
            candidates.append((len(relative.parts), 0 if name.startswith(("readme", "install")) else 1, path))
    docs: dict[str, str] = {}
    budget = 60000
    for _, _, path in sorted(candidates)[:30]:
        text = path.read_bytes()[:min(12000, budget)].decode(errors="replace")
        docs[path.relative_to(source).as_posix()] = text
        budget -= len(text)
        if budget <= 0:
            break
    return docs
