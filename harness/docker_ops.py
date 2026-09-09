# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Thin docker CLI wrapper. Shelling out keeps it dependency-free.

Agent containers run under gVisor on the `vp-internal` `--internal` network;
egress is restricted to the API allowlist proxy. The agent gets Bash inside
that sandbox: read source, run the binary, write PoC files, nothing else.
"""
from __future__ import annotations

import os
import selectors
import subprocess
import time


def build_network_args() -> list[str]:
    """`--network` args for docker build, driven by
    ``VULN_PIPELINE_DOCKER_BUILD_NETWORK`` (default: none = normal bridge).

    Needed on hosts where the build containers can't reach a registry/proxy
    through the default bridge — e.g. a loopback-only proxy (127.0.0.1:7897)
    that `docker pull` uses via the daemon but build RUN steps can't reach.
    ``--network=host`` makes RUN steps use the host network so the loopback
    proxy works. Pulls still go through the daemon (so pre-pull any FROM
    bases: `docker pull gcc:14`)."""
    v = os.environ.get("VULN_PIPELINE_DOCKER_BUILD_NETWORK")
    return ["--network", v] if v else []


def build(
    dockerfile_dir: str,
    tag: str,
    *,
    log_path: str | None = None,
    timeout: int | None = None,
) -> str:
    """Build a docker image from a directory containing a Dockerfile.

    The existing callers only need the blocking two-argument form.  Build
    workflows can additionally provide ``log_path`` and ``timeout``: output is
    streamed to the terminal and persisted, while a hung build is terminated
    after the requested number of seconds.
    """
    cmd = ["docker", "build", *build_network_args(), "-t", tag, dockerfile_dir]
    if log_path is None and timeout is None:
        subprocess.run(cmd, check=True)
        return tag

    log_file = open(log_path, "wb") if log_path else None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception:
        if log_file:
            log_file.close()
        raise
    assert proc.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    started = time.monotonic()
    try:
        while True:
            remaining = None if timeout is None else timeout - (time.monotonic() - started)
            if remaining is not None and remaining <= 0:
                proc.kill()
                proc.wait()
                raise subprocess.TimeoutExpired(cmd, timeout)
            events = selector.select(0.5 if remaining is None else min(0.5, remaining))
            if not events:
                if proc.poll() is not None:
                    break
                continue
            for key, _ in events:
                chunk = key.fileobj.read1(64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if log_file:
                    log_file.write(chunk)
                    log_file.flush()
                print(chunk.decode("utf-8", errors="replace"), end="", flush=True)
            if proc.poll() is not None and not selector.get_map():
                break
        returncode = proc.wait()
    finally:
        selector.close()
        if log_file:
            log_file.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    if returncode != 0:
        raise subprocess.CalledProcessError(returncode, cmd)
    return tag


def run(
    image_tag: str,
    name: str,
    network: str = "none",
    memory: str = "4g",
    shm_size: str | None = None,
    shell: str = "/bin/bash",
    runtime: str | None = None,
    env: dict[str, str] | None = None,
    mounts: list[tuple[str, str]] | None = None,
    devices: list[str] | None = None,
) -> str:
    """Start a container, detached, interactive. Cleans up any existing
    container with the same name first (clean slate).

    ``runtime`` selects an OCI runtime (e.g. ``runsc`` for gVisor). The
    active runtime is verified via ``docker inspect`` so a typo or missing
    registration fails loudly instead of silently falling back to runc.
    ``devices`` passes host devices through (e.g. ``["/dev/kvm"]`` for
    targets that boot QEMU accelerators)."""
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    runtime = runtime or os.environ.get("VULN_PIPELINE_DOCKER_RUNTIME")
    extra: list[str] = []
    if runtime:
        extra += ["--runtime", runtime]
    if shm_size:
        extra += ["--shm-size", shm_size]
    for dev in (devices or []):
        extra += ["--device", dev]
    for k, v in (env or {}).items():
        # Prefer ``-e KEY`` (value read from this process's env) so secrets don't
        # appear in argv / host ps output. Fall back to ``-e KEY=VAL`` for
        # computed values (e.g. HTTPS_PROXY) that aren't in our env.
        extra += ["-e", k] if os.environ.get(k) == v else ["-e", f"{k}={v}"]
    for src, dst in (mounts or []):
        extra += ["-v", f"{src}:{dst}:ro"]
    r = subprocess.run(
        [
            "docker", "run", "-dit",
            *extra,
            "--name", name,
            "--network", network,
            "--memory", memory,
            image_tag, shell,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"docker run failed (exit {r.returncode}): {r.stderr.strip()}"
        )
    actual_image, actual_runtime = subprocess.run(
        ["docker", "inspect", name, "--format",
         "{{.Config.Image}}\t{{.HostConfig.Runtime}}"],
        capture_output=True, text=True, check=True,
    ).stdout.rstrip("\n").split("\t")
    if actual_image != image_tag:
        raise RuntimeError(
            f"container {name} has wrong image: requested {image_tag!r}, got {actual_image!r}"
        )
    if runtime and actual_runtime != runtime:
        raise RuntimeError(
            f"container {name} runtime mismatch: requested {runtime!r}, "
            f"docker reports {actual_runtime!r}"
        )
    return name


def read_file(container: str, path: str) -> bytes:
    """Read a file from inside a container. Returns b'' if the file doesn't
    exist — that's the detection for "agent narrated a PoC path it never wrote".
    """
    r = subprocess.run(
        ["docker", "exec", container, "cat", path],
        capture_output=True,
    )
    return r.stdout if r.returncode == 0 else b""


def write_file(container: str, path: str, content: bytes) -> None:
    """Write bytes to a path inside a container.

    Uses ``docker exec`` (not ``docker cp``) so the write happens from the
    container's own view of the filesystem — under gVisor, ``/tmp`` is an
    in-sandbox tmpfs that host-side ``docker cp`` can't reach."""
    subprocess.run(
        ["docker", "exec", "-i", container, "sh", "-c", 'cat > "$1"', "_", path],
        input=content,
        check=True,
        capture_output=True,
    )


def rm(container: str) -> None:
    """Remove a container, force-killing if running. Idempotent."""
    subprocess.run(["docker", "rm", "-f", container], capture_output=True)


def image_exists(tag: str) -> bool:
    """Check whether an image tag exists locally."""
    r = subprocess.run(
        ["docker", "image", "inspect", tag],
        capture_output=True,
    )
    return r.returncode == 0


def exec_sh(
    container: str, command: str, timeout: int | None = None
) -> tuple[int, str, str]:
    """Run a shell command inside a container and return (rc, stdout, stderr).

    Unlike read_file/write_file this passes the command through sh -c so shell
    syntax (pipes, &&, redirects) works. Raises subprocess.TimeoutExpired on
    timeout — caller decides whether that's a tier failure or a hard error.
    """
    r = subprocess.run(
        ["docker", "exec", container, "sh", "-c", command],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def commit(container: str, tag: str) -> str:
    """Snapshot a container's filesystem as a new image. Used by re-attack to
    run a find-agent against the patched binary without rebuilding."""
    subprocess.run(["docker", "commit", container, tag], check=True, capture_output=True)
    return tag


def rmi(tag: str) -> None:
    """Remove an image tag. Idempotent."""
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)
