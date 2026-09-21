# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Build the per-target agent image: target runtime + opencode CLI.

The agent runs *inside* its container, so the container needs the CLI. To
avoid one node/npm install per target, ``ensure()`` builds a shared
``vuln-pipeline-agent-base:<cli-version>`` once and copies its standalone
opencode executable and git support into the target image. The target image
is the final base, rather than merely a source of ``/work``: runtime packages
installed by a target Dockerfile (for example QEMU, Java, or a service's
native libraries) must remain available to dynamic validation and grade.

The backend is the opencode CLI (``opencode-ai`` npm package): it drives the
agentic loop (Read/Write/Bash tools), streams raw JSON events with
``--format json``, and supports arbitrary providers (DeepSeek, OpenAI, ...)
via provider env vars or opencode.json.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import textwrap

from . import docker_ops

OPENCODE_VERSION = "1.17.18"  # bump alongside the dev-env opencode pin
BASE_TAG = f"vuln-pipeline-agent-base:{OPENCODE_VERSION}"
TARGET_ID_LABEL = "io.vuln-pipeline.target-image-id"
_TAG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:-]*$")


def agent_tag(target_tag: str) -> str:
    """Distinct agent-image tag per *full* target tag, so a committed
    ``<name>:patched-<uuid>`` snapshot doesn't collide with ``<name>:v1``."""
    return f"{target_tag.replace(':', '-')}-agent:{OPENCODE_VERSION}"


def validate_tag(tag: str) -> None:
    """Raise ValueError if ``tag`` is not a valid docker image reference."""
    if not _TAG_RE.match(tag):
        raise ValueError(f"invalid image tag: {tag!r}")


def build(dockerfile: str, tag: str, context: str | None = None) -> None:
    """Build ``dockerfile`` (a string) as ``tag``. With ``context``, the build
    context is that directory instead of the Dockerfile's temp dir — used by
    harnesses whose Dockerfiles COPY from a host tree."""
    with tempfile.TemporaryDirectory() as ctx:
        with open(f"{ctx}/Dockerfile", "w") as f:
            f.write(dockerfile)
        if context is None:
            cmd = ["docker", "build", "-q", *docker_ops.build_network_args(),
                   "-t", tag, ctx]
        else:
            cmd = ["docker", "build", "-q", *docker_ops.build_network_args(),
                   "-f", f"{ctx}/Dockerfile", "-t", tag, context]
        subprocess.run(cmd, check=True, capture_output=True, text=True)


def ensure_base() -> str:
    if docker_ops.image_exists(BASE_TAG):
        return BASE_TAG
    # xxd + gdb: the find/patch prompts list these as available. Target
    # Dockerfiles install them too, but ``ensure()`` only copies /work from the
    # target image — apt packages outside /work don't survive the COPY --from.
    # Anything the prompts promise has to live in this base layer.
    # git: opencode's file-snapshot system uses an internal git repo.
    build(
        textwrap.dedent(f"""\
            FROM gcc:14
            RUN apt-get update && \\
                apt-get install -y --no-install-recommends nodejs npm ca-certificates xxd gdb git && \\
                rm -rf /var/lib/apt/lists/* && \\
                npm install -g opencode-ai@{OPENCODE_VERSION}
            WORKDIR /work
        """),
        BASE_TAG,
    )
    return BASE_TAG


def ensure(target_tag: str) -> str:
    """Build (if missing) and return the agent-image tag for ``target_tag``."""
    validate_tag(target_tag)
    tag = agent_tag(target_tag)
    target_id = docker_ops.image_id(target_tag)
    if target_id is None:
        raise RuntimeError(f"target image is not available locally: {target_tag!r}")
    if (
        docker_ops.image_exists(tag)
        and docker_ops.image_label(tag, TARGET_ID_LABEL) == target_id
    ):
        return tag
    ensure_base()
    build(
        # Keep the target image as the runtime base.  The old reverse layering
        # (FROM agent-base + COPY target /work) silently discarded packages
        # outside /work, which made QEMU/service targets impossible to run.
        # opencode is a standalone native executable; only the executable is
        # copied instead of the 700+ MB multi-platform npm package.  Git is
        # needed by opencode's workspace snapshot handling.
        f"""FROM {target_tag}
LABEL {TARGET_ID_LABEL}="{target_id}"
COPY --from={BASE_TAG} /usr/local/lib/node_modules/opencode-ai/bin/opencode.exe /usr/local/bin/opencode
COPY --from={BASE_TAG} /usr/bin/git /usr/bin/git
COPY --from={BASE_TAG} /usr/lib/git-core /usr/lib/git-core
COPY --from={BASE_TAG} /usr/share/git-core /usr/share/git-core
WORKDIR /work
""",
        tag,
    )
    subprocess.run(
        ["docker", "tag", tag, f"{tag.rsplit(':', 1)[0]}:latest"],
        check=True,
    )
    return tag
