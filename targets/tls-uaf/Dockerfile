# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
#
# kernelctf CVE-2025-39682 (net/tls UAF) validation target — PREBUILT agent
# image. Same base and layering as targets/kernelval (the two kernelctf
# targets share the mitigation-v4-6.12 image); kept as its own image_tag so
# config is self-contained.
#
# The image carries the vulnerable kernel, QEMU, and the opencode CLI, so the
# find/grade agents boot the kernel themselves (config.yaml: agent_prebuilt:
# true).
#
# Build needs network (apt + npm): run with
#   VULN_PIPELINE_DOCKER_BUILD_NETWORK=host  (or docker build --network=host)
# and pre-pull the base: docker pull cybergym/kernelctf-target:mitigation-v4-6.12
FROM cybergym/kernelctf-target:mitigation-v4-6.12

# Host-side tools the agent needs to drive QEMU + serial + write PoCs. The
# kernelctf base ships qemu-system-x86_64 and socat but not python3/gcc on the
# host side. Ubuntu 22.04's apt nodejs is v12 — too old for opencode-ai, so
# install node 20 from NodeSource.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl xxd gdb git python3 && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g opencode-ai@1.17.18 && \
    rm -rf /var/lib/apt/lists/*

# harness/agent.py runs the CLI with `docker exec -w /work` — /work must exist.
RUN mkdir -p /work
WORKDIR /work
