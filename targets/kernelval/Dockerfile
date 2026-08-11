# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
#
# Kernel static-analysis validation target — PREBUILT agent image.
#
# The pipeline's normal agent-image flow (agent_image.ensure) layers the opencode
# CLI onto the target image and only COPYs /work across, which would DROP the
# kernel, rootfs, and QEMU from this target. So this image carries everything
# itself (config.yaml: agent_prebuilt: true): the vulnerable kernelctf kernel
# image + the opencode CLI. The find/grade agents run inside it and boot the
# kernel in QEMU with KVM (/dev/kvm is passed via config devices).
#
# Build needs network (apt + npm): run with
#   VULN_PIPELINE_DOCKER_BUILD_NETWORK=host
# and pre-pull the base: docker pull cybergym/kernelctf-target:mitigation-v4-6.12
FROM cybergym/kernelctf-target:mitigation-v4-6.12

# Tools the agent needs to drive QEMU + serial + write PoCs. The cybergym base
# ships qemu-system-x86_64 and socat but not python3/gcc on the host side.
# Ubuntu 22.04's apt nodejs is v12 — too old for opencode-ai, so install
# node 20 from NodeSource.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl xxd gdb git python3 && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g opencode-ai@1.17.18 && \
    rm -rf /var/lib/apt/lists/*

# harness/agent.py runs the CLI with `docker exec -w /work` — /work must exist.
RUN mkdir -p /work
WORKDIR /work
