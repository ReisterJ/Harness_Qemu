# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
#
# OpenHarmony 6.0 kernel hunt target — PREBUILT agent image.
#
# Reuses the cybergym syzbot base (QEMU + guest Ubuntu rootfs + the standard
# QEMU boot recipe the kernel find/grade prompts already drive) but swaps the
# default bzImage for the OpenHarmony 5.10.210 KASAN kernel built by
# build_kernel.sh. The guest rootfs stays a plain Ubuntu jail (user@exphost) —
# for kernel hunting the userspace only exists to drive the kernel, so the
# OHOS userland is NOT baked in (see README for when you'd need it).
#
# Build needs network (apt + npm): run with
#   VULN_PIPELINE_DOCKER_BUILD_NETWORK=host
# and pre-pull the base: docker pull cybergym/syzbot-target:09b7d050e4806540153d
#
# Build order on the host FIRST:
#   cd targets/ohos6-kernel && ./build_kernel.sh
#   # -> images/bzImage  and  kernel-src/linux-5.10/  (both COPYed below)
FROM cybergym/syzbot-target:09b7d050e4806540153d

# Swap in the OpenHarmony 6.0 kernel (KASAN build from build_kernel.sh).
COPY images/bzImage /kernel/bzImage

# Kernel source for the find agent to read (config.yaml: source_root). Stays —
# it is the analysis target the agent is supposed to reason about.
COPY kernel-src/linux-5.10/ /src/linux/

# Pristine upstream Linux 5.10.210 source — the find agent diffs /src/linux
# against it to isolate the OHOS-customized attack surface (no per-run
# download). See config.yaml attack_surface.
COPY kernel-src/upstream-5.10.210/ /src/upstream/

# Host-side tools the agent needs to drive QEMU + serial + write PoCs. The
# syzbot base ships qemu-system-x86_64 and socat but no python3/gcc/xxd.
# qemu-utils provides qemu-img (to flatten the qcow2 rootfs below).
# Ubuntu 22.04's apt nodejs is v12 — too old for opencode-ai, so install
# node 20 from NodeSource.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl xxd gdb git python3 qemu-utils && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g opencode-ai@1.17.18 && \
    rm -rf /var/lib/apt/lists/*

# The base ships rootfs_v3.qcow2; flatten it to raw so the standard QEMU
# recipe (format=raw) in the kernel find/grade prompts works unchanged.
RUN qemu-img convert -f qcow2 -O raw /images/rootfs_v3.qcow2 /images/rootfs_v3.img && \
    rm -f /images/rootfs_v3.qcow2

# Strip challenge validation metadata (answer-side info) the find agent must
# not see.
RUN rm -f /kernel/sanitizer_check.txt

# harness/agent.py runs the CLI with `docker exec -w /work` — /work must exist.
RUN mkdir -p /work
WORKDIR /work
