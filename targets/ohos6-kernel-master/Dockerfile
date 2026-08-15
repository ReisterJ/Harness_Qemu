# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
#
# OpenHarmony kernel hunt target — **master branch** (latest), PREBUILT agent
# image. Same recipe as targets/ohos6-kernel (syzbot QEMU base + swapped
# bzImage + baked source), but the kernel is built from the OHOS **master**
# branch (f88704ae607f, 2025-09-09) instead of the stale 6.0-Release snapshot.
#
# Build needs network (apt + npm): run with
#   VULN_PIPELINE_DOCKER_BUILD_NETWORK=host
# and pre-pull the base: docker pull cybergym/syzbot-target:09b7d050e4806540153d
#
# Build order on the host FIRST:
#   cd targets/ohos6-kernel-master && ./build_kernel.sh
#   # -> images/bzImage  and  kernel-src/linux-5.10/  (both COPYed below)
FROM cybergym/syzbot-target:09b7d050e4806540153d

# Swap in the OpenHarmony master kernel (KASAN + softlockup-panic build from
# build_kernel.sh).
COPY images/bzImage /kernel/bzImage

# Kernel source for the find agent to read (config.yaml: source_root).
COPY kernel-src/linux-5.10/ /src/linux/

# Pristine upstream Linux 5.10.210 source — the find agent diffs /src/linux
# against it to isolate the OHOS-customized attack surface (no per-run
# download).
COPY kernel-src/upstream-5.10.210/ /src/upstream/

# Host-side tools the agent needs to drive QEMU + serial + write PoCs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl xxd gdb git python3 qemu-utils && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g opencode-ai@1.17.18 && \
    rm -rf /var/lib/apt/lists/*

# Flatten the qcow2 rootfs to raw so the standard QEMU recipe works unchanged.
RUN qemu-img convert -f qcow2 -O raw /images/rootfs_v3.qcow2 /images/rootfs_v3.img && \
    rm -f /images/rootfs_v3.qcow2

# Strip challenge validation metadata the find agent must not see.
RUN rm -f /kernel/sanitizer_check.txt

RUN mkdir -p /work
WORKDIR /work
