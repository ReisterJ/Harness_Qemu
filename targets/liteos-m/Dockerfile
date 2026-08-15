# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
#
# OpenHarmony LiteOS-M kernel hunt target — agent image.
#
# Host build order FIRST:
#   cd targets/liteos-m && ./build_liteos_m.sh
#   # -> images/OHOS_Image, images/src-tree/ (full build tree),
#   #    images/tools/{gn,ninja,arm-none-eabi} (toolchain staged for offline
#   #    docker build — no network downloads inside docker)
#
# Build with host network (npm install for opencode):
#   VULN_PIPELINE_DOCKER_BUILD_NETWORK=host docker build --network=host \
#     -t vuln-pipeline-liteos-m:latest targets/liteos-m
FROM ubuntu:22.04

# QEMU for Cortex-M55 + python for gn scripts/hb helper.
RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-system-arm python3 python3-pip ca-certificates curl git xxd \
        build-essential nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Toolchain staged by build_liteos_m.sh (gn + ninja + arm-none-eabi-gcc 15).
COPY images/tools/gn /usr/local/bin/gn
COPY images/tools/ninja /usr/local/bin/ninja
COPY images/tools/arm-none-eabi /opt/arm-none-eabi

# LiteOS-M source tree + kernel image (config.yaml: source_root /src).
COPY images/src-tree /src
COPY images/OHOS_Image /src/OHOS_Image

ENV PATH="/opt/arm-none-eabi/bin:/usr/local/bin:$PATH"

# Rebuild wrapper the find agent uses after editing the PoC module.
COPY rebuild.sh /src/rebuild.sh
RUN chmod +x /src/rebuild.sh

# Agent CLI (same opencode backend as the other kernel targets).
RUN npm install -g opencode-ai@1.17.18

# kconfiglib for the gn kconfig exec_scripts.
RUN pip3 install kconfiglib

RUN mkdir -p /work
WORKDIR /work
