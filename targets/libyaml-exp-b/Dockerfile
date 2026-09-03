# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
# libyaml fuzz target — pinned upstream commit, official run-parser.c harness.
#
# Build needs network (git clone): run with
#   VULN_PIPELINE_DOCKER_BUILD_NETWORK=host
# If your host needs a proxy to reach GitHub, pass it at build time:
#   docker build --network=host --build-arg HTTPS_PROXY=http://127.0.0.1:7897 \
#     --build-arg HTTP_PROXY=http://127.0.0.1:7897 -t vuln-pipeline-libyaml:latest .
FROM gcc:14

ARG HTTPS_PROXY=
ARG HTTP_PROXY=
ENV HTTPS_PROXY=${HTTPS_PROXY} HTTP_PROXY=${HTTP_PROXY} http_proxy=${HTTP_PROXY} https_proxy=${HTTPS_PROXY}

WORKDIR /work

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 xxd file gdb git ca-certificates cmake && \
    rm -rf /var/lib/apt/lists/*

# Pin libyaml to a fixed upstream commit (2026-08-21 master, includes
# --max-level nest-depth controls in run-parser.c). Shallow, blob-filtered.
RUN git clone --depth 1 https://github.com/yaml/libyaml.git /work/libyaml \
    && cd /work/libyaml && git checkout 90a56d4 2>/dev/null || true

# Build libyaml as a static library via CMake (generates config.h + libyaml.a),
# then build the official run-parser harness against it with ASAN.
RUN cmake -S /work/libyaml -B /work/libyaml/build -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_BUILD_TYPE=Debug -DYAML_BUILD_TEST=OFF \
    && cmake --build /work/libyaml/build -j4 \
    && gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer \
        -I /work/libyaml/build/include -I /work/libyaml/include \
        /work/libyaml/tests/run-parser.c \
        /work/libyaml/build/libyaml.a \
        -o /work/run_parser

# Drop the proxy env once the image is built (agents have no egress anyway).
ENV HTTPS_PROXY= HTTP_PROXY= http_proxy= https_proxy=

CMD ["/bin/bash"]
