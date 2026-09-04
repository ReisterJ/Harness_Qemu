# Apache curl 8.22.0 — C memory-error target (ASAN)
# Build: CMake, static libcurl + ASAN-instrumented curl CLI.
# Only plain-HTTP parsing surface is kept (SSL/etc disabled for build
# stability); the harness feeds raw HTTP responses from a local server.
#
# Build needs network (git clone + apt): run with
#   VULN_PIPELINE_DOCKER_BUILD_NETWORK=host
# and pass the proxy at build time, e.g.
#   --build-arg HTTPS_PROXY=http://127.0.0.1:7897 --build-arg HTTP_PROXY=http://127.0.0.1:7897
FROM gcc:14

ARG HTTPS_PROXY=
ARG HTTP_PROXY=
ENV HTTPS_PROXY=${HTTPS_PROXY} HTTP_PROXY=${HTTP_PROXY} http_proxy=${HTTP_PROXY} https_proxy=${HTTPS_PROXY}

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 cmake zlib1g-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# curl source at the exact release tag (shallow).
RUN git clone --depth 1 --branch curl-8_22_0 https://github.com/curl/curl.git /work/curl

# ASAN build via CMake. Keep the parsing surface: http, cookie, url,
# content-encoding (zlib/gzip). Disable optional heavy deps for stability.
WORKDIR /work/curl
RUN cmake -S /work/curl -B /work/curl/build \
        -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=ON -DBUILD_TESTING=OFF \
        -DCURL_USE_OPENSSL=OFF -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBIDN2=OFF \
        -DCURL_USE_BROTLI=OFF -DCURL_USE_ZSTD=OFF -DCURL_USE_NGHTTP2=OFF \
        -DCURL_USE_LIBSSH2=OFF -DCURL_USE_LIBSSH=OFF \
        -DCURL_ZLIB=ON -DCURL_DISABLE_LDAP=ON -DCURL_DISABLE_LDAPS=ON \
        -DCURL_DISABLE_DICT=ON -DCURL_DISABLE_TELNET=ON -DCURL_DISABLE_TFTP=ON \
        -DCMAKE_C_FLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
    && cmake --build /work/curl/build -j"$(nproc)"

# Harness: raw-HTTP-response feeder -> ASAN curl.
COPY run_curl.sh /work/run_curl.sh
RUN chmod +x /work/run_curl.sh

# Drop the proxy env once the image is built (agents have no egress anyway).
ENV HTTPS_PROXY= HTTP_PROXY= http_proxy= https_proxy=

WORKDIR /work
