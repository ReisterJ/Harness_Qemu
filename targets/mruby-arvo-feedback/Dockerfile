# MRuby ARVO 57672 target with prebuilt SymCC source-location feedback.
#
# The feedback map and the instrumented binary come from one build.  The
# instrumenter caches block IDs computed during map emission and reuses them
# when notifications are inserted (compiler/Feedback.h); without that cache the
# map and the binary enumerate the CFG differently (instrumentation splits and
# adds blocks), and the harness can never match a target ID.  The pairing check
# below fails the build if the two ever diverge again.
#
# Build from this directory:
#   docker build -t local/arvo-57672-site-feedback:20261007-idcache .
#   docker build -t local/arvo-57672-site-feedback-nogit:20261007-idcache \
#     --build-arg BASE_TAG=local/arvo-57672-site-feedback:20261007-idcache \
#     -f Dockerfile.nogit .
FROM n132/arvo:57672-vul AS target_source
ARG TARGET_COMMIT=2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b
RUN git -C /src/mruby rev-parse HEAD > /tmp/mruby-source.commit \
    && test "$(cat /tmp/mruby-source.commit)" = "${TARGET_COMMIT}"

FROM local/symcc-target-feedback:20261007-idcache AS symcc_builder
ARG TARGET_COMMIT=2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b
USER root

COPY --from=target_source /src/mruby /src/mruby
COPY --from=target_source /tmp/mruby-source.commit /tmp/mruby-source.commit
COPY --from=target_source /usr/bin/ruby /usr/bin/ruby
COPY --from=target_source /usr/bin/ruby2.7 /usr/bin/ruby2.7
COPY --from=target_source /usr/bin/rake /usr/bin/rake
COPY --from=target_source /usr/lib/ruby /usr/lib/ruby
COPY --from=target_source /usr/lib/x86_64-linux-gnu/libruby-2.7.so.2.7* /usr/lib/x86_64-linux-gnu/
COPY --from=target_source /usr/lib/x86_64-linux-gnu/ruby /usr/lib/x86_64-linux-gnu/ruby
COPY --from=target_source /usr/share/rubygems-integration /usr/share/rubygems-integration
COPY mruby_file_driver.c /tmp/mruby_file_driver.c
COPY feedback_gate_check.py /tmp/feedback_gate_check.py
COPY gate_witness.rb /tmp/gate_witness.rb

RUN set -eux; \
    test "$(cat /tmp/mruby-source.commit)" = "${TARGET_COMMIT}"; \
    cd /src/mruby; \
    rm -rf build; \
    rm -rf /out/symcc-feedback-map-raw; \
    mkdir -p /out/symcc-feedback-map-raw; \
    export CC=symcc CXX=sym++ LD=symcc; \
    export CFLAGS='-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION'; \
    export CXXFLAGS="${CFLAGS}"; \
    export SYMCC_FEEDBACK_MAP_DIR=/out/symcc-feedback-map-raw; \
    export SYMCC_SOURCE_ROOT=/src/mruby; \
    export SYMCC_SOURCE_COMMIT="${TARGET_COMMIT}"; \
    rake -m; \
    test -f build/host/lib/libmruby.a; \
    symcc ${CFLAGS} -Iinclude \
      oss-fuzz/mruby_fuzzer.c /tmp/mruby_file_driver.c \
      build/host/lib/libmruby.a -lm -o /out/mruby_fuzzer_symcc; \
    find /out/symcc-feedback-map-raw -type f -name '*.jsonl' -print0 \
      | sort -z \
      | xargs -0 -r cat > /out/symcc-feedback-map.jsonl; \
    test -s /out/symcc-feedback-map.jsonl; \
    python3 /tmp/feedback_gate_check.py \
      /out/symcc-feedback-map.jsonl /out/mruby_fuzzer_symcc \
      /tmp/gate_witness.rb src/vm.c mrb_env_unshare 398

FROM local/symcc-target-feedback:20261007-idcache
ARG TARGET_COMMIT=2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b
LABEL org.harness.target.source-commit="${TARGET_COMMIT}" \
      org.harness.target.symcc-binary="/out/mruby_fuzzer_symcc" \
      org.harness.target.symcc-feedback-map="/out/symcc-feedback-map.jsonl"
USER root

COPY --from=target_source /src/mruby /src/mruby
COPY --from=target_source /out/mruby_fuzzer /out/mruby_fuzzer
COPY --from=symcc_builder /out/mruby_fuzzer_symcc /out/mruby_fuzzer_symcc
COPY --from=symcc_builder /out/symcc-feedback-map.jsonl /out/symcc-feedback-map.jsonl
