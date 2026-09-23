FROM n132/arvo:57672-vul AS mruby_source
RUN git -C /src/mruby rev-parse HEAD > /tmp/mruby-source.commit

FROM eurecoms3/symcc:latest AS symcc_builder
ARG TARGET_COMMIT=2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b
USER root

COPY --from=mruby_source /src/mruby /src/mruby
COPY --from=mruby_source /tmp/mruby-source.commit /tmp/mruby-source.commit
COPY --from=mruby_source /usr/bin/ruby /usr/bin/ruby
COPY --from=mruby_source /usr/bin/ruby2.7 /usr/bin/ruby2.7
COPY --from=mruby_source /usr/bin/rake /usr/bin/rake
COPY --from=mruby_source /usr/lib/ruby /usr/lib/ruby
COPY --from=mruby_source /usr/lib/x86_64-linux-gnu/libruby-2.7.so.2.7* /usr/lib/x86_64-linux-gnu/
COPY --from=mruby_source /usr/lib/x86_64-linux-gnu/ruby /usr/lib/x86_64-linux-gnu/ruby
COPY --from=mruby_source /usr/share/rubygems-integration /usr/share/rubygems-integration
COPY harness/symbolic/fuzzer_file_driver.c /tmp/fuzzer_file_driver.c

RUN set -eux; \
    ruby --version; \
    rake --version; \
    test "$(cat /tmp/mruby-source.commit)" = "${TARGET_COMMIT}"; \
    cd /src/mruby; \
    rm -rf build; \
    export CC=symcc CXX=sym++ LD=symcc; \
    export CFLAGS='-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION'; \
    export CXXFLAGS="${CFLAGS}"; \
    rake -m; \
    test -f build/host/lib/libmruby.a; \
    mkdir -p /out; \
    symcc ${CFLAGS} -Iinclude \
      oss-fuzz/mruby_fuzzer.c /tmp/fuzzer_file_driver.c \
      build/host/lib/libmruby.a -lm -o /out/mruby_fuzzer_symcc

FROM eurecoms3/symcc:latest
ARG TARGET_COMMIT=2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b
LABEL org.harness.target.source-commit="${TARGET_COMMIT}" \
      org.harness.target.symcc-binary="/out/mruby_fuzzer_symcc"
USER root

COPY --from=mruby_source /src/mruby /src/mruby
COPY --from=mruby_source /out /out
COPY --from=symcc_builder /out/mruby_fuzzer_symcc /out/mruby_fuzzer_symcc
