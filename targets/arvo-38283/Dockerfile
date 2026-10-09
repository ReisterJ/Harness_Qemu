# FreeRADIUS TACACS decoding target (ARVO 38283).
#
# Builds three executables from the same source commit:
#   /out/run-fuzzer-tacacs-clean  -> original ASan binary (from the ARVO image)
#   /out/fuzzer_tacacs_symcc      -> SymCC-instrumented build (plain, no feedback map)
#   /out/fuzzer_tacacs_cov        -> LLVM coverage build for per-input feedback
#
# Fully offline: the base image already carries the SymCC/LLVM-15 build tree, so
# only the fixed Feedback.h from the idcache toolchain image is swapped in
# before the compiler is rebuilt incrementally.

FROM local/cybergym-arvo-38283-symcc:20260929 AS common
USER root
COPY --from=local/symcc-target-feedback:20261007-idcache \
     /symcc-feedback-source/compiler/Feedback.h \
     /symcc-feedback-source/compiler/Feedback.h
RUN ninja -C /symcc-feedback-build
COPY fuzzer_file_driver.c /tmp/fuzzer_file_driver.c
COPY openssl_compat.c /tmp/openssl_compat.c
LABEL org.harness.target.source-commit="f3c0dd8cffb96973210130b5483b63996fdde48c"

FROM common AS symcc-target
USER root
ENV CC="/symcc-feedback-build/symcc"
ENV CXX="/symcc-feedback-build/sym++"
ENV CCC="/symcc-feedback-build/sym++"
ENV CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -Dfuzzer=1 -fno-pie"
ENV CXXFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -Dfuzzer=1 -stdlib=libc++ -fno-pie -no-pie"
ENV LDFLAGS="-no-pie"
ENV LIB_FUZZING_ENGINE="/usr/lib/llvm-15/lib/clang/15.0.7/lib/linux/libclang_rt.fuzzer-x86_64.a"

RUN set -eux; \
    cd /src/freeradius-server; \
    cp /tmp/fuzzer_file_driver.c src/bin/fuzzer_file_driver.c; \
    cp /tmp/openssl_compat.c src/bin/openssl_compat.c; \
    sed -i 's/^SOURCES[[:space:]]*:=[[:space:]]*fuzzer\.c$/SOURCES := fuzzer.c fuzzer_file_driver.c openssl_compat.c/' src/bin/fuzzer.mk; \
    ./configure --enable-fuzzer > /tmp/symcc-configure.log 2>&1 \
      || { tail -100 /tmp/symcc-configure.log; grep -n -A16 -B8 -E 'error:|undefined reference|cannot find|No such file|GLIBC_' config.log | tail -120; exit 77; }; \
    make -j"$(nproc)" PROTOCOL=tacacs ./build/bin/local/fuzzer_tacacs; \
    install -D -m 0555 build/bin/local/fuzzer_tacacs /out/fuzzer_tacacs_symcc; \
    test -s /out/fuzzer_tacacs_symcc; \
    readelf -h /out/fuzzer_tacacs_symcc | grep -Eq 'Type:[[:space:]]+EXEC'

FROM common AS coverage-target
USER root
ENV CC="/usr/bin/clang-15"
ENV CXX="/usr/bin/clang++-15"
ENV CCC="/usr/bin/clang++-15"
ENV CFLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -Dfuzzer=1 -fno-pie -fprofile-instr-generate -fcoverage-mapping"
ENV CXXFLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -Dfuzzer=1 -fno-pie -fprofile-instr-generate -fcoverage-mapping"
ENV LDFLAGS="-no-pie -fprofile-instr-generate"
ENV LIB_FUZZING_ENGINE="/usr/lib/llvm-15/lib/clang/15.0.7/lib/linux/libclang_rt.fuzzer-x86_64.a"

RUN set -eux; \
    cd /src/freeradius-server; \
    cp /tmp/fuzzer_file_driver.c src/bin/fuzzer_file_driver.c; \
    cp /tmp/openssl_compat.c src/bin/openssl_compat.c; \
    sed -i 's/^SOURCES[[:space:]]*:=[[:space:]]*fuzzer\.c$/SOURCES := fuzzer.c fuzzer_file_driver.c openssl_compat.c/' src/bin/fuzzer.mk; \
    ./configure --enable-fuzzer > /tmp/cov-configure.log 2>&1 \
      || { tail -100 /tmp/cov-configure.log; exit 77; }; \
    make -j"$(nproc)" PROTOCOL=tacacs ./build/bin/local/fuzzer_tacacs; \
    install -D -m 0555 build/bin/local/fuzzer_tacacs /out/fuzzer_tacacs_cov; \
    test -s /out/fuzzer_tacacs_cov

FROM common AS runtime
USER root
LABEL org.harness.target.symcc-binary="/out/fuzzer_tacacs_symcc" \
      org.harness.target.coverage-binary="/out/cov/fuzzer_tacacs"
# Flag-tolerant clean wrapper: the base image bakes a 1-argument version, and
# the dynamic-execution protocol lets the agent pass libFuzzer flags around the
# input file (they were rejected with "usage" before).
COPY --chmod=0555 run-fuzzer-tacacs-clean /out/run-fuzzer-tacacs-clean
COPY --from=symcc-target /out/fuzzer_tacacs_symcc /out/fuzzer_tacacs_symcc
COPY --from=symcc-target /src/freeradius-server/build/lib/local/.libs/ /out/symcc-libs/
# The SymCC binary links its runtime from the compiler tree; the wrapper's
# LD_LIBRARY_PATH resolves it from /out/symcc-libs once the tree is removed.
COPY --from=symcc-target /symcc-feedback-build/SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.so /out/symcc-libs/libsymcc-rt.so
# The fuzzer derives its protocol library name from argv[0], so the coverage
# build must keep the plain `fuzzer_tacacs` name; it lives in its own directory
# and resolves libfreeradius-*.so through the loader cache.
COPY --from=coverage-target /out/fuzzer_tacacs_cov /out/cov/fuzzer_tacacs
COPY --from=coverage-target /src/freeradius-server/build/lib/local/.libs/ /usr/local/lib/
RUN ldconfig \
    && mkdir -p /usr/local/share/freeradius \
    && ln -sfn /src/freeradius-server/share/dictionary /usr/local/share/freeradius/dictionary \
    && rm -rf /symcc-feedback-build /symcc-feedback-source /symcc_build /libcxx_symcc_install \
    && test ! -e /symcc-feedback-build \
    && test -x /out/fuzzer_tacacs_symcc \
    && test -x /out/cov/fuzzer_tacacs \
    && test -r /usr/local/lib/libfreeradius-tacacs.so
