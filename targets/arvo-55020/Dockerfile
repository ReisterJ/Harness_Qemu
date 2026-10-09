# GNU binutils objdump target (ARVO 55020).
#
# Builds three executables from the same source commit:
#   /out/run-objdump-clean        -> wrapper around the ASan binary (leak checks off)
#   /out/fuzz_objdump_safe_symcc  -> SymCC-instrumented build (fixed compiler)
#   /out/fuzz_objdump_safe_cov    -> LLVM coverage build for per-input feedback
#
# Fully offline: the base image already carries the binutils source, build.sh,
# the bison/flex/texinfo packages and the SymCC/LLVM-15 toolchain; only the
# fixed Feedback.h from the idcache toolchain image is swapped in.
# The binutils rebuild is heavy (~1 h per variant), so both variants are built
# from the same `common` layer.

FROM local/cybergym-arvo-55020-symcc:20260929 AS common
USER root
COPY --from=local/symcc-target-feedback:20261007-idcache \
     /symcc-feedback-source/compiler/Feedback.h \
     /symcc-feedback-source/compiler/Feedback.h
RUN ninja -C /symcc-feedback-build
COPY file_driver.c /tmp/file_driver.c
COPY --chmod=0555 run-objdump-clean /out/run-objdump-clean
LABEL org.harness.target.source-commit="da1f81c128b9be3cface7b0860085da8c6452510"

FROM common AS symcc-target
USER root
ENV CC="/symcc-feedback-build/symcc"
ENV CXX="/symcc-feedback-build/sym++"
ENV CCC="/symcc-feedback-build/sym++"
ENV SRC="/src"
ENV OUT="/out"
ENV WORK="/work"
ENV FUZZING_ENGINE="libfuzzer"
ENV LIB_FUZZING_ENGINE="/tmp/objdump-file-driver.o"
ENV CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fno-pie -no-pie -Wno-int-conversion -Wno-unused-command-line-argument"
ENV CXXFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -stdlib=libc++ -fno-pie -no-pie -Wno-int-conversion -Wno-unused-command-line-argument"
ENV LDFLAGS="-no-pie"

RUN set -eux; \
    /symcc-feedback-build/symcc -O1 -g -fno-pie -c \
      /tmp/file_driver.c -o /tmp/objdump-file-driver.o; \
    sed -i 's/--enable-targets=all/--enable-targets=all --enable-gprofng=no/' /src/build.sh; \
    sed -i 's/make MAKEINFO=true && true/make MAKEINFO=true/' /src/build.sh; \
    sed -i 's|^make MAKEINFO=true$|make CC_FOR_BUILD=/usr/lib/llvm-15/bin/clang CXX_FOR_BUILD=/usr/lib/llvm-15/bin/clang++ MAKEINFO=true|' /src/build.sh; \
    cd /src; bash -e /src/build.sh; \
    install -D -m 0555 /out/fuzz_objdump_safe /out/fuzz_objdump_safe_symcc; \
    test -s /out/fuzz_objdump_safe_symcc; \
    readelf -h /out/fuzz_objdump_safe_symcc | grep -Eq 'Type:[[:space:]]+EXEC'

FROM common AS coverage-target
USER root
ENV CC="/usr/lib/llvm-15/bin/clang"
ENV CXX="/usr/lib/llvm-15/bin/clang++"
ENV CCC="/usr/lib/llvm-15/bin/clang++"
ENV SRC="/src"
ENV OUT="/out"
ENV WORK="/work"
ENV FUZZING_ENGINE="libfuzzer"
ENV LIB_FUZZING_ENGINE="/tmp/objdump-file-driver.o"
ENV CFLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fno-pie -no-pie -Wno-int-conversion -Wno-unused-command-line-argument -fprofile-instr-generate -fcoverage-mapping"
ENV CXXFLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fno-pie -no-pie -Wno-int-conversion -Wno-unused-command-line-argument -fprofile-instr-generate -fcoverage-mapping"
ENV LDFLAGS="-no-pie -fprofile-instr-generate"

RUN set -eux; \
    /usr/lib/llvm-15/bin/clang -O1 -g -fno-pie -fprofile-instr-generate -fcoverage-mapping \
      -c /tmp/file_driver.c -o /tmp/objdump-file-driver.o; \
    sed -i 's/--enable-targets=all/--enable-targets=all --enable-gprofng=no/' /src/build.sh; \
    sed -i 's/make MAKEINFO=true && true/make MAKEINFO=true/' /src/build.sh; \
    sed -i 's|^make MAKEINFO=true$|make CC_FOR_BUILD=/usr/lib/llvm-15/bin/clang CXX_FOR_BUILD=/usr/lib/llvm-15/bin/clang++ MAKEINFO=true|' /src/build.sh; \
    cd /src; bash -e /src/build.sh; \
    install -D -m 0555 /out/fuzz_objdump_safe /out/fuzz_objdump_safe_cov; \
    test -s /out/fuzz_objdump_safe_cov

FROM common AS runtime
USER root
LABEL org.harness.target.symcc-binary="/out/fuzz_objdump_safe_symcc" \
      org.harness.target.coverage-binary="/out/fuzz_objdump_safe_cov"
# The `common` stage bakes the historical 1-argument wrapper as
# /out/run-objdump-clean; that COPY instruction is left byte-identical so the
# heavy binutils build-stages above stay cache-valid, and the final image gets
# the flag-tolerant version here instead (it accepts libFuzzer flags before or
# after the input file, which is what the dynamic-execution protocol sends).
COPY --chmod=0555 run-objdump-clean.runtime /out/run-objdump-clean
COPY --from=symcc-target /out/fuzz_objdump_safe_symcc /out/fuzz_objdump_safe_symcc
COPY --from=coverage-target /out/fuzz_objdump_safe_cov /out/fuzz_objdump_safe_cov
COPY --from=symcc-target /symcc-feedback-build/SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.so /usr/local/lib/libsymcc-rt.so
RUN ldconfig \
    && rm -rf /symcc-feedback-build /symcc-feedback-source /symcc_build /libcxx_symcc_install \
    && test ! -e /symcc-feedback-build \
    && test -x /out/fuzz_objdump_safe \
    && test -x /out/fuzz_objdump_safe_symcc \
    && test -x /out/fuzz_objdump_safe_cov \
    && ldd /out/fuzz_objdump_safe_symcc | grep -q libsymcc-rt.so
