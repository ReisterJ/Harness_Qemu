# libavc (H.264 SVC) decoder target (ARVO 62290).
#
# Builds three executables from the same source commit:
#   /out/svc_dec_fuzzer_clean  -> ASan build (from the existing image)
#   /out/svc_dec_fuzzer_symcc  -> SymCC-instrumented ASan build (fixed compiler)
#   /out/svc_dec_fuzzer_cov    -> LLVM coverage build for per-input feedback
#
# Fully offline: the base image already carries the libavc source, the libavc
# build tree and the SymCC/LLVM-15 toolchain.  Only the fixed Feedback.h from
# the idcache toolchain image is swapped in before the compiler is rebuilt.

FROM local/arvo-62290-site-feedback-nogit:20260924-nopie-retest AS common
USER root
COPY --from=local/symcc-target-feedback:20261007-idcache \
     /symcc-feedback-source/compiler/Feedback.h \
     /symcc-feedback-source/compiler/Feedback.h
RUN ninja -C /symcc-feedback-build
COPY libavc_file_driver.c /tmp/libavc_file_driver.c
RUN test -d /src/libavc && test -f /out/svc_dec_fuzzer_clean
LABEL org.harness.target.source-commit="b2a61a152a5e83b3419212e8d15a10d4488e51d9"

FROM common AS symcc-target
USER root
RUN set -eux; \
    export SYMCC_REGULAR_LIBCXX=1; \
    /symcc-feedback-build/symcc -O1 -g -fsanitize=address -c \
      /tmp/libavc_file_driver.c -o /tmp/libavc_file_driver_symcc.o; \
    env -u SYMCC_FEEDBACK_MAP_DIR \
      LIB_FUZZING_ENGINE='/tmp/libavc_file_driver_symcc.o -fsanitize=fuzzer-no-link,address' \
      cmake -S /src/libavc -B /work/libavc-symcc-build \
        -DCMAKE_C_COMPILER=/symcc-feedback-build/symcc \
        -DCMAKE_CXX_COMPILER=/symcc-feedback-build/sym++ \
        -DCMAKE_ASM_COMPILER=/usr/lib/llvm-15/bin/clang \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_FLAGS='-O1 -g -fno-omit-frame-pointer' \
        -DCMAKE_CXX_FLAGS='-O1 -g -fno-omit-frame-pointer' \
        -DENABLE_SVC=1 -DENABLE_MVC=1 -DSANITIZE=address; \
    cmake --build /work/libavc-symcc-build --target svc_dec_fuzzer --parallel 4; \
    install -D -m 0555 /work/libavc-symcc-build/svc_dec_fuzzer /out/svc_dec_fuzzer_symcc; \
    test -s /out/svc_dec_fuzzer_symcc

FROM common AS coverage-target
USER root
RUN set -eux; \
    /usr/lib/llvm-15/bin/clang -O1 -g -fprofile-instr-generate -fcoverage-mapping -c \
      /tmp/libavc_file_driver.c -o /tmp/libavc_file_driver_cov.o; \
    LIB_FUZZING_ENGINE='/tmp/libavc_file_driver_cov.o' \
      cmake -S /src/libavc -B /work/libavc-cov-build \
        -DCMAKE_C_COMPILER=/usr/lib/llvm-15/bin/clang \
        -DCMAKE_CXX_COMPILER=/usr/lib/llvm-15/bin/clang++ \
        -DCMAKE_ASM_COMPILER=/usr/lib/llvm-15/bin/clang \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_FLAGS='-O1 -g -fno-omit-frame-pointer -fprofile-instr-generate -fcoverage-mapping' \
        -DCMAKE_CXX_FLAGS='-O1 -g -fno-omit-frame-pointer -fprofile-instr-generate -fcoverage-mapping' \
        -DCMAKE_EXE_LINKER_FLAGS='-fprofile-instr-generate' \
        -DENABLE_SVC=1 -DENABLE_MVC=1; \
    cmake --build /work/libavc-cov-build --target svc_dec_fuzzer --parallel 4; \
    install -D -m 0555 /work/libavc-cov-build/svc_dec_fuzzer /out/svc_dec_fuzzer_cov; \
    test -s /out/svc_dec_fuzzer_cov

FROM common AS runtime
USER root
LABEL org.harness.target.symcc-binary="/out/svc_dec_fuzzer_symcc" \
      org.harness.target.coverage-binary="/out/svc_dec_fuzzer_cov"
COPY --from=symcc-target /out/svc_dec_fuzzer_symcc /out/svc_dec_fuzzer_symcc
COPY --from=coverage-target /out/svc_dec_fuzzer_cov /out/svc_dec_fuzzer_cov
# The SymCC binary links its runtime from the compiler tree that is removed
# below; a loader-cache copy keeps it runnable without an environment wrapper.
COPY --from=symcc-target /symcc-feedback-build/SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.so /usr/local/lib/libsymcc-rt.so
RUN ldconfig \
    && rm -rf /symcc-feedback-build /symcc-feedback-source /symcc_build /libcxx_symcc_install \
    && test ! -e /symcc-feedback-build \
    && test -x /out/svc_dec_fuzzer_clean \
    && test -x /out/svc_dec_fuzzer_symcc \
    && test -x /out/svc_dec_fuzzer_cov \
    && ldd /out/svc_dec_fuzzer_symcc | grep -q libsymcc-rt.so
