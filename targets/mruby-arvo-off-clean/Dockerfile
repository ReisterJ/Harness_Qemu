FROM n132/arvo:57672-vul

ARG TARGET_COMMIT=2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b

LABEL org.harness.target.source-commit="${TARGET_COMMIT}" \
      org.harness.target.symbolic-execution="disabled"

# This image deliberately starts from the original ASan target image.  It must
# not inherit the SymCC toolchain or feedback artifacts from the feedback image.
RUN rm -rf /src/aflplusplus/custom_mutators/symcc \
    && test ! -e /out/mruby_fuzzer_symcc \
    && test ! -e /out/symcc-feedback-map.jsonl \
    && test ! -e /symcc-feedback-build \
    && test ! -e /symcc_build \
    && test ! -e /libcxx_symcc_install
