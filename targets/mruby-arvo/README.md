# mruby OSS-Fuzz experiment target

This target config points at the prebuilt n132/arvo:57672-vul image. The image
contains the mruby source tree at /src/mruby and its ASan/libFuzzer binary at
/out/mruby_fuzzer. The target is intentionally configured without focus areas
or known-bug notes so the dynamic experiment receives only its supplied static
report.

Use `--symbolic-execution off` for the baseline, `--symbolic-execution symcc`
for concolic execution from concrete seeds, or `--symbolic-execution klee` for
fully symbolic bounded inputs. SymCC and KLEE run in separate no-network
containers; both produce candidates that must be replayed against the original
ASan/libFuzzer binary.
