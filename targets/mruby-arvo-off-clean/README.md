# MRuby ARVO 57672 clean off target

This target is the uncontaminated baseline for experiments that do not use
SymCC feedback. It is built directly from `n132/arvo:57672-vul`, whose pinned
source commit is `2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b`.

The image intentionally contains the normal ASan/libFuzzer entry point at
`/out/mruby_fuzzer` and the source tree at `/src/mruby`. It does not contain a
SymCC executable, feedback map, SymCC runtime directory, or SymCC-specific
environment variable. The target has no `symbolic_execution` configuration,
so it can only be used as the clean `off` arm.

Build from the repository root:

```sh
docker build \
  -f targets/mruby-arvo-off-clean/Dockerfile \
  -t local/arvo-57672-off-clean:20261006 \
  .
```
