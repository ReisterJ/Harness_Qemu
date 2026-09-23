# mruby OSS-Fuzz SymCC experiment target

Build the local runtime image from the repository root:

```sh
docker build -f targets/mruby-arvo/SymCC.Dockerfile \
  -t local/mruby-arvo-prebuilt-symcc:2de602b .
```

The image is derived from `eurecoms3/symcc:latest` to keep SymCC's runtime ABI
compatible. It carries the pinned mruby source tree at `/src/mruby`, the
original ASan/libFuzzer executable at `/out/mruby_fuzzer`, and a SymCC-built
full-target executable at `/out/mruby_fuzzer_symcc`. The SymCC build compiles
mruby's full library and the real OSS-Fuzz `LLVMFuzzerTestOneInput` entry point,
then links the harness file-input adapter; it does not use an agent-generated
source slice. The target config checks that the prebuilt SymCC artifact declares
the same source commit as the target.

The target is intentionally configured without focus areas or known-bug notes
so dynamic experiments receive only their supplied static report.

Use `--symbolic-execution off` for a baseline run or
`--symbolic-execution symcc` for prebuilt concolic feedback from each candidate
input. The Harness replays SymCC-generated inputs against the original ASan
binary. KLEE remains available as a separate opt-in provider.
