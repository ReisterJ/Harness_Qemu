# mruby ARVO 57672 feedback target

This target is a smoke-test wrapper around a locally prebuilt MRuby image with
the SymCC source-location feedback map included at
`/out/symcc-feedback-map.jsonl`.

It intentionally exists beside `targets/mruby-arvo/` instead of replacing it:

- `mruby-arvo` keeps the older prebuilt SymCC baseline target.
- `mruby-arvo-feedback` is used to test v2 target-site feedback semantics.

The image expected by this config is:

```sh
local/arvo-57672-site-feedback-nogit:20261007-idcache
```

The corresponding static report for smoke runs is
`static-report-57672-v2.json` (rolled back 2026-10-07 to the mechanism
description that succeeded on 09-23/09-24: "generational-GC write barrier",
with a plain `src/vm.c:397` location anchor instead of `target_operation`).

## Rebuilding (2026-10-07 ID-cache fix)

The previous image (`...-nogit:20260924-sitefix1`) was unusable for
target-site feedback: the map was emitted from the pipeline-start (pre
optimization) CFG, while the notification callbacks were inserted before the
vectorizer and recomputed block IDs from the optimized CFG.  Instrumentation
adds and splits blocks, so the IDs drifted (e.g. `mrb_env_unshare`'s target
block had ordinal 18 in the map but ordinal 12 in the binary); every
reachability check silently reported "not reached", including runs of known
PoCs.

The fix caches the IDs computed during map emission
(`compiler/Feedback.h: blockIdCache()`) and reuses them when notifications are
inserted.  The image is built from `local/symcc-target-feedback:20261007-idcache`;
`Dockerfile` regenerates map + binary in one build and then runs
`feedback_gate_check.py` against `gate_witness.rb`, which fails the build if
the binary does not emit the map's anchor IDs for `src/vm.c:398`.

Build from this directory:

```sh
docker build -t local/arvo-57672-site-feedback:20261007-idcache .
docker build -t local/arvo-57672-site-feedback-nogit:20261007-idcache \
  --build-arg BASE_TAG=local/arvo-57672-site-feedback:20261007-idcache \
  -f Dockerfile.nogit .
```

