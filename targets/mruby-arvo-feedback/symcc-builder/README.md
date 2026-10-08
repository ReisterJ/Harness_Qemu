# SymCC instrumenter (feedback ID cache)

`Feedback.h` is the patched `compiler/Feedback.h` from the SymCC source inside
`local/symcc-target-feedback:20260924-sitefix1`; `feedback-id-cache.patch` is
the same change as a reviewable diff.

Why: the SymCC feedback map is emitted at pipeline start (pre-optimization
CFG) while the notification callbacks are inserted before the vectorizer and
recomputed block/location IDs from the optimized CFG.  Instrumentation adds
and splits blocks, so the IDs drifted (for `mrb_env_unshare` the target block
was `bb|18` in the map but `bb|12` in the binary).  The harness then never
matched a target ID and reported "not reached" even for known PoCs.

The fix caches IDs computed during map emission and reuses them when
notifications are inserted, so both views agree.

Build the instrumenter image, then the target image
(`targets/mruby-arvo-feedback/Dockerfile`):

```sh
docker build -t local/symcc-target-feedback:20261007-idcache \
  targets/mruby-arvo-feedback/symcc-builder
cd targets/mruby-arvo-feedback
docker build -t local/arvo-57672-site-feedback:20261007-idcache .
docker build -t local/arvo-57672-site-feedback-nogit:20261007-idcache \
  --build-arg BASE_TAG=local/arvo-57672-site-feedback:20261007-idcache \
  -f Dockerfile.nogit .
```
