# mruby ARVO 57672 feedback target

This target is a smoke-test wrapper around a locally prebuilt MRuby image with
the SymCC source-location feedback map included at
`/out/symcc-feedback-map.jsonl`.

It intentionally exists beside `targets/mruby-arvo/` instead of replacing it:

- `mruby-arvo` keeps the older prebuilt SymCC baseline target.
- `mruby-arvo-feedback` is used to test v2 target-site feedback semantics.

The image expected by this config is:

```sh
local/arvo-57672-site-feedback-nogit:20260924-sitefix1
```

The corresponding static report for smoke runs is
`static-report-57672-v2.json`. It uses `target_operation` to anchor exact
target reach at `src/vm.c:398` in `mrb_env_unshare`.
