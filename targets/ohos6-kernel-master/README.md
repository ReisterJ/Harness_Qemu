# OpenHarmony kernel hunt target — master branch

A vuln-pipeline kernel target that boots the **latest** OpenHarmony
common-kernel (openharmony/kernel_linux_5.10 **master** branch) in QEMU/KVM
with KASAN enabled, for autonomous kernel vulnerability hunting.

## Why master (vs `targets/ohos6-kernel`)

- `targets/ohos6-kernel` pins `OpenHarmony-6.0-Release` = `0461994cd`
  (2025-08-12), a snapshot that lags master by 19 commits and is **missing**
  the CVE-2025-38588 family fixes. Hunting it mostly surfaces *known,
  already-fixed-upstream* bugs (the CVE-2025-38588 `rt6_nlmsg_size` infinite
  loop is a concrete example — present in release, fixed in master).
- This target pins **master** = `f88704ae607f` (2025-09-09), which carries the
  latest CVE backports. A bug found here is far more likely to be real and
  not-yet-fixed anywhere.

Both are Linux 5.10.210 baselines (verified: same VERSION/PATCHLEVEL/SUBLEVEL
in both branches).

## Verified facts (2026-08-15, all `git ls-remote`-verifiable)

- Kernel repo: https://gitee.com/openharmony/kernel_linux_5.10.git
- `master` HEAD: `f88704ae607f90518f67aee33790ac06d6ada77d`
  (2025-09-09, subject `!1866 master CVE fix`)
- `OpenHarmony-6.0-Release` HEAD: `0461994cd06aa4d37199d4a6e5d58abab642a4ee`
  (2025-08-12)
- Branch relation: release is an ancestor of master (`git merge-base` =
  release HEAD); master leads release by 19 commits, release leads master by 0.
- The CVE-2025-38588 fix (`cd4f714dc` "ipv6: prevent infinite loop in
  rt6_nlmsg_size()") is in master but absent from the release branch.

## Build

```bash
cd targets/ohos6-kernel-master
JOBS=6 ./build_kernel.sh          # -> images/bzImage (KASAN + softlockup-panic)
docker build --network=host -t vuln-pipeline-ohos6-kernel-master:latest .
```

`build_kernel.sh` clones the master branch (shallow, pinned to
`f88704ae607f`), applies the KASAN `addr_has_shadow` compat patch, enables
KASAN + SOFTLOCKUP_DETECTOR + BOOTPARAM_SOFTLOCKUP_PANIC + namespace set for
nsjail, and produces `images/bzImage`. It also fetches pristine upstream
5.10.210 into `kernel-src/upstream-5.10.210/` for the agent to diff against.

## Run

```bash
cd <repo root>
VULN_PIPELINE_DOCKER_BUILD_NETWORK=host \
  .venv/bin/vuln-pipeline run targets/ohos6-kernel-master \
    --dangerously-no-sandbox --model deepseek/deepseek-v4-flash \
    --max-turns 5000 --runs 1
```

## Gotchas

- Same as `targets/ohos6-kernel`: docker build must use `--network=host`
  (loopback proxy), and the pipeline build needs
  `VULN_PIPELINE_DOCKER_BUILD_NETWORK=host`.
- The KASAN compat patch is applied with an idempotency check
  (`apply --reverse --check`) so re-runs are safe.
- The config repo (`kernel_linux_config`) is fetched from its **master**
  branch for this target.
