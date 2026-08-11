# ohos6-kernel — OpenHarmony 6.0 kernel hunt target

Hunts the **OpenHarmony 6.0 standard-system kernel** (`kernel_linux_5.10`,
Linux **5.10.210**) for real kernel bugs using the pipeline's kernel
find/grade machinery (`detector: kasan`). This is a **hunt target** — no
pre-planted CVE. The find agent reads the OHOS kernel source, crafts PoCs,
boots the kernel in QEMU/KVM, and submits whatever real crash it lands.

## Verified kernel facts (2026-08-11, from gitee)

| Repo | Path in manifest | Branch | Commit (gitee) | Version |
|---|---|---|---|---|
| `openharmony/kernel_linux_5.10` | `kernel/linux/linux-5.10` | `OpenHarmony-6.0-Release` | `0461994cd06aa4d37199d4a6e5d58abab642a4ee` | Linux 5.10.210 |
| `openharmony/kernel_linux_6.6` | `kernel/linux/linux-6.6` | `OpenHarmony-6.0-Release` | `05abe5cb2815cc7a2ebb64669a347884db467f6d` | Linux 6.6-based (alternative) |

OHOS 6.0 ships **two** standard-system kernels (5.10 and 6.6). This target
defaults to **5.10** (the long-standing standard-system workhorse); switching
to 6.6 is a one-line change in `build_kernel.sh` + `config.yaml`.

Support repos (all `OpenHarmony-6.0-Release`): `kernel_linux_build`
(`build_kernel.sh`/`kernel_build.py`), `kernel_linux_config` (defconfigs),
`kernel_linux_patches` (HDF + board patches), `kernel_linux_common_modules`.

Key config facts: the official
`linux-5.10/arch/x86/configs/qemu-x86_64-linux_standard_defconfig` is a gcc
11.3 build with `DEBUG_INFO(DWARF4)`, `STACKPROTECTOR_STRONG`,
`BLK_DEV_INITRD`, `VIRTIO_BLK` — but **KASAN is NOT set**; this target's build
script enables KASAN on top of it.

## Why kernel-only (not the full OHOS system)

A kernel bug manifests identically no matter what userspace booted it. For
kernel hunting you only need the OHOS kernel booted under a plain rootfs (the
syzbot base's Ubuntu jail). Building the full OHOS 6.0 userland (repo sync,
~100 GB, multi-hour build) is **only** needed if you later want to hunt
userspace services or kernel paths that only real OHOS services trigger.

## One-time build (host)

```bash
# 1. prerequisites: gcc>=11 make flex bison bc libssl-dev libelf-dev dwarves cpio git
cd targets/ohos6-kernel
./build_kernel.sh                      # common baseline + KASAN  (~10-30 min)
# APPLY_OHOS_PATCHES=1 ./build_kernel.sh   # optionally add HDF (more attack surface)
```

Produces `images/bzImage` and `kernel-src/linux-5.10/` (both are gitignored).

## Build the agent image

```bash
export VULN_PIPELINE_DOCKER_BUILD_NETWORK=host   # syzbot base presets proxy on 127.0.0.1:7897
docker pull cybergym/syzbot-target:09b7d050e4806540153d
vuln-pipeline build-image targets/ohos6-kernel   # or: docker build -t vuln-pipeline-ohos6-kernel:latest targets/ohos6-kernel
```

## Run

```bash
cd /home/user/workstation/defending-code-reference-harness
export VULN_PIPELINE_DOCKER_BUILD_NETWORK=host
nohup .venv/bin/vuln-pipeline run targets/ohos6-kernel \
    --dangerously-no-sandbox --model deepseek/deepseek-v4-flash --max-turns 1000 \
    > /tmp/ohos6_kernel_run.log 2>&1 &
```

Single-run convention (like the other validation targets): `--runs 1` is the
default; don't use `--runs N` batches for hunt targets unless you understand
the batch dedup semantics (see `targets/README.md` / repo memory).

## How the agents work (no new machinery)

- The container carries the OHOS bzImage at `/kernel/bzImage` and the OHOS
  source at `/src/linux` (`source_root`).
- Find/grade agents reuse the existing `detector: kasan` boot recipe:
  `qemu-system-x86_64 -enable-kvm -kernel /kernel/bzImage -initrd
  /images/ramdisk_v1.img -drive file=/images/rootfs_v3.img,...` with serial on
  a unix socket; they base64 the PoC in over serial, `gcc -B/usr/bin` inside
  the Ubuntu guest, run, and capture the kernel console.
- Crashes are judged on the KASAN report / oops / panic Call Trace (this
  image's kernel **is** KASAN-enabled).

## Switching from hunt mode to CVE validation

To validate a specific known bug instead of open hunting:

1. Pin the kernel to the vulnerable commit in `config.yaml` (`commit:`) and
   rebuild via `build_kernel.sh`.
2. Rewrite `attack_surface` as the neutral vuln description (functions +
   mechanism, **no trigger steps / no signature** — see `targets/kernelval`
   for the leak-hygiene pattern).
3. Replace `grade_reference` with the exact expected crash shape (class + top
   frames), like `targets/kernelval/config.yaml`.
4. Set `focus_areas` to the single claim.

## Gotchas

- **Docker build needs `--network=host`** and a pre-pulled base image (syzbot
  images preset `HTTP_PROXY=127.0.0.1:7897`).
- **KVM required**: `--device /dev/kvm` is in `config.yaml`; the run needs
  `--dangerously-no-sandbox`.
- **KASAN on x86** is mature in 5.10 — if a specific driver build fails under
  KASAN, fall back to `CONFIG_KASAN=n` and rely on oops detection (update the
  `attack_surface` / `grade_reference` environment notes accordingly).
- The guest rootfs is Ubuntu (chroot jail at `user@exphost`) — the OHOS kernel
  boots it with `root=/dev/vda1`; keep `EXT4_FS` + `VIRTIO_BLK` + initramfs
  enabled in the build (the script forces them).
