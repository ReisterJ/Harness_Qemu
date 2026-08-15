#!/usr/bin/env bash
#
# Build the OpenHarmony 6.0 standard-system kernel for the vuln-pipeline
# QEMU/KVM hunt target (targets/ohos6-kernel).
#
# Produces:
#   targets/ohos6-kernel/images/bzImage        (KASAN-enabled OHOS 5.10.210 bzImage)
#   targets/ohos6-kernel/kernel-src/linux-5.10 (source the Dockerfile COPYs to /src/linux)
#
# Verified inputs (2026-08-11):
#   openharmony/kernel_linux_5.10 @ OpenHarmony-6.0-Release = Linux 5.10.210
#     gitee commit 0461994cd06aa4d37199d4a6e5d58abab642a4ee
#   openharmony/kernel_linux_config @ OpenHarmony-6.0-Release:
#     linux-5.10/arch/x86/configs/qemu-x86_64-linux_standard_defconfig
#     (gcc 11.3 build; DEBUG_INFO DWARF4 + STACKPROTECTOR_STRONG; KASAN NOT set
#      by default — this script enables KASAN + boot essentials on top)
#
# Usage:
#   ./build_kernel.sh                     # common baseline + KASAN
#   APPLY_OHOS_PATCHES=1 ./build_kernel.sh  # also apply OHOS common/HDF patches
#
# Host prerequisites: gcc (>=11), make, flex, bison, bc, libssl-dev,
# libelf-dev, dwarves, cpio, git. ~15 GB disk. ~10-30 min with enough cores.
set -euo pipefail

TARGET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$TARGET_DIR/images"
SRC_DIR="$TARGET_DIR/kernel-src"
KERNEL_DIR="$SRC_DIR/linux-5.10"

KERNEL_REPO="${KERNEL_REPO:-https://gitee.com/openharmony/kernel_linux_5.10.git}"
KERNEL_BRANCH="${KERNEL_BRANCH:-OpenHarmony-6.0-Release}"
KERNEL_COMMIT="${KERNEL_COMMIT:-0461994cd06aa4d37199d4a6e5d58abab642a4ee}"

CONFIG_REPO="${CONFIG_REPO:-https://gitee.com/openharmony/kernel_linux_config.git}"
CONFIG_BRANCH="${CONFIG_BRANCH:-OpenHarmony-6.0-Release}"
DEFCONFIG_REL="linux-5.10/arch/x86/configs/qemu-x86_64-linux_standard_defconfig"

PATCHES_REPO="${PATCHES_REPO:-https://gitee.com/openharmony/kernel_linux_patches.git}"
PATCHES_BRANCH="${PATCHES_BRANCH:-OpenHarmony-6.0-Release}"
HDF_PATCH_REL="linux-5.10/common_patch/hdf.patch"

JOBS="${JOBS:-$(nproc)}"

mkdir -p "$IMAGES_DIR" "$SRC_DIR"

# ---- 1. Fetch kernel source (shallow, pinned commit) -----------------------
if [ ! -d "$KERNEL_DIR/.git" ]; then
  echo "[*] cloning $KERNEL_REPO @ $KERNEL_BRANCH"
  git clone --depth 1 --branch "$KERNEL_BRANCH" "$KERNEL_REPO" "$KERNEL_DIR"
fi
CUR="$(git -C "$KERNEL_DIR" rev-parse HEAD)"
if [ "$CUR" != "$KERNEL_COMMIT" ]; then
  echo "[*] pinning to $KERNEL_COMMIT (was $CUR)"
  git -C "$KERNEL_DIR" fetch --depth 1 origin "$KERNEL_COMMIT"
  git -C "$KERNEL_DIR" checkout --detach "$KERNEL_COMMIT"
fi

# ---- 2. (optional) apply OHOS patches (HDF etc.) ---------------------------
if [ "${APPLY_OHOS_PATCHES:-0}" = "1" ]; then
  echo "[*] applying OHOS common patches ($HDF_PATCH_REL)"
  PATCH_DIR="$SRC_DIR/patches"
  if [ ! -d "$PATCH_DIR/.git" ]; then
    git clone --depth 1 --branch "$PATCHES_BRANCH" "$PATCHES_REPO" "$PATCH_DIR"
  fi
  # Board patches are NOT applied (x86 QEMU has no vendor board).
  git -C "$KERNEL_DIR" apply "$PATCH_DIR/$HDF_PATCH_REL"
else
  echo "[*] skipping OHOS patches (set APPLY_OHOS_PATCHES=1 to include HDF)"
fi

# ---- 2b. KASAN compat patch (5.10.210 stable backport renamed
#          addr_has_shadow -> addr_has_metadata but left the mm/kasan callers
#          on the old name; without this alias the KASAN build breaks).
# NOTE: idempotency is checked with `apply --reverse --check` (a plain
# `apply --check` stays 0 on an already-applied patch because the hunk anchor
# context still matches, causing double application).
KASAN_COMPAT_PATCH="$TARGET_DIR/patches/0001-kasan-addr_has_shadow-compat.patch"
if git -C "$KERNEL_DIR" apply --reverse --check "$KASAN_COMPAT_PATCH" 2>/dev/null; then
  echo "[*] KASAN compat patch already applied (skipping)"
else
  echo "[*] applying KASAN compat patch (addr_has_shadow alias)"
  git -C "$KERNEL_DIR" apply "$KASAN_COMPAT_PATCH"
fi

# ---- 2c. Fetch pristine upstream 5.10.210 source (for diffing) -------------
# The find agent diffs the OHOS tree (/src/linux) against upstream to isolate
# the OHOS-customized attack surface. Bake it into the image so the agent
# doesn't download ~115MB per run. TUNA mirror by default (cdn.kernel.org is
# very slow from CN networks); override with UPSTREAM_URL.
UPSTREAM_URL="${UPSTREAM_URL:-https://mirrors.tuna.tsinghua.edu.cn/kernel/v5.x/linux-5.10.210.tar.xz}"
UPSTREAM_DIR="$SRC_DIR/upstream-5.10.210"
if [ -d "$UPSTREAM_DIR" ]; then
  echo "[*] upstream source already present ($UPSTREAM_DIR)"
else
  echo "[*] downloading upstream linux-5.10.210 (once, ~115MB)"
  curl -fSL -o "$SRC_DIR/linux-5.10.210.tar.xz" "$UPSTREAM_URL"
  tar -C "$SRC_DIR" -xJf "$SRC_DIR/linux-5.10.210.tar.xz"
  rm -f "$SRC_DIR/linux-5.10.210.tar.xz"
  # the tarball extracts as linux-5.10.210/ -> rename to upstream-5.10.210
  [ -d "$SRC_DIR/linux-5.10.210" ] && mv "$SRC_DIR/linux-5.10.210" "$UPSTREAM_DIR"
  [ -d "$UPSTREAM_DIR" ] || { echo "[!] upstream extract failed"; exit 1; }
fi

# ---- 3. Config: official x86 QEMU defconfig + KASAN + boot essentials ------
echo "[*] fetching defconfig ($CONFIG_BRANCH/$DEFCONFIG_REL)"
if [ ! -d "$SRC_DIR/config/.git" ]; then
  git clone --depth 1 --branch "$CONFIG_BRANCH" "$CONFIG_REPO" "$SRC_DIR/config"
fi
cp "$SRC_DIR/config/$DEFCONFIG_REL" "$KERNEL_DIR/.config"

# The OHOS kernel's top Makefile hardcodes `CC = $(CCACHE) gcc` (CCACHE=ccache).
# Override the toolchain on the make command line so no ccache is required on
# the build host (command-line vars win over Makefile assignments).
TC_OVERRIDES="CC=gcc LD=ld AR=ar NM=nm OBJCOPY=objcopy OBJDUMP=objdump READELF=readelf STRIP=strip"

# OHOS code is written against gcc 11 (its tested toolchain); the host's gcc 13
# flags extra style warnings in OHOS drivers (e.g. access_tokenid.c) as errors.
# Relax the purely stylistic ones (-Werror=strict-prototypes /
# -Werror=declaration-after-statement); KEEP the memory-safety-relevant ones
# (-Werror=implicit-* etc.). Later flags win in gcc, so KCFLAGS (appended
# after KBUILD_CFLAGS) overrides them.
KCFLAGS_EXTRA="-Wno-error=strict-prototypes -Wno-error=declaration-after-statement"

cd "$KERNEL_DIR"
# Boot essentials + KASAN + nsjail support. The syzbot guest's run.sh wraps the
# user shell in nsjail (namespaces/cgroups/seccomp) — the OHOS qemu defconfig
# disables CONFIG_NAMESPACES, which makes nsjail's clone() fail and the guest
# init (run.sh) exit -> kernel panic "Attempted to kill init". Enable the
# namespace/cgroup set nsjail needs so the guest jail boots.
scripts/config \
  --enable KASAN --enable KASAN_GENERIC --enable KASAN_INLINE \
  --enable DEBUG_INFO --enable DEBUG_INFO_DWARF4 \
  --enable BLK_DEV_INITRD --enable DEVTMPFS --enable DEVTMPFS_MOUNT \
  --enable TMPFS --enable PROC_FS --enable SYSFS --enable BINFMT_ELF \
  --enable EXT4_FS --enable SERIAL_8250 --enable SERIAL_8250_CONSOLE \
  --enable VIRTIO --enable VIRTIO_PCI --enable VIRTIO_BLK \
  --enable UNIX --enable INET --enable PACKET --enable KALLSYMS \
  --enable NAMESPACES --enable UTS_NS --enable IPC_NS --enable PID_NS \
  --enable NET_NS --enable USER_NS --enable TIME_NS --enable NSFS \
  --enable DEVPTS_MULTIPLE_INSTANCES --enable MEMCG --enable VETH \
  --enable SOFTLOCKUP_DETECTOR --enable BOOTPARAM_SOFTLOCKUP_PANIC \
  --enable HUNG_TASK --enable DETECT_HUNG_TASK
make olddefconfig $TC_OVERRIDES KCFLAGS="$KCFLAGS_EXTRA"

# ---- 4. Build ---------------------------------------------------------------
echo "[*] building bzImage with $JOBS jobs"
make -j"$JOBS" bzImage $TC_OVERRIDES KCFLAGS="$KCFLAGS_EXTRA"

# ---- 5. Collect --------------------------------------------------------------
cp arch/x86/boot/bzImage "$IMAGES_DIR/bzImage"
echo "[+] done: $IMAGES_DIR/bzImage"
echo "    key configs:"
grep -E "^CONFIG_(KASAN|KASAN_INLINE|DEBUG_INFO|EXT4_FS|VIRTIO_BLK|SERIAL_8250_CONSOLE)=" .config || true
echo "[+] source tree ready for Docker COPY at: $KERNEL_DIR"
