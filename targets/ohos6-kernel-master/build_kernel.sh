#!/usr/bin/env bash
#
# Build the OpenHarmony kernel from the **master** branch (latest) for the
# vuln-pipeline QEMU/KVM hunt target (targets/ohos6-kernel-master).
#
# Rationale: the OpenHarmony-6.0-Release branch (targets/ohos6-kernel) is a
# 2025-08-12 snapshot that lags master by 19 commits and is missing the
# CVE-2025-38588 family fixes — hunting it mostly surfaces *known, already
# fixed upstream* bugs. Master (2025-09-09, f88704ae607f) carries the latest
# CVE backports, so a bug found here is far more likely to be a real,
# not-yet-fixed issue.
#
# Produces:
#   targets/ohos6-kernel-master/images/bzImage         (KASAN-enabled bzImage)
#   targets/ohos6-kernel-master/kernel-src/linux-5.10  (source for /src/linux)
#
# Verified inputs (2026-08-15, git ls-remote):
#   openharmony/kernel_linux_5.10 @ master = Linux 5.10.210
#     gitee commit f88704ae607f90518f67aee33790ac06d6ada77d (2025-09-09)
#
# Usage:
#   ./build_kernel.sh
# Host prerequisites: same as targets/ohos6-kernel/build_kernel.sh
set -euo pipefail

TARGET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$TARGET_DIR/images"
SRC_DIR="$TARGET_DIR/kernel-src"
KERNEL_DIR="$SRC_DIR/linux-5.10"

KERNEL_REPO="${KERNEL_REPO:-https://gitee.com/openharmony/kernel_linux_5.10.git}"
KERNEL_BRANCH="${KERNEL_BRANCH:-master}"
KERNEL_COMMIT="${KERNEL_COMMIT:-f88704ae607f90518f67aee33790ac06d6ada77d}"

CONFIG_REPO="${CONFIG_REPO:-https://gitee.com/openharmony/kernel_linux_config.git}"
CONFIG_BRANCH="${CONFIG_BRANCH:-master}"
DEFCONFIG_REL="linux-5.10/arch/x86/configs/qemu-x86_64-linux_standard_defconfig"

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

# ---- 2. KASAN compat patch (5.10.210 stable backport renamed
#          addr_has_shadow -> addr_has_metadata but left the mm/kasan callers
#          on the old name; without this alias the KASAN build breaks).
KASAN_COMPAT_PATCH="$TARGET_DIR/patches/0001-kasan-addr_has_shadow-compat.patch"
if git -C "$KERNEL_DIR" apply --reverse --check "$KASAN_COMPAT_PATCH" 2>/dev/null; then
  echo "[*] KASAN compat patch already applied (skipping)"
else
  echo "[*] applying KASAN compat patch (addr_has_shadow alias)"
  git -C "$KERNEL_DIR" apply "$KASAN_COMPAT_PATCH"
fi

# ---- 2b. Fetch pristine upstream 5.10.210 source (for diffing) -------------
# master is the same Linux 5.10.210 baseline, so diff against the same
# pristine upstream to isolate the OHOS-customized / backported surface.
UPSTREAM_URL="${UPSTREAM_URL:-https://mirrors.tuna.tsinghua.edu.cn/kernel/v5.x/linux-5.10.210.tar.xz}"
UPSTREAM_DIR="$SRC_DIR/upstream-5.10.210"
if [ -d "$UPSTREAM_DIR" ]; then
  echo "[*] upstream source already present ($UPSTREAM_DIR)"
else
  echo "[*] downloading upstream linux-5.10.210 (once, ~115MB)"
  curl -fSL -o "$SRC_DIR/linux-5.10.210.tar.xz" "$UPSTREAM_URL"
  tar -C "$SRC_DIR" -xJf "$SRC_DIR/linux-5.10.210.tar.xz"
  rm -f "$SRC_DIR/linux-5.10.210.tar.xz"
  [ -d "$SRC_DIR/linux-5.10.210" ] && mv "$SRC_DIR/linux-5.10.210" "$UPSTREAM_DIR"
  [ -d "$UPSTREAM_DIR" ] || { echo "[!] upstream extract failed"; exit 1; }
fi

# ---- 3. Config: official x86 QEMU defconfig + KASAN + boot essentials ------
echo "[*] fetching defconfig ($CONFIG_BRANCH/$DEFCONFIG_REL)"
if [ ! -d "$SRC_DIR/config/.git" ]; then
  git clone --depth 1 --branch "$CONFIG_BRANCH" "$CONFIG_REPO" "$SRC_DIR/config"
fi
cp "$SRC_DIR/config/$DEFCONFIG_REL" "$KERNEL_DIR/.config"

TC_OVERRIDES="CC=gcc LD=ld AR=ar NM=nm OBJCOPY=objcopy OBJDUMP=objdump READELF=readelf STRIP=strip"

KCFLAGS_EXTRA="-Wno-error=strict-prototypes -Wno-error=declaration-after-statement"

cd "$KERNEL_DIR"
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
  --enable HUNG_TASK --enable DETECT_HUNG_TASK \
  --enable UBSAN --enable UBSAN_SANITIZE_ALL \
  --enable UBSAN_BOUNDS --enable UBSAN_SHIFT \
  --enable UBSAN_SIGNED_OVERFLOW --enable UBSAN_DIV_ZERO \
  --enable PANIC_ON_OOPS
make olddefconfig $TC_OVERRIDES KCFLAGS="$KCFLAGS_EXTRA"

# ---- 4. Build ---------------------------------------------------------------
echo "[*] building bzImage with $JOBS jobs"
make -j"$JOBS" bzImage $TC_OVERRIDES KCFLAGS="$KCFLAGS_EXTRA"

# ---- 5. Collect --------------------------------------------------------------
cp arch/x86/boot/bzImage "$IMAGES_DIR/bzImage"
echo "[+] done: $IMAGES_DIR/bzImage"
