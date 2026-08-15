#!/bin/bash
# LiteOS-M kernel hunt target build — assembles a MINIMAL OpenHarmony-style
# source tree (no full manifest / repo sync), applies the build-adapt patch,
# and produces the QEMU Cortex-M55 (mps3-an547) kernel image with LMS
# (Lite Memory Sanitizer) enabled.
#
# Verified 2026-08-15 against:
#   kernel_liteos_m @ master 32beca78be1fd2a23c8b275a6c5853fa38dbd67f
#   device_qemu / vendor_ohemu @ gitee master
#   arm-none-eabi-gcc 15.2.1 (xpack), gn 2222, ninja 1.13
#
# Prereqs on the build host:
#   git, python3, pip kconfiglib, gn + ninja on PATH,
#   arm-none-eabi-gcc on PATH (xpack or ARM GNU toolchain)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="${SRC_ROOT:-$ROOT/build-tree}"
GITCODE="https://gitcode.com/openharmony"
GITEE="https://gitee.com/openharmony"
PRODUCT="qemu_cm55_mini_system_demo"
BOARD="arm_mps3_an547"

clone_shallow() { # $1=url $2=dest
  if [ ! -d "$2/.git" ]; then
    git clone --depth 1 "$1" "$2"
  fi
}

echo "==> [1/6] assembling minimal source tree under $SRC"
mkdir -p "$SRC"
cd "$SRC"
clone_shallow "$GITCODE/build.git"                       build
clone_shallow "$GITCODE/kernel_liteos_m.git"             kernel/liteos_m
clone_shallow "$GITCODE/drivers_hdf_core.git"            drivers/hdf_core
clone_shallow "$GITCODE/third_party_musl.git"            third_party/musl
clone_shallow "$GITCODE/third_party_bounds_checking_function.git" third_party/bounds_checking_function
clone_shallow "$GITCODE/third_party_FatFs.git"           third_party/FatFs
clone_shallow "$GITCODE/third_party_littlefs.git"        third_party/littlefs
clone_shallow "$GITCODE/third_party_lwip.git"            third_party/lwip
clone_shallow "$GITCODE/third_party_cmsis.git"           third_party/cmsis
clone_shallow "$GITCODE/third_party_optimized_routines.git" third_party/optimized-routines
clone_shallow "$GITCODE/productdefine_common.git"        productdefine/common
clone_shallow "$GITCODE/commonlibrary_utils_lite.git"    commonlibrary/utils_lite
clone_shallow "$GITCODE/developtools_integration_verification.git" developtools/integration_verification
clone_shallow "$GITEE/vendor_ohemu.git"                  vendor/ohemu
clone_shallow "$GITEE/device_qemu.git"                   device/qemu

echo "==> [2/6] applying build-adapt patches"
for f in kernel/liteos_m/config.gni kernel/liteos_m/BUILD.gn \
         device/qemu/arm_mps3_an547/liteos_m/config.gni \
         device/qemu/arm_mps3_an547/liteos_m/board/BUILD.gn; do
  git -C "$(dirname "$f")" apply "$ROOT/patches/0001-liteos-m-build-adapt.patch" \
    --include="$(basename "$f")" 2>/dev/null || true
done
# Product-level adapts (config.json / debug.config) applied directly:
cp "$ROOT/overlays/config.json" vendor/ohemu/$PRODUCT/config.json
cat vendor/ohemu/$PRODUCT/kernel_configs/debug.config \
    "$ROOT/overlays/lms.config" > /tmp/dbg.config.$$
mv /tmp/dbg.config.$$ vendor/ohemu/$PRODUCT/kernel_configs/debug.config

echo "==> [3/6] root .gn / BUILD.gn (kernel-only)"
printf 'buildconfig = "//build/config/BUILDCONFIG.gn"\n' > .gn
cat > BUILD.gn <<'EOF'
group("default") {
  deps = [ "//kernel/liteos_m:kernel" ]
}
EOF

echo "==> [4/6] hb config"
mkdir -p out
cat > out/ohos_config.json <<EOF
{
  "board": "$BOARD",
  "kernel": "liteos_m",
  "product": "$PRODUCT",
  "product_path": "$SRC/vendor/ohemu/$PRODUCT",
  "device_path": "$SRC/device/qemu/$BOARD/liteos_m",
  "device_company": "qemu",
  "version": "3.0",
  "os_level": "mini",
  "patch_cache": "",
  "product_json": "$SRC/vendor/ohemu/$PRODUCT/config.json",
  "device_config_path": "//device/qemu/$BOARD/liteos_m",
  "subsystem_config_json": "build/subsystem_config.json",
  "out_path": "$SRC/out/$BOARD/$PRODUCT"
}
EOF

echo "==> [5/6] gn gen + ninja"
OUT="$SRC/out/$BOARD/$PRODUCT"
GN_ARGS="product_name=\"$PRODUCT\" is_mini_system=true \
product_path=\"//vendor/ohemu/$PRODUCT\" \
product_config_path=\"//vendor/ohemu/$PRODUCT\" \
device_name=\"$BOARD\" \
device_path=\"//device/qemu/$BOARD/liteos_m\" \
device_company=\"qemu\" \
device_config_path=\"//device/qemu/$BOARD/liteos_m\" \
ohos_kernel_type=\"liteos_m\" \
ohos_build_compiler_specified=\"gcc\" \
liteos_kernel_only=true"

gn gen --script-executable="$(command -v python3)" \
       --args="$GN_ARGS" "$OUT"
ninja -C "$OUT" liteos

echo "==> [6/6] stage artifacts (incl. toolchain for the docker build)"
mkdir -p "$ROOT/images/tools"
cp "$OUT/obj/kernel/liteos_m/bin/liteos" "$ROOT/images/OHOS_Image"
cp -r "$SRC" "$ROOT/images/src-tree"
# Toolchain: gn/ninja from PATH; arm-none-eabi-gcc tree so the docker build
# needs no network downloads.
cp "$(command -v gn)" "$ROOT/images/tools/gn"
cp "$(command -v ninja)" "$ROOT/images/tools/ninja"
ARM_GCC_BIN="$(command -v arm-none-eabi-gcc)"
ARM_GCC_DIR="$(dirname "$(dirname "$ARM_GCC_BIN")")"
rm -rf "$ROOT/images/tools/arm-none-eabi"
cp -r "$ARM_GCC_DIR" "$ROOT/images/tools/arm-none-eabi"
echo "==> done. kernel: images/OHOS_Image  source: images/src-tree  tools: images/tools"
