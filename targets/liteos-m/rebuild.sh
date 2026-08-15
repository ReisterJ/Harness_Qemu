#!/bin/bash
# Rebuild the LiteOS-M kernel after editing sources (used by the find agent).
# Runs inside the agent image where /src is the assembled build tree and
# gn/ninja/arm-none-eabi-gcc are on PATH.
set -euo pipefail

cd /src
OUT=/src/out/arm_mps3_an547/qemu_cm55_mini_system_demo

gn gen --script-executable="$(command -v python3)" \
  --args='product_name="qemu_cm55_mini_system_demo" is_mini_system=true product_path="//vendor/ohemu/qemu_cm55_mini_system_demo" product_config_path="//vendor/ohemu/qemu_cm55_mini_system_demo" device_name="arm_mps3_an547" device_path="//device/qemu/arm_mps3_an547/liteos_m" device_company="qemu" device_config_path="//device/qemu/arm_mps3_an547/liteos_m" ohos_kernel_type="liteos_m" ohos_build_compiler_specified="gcc" liteos_kernel_only=true' \
  "$OUT"

ninja -C "$OUT" liteos
cp "$OUT/obj/kernel/liteos_m/bin/liteos" /src/OHOS_Image
echo "rebuild done: /src/OHOS_Image"
