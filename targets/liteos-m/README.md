# OpenHarmony LiteOS-M kernel hunt target

Hunt memory-safety bugs in the **OpenHarmony LiteOS-M kernel** — Huawei's
own MCU RTOS (~52K lines of C, no upstream CVE database) — using its built-in
**LMS (Lite Memory Sanitizer)** in QEMU (Cortex-M55 `mps3-an547`).

Unlike the Linux-kernel targets (`ohos6-kernel*`), every heap OOB / UAF found
here is a genuine OpenHarmony-native bug, not a known-Linux-CVE backport gap.

## Layout

| File | Purpose |
|---|---|
| `build_liteos_m.sh` | host-side: assemble a MINIMAL OpenHarmony-style source tree (~15 repos, no repo sync), apply adapt patches, build the LMS-enabled kernel, stage image + tools |
| `patches/0001-liteos-m-build-adapt.patch` | build-adapt diffs for kernel `config.gni`/`BUILD.gn` + board configs (gcc-15 compat, device-SDK hardcode, exidx defsym) |
| `overlays/config.json` | kernel-only product config (non-kernel subsystems stripped) |
| `overlays/lms.config` | `LOSCFG_KERNEL_LMS=y` + strict checks, appended to the board debug config |
| `Dockerfile` | agent image: QEMU + gn/ninja + arm-none-eabi-gcc + source tree + rebuild wrapper + opencode |
| `rebuild.sh` | in-image rebuild (gn gen + ninja) the find agent runs after editing the PoC module |
| `config.yaml` | pipeline config: `detector: lms`, QEMU boot recipe, attack surface, grade reference |

## Build the target image

```sh
cd targets/liteos-m
./build_liteos_m.sh        # ~10 min incl. clones; needs git/gn/ninja/arm-none-eabi-gcc
VULN_PIPELINE_DOCKER_BUILD_NETWORK=host docker build --network=host \
  -t vuln-pipeline-liteos-m:latest .
```

## Run the hunt

```sh
vuln-pipeline run targets/liteos-m --dangerously-no-sandbox \
  --model deepseek/deepseek-v4-flash --max-turns 500 --runs 20
```

## How detection works

- The kernel is built with `LOSCFG_KERNEL_LMS=y` (shadow-memory heap checker).
- The board module (`device/qemu/arm_mps3_an547/liteos_m/board`) is compiled
  with `-fsanitize=kernel-address` — the find agent injects its PoC into
  `board/test/test_demo.c` and that code's heap accesses are shadow-checked
  (same scoping as the official `testsuites/sample/kernel/lms` sample).
- A violation prints `Kernel Address Sanitizer Error Detected` with class
  (`Use after free` / `Heap buffer overflow` / `Illegal Double free`),
  illegal address, shadow value, task, and `lr` traceback — parsed by
  `harness/lms.py` (detector `lms`), feeding dedup/judge/found_bugs as usual.

## Verified (2026-08-15)

- kernel_liteos_m master `32beca78be1fd2a23c8b275a6c5853fa38dbd67f`
- arm-none-eabi-gcc 15.2.1, gn 2222, ninja 1.13
- QEMU boots to `Entering scheduler` + shell; an injected OOB write produces
  a full LMS report with traceback.
