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

## Detection coverage — read before reporting

LMS here is a **heap-only** checker with **module-level instrumentation**
(the official LiteOS-M pattern — whole-kernel `-fsanitize=kernel-address`
faults at boot). Practical consequences:

- **What is detected:** heap lifetime bugs (UAF / double-free / heap OOB)
  that are touched through (a) LMS-instrumented code (the board module the
  PoC lives in) or (b) the LMS-wrapped libc entry points (`memcpy`,
  `memcpy_s`, `memset`, `malloc`/`free`, ...) that kernel paths call.
  All findings to date have been `memcpy`-family UAFs — this is the
  instrumented surface, not a property of the kernel.
- **What is *not* detected:** stack overflows, global-buffer overflows,
  writes from uninstrumented kernel code that bypass libc (direct pointer
  dereferences, `memmove` variants not wrapped, asm copies), and use of
  uninitialized memory. **Absence of a report is not absence of a bug.**
- **Build flags:** board/test modules are compiled `-O0` (instrumentation
  fidelity), kernel core `-Os`. The lifetime defects this target finds are
  optimization-independent; this does not affect validity of findings.
- **Environment:** bare-metal QEMU (`mps3-an547`), no user/kernel split —
  PoCs run as kernel tasks by design, which is the MCU threat model.

## Verified (2026-08-15)

- kernel_liteos_m master `32beca78be1fd2a23c8b275a6c5853fa38dbd67f`
- arm-none-eabi-gcc 15.2.1, gn 2222, ninja 1.13
- QEMU boots to `Entering scheduler` + shell; an injected OOB write produces
  a full LMS report with traceback.
