# LiteOS-M 靶标制作全记录（迁移复现指南）

> 目标：让 vuln-pipeline 能对 **OpenHarmony LiteOS-M**（华为自研 MCU RTOS，非 Linux）做
> 自动化漏洞挖掘。检测器用内核自带的 **LMS（Lite Memory Sanitizer）**，运行环境 QEMU
> Cortex-M55（`mps3-an547`）。
>
> 验证日期：2026-08-15。本指南记录每一步实际执行过的命令、版本号、报错与解法，
> 全部可复现。

---

## 1. 背景：为什么是 LiteOS-M

OpenHarmony 是多内核架构：

| 内核 | 定位 | 代码量 | 漏洞挖掘价值 |
|---|---|---|---|
| Linux 5.10/6.6 | 标准系统（富设备） | 上游内核 | 低——挖到的多为上游已知 CVE 的 backport 缺口（如 CVE-2026-23398） |
| LiteOS-A | 小型系统（Cortex-A） | ~93K 行 | 中——但 QEMU 板级配置（vendor_ohemu）停更于 3.1，构建依赖更重 |
| **LiteOS-M** | 轻量系统（MCU） | **~52K 行** | **高——华为自研、无上游 CVE 库、体量小、QEMU 板级在 Kconfig 中自包含** |
| UniProton | 实时系统 | — | QEMU 支持弱，放弃 |

LiteOS-M 关键事实（2026-08-15 验证）：

- 内核 master：`32beca78be1fd2a23c8b275a6c5853fa38dbd67f`（2026-06-22）
- 自带 **LMS**（`components/lms/`）：shadow-memory 堆检查器（2 bits/4 bytes），
  检测 heap buffer overflow / use-after-free / double-free，且实现了 `__asan_storeN`
  等编译器插桩接口——即官方支持的用法是"模块级 `-fsanitize=kernel-address` 插桩"，
  与 Linux KASAN 同源思路
- 官方自带 fuzz 测试框架（`testsuites/unittest/fuzz/`）——华为自己就用这套测
- QEMU 板级：`qemu_arm_virt_cm7/cm4/cm55`、`riscv32_virt`、`csky`、`xtensa`

## 2. 总体构建链路

```
15 个 git 仓库（浅克隆） ──> 标准 OHOS 目录布局 ──> 5 处适配 patch
      │                                              │
      │                                              v
      │                                   gn gen（// 路径参数）+ ninja
      │                                              │
      │                              ┌───────────────┴───────────────┐
      │                              v                               v
      │                       LMS 运行时开启（debug.config）   模块级 kasan 插桩
      │                              └───────────────┬───────────────┘
      │                                              v
      │                                     OHOS_Image（ELF）
      │                                              │
      │                                              v
      │                    qemu-system-arm -M mps3-an547 -semihosting -kernel
      │                                              │
      │                                              v
      │                        LMS 报告 / HardFault ──> harness/lms.py ──> find/grade
      v
  Docker 镜像（syzbot base + qemu-system-arm + gn/ninja + arm-none-eabi-gcc
              + 完整源码树 + rebuild.sh + opencode CLI）
```

**关键设计决策**：LiteOS-M 是裸机 RTOS，没有用户态——PoC 无法"传进去执行"，
必须**编译进镜像**。因此 find-agent 的工作循环是：

```
读源码 → 改 board/test/test_demo.c（已插桩模块）→ ./rebuild.sh → QEMU 跑 → 抓 LMS 报告
```

（与官方 `testsuites/sample/kernel/lms` 的模块级插桩模式完全一致。）

---

## 3. 工具链安装（本机，逐条可执行）

| 工具 | 版本 | 安装方式 | 备注 |
|---|---|---|---|
| repo | 2.65 | `curl -fsSL https://mirrors.tuna.tsinghua.edu.cn/git/git-repo -o ~/bin/repo && chmod +x` | 最终未使用（不需要全量 manifest） |
| hb | ohos-build 1.0.0 | `pip install --break-system-packages --user build/hb`（在源码树内、从 build 仓库源码装） | PyPI 的 `ohos-build 0.4.6` 过旧且 `--version` 报错；**从 build 仓库装**才是新版。hb 实际只用了 `hb set -p <product>` 一步生成配置 |
| gn | 2222 (3c7785ec2008) | `https://github.com/timniederhausen/gn/releases/download/2024.12/gn-linux-amd64.tar.gz` 解压到 `~/bin/gn` | google CIPD 与 gn.googlesource 均不可达 |
| ninja | 1.13.0 | `pip install --break-system-packages --user ninja` | |
| kconfiglib | 14.1.0 | `pip install --break-system-packages kconfiglib` | gn 的 kconfig exec_script 需要 |
| arm-none-eabi-gcc | **15.2.1**（xPack） | `xpack-arm-none-eabi-gcc-15.2.1-1.1-linux-x64.tar.gz`（292MB），解压到 `~/tools/`，`bin/` 加入 PATH | **下载坑见 §11-6**：GitHub 直连中断，用镜像 `https://ghfast.top/<原 github url>` 成功 |
| qemu-system-arm | 系统自带 | apt 包 | 板级 README 要求 QEMU ≥ 6.2（MVE 支持） |

> 为什么用 gcc 15 而不是官方 README 指定的 gcc 10：gcc 10 需从 ARM 官网登录下载；
> gcc 15 会带来一批"warning 升级为 error"问题，但均可通过编译选项压制（见 §5.3）。

---

## 4. 最小源码树组装（不需要拉整个 OpenHarmony）

**结论先行：不需要 repo 全量 sync（~100GB）。** LiteOS-M GN 构建的外部引用只有
以下 15 个仓库（全部浅克隆，合计 ~160MB）：

| # | 仓库 | 来源 | 布局路径 | 作用 |
|---|---|---|---|---|
| 1 | `build` | gitcode | `build/` | GN 构建脚本（`//build/lite/run_shell_cmd.py`、`lite_component.gni`）、hb 工具 |
| 2 | `kernel_liteos_m` | gitcode | `kernel/liteos_m/` | **内核本体** |
| 3 | `drivers_hdf_core` | gitcode | `drivers/hdf_core/` | HDF 框架（`group("modules")` 无条件引用 `HDFTOPDIR`） |
| 4 | `third_party_musl` | gitcode | `third_party/musl/` | libc |
| 5 | `third_party_bounds_checking_function` | gitcode | `third_party/bounds_checking_function/` | 安全函数库 |
| 6 | `third_party_FatFs` | gitcode | `third_party/FatFs/` | FAT 文件系统 |
| 7 | `third_party_littlefs` | gitcode | `third_party/littlefs/` | littlefs |
| 8 | `third_party_lwip` | gitcode | `third_party/lwip/` | lwIP |
| 9 | `third_party_cmsis` | gitcode | `third_party/cmsis/` | CMSIS 头 |
| 10 | `third_party_optimized_routines` | gitcode | `third_party/optimized-routines/` | musl 依赖（**注意仓库名是下划线**，目录是连字符） |
| 11 | `productdefine_common` | gitcode | `productdefine/common/` | 产品定义（hb preloader 校验路径） |
| 12 | `commonlibrary_utils_lite` | gitcode | `commonlibrary/utils_lite/` | 板级引用 `//commonlibrary/utils_lite/include` |
| 13 | `developtools_integration_verification` | gitcode | `developtools/integration_verification/` | BUILDCONFIG.gn 读 NAPI 白名单 |
| 14 | `vendor_ohemu` | **gitee** | `vendor/ohemu/` | QEMU 板级产品配置（`qemu_cm55_mini_system_demo`） |
| 15 | `device_qemu` | **gitee** | `device/qemu/` | 板级 BSP（`arm_mps3_an547/liteos_m`，含 `target_config.h`、链接脚本） |

- 仓库 URL 前缀：`https://gitcode.com/openharmony/`、`https://gitee.com/openharmony/`
- 板级产品名：`qemu_cm55_mini_system_demo`；板级：`arm_mps3_an547`（Cortex-M55，ARM MPS3 AN547 FPGA 板）
- ⚠️ Gitee 上这些仓库**均已"关闭"**（OpenHarmony 开发迁移至 GitCode），但
  `vendor_ohemu`/`device_qemu` 在 gitee 仍可克隆且 master 是活跃内容（gitcode 的
  device_qemu 缺 liteos_m 板级，**必须用 gitee 的**）
- 注意：`gitcode` 的 `productdefine` 仓库不存在（404），正确名字是 **`productdefine_common`**

## 5. 构建适配 patch（5+1 处，逐条解释原因）

源码树组装后**不能直接构建**，需要以下适配（`targets/liteos-m/build_liteos_m.sh`
内嵌 python 替换实现；原 unified diff 存于 `patches/0001-liteos-m-build-adapt.patch`）：

### 5.1 `kernel/liteos_m/config.gni`：`liteos_kernel_only` 可被 gn args 覆盖
```gni
# 原：liteos_kernel_only = false
declare_args() {
  liteos_kernel_only = false
}
```
**原因**：`BUILD.gn:207` 有 `if (liteos_kernel_only) { deps=[":kernel"] } else { deps=["//build/lite:ohos"] }`。
不开 kernel_only 会拉入整个 OHOS 组件图（hievent_lite 等大量缺失仓库），必须走 kernel-only。

### 5.2 `kernel/liteos_m/BUILD.gn`：板级检测硬编码
```gni
# 原：exec_script 用 shell 检查 $device_path/BUILD.gn 是否存在
HAVE_DEVICE_SDK = true
# 原：按 device_path 是否含 /vendor/、/board/ 判定 decouple
BOARD_SOC_FEATURE = false
```
**原因**：该 shell 检查只在 device_path 为绝对路径时成立；而我们 gn args 必须用
`//` 相对路径（见 §6），两者冲突。device_qemu 是 board+soc 合一仓库，不走
decouple 分支（否则会引用不存在的 `//device/board/qemu`）。

### 5.3 `device/qemu/arm_mps3_an547/liteos_m/config.gni`：gcc-15 兼容
```gni
board_cflags += [
  "-Wno-error=implicit-function-declaration",   # gcc14+ 默认 -Werror
  "-Wno-error=implicit-int",
  "-Wno-error=int-conversion",
  "-Wno-error=incompatible-pointer-types",
]
board_ld_flags += [
  "-Wl,--defsym=__exidx_start=0",   # gcc15 libgcc unwind-arm.o 引用了
  "-Wl,--defsym=__exidx_end=0",     # 链接脚本未定义的 EABI 异常索引符号
]
```
**原因**：LiteOS-M 官方用 gcc 10 编译（README 指定 10-2020-q4-major）；gcc 14/15
把 implicit-function-declaration、int-conversion 等升级为 error，且 libgcc 的
unwind 实现变化引入 `__exidx_start/end` 未定义符号。

### 5.4 `device/qemu/arm_mps3_an547/liteos_m/board/BUILD.gn`：模块级插桩
```gni
kernel_module(module_name) {
  asmflags = board_asmflags
  cflags = [ "-fsanitize=kernel-address", "-O0" ]   # 新增
  ...
}
```
**原因**：这是 LMS 的官方用法（对照 `testsuites/sample/kernel/lms/BUILD.gn`）。
**全局插桩不可行**（实测：`Entering scheduler` 后立即 HardFault
"Lockup: can't escalate 3 to HardFault"——启动路径/上下文切换被插桩破坏；
`--param=asan-stack=0 --param=asan-globals=0` 也救不回）。
所以：**内核核心不插桩，只有 agent 写 PoC 的板级模块插桩**。

### 5.5 `vendor/ohemu/qemu_cm55_mini_system_demo/config.json`：只留 kernel 组件
subsystems 精简为 `kernel:liteos_m`。
**原因**：原始配置含 hievent_lite/samgr_lite/kv_store 等 8 个组件，hb loader 会
逐个校验组件存在（`find component hievent_lite failed`）。kernel-only 构建用不到。

### 5.6 `vendor/ohemu/.../kernel_configs/debug.config`：开 LMS
```
LOSCFG_KERNEL_LMS=y
LOSCFG_LMS_CHECK_STRICT=y
```
依赖的 `DEBUG_VERSION`/`KERNEL_EXTKERNEL`/`KERNEL_BACKTRACE` 已默认开启。

### 5.7 根目录文件（源码树内创建，不在任何仓库）
```
# .gn
buildconfig = "//build/config/BUILDCONFIG.gn"
# BUILD.gn
group("default") { deps = [ "//kernel/liteos_m:kernel" ] }
```
**原因**：gn 需要根 `.gn` 定位 source root；根 BUILD.gn 只引用 kernel target。

---

## 6. gn gen + ninja（完整参数，必须用 `//` 路径）

```bash
OUT=$SRC/out/arm_mps3_an547/qemu_cm55_mini_system_demo
gn gen --script-executable="$(command -v python3)" \
  --args='product_name="qemu_cm55_mini_system_demo" is_mini_system=true \
product_path="//vendor/ohemu/qemu_cm55_mini_system_demo" \
product_config_path="//vendor/ohemu/qemu_cm55_mini_system_demo" \
device_name="arm_mps3_an547" \
device_path="//device/qemu/arm_mps3_an547/liteos_m" \
device_company="qemu" \
device_config_path="//device/qemu/arm_mps3_an547/liteos_m" \
ohos_kernel_type="liteos_m" \
ohos_build_compiler_specified="gcc" \
liteos_kernel_only=true' "$OUT"
ninja -C "$OUT" liteos
```

### 关键坑：绝对路径 vs `//` 路径
- `BUILDCONFIG.gn` 里 `import("${device_config_path}/config.gni")` 要求 **`//` 形式**
- hb 写进 `ohos_config.json` 的是**绝对路径**——官方用 OHOS 定制 gn（prebuilts 里，
  gitcode/gitee 均 403 拉不到）支持绝对路径 import，**上游 gn 2222 不支持**
- 解法：`hb set -p` 生成配置后，把 `ohos_config.json` 的路径字段手工改成 `//` 形式；
  而 §5.2 的 patch 同时解决 kernel BUILD.gn 的 shell 检查——两处配合才走得通

### preloader 产物（hb 本应生成，手工补两份）
`BUILDCONFIG.gn:129/132` 读取：
```
out/preloader/qemu_cm55_mini_system_demo/build_config.json   # 产品元数据
out/preloader/qemu_cm55_mini_system_demo/parts_config.json   # {"kernel_liteos_m": true}
```
不跑 hb 时这两个文件不存在，必须由构建脚本生成（内容模板见 `build_liteos_m.sh`）。

### hb 工具的实际使用范围
仅一步：`hb set -p qemu_cm55_mini_system_demo`（在源码树根、含 `out/ohos_config.json`）。
- `hb set`（无参数）走交互菜单，非 TTY 会 `assert stdout.isatty()` 崩溃 → 必须用 `-p`
- `hb build` 因路径/gn 兼容问题不能直接用，gn gen 全部手工执行

### 编译产物
```
out/arm_mps3_an547/qemu_cm55_mini_system_demo/obj/kernel/liteos_m/bin/liteos        # stripped ELF（~100KB）
out/arm_mps3_an547/qemu_cm55_mini_system_demo/obj/kernel/liteos_m/unstripped/bin/liteos
```
链接警告 `LOAD segment with RWX permissions` 无害（官方即如此）。

---

## 7. QEMU 运行

```bash
qemu-system-arm -M mps3-an547 -nographic -semihosting \
  -kernel out/arm_mps3_an547/qemu_cm55_mini_system_demo/obj/kernel/liteos_m/bin/liteos
```

正常启动输出：
```
entering kernel init...
Timer with period zero, disabling
Entering scheduler
OHOS # TaskSampleEntry1 running...
TaskSampleEntry2 running...
```
（`OHOS #` 是 shell 提示符；两个 sample 任务是板级 demo，也是 agent 注入 PoC 的位置。）

## 8. LMS 检测机制与验证方法

### 机制
- 堆内存（`LOS_MemAlloc`/`LOS_MemFree` 系列）由 LMS shadow memory 跟踪；
  状态：`ACCESSIBLE / REDZONE(0xAA) / AFTERFREE(0xFF) / PAINT`
- **只有被 `-fsanitize=kernel-address` 插桩的代码**的堆访问才会触发 shadow 检查
  （调用 `__asan_storeN`/`__asan_loadN`，实现在 `components/lms/los_lms.c`）
- 违规时经串口打印完整报告：

```
[ERR][TaskSampleEntry1]*****  Kernel Address Sanitizer Error Detected Start *****
[ERR][TaskSampleEntry1]Use after free error detected          # 或 Heap buffer overflow / Illegal Double free
[ERR][TaskSampleEntry1]Illegal WRITE address at: [0x2102ecbc]
[ERR][TaskSampleEntry1]Shadow memory address: [0x211e4acb : 6]  Shadow memory value: [3]
psp, start = 2102db90, end = 2102dc80
taskName = TaskSampleEntry1
taskID   = 3
----- traceback start -----
traceback 0 -- lr = 0x2100966a
traceback 1 -- lr = 0x2100fbf2
----- traceback end -----
[LMS] Dump info around address [0x2102ecbc]: ...
```
- 未插桩路径的崩溃 → QEMU HardFault dump（`qemu: fatal: Lockup ... R13/R14`）

### 验证方法（已实测通过）
1. 在 `board/test/test_demo.c` 的 `TaskSampleEntry1` 注入：
   ```c
   char *buf = LOS_MemAlloc(m_aucSysMem0, 32);
   buf[40] = 'X';   /* heap OOB */
   ```
2. `ninja -C $OUT liteos` 重编 + QEMU 跑 → 上述 LMS 报告（实测得到
   "Use after free error detected / Illegal WRITE"）

## 9. 管线框架适配（vuln-pipeline 侧）

| 文件 | 改动 |
|---|---|
| `harness/lms.py` | **新增**。LMS 崩溃解析器，与 `kasan.py` 同接口：`looks_like_lms` / `project_frames`（traceback lr 行）/ `top_frame` / `crash_reason`（UAF/堆溢出/双重释放 + READ/WRITE）/ `lms_excerpt` |
| `harness/asan.py` | 新增 `_looks_like_lms` 分发；四个函数（project_frames/top_frame/crash_reason/asan_excerpt）在 KASAN 委托前先试 LMS（LMS 标记与 KASAN/用户态 ASAN 输出不相交，嗅探无歧义） |
| `harness/prompts/find_prompt.py` | 新增 `LITEOS_M_FIND_TEMPLATE`（`detector == "lms"` 分支）：教 agent 改 `test_demo.c` → `./rebuild.sh` → QEMU 跑 → 判读 LMS 报告，3/3 复现后提交 `repro.sh` + XML tags |
| `harness/config.py` | detector 注释补 "lms" |
| `tests/test_asan.py` | +2 个 LMS 委托单测 |

**关键设计**：LMS 报告的 `crash_type` 直接取报告类名（如
`Heap-buffer-overflow-error-detected`），dedup/judge/found_bugs 全链路复用
现有机制，无需改判重逻辑。

## 10. Docker 镜像

```dockerfile
FROM cybergym/syzbot-target:09b7d050e4806540153d     # 本地已有（docker.io 被墙）
RUN apt-get update && apt-get install -y ca-certificates curl xxd gdb git \
        python3 python3-pip qemu-system-arm && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && npm install -g opencode-ai@1.17.18 && ...
COPY images/tools/gn /usr/local/bin/gn              # build_liteos_m.sh stage 的
COPY images/tools/ninja /usr/local/bin/ninja        # 工具链（docker build 全程离线）
COPY images/tools/arm-none-eabi /opt/arm-none-eabi
COPY images/src-tree /src                            # 完整源码树 + out/
COPY images/OHOS_Image /src/OHOS_Image
COPY rebuild.sh /src/rebuild.sh
ENV PATH="/opt/arm-none-eabi/bin:/usr/local/bin:$PATH"
RUN pip3 install kconfiglib
```

- 构建命令：`VULN_PIPELINE_DOCKER_BUILD_NETWORK=host docker build --network=host -t vuln-pipeline-liteos-m:latest .`
- ⚠️ 不能 `FROM ubuntu:22.04`（docker.io 被墙）；base 必须是本地已有的镜像
- 工具链由 `build_liteos_m.sh` stage 到 `images/tools/`（含 arm-none-eabi 完整目录
  ~1.3GB），Dockerfile 只需 COPY，构建无需外网下载大文件

## 11. 踩坑记录（按时间序，全部实测）

1. **Gitee 仓库"关闭"**：`openharmony/kernel_liteos_{a,m,5.10}` 在 Gitee 均显示
   `status: 关闭`，master 停更于 2025-09。开发已迁 GitCode；但
   `vendor_ohemu`/`device_qemu` 的可用内容仍在 gitee。
2. **仓库名易错**：`productdefine`（404）→ 正确 `productdefine_common`；
   `third_party_optimized-routines`（403）→ 正确 `third_party_optimized_routines`
   （下划线），而它在源码树里的目录名是连字符 `optimized-routines`。
3. **`--filter=blob:none` 浅克隆陷阱**：部分克隆的 blob 按需拉取，gn 读文件时
   不会触发 git 的 blob fetch → "Could not read file" 假象。克隆依赖仓库时
   **不要带 `--filter=blob:none`**（或事后 `git checkout HEAD -- .` 强制拉齐）。
4. **hb 版本**：PyPI `ohos-build` 已过时；必须 `pip install build/hb`（源码装），
   装完 `hb --version` 报 "no such option" 是正常的（新版无该选项），
   `hb set -p <product>` 才是正确用法。
5. **gn 来源**：OHOS 定制 gn 在 `prebuilts` 大仓库（403）；Google CIPD 不可达；
   可用的是 github `timniederhausen/gn` release 2024.12（2222）。差异点：
   不支持绝对路径 import → gn args 必须全用 `//` 形式。
6. **arm-none-eabi-gcc 下载**：GitHub 直连 ~5MB 即断（HTTP/2 INTERNAL_ERROR）；
   `gh-proxy.com` 403、`mirror.ghproxy.com` 连接失败；**`ghfast.top` 可用**
   （URL 形如 `https://ghfast.top/https://github.com/...`，292MB 约 4 分钟）。
7. **gcc 15 vs gcc 10**：见 §5.3。三类错误逐个出现：implicit-function-declaration
   → int-conversion → `__exidx_start/end` 未定义，逐一压制/defsym 解决。
8. **全局 `-fsanitize=kernel-address` 插桩会杀死内核**：scheduler 启动后立即
   HardFault（优先级 -1 锁死）。只能模块级插桩（官方 sample 同款）。
   实测确认：**板级模块插桩 + 内核核心不插桩**可正常启动且能检测堆越界。
9. **`hb set` 交互 TTY**：无参数/无 `-p` 会弹 prompt_toolkit 菜单，
   非交互环境直接 `assert stdout.isatty()` 崩溃。
10. **preloader 产物缺失**：不跑 `hb build` 就没有
    `out/preloader/<product>/{build_config,parts_config}.json`，
    而 `BUILDCONFIG.gn` 无条件读取 → 构建脚本需手工生成（模板见 §6）。
11. **误提交 292MB tarball**：`git reset --soft` + 重提交 + 
    `git reflog expire --expire=now --all && git gc --prune=now --aggressive`
    才能把 `.git` 从 296MB 压回 1.8MB。
12. **Docker Hub 被墙**：`FROM ubuntu:22.04` 拉不动（auth.docker.io 拒绝连接）。
    改用本地已有 base 镜像（本项目 `cybergym/syzbot-target:09b7d050e4806540153d`）。

## 12. 完整复现步骤（从零开始）

```bash
# 0) 前置
#    - git、python3、docker
#    - gn + ninja 在 PATH（§3）
#    - arm-none-eabi-gcc 在 PATH（§3，注意 gcc 15 + §5.3 patch）
cd <repo>/targets/liteos-m

# 1) 构建源码树 + 内核（~10 分钟，产出 images/）
./build_liteos_m.sh

# 2) 构建 agent 镜像
VULN_PIPELINE_DOCKER_BUILD_NETWORK=host docker build --network=host \
  -t vuln-pipeline-liteos-m:latest .

# 3) 冒烟验证（镜像内）
docker run --rm vuln-pipeline-liteos-m:latest sh -c \
  'cd /src && timeout 15 qemu-system-arm -M mps3-an547 -nographic \
   -semihosting -kernel OHOS_Image'
# 期望看到 "Entering scheduler" + "OHOS #"

# 4) 跑管线
VULN_PIPELINE_DOCKER_BUILD_NETWORK=host .venv/bin/vuln-pipeline run \
  targets/liteos-m --dangerously-no-sandbox \
  --model deepseek/deepseek-v4-flash --max-turns 200 --runs 20
```

### 验证清单（迁移到新机器后逐项核对）

- [ ] `arm-none-eabi-gcc --version` = 15.2.1（或 gcc 10，则 §5.3 的 flag 可留可去）
- [ ] `gn --version` 能跑；gn args 全为 `//` 形式
- [ ] 构建日志 `Done. Made 82 targets from 108 files`（数量随版本漂移属正常）
- [ ] `config.h` 含 `#define LOSCFG_KERNEL_LMS 1`
- [ ] QEMU 输出 `Entering scheduler` + `OHOS #`
- [ ] 注入 OOB 后输出 `Kernel Address Sanitizer Error Detected`（§8 验证法）
- [ ] `pytest tests/test_asan.py` 含 `test_lms_*` 用例通过

---

## 附录：版本与提交锚点

| 项 | 值 |
|---|---|
| kernel_liteos_m | master `32beca78be1fd2a23c8b275a6c5853fa38dbd67f`（2026-06-22） |
| vendor_ohemu / device_qemu | gitee master（2026-08-15 克隆） |
| arm-none-eabi-gcc | xpack 15.2.1-1.1 |
| gn / ninja | 2222 / 1.13.0 |
| kconfiglib | 14.1.0 |
| 靶标代码 | git 分支 `feature/LiteOS-A` |
| 20 轮验证 | `--max-turns 200 --runs 20`，日志 `/tmp/liteos_m_run.log` |
