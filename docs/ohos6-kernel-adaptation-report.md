# 工作汇报：OpenHarmony 6.0 内核漏洞挖掘目标适配

- **日期**：2026-08-11
- **范围**：将本仓库的自动漏洞挖掘流水线（vuln-pipeline）从「用户态 C/C++ 二进制 ASAN 检测」扩展适配为「Linux 内核 KASAN 检测」，并以 OpenHarmony 6.0 内核（kernel_linux_5.10，Linux 5.10.210）为第一个内核挖掘目标。
- **结论**：流水线骨架零改动，通过「配置驱动 + 检测器可插拔 + 各环节指令内核化」完成适配；KASAN 内核已成功编译并引导，20 轮冒烟测试进行中。

---

## 一、背景与目标

仓库原有流水线针对**用户态 C/C++ 目标**：agent 在容器内直接执行 ASAN 编译的二进制、制造畸形输入、观察崩溃输出。本次目标是将同一套 find → grade → judge → report → patch 流水线复用到 **Linux 内核**上：

| 维度 | 用户态（原版） | 内核（本次） |
|---|---|---|
| 检测器 | AddressSanitizer（用户态） | KASAN（内核） |
| 运行方式 | 直接执行目标二进制 | QEMU/KVM 引导内核，guest 内执行 PoC |
| 崩溃输出 | `ERROR: AddressSanitizer ...` | `BUG: KASAN ...` / 内核 oops / panic + Call Trace |
| 验证方式 | 重新运行二进制 | 重新引导全新 QEMU 虚拟机 |

**硬约束**：不重写流水线骨架，复用原有数据契约（`found_bugs.jsonl`、`manifest.jsonl`、`result.json`、`reports/bug_NN/`）。

---

## 二、总体思路

不改流水线主流程，改动收敛在四个层面：

1. **检测层可插拔** —— 新增内核崩溃解析器，与用户态解析器共用同一接口，下游（去重、判定、报告）无感知。
2. **运行环境参数化** —— 容器支持透传 `/dev/kvm`、host 网络、镜像内置 agent CLI，通过 `config.yaml` 声明。
3. **各环节指令内核化** —— find/grade 的 agent 指令模板分别新增内核版本，教 agent 如何引导虚拟机、传输并运行 PoC、判读内核崩溃。
4. **目标侧独立成靶** —— 新增 `targets/ohos6-kernel/` 目标目录（Dockerfile、内核构建脚本、KASAN 兼容补丁、配置），不触碰管线代码。

---

## 三、流水线适配改动（对照 7 步）

### 0. 横切层（每一步都受影响）

| 改动内容 | 涉及文件 | 说明 |
|---|---|---|
| 新增内核崩溃解析器 `kasan.py`（KASAN 报告 / oops / panic / 内核 Call Trace 解析） | `harness/kasan.py`（新增） | 接口与 `asan.py` 完全对齐 |
| `asan.py` 四入口（project_frames / top_frame / crash_reason / asan_excerpt）加内核嗅探，自动委托 | `harness/asan.py` | 内核与用户态崩溃输出互斥（`BUG: KASAN`/`RIP:`/`Kernel panic` 标识），嗅探无歧义 |
| `TargetConfig` 新增字段：`detector`、`devices`、`agent_prebuilt`、`agent_network`、`grade_reference`、`build_command`/`test_command` | `harness/config.py` | 全部由 `config.yaml` 驱动 |
| 容器运行：`--device /dev/kvm` 透传、`network=host` 覆盖、docker build 网络参数 | `harness/docker_ops.py`、`harness/sandbox.py` | 适配 loopback 代理 + KVM 加速 |
| agent 后端切换为 opencode CLI（可接 DeepSeek 等任意 provider），支持 `agent_prebuilt` 镜像 | `harness/agent_image.py` | `BASE_TAG` + 每目标 `COPY --from` 分层 |
| 系统提示词补充 native function calling 协议说明 | `harness/prompts/system_prompt.py` | 适配 opencode 后端 |
| 术语中性化：「ASAN excerpt」→「Crash excerpt」、untrusted 提示改为 "a binary or a kernel" | `harness/prompts/judge_prompt.py` | 兼容内核崩溃 |

### ① Build —— 从「构建 ASAN 二进制」到「构建 KASAN 内核镜像」

- **原版**：目标 Dockerfile 编译用户态 ASAN 二进制打进镜像。
- **改动**：目标 Dockerfile 改为构建内核镜像——替换 `/kernel/bzImage`、COPY OHOS 源码至 `/src/linux`、上游源码至 `/src/upstream`、安装 node20 + opencode CLI；新增 `build_kernel.sh` 从固定 commit 编译 KASAN 内核；构建侧支持 `--network=host`（`VULN_PIPELINE_DOCKER_BUILD_NETWORK`）。

### ② Recon（可选）—— 无逻辑改动

- 仅容器启动参数透传（`/dev/kvm` + host 网络 + prebuilt），agent 直接读镜像内源码。

### ③ Find —— 核心变化：从「跑二进制」到「引导内核」

- **原版**：读源码 → 造输入 → 跑 ASAN 二进制 → 3/3 复现 → 提交崩溃输入。
- **改动**：`find_prompt.py` 新增 `KERNEL_FIND_TEMPLATE`：QEMU/KVM 引导命令、串口 unix socket + base64 分块传输 PoC 进 guest、guest 内编译运行、抓取串口输出判读 `BUG: KASAN`/`RIP:`/`Kernel panic`。
- **保留**：崩溃提交格式（`<poc_path>` + `<dup_check>`）与 3/3 复现要求不变。
- **本次会话修复**：移除模板中硬编码的「kernel 6.12」误导描述，改为按 attack_surface 描述实际内核版本。

### ④ Grade —— 每次引导全新虚拟机验证

- **原版**：新容器重跑 PoC。
- **改动**：`grade_prompt.py` 新增 `KERNEL_GRADE_PROMPT_TEMPLATE`：grader 每次 boot **全新** QEMU 虚拟机跑 reproducer 脚本；新增 `grade_reference`（官方崩溃签名，**仅 grade 可见，find 永远看不到**）作为根因判定的对照基准。

### ⑤ Judge —— 无逻辑改动

- 内核崩溃经 `kasan.py` 归一化为与 ASAN 相同的 excerpt 格式，judge 的语义去重照常工作；仅 prompt 术语泛化。

### ⑥ Report —— 无逻辑改动

- 容器透传 `/dev/kvm`/host 网络/prebuilt，报告 agent 可在容器内自行复跑验证；攻击面文本注入沿用。

### ⑦ Patch —— 无 kernel 特定逻辑改动

- T0 重建 → T1 PoC 不崩 → T2 测试套件 → T3 重攻击的验证阶梯原样保留；`config.yaml` 新增 `build_command`/`test_command` 字段支撑内核重建。

---

## 四、新增目标：`targets/ohos6-kernel/`

| 文件 | 说明 |
|---|---|
| `config.yaml` | `detector: kasan`、`devices: [/dev/kvm]`、`agent_prebuilt: true`、`agent_network: host`、HUNT 模式（无预置 CVE，任意内核 KASAN/oops/panic 入 scope） |
| `Dockerfile` | 基于 syzbot QEMU 基础镜像，换 bzImage、COPY 源码、装 opencode |
| `build_kernel.sh` | 固定 commit 拉取 OHOS `kernel_linux_5.10`（Linux 5.10.210），打 KASAN 兼容补丁，开启 KASAN + 命名空间（nsjail 必需），产出 bzImage |
| `patches/0001-kasan-addr_has_shadow-compat.patch` | 桥接 5.10.210 稳定版 `addr_has_shadow`→`addr_has_metadata` 改名遗漏，使 KASAN 构建通过 |
| `README.md` / `.gitignore` | 构建/运行指引、忽略大文件 |

**内核事实（已核实）**：OHOS 6.0 标准系统内核 = `kernel_linux_5.10` @ OpenHarmony-6.0-Release，即 Linux 5.10.210（gitee commit `0461994cd...`）；另有 6.6 分支。

---

## 五、关键技术问题与解决

| # | 问题 | 根因 | 解决 |
|---|---|---|---|
| 1 | `make olddefconfig` 找不到编译器 | OHOS 顶层 Makefile 硬编码 `ccache gcc`，宿主机无 ccache | 命令行 `TC_OVERRIDES` 覆盖工具链变量 |
| 2 | KASAN 构建报 `addr_has_shadow` 隐式声明 | 5.10.210 稳定版改名 `addr_has_metadata` 但调用点未同步 | 新增兼容补丁桥接（并修正幂等性检测避免重复应用） |
| 3 | `-Werror=strict-prototypes` 构建失败 | OHOS 驱动为 C90 风格声明，gcc13 比 OHOS 的 gcc11 更严格 | `KCFLAGS_EXTRA` 仅放宽风格类告警，保留内存安全相关 `-Werror` |
| 4 | 镜像构建 apt 拉不到包 | 裸 `docker build` 走桥接网络，loopback 代理不可达 | `docker build --network=host`（pipeline 侧用 `VULN_PIPELINE_DOCKER_BUILD_NETWORK=host`） |
| 5 | 内核引导 panic（`Attempted to kill init!`） | OHOS 配置未开 `CONFIG_NAMESPACES`，guest 的 nsjail 无法工作 | 开启命名空间/容器相关配置，验证引导至 `user@exphost` |
| 6 | 上游源码下载过慢 | cdn.kernel.org 约 13KB/s | 切换 TUNA 镜像（约 11MB/s，10 秒），并烤入镜像免重复下载 |
| 7 | 磁盘 100% 占满 | Docker 构建缓存累积 18.9GB | 清理构建缓存，释放约 20GB |

---

## 六、验证情况

| 验证项 | 结果 |
|---|---|
| 内核编译（KASAN 开启） | ✅ 通过，产出 bzImage（Linux 5.10.210，25MB） |
| 内核引导 | ✅ QEMU/KVM 引导至 guest 提示符 `user@exphost`（nsjail 正常） |
| 上游源码烘焙 | ✅ `/src/upstream` 已入镜像（SUBLEVEL=210 已验证），find agent 免下载 |
| 流水线冒烟测试 | 🔄 进行中：20 轮 × 100 turns，Run 1 的 find agent 已 50+ 次工具调用，尚无崩溃（探索阶段，符合预期） |

---

## 七、当前状态与后续计划

**当前**：20 轮冒烟测试运行中（结果目录 `results/ohos6-kernel/20260811T145440Z/`，测试日志 `/tmp/ohos6_run.log`）。首轮聚焦验证「镜像构建 → find agent 探索源码 → QEMU 引导 → 崩溃提交」整条链路是否正常。

**后续计划**：
1. 观察 20 轮测试完成情况，确认 find/grade/judge/report 全链路无崩溃；
2. 评估首个真实内核漏洞发现（HUNT 模式，无预置 CVE）；
3. 如需针对特定子系统（如 HDF 驱动、具体 CVE 复现），再收窄 `focus_areas` / 切换 CVE 验证模式；
4. 视测试结果决定是否升级为 `--parallel` 并发挖掘。
