# 动态验证插桩与对照实验工作计划

## 1. 目标与边界

当前 `find` 已经拆成静态分析和动态验证两个子阶段，但动态 agent 主要依赖
自己的源码理解、编译和运行结果来判断候选位点是否真的可达。这个计划为动态
验证增加一个可选的观测层：对目标构建物进行插桩，收集输入实际触及的函数、
源码位置、边和比较操作，并以统一格式反馈给动态 agent。

插桩是“帮助理解执行路径”的观测能力，不是新的漏洞检测器。最终的目标仍是
生成可复制的 PoC，原有 `grade` 仍然在干净的目标环境中独立复现 PoC，并继续
作为最终裁判。静态候选、插桩反馈和动态 agent 的判断都不能直接替代 grade。

本阶段不改变 `judge`、`report`、`patch`，也不把插桩信息写入
`found_bugs.jsonl` 作为已确认漏洞。

## 2. 目标流程

```text
固定源码 commit
    ↓
静态分析 agent
    ↓ StaticFinding
动态验证 agent
    ├─ 复核静态候选
    ├─ 选择/请求观测点
    ├─ 在临时副本中构建插桩版本
    ├─ 执行探针和候选 PoC
    └─ 消费统一 ExecutionFeedback
    ↓
干净目标上的 PoC
    ↓
原有 grade（最终验收）
```

动态阶段同时保留两个概念：

- `clean`：未经插桩的目标，作为最终 PoC 的真实性基线；
- `observed`：由 provider 生成的临时插桩目标，只用于快速判断路径和收集证据。

插桩版本的成功只说明“输入触及了某些代码”，不说明漏洞成立；插桩版本失败
也不能自动证明静态候选是误报，因为插桩可能改变时序、内存布局、构建选项或
服务行为。提交前必须回到 clean 目标重放，并由 grade 再次判断。

## 3. 通用插桩接口

### 3.1 与 detector 解耦

`detector` 表达什么结果算漏洞，例如 `asan`、`ubsan`、`logic`；
`instrumentation` 表达如何观察执行，例如 `llvm`、未来的 Java agent、Go
coverage、QEMU trace 或网络代理。两者不能互相替代：逻辑漏洞即使没有 ASAN
报告，也可以使用 LLVM coverage 证明路径到达，再使用语义 oracle 验证结果。
未显式指定时使用 `auto`，自动选择目标声明或 harness 注册的可用 provider；用户
可以通过 `--instrumentation off` 或目标 manifest 中的 `default: off` 明确关闭。

### 3.2 Provider 职责

每个 provider 实现稳定的生命周期，而不把 provider 的原始工具输出直接塞进
prompt。对 harness 暴露的最小接口是 `prepare` 和 `collect`；其中 `prepare`
内部完成探测和初始化，`collect` 内部完成原始数据读取、归一化和摘要。具体
职责是：

1. `detect`：检查当前镜像是否有可用工具和必要的运行时能力；
2. `prepare`：创建临时工作目录、构建说明、环境变量和报告入口；
3. `build_instrumented`：根据静态候选和 agent 的选择生成插桩构建；
4. `record`：在一次输入执行前后采集原始反馈；
5. `normalize`：转成统一的 `ExecutionFeedback`；
6. `summarize`：生成面向 agent 的短摘要，同时保留完整原始事件；
7. `cleanup`：清理临时过程和 profile 文件。

其中第 3 项明确由动态 agent 执行，provider 不假设 CMake、Make 或某一种语言，
这样后续 provider 才能覆盖 Go、Rust、Java、QEMU 和服务型目标。

provider 只在动态 agent 容器内工作，不访问宿主机 Docker socket，也不修改发布
的 clean image。构建与执行失败要区分为“工具不可用”“插桩构建失败”“目标
执行失败”和“目标自身返回非零”。

### 3.3 统一反馈格式

建议使用 JSONL 事件加 JSON 汇总：

```json
{
  "schema_version": 1,
  "provider": "llvm",
  "run_id": "run-003",
  "input_sha256": "...",
  "status": "completed",
  "exit_code": 0,
  "duration_ms": 42,
  "reached_functions": ["xmlXIncludeProcessFlags", "xmlXIncludeLoadTxt"],
  "reached_locations": [
    {"file": "xinclude.c", "line": 1458, "function": "xmlXIncludeLoadTxt"}
  ],
  "edges": [],
  "branches": [],
  "comparisons": [],
  "stdout": "...bounded...",
  "stderr": "...bounded...",
  "errors": [],
  "raw_artifacts": ["runs/003.profraw"]
}
```

最低要求是 `provider`、`status`、输入摘要、退出状态、到达函数/位置和错误
信息。函数/位置证明可达性，不能证明 root cause；`branches`、`comparisons` 和
`edges` 是可选能力，缺失时必须显式标记而不是伪造空证据。

agent 只需要面对 provider 无关的命令/文件契约，例如：

```text
/work/instrumentation/README.md
/work/instrumentation/provider.json
/work/instrumentation/run <label> -- <target command>
/work/instrumentation/report/summary.json
/work/instrumentation/report/events.jsonl
```

如果 provider 不可用，动态阶段仍可在 clean 目标上继续工作，并在上下文中明确
说明“无观测反馈”，不能把它当作动态验证失败。

## 4. Agent 交互设计

静态报告作为不可信但有边界的输入传递给动态 agent。动态 agent 必须：

1. 以当前源码 commit 重新检查候选的位置、调用链和外部入口；
2. 从静态报告中选择需要观察的函数/文件，而不是盲目插桩整个仓库；
3. 通过 provider 提供的接口构建 observed 版本；
4. 先运行低成本可达性探针，再运行候选 PoC；
5. 读取 `summary.json`/`events.jsonl`，把到达证据和语义/ASAN oracle 分开；
6. 在 observed 版本得到候选 PoC 后，用完全相同的 PoC 在 clean 版本复核；
7. 只有 clean 复核成功，才输出现有 PoC XML 标签。

agent 可以决定“观察哪些点”和“怎样组织构建”，但实际的 provider 能力、输出
路径、事件格式和最大资源消耗由 harness 控制。禁止让模型把任意宿主机命令或
未经记录的自定义 trace 当成正式插桩证据。

## 5. LLVM 第一版实验

第一版只支持 C/C++ process target，并使用 Clang 的 source-based coverage：

```text
-g -fprofile-instr-generate -fcoverage-mapping
LLVM_PROFILE_FILE=/work/instrumentation/runs/%p-%m.profraw
```

它适合快速回答“函数/源码区域是否被输入触及”，不需要依赖 ASAN，也不会把
LLVM 的原始 profile 格式暴露给 agent。provider 在镜像内发现 `clang`、
`llvm-profdata` 和 `llvm-cov` 后，使用 `llvm-cov export` 生成统一函数/位置
数据；工具版本或架构不匹配时报告明确错误。

对 libxml2 的首个候选，静态报告可能指向：

```text
xmlXIncludeProcessFlags
  → xmlXIncludeLoadTxt
  → xmlParserInputBufferRead
  → xmlBufUse
  → xmlNodeAddContentLen
```

实验中的 observed 构建应覆盖 `/work/entry` 和实际链接到它的 libxml2 代码，
不能只给 entry harness 插桩，否则会把“进入 harness”误报成“进入漏洞位点”。

## 6. A/B 对照实验

实验问题是：插桩反馈是否显著缩短动态阶段从候选到可用 PoC 的时间，而不是插桩
构建本身是否更快。

### 6.1 固定变量

- 同一个仓库 commit、Docker 基础镜像和 clean build artifact；
- 同一份 `StaticFinding`；
- 同一个模型、prompt、max turns、资源限制和网络条件；
- 同一个动态 agent 初始上下文；
- 同一组控制输入、触发输入和运行次数。

只改变是否启用 instrumentation provider。每个条件至少 5 次独立重复；如果
模型调用成本允许，优先 10 次，并报告中位数、P95 和成功率。

### 6.2 记录指标

分别记录：

- provider 检测、插桩构建和 profile 解析的额外时间；
- agent 首次运行目标的时间；
- 首次获得正确可达性证据的时间；
- 首次形成候选 PoC 的时间；
- clean 重放成功时间和 grade 通过时间；
- agent turns、工具调用数、编译次数、目标运行次数；
- `not_reached`、`reached_no_effect`、环境失败和 grade 失败数量。

主指标是 `dynamic_start → clean PoC ready` 和 `dynamic_start → grade passed`。
插桩准备/构建时间单独列出，避免把基础设施成本与 agent 推导效率混为一谈。

### 6.3 结果目录

```text
results/<target>/<batch>/run_NNN/
  static_analysis.json
  dynamic_validation.json
  instrumentation/
    manifest.json
    summary.json
    events.jsonl
    build.log
    runs/
  clean_replay.json
  result.json
```

`events.jsonl` 可以详细，`summary.json` 必须有大小上限；stdout、stderr、源码
路径和模型输出都要截断，避免一次异常运行撑爆 transcript 或 prompt。

## 7. 安全、可恢复性和兼容性

- 插桩构建只发生在动态阶段的临时容器/工作树中，clean image 不被覆盖；
- provider 输出按路径白名单读取，不能通过路径穿越把宿主文件带入结果目录；
- 单次 build、单次 run、profile 解析和总观测次数均有超时/数量上限；
- 动态 agent 中断后，至少保留 static、instrumentation 和 dynamic transcript；
- 没有 provider 或目标不支持插桩时自动降级到当前 clean 动态流程；
- 旧 target/config、旧 `CrashArtifact`/`LogicArtifact` 和原 grade 协议保持兼容；
- 插桩的候选、版本、编译参数和 provider 能力写入 manifest，保证结果可复现；
- grade 永远从 clean image 创建新 session，不消费 agent 修改后的插桩文件或二进制。

## 8. 实施顺序

### P0：接口和持久化

- 新增 instrumentation 数据类、provider registry 和统一 schema 校验；
- 新增结果目录写入、大小限制、事件截断和 provider 缺失状态；
- 为静态候选增加可选的观测目标信息，保持旧 JSON 可读。

### P1：动态 agent 接入

- 在动态 prompt 中声明插桩接口、临时 observed/clean 边界和失败语义；
- 在 `run_dynamic_validation` 中创建 provider session，向 agent 注入说明；
- 解析并保存反馈摘要，但不把反馈直接当作 PoC 或 grade 结论。

### P2：LLVM provider

- 实现 Clang coverage 构建环境探测、profile 收集和 `llvm-cov` 归一化；
- 提供 `/work/instrumentation/run` 和报告文件接口；
- 在 libxml2 上验证目标函数位置能被观测到，并覆盖逻辑漏洞路径。

### P3：clean 回放与 grade 边界

- 明确 observed PoC 到 clean image 的文件/命令迁移规则；
- 动态阶段成功后强制 clean replay，再进入现有 grade；
- grade 只增加必要的上下文，不改变最终 PoC 验收职责。

### P4：A/B 基准和扩展点

- 固化 libxml2 A/B runner 和实验 manifest；
- 运行至少 5 次/条件，输出时间分布和失败分类；
- 预留 Java agent、Go coverage、Rust instrumentation、QEMU trace 等 provider，
  但不提前把语言写进核心流程。

当前可直接使用的独立入口是：

```bash
# 只运行源码静态分析，生成结果目录中的 static_analysis.json
.venv/bin/vuln-pipeline static libxml2 --model deepseek-flash \
  --dangerously-no-sandbox

# 使用同一份静态报告运行动态 agent；不在此命令中调用 grade
.venv/bin/vuln-pipeline dynamic libxml2 \
  --static-report results/libxml2/<timestamp>/static_analysis.json \
  --model deepseek-flash --instrumentation off \
  --dangerously-no-sandbox

# 只改变观测条件即可进行对照；两次输出目录中的 timings、transcript 和
# dynamic_validation.json 用于记录耗时、agent 工具调用数、首次 PoC 标签时间和最终状态。
.venv/bin/vuln-pipeline dynamic libxml2 \
  --static-report results/libxml2/<timestamp>/static_analysis.json \
  --model deepseek-flash --instrumentation llvm \
  --dangerously-no-sandbox
```

`dynamic` 的结果仍需交给原有 `run` 的 grade 边界（或后续等价的 grade 调度）
进行最终验收；本命令不会把 observed 版本的成功直接标记为漏洞。

## 9. 验收标准

1. 全部现有单元测试通过；
2. provider 无法使用时，旧动态流程仍能运行；
3. provider 输出可被 schema 解析，恶意路径/超大输出/非法状态会被拒绝或截断；
4. 一个带静态候选的动态 agent 能读取统一反馈并在结果目录留下可审计证据；
5. observed 版本产生的 PoC 必须由原有 grade 在 clean image 的新 session 中重新
   验证，才能成为通过结果；本次实现不新增独立的 grade 替代路径；
6. libxml2 的 LLVM 实验能够区分控制输入和候选输入的到达路径；
7. A/B 报告同时包含“到达/PoC/grade”成功率和时间，而不只报告插桩覆盖率；
8. grade、judge、report、patch 的职责和旧 artifact 兼容性没有回归。
