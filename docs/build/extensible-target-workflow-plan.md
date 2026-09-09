# 可扩展目标构建与运行工作计划

## 1. 背景

当前目标构建流程已经可以从仓库生成 `Dockerfile`、`config.yaml` 和入口程序，
并支持后续的 target-agent 镜像构建。但当前设计仍然把目标类型近似为
`cli`、`library`、`kernel`，并且 find、dynamic validation、grade 默认目标是一个
可以执行的 `/work/entry`。

这个模型无法自然覆盖 Java、Go、Rust、Python、Web 服务和需要在 QEMU 中运行的
Linux kernel。继续增加语言枚举会让构建器和后续工作流不断出现目标特例。

本计划的目标是让 agent 在获得仓库后先判断项目的构建方式、运行方式和验证方式，
再生成一个标准化目标契约。平台只实现通用运行时适配器，不按具体语言写死流程。

## 2. 目标和边界

### 2.1 目标

1. 新增语言或构建系统时，不需要修改核心 find、dynamic validation、grade 代码。
2. agent 能从源码、文档和 CI 配置中判断目标属于哪一种运行形态。
3. C/C++ 库、Java、Go、Rust、Python CLI 可以使用同一个进程运行时。
4. Web 服务可以通过服务运行时启动、健康检查、发送请求、重置和采集日志。
5. Linux kernel、固件等目标可以通过 QEMU 运行时启动 guest，并通过串口、SSH
   或 guest 内控制程序交互。
6. 静态分析、动态验证和 grade 继续分离；最终结论仍然只由 grade 对 PoC 的
   独立复现决定。
7. 不依赖 Claude Code 的 `customize` 流程，使用现有 opencode agent 和结构化
   输出协议。

### 2.2 非目标

- 不在本阶段重新设计漏洞判断标准或 grade 的评分逻辑。
- 不让 agent 访问宿主机 Docker socket。
- 不让 agent 通过自然语言直接改变宿主机的网络、设备和权限配置。
- 不为每一种编程语言维护一套独立的核心流水线。

## 3. 核心设计

### 3.1 按运行形态而不是按语言分类

语言、版本、构建系统和编译器由 agent 判断并写入构建方案；平台只根据运行
形态选择适配器：

| 运行形态 | 覆盖范围 | 典型交互 |
| --- | --- | --- |
| `process` | CLI、库 consumer、Java/Go/Rust/Python 程序 | 启动进程、传入文件或命令行、读取退出码和日志 |
| `service` | HTTP、HTTPS、gRPC、TCP 等服务 | 启动服务、健康检查、发送请求、重置状态、采集日志 |
| `qemu` | Linux kernel、嵌入式系统、固件 | 启动 guest、执行 guest 命令、读取串口或 SSH、重启 guest |
| `custom` | 无法由上述契约表达的环境 | 通过 runtime plugin 扩展 |

因此，libpng 虽然是 C 库，但构建 agent 可以生成 consumer harness，最终使用
`process` 运行时；Java、Go、Rust 和 Python CLI 也不需要新的核心类型。

### 3.2 Target Manifest

构建 agent 除了生成 Dockerfile 和兼容用的 `config.yaml`，还必须生成
`target-manifest.yaml`。manifest 是后续 agent 和 runtime adapter 的唯一正式契约。

最小结构如下：

```yaml
schema_version: 1

identity:
  name: example
  repository: https://example.invalid/project.git
  commit: <locked-commit>

build:
  base_image: ubuntu:24.04
  language: c
  build_system: cmake
  build_steps: []
  generated_files: []

runtime:
  profile: process
  source_root: /work/src
  artifact:
    kind: executable
    path: /work/entry
  start:
    command: /work/entry
  capabilities:
    - file_input
    - stdout
    - stderr
    - exit_code

detection:
  detectors:
    - asan
    - ubsan
  crash_signals:
    - sanitizer_report
    - nonzero_exit

workflow:
  static_analysis: source
  dynamic_validation: process
  grade: process_replay

resources:
  memory: 4g
  devices: []
```

manifest 中的命令必须指向容器内部路径。宿主机只执行固定的 runtime adapter，
不能执行 agent 输出的宿主机命令。

### 3.3 Contract 脚本

对于无法用单条命令表达生命周期的目标，构建 agent 在 `/work/contract/` 下生成
以下脚本：

```text
/work/contract/start
/work/contract/ready
/work/contract/exec
/work/contract/reset
/work/contract/stop
/work/contract/replay
/work/contract/collect
```

例如 Web 服务需要 `start`、`ready`、`reset` 和 `collect`；QEMU 目标需要
`start`、`ready`、`exec`、`reset` 和 `collect`。脚本运行在隔离的 target-agent
容器内，不能写入宿主机路径。

## 4. 端到端工作流

```text
仓库
  ↓
分类 agent：判断构建方式、运行形态、检测器和验证方案
  ↓
方案 agent：生成 Dockerfile、manifest、config 和 contract
  ↓
宿主机 docker build
  ↓ 失败
修复 agent：读取源码、当前产物和 build.log
  ↓
运行契约验收
  ↓
构建 target-agent 镜像
  ↓
静态分析 → 动态验证 → grade
```

### 阶段 A：源码分类

分类 agent 只读仓库和项目文档，重点检查：

- README、INSTALL、BUILDING、SECURITY、CI workflow 和 package manifest；
- 使用的语言、版本和构建系统；
- CLI、库、服务、kernel 或固件等运行形态；
- 外部输入入口和可达路径；
- 是否需要 consumer harness、rootfs、QEMU、KVM 或额外设备；
- 可以使用的 sanitizer、运行时检测器和 crash oracle；
- 动态验证和 grade 所需的重置方式。

分类结果必须通过 JSON/YAML schema 校验，并保存到构建 job 目录。agent 可以
报告多个候选方案和置信度，但不能用自然语言代替结构化结论。

### 阶段 B：构建方案生成

方案 agent 根据分类结果和源码生成：

- `Dockerfile`；
- `target-manifest.yaml`；
- 兼容现有流程的 `config.yaml`；
- consumer harness、启动脚本、健康检查脚本和其他 `support/` 文件；
- `build-plan.json`。

没有自然入口的库必须生成独立的 consumer harness，不能修改上游源码来制造
入口。如果项目无法产生可靠的运行契约，agent 应报告 blocker，不能伪造一个
看似可运行的 `/work/entry`。

### 阶段 C：宿主机 Docker 构建

宿主机负责：

1. 克隆并锁定指定分支的最新 commit，或固定指定的 tag/commit；
2. 将源码快照放入 Docker build context；
3. 校验 Dockerfile 必须使用锁定的 `source/`；
4. 执行 Docker build 并保存完整日志；
5. 构建失败时调用 repair agent；
6. 限制修复次数和单次构建时间。

repair agent 可以修改 Dockerfile、manifest、config 和 contract，但不能修改
源码快照，也不能直接访问 Docker daemon。

### 阶段 D：运行契约验收

构建成功后由宿主机启动一个全新的 target-agent session：

- `process`：检查 artifact 存在、可执行、最小输入可以启动并返回预期状态；
- `service`：启动服务、执行 ready 检查、发送最小请求、采集响应和日志、重置；
- `qemu`：启动 QEMU、等待 guest ready、执行最小 guest 命令、采集串口、重启；
- `custom`：加载对应 plugin 并执行 plugin 的验收方法。

只有 Docker build 和运行契约验收都成功，才发布 `targets/<name>/`。

## 5. 运行时适配器

新增 `harness/runtimes/`：

```text
harness/runtimes/
  base.py
  process.py
  service.py
  qemu.py
  registry.py
```

每个 adapter 至少提供：

```text
create_session()
start()
ready()
execute()
reset()
collect_logs()
replay_poc()
stop()
```

`custom` 通过稳定的 Python plugin protocol 注册，不修改 find、dynamic validation
和 grade 的主流程。新语言只要能生成已有 profile 的 manifest，就不需要新增
adapter。

## 6. find、dynamic validation 和 grade 改造

### 6.1 静态分析

静态 agent 只读取源码、文档和 manifest 中的攻击面信息，输出候选位点、外部
入口、调用链、到达条件和验证计划。静态结果不是最终 finding，也不能直接进入
grade。

### 6.2 动态验证

动态 agent 使用 manifest 对应的 runtime adapter：

- `process`：运行程序并传入文件、参数或环境变量；
- `service`：启动服务并发送请求或协议消息；
- `qemu`：启动 guest，执行 syscall、ioctl、测试程序或网络操作；
- 无法从外部入口到达时，输出 `not_reached`；环境无法运行时，输出
  `environment_blocked`。

只有动态阶段生成了真实、非空且可复制的 PoC，才允许进入 grade。

### 6.3 Grade

grade 仍然是最终裁判，不信任静态或动态阶段的结论：

1. 创建全新的 runtime session；
2. 部署干净目标；
3. 重新执行 PoC；
4. 检查 sanitizer、服务响应、QEMU 日志或其他 manifest 声明的 oracle；
5. 判断复现稳定性和根因是否匹配。

最终关系保持为：

```text
静态分析：提出候选
动态验证：尝试形成 PoC
grade：独立确认 PoC
```

### 6.4 PoC Artifact 扩展

当前 `CrashArtifact` 假设 PoC 是单个输入文件，需要扩展为通用 artifact：

```yaml
poc:
  kind: file | command | request | program | bundle
  files: []
  reproduction_command: ...
  environment: {}
```

兼容关系如下：

- CLI、库 consumer：`file`；
- Web 服务：`request` 或 `command`；
- Linux kernel：`program`，可包含源码、编译产物和运行命令；
- 多组件服务：`bundle`。

grade 仍然围绕 PoC 复现，不会把静态报告当作最终漏洞结论。

## 7. CLI 设计

正常情况下用户不需要指定语言或目标类型：

```bash
secrun build libpng \
  --repo https://github.com/pnggroup/libpng.git \
  --model deepseek/deepseek-v4-flash
```

原有 `--kind` 可以暂时保留，但降级为可选提示或调试约束，不应成为正常使用
的必选参数。构建成功后仍使用原始流程：

```bash
secrun run libpng --model deepseek/deepseek-v4-flash
```

建议增加：

```bash
secrun inspect <name-or-repo> --model <model>
```

用于只执行分类阶段，输出 agent 判断的构建和运行方案，方便用户在正式构建前
检查结果。

## 8. 兼容策略

1. 现有 `config.yaml` 继续可加载，旧 target 自动转换为 legacy manifest。
2. `binary_path`、`detector`、`agent_prebuilt` 等字段在兼容层保留。
3. 新 target 以 manifest 为准，`config.yaml` 只作为旧模块的投影。
4. 现有 `find → grade` 调用接口保持不变，内部改为通过 runtime adapter 执行。
5. 现有 `CrashArtifact` 可以继续反序列化，新字段使用兼容默认值。

## 9. 实施阶段

### P0：契约和 schema

- 定义 manifest、classification、runtime contract 和 PoC artifact schema；
- 明确允许的路径、设备、网络和命令范围；
- 增加 schema parser、版本检查和错误提示；
- 为旧 `TargetConfig` 增加 legacy manifest 转换。

### P1：构建流程改造

- 将当前 `kind` 改为 agent 分类结果；
- build prompt 增加分类和 manifest 输出要求；
- build/repair 流程支持 contract 文件；
- 增加 process、service、qemu 的构建验收；
- 保留 Dockerfile、commit、source snapshot 和 build log 的现有审计信息。

### P2：runtime adapter

- 实现 `process` adapter；
- 实现 `service` adapter，包括健康检查、端口和状态重置；
- 实现 `qemu` adapter，包括 KVM、串口、guest 命令和重启；
- 建立 custom plugin registry。

### P3：find 和 grade 接入

- 将 prompts 中的固定 `/work/entry` 改为读取 runtime contract；
- 静态 agent 使用 manifest 描述的源码和入口；
- 动态 agent 使用 runtime adapter；
- grade 使用全新 session 重放通用 PoC；
- 保证最终 grade 仍然是唯一确认边界。

### P4：PoC 和结果目录

- 扩展 `CrashArtifact` 为通用 PoC artifact；
- 保存 classification、manifest、runtime logs、PoC bundle 和 grade evidence；
- 保持旧结果目录可以被 dedup、report 和 patch 读取。

### P5：测试矩阵和文档

- 建立不依赖核心代码分支的 `tests/e2e/target_matrix.yaml`；
- 覆盖 flex、libpng、Java CLI、Go CLI/service、Rust CLI、Python service 和
  Linux kernel/QEMU；
- 每个测试只声明仓库、ref、预期 profile 和最小验收条件；
- 增加构建失败修复、服务重置、QEMU 重启和 grade 重放测试；
- 更新 CLI、构建流程、runtime adapter 和目标编写文档。

## 10. 验收标准

实现完成后应满足：

1. 对 flex 和 libpng，不指定 `--kind` 也能正确分类并生成可用 target。
2. 对 Java、Go、Rust、Python CLI，核心代码无需增加语言分支。
3. 对 Web 服务，agent 能生成启动、ready、reset 和 replay contract。
4. 对 Linux kernel，agent 能生成 QEMU manifest，完成启动和最小 guest 交互。
5. 动态验证无法到达静态位点时，结果明确标记为非验证成功，不生成 grade 输入。
6. grade 在全新 session 中独立重放 PoC，并继续作为最终结论来源。
7. 新增一个属于已有 profile 的语言时，只需要测试 manifest 和 Dockerfile，不需要
   修改流水线核心代码。
8. 新增一种全新运行环境时，只需要实现 runtime plugin，不需要复制整套 find/grade
   流程。
