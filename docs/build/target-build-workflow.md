# Target 构建工作流计划

本文规划一个面向原始 `find → dynamic validation → grade` 工作流的 target
构建入口。它的目标不是建立一套独立的通用应用镜像系统，而是从一个开源仓库
生成原始挖掘流程能够直接使用的 `Dockerfile`、`config.yaml` 和必要的入口驱动。

## 1. 目标与边界

新增一个构建命令：

```bash
bin/vp-sandboxed build <name> \
  --repo <url> \
  [--branch <branch>] \
  [--ref <tag-or-commit>] \
  --model <model> \
  [--kind auto|cli|library|kernel]
```

构建成功后，用户可以直接执行现有挖掘流程：

```bash
bin/vp-sandboxed run <name> --model <model>
```

本功能不重新实现 find、dynamic validation、grade、judge 或 report，也不把
完整漏洞验证逻辑复制到构建阶段。

构建阶段只负责：

1. 获取并锁定源码；
2. 生成符合 target contract 的文件；
3. 构建 target image；
4. 准备后续 agent 所需的 target-agent image；
5. 做最小结构检查；
6. 发布可供原始工作流使用的 target。

## 2. 工作流

```text
获取并锁定源码
        ↓
构建规划 agent 生成 Dockerfile/config/entry
        ↓
宿主机执行 docker build
        ↓
失败时将 build.log 交给修复 agent
        ↓
重新构建
        ↓
生成 target-agent image
        ↓
最小结构检查
        ↓
发布 targets/<name>/
        ↓
使用原始 run/find/grade 流程
```

规划 agent 不直接访问 Docker daemon。Docker build 由宿主机调度；agent 与
Docker build 之间通过任务目录、构建日志和结构化输出衔接。

## 3. 源码锁定

每个新建构建任务都要查询远程仓库并记录源码身份：

```json
{
  "repo": "https://example.com/project.git",
  "branch": "main",
  "ref": null,
  "commit": "0123456789abcdef...",
  "snapshot_sha256": "..."
}
```

分支模式使用指定分支的最新 commit；`--ref` 用于固定 tag 或 commit。源码先
物化为干净快照，Dockerfile 使用：

```dockerfile
COPY source/ /work/src/
```

不允许 Dockerfile 在构建时重新 clone 仓库，以避免构建输入与锁定的 commit
不一致。

## 4. 构建规划 agent

规划 agent 使用通用 agent 基础镜像，以只读方式查看源码和文档，生成：

```text
Dockerfile
config.yaml
entry.c / entry.cpp / support/*
```

规划内容至少包括：

- 构建系统和基础镜像；
- 系统依赖；
- 源码路径；
- 构建命令；
- `binary_path`；
- `source_root`；
- `detector`；
- 是否使用 `agent_prebuilt`；
- 是否需要 `/dev/kvm`；
- 是否需要生成入口驱动。

agent 不修改上游源码，也不直接执行 Docker build。

## 5. 入口驱动约定

原始 find 和 grade 主要围绕一个可执行入口和输入文件工作。因此，对于没有
自然 CLI 的项目，构建阶段应生成统一入口，而不是修改后续流程。

### CLI 项目

直接把项目程序作为：

```yaml
binary_path: /work/entry
```

### C/C++ 库

生成一个 consumer harness，例如 `entry.c`，调用库的公开 API，并编译为：

```text
/work/entry
```

后续 agent 仍然可以使用：

```bash
/work/entry /tmp/input.bin
```

### Rust 库

生成一个 Rust consumer binary，最终放在 `/work/entry`。

### Linux kernel

Linux kernel 不强行伪造普通 CLI 入口，使用：

```yaml
agent_prebuilt: true
detector: kasan
devices:
  - /dev/kvm
```

由 target Dockerfile 自己准备 kernel、rootfs、QEMU、opencode 和启动脚本。

## 6. Docker build 与失败修复

规划结果通过校验后，宿主机创建独立构建上下文并执行：

```bash
docker build -t vuln-pipeline/<name>:<commit-short> <context>
```

构建失败时，宿主机保存完整 `build.log`，再启动修复 agent。修复 agent 读取：

- 源码快照；
- 当前 Dockerfile；
- 当前 `config.yaml`；
- entry/support 文件；
- build.log 和错误摘要。

修复 agent 只能修改构建相关文件，不能修改源码快照。默认允许有限次重试：

```text
规划 → build → 失败日志 → 修复 → build retry
```

## 7. target-agent 镜像

target image 构建完成后，使用现有 `agent_image.ensure()` 生成后续挖掘使用的
组合镜像：

```text
agent 基础环境 + target image 中的 /work
```

普通 target 必须把后续 agent 需要的文件放在 `/work` 下，例如：

```text
/work/entry
/work/src
/work/include
/work/lib
/work/testdata
```

复杂目标可以使用 `agent_prebuilt: true`，由 target Dockerfile 自己生成完整
的 agent 镜像。

## 8. 构建阶段的最小检查

构建阶段不重复执行完整 PoC 动态验证，只检查 target 是否满足原始工作流的
基本接口：

1. Dockerfile 构建成功；
2. `config.yaml` 可以被 `TargetConfig.load()` 解析；
3. 镜像存在且 commit 信息一致；
4. `source_root` 存在；
5. 普通 target 的 `binary_path` 存在；
6. 普通 target 可以生成 target-agent image；
7. `agent_prebuilt` target 可以直接作为 agent image 使用。

真正的编译产物交互、PoC 生成和动态验证仍由后续 find 流程中的 agent 完成。

## 9. 发布与恢复

任务先写入临时目录：

```text
results/builds/<name>/<job-id>/
├── source/
├── context/
├── planner.log
├── build.log
├── status.json
└── build.json
```

只有构建成功并通过最小检查后，才发布到：

```text
targets/<name>/
├── Dockerfile
├── config.yaml
├── entry.c
├── support/
├── source/
├── source.lock.yaml
└── build.json
```

当前实现使用以下入口启动构建：

```bash
bin/vp-sandboxed build <name> \
  --repo <url> \
  [--branch <branch> | --ref <tag-or-commit>] \
  --model <model>
```

如果目标目录已经存在，默认不会覆盖；确认要用新 commit 刷新时显式添加
`--force`。每次未指定 `--ref` 的执行都会重新克隆分支并记录当次实际 commit，
因此 Dockerfile 使用的是构建开始时锁定的源码快照，而不是 Docker build 期间
重新拉取的仓库。

失败任务不覆盖已有可用 target。

长任务应支持后台运行、日志跟踪、取消和恢复：

```bash
bin/vp-sandboxed build ... --detach
bin/vp-sandboxed build-status <job>
bin/vp-sandboxed build-logs <job> --follow
bin/vp-sandboxed build-cancel <job>
bin/vp-sandboxed build-resume <job>
```

## 10. 实现顺序

1. 增加源码锁定和构建任务目录；
2. 增加构建规划 agent prompt；
3. 增加 `vuln-pipeline build` 子命令；
4. 实现 Dockerfile/config/entry 的结构校验；
5. 实现宿主机 Docker build 和日志保存；
6. 实现基于 build.log 的修复重试；
7. 接入现有 `agent_image.ensure()`；
8. 实现 target 发布和失败恢复；
9. 使用 canary、htslib/yyjson、flex 做端到端测试；
10. 最后再验证 Linux kernel 的 `agent_prebuilt` 和 QEMU 场景。

## 11. 成功标准

构建命令成功后必须满足：

```text
targets/<name>/Dockerfile 存在
targets/<name>/config.yaml 可加载
target image 已构建
target-agent image 可以生成
原始 bin/vp-sandboxed run <name> 可以直接开始工作
```

构建命令本身不负责证明目标没有漏洞，也不取代后续的 find、dynamic validation
或 grade。
