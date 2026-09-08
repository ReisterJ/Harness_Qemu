# secrun：从仓库生成可运行镜像

`secrun` 是独立的镜像构建入口：获取仓库最新分支提交，优先阅读仓库文档，
生成 Dockerfile，构建镜像，并在最终镜像的新容器中进行功能验收。
它不调用现有的 find、grade 或其他挖掘阶段，也不要求 sanitizer。

## 快速开始

需要 Linux、Python 3.11+、Git 和可访问的 Docker daemon（含 BuildKit）。
模型规划沿用项目的 opencode 后端；模型凭据从环境或项目 `.env` 读取。

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
source .venv/bin/activate

# 设置提供商凭据后，选择模型；也可以配置 SECRUN_MODEL。
secrun --name flex --repo https://github.com/westes/flex.git \
  --model deepseek/deepseek-chat
```

如果只有 `DEEPSEEK_API_KEY`，默认模型为 `deepseek/deepseek-chat`。
其他提供商请显式设置 `--model`、`SECRUN_MODEL` 或 `VULN_PIPELINE_MODEL`。
API key 不会作为命令参数、写入 job.json 或放入最终软件镜像。
构建规划会将仓库文档和读取的源码交给用户配置的模型提供商。

常用选项：

```bash
secrun --name flex --repo https://github.com/westes/flex.git \
  --branch master --build-timeout 30m --task-timeout 90m --detach
```

不指定 `--branch` 时读取远端默认分支，不假定是 main 或 master。
`--workspace` 可以指定输出工作区，默认是当前目录。

## 最新提交与缓存

每次**新任务**都执行远端查询和 Git fetch，记录实际取得的分支 HEAD。
查询失败即失败，不退回旧镜像并宣称它是最新版本。
同一次任务的构建和自动修复锁定这个 commit，不在中途更换源码。

Dockerfile 使用 `COPY source/ ...` 构建已锁定的源码快照，而不是在缓存层中
执行 `git clone --branch`。`source.lock.json` 保存仓库、分支、完整 commit、
查询时间、子模块提交和源码快照 SHA-256。编译输入不含 `.git` 元数据。

新任务发现 commit 和快照均未变化时，可以复用上次通过验收的生成方案，
但仍运行构建和新容器验收。`--replan` 强制重新让模型规划。
Docker 的构建缓存可以复用未变化的层；不会恢复半途终止的编译进程。
提交固定不意味着逐字节可重复：基础镜像或未锁定的外部依赖仍可能变化。

## 工作过程与验收

1. 创建任务目录、检查 Docker、拉取并锁定源码。
2. 提取 README、INSTALL、项目清单及已有容器文档。只读的规划 agent 可以
   继续查看源码和示例；不能改上游源码或直接操作 Docker daemon。
3. 生成结构化方案。工具步数耗尽或输出不合规时，允许一个无工具的收尾步骤，
   使用已有证据输出方案。日志保留完整文本，不截掉大 JSON 构建文件。
4. 校验文件路径、文档依据和验收协议，再写入独立构建上下文。
5. 宿主调度器执行 Docker build，持续保存日志，记录不可变镜像 ID。
6. 按验收协议启动最终镜像的新容器；比较真实退出码、输出和 HTTP 响应。
7. 验收通过后发布一个新版本目录，并原子更新 `current.json`。

验收类型：

| 类型 | 默认验收方式 |
| --- | --- |
| CLI / 批处理 | 按声明的命令、参数和 stdin 执行，检查退出码及实际输出 |
| HTTP 服务 | 映射一个临时回环端口，等待就绪，GET 实际接口并校验响应内容 |
| 库环境 | 运行公开 API 的最小使用示例，明确标记为 library |

至少需要一个真实功能用例；CLI/库的用例中还必须包含交付启动命令本身。
HTTP 只返回 200、CLI 只有版本号，都不足以替代真实功能检查。
测试不覆盖 ENTRYPOINT，不挂载源码来弥补镜像缺文件，也不在容器启动后补装依赖。
CLI 验收默认无网络；HTTP 从宿主直接请求映射端口，不继承 HTTP 代理。
每个 CLI 用例使用新容器，HTTP 用例在一次正常启动的服务中执行。

初次合法方案的验收协议在任务中冻结。自动修复可以改 Dockerfile 和
`support/` 下的包装文件，不能修改源码快照、用例或预期输出。
若用例本身有误，不会偷偷放宽断言：任务报告失败，用户可以基于有问题的方案
修改独立 recipe，再启动新任务。模型生成的用例并不构成软件全部功能正确的证明。

## 进度、时间预算与后台任务

所有命令会打印结果目录。长命令每 10 秒更新一次心跳：阶段、耗时、
距最近输出的时间和日志路径；不显示虚构的总体进度百分比。

| 选项 | 默认 | 含义 |
| --- | --- | --- |
| `--build-timeout` | 30 分钟 | 每次镜像构建上限，包括初次规划器基础镜像构建 |
| `--task-timeout` | 90 分钟 | 本次执行总预算，包含源码获取、规划、重试与验收 |
| `--agent-timeout` | 10 分钟 | 每次规划的阅读与结构化收尾共享预算 |
| `--fetch-timeout` | 5 分钟 | 单次远端 Git 操作上限 |
| `--build-attempts` | 3 | 本次执行最多尝试次数，非法规划也消耗次数 |
| `--memory` | 2g | 规划器和验收容器内存；不是 BuildKit 编译内存限额 |
| `--cpus` | 2 | 验收容器 CPU 上限；构建提示默认使用 modest parallelism |

```bash
secrun status <任务ID或结果目录>
secrun logs <任务ID或结果目录> --follow
secrun cancel <任务ID或结果目录>
secrun resume <任务ID或结果目录> --build-timeout 60m --task-timeout 120m --detach
```

后台任务由独立会话的工作进程运行，终端关闭后继续执行。任务状态和日志落盘；
进程崩溃后可以恢复，不依赖常驻数据库服务。机器重启后需要显式 resume。
`resume` 沿用原任务的源码快照，并提供一轮新的时间/尝试预算；它不是“检查新版本”。
要取分支最新版本，请重新执行 `secrun --name ... --repo ...`。

取消命令先登记请求，工作进程中止当前子进程并清理自己创建的容器。
请用 status 确认终态；不会执行全局 `docker prune` 或删除其他任务资源。
构建中断后已经完成的缓存层可以保留，恢复会重新提交构建。

## 输出位置

```text
results/images/<name>/<job-id>/
  job.json                 非敏感运行参数
  status.json              当前状态和最后进度
  source.lock.json         本次实际获取的源码身份
  source/                  干净的锁定源码快照
  plan.json                已通过结构校验的生成方案
  acceptance.yaml          冻结的验收协议
  acceptance.json          最新完成的验收报告
  attempt_01/
    documents.json         优先读取的文档摘录
    planner.log            规划过程与完整输出
    context/               Dockerfile、source/ 和包装文件
    build.log              完整构建日志
    image.json             镜像检查信息
    acceptance.json        该次尝试的验收报告
    test-*.log             功能用例输出

targets/<name>/image/
  current.json             最近一次验收通过的版本
  versions/<job-id>-<attempt>/  可重建上下文、方案、报告与启动 README
```

生成目录已加入 `.gitignore`，避免将整个上游仓库意外提交到本项目。
已有 `targets/<name>/Dockerfile`、`config.yaml` 及手工文件不会被覆盖。
同名目标不能并发构建；失败不会替换上次通过的 `current.json`。

状态包括 `passed`、`source_failed`、`planning_failed`、`build_failed`、
`validation_failed`、`needs_config`、`timed_out`、`cancelled` 和基础设施 `failed`。
只有 `passed` 发布为可运行镜像。前台运行退出码：成功 0，普通失败 1，
配置/用法错误 2，超时 124，取消 130。后台提交成功仅代表任务已启动。

## 显式 recipe（无需模型）

`--recipe path.json` 或 YAML 可用于复现方案、人工修正或离线回归测试。
采用与 agent 相同的严格协议，不跳过远端更新检查、构建或验收。
显式 recipe 不会交给模型自动修改；构建/验收失败后停止。
可以从生成版本目录中的 `plan.json` 开始编辑。

```json
{
  "version": 1,
  "summary": "Build the documented application from this checkout",
  "evidence": [{"path": "README.md", "reason": "build and usage instructions"}],
  "files": {
    "Dockerfile": "FROM gcc:14\nCOPY source/ /src/\nRUN cc /src/main.c -o /app\nCMD [\"/app\"]\n"
  },
  "acceptance": {
    "kind": "cli",
    "run": {"args": [], "env": {}, "required_env": []},
    "cases": [{
      "name": "hello", "purpose": "functional", "args": [],
      "timeout_seconds": 10,
      "expect": {"exit_code": 0, "stdout": "hello\n"}
    }]
  }
}
```

`purpose` 使用 `startup` / `functional`；描述另放 `description`。
精确输出比较包含换行；也可使用非空 `stdout_contains` / `stderr_contains`。
HTTP 使用 `run.port`、`run.startup_timeout_seconds`，用例提供 `path` 和
`expect.status`，以及 `body` 或非空 `body_contains`。

`run.required_env` 声明外部提供的环境变量名。缺配置时为 `needs_config`，
不会编造凭据。普通默认值放在 `run.env`；不要把真实凭据写入 recipe。

## 网络与当前边界

规划器默认使用 bridge 网络，构建使用 Docker 默认网络。若虚拟机中的
代理或模型服务只监听宿主回环地址，可以按环境需要设置：

```bash
secrun --name flex --repo https://github.com/westes/flex.git \
  --agent-network host --build-network host
```

规划器不会自动继承 Docker 客户端注入的 HTTP 代理。确实需要时使用
`--agent-proxy` / `SECRUN_AGENT_PROXY`。构建代理仍由 Docker 配置管理。
第一版连接的是本机 Docker；暂不自动管理远程 builder、Compose 依赖服务、
图形应用、GPU 或复杂数据卷配置。对这些项目应明确返回需要配置，
不能把“镜像能构建”当成“应用已可用”。

## 回归测试

```bash
.venv/bin/pytest -q tests/test_secrun.py
SECRUN_DOCKER_TESTS=1 .venv/bin/pytest -q tests/test_secrun.py
```

普通测试不依赖模型或 Docker。可选 Docker 测试使用本地临时 Git 仓库，
实际编译、运行，并验证仓库提交变化后自动构建新源码。

实际 flex 的自动生成、修复与功能验收过程见 [端到端验证记录](secrun-flex-e2e.md)。
