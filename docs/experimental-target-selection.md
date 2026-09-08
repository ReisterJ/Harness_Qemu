# 实验目标选型与验证计划

本文整理适合验证本项目“静态分析 → 动态验证 → grade”流程的开源目标，重点关注较新的工具类项目、较薄的代码规模、明确的外部输入入口，以及 AddressSanitizer（ASan）或其他内存检测工具的可用性。

本文只讨论实验目标和适配策略，不改变原始工作流。目标项目产生的 PoC 仍然必须交给现有 `grade` 阶段确认；静态分析和动态验证只负责给出候选及 PoC，不直接替代最终验证。

## 1. 选型目标

理想的实验目标应同时满足以下条件：

- 有明确的外部输入入口，例如文件、标准输入、命令行参数、网络协议或压缩包；
- 输入处理链路较短，便于静态分析建立“入口 → 解析/转换 → 可疑操作”的调用链；
- 项目规模适中，agent 可以在有限 turn 数内完成源码审查；
- 能够稳定构建，并可以在 Sanitizer、Valgrind、Miri 或 fuzz harness 下运行；
- 存在适合构造最小 PoC 的命令行工具或库 API；
- 崩溃输出、退出状态或运行日志足够稳定，便于现有 `grade` 重放；
- 项目本身没有过多安全加固、复杂运行时依赖或必须连接外部服务的条件。

需要特别避免把“项目较新”直接等同于“更容易找到漏洞”。较新的项目通常更适合验证流程和工具链，但未必已经存在可复现的公开缺陷。因此实验应同时准备两类目标：

1. **流程目标**：用于验证静态候选、动态可达性探针、PoC 生成和 grade 协议；
2. **缺陷目标**：已知存在边界条件、解析器复杂度或内存安全风险，用于验证系统能否发现并复现问题。

## 2. 推荐候选

### 2.1 第一梯队

| 优先级 | 项目 | 语言 | 适合的输入面 | 检测方式 | 推荐理由 |
| --- | --- | --- | --- | --- | --- |
| 1 | [libfyaml](https://github.com/pantoniou/libfyaml) | C | YAML/JSON 文档、流式解析、事件处理 | ASan、UBSan、Valgrind、fuzzing | 解析器边界清晰，代码规模适中，适合验证入口可达性和内存错误 PoC |
| 2 | [yyjson](https://github.com/ibireme/yyjson) | C | JSON/JSON5、指针、Patch、流式处理 | ASan、UBSan、Valgrind、fuzzing | 单库依赖少、构建快、输入格式容易生成，适合作为稳定的 C 基准目标 |
| 3 | [jaq](https://github.com/01mf02/jaq) | Rust | JSON 查询、过滤、转换及多格式输入 | Rust Sanitizer、cargo-fuzz、Miri（适用时） | Rust 工具项目，数据流明确，能够检验 Rust 构建和检测器适配 |

这三个项目覆盖了两种重要实验形态：

- `libfyaml` 和 `yyjson` 适合验证传统 C/ASan 路径；
- `jaq` 适合验证 Rust 项目中的 panic、资源消耗、unsafe/FFI 边界以及 Rust Sanitizer 工具链。

### 2.2 第二梯队

| 项目 | 语言 | 主要输入面 | 适合验证的内容 | 注意事项 |
| --- | --- | --- | --- | --- |
| [comrak](https://github.com/kivikakk/comrak) | Rust | Markdown/GFM 文档、扩展语法 | 解析器状态机、深层嵌套、panic 和资源消耗 | 纯 Rust 内存破坏问题预期较少，需要扩大 grade 对非 ASan 失败的识别 |
| [ugrep](https://github.com/Genivia/ugrep) | C++ | 文本、正则表达式、归档和压缩输入 | 多格式输入、归档解析、CLI 参数组合 | 功能面较宽，应使用 focus area 限制 agent 搜索范围 |
| [Ruff](https://github.com/astral-sh/ruff) | Rust | Python 源码、配置文件、命令行参数 | 高吞吐解析器、复杂语法、错误恢复 | 项目规模较大，适合在建立 Rust 适配后再进行实验 |
| [uv](https://github.com/astral-sh/uv) | Rust | `pyproject.toml`、lockfile、wheel/sdist、Git/HTTP 输入 | 解析、归档、路径和依赖处理 | 外部依赖和网络场景较多，第一轮实验应限定为本地文件输入 |

## 3. 建议的实验顺序

### 阶段 A：C 基准链路

先使用 `yyjson` 或 `libfyaml` 建立稳定基准。目标不是立刻追求高危漏洞，而是确认以下链路完整工作：

```text
静态分析
  → 输出带外部入口和可达性证据的 StaticFinding
  → 动态验证消费 StaticFinding
  → 生成非空 PoC
  → 现有 grade 在新容器中重放 PoC
  → 输出最终 verdict
```

建议优先选择具有独立 CLI 或容易补充测试驱动程序的提交版本，并为每个实验目标准备固定的：

- 构建命令；
- Sanitizer 环境变量；
- 最小正常输入；
- PoC 输入文件位置；
- 目标程序调用命令；
- 预期崩溃类型和退出行为。

### 阶段 B：解析器和多格式输入

使用 `libfyaml`，关注 YAML 锚点、别名、嵌套集合、长标量、流式输入和错误恢复等代码路径。这里的重点是让静态 agent 证明输入确实能从公开 API 或 CLI 入口进入目标函数，而不是只报告某个危险操作。

### 阶段 C：Rust 工具链

使用 `jaq` 或 `comrak` 验证 Rust 项目。重点观察：

- Rust 项目是否能在当前 Docker 镜像中稳定构建；
- `cargo test`、`cargo fuzz` 和 Sanitizer 是否需要 nightly 或额外 target；
- agent 是否会把普通 `panic`、栈溢出、超时和真正的内存安全问题混为一谈；
- grade 是否能识别 Rust 的 panic、abort、Sanitizer 报告和非零退出，而不仅是 ASan 栈帧；
- 是否存在 `unsafe`、C FFI、压缩/归档库等适合动态验证的边界。

## 4. C 项目运行模板

具体项目应以其仓库提供的构建方式为准。下面是适合放入目标 `Dockerfile` 的通用思路：

```dockerfile
ENV CC=clang
ENV CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined"
ENV LDFLAGS="-fsanitize=address,undefined"

# 按目标项目实际构建系统替换
RUN cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_FLAGS="$CFLAGS" \
      -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \
 && cmake --build build -j"$(nproc)"
```

动态验证 agent 应优先执行以下顺序：

1. 用正常输入确认程序和入口可用；
2. 用静态候选指定的入口构造可达性探针；
3. 检查日志、覆盖率、调用栈或 Sanitizer 输出，确认目标函数被执行；
4. 再逐步放大长度、深度、计数或边界值，构造最小触发 PoC；
5. 将 PoC、命令、退出码和完整输出写入现有 `CrashArtifact`。

如果只获得内存泄漏、超时、正常错误返回或资源耗尽，不能直接当作 ASan 崩溃提交给 grade；应根据目标配置和 `--accept-dos` 语义明确分类。

## 5. Rust 项目运行模板

Rust 的安全保证意味着“能被 Sanitizer 捕获的内存破坏”通常集中在 `unsafe`、FFI、第三方 C 库或编译器/运行时边界。纯 safe Rust 项目更适合验证 panic、栈深度、资源耗尽和解析器健壮性，而不是期待传统 use-after-free。

### 5.1 AddressSanitizer

Rust Sanitizer 通常需要 nightly toolchain、Sanitizer 编译选项以及标准库重编译。例如 Linux x86_64 的实验命令可以从下面的模板开始：

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

RUSTFLAGS="-Zsanitizer=address" \
  cargo +nightly build -Zbuild-std \
  --target x86_64-unknown-linux-gnu

ASAN_OPTIONS=abort_on_error=1:detect_leaks=1 \
  cargo +nightly run -Zbuild-std \
  --target x86_64-unknown-linux-gnu -- <input>
```

实际项目可能需要调整 target、链接参数或禁用不兼容的依赖。第一次接入 Rust 目标时，应先把构建和一个正常输入测试固定下来，再接入 agent。

### 5.2 cargo-fuzz

如果目标项目已有 fuzz target，优先复用它，而不是让动态 agent 从零搭建 fuzz harness：

```bash
cargo +nightly fuzz list
cargo +nightly fuzz run <target> -- -max_total_time=60
```

`cargo-fuzz` 适合辅助动态验证和缩减输入，但它不能取代本项目的验证链路。最终仍需将可复现的输入文件和执行命令交给现有 `grade`。

### 5.3 Miri 的边界

Miri 适合发现部分未定义行为、越界访问和违反 Rust 内存模型的测试问题，但它不是普通命令行程序的通用替代运行时，也不等价于 ASan。若实验使用 Miri，结果应在动态结果中单独标注，避免把 Miri 报告直接伪装成 ASan 崩溃。

## 6. 对当前 find/grade 实现的适配要求

当前拆分后的 `find` 阶段已经满足以下原则：

- 静态 agent 只输出 `StaticFinding`，不生成 PoC；
- 动态验证消费静态候选，并负责生成 `CrashArtifact`；
- 静态候选不会写入 `found_bugs.jsonl`；
- 只有动态验证得到的 PoC 才进入现有 `grade`；
- `grade`、`judge`、`report` 和 `patch` 的职责不变。

为了支持 Rust 和非 ASan 目标，后续适配建议按以下顺序实施：

1. 将检测器从“ASan 输出解析”扩展为显式的 detector 类型，例如 `asan`、`ubsan`、`rust-sanitizer`、`miri`、`panic` 和 `custom`；
2. 为每类 detector 定义“有效崩溃”的最小证据，不仅依赖固定的 `ERROR: AddressSanitizer` 字符串；
3. 在 grade prompt 中区分内存破坏、panic、栈溢出、超时、资源耗尽和普通错误退出；
4. 保留项目代码栈帧、PoC 可重放性和非内存耗尽检查；
5. 让 `DynamicValidationResult` 记录到达证据，即使最终没有 `CrashArtifact`，也能区分 `not_reached`、`reached_no_crash` 和环境失败；
6. 对 Rust 目标优先支持已有 fuzz target 和本地输入，暂不把网络安装、Git 拉取和外部服务作为第一轮 PoC 依赖。

## 7. 已完成的 libyaml 端到端实验

在历史目标版本中对 `libyaml` 执行过一次完整实验，目的是验证流程协议，而不是证明目标一定存在漏洞。实验使用危险模式运行在当前虚拟机环境中，结果如下：

- Docker 镜像构建成功；
- 静态分析 agent 正常启动并读取 parser、scanner、reader 及相关 API 源码；
- 静态分析最终输出 `candidate_count: 0`，没有提交缺乏可达性证据的候选；
- 因为没有静态候选，动态验证和 grade 按设计没有执行；
- 最终运行状态为 `no_crash_found`，不是流程异常。

这个结果验证了负分支：静态阶段无法给出可信候选时，系统不会为了“完成一条流水线”而伪造 PoC，也不会把静态怀疑直接送入 grade。下一次端到端实验应选择更容易形成输入到解析器 sink 的目标，例如 `yyjson` 或 `libfyaml`，并准备已知可触发的测试样例或专门实验分支。

## 8. yyjson 实验记录

本轮使用 yyjson 官方仓库的固定 commit `43ce2ff2a29b136722eb98f83db226c8344ffc4d`，通过一个只接受本地 JSON 文件的最小 CLI 入口构建实验镜像：

```text
外部文件
  → /work/entry
  → yyjson_read_opts()
  → 文档根节点遍历/序列化
  → yyjson_doc_free()
```

已完成的准备和运行检查：

- Docker 镜像 `vuln-pipeline-yyjson-e2e:latest` 构建成功；
- wrapper 使用 AddressSanitizer 和 UBSan 编译；
- 正常 JSON、JSON5 特性输入和 malformed JSON 均在容器内运行成功；
- malformed JSON 返回 yyjson 解析错误，没有观察到 Sanitizer 报告；
- `--dangerously-no-sandbox` 下启动了三次完整流水线尝试，分别使用 `deepseek-v4-flash`（100/40 turns）和 `deepseek-chat`（20 turns）。

第一次实验没有得到静态候选或 `no_crash_found` 结论，因为 agent 容器继承了宿主 Docker 配置中的 `127.0.0.1:7897` loopback 代理，模型请求无法从容器访问宿主代理。清空 Docker client 的代理配置后，重跑已经能够正常产生工具调用和完整 transcript，说明网络问题已解决。

修复网络后的实际结果如下：

- `deepseek-v4-flash`、100 turns：静态阶段运行 697 秒、107 条消息，最后因未输出 `<static_findings>` 进入 `agent_failed`；
- `deepseek-chat`、80 turns：静态阶段运行 243 秒，模型停止时只输出了未完成的分析文本，结构化结果解析失败；
- 增加静态 prompt 的分析时间盒后再次运行 `deepseek-chat`、50 turns：运行 272 秒，仍在达到最大 steps 时没有输出 `<static_findings>`。

三次修复网络后的运行都没有进入动态验证或 grade。流水线把它们标记为 `agent_failed` 是正确的：不能把缺少结构化结果误判为 `no_candidates`，也不能据此判断 yyjson 没有漏洞。当前剩余问题是静态 agent 的完成协议和分析范围控制，而不是 yyjson 构建或网络连接。

待模型服务恢复后，可使用相同目标重新运行：

```bash
VULN_PIPELINE_DOCKER_BUILD_NETWORK=host \
  ./.venv/bin/vuln-pipeline run /tmp/yyjson-e2e.8HzLl1 \
  --dangerously-no-sandbox \
  --model deepseek/deepseek-v4-flash \
  --max-turns 100 --runs 1 \
  --results-dir /tmp/yyjson-e2e.8HzLl1/results
```

目标构建和入口已被单独验证，因此下一次重试可以直接聚焦 agent 后端是否恢复，以及最终是否能形成 `StaticFinding → CrashArtifact → grade verdict`。

## 9. 最终推荐

推荐按以下顺序推进：

```text
yyjson
  → libfyaml
  → jaq
  → comrak
  → ugrep / Ruff / uv
```

- 如果目标是尽快验证 C/ASan/grade 链路，选择 `yyjson`；
- 如果目标是验证复杂解析器和入口可达性，选择 `libfyaml`；
- 如果目标是验证 Rust 构建、Sanitizer 和非 ASan 结果模型，选择 `jaq`；
- 如果目标是验证更复杂的 CLI 和多格式输入，再进入 `ugrep`、`Ruff` 或 `uv`。
