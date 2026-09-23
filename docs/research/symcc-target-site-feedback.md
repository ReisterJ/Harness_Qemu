# SymCC 目标位点反馈：实现与实验说明

## 1. 目标

本设计把 SymCC 当作动态验证 agent 的反馈来源，而不是 PoC 自动生成器。agent 负责理解漏洞描述、阅读源码并构造输入；同一份输入由普通目标二进制验证，并异步提交给预先构建好的 SymCC 二进制。agent 可继续工作，之后按 request/input ID 读取 SymCC 的实际执行轨迹、目标命中状态、距离参考和候选输入，再结合源码决定下一步。

命中静态报告中的目标代码，只能证明这次运行到达了目标位点；它不代表漏洞已经触发。崩溃或逻辑错误仍由原有 PoC 生成与 `grade` 流程判断。本工作不把二进制构建接入主工作流，也不更改 grade 的判定语义。

## 2. 构建期：SymCC 的可选源代码/CFG 映射

反馈功能位于本机 SymCC fork（`/home/user/workstation/symcc`），基于 SymCC 上游 `3b8acab` 和 QSYM runtime 子模块 `892f817f38f5abfa083dd0c1caa7ced821566bf5`。默认未设置 `SYMCC_FEEDBACK_MAP_DIR` 时，不输出映射，也不启用源位置回调；普通 SymCC 编译保持原有行为。

构建时设置：

```sh
SYMCC_FEEDBACK_MAP_DIR=/out/feedback-map \
SYMCC_SOURCE_ROOT=/src/project \
SYMCC_SOURCE_COMMIT=<exact-source-commit> \
  symcc <the-project's-original-compile-command>
```

LLVM pass 为编译模块输出 JSONL 映射，并在 IR 中加入运行时通知：

- 每个基本块有稳定 ID、所属模块/函数、后继边、入口/出口标记以及直接调用信息。
- 有 DWARF 行号的指令位置形成源位置记录，带文件、函数、行列号和稳定 ID。
- 每次进入基本块时记录 block ID；块内遇到不同的源位置时记录 source-location ID。
- 每条映射记录带 `source_commit`。动态端拒绝缺少版本信息或 commit 不匹配的映射，不猜测“看起来相同”的位置。

这不是源代码语义分析：优化、内联、宏展开、缺失调试信息和间接调用都会影响映射完整性。source anchor 无法唯一解析时，目标命中状态必须保持 `unknown`，不能把 CFG 近似结果包装成事实。

### 2.1 SymCC fork 的具体改造

实验用的本地 SymCC fork 基于 `eurecom-s3/symcc` 上游提交 `3b8acab`，QSYM runtime 基于 `892f817f38f5abfa083dd0c1caa7ced821566bf5`。改造限于可选反馈旁路；不改变输入符号化、约束建模或 solver 求解策略。

| 文件 | 改动及职责 |
| --- | --- |
| `compiler/Feedback.h`（新增） | 仅在设置 `SYMCC_FEEDBACK_MAP_DIR` 时生成映射。用 FNV-1a 对规范化模块路径、函数名、基本块序号和调试位置生成带类型前缀的 64 位 ID；JSONL 每行记录一个函数的基本块、CFG 后继、调试源位置及可解析的直接调用边，并附 `SYMCC_SOURCE_COMMIT`。写入临时文件后 rename，避免留下半行映射。 |
| `compiler/Pass.cpp` | 在每个 LLVM 模块进入现有 pass 时调用 `emitMap`；未启用映射时不输出文件。 |
| `compiler/Symbolizer.cpp` | 在原有基本块通知之外插入 source-location 通知；只为具有 DWARF 行号且 ID 与前一个不同的位置插桩。启用反馈时采用映射中的稳定 block ID，否则仍用原来的 SymCC site ID。 |
| `compiler/Runtime.h`, `compiler/Runtime.cpp` | 向生成的 LLVM IR 声明 `_sym_notify_source_location` runtime callback。 |
| `runtime/include/RuntimeCommon.h` | 声明 source-location callback，使不同 runtime backend 的接口保持一致。 |
| `runtime/src/backends/qsym/Runtime.cpp` | 在 QSYM backend 实现可选 trace：进程启动时按环境变量打开 trace 文件并映射有界缓冲区；basic-block 和 source-location callback 以首次访问去重记录；目标命中标志在缓冲区容量检查前设置；析构时写完成标志。支持配置目标 ID、容量，标记 trace 完成/截断/目标命中/目标配置无效。 |
| `runtime/src/backends/simple/Runtime.cpp` | 提供空 callback，保证不使用 QSYM backend 的构建仍可链接。 |
| `Dockerfile.feedback`（新增） | 从 digest 固定的官方 SymCC 镜像构建改造后的 compiler 和 QSYM runtime；这是实验预构建工具镜像，不由动态 agent 临时编译。 |

ID 的稳定性范围是“相同源码与相同编译产物映射”，不是跨编译器版本或优化选项的 ABI。source commit 校验能发现仓库版本不匹配，但不能证明不同 flags 编译的 CFG 相同；因此映射必须与生成它的那一个插桩 binary 成套发布，不能只因 commit 相同就跨 binary 复用。映射无法解析、源码 anchor 多义或 trace 格式/目标 ID 无效时，Harness 返回 `unknown`。

当前 trace 格式在 QSYM runtime 和 Harness parser 中共同实现：little-endian `SYMFDB1` 文件头（schema、header size、capacity、event count、flags）后跟定长事件 `(uint64 site_id, uint32 kind, uint32 padding)`；`kind=1` 是基本块，`kind=2` 是源码位置。每个 site 在一次运行中只保留首次访问事件，Harness 使用的是已观察 site 集合及其 CFG 距离，不依赖命中次数或完整执行顺序。默认容量 1,000,000 条，最高 20,000,000 条。正向目标命中标志独立于有界事件缓冲区；若轨迹截断且没有命中标志，则未命中结论仍为 `unknown`。

## 3. 运行期：准确轨迹和距离参考

修改后的 QSYM runtime 通过 `SYMCC_FEEDBACK_TRACE` 写出有界二进制轨迹。当前格式为 `SYMFDB1`，包含 schema、容量、事件数和标志位；事件由 `(site_id, kind)` 构成，`kind=1` 表示基本块，`kind=2` 表示源码位置。同一次执行中每个 site 只记录首次访问，便于在循环程序中保留更多不同位置。结束标志区分正常完成和截断。目标 marker IDs 由 harness 从静态报告的源文件/函数/行号解析后，通过 `SYMCC_FEEDBACK_TARGET_IDS` 交给运行时；runtime 在容量检查前识别目标 marker，因此即使事件缓冲区已满，正向命中仍可精确报告。

Harness 对事实和估算分开处理：

- **实际命中：** 轨迹观察到目标 marker，或 runtime 明确记录 marker 命中。这是该次插桩运行的执行事实，即使进程随后崩溃、轨迹不完整，正向命中仍成立。
- **本次未命中：** 只有完整、未截断的执行轨迹且目标 marker 配置有效，才可以报告 `false`。异常退出、超时、轨迹缺失，或轨迹截断且没有正向 marker 时返回 `unknown`。
- **距离：** 从本次实际观察到的基本块，在静态映射构造的近似 interprocedural CFG 上反向 BFS，计算到目标 block 的最短边数。调用图仅能解析的直接调用会加入近似边；间接调用和外部函数会造成不确定性。该值是导航参考，基本块粒度的 `distance=0` 也不等于精确源行 marker 已命中。
- **候选种子：** SymCC 生成的输入作为独立候选记录来源、摘要、普通目标 replay 与其自身的插桩观察。它不覆盖原始输入结果，也不会自动成为 PoC。

因此，距离变小不能证明真正可达；距离不变也不能证明 agent 没有进展。可靠命中、可靠未命中和未知三种状态不可互换。

## 4. Harness 异步协议

当动态阶段显式启用 `--symbolic-execution symcc` 时，Harness 在容器准备阶段验证预构建二进制、source commit 和 feedback map，并把普通目标与 SymCC 二进制移入受保护路径，防止 agent 绕过协议直接调用。agent 使用执行协议提交请求，不能自行选择/替换 Harness 管理的可执行文件。

请求包括唯一 `request_id`、输入路径、输入摘要、父输入 ID、目标 commit、程序参数、超时和环境变量。Harness 在接收时立即将输入字节复制到该 request 专属、只读快照；普通目标运行、SymCC 具体输入轨迹和符号探索都引用这份快照，后续覆盖 agent 的候选文件不会改变已提交请求。普通目标执行结果及时返回，SymCC 分析不占住 agent 的工具调用。反馈使用相同 request ID 发布，允许乱序完成。每个请求最多复用唯一 ID 一次；后台默认并行运行 1 个 SymCC job，之后已接受的 job 排队等待，不会因为队列繁忙而丢弃。并发度、worker CPU 与内存上限可在 target 的 `symbolic_execution.symcc` 配置中覆盖。SymCC 在单独的、无网络 sidecar 容器运行，只有该请求的输入和专属 trace/output 目录以可写 mount 暴露给它；solver OOM 记为 `resource_exhausted`，不应被解释为有效未命中。agent 可以继续阅读源码、构造其他输入，稍后读取 `pending` 或完成反馈。

为了不把“是否记得调用查询工具”变成实验变量，下一次 `run-input` 响应会附带此前已完成、尚未呈现给 agent 的 `ready_feedback` 摘要。摘要保留输入身份、普通目标结果、原始输入的精确位点命中与 heuristic 距离、候选输入的独立回放状态和位点观察，不复制无界的 solver stdout/stderr。原请求的早期响应不会被异步改写；若 agent 暂时没有新输入，仍可用 `read-feedback REQUEST_ID` 非阻塞查询。

每个已提交输入会先以 `SYMCC_NO_SYMBOLIC_INPUT=1` 单独运行一次 SymCC 二进制，得到该输入本身的具体执行轨迹；这与后续符号探索分开。随后 Harness 再以 `SYMCC_INPUT_FILE` 将本次文件读操作标记为符号输入，探索路径并把 solver 产物写入独立输出目录。Harness 对每个产物执行有界的普通二进制重放，并为每个产物单独采集具体轨迹。若具体轨迹完整且未截断，可精确判断本次命中/未命中；若截断但 runtime 命中标志为真，可精确报告命中，否则为 `unknown`。候选种子的 reach 结果不能冒充原始输入的 reach 结果。

SymCC runtime 以 `0600` 权限创建 trace 文件；sidecar 保持该权限，不向宿主机放宽文件可读性。Harness 通过 Docker exec 在 sidecar 内读取 trace，避免宿主非特权用户把权限错误误判为“trace 缺失”。单次符号探索到达 timeout 时显式记为 `timed_out`；若 cgroup 证实 OOM，则优先标为 `resource_exhausted`。

如果 agent 在后台任务完成前结束，Harness 不延长 PoC 阶段等待 SymCC；会取消并终止对应 sidecar，未完成任务标成 `abandoned_agent_finished`。完整原始请求记录只写入 Harness 结果目录；给 agent 的 `read-feedback` 文件使用有界摘要，避免把求解器日志灌入模型上下文。

## 5. 实验设置和避免答案泄漏

端到端对比实验采用相同的目标镜像、源 commit、模型、静态候选、运行参数和结果目录布局，仅切换动态阶段的 SymCC 设置：

```sh
# 对照组
.venv/bin/python -m harness.cli dynamic <target> \
  --static-report <shared-static-report.json> \
  --model deepseek-flash --symbolic-execution off \
  --results-dir <experiment>/pairs --dangerously-no-sandbox

# SymCC 组
.venv/bin/python -m harness.cli dynamic <target> \
  --static-report <shared-static-report.json> \
  --model deepseek-flash --symbolic-execution symcc \
  --results-dir <experiment>/pairs --dangerously-no-sandbox
```

不显式给 `--max-turns` 时使用项目默认 20,000 turns；动态 agent 的阶段上限为 1,800 秒，迭代上限使用默认值 8。每个靶标两组共用同一个经过审计的静态报告。原始静态分析输出单独保存，不直接传给动态 agent：如果原报告含有精确条件顺序、攻击者控制值、PoC 伪代码或复现流程，应在共同报告中删除这些触发配方，只保留研究问题需要的候选类别、位点、有限 root cause、入口和目标 marker。报告清理过程和两个 arm 的报告 hash 应记录在结果文档中。

报告清理不能隐藏候选本身的合理静态证据，但也不能让某一组比另一组获得额外答案。实验结论分别统计：

1. 到达目标代码位点的耗时/比例；
2. PoC 的生成与复现情况；
3. grade 独立重放结果；
4. agent wall time、输入迭代数、token 用量（若 provider 返回）及后台 SymCC 实际耗时/错误/跳过/未完成任务数。

“目标位点到达更快”与“更快产生可复现 PoC”是不同指标，报告中不可合并为同一成功率。

## 6. 已完成的实现验证

- Harness 单元测试：`tests/test_symcc_feedback.py`、`tests/test_execution_protocol.py`、`tests/test_symbolic.py`。
- 自动呈递测试：完成的旧任务反馈会出现在下一请求响应的 `ready_feedback` 中；测试覆盖乱序前置结果、紧凑字段边界和同一 job 不重复呈递。pilot 日志发现 agent 连续提交多个输入却没有读取已完成反馈，因此把异步结果交付从单纯依赖 agent 主动轮询改为随下一次提交自动呈递，手动查询仍保留。
- Canary 编译与轨迹冒烟：一个输入实际命中配置的 `parse_charlie` 行 marker，另一个完整运行未命中；解析器分别报告 `true` 和 `false`，并把 block-distance 单独标记为 heuristic。
- 真实目标预构建镜像：`n132/arvo:57672-vul` 与 `n132/arvo:62290-vul` 的普通二进制、SymCC 二进制和 source map 均已由本地 Docker build 产出。映射带有各自准确 source commit，目标镜像使用的 SymCC feedback 工具镜像为 `local/symcc-target-feedback:20260924`。

以上是协议/构建验证，不等同于两个 ARVO 的 PoC 对比实验完成。真实靶标实验结果和 grade 复现证据应另写入 `results/experiments/` 下的实验报告，不应把 Canary 测试算作靶标结果。

## 7. 解释结果时的限制

SymCC 本身不会理解静态报告中的漏洞语义，也不会计算“对漏洞还有多少语义距离”。它在一个具体输入上记录插桩执行路径，并可在符号约束允许时产生扩展路径的候选输入。Harness 把可验证的动态位置和求解器候选重新组织成 agent 可用证据；模型仍需理解源码、解释状态变化并选择输入改动。

当前实现的 CFG 距离是方便排序的图距离，不是程序切片、路径可达性证明或求解难度估计。编译告警中被 concretize 的 LLVM 操作、未符号化的输入路径、库函数边界、线程行为、ASan 提前终止和 QSYM 求解失败都可能影响候选生成。实验应保留这些失败状态和原始 transcript，而不是把无反馈的运行计作“距离变差”。
