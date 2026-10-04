# SymCC 目标位点反馈工作计划

## 目标与边界

目标是在动态验证中让 agent 像人类分析者一样使用插桩执行反馈：agent 阅读静态报告和源码、构造输入；Harness 把同一输入交给普通目标验证，并异步交给预先构建好的 SymCC 目标执行；执行证据返回后，agent 结合源码决定下一步输入。SymCC 不负责理解漏洞语义，也不承诺直接生成可用 PoC。

本计划默认普通目标、SymCC 二进制和与之匹配的 source/CFG map 已经构建完成。构建、切片、SymCC 编译器部署不属于本轮研究问题。动态阶段之外的工作流不改，尤其不改变 `grade`：最终仍由 grade 在新容器中检查提交的 PoC 是否可复现。

必须区分三类反馈：

- `target_reached`：目标源位置 marker 是否在该次完整执行中被观察到。有效轨迹的正命中是事实；完整、未截断轨迹中的未命中只说明该输入没有命中。
- `target_block_reached`：是否进入目标所在的基本块。它不等于执行到目标行或指令。
- `distance`：基于观测基本块和静态 CFG/调用图估算的边数，只是导航启发式；不得当作可达性证明或真实语义距离。

到达目标位点也不等于漏洞已触发。agent 仍需验证崩溃或不合法效果，生成可复现 PoC；最终验收仍回到 grade。

一次动态验证也可能发现静态报告之外的独立漏洞。这是正向发现，不应记成原候选的“走偏”或失败；应分配独立 finding ID，保留输入、ASan/崩溃证据并单独复现/Grade。统计时仍要把“原候选位点命中”和“额外漏洞发现”分开：额外漏洞不能反向证明原候选已命中，也不能在没有对照证据时直接归因于 SymCC。

## 工作阶段

### 0. 固定实验契约与输入材料

1. 选定同一目标源码版本、普通二进制、SymCC 二进制和 map；记录源码 commit、构建参数及产物摘要。
2. 为每个目标准备一份两组共用的静态报告。报告提供入口、候选位点、有限 root cause 和必要的简单执行链，不提供 PoC、精确触发配方或已经求解出的输入。
3. 固定模型、动态预算、轮数上限、target 镜像和运行参数。对照组与实验组唯一处理变量是是否启用 SymCC 反馈；若提示词因协议必须不同，记录差异并避免把结果解释成严格的单变量因果比较。

完成条件：静态报告经审阅并计算 hash；两组的报告 hash 和目标 commit 一致；结果目录可从日志还原每次运行配置。

### 1. 目标 marker 与反馈数据正确性

1. 将静态报告中的 source file/function/line 解析成 map 中的稳定 ID，并在版本或 anchor 不匹配时拒绝给出确定结论。
2. trace 至少记录基本块和 source location；保留完成、截断、异常退出、缺 map 等状态。
3. 从 trace 独立计算精确命中、block 命中和 heuristic distance，不把三者合并成一个 `reach` 布尔值。
4. 候选种子分别关联其来源、输入 hash、普通目标 replay 和自己的 trace；候选种子的结果不能代替原始输入结果。

完成条件：单元测试覆盖精确命中、精确未命中、未知、trace 截断、目标块命中但目标 marker 未命中、错误 commit/map、候选种子与原始输入隔离。

### 2. Harness 异步执行协议

1. agent 用请求提交输入、目标参数和父输入 ID；Harness 在运行前生成不可变输入快照及 hash。
2. 普通目标执行及时返回，SymCC 在受限的独立 worker 中异步执行；SymCC 超时、崩溃、OOM、队列等待和无种子结果各自保留，不能折叠成“未到达”。
3. agent 可继续读源码、改输入，不必等待 SymCC。完成的旧反馈随下一次请求自动交付；显式读取接口保持非阻塞，`pending` 后不得 sleep 或轮询。
4. 反馈必须按 request/input/parent ID 关联，且限制大小；原始 solver 日志保存在 Harness 结果目录，不灌入模型上下文。

完成条件：测试覆盖输入覆盖不影响快照、乱序完成、自动反馈只交付一次、worker 失败、超时、排队与阶段结束清理。SymCC 工作不能同步阻塞 PoC agent。

### 3. Agent 的迭代使用方式

每一轮按以下闭环运行：

1. agent 依据报告、源码和当前输入状态构造一个真实入口可接受的输入；不要求首次输入已经接近漏洞。
2. agent 提交输入；Harness 返回普通目标结果并异步安排 SymCC。
3. agent 在等待期间继续源码分析和输入设计。首个可运行输入应尽早提交（目标为 5 分钟或 25 次有意义工具调用以内）；反馈读取不能变成等待循环。
4. agent 收到结果后先核对 exact reach、trace 完整性、closest location 和 heuristic distance，再结合代码解释反馈并修改下一输入。距离只用于排序和提出假设。
5. 若精确 marker 命中，符号执行阶段不再替代漏洞验证：agent 继续普通 PoC 调试，直到复现漏洞效果或预算结束。
6. 结束时必须提交与结果一致的标准状态；不能只留下叙述或向用户询问是否继续。成功 crash PoC 继续用既有 XML 契约；无 PoC 时用既有 inline status tags。

完成条件：transcript 能看出至少一次“输入—反馈—基于反馈的下一步决策”；所有提交输入都有迭代记录；未命中、不可达、无 crash 和工具故障不混淆；最终结果满足现有提交协议。

### 4. 单元与端到端验证

先完成单元测试，再做端到端：

1. Canary：验证反馈 schema、精确 marker、距离启发式标记和异步 worker 的基本链路，不计入真实漏洞效果。
2. ARVO 57672 与 62290：使用相同静态报告分别运行 SymCC off/on；每个实验保留 transcript、dynamic result、迭代记录、SymCC 摘要和配置快照。
3. 对成功 PoC 做独立 grade 或等价新容器重放；不能只相信动态 agent 自报。
4. 单次差异只作为案例分析。至少重复多个配对运行后再讨论稳定效果；未完成、格式错误、SymCC 崩溃等都作为结果报告，不得静默剔除。

指标分开报告：PoC 是否独立复现、首次有效输入耗时、是否精确命中目标、距目标的启发式变化、输入/请求轮数、总 agent wall time、工具调用、模型 token（注明 cache-read 计数口径）、SymCC 实际耗时与失败状态。

完成条件：报告提供每次运行的原始目录链接和机器证据；grade 结果可独立复核；对“路径更近”“到达位点”“触发漏洞”“PoC 可复现”分别下结论。

## 当前进度与下一步

- 已实现：SymCC source/CFG feedback map 与运行时 trace；Harness 输入快照、异步 SymCC sidecar、按请求关联的反馈和 heuristic distance；下一请求自动呈递已完成反馈；普通目标和 grade 契约保持分离。
- 已验证：相关单元测试已通过；两个 ARVO 目标的预构建普通/SymCC 产物已准备；57672 的 off 组产生的 PoC 通过独立 grade 重放。
- 部分验证：62290 的首次 off/SymCC 配对都在阶段预算附近停止，SymCC 组太晚才交输入，不能用于证明处理效果。之后加强了“尽早提交、禁止等待轮询”的提示并增加首次 request 时间统计。复测首个输入在 116.703 秒提交，完成两轮；反馈从 heuristic distance 29 降至 5，agent 结合源码调整了下一输入。但第二轮 SymCC 进程立刻崩溃，目标 marker 仍未命中，agent 最终也没有输出要求的标准无 PoC 状态 tags，因此 Harness 状态为 `invalid_submission`。这只能证明反馈闭环和及时迭代有运行迹象，不能算成功 PoC 或严格的 SymCC 效果比较。
- 额外发现：62290 v7 的 round-004 输入触发目标崩溃，SymCC trace 因此不完整，无法判断该输入是否到达原报告目标；但 Harness 普通目标执行触发了报告外的 ASan `negative-size-param`，栈落在 `isvcd_crop_wnd_flag_res_int`。重建输入与原始 round-004 SHA-256 完全相同，独立重放 8 次中 6 次得到相同 ASan 报告，2 次以无诊断文本的 SIGSEGV 退出。按独立 finding 记录，这是有价值的额外漏洞发现；原目标位点仍应记为 unknown，且额外 finding 尚未走独立 Grade。
- 下一步：把额外 crop-window finding 作为独立候选补充最小复现材料并做独立 Grade；排查 62290 SymCC 运行时 LeakSanitizer 退出和段错误；验证最终状态 tags 提示；再重跑配对实验，并至少重复数次后报告 SymCC 效果。

详细反馈格式和代码实现见 [SymCC 目标位点反馈说明](symcc-target-site-feedback.md)；实测逐次数据见 ignored 的 `results/experiments/symcc-target-site-feedback-20260924/final-report.md`。
