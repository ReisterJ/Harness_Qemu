# SymCC 反馈稳定性与扩大实验工作计划

## 1. 当前问题

目前的核心问题不是“SymCC 有没有用”，而是它的效果不稳定，导致实验结果很难解释。

已有实验显示，反馈组有时比 off 组更快、更清楚地收敛；但在另一些任务中，反馈会被 agent 误读、被过早/过晚交付，或者被工具噪声污染。继续简单增加样本数量只能得到更多混杂结果，不能解释为什么有效、为什么失效。

下一阶段的工作目标是：

1. 把 SymCC 反馈从“可能有帮助的信息”改造成“可审计的执行证据”；
2. 让 agent 稳定形成“构造输入 → 执行 → 读取反馈 → 修改输入”的闭环；
3. 把 target-site approach、PoC 生成、Grade 成功、额外崩溃发现分开统计；
4. 在更大的 benchmark 上做成对实验，回答 SymCC 反馈到底在哪些环节产生收益。

本阶段暂不把构建作为研究变量。实验默认目标已经准备好普通二进制、ASan 二进制、SymCC 插桩二进制和匹配的 feedback map。

## 2. 对不稳定性的工作假设

我认为当前不稳定主要来自五类原因：

### 2.1 反馈粒度不稳定

旧反馈容易把“进入目标函数”或“进入目标基本块”误解释为“到达漏洞操作”。对于大函数内部的某个分支漏洞，这会导致 agent 过早切换到 PoC 调试阶段。

修改方向：

- 函数命中、基本块命中、operation marker 命中必须分开；
- 只有 `exact_target_reached=true` 或 `target_operation_reached=true` 才能证明到达目标位点；
- `distance=0` 只能作为启发式信息，不能作为候选验证依据。

### 2.2 反馈交付时机不稳定

如果反馈太早打断 agent，agent 还没有形成基本语义理解；如果反馈太晚，agent 已经在错误空间里浪费了大量时间。

修改方向：

- SymCC 后台异步执行，不阻塞 PoC agent；
- agent 必须早期提交第一个可执行输入；
- feedback ready 后，如果 agent 长时间没有读取，harness 发出 nudge；
- feedback 已读后，如果 agent 长时间没有提交下一轮输入，harness 再发出 follow-up nudge；
- nudge 必须有 grace period，避免过早打断源码理解。

### 2.3 结果状态过载

过去一个 `dynamic_status` 同时承载了“是否到达目标”“是否触发崩溃”“是否提交成功”“是否 Grade 成功”等多种含义，导致 off 和 feedback 的对比不公平。

修改方向：

结果中增加结构化 `status_breakdown`：

- `target_site_status`：是否有机器证据表明到达目标 operation；
- `poc_status`：是否产生可执行 PoC；
- `grade_status`：是否在干净容器中通过 Grade；
- `additional_findings_status`：是否发现额外崩溃；
- `feedback_quality_status`：反馈是否产生、是否被读取、是否帮助改善输入。

### 2.4 工具噪声污染实验

PIE/ASLR、Sanitizer 自身崩溃、feedback map 不匹配、SymCC 超时等会让 agent 走偏，也会让结果难以解释。

修改方向：

- 实验目标默认关闭 PIE；
- 记录 ASLR、PIE、Sanitizer、SymCC runtime 配置；
- 工具链崩溃和目标程序崩溃分开；
- feedback map 和二进制不匹配时直接标记环境问题，不做猜测。

### 2.5 模型行为本身有随机性

LLM 可能不读取反馈、读了反馈但不使用、提交格式错误，或者在相同输入下采用不同搜索策略。

修改方向：

- 用 evidence ledger 记录 agent 是否真的读取并利用反馈；
- 做多次重复实验，而不是只看单次胜负；
- 把“PoC 已生成但没有正确提交”和“PoC 没生成”分开；
- transcript 里抽取行为模式，而不是只看最终状态。

## 3. 具体代码修改计划

### 3.1 反馈语义收紧

涉及文件：

- `harness/symbolic/feedback.py`
- `harness/execution_protocol.py`
- `harness/dynamic_validation.py`
- `tests/test_symcc_feedback.py`
- `tests/test_symcc_feedback_calibration.py`

修改内容：

1. agent-facing feedback 固定输出以下字段：

   ```json
   {
     "request_id": "round-001",
     "trace_status": "complete",
     "exact_target_reached": false,
     "target_operation_reached": false,
     "target_function_entered": true,
     "target_block_entered": false,
     "allowed_conclusion": "entered target function, exact target operation not observed",
     "best_actual_locations": []
   }
   ```

2. `best_actual_locations` 必须来自真实执行轨迹，不能来自静态 CFG 推断。
3. `heuristic_distance` 如果保留，必须标注为非权威信息。
4. 生成的新种子必须有自己的 input hash 和执行结果，不能覆盖原始输入结果。

验收标准：

- function-only 不会变成 exact hit；
- block-only 不会变成 exact hit；
- operation marker 命中才是 exact hit；
- trace 截断时结果是 unknown，而不是 miss 或 hit。

### 3.2 动态阶段反馈闭环

涉及文件：

- `harness/prompts/dynamic_validation_prompt.py`
- `harness/dynamic_validation.py`
- `harness/agent.py`
- `tests/test_agent.py`
- `tests/test_symcc_iteration_reconciliation.py`

修改内容：

1. 动态阶段 prompt 改成强约束：
   - 必须通过执行协议提交输入；
   - 必须读取 ready feedback；
   - 不能等待 SymCC 阻塞；
   - 不能把 function/block hit 当成漏洞到达；
   - 如果 feedback pending，要继续 PoC 工作或结束并报告 pending。
2. 保留 progress nudge：
   - 首次输入过晚时，要求立即提交；
   - feedback ready 但未读时，要求读取；
   - feedback 已读但无下一步动作时，要求提交下一轮输入或结束。
3. 对 nudge 增加 grace period，避免反馈刚 ready 就打断 agent。

验收标准：

- transcript 中能稳定看到“输入 → 执行 → 反馈 → 下一输入”的循环；
- agent 不会 `sleep` 等 SymCC；
- feedback ready 后不会长期不读；
- feedback 已读后不会无限源码阅读。

### 3.3 证据账本和状态拆分

涉及文件：

- `harness/dynamic_validation.py`
- `harness/execution_protocol.py`
- `harness/artifacts.py`
- `tests/test_execution_protocol.py`
- `tests/test_find_split.py`

修改内容：

1. 每次 run 输出：

   ```text
   evidence_ledger.jsonl
   symbolic_execution/evidence_ledger.jsonl
   ```

2. 账本记录：
   - 输入提交时间；
   - 普通目标执行结果；
   - ASan/crash 事件；
   - SymCC feedback ready 时间；
   - feedback 读取时间；
   - exact target hit 证据；
   - generated replay 数量；
   - additional crash 事件。
3. `dynamic_validation.json` 输出 `status_breakdown`。

验收标准：

- 单次实验可以重建 agent 的关键决策时间线；
- off 组和 feedback 组都能用相同指标比较；
- “发现 PoC”“正确提交 PoC”“Grade 通过”不会混在一起。

### 3.4 额外崩溃保存

涉及文件：

- `harness/dynamic_validation.py`
- `harness/artifacts.py`
- `tests/test_additional_crashes.py`

修改内容：

1. 如果输入触发 ASan/crash，但没有 exact target hit：
   - 不算原始候选验证成功；
   - 记录为 `additional_crash_candidate`；
   - 保存输入、命令、栈、request ID。
2. 如果额外崩溃能稳定重放，可以进入 Grade 或单独报告。

验收标准：

- 额外 crash 不污染原始候选；
- 额外 crash 不被丢弃；
- 结果里能同时报告原始候选状态和额外发现状态。

### 3.5 实验汇总工具

涉及文件：

- `harness/experiment_summary.py`
- `harness/cli.py`
- `tests/test_experiment_summary.py`

修改内容：

1. 增加 CLI：

   ```sh
   .venv/bin/python -m harness.cli summarize-experiments <result-dir>...
   ```

2. 汇总字段：
   - arm：off / feedback；
   - target；
   - dynamic status；
   - status breakdown；
   - wall time；
   - tool calls；
   - request 数量；
   - feedback ready/read/unconsumed；
   - exact target hit；
   - generated replays；
   - additional findings。
3. 支持输出 JSON 和 Markdown。

验收标准：

- 多个结果目录可以一次汇总；
- off 和 feedback 能按 target 分组；
- 汇总报告能直接用于后续技术报告和组会材料。

### 3.6 成对实验 runner

涉及文件：

- `harness/cli.py`
- `tests/test_dynamic_pairs_cli.py`

修改内容：

1. 增加 CLI：

   ```sh
   .venv/bin/python -m harness.cli dynamic-pairs <target> \
     --static-report <static_analysis.json> \
     --model <model> \
     --runs 3 \
     --phase-timeout 3600 \
     --results-dir results/experiments \
     --experiment-name <name>
   ```

2. 每个 pair 固定同一组变量：
   - target；
   - static report；
   - candidate id；
   - model；
   - max turns；
   - phase timeout；
   - max iterations；
   - instrumentation；
   - docker params。
3. 每个 pair 内依次运行：
   - `off`：`--symbolic-execution off`；
   - `feedback`：`--symbolic-execution symcc`。
4. 每轮结束后写 `manifest.json`，全部结束后自动生成 `summary.json` 和
   `summary.md`。

验收标准：

- 3×off + 3×feedback 不再需要手工拼接命令；
- 正常 no-PoC / iteration-exhausted 不会中断后续 pair；
- infra failure 会反映在 manifest 和命令返回码中；
- summary 能直接进入实验记录。

## 4. 实验设计

### 4.1 时间预算

正式实验建议使用 1 小时预算：

```sh
--phase-timeout 3600
```

复杂目标可以额外做 2 小时探索性实验：

```sh
--phase-timeout 7200
```

但是 2 小时结果必须单独标注，不能和 1 小时主实验混算。

框架默认不硬编码时间限制。只有显式传入 `--phase-timeout` 时才限制时间。

### 4.2 成功标准

实验结果分三层：

1. PoC generation success：动态阶段生成了技术上可复现的 PoC；
2. Submission success：PoC 被执行协议和动态阶段正确提交；
3. Grade success：PoC 在干净环境中通过最终 Grade。

如果模型已经构造出有效 PoC，但最终 XML/提交格式失败，应记录为提交失败，而不是 PoC 生成失败。

### 4.3 对比组

每个目标至少跑：

```text
off group:      3 runs, 3600s each
feedback group: 3 runs, 3600s each
```

如果资源允许，扩大到 5 次重复。

固定变量：

- 同一目标镜像；
- 同一源码 commit；
- 同一静态报告；
- 同一漏洞描述；
- 同一模型；
- 同一 max output / max turns；
- 同一 PoC 接口；
- 同一时间预算。

### 4.4 目标选择

第一批目标建议：

1. `n132/arvo:57672-vul`：MRuby 环境写屏障 UAF，复杂对象生命周期，适合检验反馈是否减少错误搜索空间；
2. `arvo:62290-val`：之前暴露过额外崩溃和工具噪声，适合检验 additional finding 和噪声隔离；
3. 一个 Ghostscript Type2 charstring 目标：复杂结构化输入，适合检验语法构造与路径反馈；
4. 再从 CyberGym/ARVO benchmark 中选择 2 个 build 稳定、描述清楚、触发条件不同的目标。

暂时不选择构建不稳定或需要复杂外设/QEMU 的目标作为主实验样本。

## 5. 结果分析方法

每组实验不只统计成功率，还要给出失败原因分类。

### 5.1 核心指标

- 是否在预算内生成有效 PoC；
- 是否通过 Grade；
- 首次可执行输入时间；
- 首次 feedback ready 时间；
- 首次 feedback read 时间；
- 首次 exact target hit 时间；
- 首次 ASan/crash 时间；
- agent 工具调用数；
- token 消耗；
- feedback ready/read/unconsumed 数量；
- generated replay 数量和是否改善证据；
- additional crash 数量。

### 5.2 失败分类

每次失败至少归入一类：

1. 没有构造合法输入；
2. 合法输入存在，但没有接近目标函数；
3. 到达目标函数，但没有到达 operation；
4. 到达 operation，但没有触发漏洞条件；
5. 已构造有效 PoC，但提交协议失败；
6. 动态阶段成功，Grade 失败；
7. 工具链或环境问题；
8. feedback 产生但未被读取；
9. feedback 被读取但没有改变后续输入；
10. feedback 误导 agent。

### 5.3 可解释性判断

如果 feedback 组成功，需要回答：

- 它是更快到达目标 operation，还是更快触发崩溃？
- agent 是否读取了 feedback？
- feedback 之后的输入结构是否发生了可解释变化？
- generated replay 是否被 agent 使用？
- 反馈是否避免了 off 组的错误搜索空间？

如果 feedback 组失败，需要回答：

- feedback 没产生、没读取、没帮助，还是误导？
- 是 target anchor 错了，还是 agent 没理解？
- 是否有额外崩溃？
- 是否因为工具噪声或 map mismatch？

## 6. 执行顺序

### 阶段 A：框架稳定化

1. 完成反馈语义字段和 exact target 约束；
2. 完成 evidence ledger；
3. 完成 status breakdown；
4. 完成 additional crash 保存；
5. 完成 no-wait 和 progress nudge；
6. 完成实验汇总 CLI；
7. 跑完整单元测试。

### 阶段 B：单目标校准

1. 用 canary 校准 function/block/operation/truncated 四类反馈；
2. 用 MRuby 57672 跑 off/feedback smoke；
3. 检查 transcript 是否形成稳定反馈闭环；
4. 修正 prompt 或 nudge 参数。

### 阶段 C：小规模对比

1. 选择 3 个 CyberGym/ARVO 目标；
2. 每个目标使用 `dynamic-pairs` 跑 3 次 off 和 3 次 feedback；
3. 统一生成 summary JSON/Markdown；
4. 人工抽查 transcript，确认分类是否准确。

### 阶段 D：扩大样本

1. 扩展到 5 个以上目标；
2. 对有代表性的目标增加重复次数；
3. 输出可解释性分析报告；
4. 判断是否需要继续修改 SymCC 源码中的反馈能力。

## 7. 验收标准

本轮工作不是要求 SymCC 一定显著提高所有目标成功率，而是要求结果变得可解释。

最低验收标准：

1. 所有单元测试通过；
2. 每次 feedback run 都有 `evidence_ledger.jsonl`；
3. 每次 dynamic result 都有 `status_breakdown`；
4. transcript 能看出 agent 是否读取 feedback；
5. function/block 命中不会被误报为 exact target hit；
6. additional crash 能被保存并单独报告；
7. off/feedback 对比报告能区分 PoC 生成、提交、Grade 和反馈质量。

如果这些标准达成，即使样本里仍有失败，也能明确知道失败原因，后续才能继续扩大实验。

## 8. 当前优先级

我建议接下来按这个顺序推进：

1. 先完成或确认实验汇总 CLI，避免后续结果继续手工整理；
2. 对 MRuby 57672 跑一组 1 小时 off/feedback paired run；
3. 从 CyberGym/ARVO 中再挑 3 个目标，先只跑 smoke，确认构建和 PoC 接口稳定；
4. 对稳定目标开始 3×off + 3×feedback 正式对比；
5. 根据 evidence ledger 总结不稳定原因，而不是只看成功率。
