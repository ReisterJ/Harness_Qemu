# SymCC 反馈稳定化下一阶段工作计划

## 1. 背景和当前判断

当前实验已经说明一件事：把动态符号执行作为反馈材料，确实有机会改善端到端动态验证，但效果不稳定。这个不稳定不是单一原因造成的，也不能简单归结为“样本太少”或“SymCC 没用”。目前更准确的判断是：

1. SymCC 对 PoC 生成的价值主要不是直接求出最终 PoC，而是告诉 agent 当前输入真实走到了哪里、有没有更接近目标位点、是否进入了错误搜索空间。
2. 如果反馈粒度太粗，例如只说明进入了目标函数或目标基本块，agent 很容易误判为已经到达漏洞操作，从而过早切换到崩溃调试阶段。
3. 如果反馈交付时机不好，例如过早打断源码理解，或过晚导致 agent 已经浪费大量时间，效果也会变差。
4. 如果执行噪声没有隔离，例如 PIE/ASLR、Sanitizer 自身崩溃、SymCC 超时、额外崩溃和原始候选混在一起，实验结果会很难解释。

所以下一阶段的目标不是继续堆更多复杂流程，而是把反馈边界、agent 使用方式和实验指标重新收紧，使结果能回答一个具体问题：

> SymCC 反馈到底是在帮助 agent 更快到达目标位点，还是在帮助它更快构造可复现 PoC，或者只是带来了噪声？

## 2. 总体修改原则

### 2.1 PoC agent 仍然是主导者

动态验证阶段仍由 PoC agent 负责：

- 阅读源码；
- 理解漏洞描述和静态报告；
- 构造输入；
- 根据执行结果修改假设；
- 产出最终 PoC 或明确失败原因。

SymCC 不负责替 agent 自动生成最终 PoC。SymCC 只作为后台反馈源，给出可验证的执行事实和有限的导航信号。

### 2.2 SymCC 反馈必须区分事实和启发式信息

agent 可直接信任的事实只有：

- 当前输入是否执行到精确目标 operation marker；
- 当前输入是否进入目标函数；
- 当前输入是否进入目标块；
- 当前输入实际观测到的源码位置；
- 当前输入是否触发崩溃或 sanitizer；
- 轨迹是否完整、是否截断、是否超时、是否未知。

启发式信息只能作为参考，包括：

- CFG 距离；
- 最近观测位置；
- 生成种子是否“看起来更接近”；
- 函数/基本块层面的近似进展。

计划中的核心约束是：`distance=0`、`target_function_entered=true`、`target_block_entered=true` 都不能被解释为“候选漏洞已验证”。只有 `exact_target_reached=true` 或 `target_operation_reached=true` 才能证明该次执行到达了目标操作。

### 2.3 构建问题暂时不进入研究变量

本阶段实验默认目标已经预先准备好：

- 普通目标二进制；
- ASan 目标二进制；
- SymCC 插桩二进制；
- 与 SymCC 二进制匹配的反馈 map；
- 固定 source commit。

动态验证阶段不再让 agent 临时修改编译指令、构造切片或编译 SymCC 版本。构建失败和构建耗时是工程问题，不纳入当前 PoC 生成效果实验。

### 2.4 默认不强加时间限制

框架层面不应硬编码阶段超时。只有用户或实验脚本显式传入 `--phase-timeout` 时才启用时间限制。

正式对比实验建议使用 1 小时预算，即 `--phase-timeout 3600`。对于明显复杂的目标，可以额外做 2 小时探索性实验，但必须和 1 小时主实验分开标记，不能混在同一个成功率里。

## 3. 具体代码修改计划

### 3.1 收紧目标位点描述和解析

涉及文件：

- `harness/symbolic/feedback.py`
- `harness/dynamic_validation.py`
- `harness/prompts/static_analysis_prompt.py`
- `harness/prompts/dynamic_validation_prompt.py`
- `tests/test_symcc_feedback.py`
- `tests/test_symcc_feedback_calibration.py`

修改内容：

1. 继续强化 `observability_targets` 结构，明确区分：
   - `entry_function`：入口或调用链起点；
   - `target_function`：漏洞所在函数；
   - `target_region`：漏洞相关源码范围；
   - `target_operation`：真正用于判定“到达位点”的精确源码行或 marker；
   - `target_condition`：可选，控制漏洞操作的关键分支条件。
2. 如果静态报告只有函数级位点，则标记为 `coarse_anchor`，只能用于探索，不能用于验证。
3. 如果 `target_operation` 无法在 SymCC map 中解析，反馈状态必须是 `feedback_config_invalid` 或 `unknown`，不能回退成函数入口命中。
4. 对 MRuby 57672 这类目标，必须把 `mrb_env_unshare` 的函数进入、`p != NULL` 分支和真正的 stack/env 写操作分开记录。

验收标准：

- 函数命中不会变成 operation 命中；
- 基本块命中不会变成 operation 命中；
- operation marker 缺失不会被静默降级成粗粒度成功；
- 单元测试覆盖 function-only、block-only、operation-hit、trace-truncated 四种情况。

### 3.2 重构 agent 可见的反馈摘要

涉及文件：

- `harness/symbolic/feedback.py`
- `harness/execution_protocol.py`
- `harness/dynamic_validation.py`
- `tests/test_execution_protocol.py`

修改内容：

1. agent 看到的 compact feedback 固定包含：
   - `request_id`;
   - `input_hash`;
   - `trace_status`;
   - `exact_target_reached`;
   - `target_operation_reached`;
   - `target_function_entered`;
   - `target_block_entered`;
   - `allowed_conclusion`;
   - `best_actual_locations`;
   - `generated_replays` 的独立摘要。
2. `best_actual_locations` 必须来自该输入的真实轨迹，而不是静态 CFG 推断。
3. 位置排序优先级：
   - 目标函数内实际观测位置；
   - 目标源码文件实际观测位置；
   - 与调用链相关的实际观测位置；
   - 其他位置。
4. 默认不向 agent 暴露单一 `distance` 字段，避免再次被误读。如果保留距离，只能放在 `heuristic_distance` 下，并明确标记 `not_authoritative`。
5. SymCC 生成的新种子必须绑定自己的输入 hash 和执行结果，不能覆盖原始输入的结果。

验收标准：

- agent 能看到“这次具体执行到哪里了”；
- agent 看不到容易误导的裸 `distance=0`；
- 生成种子和原始输入的结果不会混淆；
- ready feedback 即使没有自动交付，也能在结果里区分为“已手动读取”或“未消费”。

### 3.3 引入证据账本，增强可解释性

涉及文件：

- `harness/dynamic_validation.py`
- `harness/execution_protocol.py`
- `harness/artifacts.py`
- `tests/test_execution_protocol.py`

新增或扩展结果文件：

```text
results/<target>/<run>/evidence_ledger.jsonl
```

每一行记录一个事件，例如：

```json
{"t": 12.4, "event": "agent_input_created", "request_id": "round-001"}
{"t": 13.1, "event": "ordinary_execution_done", "request_id": "round-001", "asan": false}
{"t": 41.7, "event": "symcc_feedback_ready", "request_id": "round-001", "exact_target_reached": false}
{"t": 45.2, "event": "agent_feedback_read", "request_id": "round-001"}
{"t": 80.6, "event": "agent_input_created", "request_id": "round-002", "parent_request_id": "round-001"}
{"t": 120.3, "event": "additional_crash_found", "request_id": "round-002", "asan_type": "heap-use-after-free"}
```

目的：

- 解释 agent 是否真的使用了反馈；
- 区分“反馈没有产生”“反馈产生但未读”“反馈读了但无帮助”；
- 区分 PoC 生成失败、提交协议失败、Grade 失败；
- 支持之后做跨实验统计。

验收标准：

- `dynamic_validation.json` 中给出汇总指标；
- `evidence_ledger.jsonl` 能重建一次动态验证的关键时间线；
- off 组也写账本，只是没有 SymCC 反馈事件，这样两组可比较。

### 3.4 固定动态阶段的迭代协议

涉及文件：

- `harness/prompts/dynamic_validation_prompt.py`
- `harness/dynamic_validation.py`
- `tests/test_find_split.py`
- `tests/test_symcc_iteration_reconciliation.py`

修改内容：

1. 动态阶段提示词改成强约束，而不是建议：
   - 必须先提交一个可执行 baseline/candidate 输入；
   - 必须把每轮输入通过执行协议运行；
   - 如果 SymCC feedback 已 ready，必须读取并记录；
   - 如果没到达目标 operation，必须说明下一轮输入想改变哪个条件；
   - 如果到达 target operation 但未崩溃，进入普通 PoC 调试；
   - 如果发现额外崩溃，必须作为 additional finding 提交。
2. harness 保留温和的 progress nudge：
   - agent 长时间不提交第一个输入时，要求立即提交；
   - feedback ready 但未读时，要求读取；
   - feedback 已读但长时间没有下一步动作时，要求提交下一轮输入或结束。
3. nudge 不能过早打断 agent 的最小源码理解，因此要保留 grace period。
4. 不让 SymCC 反馈阻塞 PoC agent。SymCC 后台执行，PoC agent 可以继续阅读源码或构造下一轮输入。

验收标准：

- transcript 里能看到稳定的 “输入 → 执行 → 反馈 → 下一输入” 循环；
- agent 不会因为 SymCC pending 而停住；
- agent 不会把 feedback pending 当作误报；
- agent 不会在 feedback ready 后无限读源码不继续迭代。

### 3.5 保留并分离额外崩溃

涉及文件：

- `harness/dynamic_validation.py`
- `harness/artifacts.py`
- `tests/test_additional_crashes.py`

修改内容：

1. 如果某个输入触发 ASan/crash，但没有精确命中原始目标 operation：
   - 不算原始候选验证成功；
   - 记录为 `additional_crash_candidate`；
   - 保存输入、命令、ASan 栈、request ID、目标二进制信息；
   - 允许后续进入 Grade 或单独报告。
2. 如果该额外崩溃可稳定重放，它是有价值的新发现，而不是实验噪声。
3. 结果里必须同时给出：
   - 原始候选状态；
   - 额外发现状态；
   - 二者是否使用同一个输入。

验收标准：

- 原始漏洞没有被额外崩溃污染；
- 额外崩溃不会被丢弃；
- 报告中能解释“这个输入没有验证原始 bug，但发现了另一个 crash”。

### 3.6 隔离工具噪声

涉及文件：

- `targets/*/config.yaml`
- `harness/execution_protocol.py`
- `harness/dynamic_validation.py`
- 相关 target builder 或实验脚本

修改内容：

1. 对需要地址稳定性的实验，构建时默认关闭 PIE：
   - CFLAGS/CXXFLAGS 加 `-fno-pie`；
   - LDFLAGS 加 `-no-pie`。
2. 明确记录 ASLR、PIE、Sanitizer、SymCC runtime 的配置。
3. 如果出现 Sanitizer 自身崩溃、runtime 崩溃、trace 权限错误、map mismatch：
   - 标记为 tool/environment issue；
   - 不计为目标程序 PoC；
   - 不计为候选误报。

验收标准：

- 结果里能区分目标程序崩溃和工具链崩溃；
- 关闭 PIE 的配置可追溯；
- feedback map 与二进制不匹配时直接失败，不猜测。

### 3.7 结果状态拆分

涉及文件：

- `harness/dynamic_validation.py`
- `harness/find.py`
- `harness/cli.py`
- `tests/test_find_split.py`

将结果从一个布尔值拆成多个状态：

```json
{
  "target_site_status": "exact_reached | function_only | block_only | missed | unknown | invalid_feedback",
  "poc_status": "valid_poc | crash_observed_not_submitted | no_poc | invalid_submission | agent_blocked",
  "grade_status": "passed | failed | not_run",
  "additional_findings_status": "none | found_ungraded | grade_passed | grade_failed",
  "feedback_quality_status": "useful | consumed_no_improvement | ready_unconsumed | unavailable | misleading"
}
```

验收标准：

- “找到 crash 但没有正确提交”和“没有生成 PoC”分开；
- “超过预算”和“模型异常结束”分开；
- “SymCC 没有反馈”和“SymCC 有反馈但没有引导作用”分开；
- 报告可以解释不稳定发生在哪个环节。

## 4. 实验计划

### 4.1 单元测试和回放测试

先跑单元测试：

```sh
.venv/bin/python -m pytest \
  tests/test_symcc_feedback.py \
  tests/test_symcc_feedback_calibration.py \
  tests/test_execution_protocol.py \
  tests/test_symcc_iteration_reconciliation.py \
  tests/test_additional_crashes.py \
  tests/test_find_split.py

.venv/bin/python -m pytest
```

再用已有结果做离线回放，检查旧 transcript 是否能被新 evidence ledger 解释：

- MRuby 57672；
- Ghostscript Type2 51089；
- ARVO 62290；
- 之前出现 ASan 自身崩溃或额外 crash 的目标。

### 4.2 冒烟测试

先做 MRuby 57672 的单组 feedback 冒烟：

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --symbolic-execution symcc \
  --max-iterations 2 \
  --phase-timeout 600 \
  --results-dir results/experiments/symcc-feedback-smoke-<date> \
  --dangerously-no-sandbox
```

这一步只验证协议稳定性，不评价 SymCC 效果。通过条件：

- 至少提交一个输入；
- 如果 feedback ready，agent 能读取；
- 结果不是因为格式问题变成 invalid submission；
- 机器证据不会被 agent 解释反转；
- 若没有 PoC，能输出合法 `iteration_exhausted`。

### 4.3 正式对比实验

主实验预算改为 1 小时：

```text
off 组：      --symbolic-execution off    --phase-timeout 3600
feedback 组： --symbolic-execution symcc  --phase-timeout 3600
```

每个目标至少跑 3 次。建议第一批目标：

1. MRuby 57672：复杂对象生命周期和 GC 状态，适合观察反馈是否压缩错误搜索空间；
2. Ghostscript Type2 51089：结构化输入复杂，适合观察反馈是否帮助 agent 找到正确解析路径；
3. ARVO 62290：之前暴露额外 crash、目标 anchor 和工具噪声问题；
4. 再从 CyberGym/ARVO 中选择 2 个构建稳定、描述清晰、静态报告不过度泄漏答案的目标。

每次实验固定：

- 同一个目标镜像；
- 同一个源码 commit；
- 同一个静态报告；
- 同一个模型；
- 同一个 max turns/output 设置；
- 同一个 phase timeout；
- 同一个 PoC 提交协议。

记录指标：

- 是否在 1 小时内产生有效 PoC；
- 是否 Grade 通过；
- 首次输入时间；
- 首次 feedback ready 时间；
- 首次 feedback read 时间；
- 首次 exact target reach 时间；
- 首次 crash/ASan 时间；
- 首次有效 PoC 时间；
- 输入迭代数；
- feedback 是否被消费；
- feedback 是否改变下一轮输入；
- 额外崩溃数量；
- token 和工具调用数量。

### 4.4 可解释性分析

每个目标实验结束后，不只统计成功率，还要回答：

1. feedback 组是否更早到达 target operation？
2. feedback 组是否更早产生有效 PoC？
3. 如果 feedback 组失败，是因为：
   - 没有 feedback；
   - feedback 晚到；
   - feedback 粒度不够；
   - feedback 被读了但 agent 没用；
   - agent 误解了 feedback；
   - 目标本身输入构造过难；
   - 工具/环境噪声；
   - 提交协议失败？
4. 如果 off 组成功，是否因为目标本身很容易、漏洞描述接近答案、或 agent 直接读源码就足够？
5. 如果 feedback 组更慢，是否因为 SymCC 反馈打断了正常推理，还是因为工具结果误导？

最终报告不要简单写 “SymCC 加速/没加速”，而是拆成：

- target-site approach 是否加速；
- PoC debugging 是否加速；
- 是否减少错误搜索空间；
- 是否增加额外发现；
- 是否引入额外噪声。

## 5. 工作顺序

建议按以下顺序执行：

1. 补齐 evidence ledger 和结果状态拆分。
2. 收紧 compact feedback，让 agent 看到实际观测位置，移除容易误读的裸距离。
3. 强化 target operation anchor 解析和 coarse anchor 降级逻辑。
4. 修改动态提示词和 progress nudge，使迭代协议稳定，但不阻塞 PoC agent。
5. 完善额外崩溃保存和工具噪声分类。
6. 跑单元测试和离线回放。
7. 跑 MRuby 57672 feedback 冒烟。
8. 跑 MRuby/Ghostscript/ARVO 的 1 小时 off-vs-feedback 对比实验。
9. 根据 evidence ledger 做失败归因和可解释性报告。

## 6. 阶段性成功标准

这一阶段不以“所有目标都成功”为成功标准，而以能否解释结果为标准。达标条件是：

1. 每次动态验证都能说清楚 agent 什么时候提交输入、什么时候拿到反馈、反馈是什么、下一轮是否改变了输入。
2. 不再出现函数命中或基本块命中被误报为漏洞位点命中。
3. 额外 crash 被保留为有价值发现，而不是污染原始候选。
4. off 组和 feedback 组能用同一套指标对比。
5. 对于失败实验，可以明确归因到 agent 行为、反馈质量、目标难度、工具噪声或提交协议，而不是只得到一个“不稳定”的结论。

如果这些条件满足，再扩大样本规模才有意义；否则继续增加 benchmark 只会制造更多无法解释的结果。
