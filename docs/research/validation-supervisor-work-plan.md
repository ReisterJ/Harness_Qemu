# Dynamic Validation Supervisor 工作计划

日期：2026-10-04

## 1. 背景

当前动态验证阶段中，worker agent 会读取静态报告、源码和运行反馈，并尝试构造能够复现目标漏洞的 PoC。近期实验暴露出一个重要问题：worker agent 有时会把验证任务转化为低价值搜索，例如启动大规模 fuzzing、长时间等待后台 worker、重复无效方向、忽略已有反馈，导致时间和资源被消耗在不可解释的探索上。

这里的问题不是安全问题。实验运行在沙盒和目标容器中，我们并不担心 agent 执行命令本身“危险”。真正的问题是：某些操作不符合当前研究目标，会污染实验、降低可解释性，并让 off / feedback 对比失真。

因此需要引入一个 Dynamic Validation Supervisor，用来监督 worker agent 的搜索策略，而不是监督系统安全。

## 2. 目标

Supervisor 的目标是：

1. 减少无意义探索；
2. 保持 worker 的行为贴近静态报告、运行反馈和最终 PoC 目标；
3. 防止 worker 把动态验证变成不可解释的 broad fuzzing；
4. 防止 worker 过早提交成功、误报或无证据结论；
5. 提升实验结果的可解释性；
6. 为后续评估 SymCC feedback 是否有效提供更稳定的执行环境。

Supervisor 不负责直接生成 PoC，也不替代 worker 的漏洞分析。它只负责判断 worker 当前策略是否仍然服务于目标漏洞验证。

## 3. 非目标

Supervisor 明确不做以下事情：

- 不作为安全沙箱；
- 不阻止所有“危险命令”；
- 不判断 shell 命令是否会破坏系统；
- 不直接求解漏洞；
- 不直接生成最终 PoC；
- 不替代 Grade；
- 不把 SymCC feedback 的 advisory 结论升级为漏洞证据。

更准确的定位是：

```text
搜索策略监督器 / 分析效率监督器 / validation supervisor
```

## 4. 需要监督的无效策略

建议统一称为 `search_policy_violation`，而不是 `dangerous_command`。

初始分类如下：

| 类型 | 含义 | 典型例子 |
| --- | --- | --- |
| `broad_fuzzing` | 将验证任务变成大范围 fuzzing | `-max_total_time`、大 corpus 扩张、随机长时间搜索 |
| `background_worker_sprawl` | 启动多个后台 worker 且不清理 | 多个 fuzzer 后台进程残留 |
| `blocking_wait` | 通过 sleep / polling 长时间等待 | `sleep 90`、循环检查日志 |
| `source_only_stall` | 长时间只读源码，不提交输入 | 多轮 grep/sed 后仍无 concrete input |
| `feedback_ignored` | SymCC / execution feedback 已返回但没有被用于下一轮输入 | 继续沿旧假设重复构造 |
| `evidence_mismatch` | 结论与证据不一致 | 只进入函数却声称到达漏洞操作 |
| `premature_success` | 未满足证据条件就提交成功 | 无 ASan / crash / oracle 却提交 candidate_ready |
| `premature_false_positive` | 还没有充分验证路径就标记误报 | 只测试一个入口失败就 false_positive |
| `wrong_bug_drift` | 被额外 crash 吸引，偏离原 candidate | 把额外 crash 当作原漏洞提交 |
| `redundant_iteration` | 多轮重复同类无效输入 | 输入结构没有变化，反馈也没有进展 |

## 5. Supervisor 的输入

Supervisor 不需要拥有完整自由探索权限。它主要消费已有的机器可验证材料：

1. worker transcript；
2. execution protocol request / response；
3. evidence ledger；
4. SymCC feedback summary；
5. dynamic iteration records；
6. 当前 static candidate；
7. 当前阶段剩余时间和工具调用数；
8. 容器内资源状态摘要，例如残留进程数量、内存占用、长时间运行命令。

其中 evidence ledger 和 execution protocol 结果优先级高于 worker 自述。

## 6. Supervisor 的输出

Supervisor 输出不应该是长篇分析，而应该是结构化纠偏信息。

建议格式：

```json
{
  "schema_version": 1,
  "decision": "allow | warn | correct | interrupt | block_final_submission",
  "violation_type": "broad_fuzzing",
  "evidence": [
    "worker launched four libFuzzer workers with -max_total_time=280",
    "101 mruby_fuzzer processes were observed in the container"
  ],
  "reason": "This broad fuzzing strategy does not produce interpretable PoC-construction evidence for the reported candidate.",
  "required_next_action": "Stop fuzzing workers. Return to the static candidate and submit one explicit replay input through the execution protocol.",
  "allowed_scope": "Concrete input construction, source reading tied to target branch conditions, execution protocol replay"
}
```

## 7. 干预等级

Supervisor 不应该频繁强制中断 worker。建议分四级：

### 7.1 `allow`

worker 行为正常，不插入反馈。

### 7.2 `warn`

轻微偏离，仅记录，不打断。

例子：

- 连续读源码时间偏长，但仍和目标位点相关；
- 输入变化较小，但仍有合理假设。

### 7.3 `correct`

向 worker 注入强制纠偏消息。

例子：

- worker 准备继续 broad fuzzing；
- 忽略已返回的 feedback；
- 把函数命中误当成漏洞位点命中。

### 7.4 `interrupt`

停止当前低价值操作，要求回到验证协议。

例子：

- 后台 fuzzer 进程大量残留；
- 长时间 sleep / polling；
- fuzzing 进程导致资源压力。

### 7.5 `block_final_submission`

阻止 worker 提交明显无证据支撑的结果。

例子：

- 没有 target operation hit，却提交 candidate_ready；
- 只有额外 crash，却提交为原 candidate；
- 没有稳定 replay，就提交最终 PoC。

## 8. 初始实现策略

建议分两阶段实现。

### 阶段一：Deterministic Supervisor

先不引入新的 LLM agent，使用规则和结构化证据完成最小可用版本。

优先实现以下规则：

1. 检测 broad fuzzing 命令：
   - `-max_total_time`
   - 大规模 corpus 输入目录；
   - 多 worker 并行 fuzzing；
   - `artifact_prefix` 与随机 fuzz search 组合。

2. 检测后台 worker 膨胀：
   - 容器内目标进程数量超过阈值；
   - 同类 fuzzer 进程超过阈值；
   - worker 结束后仍有残留进程。

3. 检测 blocking wait：
   - `sleep N` 且 N 较大；
   - `while` / `watch` / polling loop；
   - 为等待 SymCC feedback 而阻塞。

4. 检测 source-only stall：
   - 超过指定时间或工具调用数仍未提交第一个 concrete input；
   - feedback 已经返回但多轮没有新输入。

5. 检测 final submission evidence mismatch：
   - candidate_ready 必须有具体 PoC 与可重放执行证据；
   - target operation hit 不能被 function hit 替代；
   - additional crash 不能自动等同于原 candidate 成功。

阶段一的重点是稳定实验流程，避免 worker 自己把任务改造成 fuzzing。

### 阶段二：LLM Supervisor

在 deterministic supervisor 稳定后，再引入轻量 LLM supervisor。

触发点应当有限：

1. worker 多轮没有进展；
2. feedback 与 worker 结论冲突；
3. worker 准备提交 candidate_ready；
4. worker 准备提交 false_positive；
5. 发现额外 crash，可能偏离原任务；
6. evidence ledger 显示输入距离目标没有改善。

LLM supervisor 的职责不是重新分析整个漏洞，而是给出短纠偏建议：

```text
你当前方向没有推进目标位点。最新反馈显示输入只进入解析入口，未进入目标操作。
下一轮请围绕 static report 中的对象生命周期条件构造最小输入，不要继续扩大 fuzzing corpus。
```

## 9. 与 SymCC Feedback 的关系

Supervisor 和 SymCC feedback 是不同层次：

- SymCC feedback 提供执行位置、目标到达情况、参考距离、新种子等观测；
- Supervisor 判断 worker 是否正确使用这些观测。

例如：

```text
SymCC feedback:
  target_function_entered = true
  exact_target_reached = false

worker:
  “已经到达漏洞位点，可以提交成功”

supervisor:
  evidence_mismatch，阻止提交，要求继续构造能到达 target operation 的输入。
```

因此 supervisor 可以提升 SymCC feedback 的可解释性：不是单纯把反馈扔给 worker，而是检查 worker 是否误读了反馈。

## 10. 实验设计

引入 supervisor 后，实验不能只比较 off / feedback，否则无法区分 supervisor 和 SymCC 的效果。

建议至少三组：

```text
A. worker only
B. worker + supervisor
C. worker + supervisor + SymCC feedback
```

如果资源允许，可以增加：

```text
D. worker + SymCC feedback without supervisor
```

这样可以回答：

1. supervisor 是否减少无效搜索？
2. supervisor 是否提升 PoC 成功率？
3. SymCC feedback 在 supervisor 约束下是否仍有增益？
4. feedback 的不稳定性是否来自 worker 误读反馈？

## 11. 评价指标

建议记录以下指标：

### 11.1 成功类指标

- 是否在预算内生成有效 PoC；
- 是否通过 Grade；
- 首次有效 PoC 时间；
- 是否发现额外 crash；
- 额外 crash 是否可复现。

### 11.2 策略质量指标

- 第一个 concrete input 提交时间；
- execution protocol 调用次数；
- 有效输入比例；
- 重复无效输入比例；
- feedback 被读取次数；
- feedback 后输入是否发生结构性变化；
- supervisor 纠偏次数；
- supervisor 阻断 final submission 次数。

### 11.3 资源指标

- 后台残留进程数；
- fuzzing worker 启动次数；
- blocking wait 次数和总时长；
- 容器内峰值 RSS；
- opencode rc=137 / OOM 次数。

### 11.4 可解释性指标

- worker 最终结论是否能被 evidence ledger 支撑；
- 是否区分原 candidate 和 additional crash；
- 是否把 function hit / block hit / operation hit 混淆；
- 是否有明确的输入演化链。

## 12. 实现位置建议

初始实现可以放在：

```text
harness/supervisor.py
```

并在动态验证阶段接入：

```text
harness/dynamic_validation.py
harness/agent.py
```

建议新增数据结构：

```text
SupervisorDecision
SupervisorViolation
SupervisorEvidence
SupervisorIntervention
```

建议新增产物：

```text
supervisor_events.jsonl
supervisor_summary.json
```

每次纠偏都应记录：

- 时间；
- worker 当前阶段；
- violation type；
- 证据；
- 采取的干预；
- 干预后 worker 是否改变行为。

## 13. CLI 和配置建议

建议动态验证阶段新增参数：

```text
--supervisor off|rules|llm|hybrid
```

默认初期建议：

```text
--supervisor rules
```

实验中可以使用：

```text
--supervisor off
--supervisor rules
--supervisor hybrid
```

这样可以直接形成可控对比。

目标配置中可以允许覆盖策略，例如：

```yaml
dynamic_validation:
  supervisor:
    mode: rules
    prohibit_broad_fuzzing: true
    max_background_target_processes: 8
    first_input_deadline_s: 300
    max_blocking_wait_s: 20
```

## 14. 分阶段任务清单

### 第一阶段：文档和规则定义

- [ ] 固化 search policy violation taxonomy；
- [ ] 定义 supervisor decision schema；
- [ ] 明确哪些行为只 warning，哪些需要 interrupt；
- [ ] 将现有 fuzzing/OOM 案例整理成 motivating case。

### 第二阶段：规则型 supervisor

- [ ] 实现 `harness/supervisor.py`；
- [ ] 从 transcript 中解析 worker tool call；
- [ ] 检测 broad fuzzing / sleep / polling / background worker；
- [ ] 检测 candidate_ready evidence mismatch；
- [ ] 输出 `supervisor_events.jsonl`；
- [ ] 在 dynamic validation 中注入纠偏消息。

### 第三阶段：资源清理与流程保护

- [ ] worker 被中断或动态阶段结束时清理目标残留进程；
- [ ] 记录目标进程数量和资源峰值；
- [ ] 如果 worker 启动大量后台 fuzzing，自动终止该方向并要求回到 execution protocol。

### 第四阶段：LLM supervisor 试验

- [ ] 设计短 prompt；
- [ ] 只在关键节点调用；
- [ ] 比较 rules 和 hybrid 的差异；
- [ ] 防止 LLM supervisor 变成第二个漏洞分析 agent。

### 第五阶段：对比实验

- [ ] MRuby 57672；
- [ ] ARVO 62290；
- [ ] ARVO 38283；
- [ ] ARVO 55020；
- [ ] 每个目标至少跑 worker only / worker+supervisor / worker+supervisor+feedback；
- [ ] 汇总成功率、耗时、纠偏次数、OOM/rc=137 次数。

## 15. 风险

### 15.1 Supervisor 过度干预

如果规则太强，可能阻止某些合理探索。

缓解方式：

- 初期只拦截明显无效行为；
- 大多数情况先 `correct`，少用 `interrupt`；
- 保留 `--supervisor off` 做对照。

### 15.2 实验变量变多

加入 supervisor 后，实验不再只是 off / feedback。

缓解方式：

- 明确分组；
- 不把 supervisor 效果归因给 SymCC；
- 每次实验记录 supervisor mode。

### 15.3 LLM Supervisor 自身不稳定

如果 supervisor 也是自由 LLM，可能引入新不稳定性。

缓解方式：

- 先实现 rules；
- LLM supervisor 只做短纠偏；
- 不让 LLM supervisor 直接生成 PoC。

## 16. 当前优先级

短期最应该做的是：

1. 先实现 rules supervisor；
2. 首先覆盖 broad fuzzing、background worker、blocking wait；
3. 用刚刚 MRuby off 组启动大量 fuzzer 的案例做回归测试；
4. 确认 supervisor 能阻止 worker 把动态验证变成 fuzzing；
5. 然后再恢复 off / feedback 对比实验。

这比继续细化 SymCC feedback 更优先，因为如果 worker 可以自由启动 broad fuzzing，那么实验比较本身就会失真。

## 17. 第一阶段实施记录

状态：已完成 rules supervisor 的最小可用实现。

当前实现包括：

1. 新增 `harness/supervisor.py`；
2. 新增 `SearchPolicySupervisor`；
3. 新增结构化 `SupervisorDecision`；
4. 支持 `supervisor_events.jsonl` 事件落盘；
5. 动态验证阶段默认启用 `--supervisor rules`；
6. standalone dynamic、dynamic-pairs、run/find 路径都可以传递 supervisor mode；
7. feedback 组和 off 组共用同一个 supervisor 机制；
8. 检测并纠偏以下策略问题：
   - `broad_fuzzing`；
   - `background_worker_sprawl`；
   - `blocking_wait`；
9. 对 `background_worker_sprawl` 增加 best-effort 目标/fuzzer 残留进程清理；
10. 动态阶段计时信息中记录 `supervisor_events`；
11. 单元测试覆盖规则检测、事件落盘、progress nudge、dynamic-pairs 参数传播和 CLI help。

当前不会做的事情：

- 不引入 LLM supervisor；
- 不替 worker 生成 PoC；
- 不分析漏洞语义；
- 不把 supervisor 结论作为漏洞证据；
- 不阻止所有 shell 命令；
- 不把 supervisor 做成安全沙箱。

当前测试结果：

```text
531 passed, 5 skipped
```

下一步建议：

1. 用 MRuby 57672 重跑一次短实验，确认 supervisor 可以阻止后台 fuzzing 膨胀；
2. 检查是否生成 `supervisor_events.jsonl`；
3. 如果 supervisor 纠偏后 worker 能继续构造 concrete input，再进入 1 小时预算实验；
4. 如果 worker 频繁被 supervisor 打断，需要调整规则强度，避免过度干预；
5. 暂时不要引入 LLM supervisor，先用 rules 模式验证实验稳定性是否改善。
