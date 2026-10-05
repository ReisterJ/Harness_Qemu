# Target-site feedback 受控实验计划

本文档用于收敛后续动态验证实验的变量，避免同时比较 supervisor、SymCC、插桩反馈、提示词和目标差异导致实验不可解释。当前阶段的目标不是证明“符号执行一定直接生成 PoC”，而是验证：

1. 搜索策略 supervisor 是否能减少无意义搜索；
2. 在 supervisor 固定开启时，目标位点运行时反馈是否能帮助 agent 更快构造有效 PoC；
3. SymCC / 插桩反馈应该如何表达，才能让 agent 将反馈转化为下一轮输入构造策略。

## 1. 基本原则

### 1.1 单次只跑一对实验

调参阶段不再默认跑 3 对重复实验。每次只运行一个 matched pair：

```text
off arm      : supervisor=rules, symbolic_execution=off
feedback arm : supervisor=rules, symbolic_execution=symcc
```

原因：

- 3 对实验 token 消耗过高；
- 当前仍处于工作流和反馈格式调整阶段，多次重复容易把模型随机性、提示词缺陷和工具链问题混在一起；
- 单对实验足够发现明显的行为问题，例如 agent 是否空转、是否读 feedback、是否启动 fuzzing、是否错误判 false positive。

只有当某个设计已经稳定，并且需要形成报告中的统计结论时，才对少数关键目标做多次重复。

### 1.2 暂时不拆分 SymCC 内部贡献

当前先不单独比较：

```text
trace-only
trace + generated seeds
```

也就是说，短期实验不回答“收益到底来自插桩 trace 还是符号执行 generated testcase”。这一消融实验放到后续阶段。

当前统一称为：

```text
target-site feedback
```

它由预构建 SymCC / 插桩运行时共同提供，包括：

- 输入是否进入目标函数；
- 输入是否到达精确目标操作；
- 当前输入的运行时 trace；
- SymCC 生成 testcase 的有限 replay 结果；
- 是否有 sanitizer / crash / timeout；
- 可能的距离或进展摘要。

报告中应避免直接写成“SymCC 求解显著提升 PoC 生成”。更严谨的表述是：

> 目标位点运行时反馈可能帮助 agent 调整搜索方向；该反馈当前由 SymCC 插桩执行和有限 testcase 生成共同提供，其内部贡献需要后续消融实验进一步区分。

### 1.3 时间预算

正式受控实验使用 1 小时动态阶段预算：

```text
--phase-timeout 3600
```

评价规则：

- 1 小时内产出有效 PoC：成功；
- 超过 1 小时：失败；
- 如果发生 API 余额不足、镜像损坏、执行协议异常等问题，标记为 infrastructure failure，不计入算法失败；
- 如果技术上已经产生有效 PoC，但没有正确提交，需要单独标记为 submission failure，不等同于 PoC 生成失败。

探索性长跑可以使用 2 小时或更长预算，但必须单独标记，不与 1 小时主实验混合统计。

## 2. 变量分层

### 2.1 阶段 A：验证 supervisor 的工程价值

阶段 A 的问题是：

> supervisor 是否能减少无意义搜索，让动态验证更稳定？

这一阶段不启用 target-site feedback。

推荐比较：

```text
A0: supervisor=off,   symbolic_execution=off
A1: supervisor=rules, symbolic_execution=off
```

观测指标：

- 是否启动 broad fuzzing；
- 是否启动后台 fuzzing worker；
- 是否出现残留进程；
- 是否出现 rc=137 / OOM；
- 是否出现长时间 sleep / polling；
- 是否错误地提前判 false positive；
- agent 是否仍能继续构造 concrete input。

阶段 A 的结论不能归因给 SymCC，只能说明 supervisor 对实验稳定性和搜索策略约束是否有效。

### 2.2 阶段 B：验证 target-site feedback 的研究价值

阶段 B 固定 supervisor 开启：

```text
B0: supervisor=rules, symbolic_execution=off
B1: supervisor=rules, symbolic_execution=symcc
```

这一阶段的问题是：

> 在同样的搜索策略约束下，target-site feedback 是否帮助 agent 更快到达目标位点或产出 PoC？

核心指标：

- 1 小时内是否产出有效 PoC；
- 是否通过 Grade；
- 是否出现 sanitizer / crash；
- 是否进入目标函数；
- 是否到达精确目标操作；
- 从动态阶段开始到首次目标函数进入的时间；
- 从动态阶段开始到首次精确目标操作命中的时间；
- 从动态阶段开始到首次有效 PoC 的时间；
- feedback 是否被读取；
- feedback 是否影响下一轮输入；
- supervisor 纠偏次数；
- tool calls、messages、token 使用量。

阶段 B 是当前优先级最高的实验层。

### 2.3 阶段 C：后续消融，不在当前阶段展开

阶段 C 才拆分 target-site feedback 内部贡献：

```text
C0: supervisor=rules, no feedback
C1: supervisor=rules, trace-only feedback
C2: supervisor=rules, trace + generated seeds feedback
```

判断逻辑：

- 如果 `C1 > C0`，说明插桩观测本身有效；
- 如果 `C2 > C1`，说明符号执行生成 testcase 有额外贡献；
- 如果 `C2 ≈ C1`，说明主要收益来自动态观测，而非求解。

当前先不做 C 阶段，避免实验变量过多。

## 3. 推荐执行方式

### 3.1 单目标调参命令模板

每次只跑一对：

```sh
.venv/bin/python -m harness.cli dynamic-pairs <target-path> \
  --static-report <static-report> \
  --model deepseek-flash \
  --runs 1 \
  --arms off feedback \
  --supervisor rules \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments \
  --experiment-name <target-id>-target-site-feedback-pair \
  --dangerously-no-sandbox
```

如果只是验证 supervisor，可先跑无 feedback 的 supervisor 对比。当前 CLI 的 `dynamic-pairs` 主要用于 off/feedback 对照；若需要严格比较 `supervisor=off` 与 `supervisor=rules`，可以使用两条单独的 `dynamic` 命令，保持其他参数一致。

### 3.2 候选目标选择

优先使用已经具备以下条件的目标：

- 静态报告经过清理，不包含完整 PoC 配方；
- target commit 固定；
- 普通 ASan 二进制可用；
- feedback arm 的预构建 SymCC / 插桩二进制可用；
- 运行协议已经通过 smoke test；
- 靶标来自 CyberGym 或已有实验结果，漏洞真实性较可靠。

当前优先目标：

| 目标 | 作用 |
| --- | --- |
| `mruby-57672` | 复杂对象生命周期 / GC 路径，用于观察 feedback 是否帮助进入函数后收缩内部条件 |
| `arvo-62290` | 曾暴露 target anchor、PIE/noise、额外 crash 问题，用于验证失败分类和 additional finding |
| `arvo-38283` | 协议解析类结构化输入，用于扩大样本类型 |
| `arvo-55020` | 二进制格式 / relocation 处理，用于验证非脚本语言输入场景 |

Ghostscript 51089 暂时作为案例分析目标，不进入第一批受控对比，除非其 prebuilt feedback contract 已稳定。

## 4. 成功、失败和中间状态分类

### 4.1 成功

成功必须满足：

```text
valid_poc = true
grade_status = passed
dynamic_time <= 3600s
```

如果动态阶段已经产生 ASan crash，但没有正确提交最终 PoC，需要标记为：

```text
technical_crash_found
submission_failure
```

不能简单算作算法完全失败。

### 4.2 目标接近但未复现

对于 feedback arm，尤其要区分：

```text
target_site_status = none
target_site_status = function_only
target_site_status = intra_function_progress
target_site_status = exact_target_hit
```

其中：

- `none`：没有进入目标函数；
- `function_only`：进入目标函数，但没有到达精确目标操作；
- `intra_function_progress`：进入目标函数，并命中了更接近目标操作的内部块或条件；
- `exact_target_hit`：到达目标操作 marker。

`function_only` 不是成功，也不应直接作为 false positive 证据。它只说明入口路径基本解决，下一步应收缩目标函数内部条件。

### 4.3 失败

失败分类建议如下：

| 分类 | 含义 |
| --- | --- |
| `no_target_evidence` | 没有目标函数或目标操作证据 |
| `function_only_no_progress` | 多轮进入目标函数，但始终无法接近精确操作 |
| `feedback_unconsumed` | feedback 已 ready，但 agent 未读取或未使用 |
| `feedback_consumed_no_improvement` | agent 读取了 feedback，但下一轮输入没有可解释改进 |
| `false_positive_claim_without_exact_negative` | agent 仅凭未崩溃或 function-only 反馈声称误报 |
| `submission_failure` | 已有可复现 crash / PoC，但最终提交协议失败 |
| `infrastructure_failure` | API、Docker、镜像、磁盘、网络、余额、runner 崩溃等环境问题 |

## 5. SymCC / 插桩反馈明确化计划

当前 feedback 的主要问题是：信息存在，但不够“行动化”。agent 能看到：

```json
{
  "target_function_entered": true,
  "target_operation_reached": false,
  "exact_target_reached": false
}
```

但它不一定能把这转化为下一轮输入策略。因此需要把 feedback 从“描述结果”改成“约束下一步搜索”。

### 5.1 反馈命名

在文档和提示词中优先使用：

```text
target-site feedback
```

而不是直接称为：

```text
SymCC result
```

因为当前反馈混合了：

- 插桩执行位置；
- 目标函数 / 目标操作命中；
- 有限距离或近似进展；
- SymCC generated testcase；
- replay 后的 crash / sanitizer 结果。

### 5.2 反馈应包含的核心字段

建议 feedback 至少包含以下结构：

```json
{
  "request_id": "round-003",
  "submitted_input": {
    "target_function_entered": true,
    "target_operation_reached": false,
    "exact_target_reached": false,
    "trace_complete": true,
    "site_status": "function_only",
    "allowed_conclusion": "entry path is solved; exact target operation was not reached"
  },
  "progress_summary": {
    "relative_to_previous": "same_function_no_internal_progress",
    "best_observed_status": "function_only",
    "new_target_relevant_coverage": false
  },
  "recommended_focus": {
    "search_region": "inside_target_function",
    "must_not_do": [
      "do not restart broad entry search",
      "do not claim false positive only from this feedback",
      "do not wait for more SymCC results before constructing the next input"
    ],
    "next_question": "which target-function branch condition prevented the exact operation?"
  },
  "generated_seed_summary": {
    "total": 8,
    "replayed": 8,
    "best_seed_status": "function_only",
    "recommended_seed_paths": []
  }
}
```

其中准确性边界必须写清楚：

- `target_function_entered` 和 `target_operation_reached` 是机器观测；
- `exact_target_reached` 是严格目标 marker 结论；
- `distance` 或 `progress_summary` 只能作为参考，不能单独证明漏洞；
- generated testcase 是候选材料，不是 PoC。

### 5.3 `function_only` 的强制解释规则

当 feedback 显示：

```text
target_function_entered = true
target_operation_reached = false
```

agent 必须按以下格式解释：

```text
Feedback interpretation:
- 入口链路是否已经解决？
- 是否仍需要搜索新的入口？
- 当前缺失的是目标函数内部哪个条件？

Missed condition hypothesis:
- 目标函数内部哪个 if / 状态 / 生命周期条件阻止了目标操作？
- 对应源码位置是什么？
- 当前输入为什么没有满足？

Next input delta:
- 下一轮输入只改变什么？
- 这个改变为什么会让执行更接近目标操作？
- 如何通过 run-input 验证？
```

这条规则的目标是防止 agent 在已经进入目标函数后继续浪费时间做入口搜索、广义 fuzzing 或无意义等待。

### 5.4 `generated seeds` 的使用边界

SymCC 生成的新 testcase 不应被 harness 自动递归喂回去。harness 只做：

- 保存；
- 有限 replay；
- 摘要；
- 标出是否更接近目标；
- 提供路径给 agent。

agent 决定是否读取、改写或基于它构造下一轮输入。

这样可以避免 harness 变成传统符号执行搜索器，也避免把路径爆炸和求解成本引入 PoC agent 的主循环。

## 6. Supervisor 相关修正项

本轮 MRuby 结果暴露一个 supervisor 误判边界：

```sh
grep -c . trap3.c
```

这类普通文件统计命令可能输出纯数字，不应被当作进程数量。后续需要修正规则：

- 只有明确 `ps` / `pgrep` / `pidof` / `/proc` 查询时，才解析纯数字输出为进程数量；
- 普通 `grep -c`、`wc -l`、源码统计和文件统计不应触发 `background_worker_sprawl`；
- 保留对真实后台 fuzzing 的拦截，例如 `nohup ... &`、`-max_total_time`、`-artifact_prefix`、`-workers` 等。

该修正属于实验稳定性修复，不属于新研究功能。

## 7. 单次实验检查清单

每次 pair 实验结束后，至少检查：

1. `summary.md` 中 off / feedback 的状态、耗时和 PoC 结果；
2. `dynamic_validation.json` 中：
   - `result.status`
   - `result.status_breakdown`
   - `result.symbolic_execution.metrics`
   - `timings.dynamic_validation`
   - `timings.supervisor_events`
   - `agent_error`
3. `supervisor_events.jsonl` 是否存在误判；
4. `symbolic_execution/summary.json` 中：
   - feedback ready / read / unconsumed；
   - exact target hits；
   - generated replay 数；
   - SymCC timeout / crash / resource exhausted；
5. `dynamic_transcript.jsonl` 中 agent 是否：
   - 启动 fuzzing；
   - 反复 polling；
   - 读取 feedback；
   - 根据 feedback 改变输入；
   - 错误声称 false positive；
6. `docker ps` 和进程表，确认没有遗留 target / fuzzer / opencode / SymCC 任务。

## 8. 当前推荐推进顺序

短期按以下顺序推进：

1. 修 supervisor 对普通 `grep -c` / `wc -l` 的误判；
2. 强化 target-site feedback 提示，让 `function_only` 变成明确的“目标函数内部条件收缩任务”；
3. 使用 MRuby 57672 跑 1 对 1 小时实验；
4. 如果仍失败，先看失败分类是否变得更可解释，而不是立刻扩大样本；
5. 如果 MRuby 行为改善，再换 `arvo-62290` 或 `arvo-38283` 跑 1 对；
6. 至少两个目标显示稳定趋势后，再考虑每个目标 3 次重复；
7. 最后才考虑 trace-only vs generated seeds 的阶段 C 消融。

## 9. 预期研究结论形式

在当前阶段，报告应使用保守表述：

```text
我们观察到，目标位点运行时反馈能够为动态验证 agent 提供比普通执行结果更细粒度的路径证据，尤其能区分“未进入入口”“进入目标函数但未命中目标操作”和“命中精确目标操作”。这种反馈有助于解释 agent 的搜索方向是否有效，并可能减少无意义的入口搜索和 broad fuzzing。
```

暂时避免过强结论：

```text
SymCC 直接显著提升漏洞 PoC 生成能力。
```

除非后续消融实验能证明 generated testcase 相比 trace-only 有独立增益。
