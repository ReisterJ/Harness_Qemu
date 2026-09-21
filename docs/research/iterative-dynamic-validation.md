# 动态验证内部迭代设计

## 目标

`find` 的静态分析只产生候选漏洞假设，不能保证调用链、入口或触发条件正确。
动态验证需要在同一个候选上进行多轮“假设—执行—反馈—修正”，直到形成能够在
干净目标环境中复现的 PoC，或者获得足够证据把候选标记为不可达、路径错误或
环境阻塞。

这个迭代机制同时适用于内存漏洞和逻辑漏洞。两者只使用不同的最终 oracle：

```text
内存漏洞：外部入口 → 候选位点 → 匹配的 sanitizer 事件 → 稳定复现
逻辑漏洞：外部入口 → 候选位点 → 非法状态 → 错误外部效果 → 稳定复现
```

最终验收仍由原始 `grade` 阶段负责。动态阶段产生的插桩报告、sanitizer 输出、
语义对比和 agent 解释都是证据，不直接等价于已确认漏洞。

## 动态阶段的分层

每个 `StaticFinding` 进入动态阶段后，按以下层次推进：

1. **候选复核**：重新阅读源码，确认静态位点、外部入口和根因。静态调用链
   只是待验证假设。
2. **观测计划**：选择本轮需要观察的函数、源码位置、分支、变量或 sanitizer
   事件，并决定控制输入和触发输入。
3. **观测执行**：构建临时 observed 版本，执行 bounded 的探针、控制输入和
   候选输入，读取统一的 `ExecutionFeedback`。
4. **证据判断**：区分“没有到达”“到达但没有缺陷条件”“触发了不同路径”、
   “环境失败”和“当前证据足以生成 PoC”。
5. **假设修正**：如果证据不足，保留本轮记录，修改入口、输入、状态或观测点，
   进入下一轮；不能只重复完全相同的命令。
6. **clean 复核**：在未插桩目标上执行最终 PoC，确认它不依赖 observed 构建、
   profile 文件或临时探针。

动态阶段内部迭代不需要每轮重新启动 agent。一个动态 agent 会话可以持有源码、
构建目录和观测报告，在受控的轮次上反复执行；harness 负责保存每轮的结构化记录
和限制总轮数、命令超时、输出大小及资源消耗。

## 内存漏洞的迭代 oracle

ASAN、UBSAN、MSAN、KASAN 等报告是重要的运行时 oracle，但“出现 sanitizer 输出”
本身不足以确认静态候选。至少要确认：

- 外部输入确实到达候选函数或源码位置；
- 触发条件由 PoC 输入控制；
- sanitizer 事件的类型与候选 bug class 一致；
- 顶层相关帧或源码位置与候选位点匹配；
- 不是同一次运行中更早发生的无关崩溃；
- 在多个独立运行中稳定出现；
- 不是 OOM、超时、权限或依赖失败。

例如静态候选是某个堆越界写，动态阶段应区分：

```text
候选函数执行，但没有 sanitizer 事件       → reached_no_crash
触发 sanitizer，但位置是另一个函数       → wrong_path
触发同类 sanitizer 且位置匹配             → 进入 PoC/clean 复核
目标无法启动或工具链缺失                  → environment_blocked
```

## 逻辑漏洞的迭代 oracle

逻辑漏洞不能依赖退出码或 ASAN。动态 agent 可以根据静态根因提出本轮 oracle，
但插桩应记录原始观测，不直接返回 `vulnerability=true`。判断至少分为：

```text
site_reached
    → bad_state_observed
    → bad_effect_observed
    → control/trigger 可重复区分
```

例如整数截断候选可以观测原始值、转换后的值、后续分支和输出结果；最终需要证明
“位点执行”与“非法状态”以及“错误外部效果”同时成立。只有函数被调用而没有错误
状态，或者错误状态出现但外部结果仍然正确，都不能生成已验证 PoC。

## 轮次记录格式

每轮保存一个 bounded JSON 记录。模型提供的是假设，provider 提供的是运行观测，
二者必须分开保存：

```json
{
  "schema_version": 1,
  "round_id": 3,
  "candidate_id": "candidate_001",
  "hypothesis": {
    "entry_point": "CLI file input",
    "target_site": "src/parser.c:123",
    "trigger_condition": "attacker-controlled length"
  },
  "observations": {
    "site_reached": true,
    "sanitizer_event": false,
    "bad_state_observed": false,
    "bad_effect_observed": false
  },
  "decision": "revise",
  "reason": "入口可达，但当前输入没有满足候选条件"
}
```

允许的终止状态包括：

- `candidate_ready`：观测版本和 clean 版本都已得到候选 PoC；
- `false_positive`：证明位点不可达、条件不存在或实际路径与候选不符；
- `environment_blocked`：目标、工具链、设备或权限导致验证无法完成；
- `iteration_exhausted`：在预算内仍没有足够证据，不能冒充误报。

只有在证据充分时才能使用 `false_positive`。超时、工具不可用、QEMU/设备失败等
必须保留为环境问题，不能因为没有触发而直接判定误报。

## 与 grade 的边界

动态阶段输出候选 PoC、迭代摘要和观测证据；原始 `grade` 在全新容器中重新执行
PoC。grade 需要重新确认外部入口、候选位置、内存错误或语义错误，以及重复性。
动态阶段的 instrumentation 结果不能直接作为 grade 的通过条件，也不能把 agent
在文本中声称的 `validated` 当成最终结论。

## 结果目录

在现有结果目录下增加迭代记录，不改变旧文件的用途：

```text
dynamic/
  dynamic_validation.json
  dynamic_transcript.jsonl
  iterations/
    round-001.json
    round-002.json
  instrumentation/
    manifest.json
    summary.json
    events.jsonl
```

`dynamic_validation.json` 只记录最终动态状态和摘要；每轮细节进入
`iterations/`，并受统一大小上限约束。
