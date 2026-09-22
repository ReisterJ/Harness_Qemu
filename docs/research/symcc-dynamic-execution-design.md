# SymCC 动态符号执行设计

## 1. 文档状态

本文档描述当前动态验证阶段中 SymCC 的实现方式，以及 SymCC、Harness 和
LLM agent 之间的职责边界。

当前设计的目标不是让 SymCC 独立判断漏洞，也不是让 SymCC 直接生成最终
PoC，而是利用它快速探索输入空间，并把可审计的执行反馈交给负责漏洞语义
分析的 agent。最终结果仍然由原始 Grade 阶段验收。

相关实现：

- [动态验证编排](../../harness/dynamic_validation.py)
- [种子计划协议](../../harness/symbolic/seed_plan.py)
- [SymCC worker 会话](../../harness/symbolic/symcc.py)
- [SymCC 与 LLM 融合实验报告](symcc-llm-fusion.md)

## 2. 设计边界

动态验证阶段包含两个不同性质的问题：

1. 输入应该如何变化，才能满足程序中的字节级分支条件；
2. 输入需要满足什么高层语义和对象生命周期，才能真正触发漏洞。

SymCC 适合处理第一类问题。它可以根据一次具体执行收集路径约束，并生成
满足不同分支条件的输入。第二类问题通常需要理解协议、解析器状态、对象
生命周期、垃圾回收或业务逻辑，不能仅靠符号表达式解决。

因此当前设计采用以下分工：

| 组件 | 主要职责 | 不负责的事情 |
| --- | --- | --- |
| `symcc-planner` agent | 阅读静态报告和源码，选择源码切片、入口和具体种子 | 不直接调用 SymCC，不判定漏洞成立 |
| Harness | 校验计划、调用 SymCC、回放输入、整理反馈 | 不替 agent 理解高层漏洞语义 |
| SymCC worker | 编译插桩程序、执行具体种子、生成约束驱动的输入 | 不生成最终 PoC，不替代 sanitizer 或 Grade |
| `poc-generator` agent | 根据源码和执行反馈构造、调试和稳定化 PoC | 不把 SymCC 的结果直接当成漏洞证明 |
| Grade | 在新的验证容器中重放最终 PoC并做最终判定 | 不参与 SymCC 搜索 |

## 3. 总体流程

启用 `--symbolic-execution symcc` 后，流程如下：

```text
静态报告 + 目标源码
          │
          ▼
symcc-planner agent
  分析源码并生成 symbolic_seed_plan
          │
          ▼
Harness 校验 plan 和源码工作区
          │
          ▼
固定的 SymCC worker
  编译插桩代码、执行种子、生成变异输入
          │
          ▼
Harness 在原始目标容器中回放
  原始种子 + SymCC 生成的输入
          │
          ▼
有限反馈 + 完整回放报告
          │
          ▼
poc-generator agent
  进行语义分析、输入构造和 PoC 调试
          │
          ▼
原始 Grade 阶段
  在新容器中验收最终 PoC
```

这里的“两个 agent”是两个职责不同的动态会话：第一个负责为符号执行准备
实验，第二个负责根据反馈生成最终 PoC。SymCC 的调用由 Harness 固化，agent
不能通过任意 Shell 命令自行决定何时调用或重复调用 provider。

## 4. `symcc-planner` 阶段

### 4.1 Agent 的输入

planner 会获得：

- 静态分析报告中的候选位点；
- 目标仓库、commit 和源码根目录；
- 目标程序入口和运行参数信息；
- detector 类型，例如内存漏洞或逻辑漏洞；
- 前一轮的反馈（如果存在）。

它需要阅读真实源码，而不是只根据静态报告中可能不准确的调用链做猜测。

### 4.2 Agent 的输出

Agent 必须输出一个带标签的 JSON 计划：

```xml
<symbolic_seed_plan>
{
  "schema_version": 1,
  "candidate_id": "candidate-1",
  "working_dir": "jobs/round-001",
  "sources": ["src/target.c", "driver.c"],
  "compile_flags": ["-g", "-O0"],
  "link_flags": [],
  "program_args": ["{input_file}"],
  "seeds": [
    {
      "name": "seed-01",
      "encoding": "text",
      "data": "...",
      "purpose": "reach the parser state"
    }
  ],
  "timeout_s": 120,
  "max_testcases": 64,
  "target_anchors": ["target_function"],
  "notes": "..."
}
</symbolic_seed_plan>
```

计划中最重要的是具体种子，而不是一段抽象的“请自行探索”指令。具体种子
保留了 agent 对输入格式、入口和对象状态的高层理解，SymCC 再以这些种子为
起点处理字节级约束。

### 4.3 Harness 对计划的校验

计划不会直接被执行。Harness 会检查：

- `candidate_id` 是否与当前候选一致；
- 所有路径是否位于符号工作区内；
- 源码文件是否真实存在；
- `program_args` 是否恰好包含一个 `{input_file}`；
- 种子数量是否不超过 16 个；
- 单个种子大小是否不超过 1 MB；
- `timeout_s` 是否在 1～300 秒之间；
- `max_testcases` 是否在有效范围内；
- 编译参数、链接参数和 anchor 是否满足长度限制。

这样可以避免 agent 通过路径穿越、无限输入、无限 testcase 或任意宿主机
命令扩大实验范围。

## 5. SymCC worker

Harness 将 planner 选择的源码切片和 driver 放入独立的符号执行工作区，随后
由固定的 SymCC worker 执行：

1. 编译目标源码和文件输入 driver；
2. 使用 SymCC 对编译过程进行插桩；
3. 对每个具体种子执行一次 concolic execution；
4. 记录输入读取和路径约束；
5. 求解约束并生成候选变异输入；
6. 输出每个种子对应的执行摘要和生成文件。

SymCC 处理的是字节级条件，例如：

```c
if (header == 0x7f && length > 32 && type == 2) {
    vulnerable_path();
}
```

它可以帮助找到满足这些条件的输入。但如果漏洞还要求“先建立某个对象，
再触发状态转换，最后让 GC 回收对象”，这些高层条件仍然需要 agent 根据
源码和运行反馈来构造。

SymCC 使用独立 worker 和固定资源限制，provider 的调用由
[`SymccSession`](../../harness/symbolic/symcc.py) 管理。worker 的输出只是候选
输入，不是漏洞证明。

## 6. 原始种子和生成输入的回放

SymCC 结束后，Harness 不直接相信 provider 的摘要，而是在原始目标容器中
重新执行输入。

回放分为两类：

### 6.1 原始种子

planner 提供的具体种子会首先被回放。它们可能没有触发 sanitizer，但仍然
可能包含重要的高层语义，例如：

- 正确的文件格式；
- 正确的解析器状态转换；
- 合理的对象创建顺序；
- 保持漏洞触发所需的生命周期关系。

### 6.2 SymCC 生成的输入

随后回放 SymCC 生成的输入，用于观察字节级约束求解是否把执行推进到了更
接近候选位点的位置。

只回放生成输入是不安全的，因为结构化输入的单字节变异可能破坏整个语义
结构。当前实现明确使用 `kind=seed` 和 `kind=generated` 区分两者。

每个回放样本会记录：

- 文件路径和输入类型；
- 输入大小；
- 退出码；
- sanitizer 是否出现；
- 是否观察到候选位点 anchor；
- 是否匹配当前候选；
- 输出尾部和错误信息。

## 7. 位点观察和距离反馈

Harness 会从以下信息构造候选观察 marker：

- planner 提供的 `target_anchors`；
- 静态报告中的位置；
- 静态调用链；
- root cause 描述。

回放输出中出现这些 marker 时，就记录 `site_reached`。此外还会记录：

- `sanitizer_event`：是否出现 ASan、UBSan 或 LSan 等错误；
- `matched_candidate`：是否满足当前 detector 的匹配规则；
- `distance_to_candidate`：当前实现提供的粗粒度进展标记。

当前的距离标记不是精确的 CFG 距离，而是：

| 条件 | 距离标记 |
| --- | ---: |
| 已匹配候选 | 0 |
| 到达观测位点 | 1 |
| 出现 sanitizer 但未匹配位点 | 2 |
| 没有可观察进展 | `null` |

对于内存漏洞，候选匹配通常要求位点命中并出现 sanitizer。对于逻辑漏洞，
位点命中可以作为中间反馈，但不能单独证明逻辑错误成立。两种情况都必须
经过最终 PoC 重放和 Grade 验收。

## 8. 反馈如何交给 `poc-generator`

完整回放结果会保存到：

```text
/work/validation/symcc-replay-round-NNN.json
results/.../symbolic_execution/replay-round-NNN.json
```

传给模型的内容是有界摘要，而不是所有原始日志：

- 所有具体种子的结果；
- 最多 20 个代表性的生成样本；
- 各状态的统计数量；
- exit code、sanitizer、位点和 anchor 信息；
- 输出尾部；
- 完整原始报告的路径。

模型可以先阅读摘要快速判断方向，再按需读取完整回放报告。这样可以避免
SymCC 生成大量 testcase 后直接耗尽 LLM 上下文，同时保留完整审计证据。

## 9. PoC agent 阶段

`poc-generator` 不再调用 SymCC。它的职责是把“接近位点的输入反馈”提升为
真正可复现的漏洞 PoC，包括：

1. 对照静态报告重新阅读候选函数和相关数据结构；
2. 判断原始 seed 中哪些高层语义是必要的；
3. 根据回放结果调整输入的结构、顺序和状态；
4. 必要时修改 driver 或调试运行方式；
5. 在干净目标环境中反复执行；
6. 至少进行多次稳定性确认；
7. 生成最终 PoC，并写入原始 `crash-result.xml` 协议。

例如在 mruby 的实验中，SymCC 负责探索输入字节约束，但真正的
`mrb_env_unshare` 生命周期和 GC 条件仍然由 PoC agent 根据源码、seed 回放和
ASan 结果完成构造。

## 10. 轮次和时间预算

当前动态阶段使用固定的 1800 秒墙钟预算：

- planner 阶段最多约 600 秒；
- SymCC 编译和执行由 Harness 控制；
- PoC agent 使用剩余时间，正常情况下最多约 900 秒；
- `max-turns` 使用调用方配置，默认值为 20000，不在 SymCC 编排内部再压低。

设计上保留多轮 seed plan 处理能力，但正常流程在第一轮可用 SymCC campaign
完成后就转交 PoC agent。这样可以避免因为没有观察到文本 anchor，就让 planner
重复阅读源码并不断生成相似计划，最终耗尽动态验证预算。

只有在计划解析失败、工作区不完整或 provider 不可用等情况下，才会产生错误
反馈或提前结束。错误反馈不会被解释为“候选一定是误报”。

## 11. 与 `--symbolic-execution off` 的区别

关闭符号执行时：

```text
静态报告 + 源码
          │
          ▼
单个动态 agent
  自行分析、构造输入和调试 PoC
          │
          ▼
Grade
```

开启 SymCC 时，只增加 planner、SymCC worker、目标回放和反馈交接；最终
PoC 协议及 Grade 阶段保持不变。因此对比实验关注的是：

- 到首个有效 PoC 的时间；
- 到 Grade 通过的时间；
- agent 的工具调用次数和 token 消耗；
- 成功率和失败类型；
- SymCC 反馈是否减少了无效源码搜索。

## 12. 当前限制

当前方案仍有以下限制：

- SymCC 主要适合 C/C++ 和字节级外部输入；
- 结构化输入可能被普通字节变异破坏；
- 文本输出中的函数名不等于严格的代码覆盖证明；
- 逻辑漏洞需要 agent 结合源码判断非法状态或非法操作；
- SymCC 本身不会自动构造复杂对象生命周期；
- 一次实验不能证明普遍加速，需要多个相同条件下的重复实验。

后续可以加入语法保持 seed 变异、真实覆盖反馈、结构化状态摘要和多轮
SymCC campaign，但仍应保留当前的三个边界：Harness 固化 provider 调用、
原始种子必须回放、最终结论必须经过 Grade。
