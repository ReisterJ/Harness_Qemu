# curl SOCKS5 插桩对照实验审计记录

## 1. 审计目的

本记录用于审计 curl SOCKS5 heap-buffer-overflow 的 LLVM 插桩与未插桩动态验证
对照实验，重点确认动态 agent 是否从静态报告、目标配置或运行环境中获得了超出
实验设计范围的漏洞信息。

审计对象是 2026-09-14 生成的实验结果。旧实验和后续收紧静态报告后的实验必须
分开看待，不能混合计算平均值。

## 2. 结论摘要

结论分为两部分：

1. 早期实验存在严重的信息泄漏，结果不能用于插桩效果对比。
2. 后续 `no-call-chain` 实验没有发现新的直接答案泄漏，但静态位点和 root cause
   仍然足够具体，且 curl 的漏洞是已知 CVE，因而不适合直接作为严格的盲测基准。

## 3. 早期实验的问题

早期静态报告包含了完整的漏洞推导过程，至少包括：

- 完整调用链；
- curl CLI 的具体外部入口；
- hostname 的数据流；
- 状态机重新进入的条件；
- `--limit-rate 1024` 的触发方式；
- SOCKS5 代理需要延迟回复的条件；
- 具体的验证步骤和预期 ASAN 栈。

报告中的 `static_call_chain`、`entry_points`、`required_conditions` 和
`verification_plan` 已经接近完整 PoC 设计：

[早期静态报告](../../../results/experiments/curl-socks5-overflow/off/curl-socks5-overflow/dynamic-20260914T031822Z/static_analysis.json#L12)

因此，以下两次实验不应作为有效的 instrumentation/off 对照数据：

- `results/experiments/curl-socks5-overflow/off/.../dynamic-20260914T031822Z/`
- `results/experiments/curl-socks5-overflow/llvm/.../dynamic-20260914T032044Z/`

旧 off transcript 中生成的 PoC 注释直接复述了 CVE、状态机条件和缓冲区大小：

[旧 off transcript](../../../results/experiments/curl-socks5-overflow/off/curl-socks5-overflow/dynamic-20260914T031822Z/dynamic_transcript.jsonl#L23)

这说明旧实验的 agent 并不是从有限静态提示独立推导出完整触发条件。

## 4. `no-call-chain` 实验审计

后续实验使用了收紧后的静态报告。报告只保留：

- `bug_class: heap-buffer-overflow`；
- `location: lib/socks.c:907`；
- 一句高层 root cause；
- 空的调用链、入口、攻击者数据、可达性证据和验证方案。

[收紧后的静态报告](../../../results/experiments/curl-exp-01/static/curl-exp-01/no-call-chain/static_analysis.json#L11)

### 4.1 配置和 prompt 检查

目标配置中的 `attack_surface` 确实描述了 SOCKS5、hostname、长度和 heap buffer，
本身具有较强提示性：

[目标配置](../../../targets/curl-socks5-overflow/config.yaml#L13)

但当前目标使用 `asan` detector，动态 prompt 构建路径不会把这个 `attack_surface`
字段注入 ASAN 动态验证 prompt。检查生成后的 prompt 得到以下结果：

- `known_bugs` 为空；
- 不包含 `CVE-2023-38545`；
- 不包含 grade reference；
- 不包含静态调用链；
- 不包含 `attack_surface` 的 SOCKS5 描述。

因此，在这两次最新实验中没有发现配置文件直接泄漏完整 PoC 的证据。

### 4.2 Transcript 行为

off 实验首先读取候选位置附近的源码，并继续检查 `hostname_len`、`socksreq` 和
buffer 定义：

[最新 off transcript](../../../results/experiments/curl-exp-01/no-call-chain-1800/off/curl-socks5-overflow/dynamic-20260914T060249Z/dynamic_transcript.jsonl#L3)

LLVM 实验也是在读取源码并检查 buffer、状态机之后，才将候选识别为
CVE-2023-38545：

[最新 LLVM transcript](../../../results/experiments/curl-exp-01/no-call-chain-1800/llvm/curl-socks5-overflow/dynamic-20260914T060645Z/dynamic_transcript.jsonl#L28)

这更像是模型根据源码和已有知识进行识别，而不是从运行环境中读取了隐藏答案。
Transcript 中 agent 读取的 `/tmp/vuln-pipeline-opencode.json` 也只有模型配置，
没有静态报告或 PoC 内容。

## 5. 为什么两边仍然很快

最新单次实验数据如下：

| 模式 | 动态验证时间 | 工具调用数 | 动态 agent 消息数 |
| --- | ---: | ---: | ---: |
| off | 223.2 s | 39 | 1 |
| LLVM | 249.9 s | 64 | 18 |

两边都较快的主要原因不是 LLVM 已经显著提高了推导速度，而是：

1. `lib/socks.c:907` 是非常精确的候选位置，agent 可以立即定位到 `memcpy`。
2. `heap-buffer-overflow` 已经限定了问题类型。
3. root cause 虽然没有给出调用链，但已经提示了 hostname 长度和目标 buffer 容量
   的不匹配。
4. curl SOCKS5 hostname overflow 是公开且知名的 CVE，模型可能具备先验知识。
5. LLVM 版本的 instrumentation 只提供执行观测，不会自动降低源码理解和 PoC
   编写成本；本次实验中反而产生了更多工具调用。

因此，“两边都能在几分钟内完成”不能说明 instrumentation 没有价值，也不能说明
存在新的答案泄漏。它首先说明这个候选对当前模型来说信号过强。

## 6. 数据有效性分类

| 实验 | 是否有完整静态报告泄漏 | 是否适合严格对照 | 结论 |
| --- | --- | --- | --- |
| 03:18 off | 有 | 否 | 作废 |
| 03:20 LLVM | 有 | 否 | 作废 |
| 06:02 off | 未发现直接泄漏 | 有限 | 可作为探索性结果 |
| 06:06 LLVM | 未发现直接泄漏 | 有限 | 可作为探索性结果 |

06:02/06:06 两次结果可以说明当前 agent 能够在有限静态提示下完成验证，但不能
作为消除模型先验知识后的严格 instrumentation benchmark。

## 7. 后续实验约束

后续正式对照实验应至少满足以下条件：

1. 使用中性 target 名称，避免名称本身暴露漏洞类型。
2. 静态报告只提供统一格式的位点和漏洞类别，不提供完整验证方案。
3. 对 root cause 设置固定信息等级，不能在不同实验批次中隐式增加触发条件。
4. 不在 `config.yaml` 的 `attack_surface`、`known_bugs` 或其他 prompt hint 中保存
   同一漏洞的 PoC 线索。
5. 优先使用不知名漏洞、合成漏洞或去除公开漏洞文档线索的源码快照，降低模型
   预训练知识造成的混淆。
6. 以“首次有效 PoC 时间”作为主要指标，同时记录总动态时间、工具调用数、首次
   候选执行时间和 instrumentation 准备时间。
7. off 与 LLVM 使用相同的静态报告、模型、超时、容器资源和实验顺序，并进行
   交错多次重复，而不是只比较一组均值。
8. 最终结果仍然必须回到 clean artifact，并由原有 grade 流程独立复现。

本次审计没有修改代码，也没有删除或覆盖已有实验结果。
