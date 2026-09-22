# SymCC 与 LLM 语义分析的融合方案

## 目标

动态符号执行不负责直接判定漏洞，也不负责独立生成最终 PoC。它负责从
LLM 选择的真实源码切片和具体种子出发，产生一批受约束的输入及执行反馈；
后续由 PoC agent 结合源码、对象生命周期和目标自身的 sanitizer/oracle，
把这些反馈提升为可复现的 PoC。最终验收仍然交给原始 Grade 阶段。

这个边界很重要：SymCC 能很好地解决字节级分支约束，但通常不能自行理解
“先让 env 变黑、再写入年轻对象、最后由 GC 回收并通过闭包读取”这样的高层
生命周期条件。

## 当前流程

启用 `--symbolic-execution symcc` 时，动态阶段按以下顺序运行：

1. `symcc-planner` 阅读静态候选、真实入口和相关源码，复制实际实现及入口
   driver 到 `/work/symbolic/jobs/round-NNN`，并输出受校验的
   `<symbolic_seed_plan>`。
2. Harness 验证路径、源码、参数、种子大小、timeout 和 testcase 上限，
   固定调用 SymCC worker。agent 不直接调用 provider。
3. Harness 在原始目标镜像中回放两类输入：
   - planner 产生的具体种子；
   - SymCC 从这些种子生成的变异样本。
4. Harness 保存完整回放报告，同时把压缩后的反馈交给新的
   `poc-generator`。即使 SymCC 没有命中静态位点，也立即交接；否则 planner
   会在“没有命中”的条件下重复构造源码切片，耗尽动态预算。
5. `poc-generator` 不再调用 SymCC，而是把回放结果当作观察证据，继续进行
   语义状态构造、控制输入、最小化和 3 次以上稳定复现，并写入原始
   `crash-result.xml`。
6. Grade 在新容器中重放最终 PoC；SymCC 的“命中”或“未命中”都不能替代
   Grade。

## 反馈内容

模型看到的是有限摘要，而不是把所有 testcase 的完整输出塞进上下文：

- provider 状态、编译和生成 testcase 数量；
- 原始种子逐个回放的 exit code、sanitizer、输出尾部和匹配 anchor；
- 变异样本的状态统计，以及最多 20 个代表样本；
- `site_reached`、`matched_candidate`、`sanitizer_event` 和距候选的粗粒度
  距离；
- 完整回放证据的位置 `/work/validation/symcc-replay-round-NNN.json`。

完整报告同时保存到结果目录的
`symbolic_execution/replay-round-NNN.json`，因此模型反馈是有界的，实验审计
仍然保留原始证据。

## 为什么原始种子必须回放

SymCC 的外部文件输入在一次 concolic 执行中保持固定长度。对 Ruby、JSON、
协议消息等结构化输入，单字节变异很容易把一个能进入目标语义路径的种子变成
语法错误。若只回放 SymCC 的变异样本，planner 可能已经找到了有效的对象
生命周期结构，但 Harness 会把这条信息丢掉。当前实现先回放具体种子，再回放
变异样本，并在反馈中明确区分 `kind=seed` 和 `kind=generated`。

## 受控实验

Target：`targets/mruby-arvo`，镜像 `n132/arvo:57672-vul`，模型
`deepseek-flash`，同一静态报告，动态墙钟预算 1800 秒，`--max-turns 20000`。
两条命令唯一的实验开关差异是 `--symbolic-execution`：

```bash
VULN_PIPELINE_MODEL=deepseek-flash .venv/bin/vuln-pipeline dynamic targets/mruby-arvo \
  --static-report results/experiments/mruby-env-write-barrier/symcc-mruby-20260920/static-report.json \
  --model deepseek-flash --symbolic-execution symcc --max-turns 20000 \
  --dangerously-no-sandbox \
  --results-dir results/experiments/mruby-env-write-barrier/hybrid-symcc-20260922

VULN_PIPELINE_MODEL=deepseek-flash .venv/bin/vuln-pipeline dynamic targets/mruby-arvo \
  --static-report results/experiments/mruby-env-write-barrier/symcc-mruby-20260920/static-report.json \
  --model deepseek-flash --symbolic-execution off --max-turns 20000 \
  --dangerously-no-sandbox \
  --results-dir results/experiments/mruby-env-write-barrier/hybrid-off-20260922
```

本次成对结果：

| 组别 | 动态耗时 | tool calls | assistant messages | Grade | PoC |
| --- | ---: | ---: | ---: | --- | ---: |
| SymCC 融合 | 1009.4 s | 244 | 12 | passed, 1.0 | 171 B |
| off 对照 | 1603.4 s | 267 | 20 | passed, 1.0 | 688 B |

SymCC worker 自身本轮编译约 5.7 s、执行约 0.6 s；因此这次约 594 秒的
差异不是由“符号执行速度更快”直接造成，而是由反馈改变了 LLM 的搜索策略：
实验组在首轮 SymCC 后就进入语义 PoC 阶段，对照组则持续手工源码分析、调试
构建和输入搜索。

Transcript 中可观测到的非缓存模型 token（input + output + reasoning）为：

- SymCC：481,699；其中 planner 50,791，PoC agent 430,908；
- off：597,204。

这些 token 数来自 transcript 的 `step_finish.part.tokens`，`cache.read` 未
计入非缓存 token。Grade 两组均通过，分别约 15.0 s 和 15.6 s；主要差异
发生在动态验证而不是最终验收。

结果目录：

- SymCC：[dynamic_validation.json](../../results/experiments/mruby-env-write-barrier/hybrid-symcc-20260922/mruby-arvo/dynamic-20260921T172732Z/dynamic_validation.json)
- SymCC 回放：[replay-round-001.json](../../results/experiments/mruby-env-write-barrier/hybrid-symcc-20260922/mruby-arvo/dynamic-20260921T172732Z/symbolic_execution/replay-round-001.json)
- SymCC transcript：[dynamic_transcript.jsonl](../../results/experiments/mruby-env-write-barrier/hybrid-symcc-20260922/mruby-arvo/dynamic-20260921T172732Z/dynamic_transcript.jsonl)
- off：[dynamic_validation.json](../../results/experiments/mruby-env-write-barrier/hybrid-off-20260922/mruby-arvo/dynamic-20260921T174548Z/dynamic_validation.json)
- off transcript：[dynamic_transcript.jsonl](../../results/experiments/mruby-env-write-barrier/hybrid-off-20260922/mruby-arvo/dynamic-20260921T174548Z/dynamic_transcript.jsonl)

## 结论与限制

这次成对实验支持“SymCC 反馈 + LLM 语义构造”比单纯让 LLM 自己搜索更快，
并且没有牺牲最终 Grade 正确性。但这只是一个 target、一个候选和一次成对
重复，不能据此宣称普遍加速。下一步应在相同模型和静态报告下至少做 3 对
重复，并记录成功率、到首个可用 PoC 的时间、到 Grade 通过的时间以及失败类型。
特别是对结构化输入，后续可以加入语法保持变异或候选 seed corpus，但必须
继续保留“原始种子回放”和最终 Grade 边界。
