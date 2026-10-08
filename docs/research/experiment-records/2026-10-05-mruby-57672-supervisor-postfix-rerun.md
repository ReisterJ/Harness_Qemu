# MRuby 57672 supervisor postfix 复跑记录

## 1. 元数据

```text
date: 2026-10-05
record_status: contaminated
experimental_validity: invalid_as_clean_off_control
target: targets/mruby-arvo-feedback
candidate_id: candidate_001
model: deepseek-flash
phase_timeout: 3600s
max_iterations: 8
supervisor: rules
symbolic_execution: off
instrumentation: harness protocol disabled, but SymCC artifacts remained visible in target image
result_root: results/experiments/mruby-57672-supervisor-rules-postfix
```

关联记录：

- [MRuby 57672 supervisor ablation 实验记录](2026-10-04-mruby-57672-supervisor-ablation.md)
- [Target-site feedback 受控实验计划](../target-site-feedback-controlled-experiment-plan.md)
- [Validation supervisor 工作计划](../validation-supervisor-work-plan.md)

## 2. 实验问题

本次复跑原本用于检查 supervisor 修复后的行为：

```text
在修复 additional-crash 模板、fuzzing 命令识别和纠偏后继续执行约束后，
rules supervisor 是否能够阻止无意义搜索，并让 worker 回到显式输入 replay？
```

本次结果不能回答：

- 干净的 `off` baseline 表现；
- target-site feedback / SymCC 是否提升 PoC 生成；
- MRuby 57672 静态候选在其他构建配置下是否可复现。

原因是：虽然命令使用 `--symbolic-execution off`，但目标镜像中仍暴露了 SymCC 二进制和反馈 map，worker agent 实际读取并使用了这些材料。

这里的“SymCC 泄漏”指实验处理条件污染，不是宿主机或容器的安全越权：`off` 只关闭了 Harness 的 SymCC 执行协议，没有从 worker 可见的文件系统中移除 SymCC 产物。

## 3. 固定变量

- 目标：`targets/mruby-arvo-feedback`
- 目标镜像：`local/arvo-57672-site-feedback-nogit:20260924-sitefix1`
- 源码 commit：`2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b`
- 静态报告：`targets/mruby-arvo-feedback/static-report-57672-v2.json`
- 普通执行入口：`/out/mruby_fuzzer <ruby-source-file>`
- 检测器：ASan
- 模型：`deepseek-flash`
- 动态阶段预算：3600 秒
- 最大迭代：8
- symbolic execution 参数：`off`
- supervisor：`rules`

## 4. 执行命令

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --symbolic-execution off \
  --supervisor rules \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments/mruby-57672-supervisor-rules-postfix \
  --dangerously-no-sandbox
```

## 5. 结果摘要

| Arm | 状态 | 耗时 | tool calls | primary PoC | additional finding | 备注 |
| --- | --- | ---: | ---: | --- | --- | --- |
| supervisor-rules-postfix | `false_positive` | 2463.55s | 292 | 否 | 否 | supervisor 拦截两次 fuzzing；但 off 组被 SymCC 产物污染 |

结果文件：

```text
results/experiments/mruby-57672-supervisor-rules-postfix/mruby-arvo-feedback/dynamic-20261005T091541Z/dynamic_validation.json
results/experiments/mruby-57672-supervisor-rules-postfix/mruby-arvo-feedback/dynamic-20261005T091541Z/dynamic_transcript.jsonl
results/experiments/mruby-57672-supervisor-rules-postfix/mruby-arvo-feedback/dynamic-20261005T091541Z/supervisor_events.jsonl
```

## 6. Supervisor 行为

本次记录到 2 次 supervisor 事件：

| 序号 | decision | violation_type | 被纠偏行为 |
| ---: | --- | --- | --- |
| 1 | `interrupt` | `background_worker_sprawl` | `nohup timeout 900 /out/mruby_fuzzer -max_total_time=850 ... &` 后台 fuzz worker |
| 2 | `correct` | `broad_fuzzing` | `timeout 280 /out/mruby_fuzzer -max_total_time=240 ...` fuzzing-mode 搜索 |

说明：

- supervisor 能识别并阻止后台 worker 和 broad fuzzing；
- 第二次纠偏后，worker 没有直接结束，而是继续做源码导向的确定性 replay；
- 这说明“纠偏后必须继续至少一轮具体检查”的修复在本次复跑中生效。

## 7. 关键污染点：off 组看到了 SymCC 产物

虽然命令显式指定：

```text
--symbolic-execution off
```

但 transcript 第一条工具调用显示 `/out/` 中存在：

```text
/out/mruby_fuzzer
/out/mruby_fuzzer_symcc
/out/symcc-feedback-map.jsonl
```

随后 worker agent 在分析中直接提到并使用：

```text
SYMCC_FEEDBACK_TRACE
symcc-feedback-map.jsonl
mrb_env_unshare block reachability
```

这条路径可以概括为：

```text
--symbolic-execution off
        ↓
Harness 不启动结构化 SymCC provider
        ↓
容器仍提供 /out/mruby_fuzzer_symcc 和 feedback map
        ↓
worker 通过普通 shell 工具自行发现并运行 SymCC
        ↓
off 组获得了 feedback 组才应有的观测信息
```

因此这不是“SymCC 结果被 Harness 错误写入 `symbolic_execution`”的问题；本轮结果中的
`result.symbolic_execution` 仍为 `null`。污染发生在 worker 自主读取目标镜像材料的层面。

因此本次不是干净的 `off + supervisor` 实验，而是：

```text
symbolic_execution 参数为 off，
但目标镜像仍向 agent 暴露了 SymCC oracle 材料。
```

这会污染后续对比：

- off 组不再代表“无 target-site feedback”；
- worker 对 `site_reached` 的判断包含 SymCC map / trace 影响；
- 本次耗时、行为和结论不能用于估计 supervisor-only 效果。

此外，worker 在早期曾依据 trace/map 给出 `site_reached=true`，随后又因 map 与当前二进制/源码状态不一致而撤回这一判断。该过程说明泄漏不仅改变了搜索策略，还会引入额外的解释噪声；off 组的 `site_reached` 不能当作 Harness 已验证的机器事实。

## 8. 动态验证结论

worker 最终给出：

```text
status: false_positive
primary_success: false
additional_finding: false
submission_failure: false
infrastructure_failure: partial / experimental contamination
analysis_value: high
```

它的主要理由是：

- 多组闭包、Fiber、eval、binding、deep recursion、ObjectSpace 等输入均未触发 ASan；
- 认为候选 UAF 依赖 `mrb_malloc_simple` 内部 GC 与 env stack 生命周期交错；
- 通过反汇编判断 `mrb_full_gc` 只在分配失败路径调用；
- 当前 ASan 默认 allocator 配置下，分配失败更可能由 ASan 直接 abort，而不是向 mruby 返回 NULL；
- 因此本构建下未能复现目标候选。

注意：这个 `false_positive` 只能解释为“当前镜像 / 当前配置 / 当前时间预算下没有复现目标候选”，不能作为漏洞在其他构建条件下不存在的证明。

## 9. 本次复跑的研究价值

本次虽然不能作为干净对照数据，但仍有两个重要价值：

1. 证明 supervisor 的新规则确实能阻止典型无意义策略：
   - 后台 fuzz worker；
   - broad fuzzing；
   - 纠偏后直接终止。
2. 暴露了对照实验设计中的严重隔离问题：
   - `--symbolic-execution off` 不能只关闭 harness 协议；
   - 还必须确保容器内部不可见 SymCC 二进制、map、trace reader、说明文档等 oracle 材料。

## 10. 后续动作

- [x] 准备真正干净的 off target 镜像：
  `local/arvo-57672-off-clean:20261006`，对应 target 目录为
  `targets/mruby-arvo-off-clean/`；
- [x] 对新 off 镜像执行可见性验收：worker 容器内 `/out` 仅保留普通
  ASan/libFuzzer 入口及必要文件；全文件系统中未发现 `*symcc*`、
  `*sym++*`、`*qsym*` 或 `*symcc-feedback*` 路径，环境变量中也没有
  `SYMCC`、`FEEDBACK`、`QSYM` 或 `libcxx` 相关项；
- [ ] 或者在 harness 进入动态容器后，如果 `--symbolic-execution off`，自动隐藏 / 重命名 SymCC 相关产物；
- [ ] 明确实验分层：
  - A：supervisor-only，对照必须没有 SymCC 产物；
  - B：feedback-only，固定 supervisor，比较 off vs feedback；
  - C：综合策略，只在 A/B 清楚后再做；
- [ ] 暂停新增 supervisor 功能，优先修正实验隔离和记录规范；
- [ ] 下一次只跑一对实验，避免 token 和时间成本失控。

## 11. Clean off 镜像验收

构建命令：

```sh
docker build --pull=false --no-cache \
  -f targets/mruby-arvo-off-clean/Dockerfile \
  -t local/arvo-57672-off-clean:20261006 \
  .
```

验收结果：

```text
image: local/arvo-57672-off-clean:20261006
source commit: 2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b
normal binary: /out/mruby_fuzzer
SymCC artifacts: absent
SymCC-related environment variables: absent
```

该镜像只用于 `off` arm；feedback arm 仍使用原来的
`targets/mruby-arvo-feedback` 和带 SymCC 产物的镜像。
