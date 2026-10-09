# MRuby 57672 supervisor ablation 实验记录

## 1. 元数据

```text
date: 2026-10-04
record_status: complete
target: targets/mruby-arvo-feedback
candidate_id: candidate_001
model: deepseek-flash
phase_timeout: 3600s
max_iterations: 8
supervisor: off vs rules
symbolic_execution: off
instrumentation: target default / no exact site feedback
result_root: results/experiments/mruby-57672-supervisor-ablation
```

关联文档：

- [Target-site feedback 受控实验计划](../target-site-feedback-controlled-experiment-plan.md)
- [MRuby bignum ASan 事件记录](../mruby-bignum-allocation-size-too-big-asan.md)

## 2. 实验问题

本次实验属于阶段 A：只验证 supervisor 的工程价值，不启用 SymCC / target-site feedback。

问题：

```text
rules supervisor 是否能减少 worker agent 的无意义搜索，尤其是 broad fuzzing、后台 fuzzing 和长时间低解释性探索？
```

本次不回答：

- target-site feedback 是否提升 PoC 生成；
- SymCC generated testcase 是否有独立贡献；
- 原始 MRuby 57672 UAF 是否一定不可复现。

## 3. 固定变量

- 目标：`targets/mruby-arvo-feedback`
- 目标镜像：`local/arvo-57672-site-feedback-nogit:20260924-sitefix1`
- 源码 commit：`2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b`
- 静态报告：`targets/mruby-arvo-feedback/static-report-57672-v2.json`（该路径已于 2026-10-08 删除；
  当时用的是其中的"行级锚点版"，版本对照见 [2026-10-09 记录](2026-10-09-mruby-57672-static-report-versions.md)）
- 普通执行入口：`/out/mruby_fuzzer <ruby-source-file>`
- 检测器：ASan
- 模型：`deepseek-flash`
- 动态阶段预算：3600 秒
- 最大迭代：8
- symbolic execution：`off`

## 4. 对照变量

| Arm | 配置 |
| --- | --- |
| supervisor-off | `--supervisor off --symbolic-execution off` |
| supervisor-rules | `--supervisor rules --symbolic-execution off` |

## 5. 执行命令

无 supervisor：

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --symbolic-execution off \
  --supervisor off \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments/mruby-57672-supervisor-ablation/supervisor-off \
  --dangerously-no-sandbox
```

有 supervisor：

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --symbolic-execution off \
  --supervisor rules \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments/mruby-57672-supervisor-ablation/supervisor-rules \
  --dangerously-no-sandbox
```

## 6. 结果摘要

| Arm | 状态 | 耗时 | tool calls | primary PoC | additional finding | 备注 |
| --- | --- | ---: | ---: | --- | --- | --- |
| supervisor-off | `iteration_exhausted` | 3340.03s | 177 | 否 | 未收录 | 启动了后台 / 长时间 libFuzzer 搜索 |
| supervisor-rules | `iteration_exhausted` | 561.65s | 113 | 否 | 是，但提交 schema 失败 | supervisor 拦截 broad fuzzing；发现独立 bignum ASan crash |

结果文件：

```text
results/experiments/mruby-57672-supervisor-ablation/supervisor-off/mruby-arvo-feedback/dynamic-20261004T173128Z/dynamic_validation.json
results/experiments/mruby-57672-supervisor-ablation/supervisor-rules/mruby-arvo-feedback/dynamic-20261004T183545Z/dynamic_validation.json
results/experiments/mruby-57672-supervisor-ablation/supervisor-rules/mruby-arvo-feedback/dynamic-20261004T183545Z/supervisor_events.jsonl
```

## 7. Supervisor 行为

`supervisor-rules` 组记录到 1 次纠偏事件：

```text
violation_type: broad_fuzzing
decision: correct
```

被纠偏命令为一次 libFuzzer 式搜索：

```sh
timeout 320 /out/mruby_fuzzer /tmp/corpus \
  -dict=/src/mruby/oss-fuzz/config/mruby.dict \
  -max_len=4096 \
  -timeout=25 \
  -rss_limit_mb=2048 \
  -artifact_prefix=/tmp/crash- \
  -max_total_time=300 \
  -print_final_stats=1
```

解释：

- 当前 supervisor 是事后纠偏，命令已经执行完成后才根据 transcript 产生 correction；
- 因此本轮仍消耗了约 300s fuzzing 时间；
- 但纠偏后 agent 没有继续扩大 fuzzing，而是回到源码分析、显式 replay 和结果记录；
- supervisor 没有直接终止整个动态阶段，最终 `iteration_exhausted` 是 agent 自己提交的。

## 8. Additional finding

`supervisor-rules` 组发现并 replay 了一个独立 ASan 事件：

```text
ASan type: allocation-size-too-big
path: mpz_div_2exp -> mrb_bint_rshift -> int_rshift
relation to candidate_001: unrelated
```

后续在宿主机中用目标镜像复现：

```text
3/3 reproduced
exit code: 1
stack does not contain mrb_env_unshare
```

该事件已经单独记录：

```text
docs/research/mruby-bignum-allocation-size-too-big-asan.md
```

注意：agent 当时确实写入了 `/work/validation/additional-crashes.jsonl`，但格式不符合 harness schema，导致结果中只记录为：

```text
additional_crash_errors:
- line 1: fields do not match the additional-crash schema
```

原因包括：

- 缺少 `finding_id`；
- 缺少 `summary`；
- 缺少 `poc_kind`；
- 缺少 `crash_output`；
- 缺少 `dup_check`；
- `poc_path` 指向 `/tmp/...`，而不是 `/work/validation/additional-crashes/<finding_id>/poc.bin`。

## 9. 结论

```text
primary_success: false
additional_finding: true
submission_failure: true for additional finding schema
infrastructure_failure: false
analysis_value: high
```

解释：

1. 本次没有复现原始 MRuby `mrb_env_unshare` UAF，因此不能计入 primary success。
2. 本次发现了一个稳定的独立 ASan crash，因此应计入 additional finding success。
3. supervisor 对减少无意义搜索有明显效果：耗时从 3340s 降到 562s，tool calls 从 177 降到 113。
4. 当前 supervisor 的主要缺陷是事后纠偏，不是执行前拦截；它能减少后续浪费，但不能阻止当前错误命令先跑完。
5. additional finding 的提交协议需要改进，否则真实 crash 容易因为 schema 错误丢失。

## 10. 后续动作

- [ ] 将 supervisor 从 post-hoc nudge 升级为 pre-action gate，至少对 Bash 命令做执行前审查；
- [ ] supervisor 拒绝命令后应返回修改后的具体策略，并要求 worker 继续下一轮 explicit input，而不是直接结束；
- [ ] 修 additional crash 提示和模板，强制给出完整 JSONL schema；
- [ ] 可选：为 `/work/validation/additional-crashes.jsonl` 提供 helper/template，减少 agent 手写错误；
- [ ] 后续阶段 B 实验中，固定 `--supervisor rules`，再比较 `symbolic_execution off` vs `symcc`。
