# MRuby 57672 clean off / supervisor ablation

## 元数据

```text
date: 2026-10-06
target: targets/mruby-arvo-off-clean
source_commit: 2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b
image: local/arvo-57672-off-clean:20261006
model: deepseek-flash
phase_timeout: 3600s
max_iterations: 8
symbolic_execution: off in both arms
instrumentation: off in both arms
primary_candidate: candidate_001, heap-use-after-free at src/vm.c:398
```

本实验比较 supervisor 关闭和启用 rules 时，agent 对同一个已知 MRuby 候选的复现表现。两组均使用干净 off 镜像；该镜像内没有 SymCC binary、feedback map、runtime 或相关环境变量。

> 静态报告注记：下面命令里的 `targets/mruby-arvo-feedback/static-report-57672-v2.json` 已于 2026-10-08 删除
> （当时用的是其中的"行级锚点版"，location `src/vm.c:398`）。各版本内容与最后使用版见
> [2026-10-09 MRuby 57672 静态报告版本对照](2026-10-09-mruby-57672-static-report-versions.md)。

## 命令

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-off-clean \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --candidate-id candidate_001 \
  --model deepseek-flash \
  --symbolic-execution off \
  --instrumentation off \
  --supervisor off \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments/mruby-57672-clean-off-supervisor/off \
  --dangerously-no-sandbox
```

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-off-clean \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --candidate-id candidate_001 \
  --model deepseek-flash \
  --symbolic-execution off \
  --instrumentation off \
  --supervisor rules \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments/mruby-57672-clean-off-supervisor/rules \
  --dangerously-no-sandbox
```

## 结果

| Arm | 最终状态 | 用时 | Tool calls | Agent messages | Primary ASan PoC | 其他观察 |
| --- | --- | ---: | ---: | ---: | --- | --- |
| supervisor off | `false_positive` | 2055.40s (34m 15s) | 139 | 10 | 未提交 | 找到一个与 `mpz_div_2exp` 大整数右移相关的 ASan allocation-size-too-big，属于先前已记录的同类 finding |
| supervisor rules | `wrong_behavior` | 1955.20s (32m 35s) | 169 | 37 | 未提交 | agent 报告闭包捕获变量在 GC 压力后返回错误对象；结果未形成结构化 logic finding，也未 Grade |

两组都在 3600 秒上限前结束，没有复现并提交静态候选指定的 ASan UAF。两组的 `crash` 均为 null，`grade_status` 均为 `not_run`。因此按“复现指定已知漏洞并产出可验证 PoC”的主要指标，两组都未成功。

Rules 组报告 `/tmp/cand_env.rb` 连续 5/5 次返回 `#<Object>` 而非预期字符串，并有对照输入和 bisection 描述。这是值得保留的逻辑异常线索，但动态结果中的 `logic` 仍为 null，iteration 记录没有可靠的 `site_reached=true`，输入也没有作为结构化 finding 保存，故当前只能记为 agent 报告的未验收观察，不能计为目标漏洞 PoC 或已确认 finding。

Off 组报告的额外 ASan crash 位于 `mpz_div_2exp -> mrb_bint_rshift`，与先前 [MRuby bignum ASan 记录](../mruby-bignum-allocation-size-too-big-asan.md)属于同一根因类别，不作为本轮新的独立 finding 计数。该 crash 也不匹配 candidate_001。

## Supervisor 行为与对照解释

Rules 组记录两次事件：后台 fuzz worker 的 `interrupt` 和 broad fuzzing 的 `correct`。worker 后续确实进行了源码导向的显式 replay；不过 transcript 仍显示 worker 曾发起这两类 fuzz 操作，所以本轮不能据此声称 supervisor 在命令执行前拦截了所有无效操作。

Rules 组耗时比 off 组少约 100.20 秒（约 4.9%），但 tool calls 多 30 次，messages 多 27 次。单次配对且搜索路径不同，时间差很小，不能据此得出 supervisor 提高复现成功率或稳定缩短时间的结论。该结果更支持一个有限观察：rules 组记录了纠偏事件并推进了更多显式、源码导向的验证，但本轮主要 PoC 两组均失败。

Transcript usage 字段求和（provider 账单未记录，缓存读取单列）：

| Arm | input | output | reasoning | cached input read |
| --- | ---: | ---: | ---: | ---: |
| supervisor off | 233,179 | 23,407 | 49,919 | 5,451,008 |
| supervisor rules | 316,632 | 34,634 | 97,224 | 4,960,768 |

按日志中的非缓存 input + output + reasoning 字段计算，rules 组约 448,490 tokens，off 组约 306,505 tokens。该口径是 transcript usage 统计，不等同于唯一上下文长度或实际计费金额。

## 实验控制限制

1. 镜像隔离有效：复核 clean image 后，`/out` 仅有普通 fuzz binary 和必要资源；全文件系统搜索没有发现 SymCC binary、runtime、feedback map 或相关环境变量。Off transcript 中 agent 搜索过 `*symcc*` 路径，但没有找到工具或反馈数据。
2. 静态报告的 `verification_plan` 仍明示“inspect exact SymCC feedback”。Off transcript 因而执行了 SymCC / Harness 路径搜索。这不是实际 SymCC feedback 泄漏，但属于共同输入里的模式提示，可能浪费 off 组预算。两组收到同一报告，因此本轮仍是同一报告下的 supervisor 对照；后续应提供不含 provider 专属指令的中性报告，并由 Harness 按实验组注入反馈。
3. Off 组 iteration 把 coverage 输出中的 `COVERED_FUNC mrb_env_unshare` 记成 `site_reached=true`；但 coverage 证据是函数覆盖（`src/vm.c:376`），不能证明 `stack_copy` 操作行 `src/vm.c:398` 已执行，且结果汇总的 `target_site_status` 为 `unknown`。该 reach 标记不作为精确位点证据。
4. 每组只有一次运行，且 agent 的探索策略和验证深度不相同。本轮是探索性 supervisor ablation，不足以建立统计显著的成功率或时间效果。

## 结果文件

```text
results/experiments/mruby-57672-clean-off-supervisor/off/mruby-arvo-off-clean/dynamic-20261006T045228Z/dynamic_validation.json
results/experiments/mruby-57672-clean-off-supervisor/off/mruby-arvo-off-clean/dynamic-20261006T045228Z/dynamic_transcript.jsonl
results/experiments/mruby-57672-clean-off-supervisor/rules/mruby-arvo-off-clean/dynamic-20261006T055835Z/dynamic_validation.json
results/experiments/mruby-57672-clean-off-supervisor/rules/mruby-arvo-off-clean/dynamic-20261006T055835Z/dynamic_transcript.jsonl
results/experiments/mruby-57672-clean-off-supervisor/rules/mruby-arvo-off-clean/dynamic-20261006T055835Z/supervisor_events.jsonl
```

## 后续

- 若继续研究 supervisor，先解决执行前拦截问题，并在同一中性静态报告下重复成对实验。
- 保存并独立 Grade rules 组的错误对象最小输入；确认是否稳定、是否对应报告中的已知缺陷。
- 后续比较 SymCC 时，保持 supervisor 固定，只改变 feedback；提供反馈的方式应由 Harness 控制，off 镜像仍作为纯对照。
