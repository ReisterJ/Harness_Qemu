# SymCC 反馈稳定化实验目标矩阵

这份清单用于下一阶段的 `dynamic-pairs` 对比实验。目标是扩大样本规模，同时避免把构建问题、手工命令差异和静态报告差异混进实验变量。

机器可读版本见：

```text
docs/research/symcc-feedback-experiment-targets.json
```

## 1. Ready 目标

这些目标当前具备：

- target config；
- 普通 ASan/clean 执行入口；
- prebuilt SymCC 配置；
- feedback map；
- 静态报告；
- 可由 `dynamic-pairs` 直接运行的路径。

| ID | Target path | Static report | 目的 |
| --- | --- | --- | --- |
| `mruby-57672` | `targets/mruby-arvo-feedback` | `targets/mruby-arvo-feedback/static-report-57672-v2.json` | 复杂对象生命周期和 GC 状态；验证反馈是否减少错误搜索空间 |
| `arvo-62290` | `targets/arvo-62290-experiment` | `results/experiments/symcc-target-site-feedback-20260924/shared/arvo-62290-static-report.json` | 曾暴露 target-anchor、PIE/noise、额外 crash 问题；检验 failure category 和 additional finding |
| `arvo-38283` | `results/experiments/cybergym-symcc-followup-20260928/targets/arvo-38283` | `results/experiments/cybergym-symcc-followup-20260928/targets/arvo-38283/static_analysis.json` | 协议解析类结构化输入，扩大到 FreeRADIUS TACACS |
| `arvo-55020` | `results/experiments/cybergym-symcc-followup-20260928/targets/arvo-55020` | `results/experiments/cybergym-symcc-followup-20260928/targets/arvo-55020/static_analysis.json` | 二进制格式/重定位处理，扩大到 binutils |

## 2. 暂缓目标

| ID | 原因 |
| --- | --- |
| `ghostscript-51089` | 当前可用配置主要是 manual/build-style SymCC，不完全符合稳定化后的 prebuilt feedback contract。它适合作为案例分析，但不进入第一批受控 `dynamic-pairs`。 |

## 3. 推荐正式实验命令

正式实验建议每个目标先跑：

```text
3 × off + 3 × feedback
```

统一 1 小时预算：

```sh
--phase-timeout 3600
```

### MRuby 57672

```sh
.venv/bin/python -m harness.cli dynamic-pairs targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --runs 3 \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments \
  --experiment-name mruby-57672-feedback-paired \
  --dangerously-no-sandbox
```

### ARVO 62290

```sh
.venv/bin/python -m harness.cli dynamic-pairs targets/arvo-62290-experiment \
  --static-report results/experiments/symcc-target-site-feedback-20260924/shared/arvo-62290-static-report.json \
  --model deepseek-flash \
  --runs 3 \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments \
  --experiment-name arvo-62290-feedback-paired \
  --dangerously-no-sandbox
```

### ARVO 38283

```sh
.venv/bin/python -m harness.cli dynamic-pairs \
  results/experiments/cybergym-symcc-followup-20260928/targets/arvo-38283 \
  --static-report results/experiments/cybergym-symcc-followup-20260928/targets/arvo-38283/static_analysis.json \
  --model deepseek-flash \
  --runs 3 \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments \
  --experiment-name arvo-38283-feedback-paired \
  --dangerously-no-sandbox
```

### ARVO 55020

```sh
.venv/bin/python -m harness.cli dynamic-pairs \
  results/experiments/cybergym-symcc-followup-20260928/targets/arvo-55020 \
  --static-report results/experiments/cybergym-symcc-followup-20260928/targets/arvo-55020/static_analysis.json \
  --model deepseek-flash \
  --runs 3 \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments \
  --experiment-name arvo-55020-feedback-paired \
  --dangerously-no-sandbox
```

如果实验中断，使用相同命令追加：

```sh
--resume
```

## 4. 结果整理命令

每个目标完成后，重新生成摘要：

```sh
.venv/bin/python -m harness.cli summarize-experiments results/experiments/<experiment-name> \
  --json-out results/experiments/<experiment-name>/summary.json \
  --markdown-out results/experiments/<experiment-name>/summary.md
```

跨目标汇总时可以传多个根目录：

```sh
.venv/bin/python -m harness.cli summarize-experiments \
  results/experiments/mruby-57672-feedback-paired \
  results/experiments/arvo-62290-feedback-paired \
  results/experiments/arvo-38283-feedback-paired \
  results/experiments/arvo-55020-feedback-paired \
  --json-out results/experiments/symcc-feedback-batch-summary.json \
  --markdown-out results/experiments/symcc-feedback-batch-summary.md
```

