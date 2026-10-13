# 审计对象清单：要分析哪些实验记录

> 状态：清单（2026-10-09 起草，2026-10-10 整理）
> 配套：[agent-behavior-audit-plan.md](agent-behavior-audit-plan.md)（审计总计划：AQ 问题、干预因子 I1–I9、流程 P0–P6、判据）
> 口径：`results/experiments/**` 下**凡有 `dynamic_transcript.jsonl` 的实验一律在册**——共 **56 个目录 / 288 个 run**（截至 2026-10-10）。
> 无 transcript 的目录只读其总结文档（见 G5）。分组按"能回答什么"排，不按时间。

---

## 0. 分组与优先级

| 组 | 内容 | 用途 | 优先级 |
|---|---|---|---|
| **G1 核心对照** | off 与 symcc 同条件配对（含 klee/hybrid 臂） | 唯一能做"计时 + 判因"的来源 | P1 |
| **G2 反馈机制** | 覆盖率 / 目标点 / 求解器反馈的单臂与半配对 | 回答"反馈到达了吗、被消费了吗、改变行为了吗" | P1 |
| **G3 失败与契约** | 预算 / 看门狗 / 监督规则 + 全部失败 run | 回答"为什么失败、损失在哪" | P1 |
| **G4 工程冒烟与世代桥接** | 每个 1–2 run 的调试波（约 25 个目录） | 只用于干预标注（I1–I9）与世代划分 | P2 |
| **G5 无 transcript** | 3 个目录 | 读总结文档 | P3 |
| **G6 仅附录** | canary（校准分类器）、手工调试系列 | 不做效果结论 | P3 |

**互证文档（每个 G1 套件都要一起读）**：各目录下的 `records.jsonl`（wave 级 wall/first_asan/status）、`SUMMARY.md` / `summary.txt` / `RESULTS.md` / `comparison.md` / `final-report.md` / `README.md` / `ANALYSIS.md`。
⚠️ 这些文档里的数字都是**旧结论**，本次审计要**复核而不是引用**。

---

## 1. G1 核心对照（判效果与判因）

### 1.1 主表

| # | 实验（记录位置） | 日期 | 目标 | 组成 | 既有结论（待复核） | 审计用途 | 陷阱 |
|---|---|---|---|---|---|---|---|
| G1-1 | `mruby-env-write-barrier/symcc-mruby-20260920/pairs/{pair-1..5, pair-2-maxturn-20000}` | 09-18~09-20 | mruby 57672 | 6 个配对 | pair-1：SymCC 1530s / OFF 无（截断）；pair-2：392s / OFF `agent_failed`@913s；pair-3：**419s vs 730s（1.74×）**；pair-4：双无；pair-5：OFF 581s 赢 / SymCC 只得 SEGV；maxturn：SymCC 890s、1230s、无 / OFF `agent_failed` | **速度报告 13 组配对的主来源**；逐组解剖 UAF 到达路径 | 早期 plain 世代（无 coverage 块）；上限设置不对称 |
| G1-2 | `mruby-env-write-barrier/{hybrid-off-20260922, hybrid-symcc-20260922}` | 09-22 | mruby 57672 | 1 配对 | **850s vs 1424s（1.68×）** | 与 pair-3 组成唯二"双臂都成功"的计时对 | 需确认两臂 prompt/协议差异 |
| G1-3 | `mruby-async-paired-20260923` | 09-23 | mruby 57672 | 1 配对（2 run） | **SymCC 406.7s validated vs OFF 1528s 未提交**；工具调用 92 vs 257；token 表在 `comparison.md` | **最强单对（3.76×）**；已探明"该臂唯一一次读 sidecar 反馈发生在崩溃之后" | async 侧车与协议强制同时在场，需分离 |
| G1-4 | `arvo-symcc-paired-20260923`、`arvo-symcc-async-20260923` | 09-23 | arvo 62290 | 1 配对 + 1 单臂 | 两臂均 `agent_blocked`（"测试不理想"） | 失败样本；跨协议形态（async）对照 | 目标本身先失败，别当效果证据 |
| G1-5 | `symcc-target-site-feedback-20260924`（`pairs/arvo-57672`、`paired-final-v2..v7`、`strict-paired`、`post-nopie-crash-sidechannel-*`、`feedback-payload-v1*`） | 09-23~09-24 | mruby 57672 + arvo 62290 | 33 run：validated 10 / invalid 7 / agent_blocked 6 / 无 7 / reached_no_crash 3 | v2：OFF 983s validated / SymCC 截断；v3：SymCC 611s 但**提交被路径规则拒**；v4：OFF 443s / SymCC 1276s `reached_no_crash`；v5~v7 为 62290 | **target-site 反馈世代的全部证据**；契约损失样本集中（v3） | 报告版本与反馈 payload 同时换过；静态报告见版本对照表 |
| G1-6 | `cybergym-symcc-followup-20260928`（`pairs`、`runs`、`shared`） | 09-28 | arvo 38283 / 55020 / 62290 | 10 run | 38283：SymCC 195.3s vs OFF 444.6s（3/3 PoC）；55020：OFF 162.5s vs SymCC 379.1s；62290：双 `reached_no_crash` | CyberGym 三目标的唯一历史配对；含 55020 反例 | 规模小；需确认两臂镜像/驱动差异 |
| G1-7 | `symcc-anchor-20261009/arvo-38283` | 10-09 | arvo 38283 | 3 配对（6 run） | **6/6 validated**；OFF 中位 45.3s / SymCC 中位 74.1s；focus 首轮即 hit | **coverage 世代**唯一干净配对；验证"锚点→focus→策略"链路 | 任务过易（首轮即崩），计时差异主要来自协议开销 |
| G1-8 | `symcc-retest-20261009/arvo-38283`（17 配对）+ `arvo-62290`（1 配对） | 10-08~10-09 | arvo 38283 / 62290 | 35 run：validated 12 / invalid 11 / reached_no_crash 5 / agent_blocked 4 | OFF 中位 479s（10/16 validated）vs SymCC 中位 753s（2/16）；另有静态报告换版实验（`STATIC-REPORTS-COMPARISON.md`） | **最大样本**；失败组与契约损失主矿脉 | **OFF 臂污染**：至少 6 个 off run（group-1/11/12/14/15/16-off）触碰了镜像内 SymCC 二进制或 feedback map——审计时必须逐 run 标注，不能整波当"无助力基线" |
| G1-9 | `ghostscript-type2-51089`（`harness-symcc-20260921*`、`hybrid-off/symcc-20260922*`、`advisory-sidecar-20260922`、`manual-*`、`build-agent-symcc-20260922`、`sidecar-*`） | 09-21~09-23 | Ghostscript Type2 51089 | 31 run：validated 7 / agent_blocked 6 / invalid 2 / 无 16 | 存在 symmetry 配对与手工调试系列 | sidecar/提示型反馈对策略的影响；含大量工程波 | `manual-*` 是调试记录，不能计入效果 |
| G1-10 | `canary-klee`（`template-paired` 13、`controlled-20260919` 4、klee 系列） | 09-18~09-21 | canary | 31 run：validated 27 | canary ~数秒级 | **分类器校准与 M4 契约检查**；不进真实结论 | 目标是玩具级 |
| G1-11 | `curl-exp-01`（22）、`curl-cve-2023-38039`（9）、`curl-socks5-overflow`（4） | 09-13~09-14 | curl | 35 run | 静态报告 ablation（location/root cause/无调用链）；已有审计文档 `docs/research/experiment-audits/curl-socks5-instrumentation-audit.md` | **提示文本（静态报告）对行为的影响**——AQ5 的直接证据 | provider-trace 世代；早期波无统一口径 |

### 1.2 G1 的数字锚点（扫描器必须对上，否则不进结论阶段）

| 锚点 | 期望 |
|---|---|
| `mruby-async-paired-20260923` | OFF 257 次调用 / 目标类事件 1528.0s；SymCC 92 次 / 406.7s |
| `symcc-anchor-20261009` | 首崩中位 OFF 45.3s、SymCC 74.1s |
| `symcc-retest-20261009` | 首崩中位 OFF 479s、SymCC 753s |

---

## 2. G2 反馈机制（判"反馈是否被消费"）

| # | 实验（记录位置） | 日期 | 反馈类型 | 组成 | 审计用途 |
|---|---|---|---|---|---|
| G2-1 | `mruby-57672-coverage-focus-3600` | 10-08 | 覆盖率 + focus 块 | 1 run（validated，约 1770s） | **coverage 世代正样本**：反馈到达时刻、被消费方式、断点后的行为迁移 |
| G2-2 | `mruby-57672-coverage-feedback-smoke` | 10-08 | 覆盖率 | 1 run（agent_blocked） | 反馈世代失败样本（对照 G2-1） |
| G2-3 | `symcc-target-site-feedback-20260924/{feedback-payload-v1, feedback-payload-v1-full-1800, ...-arvo62290}` | 09-24 | sidecar 反馈 payload | 3 run | 反馈"给什么、给多少"的消融 |
| G2-4 | `mruby-57672-symcc-{fixed,trusted,trusted2,check,converged,nosup}-2026*` | 10-06~10-07 | provider instrumentation（`report/<label>.json`、`events.jsonl`） | 6 run | provider-trace 世代的干预形态与失败样本（含 `invalid_submission`、`false_positive`） |
| G2-5 | `symcc-feedback-{consumption-metrics, final-status, followup-nudge, ledger, no-wait, stabilization-smoke, stabilization-smoke2, stabilization-watchdog-smoke1..8}-20261001`、`symcc-feedback-paired-smoke-20261002`、`symcc-feedback-batch-20261004` | 09-30~10-04 | sidecar feedback | 17 run | **"反馈被消费"的埋点实验**：到达、去重、超时、再提示、ledger 统计（失败形态全覆盖：agent_blocked / invalid_submission / iteration_exhausted / reached_no_crash / not_reached） |
| G2-6 | `supervisor-feedback-batch-20261004`、`supervisor-smoke-20261004(+rerun)` | 10-04 | supervisor 反馈 | 10 run | 规则纠偏是否改变行为（AQ6 交叉） |
| G2-7 | `ghostscript-type2-51089/{advisory-sidecar-20260922, sidecar-20260922, sidecar-agent-reach-20260922, build-agent-symcc-20260922}` | 09-22 | advisory 提示 / sidecar | 9 run | 另一目标上的"提示是否被采纳"证据 |

---

## 3. G3 失败与契约（判"为什么失败、损失在哪"）

### 3.1 全量失败清单（数据源）

`runs_index.csv` 的 `status` 列即全量清单（288 行）。现状汇总：

```text
validated 104   agent_blocked 48   invalid_submission 36   reached_no_crash 18
iteration_exhausted 13   false_positive 7   agent_failed 5   wrong_behavior 1
not_reached 1   (未写盘/空) 55
```

审计动作：**按 status 分组逐类采样复盘**（每类 ≥2 例到逐回合），并对 `invalid_submission`（36 例）做**事后重放**——判定"其实已找到却被契约吃掉"的真实比例。

### 3.2 专项实验（预算 / 监督 / 看门狗）

| # | 实验（记录位置） | 日期 | 干预 | 组成 | 已知形态 |
|---|---|---|---|---|---|
| G3-1 | `mruby-57672-supervisor-ablation` | 10-04 | supervisor rules | 2 run | 双 `iteration_exhausted`；含已记录的 bignum 附加 crash（见 `docs/research/mruby-bignum-…-asan.md`） |
| G3-2 | `mruby-57672-supervisor-rules-postfix`、`mruby-57672-clean-off-supervisor`、`clean-supervisor-repeat(-2)-20261006` | 10-05~10-06 | 修复后 supervisor | 6 run | `false_positive`×2、`wrong_behavior`、`reached_no_crash`、`agent_failed` |
| G3-3 | `mruby-57672-{off,symcc}-rollback-20261008-no-iteration-cap`（含 `-3600`） | 10-08 | 无轮次/迭代上限 | 4 run | OFF 2915s 零事件 vs SymCC 1765s 崩溃（速度报告 §2 行 12/13） |
| G3-4 | `mruby-57672-symcc-{nodeadline-check, timeout-check, git-rollback-smoke, rollback-smoke}-20261008`、`symcc-rollback-20261007` | 10-06~10-08 | 时限/看门狗调试 | 5 run | `agent_blocked`/`reached_no_crash`/无 |
| G3-5 | `mruby-dynamic-pairs-smoke-20261002`、`off-generic-ledger-smoke-20261002`、`symcc-feedback-paired-smoke-20261002` | 10-02 | 契约/ledger 冒烟 | 4 run | 契约类失败样本 |

---

## 4. G4 工程冒烟与世代桥接（只做标注，不做效果）

以下目录每个只有 1–2 个 run，用途是**判定该 run 属于哪一代、哪些干预在场（I1–I9）**，以及为 G2/G3 提供时间线样本：

```text
mruby-57672-symcc-{check,converged,fixed,git-rollback-smoke,nodeadline-check,nosup,
  rollback-20261007,rollback-20261008-no-iteration-cap,rollback-smoke,timeout-check,
  trusted,trusted2}                                   ← 12 个目录 / 12 run
symcc-feedback-stabilization-smoke{,2}-20261001、
symcc-feedback-stabilization-watchdog-smoke{1..8}-20261001   ← 10 个目录 / 10 run
（另有 5 个 `symcc-feedback-{consumption-metrics,…}-smoke-20261001` 与 G2-5 重叠）
```

共约 22 个目录（不与 G2 重叠部分）/ 22 个 run。**禁止**用它们计算倍速或胜负。

---

## 5. G5 无 transcript 的目录（只读文档）

| 目录 | 处理 |
|---|---|
| `mruby-57672-rollback-20261008-analysis/` | 读其结论文档，作为 10-08 对照的交叉引用 |
| `symcc-status-deck-20261009/` | PPT 构建目录，跳过 |

（脚手架与汇总日志已迁至 `agent-behavior-audit/`，见 §8。）

---

## 6. G6 排除 / 仅附录

| 对象 | 理由 |
|---|---|
| `canary-klee` 的真实结论 | canary 是玩具目标，只用于分类器校准与契约检查（G1-10） |
| `ghostscript-type2-51089/manual-*`、`manual-prebuilt-*` | 手工调试系列，非受控实验 |
| `curl-*/blind`、`curl-*/llvm` 早期波 | 无统一口径；引用已有审计文档而不重新判定 |
| `symcc-retest-20261009` 中 OFF 臂的历史定位 | 该臂被污染（见 G1-8 陷阱列），只能作为"off 臂带 SymCC 资产"的特殊样本 |

---

## 7. 建议的批次与产出

| 批次 | 对象 | 产出 | 预估 |
|---|---|---|---|
| B1（判因主线） | G1-1/2/3/7/8（mruby 09-20 六对、hybrid、async、anchor、retest）+ §1.2 三锚点校验 | 机制判据矩阵（M1–M5 × 世代）+ ≥3 个案例解剖 | 最大 |
| B2（反馈消费） | G2 全部 + G1-5 | "反馈到达/被消费/行为迁移"统计表 + 失败样本 | 中 |
| B3（失败与契约） | G3 全部 + 全量 status 清单 | `FAILURES.md`：分类×数量×逐例复盘 + `invalid_submission` 重放结论 | 中 |
| B4（提示与报告消融） | G1-11 + G1-5 的静态报告版本 | 静态报告文本对行为影响的对照表 | 小 |
| B5（附录校准） | G1-10 + G4 + G5 | 分类器校准记录、世代/干预标注表 | 小 |

每个 run 的六项基础指标（`runs_index.csv` 已含大部分）：
`T_target`、`executions/turn`、侦察/建造占比、提示到达时刻、是否提交、`result.status`。

---

## 8. 现有脚手架与已知坑（交接给实现）

- 脚手架与汇总日志：`results/experiments/agent-behavior-audit/` —— `logs/G1-core-pairs|G2-feedback|G3-budget-failure/`（254 run 目录 / 2,220 文件，硬链接，含全部 288 transcript + 伴随文件）、`manifest.csv`（逐文件映射）、`collect_logs.py`（重建）、`README.md`（收集规则与排除项）。
- 扫描脚本：`mechanism_scan.py`（288 transcript → `tables/runs_index.csv`/`turn_kinds.csv`）、`mechanism_pairs.py`（→ `tables/pairs.csv`/`PAIRS.md`，41 对）。**注意**：在 `results/` 内（gitignore）。
- 提取口径与 6 个坑见总计划 §6（read 工具用 `filePath`；时间戳在 `state.time`；首 token 判定执行；agent 自述与 harness 提示分离；缺 `summary.json` 记 unknown；`cat` 包装脚本不算执行）。
- 本清单中的既有数字全部来自旧文档/旧脚本，**审计阶段要复核**；对不上的以 transcript 为准并记录差异。
