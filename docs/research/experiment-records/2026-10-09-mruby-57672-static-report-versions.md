# MRuby 57672（arvo 57672）静态报告版本对照

> 记录日期：2026-10-09。**本文是"某次 mruby 实验用的是哪份静态报告"的唯一对照表**；
> 其他文档（实验记录、计划、报告）提到 mruby 报告时请链接本文，避免同名不同内容的混淆。

背景：mruby-57672 前后用过 **6 种内容**的静态报告，散落在 `results/experiments/` 与 `targets/` 下，
其中 `targets/mruby-arvo-feedback/static-report-57672-v2.json` 已于 2026-10-08 随目录一并删除
（提交 `a1bb97d6e` *"remove the target-site feedback experiment targets"*），且它本身还有两个不同内容的版本。
复查实验时极易张冠李戴，故立此表。

`findings hash` = 对该报告 `findings` 字段做规范 JSON 序列化后的 sha256 前 16 位，
用于跨 run 拷贝比对（harness 会把报告拷进 run 目录并加 `source_report` 指针，`findings` 部分保持不变——
`target-site feedback` 时代的拷贝会被 harness 富化出 `target_*` 字段，故富化版不能直接用 hash 比对，见 §1 注）。

---

## 1. 版本一览

| # | 报告文件 | 写入时间 | 锚点写法 | 描述文本 | findings hash | 被哪些波次使用 | 现存 |
|---|---|---|---|---|---|---|---|
| **V1a** | `results/experiments/mruby-env-write-barrier/static-report.json` | 09-18 19:30 | 无（`location: ""`，函数名只在 `root_cause` 散文里） | **原描述逐字**："A write barrier bug exists in the mrb_env_unshare function in gc.c" | `5e35579b…` | 09-18 系列（`klee`、`off`、`round2`–`round6`、`final-paired-fixed`、`controlled-paired`、`template-paired`…） | ✅ |
| **V1b** | `results/experiments/mruby-env-write-barrier/symcc-mruby-20260920/static-report.json` | 09-18 19:30（V1a 的同内容拷贝） | 同上 | 同上 | `5e35579b…` | 09-20 系列 + **10-08 15:20/15:51 无上限严格配对**（`mruby-57672-symcc/off-rollback-20261008-no-iteration-cap`(-3600)） | ✅ |
| **V2** ★ | `results/experiments/mruby-async-paired-20260923/static_analysis.json` | **09-23 18:21** | `location: "mrb_env_unshare in gc.c"`（`observability_targets: []`，靠 harness 正则抓函数名） | 原描述轻改："A write-barrier bug exists in mrb_env_unshare." | `9058ccc0…` | 09-23 `mruby-async-paired-20260923`（2 run）+ **10-08 分支会话 6 波**（见 §2） | ✅ |
| **V3-raw** | `results/experiments/symcc-target-site-feedback-20260924/static/arvo-57672/20260923T165441Z/static_analysis.json` | 09-24 00:56 | `location` 行级 `src/vm.c:397-401` + **5 条** `observability_targets`（带 `why`） | static 相位产出的机制描述 | `3b85e5e8…` | 仅该实验（static 相位原始产物，含 `timings`/`parse_error`） | ✅ |
| **V3-shared** | `results/experiments/symcc-target-site-feedback-20260924/shared/arvo-57672-static-report.json` | 09-24 01:07 | `location: "src/vm.c:397-401, function mrb_env_unshare"` + **1 条** obs 锚点 | **重写的机制描述**（"The reported environment-copy/close path appears to omit…"） | `5eb9e3ba…` | 09-24 site-feedback 配对系列（`strict-paired`、`paired-final-v2`、`feedback-payload*`、`pairs`…，共 10 个 run） | ✅ |
| **V4** | `targets/mruby-arvo-feedback/static-report-57672-v2.json` | 10-04 加入仓库（`cac7d96b1`） | 行级锚点版：`location: "src/vm.c:398…"`（`b5cf1a6c…`）；10-07 起换回 B 版（`e935b3cbf`，= V3-shared 内容，`397-401`） | 重写的机制描述 | 行级版 `b5cf1a6c…`；B 版 `5eb9e3ba…` | 行级版：09-30～10-06 共 **32 波**（`symcc-feedback-stabilization*`、`supervisor-*`、`mruby-57672-clean-*`…）；B 版：10-07 两波（`mruby-57672-symcc-rollback-20261007`、`mruby-57672-symcc-converged-20261007`） | ❌ **已删**（10-08 `a1bb97d6e`） |

注：`target-site feedback` 时代的 run 拷贝会被 harness 富化（`observability_targets[0]` 增加
`target_function`/`target_region`/`target_operation`/`target_condition`），因此那 32 波的拷贝
不能用 hash 与 V4 行级版直接比对；用 `location` 字段（`398` vs `397-401`）区分最稳。

---

## 2. 结论：分支 `symcc-rollback-20260923` 上最后使用的就是 **V2**

2026-10-08 那次"重新开始设计"的会话（回滚到 09-23 基线 + 可配置看门狗 + 去除非时间上限 +
coverage/focus 反馈）里，mruby 测试用的静态报告**只有两种**，其中**最后一次（18:32 长跑）用的是 V2**：

| 10-08 时间 | 波次 | 用的报告 |
|---|---|---|
| 10:45 | `mruby-57672-symcc-rollback-smoke-20261008` | **V2** |
| 10:55 | `mruby-57672-symcc-git-rollback-smoke-20261008` | **V2** |
| 11:01 | `mruby-57672-symcc-timeout-check-20261008` | **V2** |
| 11:02 | `mruby-57672-symcc-nodeadline-check-20261008` | **V2** |
| 15:20 | `mruby-57672-symcc-rollback-20261008-no-iteration-cap` | V1b（无锚点） |
| 15:51 / 15:52 | `mruby-57672-off-rollback-20261008-no-iteration-cap`(`-3600`) | V1b（无锚点） |
| 18:20 | `mruby-57672-coverage-feedback-smoke` | **V2** |
| **18:32 → 21:52** | **`mruby-57672-coverage-focus-3600`（分支上最后一次 mruby 测试，`validated`，UAF 首现 1770s）** | **V2** |

证据（任一条都可独立复核）：

1. 6 个 run 目录里的 `static_analysis.json` 拷贝都带 `"source_report": "results/experiments/mruby-async-paired-20260923/static_analysis.json"`；
2. 这些拷贝的 `findings` hash 都是 `9058ccc0…`，与 V2 原文件**逐字节相同**（未被重写、未被富化）；
3. 归档文档写的就是这条路径：`results/experiments/mruby-57672-final-report-20261008.md`
   §2「静态输入」与 §11.2 复跑命令；`results/experiments/mruby-57672-rollback-20261008-analysis/ANALYSIS.md:125`。

V2 的内容就是"**原描述 + 锚点函数**"：锚点 `mrb_env_unshare` 来自描述本身，被挪进 `location`
以便 harness 派生 focus；`observability_targets` 为空、没有机制/条件/计划等散文。

---

## 3. 两份最容易认错的版本

- **V3-raw（`…/static/arvo-57672/20260923T165441Z/static_analysis.json`，5 个 `why` 锚点）** 是
  "**mruby 报告写得干练**"这类评价的来源（`results/experiments/symcc-retest-20261009/STATIC-REPORTS-COMPARISON.md`
  §0 表的 mruby 行描述的就是它）。它是 `static` 相位的原始产物，**不是** 10-08 最后实验使用的那份。
- **V3-shared / V4（`src/vm.c:397-401` + 重写机制描述）** 是 target-site feedback 专用稿，
  描述文本已被重写、锚点被细化到行，**不是原描述**；它只在 09-24～10-07 之间使用，10-08 分支会话没用它。

两类的共同点：锚点都落在真凶函数 `mrb_env_unshare` 上；差别在散文丰度与锚点粒度。

---

## 4. 已删文件（V4）的取回

```sh
# B 版（10-07～10-08 使用；location "src/vm.c:397-401, function mrb_env_unshare"）
git show a1bb97d6e^:targets/mruby-arvo-feedback/static-report-57672-v2.json

# 行级锚点版（09-30～10-06 的 32 波使用；location "src/vm.c:398, function mrb_env_unshare"）
git show cac7d96b1:targets/mruby-arvo-feedback/static-report-57672-v2.json

# 最后使用版（仍在磁盘上，无需恢复）
cat results/experiments/mruby-async-paired-20260923/static_analysis.json
```

V3-shared 与 V4-B 版的 `findings` 完全相同（hash `5eb9e3ba…`），所以即使不取 git，
`results/experiments/symcc-target-site-feedback-20260924/shared/arvo-57672-static-report.json`
也是 B 版内容的等价副本。

---

## 5. 复核命令

```sh
# 每个 mruby run 拷贝记录的报告来源
find results/experiments -maxdepth 8 -name static_analysis.json -path '*mruby*' \
  -exec grep -H -o '"source_report": "[^"]*"' {} \; | sort | uniq -c

# 某个 run 用的是哪一版（看 location）
grep -o '"location": "[^"]*"' <run 目录>/static_analysis.json
```
