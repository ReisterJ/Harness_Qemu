# Agent 行为审计计划（全实验日志）

> 状态：计划（2026-10-09 起草）
> 配套：**审计对象清单**（要分析哪些实验记录）见 [agent-behavior-audit-inventory.md](agent-behavior-audit-inventory.md)。
> 目的：在做下一步探索之前，先把**所有历史实验日志**审一遍，回答"**模型的行为为什么会变好／变坏**"。
> 口径：只要能让模型行为发生改变的因素都在审计范围内——求解器、执行协议、路径/覆盖反馈、提示与禁令、
> 预算与看门狗、提交契约、环境、模型本身。**失败组同样是一等公民**：要回答"它为什么失败"。
> 这不是一份"SymCC 效果报告"，而是一次**超大号审计**：先建事实，再谈结论。

---

## 1. 为什么要先审计

已有的实验结论互相矛盾且无法互相解释：

- 有的波次 SymCC 快 1.7×～3.8×（2026-10-08 速度报告 §2），有的波次更慢（重测波 OFF 479s vs SymCC 753s），锚点波甚至同量级但 SymCC 略慢（45.3s vs 74.1s）；
- 已发现"symcc 臂"在历史上**至少三层含义**（求解器 / 目标点反馈 / 覆盖率反馈），而且常常与"执行协议强制"绑在一起；
- 已实测**求解器自身产出从未直接给出答案**（已知的生成样例全 0 sanitizer 事件，13,258 例）；
- 失败组从未被系统解剖过——`agent_blocked` 48 个、`invalid_submission` 36 个、`reached_no_crash` 18 个、`iteration_exhausted` 13 个、`false_positive` 7 个、`agent_failed` 5 个（详见 §7）。

**在这些事实被区分清楚之前，任何"加一个开关再跑一波"的实验都会重蹈覆辙。** 所以本审计是下一步探索的前置条件（验收门见 §11）。

---

## 2. 审计问题（AQ）

每条都写成可判定形式，允许的答案只有 **支持 / 否证 / 无法区分**。

| 编号 | 问题 | 判定依据（简述） |
|---|---|---|
| AQ1 | 求解器产出是否直接缩短了输入构造？ | 最终 PoC 与生成样例的字节关系；生成样例是否含 sanitizer 事件 |
| AQ2 | 路径/覆盖反馈（`coverage.focus`、`new_lines`）是否改变了搜索策略？ | 提示到达时间 → 首个目标类事件；到达前后行为分布变化 |
| AQ3 | 目标点反馈（provider `site_reached`、async sidecar feedback）是否把盲搜变定向？ | 同上，按世代分层 |
| AQ4 | 执行协议（harness 代执行、只读反馈、126 守护）本身是否改变行为？ | 协议轮数 / 直连执行次数 / 每回合执行量 |
| AQ5 | 提示与禁令（prompt 文本差异）是否独立影响策略？ | prompt 禁令行是否出现的对照 + 侦察/建造类回合占比 |
| AQ6 | 预算、看门狗、supervisor 规则如何改变成败形态？ | 截断点、被拦截前后的命令分布 |
| AQ7 | 提交契约（`poc_kind` / 路径 / 机器可观察证据 / 轮次记录）损失了多少"其实已找到"的结果？ | `invalid_submission` 组的事后重放 |
| AQ8 | 失败组的失败原因如何归类？ | §7 的失败分类与签名 |
| AQ9 | 以上因素里，哪些是"信号"（可复现），哪些是"方差"？ | 臂内离散度 vs 臂间差值 |

---

## 3. 干预因子分类（I）——不限于求解器

审计的最小单位是"**某 run 相对基线多/少了哪些干预**"。

| 编号 | 干预 | 在日志里的可观测形态 |
|---|---|---|
| I1 | 求解器产出 | `symcc` 块（`testcase_count`、`generated_replays[]`、sidecar `feedback_path`） |
| I2 | 路径/覆盖反馈 | `coverage` 块（`focus[].status/hits/lines_hit`、`new_lines`、`new_functions`）、容器内 `coverage/round-NNN.lcov` |
| I3 | 目标点反馈 | provider `<label>.json` / `events.jsonl`；async 世代 `read-feedback` 输出 |
| I4 | 执行协议 | `run-input` / `read-feedback` 调用；**直连二进制执行**；隐藏二进制（直跑 exit 126） |
| I5 | 提示与禁令 | transcript 中 agent 复述的约束（如 "Do NOT build a source slice / invoke compiler or target binaries directly"）、静态报告文本、攻击面文本 |
| I6 | 预算与看门狗 | 时限（1800 / 2915 / 3600s）、轮次上限、`--max-iterations`、watchdog、supervisor rules |
| I7 | 提交契约 | `crash-result.xml` 是否写出、`poc_kind`、路径匹配、`iterations/round-*.json` 是否齐 |
| I8 | 环境 | 镜像 tag、目标 commit、工具链、网络策略、镜像内是否残留 SymCC 二进制/feedback map |
| I9 | 模型与采样 | 模型 id、并行/串行、重试与 resume、是否有 subagent |

**关键原则**：一次 run 通常同时受多个因子影响。审计要做的是**把因子标注出来**（谁在场、谁缺席），而不是假设"臂 = 因子"。

---

## 4. 数据资产

| 资产 | 路径 | 用途 | 备注 |
|---|---|---|---|
| 主证据 | `results/experiments/**/dynamic_transcript.jsonl` | 逐回合行为、工具输出 | 288 个（截至 2026-10-09） |
| **汇总副本（审计用）** | `results/experiments/agent-behavior-audit/logs/{G1-core-pairs,G2-feedback,G3-budget-failure}/` | 上表全部日志 + 伴随文件，按组集中；硬链接，原目录未动 | 254 run 目录 / 2,220 文件；规则见该目录 `README.md`，映射见 `manifest.csv` |
| 相位结果 | 同目录 `dynamic_validation.json` | `result.status`、timings | status 分布见 §7 |
| 波次记录 | `.../records.jsonl` | wall、`first_asan`、status（wave 级） | 只在部分 wave 存在 |
| 侧车统计 | `.../symbolic_execution/summary.json` | 逐轮生成样例数、replay 是否崩、求解器耗时、coverage 计数 | 缺则记 `unknown`，**不得当 0** |
| Agent 自述 | `.../iterations/round-*.json` | hypothesis / decision / reason | 与 harness 提示严格区分 |
| 提交物 | `.../crash-result.xml`、`poc_*` | 是否提交、PoC 字节 | 事后重放用 |
| 波次说明 | 各目录 `comparison.md` / `summary.txt` / `SUMMARY.md` | 交叉核对口径 | 已知中位数锚点 |
| 静态报告 | 各 run 的 `static_analysis.json` | 该 run 用的报告版本/hash | 报告换版是独立因子 |
| 元数据 | `targets/*/config.yaml`、`.gitignore` | 目标类事件映射、镜像 tag | — |

---

## 5. 审计流程（P0–P6）

### P0 建索引（每 run 一行）

`runs_index.csv`：身份（wave / pair key / target / arm / 世代 / 镜像 / 模型 / 报告 hash）、规模（tool_calls、
model steps、各行为类别计数）、时间（wall、首个任意 ASan、首个**目标类**事件、是否截断）、执行（实际执行目标
二进制的次数、协议轮数、直连次数、生成样例数与是否崩）、结局（是否提交、`result.status`）。

### P1 归一化与世代标注

按 §3 的 I1–I3 形态把每个 wave 判为 `plain` / `async-sidecar` / `provider-trace` / `coverage` 四代之一
（当前分布：197 / 48 / 19 / 24 个 run）。**跨代不做合并统计**。

### P2 干预标注

对每个 run 产出 `interventions.csv`：I1–I9 每一项在场/缺席/未知，并给出证据行（transcript 里的原话或块）。

### P3 行为标注

`turn_kinds.csv`（每 run × 类别）与派生指标：

- 类别：`protocol_round` / `run_target` / `recon_read` / `recon_fs` / `craft_input` / `parse_response` /
  `mine_feedback` / `build_or_fuzz` / `verify_replay`；
- 指标：**executions / agent turn**、**侦察占比**、**建造占比**、**提示后 5 回合内的类别迁移**。

"正向变化"的算子化定义（全部可测）：

| 正向信号 | 度量 |
|---|---|
| 更早到达目标点 | `T_first_target_event` 前移 |
| 更少的盲搜 | `recon_*` 回合数、`build_or_fuzz` 回合数下降 |
| 更快的负结果转向 | 一次失败探测 → 改变假设所需回合数（`iterations/*.json` 的 hypothesis 变化） |
| 更少的重复劳动 | 重复提交同一输入（sha 相同）的次数 |
| 更少的契约损失 | `invalid_submission` 占比 |
| 更少的无证据提交 | `false_positive` 占比 |

负向变化同样记录：额外确认回合、挖无信息量产出（`mine_feedback` 无后效）、被提示带偏（提示与目标不符）。

### P4 结局标注

结局分三类：`hit_target`（首个目标类事件）/ `hit_other`（非目标类 ASan）/ `none` + 是否 `censored`（撞时限）。
同时记录 `result.status`（contract 层结果），用于 AQ7 的"已找到但未通过契约"分析。

### P5 归因与判定

按 §8 的判据逐机制出结论；对无法区分的条目，写明**缺哪一条证据**以及需要什么实验补齐。

### P6 报告

产物见 §10。

---

## 6. 扫描规则（提取口径）

**事件定义**

- 目标类事件：按 target 映射 —— `mruby`=`heap-use-after-free`；`arvo-38283`=`global-buffer-overflow`；
  `arvo-55020`=`heap-buffer-overflow`；`62290`/其它=任意 `AddressSanitizer`。必须同时出现
  `ERROR: AddressSanitizer`（排除只在源码/回显里出现的格式串）。
- harness 提示：coverage 世代=`focus[].status == "hit"`；async 世代=`read-feedback` 输出；provider 世代=
  `report/<label>.json` 的 reached 字段。
- **执行动作**：命令的某个 shell 段的首个可执行 token 是目标二进制/包装脚本（剥离 `timeout N`、`env VAR=`），
  且首 token 不是 `cat/ls/strings/file/head/xxd/objdump/nm/grep/sed`。

**坑（已实测踩过，务必写进实现）**

1. `read` 工具参数是 `filePath` 而非 `command`——只按 `command` 分类会产生 40%+ 假 `other`。
2. 时间戳在 `part.state.time.start/end`，不在 `part.time`。
3. 完整输出可能在 `state.output` 与 `state.metadata.output`；超大响应被 CLI 截断，agent 会回读
   `/root/.local/share/opencode/tool-output/…`，计数时按**实际执行**而非输出完整度。
4. `cat /out/run-fuzzer-*-symcc` 会被误判成"执行了 SymCC"——必须按首 token 判定。
5. agent 自己写的 `round-NNN.json` 里也有 `"site_reached": true`——**harness 提示与 agent 自述必须分开**。
6. 缺 `symbolic_execution/summary.json` 的 run：`gen_cases/gen_crash` 记 `unknown`。

---

## 7. 失败组分析（一等公民）

现状（288 个 run，按 `dynamic_validation.json` 的 `result.status`）：

| status | 数量 | 需要回答的问题 |
|---|---:|---|
| `validated` | 104 | 其中多少是"靠反馈"、多少是"自己撞上"？ |
| （空，多为早期 run 或未写盘） | 55 | 是否等于未提交？逐个人工核对 |
| `agent_blocked` | 48 | 卡在模型自身（循环/放弃）、环境（编译/网络）、还是预算？ |
| `invalid_submission` | 36 | **事后重放有多少其实有效**（速度报告已指出这一类是主要损失源） |
| `reached_no_crash` | 18 | 到达目标点却没崩：反馈误导？构造能力不足？根因不可触发？ |
| `iteration_exhausted` | 13 | 轮次上限是否早于"该有的收敛时间"？ |
| `false_positive` | 7 | 触发的是非目标类/误读输出？ |
| `agent_failed` / `wrong_behavior` / `not_reached` | 5 / 1 / 1 | 逐例解剖 |

**失败分类表（可检出签名 → 归属）**

| 失败模式 | 可检出签名 | 归属因子 |
|---|---|---|
| 盲搜耗尽 | `build_or_fuzz`/`recon_*` 占比高、`T_target` 不存在、撞时限 | I5/I6 |
| 卡在反馈上 | 反复 `mine_feedback`/`parse_response` 但假设不变 | I2/I3 |
| 契约损失 | 有目标类事件但无 `crash-result.xml` 或 status=`invalid_submission` | I7 |
| 轮次截断 | `iteration_exhausted` 且最后一轮 reason 仍在前移 | I6 |
| 环境阻塞 | 出现编译/依赖/权限/超时错误（`environment_blocked`） | I8 |
| 模型自身失败 | 重复命令、空转、提前放弃、自评 `iteration_exhausted` 但日志显示还有手段 | I9/I5 |
| 反馈误导 | 提示"命中"但后续构造朝着非触发条件走 | I2/I3 |

---

## 8. 评价方法

**逐对计算**：`ratio = T_off / T_symcc`（目标类事件；截断记 `≥limit`）、`Δcalls`、`Δexecutions`、
`executions/turn` 两臂比、`hint_lead = T_target − T_first_hint`。

**机制判据与阈值**

| 机制 | 判"支持" | 判"否证" |
|---|---|---|
| M1 求解器给答案 | `gen_crash > 0`，或最终 PoC 的 sha 命中生成样例（或逐字节派生） | 生成样例 ≫0 且无一崩、PoC 与样例无关 |
| M2 路径反馈 | `hint_lead > 0` 且提示后 5 回合行为迁移（侦察↓/建造↑），且在多对里稳定 | 提示在事件之后才被读到，或根本没有提示 |
| M3 机械替代 | `executions/turn` ≥2× 且"到达目标的总执行次数"两臂接近（差的是回合不是探索量） | 两臂 `executions/turn` 接近 |
| M4 执行契约/提示 | off 臂有直连执行而 symcc 臂 0，或禁令行只在 symcc 臂出现，且行为差异与之一致 | 两臂契约一致 |
| M5 方差 | 臂内 `T_target` 离散度 > 臂间中位数差 | 反之（信号强于噪声） |

**分层口径（必须）**

1. 按世代分层（§5-P1）；2. 按结局分层：两臂都命中（唯一可计时）/ 单臂命中 / 双空手；
3. 单点结论与分布结论分开写；4. 截断样本不进均值。

**证据等级**：`强`（多对同向 + 机制可解释 + 无混淆）/ `中`（方向一致但样本少或混淆未消）/ `弱`（单例）/ `否证`。

---

## 9. 校验锚点（扫描器先过这三关）

| 锚点 | 期望值 |
|---|---|
| `mruby-async-paired-20260923` | OFF 257 次工具调用、首个目标类事件 1528.0s；SymCC 92 次、406.7s |
| `symcc-anchor-20261009` 首崩中位数 | OFF 45.3s；SymCC 74.1s |
| `symcc-retest-20261009` 首崩中位数 | OFF 479s；SymCC 753s |

对不上就不进入结论阶段。

---

## 10. 交付物与验收标准

| 交付物 | 内容 | 验收 | 状态（2026-10-12） |
|---|---|---|---|
| `runs_index.csv` | 288 行 | 锚点三关通过；字段无 `unknown` 混入 0 | ✅ `results/experiments/agent-behavior-audit/tables/runs_index.csv` |
| `interventions.csv` | 每 run 的 I1–I9 标注 + 证据 | 抽查 10 个 run 与原文一致 | ❌ 未单独产出（I1/I4/I6 的信息并入 `metrics_deep.csv` 与报告 §1.4） |
| `turn_kinds.csv` | 每 run × 类别 | 分类器对两臂的 `direct_run` 判定与人工抽查一致 | ✅ 同名表在 `tables/` |
| `milestones.csv` | 每 run 事件线 | 抽查含"提示晚于事件"的案例 | ⭕ 以 `timeline.py` + 报告 §3/§4 的时间线表格代替 |
| `pairs.csv` / `PAIRS.md` | 配对表 + 机制判据 | 至少覆盖 41 对 | ✅ 44 对；另有 `pairs2.csv`（配对口径修正版）与 `metrics_deep.csv` |
| `FAILURES.md` | 失败分类 × 数量 × 逐例解剖（≥8 例） | 每类至少 1 例逐回合复盘 | ✅ 并入 `AUDIT-REPORT.md` §4.2/§4.3/§4.5 与 `BEHAVIOR-DEEP-DIVE.md` §7–§9（契约 19:14、锚定 71 轮、codex 11 例） |
| `AUDIT-REPORT.md` | 按世代分层的机制证据矩阵 + 案例解剖 + 下一步建议 | 每条机制标 支持/否证/无法区分 + 证据等级 | ✅ **第四版·校对版**（§0 一页版结论；§1.5 列出本轮自查修正的 9 处；机制矩阵带等级） |
| `BEHAVIOR-DEEP-DIVE.md` | （计划外新增）两臂"分析—构造"循环的逐事件对照 | 每条结论可回溯到 transcript 时刻 + 原文 | ✅ 7 对有效实验 + 4 对单侧命中 + 锚定组 + codex 世代 |
| `notebook.py` | （计划外新增）逐事件"命令 + 关键输出"日志 | 对任一 run 可复算 | ✅ `results/experiments/agent-behavior-audit/notebook.py` |

---

## 11. 决策门（审计结论 → 下一步）

| 审计结论 | 下一步动作 |
|---|---|
| M3 支持、M1 否证 | 加"cheap-iteration 判别臂"（无求解器，每轮 harness 自动变异+回放）；若同样加速，则停止把求解器当助力卖点 |
| M2 支持、且提示与目标一致 | 保留路径反馈，做"反馈开关矩阵"（off / coverage-only / coverage+solver），并统一执行契约 |
| M4 支持 | 先统一执行契约（所有臂强制走协议、隐藏二进制），再重测历史关键对 |
| M5 主导 | 停止小样本对比，改为"同条件多重复 + 预注册判定规则"扫，先解决方差 |
| 契约损失占比高（AQ7） | 优先修提交契约/证据链，而不是加外力 |

---

## 12. 风险与局限

- **代际异构**：四代 harness 的"帮助内容"不同，任何跨代聚合都无意义；
- **样本小**：结局"两臂都命中"的对只有个位数，分布结论要用证据等级标注；
- **删失**：大量 run 撞时限，只能给下界；
- **污染**：部分波次的 off 臂可直连二进制、甚至自取 SymCC（见 `PAIRS.md` 的 `M4` 列），这些波次不能当"无助力基线"；
- **元数据缺失**：早期 run 无 `symbolic_execution/summary.json`，生成样例统计缺失，需人工抽样补齐；
- **报告版本差异**：同一目标换过静态报告（见 [mruby 57672 静态报告版本对照](../experiment-records/2026-10-09-mruby-57672-static-report-versions.md)），是独立因子，必须在 `interventions.csv` 里标出。

---

## 附录 A：日志布局速查

```text
results/experiments/<wave>/…/<arm>/<target>/dynamic-<ts>/   ← 一个 run
├── dynamic_transcript.jsonl     逐回合：text / tool_use（part.tool、state.input/state.output、state.time）
├── dynamic_validation.json      result.status、timings、candidate
├── iterations/round-NNN.json    agent 自述（decision/reason/observations）
├── symbolic_execution/          summary.json（逐轮生成样例与 replay）、requests.jsonl
├── crash-result.xml             是否提交（存在即提交过）
└── static_analysis.json         该 run 使用的静态报告（版本/hash）
<wave>/records.jsonl             wave 级：wall_s、first_asan、status
```

## 附录 B：术语

- **目标类事件**：与静态候选根因同类的 sanitizer 事件（按 target 映射）。
- **harness 提示**：harness（而非 agent 自己）产出的、关于"是否接近/到达目标点"的信息。
- **正向行为改变**：§5-P3 的六个算子中任一改善。
- **契约损失**：已拿到有效 PoC，但因 `poc_kind`/路径/轮次记录等规则未被记录为成功。

## 附录 C：已有脚手架（2026-10-09 第一遍；2026-10-10 归位）

> 全部脚手架与**汇总后的审计日志**现在位于 `results/experiments/agent-behavior-audit/`（`results/` 在
> `.gitignore` 内，只存在于本地，未随仓库分发）：
>
> - `logs/G1-core-pairs|G2-feedback|G3-budget-failure/`：254 个 run 目录、2,220 个文件（硬链接，
>   不额外占盘），含全部 288 个 transcript + 伴随文件；收集规则与排除项见该目录 `README.md`，
>   逐文件映射见 `manifest.csv`，原始 wave 目录未改动；
> - `mechanism_scan.py`：扫 288 个 transcript → `tables/runs_index.csv` / `tables/turn_kinds.csv`
>   （含 §6 的坑 1/2/4 修复）；
> - `mechanism_pairs.py`：41 对配对 → `tables/pairs.csv` / `tables/PAIRS.md`（含 M1–M4 判据列）；
> - `collect_logs.py`：重建 `logs/`（默认先删后建，硬链接）。
>
> 首轮粗扫已确立的起点事实：**M1 全为 0**（有样例的对全部"生成 0 崩"）；M2 只在 coverage 世代成立
> （lead 可达数百秒）；M4 几乎处处成立；`mruby-async-paired-20260923` 这对里，该臂唯一一次读 sidecar 反馈
> 发生在崩溃之后（+469.7s vs 崩溃 +406.7s）——**加速与"被提示"无关**。
> 待补：`interventions.csv`、`milestones.csv`（提示到达/行为迁移）、`FAILURES.md`、按世代分层的
> `AUDIT-REPORT.md`。
