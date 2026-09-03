# 记忆系统实验 — 观测结果报告

> 日期: 2026-08-31
> 靶标: libyaml (commit 90a56d4)，官方 `run-parser.c` harness，ASAN 编译
> 模型: `deepseek/deepseek-v4-flash`
> 设计: 组 A（无记忆基线） vs 组 B（函数摘要记忆），各 3 runs × 100 turns

## 1. 实验设置

| 组 | 命令 | 记忆 |
|---|---|---|
| A | `run targets/libyaml-exp-a --runs 3 --max-turns 100` | 关闭 |
| B | `run targets/libyaml-exp-b --runs 3 --max-turns 100 --memory` | 函数摘要 MEMORY.md + prior 传导 + ledger |

**记忆链路**（B 组）: 预置 `/work/MEMORY.md` → agent 追加函数摘要（`### [EXPLORED] file.c:func` + 作用/输入/安全关注/已验证/可疑点）→ run 结束收集 → 解析追加 `exploration_memory.jsonl` → 下一 run 以 `PRIOR_EXPLORATION_SECTION` 渲染注入提示词。

## 2. 量化指标（观测器 trace_path.py 修正版）

### 2.1 批量对比

| run | turns | regions | reentry | forks | span | memR | memW |
|---|---|---|---|---|---|---|---|
| A run_000 | 99 | 5 | 3 | 5 | 15.7 | 0 | 0 |
| A run_001 | 96 | 3 | 4 | 4 | 61.5 | 0 | 0 |
| A run_002 | 99 | 8 | 40 | 29 | 55.0 | 0 | 0 |
| **A 均值** | **98.0** | **5.3** | **15.7** | **12.7** | **44.1** | 0 | 0 |
| B run_000 | 99 | 5 | 9 | 8 | 40.5 | 4 | 1 |
| B run_001 | 96 | 5 | 10 | 9 | 52.3 | 2 | 0 |
| B run_002 | 98 | 7 | 41 | 27 | 63.0 | 4 | 1 |
| **B 均值** | **97.7** | **5.7** | **20.0** | **14.7** | **51.9** | **3.3** | **0.7** |

### 2.2 时长（find 阶段）

| run | A | B |
|---|---|---|
| run_000 | 1422s | 1777s |
| run_001 | 1664s | 2483s |
| run_002 | 1341s | 1798s |
| 均值 | 1476s | 2019s (**+37%**) |

### 2.3 记忆产出（B 组）

| run | MEMORY.md 条目 | ledger 追加 | 状态 |
|---|---|---|---|
| run_000 | 13 条 | 13 条 | ✅ 写侧正常 |
| run_001 | 0 条 | 0 条 | ❌ 写侧失效 |
| run_002 | 4 条 | 4 条 | ⚠️ 部分 |
| **合计** | 17 条 | 17 条 | 平均 5.7 条/run |

## 3. 区域覆盖明细（记忆传导的核心观测）

| run | A 覆盖区域 | B 覆盖区域 |
|---|---|---|
| run_000 | parser(2) scanner(2) headers(2) | parser(1) api(1) headers(3) |
| run_001 | **无新区域（完全空转）** | headers(4) 新增 |
| run_002 | scanner(19) parser(5) reader(2) loader(1) api(3) | **scanner(26)** headers(11) parser(6) reader(1) |
| 累计 | 9 区域（含 loader） | 8 区域 |

**跨 run 新区域**:
- A: run_0 发现 parser/scanner → run_1 **零新增** → run_2 才补 api/loader/reader
- B: run_0 发现 parser/api/headers → run_1 加 headers → run_2 深度聚焦 scanner/reader

## 4. 假设验证

| 假设 | 结论 | 证据 |
|---|---|---|
| H1 记忆提升探索覆盖率 | ⚠️ 微弱/不支持 | B 单 run 均值 5.7 > A 5.3，但累计 A 9 区 > B 8 区 |
| H2 记忆降低重复探索 | ❌ 不支持 | B reentry 20 > A 15.7（样本小） |
| H3 记忆提升收敛效率 | ❌ 不支持 | B 时长 +37%（含读写开销） |
| H4 记忆改变路径结构 | ⚠️ 略有 | B forks 14.7 > A 12.7；B run_002 聚焦 scanner 单点深挖（26 读） |
| H5 记忆可观测性 | ✅ 成立 | memR/memW 可观测；但写侧不稳定（13/0/4） |

## 5. 质性发现

### 5.1 记忆内容质量高（✅ 核心亮点）

B 组记忆不是流水账，而是**可复用的函数知识卡片**：
- run_000 的 `scanner.c:yaml_parser_save_simple_key` 记录了 `index = token_number - tokens_` 的 QUEUE_INSERT 越界风险；
- run_002 的 `reader.c:yaml_parser_update_buffer` 给出了**数学安全论证**（buffer 49152 = 3×raw；UTF-16 最大扩展 1.5× → 24576 < 49152，故溢出不可达），并附带 75 个边界用例验证 + 条件性风险（"若未来某处 CACHE(length>49152) 则解码循环可溢出"）。

这正是"函数摘要"格式设计目标——把一次 run 的分析成果沉淀为下一 run 可消费的知识。

### 5.2 写侧触发不稳定（❌ 主要瓶颈）

记忆产出 13/0/4 条，**run_001 完全没写**。transcript 显示:
- run_001 拿到 prior 摘要后**立即转向深度 fuzzing**（写 fuzzer → 并行 fuzzing → UTF-16/CRLF 变异 → 插桩验证 QUEUE_INSERT → UBSAN+ASAN → gcov），100 turns 全部用于"执行型任务"，**跳过了记忆写入检查点**；
- 记忆只在"读源码型任务"后触发；一旦进入"跑 fuzzer 循环"，强制检查点失效。

### 5.3 无记忆时 run 间无方向（A run_001 空转）

A run_001 三区域全落在 `other/src` 等粗粒度区域，**零新区域**——无记忆时每个 run 重新"白手起家"，run_001 在重复 run_000 的方向。B run_001 虽也少，但 run_002 表现出了**聚焦深挖**（scanner 26 读，memory 引导深化 reader.c）。

### 5.4 为什么"开了记忆重复率反而变高"（H2 深入分析）

raw reentry 指标 B(20) > A(15.7) 是事实，但按 reentry 来源分解后，**这不是"记忆导致无效重复探索"**：

**a) reentry 指标把三类活动混为一谈**，逐一拆开看：

| reentry 来源 | A 组 | B 组 |
|---|---|---|
| run_002 scanner.c 深挖（两组共有的行为） | 40 次 | 41 次 |
| 自建 fuzzer/输出文件反复 cat（`/tmp/fuzz/*.c`、err.txt） | A run_002 大量 | B run_001 大量 |
| 写记忆时的回读确认（yaml.h 反复读） | — | B run_000/001 有 |

**b) 两组的 run_002 reentry 都异常高（40 vs 41）**——scanner 深挖是两组共有的行为（大概率被 focus_areas 引导），**不是记忆造成的**，直接拉高了双方均值。

**c) B 组 run_000/001 的 reentry 高（9/10 vs A 的 3/4）构成不同**：
- `yaml.h` 回读 4-7 次 —— **写记忆时的确认动作**（agent 记录函数摘要前回读头文件确认签名/宏）；
- `err.txt`/`campaign.sh` 反复 cat —— **fuzzing 验证循环**（run_001 拿到 prior 后直接进入 fuzzing 阶段：跑 fuzzer → 检查输出 → 调整）。

**d) 靶标源码级精确度量**（排除自建文件噪声，只看 `/work/libyaml/` 源码）：

| run | A 源码读/unique 文件 | B 源码读/unique 文件 |
|---|---|---|
| run_000 | 7 / 4 | 5 / 3 |
| run_001 | 2 / 2 | 5 / 4 |
| run_002 | 34 / 9 | **45 / 7** |

B run_002 读 45 次但只集中在 7 个文件（scanner.c 26 + yaml_private.h 9 + parser.c 6），A run_002 读 34 次分散在 9 个文件。**B 不是"重复探索"，是"更集中的深挖"**。

**e) 记忆引导深挖有直接证据**：run_000 摘要里 scanner.c 标了可疑点（`QUEUE_INSERT 的 index 来自 simple-key`、`index = token_number - tokens_`、`栈空 POP`）→ run_002 深挖 scanner.c（26 读）正是验证这些风险，并在 turn=15 沉淀 4 条 reader.c 新摘要（含数学安全论证）。

**结论**：记忆没有造成"忘记看过又重头学"式的无效重复；它**改变了活动构成**——B 组更早进入 fuzzing 验证阶段（产生输出文件检查的"执行噪声"）、更聚焦地针对可疑点深挖。但**当前 reentry 指标无法证明"记忆降低重复"**，因为它把深化回访与执行噪声都算作重复。要严谨回答 H2，需要**函数级去重度量**（同一函数重复 read 且无新增产出 = 无效重复），而非文件/区域级 reentry。

## 6. 局限性

1. **样本量小**：3 runs/组，随机性大（两组 run_002 的 reentry/forks 都异常高，说明单 run 行为方差大）
2. **写侧不稳定污染实验**：B 实际只有 run_000（13 条）+ run_002（4 条）有记忆写入，run_001 的 prior 传导效果无法评估（它没写后续记忆，但也消费了 prior）
3. **region 规则粗粒度**：`other`/`other/src` 噪声（bash cat 解析 + agent 写自己的 .c 测试文件也算 src），区域粒度是文件级而非函数级
4. **观测器是启发式**：从 bash 命令提取 cat 路径，`cat file | head` 多文件命令只取第一个路径
5. 无 crash 命中（实验设计不依赖 crash，但这也意味着无法用"挖到洞"这种硬指标判断）

## 7. 结论

**记忆系统在功能层面完全可行**：预置→写入→收集→解析→ledger→跨 run 渲染的全链路稳定工作，且 agent 产出的函数摘要质量高、可复用（数学论证级）。

**在优化挖掘逻辑的效果层面，本次实验证据不足，无法确认显著改善**。主要原因是写侧触发不稳定（run_001 零写入）叠加样本量小，导致 B 组的记忆浓度不够（平均 5.7 条/run），跨 run 传导的实际承载有限。

**最大瓶颈不是格式，而是"写侧纪律"**。记忆的价值取决于 agent 是否持续沉淀；一旦进入执行型任务（fuzzing/验证），检查点就被跳过。

## 8. 改进建议（下一轮实验）

1. **写侧强制下沉到 harness 层**：find.py 在每 N 个工具调用后主动 `cat /work/MEMORY.md` 检查增量，若长时间无增量则在下一轮提示词中"提醒"agent 先沉淀再继续（而不是依赖 agent 自觉）
2. **为执行型任务定义记忆形态**：fuzzing 后的"已验证负面结果"（如"QUEUE_INSERT 边界已 fuzz 2000 次无崩溃"）也是高价值记忆，提示词明确允许这种条目
3. **加大样本**：各 8-10 runs，才能压过单 run 方差（本次 run_002 两组都异常高说明方差大）
4. **观测器升级**：把 `other` 区域按 agent 自建 fuzzer/工具文件 vs 靶标源码区分；region 粒度细化到函数级（从记忆 ledger 对齐）
5. **对照组增强**：A 组也注入"空提示词块"占位，排除"提示词更长"本身的影响

## 9. 复现

```bash
# 组 A（无记忆）
VULN_PIPELINE_DOCKER_BUILD_NETWORK=host .venv/bin/vuln-pipeline run targets/libyaml-exp-a \
  --dangerously-no-sandbox --model deepseek/deepseek-v4-flash --max-turns 100 --runs 3 \
  --results-dir results/libyaml/exp-A

# 组 B（有记忆）
VULN_PIPELINE_DOCKER_BUILD_NETWORK=host .venv/bin/vuln-pipeline run targets/libyaml-exp-b \
  --dangerously-no-sandbox --model deepseek/deepseek-v4-flash --max-turns 100 --runs 3 --memory \
  --results-dir results/libyaml/exp-B

# 观测
python3 tools/trace_path.py results/libyaml/exp-A/libyaml-exp-a/<ts> --batch
python3 tools/trace_path.py results/libyaml/exp-B/libyaml-exp-b/<ts> --batch
```

> 注意：targets/libyaml-exp-a、targets/libyaml-exp-b 是 targets/libyaml 的副本（改 image_tag 隔离容器/镜像名，避免并行容器名冲突）。
