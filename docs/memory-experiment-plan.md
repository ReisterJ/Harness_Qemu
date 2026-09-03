# 记忆系统实验计划：记忆能否优化漏洞挖掘路径

> **目标**：通过可控的 A/B 对照实验 + 路径观测工具，回答一个明确的问题——
> **在 find-agent 的一次 run 流程中引入"探索记忆"（agent 内 `MEMORY.md` + 跨 run `exploration_memory.jsonl`），能否可观测地优化漏洞挖掘逻辑**（减少重复探索、更快收敛到崩溃、更好利用前序证伪）。
>
> 最终交付：观测器工具 + 两组实验数据 + 结论报告（不是"装了记忆"就完事，而是用数据说话）。

---

## 0. 现状与动机

| 现有机制 | 记什么 | 缺陷 |
|---|---|---|
| `found_bugs.jsonl`（跨 run 挂载） | 已提交崩溃的 ASAN 摘要 | 只记**成果**，不记**过程**（证伪、已探区域、卡点） |
| `focus_areas.json`（recon 生成） | 静态挖掘方向 | 静态分区，run 之间**无信息流动** |
| find-agent 会话（≤2000 turns） | 模型上下文 | 一次性；run 结束即丢；resume 只恢复同会话 |

**核心缺口**：agent 在长会话中会忘记自己查过什么、证伪过什么假设；多个 run 各自为战，重复挖掘同一区域，忽略未探索区域。记忆系统就是补上这层**过程记忆**。

---

## 1. 核心假设（要验证的问题）

> **重要设计决策（2026-08-31 修订）**：本实验**不依赖 crash**。
> 记忆系统的价值在于**探索过程本身的质量**（更系统、更少重复、更好利用前序信息）——crash 是这些好处的可能副产品，但不是判据。
> 因此全部主指标都是**过程指标**，即使 24 个 run 一个 crash 都没有，实验依然完整可判定；crash 只作为**次要参考指标**（找得到最好）。

**H1（探索覆盖率）**：有了记忆，单 run 覆盖的**不同源码区域数**显著增加（不重复磨蹭同一区域）。

**H2（重复率）**：有了记忆，同区域内**重复进入**的次数显著下降；后续 run 对前序已 REFUTED 区域的再访问显著减少。

**H3（收敛效率）**：有了记忆，每个区域从"首次进入"到"得出结论（REFUTED/PROMISING/DONE）"的 turn 数下降——agent 更快给区域"定性"并记下结论，而不是浅尝辄止或无限磨蹭。

**H4（路径结构 + 记忆真实性）**：有记忆的路径**分叉更少**（方向切换更线性）；且记忆条目（REFUTED/DONE/PROMISING）与真实探索行为一致（可对照 transcript 验证）。

**H5（可观测性）**：观测器能从 transcript 中稳定提取全部过程指标，路径图能肉眼区分"有/无记忆"两组。

> 反假设（实验可能推翻的）：记忆文件写入本身消耗 turns、提示词干扰 agent 聚焦、记忆内容噪声化导致后续 run 被误导、agent 写了记忆但自己也不采纳。这些都会在结论中如实报告。

> 设计收益：不依赖 crash 意味着**靶标可以用最新代码**（用户确认）——不再需要 pin 到含已知 CVE 的历史版本来保证"挖得到"；探索过程本身就有观测价值。

---

## 2. 实验设计（A/B 对照）

### 2.1 两组配置

| 组 | find_prompt | 容器内文件 | 观测 |
|---|---|---|---|
| **A（对照组 / 现状）** | 现有模板，不加记忆段落 | 无 `MEMORY.md`、无 `exploration_memory.jsonl` 挂载 | 跑 6 轮，记录 transcript |
| **B（实验组 / 加记忆）** | 加 `MEMORY_SECTION` + `PRIOR_EXPLORATION_SECTION` | 预置 `MEMORY.md`；挂载只读 `exploration_memory.jsonl`；run 结束收集追加 | 跑 6 轮，记录 transcript |

### 2.2 变量控制

- **同一靶标、同一模型**（`deepseek/deepseek-v4-flash`）、同一 `--max-turns`、同一 `focus_areas`、同一 seed 顺序——**唯一变量是记忆机制**。
- 两组各在 `targets/libyaml` 和 `targets/cjson` 上跑一遍（2 靶标 × 2 组 × 6 runs = 24 次 find）。
- 并行度固定（`--runs 6 --parallel` 或串行，两组一致）。
- 每组跑前 `docker rmi` 重建镜像，确保无缓存污染。

### 2.3 指标定义（量化）

**主指标（过程导向，全部不依赖 crash，A/B 都能算）：**

| 指标 | 定义 | 数据来源 | 对应假设 |
|---|---|---|---|
| 覆盖区域数 | 该 run 首次进入的 distinct 源码区域数（区域 = 文件 → 函数级映射，见 §4.3） | transcript `tool_use(Read)` | H1 |
| 区域内重复进入 | 同一区域被再次进入的次数（同 run 内） | transcript | H2 |
| 跨 run 重复访问 | 后续 run 进入前序已 REFUTED 区域的次数（B 组用记忆文件判定；A 组用"前 run transcript 末次结论"近似） | transcript + 记忆文件 | H2 |
| 区域收敛 turns | 每区域从首次进入到"最后一次 Read 该区域 + 得出结论"的 turn 跨度 | transcript | H3 |
| 区域定性率 | 得到明确结论（写出 REFUTED/PROMISING/DONE 或转向他处）的区域数 / 覆盖区域数 | transcript + 记忆文件 | H3 |
| 路径分叉数 | 相邻 Read 区域变化的次数（见 §4.3） | 观测器 | H4 |
| 记忆真实性 | MEMORY.md 条目中可对照 transcript 验证的比例（"说看过却无对应 Read"记为虚假） | 记忆文件 + transcript 抽查 | H4 |
| 观测器稳定性 | 全量 run 解析成功率、人工抽检归类正确率 | 观测器自检 | H5 |

**次要指标（结果导向，crash 找到才统计，仅作参考）：**

| 指标 | 定义 | 说明 |
|---|---|---|
| turns-to-crash | 会话开始到首次 `<poc_path>` 的 turn 数 | 仅对 crash 的 run 统计；不 crash 不算失败 |
| crash 命中率 | crash_found 占比 | 参考值；两组都低也不否定记忆价值 |

> 判读规则：主指标在 A/B 间的差异即实验结论；次要指标仅作为"记忆是否顺带提升找 bug 能力"的加分证据。

---

## 2.4 记忆格式设计（详细）

### 设计原则

1. **两段式**：agent 内记忆用**人读**的 `MEMORY.md`（LLM 自由写，利于推理）；跨 run 用**机器读**的 `exploration_memory.jsonl`（管线聚合、渲染、去重）。
2. **单条 = 一个被探索函数的"知识卡片"（function summary）**——比"假设/证伪记录"更贴合代码挖掘语义：后续 run 读到的是"这段代码是什么、哪里可疑"，天然可复用。
3. **每条带状态标签 + 内容字段**——后续可 5 秒扫完，且观测器能对账（防编造）。

### Agent 内记忆：`/work/MEMORY.md`

提示词教 agent 用固定格式追加（最新在底部），**强制检查点**（解决"agent 不主动写"的冒烟发现）。每条：

```markdown
### [SUSPICIOUS] parser.c:yaml_parser_parse | turn=45
- 作用: 驱动解析状态机，从 token 队列产生 event
- 输入: yaml_parser_t* (state 栈、token queue)
- 安全关注: parser->state 栈深度、error recovery 路径
- 已验证: 深嵌套(200k)不崩；畸形 UTF-8 优雅失败
- 可疑点: parse_value 递归深度无显式上限
```

字段说明：
| 字段 | 用途 | 对账价值 |
|---|---|---|
| `[STATUS]` | `EXPLORED`(读过无问题) / `SUSPICIOUS`(可疑待续) / `CONFIRMED`(已确认崩溃) | 后续 run 决策依据 |
| `FILE.c:function` | 函数定位（basename:函数名） | 去重 + 观测的键 |
| `turn=` | 写入时所在 turn | 精确定位 transcript 对应动作 |
| `作用` | 函数做什么 | 后续 run 免重读 |
| `输入` | 参数/不可信数据路径 | 攻击面提示 |
| `安全关注` | 内存操作/边界/递归/未校验尺寸 | 可疑点来源 |
| `已验证` | 实际跑过的命令 + 结果 | 真实性核对核心 |
| `可疑点` | 具体可疑发现或"无" | 后续延续点 |

**强制检查点**（MEMORY_SECTION 明文要求，否则冒烟证明 agent 不写）：
1. 读完某函数源码 → 立即追加摘要
2. 启动长任务（fuzzer/批量）前 → 先写目标函数摘要
3. 每 ~20 工具调用 → `cat /work/MEMORY.md` 确认不重复
4. 发现可疑点 → 标记 SUSPICIOUS

### 跨 run 记忆：`exploration_memory.jsonl`

管线在 run 结束后解析 `MEMORY.md`，追加结构化条目：

```json
{"run": 0, "status": "SUSPICIOUS", "func": "parser.c:yaml_parser_parse", "run_turn": 45, "fields": {"作用": "...", "可疑点": "..."}}
```

### 渲染：`exploration_memory.jsonl` → 后续 run 的提示词

新 run 启动时，管线把历史条目渲染成**紧凑只读块**（SUSPICIOUS 优先列出——最有延续价值）：

```
## 前序 run 的函数摘要（只读，非 ground truth）

可疑 (SUSPICIOUS) — 值得继续：
  - parser.c:yaml_parser_parse  递归深度无显式上限
已确认 (CONFIRMED) — 有崩溃：
  - reader.c:yaml_reader_update  已提交 poc
已探索 (EXPLORED) — 未发现问题：
  - scanner.c:yaml_scanner_scan  各类标量正常

建议：优先探索无摘要的函数；SUSPICIOUS 值得先续。
```

### 记忆如何"用于"后续挖掘（作用链路）

```
run 内：
  agent 开始 → 读提示词 MEMORY_SECTION（教维护函数摘要 + 强制检查点）
            → 读提示词 PRIOR_EXPLORATION（前序 run 函数摘要）
  探索循环：
    读源码 → 构造输入 → 跑 bin → 得结论
      └─ 强制检查点触发：追加函数摘要（EXPLORED/SUSPICIOUS/CONFIRMED）
    转向新方向前：cat /work/MEMORY.md → 确认函数不重复
  run 结束：管线收集 MEMORY.md → 解析 → 追加 exploration_memory.jsonl

跨 run：
  run_N 结束 → jsonl += [run_N 的全部函数摘要]
  run_N+1 启动 → 渲染历史 → 注入提示词 → agent 避开已探索、延续 SUSPICIOUS
```

### 记忆如何被观测（"有没有影响"的对账）

观测器实现三层：
1. **写入观测**：MEMORY.md 的写入动作（Write 工具 + bash `>> MEMORY.md` / heredoc）次数与时机。
2. **读取观测**：`cat /work/MEMORY.md` 或 `cat /tmp/exploration_memory.jsonl` 的次数与时机。
3. **影响观测（核心）**：读取记忆后的 Read 函数 vs 记忆标签的对账——
   - 读到已 CONFIRMED/SUSPICIOUS 函数 → "遵循记忆"（应延续）或"违反"（应避开 EXPLORED 无谓重查）
   - 未标记函数 → "新探索"
   输出遵循率/违反率，直接回答"记忆有没有改变行为"。

---

## 3. 分阶段实施步骤

### 阶段 0：基线观测（先看现状长什么样）—— 0.5 天

**目的**：用现有数据校准观测器，并给"无记忆"组提供预期基线。

1. 写 `tools/trace_path.py` 观测器（§4）。
2. 用**现有 liteos-m 20 轮 transcript**（`results/liteos-m/20260815T102113Z/run_*/find_transcript.jsonl`）回放：
   - 挑 `run_000`（快速收敛）与 `run_004`（发散）各出一张路径图。
   - 统计 20 轮的文件访问去重率、重复文件访问、turns-to-crash 分布。
3. **里程碑 M0**：观测器跑通 + 基线数字记录进 `experiments/baseline_liteos_m.md`。

### 阶段 1：搭靶标（libyaml + cjson）—— 1 天

**目的**：给实验提供 1-2 万行的真实、输入驱动、可观测路径的靶标。

1. 建 `targets/libyaml/`：
   - `Dockerfile`（gcc + 固定 commit clone libyaml + **官方 `tests/run-parser.c` 作 fuzz harness**，`-O1 -g -fsanitize=address -fno-omit-frame-pointer`）
   - **不写 entry**：libyaml 自带 `run-parser.c`（读文件 → `yaml_parser_parse` 循环 → delete，支持 `--max-level` 控制嵌套），作为现成输入驱动入口
   - `config.yaml`（`build_command`、`test_command`、3-4 个 focus_areas、attack_surface）
2. 建 `targets/cjson/`（同构，`cJSON_Parse`/`cJSON_Delete`，用上游 DaveGamble/cJSON，非 OHOS fork）。
3. 各 `docker build` + 单轮冒烟：agent 能读源码、构造输入、触发崩溃（`--max-turns 50 --runs 1`）。
4. **里程碑 M1**：两靶标可跑通、能产崩溃、路径图可见。

> **2026-08-31 修订**：本轮先做**小规模预实验**——只用 `libyaml`，A/B 两组**各 3 次、每次 100 turns**（`--runs 3 --max-turns 100`）。目的不是产出统计结论，而是**验证设计本身是否可行**：记忆是否被写入/读取、对账逻辑是否跑通、指标是否可算。cjson 与全量实验留待预实验通过后进行。

### 阶段 2：实现记忆系统（两层）—— 1 天

**目的**：在现有管线上加最小侵入的记忆通道（零新架构，复用 mounts + prompt section 机制）。

1. **层 1（run 内）**：
   - `find_prompt.py` 新增 `MEMORY_SECTION` 模板，插到 `{focus_area_section}` 后。
   - 模板内容：教 agent 维护 `/work/MEMORY.md`（追加式、单行 schema `[region] hypothesis | STATUS | evidence`、转向先读、证伪即记、命中标 DONE）。
   - `run_find()` / 容器准备：预置空 `MEMORY.md`（通过 `sandbox` 挂载或镜像内置）。
2. **层 2（跨 run）**：
   - `find_prompt.py` 新增 `PRIOR_EXPLORATION_SECTION` 模板。
   - `run_find()` 的 `mounts` 追加只读挂载 `exploration_memory.jsonl` → `/tmp/exploration_memory.jsonl`。
   - 新增 `harness/memory.py`：`collect_run_memory(container, ...)`（run 结束读 `MEMORY.md`）+ `append_batch_memory(path, run_idx, entries)` + `render_prior_exploration()`（把历史记忆渲染成提示词块）。
   - `cli.py`：批次级 `exploration_memory.jsonl` 的创建/追加/传递。
3. 单元测试 `tests/test_memory.py`：模板渲染、挂载路径、收集与追加的幂等性。
4. **里程碑 M2**：`vuln-pipeline run --runs 3` 在 canary 上冒烟通过，确认记忆文件被写入并被后续 run 读取（用观测器验证）。

### 阶段 3：A/B 实验 —— 1.5 天

**目的**：采集两组数据。

1. **组 A**：`libyaml`、`cjson` 各 `--runs 6`（现 config）。
2. **组 B**：同一靶标，打开记忆（环境开关 `VULN_PIPELINE_MEMORY=1` 或 CLI flag `--memory`），`--runs 6`。
3. 每组完整记录：`find_transcript.jsonl`、`MEMORY.md`（B 组）、`exploration_memory.jsonl`、`result.json`。
4. 所有 runs 落 `experiments/libyaml-A/...`、`experiments/libyaml-B/...`、cjson 同理。
5. **里程碑 M3**：24 次 find 全部完成，无 run 因记忆机制失败。

### 阶段 4：观测与分析 —— 1 天

**目的**：出结论。

1. 观测器跑全部 24 个 run，生成路径图 + 指标表（§2.3）。
2. 汇总 A vs B：
   - 文件访问去重率、跨 run 重复、turns-to-crash、命中率、分叉数的**差异 + 显著性判断**（样本小，用简单描述统计 + 直观对比，不硬上统计检验）。
   - 抽查 B 组记忆质量：REFUTED 条目是否真实（对照 transcript）。
3. 写 `experiments/MEMORY_EXPERIMENT_RESULTS.md`：
   - 每组路径图精选 2 张（libyaml A/B、cjson A/B）
   - 指标对比表
   - **明确结论**：H1-H4 各自支持/否定/存疑
   - 附带"记忆机制的副作用"（token 开销、写入 turn 消耗、误导案例）
4. **里程碑 M4**：结论文档交付。

---

## 4. 观测器设计（`tools/trace_path.py`）

### 4.1 输入/输出

- **输入**：`<run_dir>/find_transcript.jsonl`（可选 `MEMORY.md`）
- **输出**：文本路径图（stdout）+ JSON 指标（`--json` 供后续统计）

### 4.2 解析逻辑（基于已确认的 transcript 结构）

每条 `tool_use` 事件：`{"type":"tool_use","part":{"type":"tool","tool":"Read|Write|Bash","state":{"input":{...}}}}`。

| 事件 | 提取 | 归类 |
|---|---|---|
| `Read` | `state.input.path` | 文件访问（去 basename/目录归类） |
| `Write` | `state.input.path` | 写入点（`MEMORY.md` 的 Write = 记忆写入时刻） |
| `Bash` | `state.input.command` | 命令类别：编译/运行/抓日志/工具 |

### 4.3 区域切换检测（路径分叉计数）

- 把 `Read` 的文件路径映射到"区域"（如 `los_queue.c` → `kernel/queue`；cjson → `parse_value/parse_array/...`）。
- 连续 Read 落在同一区域算同一段；区域改变计一次"分叉"。
- Bash 中的 `qemu`/`./entry` 运行视为"验证动作"，不计入分叉。

### 4.4 文本路径图形态（示意）

```
run_003 探索路径 (47 turns)
──────────────────────────────────────
阶段 1  读源码        [t 1-12]   cJSON.c → cJSON_Utils.c
阶段 2  构造输入      [t 13-20]  bash: printf 畸形JSON → ./entry → ASAN clean
阶段 3  换向          [t 21-33]  cJSON_Utils.c → cJSON.c(parse_value)   ★分叉
阶段 4  命中          [t 34-45]  bash: 嵌套数组 → ASAN stack-overflow ★
记忆写入  [t 46]  MEMORY.md: "[cJSON.c] 递归无深度限制 | DONE"
──────────────────────────────────────
指标: 区域数=3 分叉=1 Read去重率=0.71 turns-to-crash=45
```

### 4.5 观测器的使用方式

```bash
python3 tools/trace_path.py results/liteos-m/.../run_000/   # 单 run 路径图
python3 tools/trace_path.py results/.../ --batch --json > metrics.json   # 批量指标
```

---

## 5. 文件/目录布局（交付物）

```
docs/memory-experiment-plan.md          ← 本文档
tools/trace_path.py                     ← 观测器（阶段 0）
harness/memory.py                       ← 记忆收集/渲染/追加（阶段 2）
harness/prompts/find_prompt.py          ← + MEMORY_SECTION / PRIOR_EXPLORATION_SECTION
harness/find.py / cli.py                ← mounts + 收集钩子 + --memory 开关
tests/test_memory.py                    ← 记忆模块单测
targets/libyaml/{Dockerfile,entry.c,config.yaml,README.md}
targets/cjson/{Dockerfile,entry.c,config.yaml,README.md}
experiments/
  baseline_liteos_m.md                  ← 阶段 0 基线
  libyaml-A/  libyaml-B/  cjson-A/  cjson-B/   ← 实验 runs 数据
  MEMORY_EXPERIMENT_RESULTS.md          ← 最终结论（阶段 4）
```

---

## 6. 风险与缓解

| 风险 | 缓解 |
|---|---|
| 记忆写入消耗 turns，反而拖慢（H3 反假设） | 提示词明确"追加单行、不编辑历史"；主指标"区域收敛 turns"单独衡量 |
| 记忆内容噪声化，误导后续 run | 提示词标注"非 ground truth，是前人的地图"；`PRIOR_EXPLORATION_SECTION` 中 REFUTED 与 PROMISING 分开渲染 |
| 24 次 find 成本（模型 token） | 用 `deepseek-v4-flash`（便宜）；`--max-turns 200` 足够；可先跑 3+3 预实验再扩到 6+6 |
| 不依赖 crash 后"覆盖区域"定义模糊 | 区域映射规则在观测器里显式定义并归档（见 §4.3），两组共用同一映射 |
| 观测器解析脆弱（transcript 格式变化） | 解析函数加容错（未知事件跳过）；用现有 20 轮 liteos-m transcript 做回归 |
| 结果不显著（样本小） | 明确这是机制验证不是统计显著性研究；结论如实报告"方向性证据" |

---

## 7. 时间线汇总

| 阶段 | 内容 | 耗时 | 里程碑 |
|---|---|---|---|
| 0 | 观测器 + 基线 | 0.5 天 | M0：观测器跑通 + 基线数字 |
| 1 | libyaml/cjson 靶标 | 1 天 | M1：两靶标可跑通 |
| 2 | 记忆系统两层 | 1 天 | M2：canary 冒烟通过 |
| 3 | A/B 实验（24 runs） | 1.5 天 | M3：数据采集完成 |
| 4 | 观测分析 + 结论 | 1 天 | M4：结论文档交付 |

**总计约 5 天**（可压缩：阶段 1 与阶段 0 可并行；阶段 3 可先 3+3 验证）。

---

## 8. 验收标准（做什么算完成）

1. `tools/trace_path.py` 能对现有 liteos-m transcript 出路径图，且对实验 24 个 run 全量解析无失败。
2. 记忆两层机制在 canary 冒烟中确认：B 组 agent 确实写 `MEMORY.md`，且后续 run 确实 `cat` 到 `exploration_memory.jsonl`。
3. A/B 各 6 runs × 2 靶标数据齐备，指标表生成。
4. `MEMORY_EXPERIMENT_RESULTS.md` 对 H1-H5 给出**明确的支持/否定/存疑**判断，附路径图证据；即使全部 run 无 crash，主指标对比依然完整。
5. 若 H1/H2/H3 获支持 → 记忆机制作为可开关功能合入管线（默认关，`--memory` 开启）。

---

## 9. 第二轮实验（Kafka Java 靶标）— 2026-09-01 起

### 9.1 背景与改动

第一轮（libyaml）暴露两个问题后，按用户要求做了三处设计改动并换更大靶标：

1. **禁 fuzz**：find 主模板加指令 0 —— "This is a code-analysis mission, NOT a fuzzing mission. Do NOT write or run fuzzers."（agent 的价值在静态代码分析，fuzz 交给专用工具）
2. **记忆索引模式**：`MEMORY_SECTION` 重写为 **INDEX-FIRST 工作流** —— 研究函数前先 `grep` 索引；EXPLORED 且无可疑 → 直接采用摘要不重读源码；SUSPICIOUS → 优先验证；无记录 → 读源码后追加
3. **换靶标 Kafka 4.4.0-rc0**（Java，完整内存检测）：见 `docs/KAFKA_MEMORY_EXPERIMENT_RESULTS.md`

### 9.2 Java 内存检测方案（无 ASAN）

| Java 错误 | 触发 | 检测 |
|---|---|---|
| `OutOfMemoryError`（堆/直接） | 输入可控大分配 | `-Xmx512m -XX:MaxDirectMemorySize=256m -XX:+ExitOnOutOfMemoryError` |
| `StackOverflowError` | 输入可控递归 | 未捕获 → 非零退出 |
| `BufferUnderflow/Overflow` | NIO 越界 | 未捕获 → 非零退出 |
| `ArrayIndexOutOfBounds` | 未检查索引 | 未捕获 → 非零退出 |

**优雅拒绝**（SchemaException/IllegalArgumentException/CorruptRecordException）= 正确行为，不算 bug。

### 9.3 第二轮结果摘要

| 指标 | A（无记忆） | B（有记忆） |
|---|---|---|
| crash 命中 | 2/3 | **3/3** |
| 崩溃类型 | OOM ×2 | OOM ×2 + IndexOutOfBounds |
| 源码分析强度（cat+grep+read 次/run） | 25.7 | **37.3（+45%）** |
| find 时长 | 243s | 471s（+94%） |

**记忆传导**：run_001 探索 protocol 层（ByteBufferAccessor/Type/ArrayOf），run_002 拿 prior 后标记 "dup 不提交"（避免重复提交已知 bug）并 CONFIRMED 新的 `AbstractLegacyRecordBatch.DataLogInputStream` 无上限 allocate。

### 9.4 第二轮新增教训

1. 记忆解析器必须**宽容 agent 格式漂移**：`File:func` / `File | func` / `File func` 都支持，func 规范化
2. `_ENTRY_RE` 支持 `.java`（原只 `.c/.h`）
3. JVM prompt 必须**指明 JDK 位置**（`/opt/java/openjdk`），否则 agent 浪费 turns 找/装 JDK
4. 观测器需适配 Java region 规则 + 独立行为对比脚本（`tools/compare_behavior.py`）

### 9.5 待办

- [ ] 把 libyaml + Kafka 两轮结果合并进最终结论
- [ ] 记忆机制合入管线（默认关，`--memory` 开启）——待 H1-H5 在更大样本下确认
