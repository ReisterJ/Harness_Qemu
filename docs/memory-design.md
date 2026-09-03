# 探索记忆机制 — 详细设计文档

> 版本: 2026-09-03（对应代码现状）
> 范围: vuln-pipeline find-agent 的"探索记忆"系统（层 1 函数索引 + 层 2 跨 run ledger）
> 定位: 本文件是**设计规范 + 实现说明 + 实验档案**三位一体，读这一份即可理解记忆机制的来龙去脉与全部实现细节。

---

## 目录

1. [定位与目标](#1-定位与目标)
2. [背景：管线机制缺陷与动机](#2-背景管线机制缺陷与动机)
3. [设计演进史](#3-设计演进史)
4. [核心设计原则](#4-核心设计原则)
5. [两层架构总览](#5-两层架构总览)
6. [完整数据流](#6-完整数据流)
7. [层 1 规格：/work/MEMORY.md](#7-层-1-规格workmemorymd)
8. [层 2 规格：exploration_memory.jsonl](#8-层-2-规格exploration_memoryjsonl)
9. [提示词契约](#9-提示词契约)
10. [解析器设计](#10-解析器设计)
11. [渲染与注入](#11-渲染与注入)
12. [管线集成点（代码地图）](#12-管线集成点代码地图)
13. [容错与鲁棒性](#13-容错与鲁棒性)
14. [观测与评估工具](#14-观测与评估工具)
15. [实验证据档案](#15-实验证据档案)
16. [已知局限](#16-已知局限)
17. [后续方向](#17-后续方向)

---

## 1. 定位与目标

**一句话**：在 find-agent 的漏洞挖掘流程中引入"探索记忆"——run 内 agent 自维护一份函数摘要索引（`/work/MEMORY.md`），run 间由编排器把索引累积到批次 ledger（`exploration_memory.jsonl`）并注入后续 run——目标是**让代码挖掘更系统：少重复、广覆盖、好接续**。

**要回答的实验问题**（来自 `docs/memory-experiment-plan.md`）：
> 引入"探索记忆"能否可观测地优化漏洞挖掘逻辑（减少重复探索、更快收敛、更好利用前序信息）？

**约束与定位**：
- **过程导向**：主指标是探索过程质量（覆盖率/重复/接续），不依赖 crash 命中（crash 是次要参考指标）。
- **记忆是辅助，不是自动驾驶**：agent 仍是完整自主的 find-agent；记忆只是它的"笔记 + 前人手札"。
- **最小侵入**：不改 agent 工具集、不改 opencode 交互；记忆只通过"一个文件 + 提示词规则 + 宿主侧纯文本/JSON 处理"实现。

---

## 2. 背景：管线机制缺陷与动机

现有管线在"探索信息持久化"上有三处缺陷，记忆系统逐一补上：

| 现有机制 | 记什么 | 缺陷 |
|---|---|---|
| `found_bugs.jsonl`（跨 run 挂载） | 已提交崩溃的 ASAN 摘要 | 只记**成果**，不记**过程**（证伪、已探区域、可疑点） |
| `focus_areas.json`（recon 生成） | 静态挖掘方向 | 静态分区，run 之间**无信息流动** |
| find-agent 会话（`max_turns` 上限） | 模型上下文 | 一次性；run 结束即丢；resume 只恢复同会话 |

**核心缺口**：agent 在长会话中会忘记自己查过什么、证伪过什么；多个 run 各自为战，重复挖掘同一区域，忽略未探索区域。记忆系统补上这层**过程记忆**——精确到"函数"粒度的探索地图。

---

## 3. 设计演进史

记忆格式与工作流不是一次成型，经历了三轮迭代（每轮都有实测证据驱动）：

### v1（假设/证伪格式）— 被推翻
最初设计每条记忆 = 一个"假设 → 证据 → 验证 → 结论"循环（DONE/REFUTED/PROMISING）。
**实测失败**（冒烟 v1）：agent 读了空 MEMORY.md 后转向写 fuzzer、陷入"写 fuzzer → 跑 fuzzer"循环，100 turns 里**从未写任何记忆条目**。结论：假设格式对"代码挖掘"场景太抽象，agent 不知道什么时候该记。

### v2（函数摘要格式）— 核心定型
改为**每条 = 一个被读函数的"知识卡片"**（作用/输入/安全关注/已验证/可疑点），状态改为 EXPLORED/SUSPICIOUS/CONFIRMED，并在提示词里加"强制检查点"。
**实测成功**（冒烟 v2）：agent 主动写出高质量函数摘要（含 YAML_MALLOC 尺寸分析、token 所有权追踪等）。
**仍存问题**（libyaml 正式 A/B）：记忆"写侧"不稳定（13/0/4 条/run）——agent 拿到 prior 后转向 fuzzing/执行型任务就跳过记忆写入；且覆盖率无显著优势。

### v3（禁 fuzz + 索引优先）— 当前版本
用户两个关键决策改变了行为：
1. **禁 fuzz**：提示词明确 "This is a code-analysis mission, NOT a fuzzing mission. Do NOT write or run fuzzers."——把 agent 的 turns 从"跑 fuzzer"解放回"读源码分析"，这是记忆能被写、被用的前提。
2. **索引优先（INDEX-FIRST）**：MEMORY.md 从"记录本"升级为"**索引**"——研究函数前先 `grep` 查是否已探索，命中就直接用摘要、不重读源码。
**实测**（冒烟 v3 + Kafka 轮）：写侧稳定（libyaml 14 条、Kafka 各 run 稳定产出），agent 主动 grep 索引、标记 dup 不提交；Kafka 轮 B 组覆盖率文件级 +89%。

### Java 适配（2026-09）
靶标切换到 Kafka 4.4.0-rc0（Java）后修了三个格式问题：`.java` 扩展名、`File:func` 分隔符漂移（agent 会用 `File | func`）、以及 JVM prompt 的 JDK 定位。

**一句话教训**：记忆格式必须贴 agent 的**自然工作单元**（读函数 → 记函数），且不能与"跑 fuzzer"争夺 turns。

---

## 4. 核心设计原则

1. **粒度 = 函数**。agent 最自然的原子动作是"读一个函数源码"。记忆按函数记录，天然可 grep、可去重、可接续。
2. **格式是"半结构化文本"，不是数据库**。agent 用 heredoc/echo 追加 markdown（不需要任何工具），宿主用正则解析成 JSON（供程序化处理）。两全：agent 好写，程序好读。
3. **管道只做搬运，不做语义判断**。宿主解析器只负责"标题行 + 字段行"的结构提取；"这函数是否真的安全"是 agent 的判断（写入时就带上了状态）。管道保证：**写了的会被记住、记住了会被传给下一个**。
4. **状态收敛到 3 个**。EXPLORED（读过没问题）/ SUSPICIOUS（有值得回查的点）/ CONFIRMED（确认了 bug/crash）。SUSPICIOUS 是专门为"跨 run 接续"设计的信号——前人把没查完的线索留给你。
5. **索引是 grep-able 的**。agent 用一次 `grep -n` 就能查询，不需要额外工具；提示词把"先查索引"设为强制工作流。
6. **追加不编辑**。MEMORY.md 只 append（不修改历史），保持审计性与 resume 一致性。
7. **可开关**。整个机制由 `--memory` flag 控制，默认关；不开启时管线行为与旧版完全一致。

---

## 5. 两层架构总览

```
┌────────────────────────────── 层 1：run 内 ──────────────────────────────┐
│  find-agent 容器里 /work/MEMORY.md（agent 自维护，追加式）                │
│  - 预置：空文件（带标题说明）                                             │
│  - 使用：研究函数前 grep 索引；新函数读后追加摘要                          │
│  - 收集：run 结束（容器拆除前）由宿主读回，存 run_NNN/MEMORY.md            │
└───────────────────────────────────────────────────────────────────────────┘
                                    │ collect_run_memory()
                                    ▼
┌────────────────────────────── 层 2：跨 run ──────────────────────────────┐
│  编排器宿主（results_root/exploration_memory.jsonl）                     │
│  1. parse_memory_md()  → MEMORY.md 文本 → 结构化条目（JSON）             │
│  2. append_entries()   → 追加到批次 ledger（每 run 一条/函数）            │
│  3. read_entries()     → 后续 run 启动前读取全部历史                     │
│  4. render_prior_exploration() → 渲染成"前序函数索引"提示词块            │
└───────────────────────────────────────────────────────────────────────────┘
                                    │ 注入下一 run 的 find prompt
                                    ▼
                        下一 run 的 agent 看到 prior 索引
                        （EXPLORED=跳过 / SUSPICIOUS=接续 / 无条目=优先探索）
```

- **信任边界**：层 1 在 agent 容器内（agent 可写）；层 2 在宿主（agent 不可达）。只有 run 结束时读出的文本穿越边界。find-agent 无法污染 ledger。
- **实现位置**：`harness/memory.py`（纯文本/JSON，无 docker、无 agent 调用）。

---

## 6. 完整数据流

一个 find run（`--memory` 开启时）的完整生命周期：

```
[批启动] cli.py _run_all
   ├─ 创建 results_root/exploration_memory.jsonl（空种子）         L777-779
   └─ 每个 run i：
        │  _task(i) 渲染 prior（读 ledger → render）               L816-824
        ▼
   [run i] run_find()
        ├─ sandbox.agent_container() 起容器
        ├─ seed_memory_content() 写空 /work/MEMORY.md              find.py L62
        ├─ entries_to_markdown(ledger) → 写 /work/PRIOR_MEMORY.md   find.py（只读历史，可 grep）
        ├─ build_find_prompt(memory_enabled, prior_exploration)
        │     └─ 模板拼 MEMORY_SECTION + PRIOR_EXPLORATION_SECTION
        ├─ run_agent()（agent 执行 max_turns 步）
        │     └─ agent 行为：grep 索引 / cat MEMORY.md /
        │        read 源码 → heredoc 追加摘要                        (容器内)
        └─ collect_run_memory(container) → run_NNN/MEMORY.md        find.py L95-99
        ▼
   [run i 收尾] cli.py _run_once
        parse_memory_md(MEMORY.md, run_idx=i)                        L302-303
        append_entries(exploration_memory.jsonl, entries)            L305
        ▼
   [run i+1 启动] 重新读 ledger 渲染 prior → 注入                   循环
```

关键点：
- **渲染发生在 run 启动前**，读到的是**已完成 run** 累积的 ledger（含当前批所有前置 run）。并行 run 之间由文件追加天然串行化（无锁竞争——每 run 收尾时一次性 append）。
- **收集发生在容器拆除前**（`run_find` 的 with 块内），保证 agent 最后写的记忆不丢。
- **一个 run 的 MEMORY.md 写两处**：`run_NNN/MEMORY.md`（原文，人工可查）+ ledger（解析后 JSON，程序可读）。

---

## 7. 层 1 规格：/work/MEMORY.md

### 7.1 文件位置与预置

- 路径：`/work/MEMORY.md`（容器内，常量 `memory.MEMORY_PATH`）
- 预置内容（`seed_memory_content()`，find 启动时 docker write）：

```markdown
# Exploration Memory — function summaries

Maintained by the find agent. Append-only. Each entry is a summary of
ONE function you have examined. See prompt for the exact schema.
```

- 生命周期：整个 run + 任何 resume 都存活（文件在容器里）；容器拆除时由宿主读回。

### 7.2 条目格式（提示词规定的 schema）

```markdown
### [STATUS] FILE.c:function | turn=N
- 作用: <what the function does>
- 输入: <what inputs/params it takes; any untrusted data path>
- 安全关注: <memory ops, bounds, recursion, unchecked sizes, ...>
- 已验证: <what you actually ran/observed, or "无">
- 可疑点: <suspicious finding, or "无">
```

字段语义：

| 行 | 键 | 目的 |
|---|---|---|
| 标题 | — | **索引键**：状态 + 文件:函数 + 记录时 turn |
| `- 作用` | role/作用 | 函数干什么（供后人判断是否相关） |
| `- 输入` | inputs/输入 | 输入/参数；是否含不可信数据路径 |
| `- 安全关注` | safety/安全关注 | 内存操作、边界、递归、未检查尺寸 |
| `- 已验证` | verified/已验证 | 实际跑了什么/观察到什么（或"无"） |
| `- 可疑点` | 可疑点 | 可疑发现（或"无"）——**渲染时优先展示** |

> 注意：字段键支持中英文两种写法（解析器白名单见 §10）。agent 实际多用中文键（Kafka 轮全部是中文键）。

### 7.3 状态机

```
       读源码，无问题                发现可疑点                验证/复现崩溃
  ──►  EXPLORED ────────────────►  SUSPICIOUS ─────────────►  CONFIRMED
        （已读，没发现）              （值得回查）               （确认 bug/crash）

  SUSPICIOUS → EXPLORED：回查后排除（追加新条目覆盖，不编辑历史）
```

- 每个状态是**追加**的新条目（标题带新状态），不修改旧条目。宿主去重时"新的覆盖旧的"。
- `turn=N`：agent 记录的写入时 turn（供追溯它在哪一步沉淀的）。

### 7.4 真实样例（来自 Kafka exp-B run_002 实际产出）

```markdown
### [CONFIRMED] AbstractLegacyRecordBatch.java:DataLogInputStream | turn=15
- 作用: 解压后的 legacy (magic-0/1) 内层记录流解析; 读 [offset:8][size:4] 后
  `ByteBuffer.allocate(size)`。
- 输入: 压缩 legacy 批次 (attributes 低 3 位=1 gzip) 的 wrapper value 内层流,
  size Int32 完全由输入控制; 无上限 (maxMessageSize=Integer.MAX_VALUE)。
- 安全关注: `if (size < 14) throw; if (size > MAX_VALUE) throw;` 之后无界
  ByteBuffer.allocate(size) → OOM; 走 DeepRecordsIterator 由 Harness 可达。
- 已验证: /tmp/poc_legacy_gzip.bin (60B, magic-1 gzip wrapper, 内层
  size=0x40000000) → `java.lang.OutOfMemoryError: Java heap space` @
  DataLogInputStream.nextBatch(AbstractLegacyRecordBatch.java:305), 3/3 复现,
  exit 3。size=0x7FFFFFFF → "Requested array size exceeds VM limit"。
- 可疑点: 无上限 allocate — 已确认 (CONFIRMED)。
```

这展示了记忆条目的信息密度：不只"看过这函数"，还带了**可达性论证 + PoC 构造 + 复现结果 + 与已知 bug 的区分**——完全可被下一 run 直接消费。

---

## 8. 层 2 规格：exploration_memory.jsonl

### 8.1 文件

- 路径：`results_root/exploration_memory.jsonl`（批次的根目录，常量 `BATCH_MEMORY_NAME`）
- 格式：JSON Lines，每行一条解析后的记忆条目（`ensure_ascii=False`，UTF-8）
- 种子：批启动时创建空文件（`cli.py` L778-779）；每次 run 收尾 append。

### 8.2 条目 JSON schema

```jsonc
{
  "status": "EXPLORED",        // EXPLORED | SUSPICIOUS | CONFIRMED
  "func": "DefaultRecord.java:readFrom",   // 规范化后的 "文件:函数"
  "run_turn": 10,              // agent 记录时 turn（可 null）
  "fields": {                  // 字段行（中英文键归一）
    "作用": "...",
    "输入": "...",
    "安全关注": "...",
    "已验证": "...",
    "可疑点": "..."
  },
  "raw": "### [EXPLORED] DefaultRecord.java:readFrom | turn=10",  // 原始标题行
  "valid": true,               // 状态是否在合法集合
  "_block": "- 作用: ...\n...", // 整个条目块原文（≤600 字符），供人工/调试
  "run": 1                     // 来源 run 序号（parse 时注入）
}
```

### 8.3 真实样例（B 组 ledger 中的一条 CONFIRMED）

```json
{"status": "CONFIRMED", "func": "AbstractLegacyRecordBatch.java:DataLogInputStream",
 "run_turn": null,
 "fields": {"作用": "解压后的 legacy (magic-0/1) 内层记录流解析; 读 [offset:8][size:4] 后 `ByteBuffer.allocate(size)`。",
            "输入": "压缩 legacy 批次 (attributes 低 3 位=1 gzip) 的 wrapper value 内层流, size Int32 完全由输入控制; 无上限 (maxMessageSize=Integer.MAX_VALUE)。",
            "安全关注": "`if (size < 14) throw; if (size > MAX_VALUE) throw;` 之后无界 ByteBuffer.allocate(size) → OOM; ...",
            "已验证": "/tmp/poc_legacy_gzip.bin (60B, magic-1 gzip wrapper, 内层 size=0x40000000) → ... 3/3 复现, exit 3。...",
            "可疑点": "无上限 allocate — 已确认 (CONFIRMED)。"},
 "raw": "### [CONFIRMED] AbstractLegacyRecordBatch.java:DataLogInputStream.nextBatch | turn=15",
 "valid": true, "_block": "...", "run": 2}
```

---

## 9. 提示词契约

记忆机制在 find prompt 里注入两个 section（只在 `memory_enabled=True` 时）：

### 9.1 MEMORY_SECTION（run 内规则，MANDATORY）

`harness/prompts/find_prompt.py`。核心是 **INDEX-FIRST 工作流**：

> 1. About to study a function? FIRST run `grep -n "<function_name>" /work/MEMORY.md`.
> 2. Entry exists with STATUS=EXPLORED and 可疑点=无 → **read the summary and move on. Do NOT re-read the source.**
> 3. Entry exists with STATUS=SUSPICIOUS → **prioritize verifying the recorded 可疑点**.
> 4. No entry → read the source, then append a summary entry.

四个强制检查点：
> 1. Check the index (grep) before studying ANY function. Never read source for a function already EXPLORED with no suspicious point.
> 2. After you read source for a NEW function, append its summary entry.
> 3. Every ~20 tool calls, `cat /work/MEMORY.md`, confirm your next action is not re-exploring an already-indexed function.
> 4. When you find a suspicious spot, mark it SUSPICIOUS with the reason.

### 9.2 PRIOR_EXPLORATION_SECTION（前序索引，只读）

> Other runs already examined functions in this target. Their summaries are below...
> **Treat this as an index: functions already EXPLORED with 可疑点=无 are done — skip them unless you have a genuinely new angle. Prioritize SUSPICIOUS entries, then functions with NO entry.**
> {prior_exploration}
> > These are a map of where predecessors dug, NOT ground truth...

### 9.3 前置条件：禁 fuzz 指令（主模板 Instructions 0）

> **This is a code-analysis mission, NOT a fuzzing mission. Do NOT write or run fuzzers.** ... Your value is reading source, tracing data flow, and reasoning about memory safety. Spend your turns on static analysis.

**为什么禁 fuzz 是记忆的前提**：如果 agent 把 turns 花在跑 fuzzer 上，它既没"读函数"可记，也不看索引。禁 fuzz 把时间还给源码分析，记忆才有内容、索引才有意义。

### 9.4 语言/靶标变体

`build_find_prompt` 按 `detector` 选模板（asan/kasan/lms/qemu-asan/jvm），记忆 section 对所有模板统一追加（5 个模板都有 `{memory_section}{prior_exploration_section}` 占位）。JVM 模板额外加了：JDK 位置（`/opt/java/openjdk` 已装）、"用 cat 读源码"、Java 内存错误质量分级（OOM/StackOverflow/越界 = 崩溃信号，SchemaException 等优雅拒绝不算 bug）。

---

## 10. 解析器设计

`memory.parse_memory_md(content, run_idx)` 是纯文本→结构化。

### 10.1 正则

```python
# 标题行：### [STATUS] file.c:function | turn=N
_ENTRY_RE = re.compile(
    r"^###\s*\[(?P<status>[A-Z_]+)\]\s*"
    r"(?P<func>[\w./-]+\.(?:c|h|java)[\s:|]+[\w]+)"
    r"(?:\s*\|\s*turn=(?P<run_turn>\d+))?"
)
# 字段行：- 键: 值（中英文冒号均可）
_FIELD_RE = re.compile(r"^\s*-\s*(?P<key>[\w/]+)\s*[:：]\s*(?P<val>.*)$")
```

### 10.2 格式容错（实测驱动的三处）

| 容错点 | 为什么 | 怎么容 |
|---|---|---|
| 扩展名 `.c/.h/.java` | 靶标从 C（libyaml）切到 Java（Kafka） | `\.(?:c|h|java)` |
| `file:func` 分隔符漂移 | agent 会写 `File.java | func`、`File.java func` 而非 `:func`（Kafka run_000 全用管道分隔，曾导致解析 0 条） | `[\s:|]+` 匹配冒号/管道/空格 |
| func 规范化 | 让 `File.java | iterator` 与 `File.java:iterator` 去重一致 | `re.sub(r"[\s:|]+", ":", func)` |

### 10.3 解析规则细节

- **条目边界**：一个标题行开始新条目，直到下一个标题行（或文件尾）。
- **字段白名单**：`role/作用`、`inputs/输入`、`safety/安全关注`、`verified/已验证`、`notes/备注`、`可疑点`、`conclusion`——命中才进 `fields`，键 `.lower()` 归一（中文键保持）。
- **`_block` 截断**：原始条目块保留 ≤600 字符（防超大条目撑爆 ledger/渲染）。
- **状态合法集**：`{EXPLORED, SUSPICIOUS, CONFIRMED}`；未知状态保留但 `valid=False`。
- **`run_idx`**：非 None 时给每条注入来源 run 序号。
- **跳过**：不符合标题正则的行（如多函数空格分隔、自由文本）不进条目；条目内非字段行并入 `_block`。

---

## 11. 渲染与注入

`memory.render_prior_exploration(entries, max_lines=15)` 把 ledger 渲染成提示词块。

### 11.1 规则

1. **按状态分组排序**：SUSPICIOUS → CONFIRMED → EXPLORED（最值得接续的在前）。
2. **按函数去重取新**：`newest_by_func`——同一 `func` 多条时保留最新（追加语义下后者覆盖前者，保证状态演进可见）。
3. **每行格式**：`- [S] func  可疑点/备注/作用`（优先展示可疑点，截断 70 字符）。
4. **截断**：超过 `max_lines`（默认 15）则截断并加 `... (截断)`。
5. **空 history 返回空串**（渲染块不注入）。

### 11.2 真实渲染输出（Kafka exp-B ledger 14 条）

```
## 前序 run 的函数索引（只读，非 ground truth）

已探索(EXPLORED)且无可疑点 = 已完成：直接采用摘要，不要重读源码。
优先 SUSPICIOUS 条目，其次无索引的函数。

已确认 (CONFIRMED) — 有崩溃：
  - [C] AbstractLegacyRecordBatch.java:DataLogInputStream  无上限 allocate — 已确认 (CONFIRMED)。
已探索 (EXPLORED) — 未发现问题：
  - [E] ByteBufferAccessor.java:readArray  无 (negative size reachable only via non-guarding caller; none found in
  - [E] ByteBufferAccessor.java:readByteBuffer  无.
  - [E] Type.java:stringRead  无.
  ...
建议：优先探索无索引的函数；SUSPICIOUS 的值得先续；EXPLORED 若你发现新角度可重查。
```

### 11.3 可查询历史文件 /work/PRIOR_MEMORY.md（2026-09-03 新增）

**动机**：注入的索引是每函数一行（15 行上限），agent 若想细看前人某函数的完整分析
（作用/输入/安全关注/已验证全文），提示词里拿不到。改进：把前序完整分析落成容器内
**只读文件**，提示词只给索引 + 指引，细节由 agent `grep` 查询。

- 路径：`/work/PRIOR_MEMORY.md`（常量 `memory.PRIOR_MEMORY_PATH`）；每 run 启动时由
  `entries_to_markdown(read_entries(ledger))` 重建并写入容器（只读，60KB 上限）。
- 内容：ledger 条目**全字段**渲染回 markdown（与索引同策略：按函数去重取新），带
  `run=`/`turn=` 溯源；agent 可 `grep -A 10 "<func>" /work/PRIOR_MEMORY.md` 拿全文。
- 提示词契约：MEMORY_SECTION 与 PRIOR_EXPLORATION_SECTION 均加指引
  （"FULL write-ups live at /work/PRIOR_MEMORY.md — grep it for details"）。
- 真实示例：Kafka exp-B ledger 14 条 → 去重 11 个条目 → 5385 字符完整历史
  （含 CONFIRMED 的 DataLogInputStream 完整论证）。

```markdown
### [EXPLORED] ByteBufferAccessor.java:readArray | run=1 turn=6
- 作用: Readable impl; reads `size` bytes into a new byte[] from the underlying ByteBuffer.
- 输入: `size` from caller (generated Message code reads it from input fields).
- 安全关注: negative size → NegativeArraySizeException; size>remaining → RuntimeException (checked).
- 已验证: read source; generated callers guard ...
- 可疑点: 无 (negative size reachable only via non-guarding caller; none found in production).
```

---

## 12. 管线集成点（代码地图）

| 环节 | 文件:函数 | 说明 |
|---|---|---|
| 常量（路径/状态/空文件） | `harness/memory.py` 顶部 | `MEMORY_PATH`、`BATCH_MEMORY_NAME`、`VALID_STATUSES`、`EMPTY_MEMORY` |
| 预置空 MEMORY.md | `harness/find.py` `run_find()`（`memory_enabled` 分支） | `docker_ops.write_file(container, MEMORY_PATH, seed_memory_content())` |
| prompt 拼接记忆段 | `harness/prompts/find_prompt.py` `build_find_prompt()` | `memory_enabled` → `MEMORY_SECTION`；`memory_enabled and prior_exploration` → `PRIOR_EXPLORATION_SECTION` |
| 收集（容器→宿主） | `harness/memory.py` `collect_run_memory()` | run 结束、容器拆除前 docker read |
| 存原文 | `harness/find.py` `run_find()` | 写 `memory_out_path`（=`run_NNN/MEMORY.md`） |
| 解析 | `harness/memory.py` `parse_memory_md()` | 标题/字段正则 + 容错 + `_block` |
| 追加 ledger | `harness/memory.py` `append_entries()` + `harness/cli.py` `_run_once()` L299-306 | run 收尾执行 |
| 读 ledger | `harness/memory.py` `read_entries()` | 容错半行 JSON |
| 渲染 prior | `harness/memory.py` `render_prior_exploration()` | 分组/去重/截断 |
| 注入 | `harness/cli.py` `_task()` L816-824 | run 启动前渲染，传 `_run_once(..., prior_exploration=prior, exploration_memory_path=...)` |
| CLI 开关 | `harness/cli.py` `--memory` flag | `memory_enabled=args.memory` |

---

## 13. 容错与鲁棒性

- **ledger 半行容忍**：`read_entries` 对 JSONDecodeError 行跳过（并发 append 时读到半个条目不崩）。
- **MEMORY.md 缺失**：`collect_run_memory` 读不到返回 `""`；`memory_file.exists()` 守卫 ledger 追加。
- **收集失败不阻断**：收集/解析/追加都包在 `if memory_enabled` 里，异常不致命（append 无 try 但仅在 exists 且 entries 非空时调）。
- **空 history**：`render_prior_exploration([])` 返回空串，prior section 不注入（不会给 agent 一段空标题）。
- **超大条目**：`_block` 600 字符封顶；渲染单行 70 字符截断、总行数 15 截断。
- **格式漂移**：正则对扩展名/分隔符宽容；解析不出的行静默跳过（不破坏其余条目）。

---

## 14. 观测与评估工具

| 工具 | 作用 |
|---|---|
| `tools/trace_path.py` | 回放 transcript → 路径图 + 过程指标（regions/reentry/forks/span/memR/memW）。region 规则含 libyaml（`/src/*.c`）与 Kafka（`common/{record,protocol,utils,memory,network}`） |
| `tools/compare_coverage.py` | 文件级/包级覆盖率对比（从 read 工具 + bash cat/grep 提取源码文件接触，按 Kafka 包分组，跨 run 累计 + 新增） |
| `tools/compare_behavior.py` | 行为分类计数（cat 源码 / grep 源码 / ls 探索 / 跑 harness / 构造 PoC / read 工具），量化"源码分析 vs 黑盒试错" |
| 实验文档 | `docs/MEMORY_EXPERIMENT_RESULTS.md`（libyaml 轮）、`docs/KAFKA_MEMORY_EXPERIMENT_RESULTS.md`（Kafka 轮） |

---

## 15. 实验证据档案

### 15.1 冒烟史（libyaml，功能验证）

| 冒烟 | 格式/提示词 | 关键结果 |
|---|---|---|
| v1 | 假设/证伪格式 | ❌ agent 100 turns 从不写记忆（转向 fuzzing） |
| v2 | 函数摘要 + 强制检查点 | ✅ agent 主动写 11+ 条高质量摘要；全链路（预置→写→收集→解析→ledger→渲染）打通 |
| v3 | +禁 fuzz +索引优先 | ✅ 14 条；agent 明说 "structured, not random fuzzing"；主动 grep/cat MEMORY.md 索引 |

### 15.2 libyaml 正式 A/B（旧提示词，3 runs × 100 turns）

- 记忆链路功能全通，B 组摘要质量高（含数学安全论证）
- **但覆盖率/重复无显著优势**（regions 5.3 vs 5.7；reentry 反而 20 vs 15.7——经分析是"深化回访 + 执行噪声"被 reentry 指标误计）
- 写侧不稳定：13/0/4 条（run_001 转向 fuzzing 零写入）

### 15.3 Kafka 冒烟（40 turns，新提示词 + JVM detector）

- **crash_found**：agent 找到 `DefaultRecord.readFrom`（line 286）`ByteBuffer.allocate(sizeOfBodyInBytes)` 无防护 → OOM；grader score 1.0
- 记忆 5 条含 CONFIRMED 标记；memR=4/memW=2
- 顺带修了 `.java` 解析 bug、分隔符漂移 bug

### 15.4 Kafka 正式 A/B（新提示词 + JVM，3 runs × 100 turns）

| 指标 | A（无记忆） | B（有记忆） |
|---|---|---|
| crash 命中 | 2/3（1 被拒） | **3/3** |
| 崩溃类型 | 仅 OOM | OOM + IndexOutOfBounds（更广） |
| 累计独特源码文件 | 18 | **34（+89%）** |
| 累计覆盖包 | 5 | **9（+80%）** |
| 源码分析强度（接触次/run） | 25.7 | **37.3（+45%）** |
| find 时长 | 243s | 471s |

- **记忆传导实证**：run_001 探索 protocol 层并写 10 条；run_002 拿 prior 后显式标记 "dup, 不提交"（避免重复提交已知 bug），并 CONFIRMED 新的 `AbstractLegacyRecordBatch.DataLogInputStream` 无上限 allocate（不同函数链 → 提交）。
- **对照天然性**：run_000→run_001 传导曾因解析 bug 断裂（run_001 prior 为空），run_001→run_002 传导成功——恰好形成"无传导 vs 有传导"的批内对照。

### 15.5 结论小结

- **功能层**：全链路稳定，agent 产出的函数摘要可复用、信息密度高（可达性论证 + PoC + 复现）。
- **效果层**：新提示词（禁 fuzz + 索引优先）下，B 组在 Kafka 轮取得**一致方向性优势**（覆盖率 +89%、命中 +1、类型更广、源码分析 +45%）；libyaml 轮（旧提示词）无显著优势 → 记忆的价值依赖"agent 真的在读源码"这一前提。
- **代价**：B 组更慢（时长 +94%）——更深入分析的合理开销。

---

## 16. 已知局限

1. **索引查询靠 agent 自觉**：`grep` 是提示词强制，无硬性执行保障（无外部监督/提醒机制）——这就是后续"提醒"实验的动机。
2. **单 run 内写侧纪律不稳**：v3 后明显改善，但执行型任务（构造 PoC/跑 harness）密集的 run 仍可能少写。
3. **解析器是启发式**：只认"标题+字段"结构；自由文本、多函数合并、非标准字段会被跳过（可接受——它们不是"可去重/可接续"的单元）。
4. **渲染截断**：ledger 大时 prior 只展示 15 行（SUSPICIOUS 优先），信息有损。
   缓解：完整分析可经 `/work/PRIOR_MEMORY.md`（60KB 上限）由 agent 自行 grep。
5. **函数粒度歧义**：agent 有时一个条目覆盖多函数（`DefaultRecordBatch.java:iterator / count`），去重按"冒号后首个 token"取，可能把相关函数拆开。
6. **观测器对 bash ls/find 探索统计不全**（Java 靶标 agent 常这样探索结构）——覆盖率用独立脚本补足。
7. **样本量**：各轮 3 runs/组，单 run 方差大；结论方向性可信，数值需更大样本确认。

---

## 17. 后续方向

1. **外部提醒/监督（已与用户讨论，未定型）**：把"写侧纪律/索引纪律"从提示词静态规则升级为可开关的监督机制。候选形态：
   - 跨 run Gap 反馈（宿主对比 transcript 读过的函数 vs MEMORY.md，下轮 prior 提示"上轮读了 X 未记录"）——零侵入，先做。
   - 分段子任务验收（把 run 拆阶段，段间 resume 注入基于实际行为的指示）——真·运行中监督，需改 agent.py。
2. **索引查询下沉 harness**：宿主周期性检查 MEMORY.md 增量，long-idle 时提醒（不依赖 agent 自觉）。
3. **函数级覆盖率**：region 粒度细化到函数，与记忆 ledger 对齐。
4. **更大样本**：8-10 runs/组压方差；对照组加空提示词占位排除"提示词更长"干扰。
5. **记忆合入管线**：默认关、`--memory` 开启的可开关功能（待更大样本确认后）。
