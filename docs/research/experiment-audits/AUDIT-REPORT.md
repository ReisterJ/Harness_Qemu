# SymCC 组正反例的 agent 行为审计（第四版·校对版）

> 日期：2026-10-12（第四版）　语料：`results/experiments/**`（254 个 dynamic run）
> 变更（相对第三版）：**对第三版做了一次逐条校对**，修正 9 处自身错误/过强表述（清单见 §1.5），
> 并完成全部 7 对有效实验 + 4 对单侧命中的逐事件深挖
> （附件 [`BEHAVIOR-DEEP-DIVE.md`](./BEHAVIOR-DEEP-DIVE.md)）。
> 变更（相对第二版）：修正 §4.1 的"慢"（一对是测量伪影、一对是自愿验证）；按全语料重算 §4.2
> 契约损失（重算为 SymCC 19 : 对照 14，形态不同）；补 §4.3/§4.5 的机制级证据（71 轮锚定、
> codex"有梯度缺升级"）。
> 变更（相对第一版）：口径改为**配对**（实验组 vs 它自己的对照组）；**剔除静态报告有问题的实验组**
> （视为失败实验，不计入结论）；新增"更快出现的条件"一节。
> 工具：[`notebook.py`](../../../results/experiments/agent-behavior-audit/notebook.py)（逐事件"命令+关键输出"日志，
> 本轮深挖的主工具）· [`timeline.py`](../../../results/experiments/agent-behavior-audit/timeline.py) ·
> [`metrics.py`](../../../results/experiments/agent-behavior-audit/metrics.py) ·
> [`deep_metrics.py`](../../../results/experiments/agent-behavior-audit/deep_metrics.py) ·
> [`pairs2.py`](../../../results/experiments/agent-behavior-audit/pairs2.py)
> 产出表：`tables/metrics_deep.csv`、`tables/pairs2.csv`（数字均可由这几个脚本复算）

---

## 0. 结论（一页版）

**口径**：只比较"SymCC 臂 vs 它自己的对照组"（同目标 / 同报告 / 同世代）；两边都命中才计
`ratio = T_off / T_sym`（>1 = SymCC 更快）；报告有问题的组整组剔除（§1.3）。括号内是证据等级。

1. **求解器从未"给出答案"（强）**：23,173 个生成回放（不含 codex 世代 17,925）里 18 个带 ASan 报告，
   全部来自"种子本身已崩"的 4 个请求；**0 例**干净种子 → ASan。另有 46 例 core dump（无 ASan 头）
   因"该 clean 二进制对空输入也 SEGV"列为未定性（§2）。
   → **SymCC 的价值是执行/观测通道，不是求解能力。**
2. **报告正确时：5 快 / 2 慢，且"慢"经不起逐事件核对（中）**：两对"慢"= 11 s 测量伪影（g3：两臂
   首次成功执行同秒 45.1 vs 45.2 s）+ 21 s 自愿验证（g1）。有时长区分度的 4 对全部 SymCC 更快：
   406.7 vs 1528.0 / 419.4 vs 729.5 / 850.1 vs 1424.2 / 1491.1 vs 1686.2 s，中位快 1.6×（§3/§4.1）。
3. **快的原因不是"试得多"，而是"每次执行读得到什么"（强，机制级）**：mruby-async 对里对照组写了
   **68** 个程序、43 次直跑、一次 **96,437 例** fuzz（0 崩）、26 个循环——是 SymCC 臂（11 个程序、
   15 次请求）的 6 倍以上，却慢 3.76×。SymCC 臂用 `.size/.class` 读数当梯度、一次只改一个条件
   （`cand_envbarrier2/3/4.rb` 的注释即因果链）；对照组崩溃前通常只有 1 bit（崩/不崩），只能批量/随机/
   参数搜索。工具相同的世代（env pair-3 / hybrid）差异退化为**"先测量还是先搜索"**（§3；深挖 §3/§10）。
4. **优势有边界（中）**：报告已点名真 sink 时，两臂 43–150 s 内都命中，差异只剩管道延迟与验证深度；
   硬目标上两臂方法趋同（62290 v5 = 1.13×）；目标对 fuzz 友好时对照组直接用 libFuzzer 赢（剔除组实测：
   战役 52.3 s 起、53.7 s 见 ASan）（§3/§5/§6）。
5. **两个"用得上"的前提（强）**：① **报告必须指真根因**——错锚点 + 恒命中反馈会把协议臂锚死
   （71 轮逐字相同的假设，`focus … hits=1`，`new_lines` 3881→336；同一波命中率 7/16 vs 15/16）；
   ② **契约必须收得下结果**——`invalid_submission` SymCC 19 : 对照 14（形态不同：`poc_path` 逐字规则
   是协议臂特有 6:0；自造 `poc_kind` 以对照组为主 12:4），另有 offload 回读 5–11 s、异步往返 ≈162 s
   的通道成本（§4.2/§4.3/§6）。
6. **命中平衡：有效实验里两组没有系统性差别（中）**：全部 44 对中"两边都命中 21 / 只有对照 12 /
   只有 SymCC 4 / 都没中 7"；只有对照命中的 12 对里 9 对来自被剔除的错报告组（§4.4）。

**要更快，能动的四处**（不改运行时，只改接口与提示词）：

1. 把"先用最小程序打印被怀疑对象的 `.class / .size / 内容`"写成动态验证的第一步；读数之前不许开
   fuzz 战役（深挖 §9/§11）。
2. 给两臂**同等的廉价观测入口**（跑一个程序 → 回传 stdout），消掉"自写 ptrace / 反复重编译"的几百秒
   （async 世代对照组因此花了 673–1506 s）（深挖 §2.3）。
3. 报告里给**缺失条件清单**（如 ①环境需变黑 ②悬垂对象所在页需被释放 ③不得有其他引用），让 agent
   逐条补齐而不是扫参数——成功的那条路径正是这样走的（深挖 §2.2）。
4. **修订交付契约**（枚举合法 `poc_kind`、接受协议重现命令）：这是"已找到却被丢弃"的最大单一来源
   （§4.2）。

**口径提醒**：<200 s 命中级别的 `ratio` 不可用作快慢判定（它测的是输出管道）；agent 自建工具也会打印
ASan 字样，判定命中必须核对崩溃类型（§1.4/§1.5）。

---

## 1. 方法与口径

### 1.1 分层（跨代不合并）

| 世代 | run 数 | 含义 |
|---|---:|---|
| `plain` | 157 | 无结构化反馈；symcc 臂=自建 source slice + `symcc-submit` |
| `async-sidecar` | 48 | `read-feedback` 世代 |
| `coverage` | 30 | 每请求响应带 `coverage.focus` |
| `provider-trace` | 19 | 早期 instrumentation provider |

### 1.2 配对口径

- 配对键 = wave + run 路径（去掉 off/symcc 臂标记）；两组必须都有 `dynamic_transcript.jsonl`；
- **命中** = 目标类 sanitizer 事件（按 target 映射；含 `==N==ERROR: AddressSanitizer: <type>` 或
  SUMMARY，排除模板/回显）；命中时刻从 transcript 的事件时间戳推算；
- `ratio = T_off / T_symcc`；ratio>1 记为"SymCC 更快"。

### 1.3 有效实验的判定与剔除清单（本版核心变更）

判定规则（依据见 §4.3 的证据）：**静态报告是否指向真正的根因/sink**。
报告缺陷会让"目标点反馈"变成噪声甚至误导（focus 恒命中），这类实验组视为失败实验，
**整组剔除，不作为 SymCC 快/慢的证据**。

剔除清单：

| 组 | 对 | 剔除原因（可核实） |
|---|---:|---|
| `symcc-retest-20261009`（38283） | 7 | 报告锚点只有 `fr_tacacs_decode`（过路函数，`decode.c:220`）；真凶是 `fr_is_base16_nstd`（base16.c 索引 255 字节表）。该波文档实测 focus **531/539 = 98.5% 恒命中**（零梯度） |
| `cybergym-symcc-followup-20260928` arvo-38283 | 1 | 同一份错报告（sha `cea11015`，仅 `fr_tacacs_decode`） |
| `cybergym-symcc-followup-20260928` arvo-55020 | 1 | 报告把数据集点名的真凶 `coff_aarch64_addr64_reloc` 换成了链接期不可达的 `coff_pe_aarch64_relocate_section` |
| `ghostscript-type2-51089` | 2 | 报告无锚点（"source location to be verified dynamically"），可达性未建立 |
| `canary-klee` | 4 | provider 是 KLEE，不是 SymCC，不属本审计对象 |
| （旁注）`arvo-symcc-paired-20260923` 62290 | 1 | 报告无具体锚点（"svcdec inter-layer prediction functions"）；两臂均未命中，不影响配对结论 |

保留（报告正确）的实验组：`mruby-async-paired-20260923`、`mruby-env-write-barrier`（7 对）、
`symcc-anchor-20261009`（3 对，报告含真 sink）、`symcc-target-site-feedback-20260924` 的 57672 对（2）、
62290 的 v5 对（1，报告把函数/行号写对）、codex 世代（附 §4.5）。

**配对不唯一、单独列出不计入**：`cybergym-symcc-followup-20260928` 的 arvo-62290 目录里每个臂各有
两个 run（153618Z/170809Z 与 161934Z/162546Z），按"每臂取一个 run"会得到两种配对结果
（一种 SymCC 2118.2 s 独有命中、一种两臂都空手），故不计入 §4.4 的命中计数。

### 1.4 扫描器修正（影响旧数字，必须声明）

1. `mechanism_scan.py` 曾把 `grade_transcript.jsonl` 当行为 run（假"4.6 s 命中"）→ 已限定只扫 dynamic；
2. mruby 判据为裸 `heap-use-after-free`，agent 打印的 skill 文本也命中（假"339 s 命中"）→ 已要求真 ASan 头；
3. 崩溃模板内嵌的 `==12345==ERROR: …` 被当成真崩 → 已排除模板上下文；
4. 非 mruby/38283/55020 目标（如 62290）此前不产出目标时刻 → 已改为"任意真 ASan"（本版 62290 对才可比）。

**深挖阶段又发现两类陷阱（对 §4.1 的"慢"结论有直接影响）**：

5. **agent 自建工具会打印 ASan 字样**：62290 OFF 用 `asanraise.c`+`LD_PRELOAD`+`handle_segv=0`
   探测 ASan 的 SEGV 行为，300.6 s 打出 `==N==ERROR: AddressSanitizer: SEGV`——不是目标崩溃。
   核对崩溃类型后 62290 OFF 的真实命中仍是 1686.2 s（`negative-size-param`）。
6. **协议臂的响应会被 offload 到文件**，agent 需再 `sed/cat` 回读，导致"ASan 进入 transcript"比
   "进程崩溃"晚 5–11 s。anchor g3 实测：请求发出 45.1 s、ASan 可见 56.4 s、报告记 `sym_t=56.4`。
   → **<200 s 命中级别的 `ratio` 不可用作快慢判定**（详见 BEHAVIOR-DEEP-DIVE §1/§6.2）。

### 1.5 本轮校对：第三版自身被修正的 9 处（自查清单）

| # | 第三版原文 | 实测 | 影响 |
|---|---|---|---|
| 1 | §4.5「8 例 `reached_no_crash`，其中**至少 3 例**已看到语义异常」 | **2 例**（1436 s、2694 s）；其余 6 例原文明确写"未看到异常/未到达路径" | 缩小 codex"有梯度"的证据范围（但仍成立） |
| 2 | §2「**全部语料** 17,925 个生成输入」 | 17,925 = **不含 codex 世代**；含则 **23,173** | 口径必须标注；两种口径下都只有 18 个 ASan 回放 |
| 3 | §2「**0 例**干净种子 → 生成输入崩」 | 只对 **ASan** 成立；另有 **46 例** core dump（无 ASan 头）未定性，须披露 | 结论措辞改为"harness 采信的 ASan 崩溃 0 例"，并说明 46 例为何不可用（§2） |
| 4 | §6「直跑二进制 **4–44 次**」 | 有效实验对照组 **4–46 次**（max = 62290 v5 的 46） | 数字修正 |
| 5 | §6「首次 focus 观测 **20–110 s**」 | `first_feedback_read_t` 只有 **8/96** 个 run 有记录，范围 **66.8–1687.0 s**；有效实验里最早 469.7 s（**晚于自己 406.7 s 的命中**） | 该行原表述无据，已按实测重写 |
| 6 | §0/§3「38283 上对照组 libFuzzer **39.6 s** 起跑、53.7 s 命中」 | 该 run 实测：战役 **52.3 s** 起、**53.7 s** 见 ASan、**58.9 s** 复制出 artifact | 数字改为实测值（该组仍在剔除清单内） |
| 7 | §4.2「`invalid_submission` SymCC **28** : 对照 **7**」「协议臂交割面更宽」 | 按**臂别**逐条复核：**SymCC 19 : 对照 14**；其中自造 `poc_kind` 是**对照臂更多**（12 : 4），只有 `poc_path` 逐字规则是协议臂特有（6 : 0）。旧数字来自路径启发式把 `group-N-off`、`*/off/` 误判成协议臂 | 结论方向修正：契约损失两臂相当、形态不同 |
| 8 | §6「求解器实际耗时：大多 <10% 总时长（最大 113 s / 3602 s）」 | `pairs2.csv` 实测：async 297.8 s（62.6%）、env3 468.4/467、hybrid 1011.0/1009（≈100%，字段含义随世代变）、62290 v5 120.1 s（6.7%）、anchor g2 1.2 s（0.6%） | 按实测重写该行 |
| 9 | §4.4「只有对照命中 9 / 只有 SymCC 3 / 两边都命中 15；合计 10:10」 | 按"任一臂产出真 ASan"重算 44 对：**两边都命中 21 / 只有对照 12 / 只有 SymCC 4 / 都没中 7**；有效实验独有命中各 3 对 | 替换旧口径，结论改为"有效实验里两组无系统性差别" |

**另有深挖文档（BEHAVIOR-DEEP-DIVE）里被修正的 3 处**（见其 §14）：
env pair-3 被误写成"用协议请求 1–2 s 拿到读数"（该对是 `plain` 世代、**无协议**，两臂都有工具链，
差异是"先插桩还是先 fuzz"）；async 对的协议请求数 17 → **15**（以 harness 字段为准）；
`invalid_submission` 的 28 : 7 → **19 : 14**（同上第 7 条）。

---

## 2. 事实基线（M1 否证）：harness 采信的"求解器独立产出崩溃"= 0 例

> 口径说明（本轮校对后修正）：统计对象是 `symbolic_execution/summary.json` 里的
> `generated_replays`（SymCC 生成、再用 clean 目标回放的输入）。**17,925 是"不含 codex 世代"的数**；
> 含 codex 世代（`codex-mruby-*`，5,248 个回放）共 **23,173**。两套口径下的 ASan 结果相同。

| 指标 | 值 |
|---|---:|
| SymCC 生成并通过 clean 目标回放的输入（不含 codex 世代） | 17,925 |
| 同上（含 codex 世代） | 23,173 |
| 回放里带 **ASan 报告**的 | **18**（0.100% / 0.078%） |
| 有"生成崩"的请求记录 | 4 |
| 这 4 个里"种子输入本身干净"的 | **0** |
| 回放记录写着 **core dump 但无 ASan 头** | **46**（见下，不计入结论） |

**推理**：4 个出现"生成输入崩（ASan）"的请求，其 `clean.sanitizer_event` 全为 true——agent 已先把
崩溃输入交给 harness，SymCC 只是对它做变体。不存在"干净种子→生成输入产生 **ASan 报告**"。
快例复核（anchor 波三例）：首崩都发生在 agent 自己 `round-001` 的响应里，96–160 个生成回放全 clean。

**46 例 core dump 为什么不计入（本轮新增披露）**：它们全部落在 `arvo-62290`（libavc）的 6 个 run 里
（其中 45 例所在 run 的 SymCC 会话以 SIGKILL `exit 137` 结束），回放记录只有
`timeout: the monitored command dumped core / Segmentation fault`、**没有 ASan 头**。
关键是：**该世代该目标的 clean 二进制本身不可信**——agent 自己发现
`printf '' > empty.bin && /out/svc_dec_fuzzer_clean empty.bin` → `exit=139`
（空输入即 SEGV，v5 OFF `dynamic-20260923T232345Z` 0.9 s）。所以 core dump 既可能是
"求解器造出的畸形输入"，也可能是"被 SIGKILL 的会话写出的半截文件"或"该二进制的空输入级缺陷"，
**无法区分**。要定性必须把那些字节在目标上重放（本审计环境不具备），因此列为"未定性"。

---

## 3. 有效实验：SymCC 比对照组快的 5 对，为什么快

| 对 | 对照 | SymCC | ratio | 对照组时间去向（逐事件核实） | SymCC 的命中来源 |
|---|---:|---:|---:|---|---|
| mruby async | 1528.0 s | 406.7 s | **3.76×** | 271 s fuzz 战役（96,437 例 0 崩）、673 s 起写 ptrace/生成器工具、1143–1506 s 三个 ptrace 工具；757 s 先撞到**错类** SEGV 并花 ~70 s 反汇编；257 tool calls（直跑 43 次） | 15 次协议请求；第 4 个假设（332–356 s 写 cand_envbarrier2/3/4，含"闭包→GC.start 提升→写入"时序）命中 |
| env pair-3 | 729.5 s | 419.4 s | **1.74×** | 7 条 fuzz 命令（含 1 次 154,444 例、0 崩的战役）+ 27 次直跑 + 76 条读/查 | 177 s 自建 ASan 解释器 → 16 处值探针（151–408 s）→ 419.4 s 崩；命中被契约拒收（§4.2） |
| env hybrid | 1424.2 s | 850.1 s | **1.68×** | 1 次 fuzz + 14 次直跑 + 146 条读/查（8–26 min 每 2 分钟 4–8 次直跑） | 先插桩确认路径，819.4 s 单维扫分配量后 850.1 s 崩；validated |
| 62290 v5 | 1686.2 s | 1491.1 s | **1.13×** | 自建 `svcdec_asan`+`patch_sps.py` 扫 crop 偏移 + 1 次 fuzz（168,560 例 0 崩）；两臂都 `agent_blocked`(1804 s) | 自建编码器 `svcenc` + ASan 探针扫 `SVC_L/SVC_R`；协议交货被异步反馈拖到 1780.8 s |
| 38283 anchor g2 | 149.5 s | 93.7 s | **1.60×** | 选 fuzz（44.8 s 起 `-runs=2000000`，149.5 s 拿到 artifact） | 手写构造，90.9 s 请求即命中 |

**共同条件（5/5）**：对照组的"直接执行/乱 fuzz/参数枚举"路线耗时长（数百到上千秒），而漏洞需要按
源码构造特定输入；SymCC 臂的执行循环（协议世代的请求、或 plain 世代的自建 ASan 解释器）都能**读回
程序打印的语义状态**，且报告方向正确。

**为什么快（机制级，见 [`BEHAVIOR-DEEP-DIVE.md`](./BEHAVIOR-DEEP-DIVE.md)）**：不是"尝试密度"。
逐事件核对 mruby-async 对得到：SymCC 臂把执行通道当**测量仪器**——一次请求读回被怀疑对象的
语义状态（`diag3` 原文 `class=Hash\nsize=0`），然后在 216.7/260.9/349.5/355.3 s 四次"读数→
只改一个条件"（`cand_envbarrier2/3/4.rb` 的注释即因果链）；对照组把执行通道当**搜索器**——
runner 只 `grep AddressSanitizer|SUMMARY|ERROR`（188.9 s 原文），崩溃之前每次执行只有 1 bit 信息。
同一对里对照组写了 **68** 个 `.rb`、43 次直跑 + 一次 **96,437 例** fuzz 战役（0 崩）、26 个循环，
SymCC 臂只写了 **11** 个 `.rb`、17 次协议请求——**对照组"试得更多"却慢 3.76 倍**。
两臂最终 PoC 形状相同（方法内闭包 → unshare → GC 压力 → 解引用）：SymCC 臂形状正确后 50 s 命中，
对照组 757 s 写出同形状后**再用 771 s 盲扫参数**才崩。

典型证据（mruby async）：SymCC 唯一一次读 sidecar 反馈发生在**崩溃之后 63 s**——它的快与"被提示"无关。

**逐对机制（见 [`BEHAVIOR-DEEP-DIVE.md`](./BEHAVIOR-DEEP-DIVE.md) §2–§5）**：

- **mruby-async（3.76×）**：测量仪器 vs 搜索器（下述）。
- **env pair-3（1.74×）**：SymCC 臂的语义探针全在命中前（151–368 s：`puts r.length` → `puts r.class`
  → `sed 's/puts r.length/puts r[0]/'` 升级为解引用 → 419.4 s 崩）；对照组的 `p v.size` 出现在
  **729.5 s 命中之后**，是确认而非搜索；对照组路径是 280 s/154,444 例 fuzz（0 崩）后**三次重编译**
  自建 `DBG_UNSAFE_UNSHARE` 插桩（604–710 s），观测信号来得太晚。
- **env hybrid（1.68×）**：SymCC 臂 111–139 s 先插桩确认路径，819 s 只扫"分配量"一个维度后命中；
  对照组 8–26 min 每 2 分钟 4–8 次直跑（20+ 次执行）+ 7 次参数扫描，崩后自述"ASAN fires for
  N in [77–85]…"——靠 N 区间扫出来。
- **62290 v5（1.13×）**：**两臂方法趋同**——都在给解码器打插桩 + 只扫 SPS crop 偏移一个参数；
  对照组多跑了一次 181 s/168,560 例 fuzz（0 崩）；SymCC 臂命中后走协议交货被**异步反馈延迟**拖住
  （1618.4 s 提交 → 1687.0 s 读回 `pending` → 1780.8 s 才拿到响应 → 1804 s 被截断，单次往返 ≈162 s）。
- **anchor g2（1.60×）**：对照组选择 fuzz（44.8 s 起跑、149.5 s 拿到 artifact），SymCC 臂手写构造
  在 90.9 s 命中——同一"构造 vs 搜索"机制。

**附注**：62290 v5 对两臂都 `agent_blocked`（时长相同 1804 s），命中时刻差 195 s，
是"迟到命中"而非干净胜利；引用时请按 1.13× 的弱证据处理。

---

## 4. 有效实验：SymCC 比对照组慢的 2 对，以及"慢"的边界

### 4.1 两对"慢"是伪影/验证深度，不是通道劣势（**本版修正**）

| 对 | 对照 | SymCC | ratio | 绝对差 | 逐事件核对后的真实原因 |
|---|---:|---:|---:|---:|---|
| 38283 anchor g3 | 45.2 s | 56.4 s | 0.80× | 11 s | **伪影**：两臂首次成功执行在**同一秒**（对照 45.2 s 直跑 / SymCC 45.1 s 协议请求）；11 s 全是"协议响应被 offload 到文件后再 `sed` 回读"的管道延迟（45.1 → 56.4 s） |
| 38283 anchor g1 | 43.2 s | 74.1 s | 0.58× | 31 s | **验证深度**：对照在 43.2 s 直接写 PoC + 直跑（一枪命中，只 grep 过 `fr_is_base16_nstd`）；SymCC 臂在 39.1–62.1 s 读 `value.c`/`pair.c`/`struct.c`/`dictionary.tacacs` 验证 `Data=0x` → octets → base16 路径后才射击（64.6 s 请求），多花 21.4 s |

**修正后的口径**（"首次产出崩溃的执行命令时刻"）：g1 = 64.6/43.2（0.67×）、g3 = 45.1/45.2（**1.00×**）、
g2 = 90.9/149.5（1.64×）。即：**两对"慢"里，一对是纯测量伪影，另一对是 agent 自愿多做的路径验证**。
结论：这个场景下协议通道**没有系统性劣势**，但**当"只需 1–2 次射击"时它的管道成本会吃掉优势**
（同波 g2 对 SymCC 快 1.6×，因为对照组选择了 fuzz 战役：44.8 s 起跑、149.5 s 才拿到 artifact）。
详见 [`BEHAVIOR-DEEP-DIVE.md`](./BEHAVIOR-DEEP-DIVE.md) §6。

### 4.2 契约损失（两臂都有，形态不同；**本版按全语料重算**）

对 221 个 `dynamic_validation.json` 统计 `invalid_submission`（**本轮按臂别重新分类**，
旧版 28 : 7 的数字是路径启发式误判的结果）：

| 形态 | SymCC 臂 | 对照 | 说明 |
|---|---:|---:|---|
| `unsupported poc_kind: <自由字符串>` | 4 | **12** | 模型自造枚举值（`raw`/`ruby_script`/`postscript`/`executable`/`libfuzzer-testcase`/`coff-aarch64-object`…）；**这类以对照组为主** |
| `poc_path must appear verbatim in reproduction_command` | 6 | 0 | **协议臂特有**：它的"重现命令"天然写 `run-input <request.json>`，与规则冲突 |
| 缺 `candidate_ready` 轮次证据 | 2 | 1 | — |
| 原因未记录（早期世代/冒烟） | 7 | 1 | — |
| **合计** | **19** | **14** | 两臂总量相当（≈1.4×），**形态不同** |
| 无法从路径判定臂别（未计入） | 2 | — | `final-paired` / `prebuilt-baseline` |

有效实验里也各有一例：SymCC env pair-3（419.4 s 命中后被 `poc_path` 规则丢弃）、
对照 env pair-5 之外的 `unsupported poc_kind` 例。另有 4 对单侧命中的失败原因属**契约/停摆**而非
"找不到崩溃"（`agent did not persist any validation round` ×2、`phase exceeded 1800s` 且 1803 s 只有
79 calls ×1、`unsupported poc_kind: libfuzzer single-file byte input …` ×1）——
见 [`BEHAVIOR-DEEP-DIVE.md`](./BEHAVIOR-DEEP-DIVE.md) §7.2。


有效实验中"已找到但被丢弃"的只出现在协议臂：SymCC env pair-3（419.4 s 命中后被 `poc_path` 规则丢弃）；
单侧命中的 pair-5 里 SymCC 也被 `unsupported poc_kind` 丢弃（§7.2）。对照侧在有效/单侧实验里没有契约丢弃，
6 例 `unsupported poc_kind` 都落在其他实验组。

### 4.3 被剔除组的"慢/失败"机制（用于支持剔除判定，不计入结论）

以被剔除的 38283 重测波为例（同一份错报告，两臂同条件）：

- 命中率 OFF 15/16 vs SymCC 7/16；
- SymCC 命中组提及 `base16`（真 sink）170–288 次；未命中的 9 个 run 只提及 2–12 次；
- 极端案例 `dynamic-20261008T175927Z`：**71 个 round 记录、假设逐字相同**，每条 reason 都引用
  `focus decode.c@221 hits=1`（恒命中），最终以"decode.c 覆盖已穷尽"收工。
  **逐事件深挖（本版新增）**：71 条 `iterations/round-*.json` 的 `hypothesis` 字段完全一致
  （`entry_point: … -> fr_tacacs_decode`），`new_lines` 从 3881 递减到 336，**70 条记录里
  `hits` 恒为 1**——反馈只回答"我命中了被指定的那个点吗"（恒 yes），不回答"被指定的点是不是真 bug"。
  详见 [`BEHAVIOR-DEEP-DIVE.md`](./BEHAVIOR-DEEP-DIVE.md) §8；
- 已命中的 5 个 SymCC run 又被契约（path-verbatim）丢弃；另有 3 个被看门狗截断。

**结论**：这是"错锚点 + 饱和反馈 = 行为锚定"的干净证据——它说明为什么这类实验组
不能作为"SymCC 是否更快"的证据，而不是"SymCC 慢"的证据。

### 4.4 命中平衡（本轮按"任一臂产出真 ASan"口径重算）

| 口径 | 只有对照命中 | 只有 SymCC 命中 | 两边都命中 | 都没命中 |
|---|---:|---:|---:|---:|
| **全部 44 对** | **12** | **4** | **21** | 7 |
| 其中：只有对照命中的 12 对里 | — | — | — | 8 对来自被剔除的 38283 重测波（错报告）+ 1 对 ghostscript（报告无锚点）+ 3 对有效区（env pair-5、57672 v2/v4） |
| **有效实验（剔除后）** | 3 | 3 | 7 | — |

有效实验的"唯一命中"明细：SymCC 独有 = env pair-1 / pair-2 / pair-2-maxturn（对照组分别
`agent_blocked`（1803 s 只有 79 calls，相位停摆）/`agent_failed`（`agent did not persist any validation
round`）/`agent_failed`（同））；对照独有 = env pair-5、57672 v2、57672 v4（SymCC 侧分别
`unsupported poc_kind` 与 `agent_blocked`/`reached_no_crash`）。
**就"能否找到崩溃"而言，两组在有效实验里没有系统性差别**（独有命中各 3 对）；
第一版"SymCC 净亏"的印象主要来自被剔除的错报告组。
逐条原因见 [`BEHAVIOR-DEEP-DIVE.md`](./BEHAVIOR-DEEP-DIVE.md) §7。

### 4.5 附：codex 世代（同报告正确，无配对命中，仅供观察）

`mruby` 目标 + codex/luna（报告同为 `mrb_env_unshare`）：逐条核对 11 个 dynamic run 的
`dynamic_validation.json` 得到——

- **8 例 `reached_no_crash`**（81–2694 s），其中**2 例**的原文理由明确写着**已经看到语义异常**
  （另有 6 例明确写"没看到异常/没到达路径"，例如 981 s："none of the probes exposed a stale read or
  crash"；1198 s："without a crash or observed lost reference"）：
  "The candidate's missing-reference effect **was observed**…"（1436 s）、
  "The closure path produced an **incorrect captured value** under the GC condition, but no matching
  sanitizer crash"（2694 s）；
- **1 例 `validated`（4723 s，101 次协议请求）**：其理由原文是 "The captured value **changed type** after
  GC and allocation churn … **The ordinary target exited 0 with no ASan event**, so no matching crash or
  crash PoC was validated"——即**逻辑/观测轨**的 validated，不是 ASan 崩溃；
- **2 例 `agent_blocked`**（各 127 s，`helper_blocked: unbounded helper process exceeded 120s`，bug 已修）。

**机制结论（本版新增）**：这一世代**已经具备便宜的值级读数**（"captured value changed type" 与 async
对的 `class=Hash / size=0` 是同一现象），但没有**升级模型**（"要让悬垂 RVALUE 所在页被释放"这一步），
所以停在 `reached_no_crash`/观测轨 validated。即：**读数（A 机制）必要但不充分，
"缺失条件清单 + 逐条补齐"才是从读数到崩溃的那一步。**
详见 [`BEHAVIOR-DEEP-DIVE.md`](./BEHAVIOR-DEEP-DIVE.md) §9。

---

## 5. 报告质量是最大的单因子（为什么剔除是必须的）

同一目标（38283）、同一模型、同一 harness，只有报告不同：

| 波 | 报告锚点 | 结果 |
|---|---|---|
| `symcc-anchor-20261009`（保留） | `fr_base16_decode_nstd`（真 sink）+ 入口 | 6/6 validated，首崩 43–150 s |
| `symcc-retest-20261009`（剔除） | 只写 `fr_tacacs_decode`（过路函数） | OFF 15/16、SymCC 7/16；中位首崩 479 / 753 s |

即：**"报告 → 真 sink"与否，把同一目标的结果从"分钟级"推到"十几分钟/失败"**。
这比换求解器、换模型的影响都大；也是本版剔除规则的依据。

---

## 6. SymCC 组 vs 对照组：结构性行为差异（有效实验，强）

> 本轮校对后按**世代**拆分：`plain`/`provider-trace` 世代两臂都有源码+工具链；
> `async-sidecar` 世代的对照组**没有 ruby/rake**（`which ruby rake mruby mrbc bison gperf` → rc=1），
> 只能自写工具。结构差异必须按世代读，不能跨代合并。

| 维度 | SymCC 臂 | OFF 臂 | 证据 |
|---|---|---|---|
| 执行通道 | `plain`/`provider-trace` 世代：自建 source slice（编译源码）；`coverage`/`async-sidecar` 世代：协议 `run-input`（1–25 次/run） | 直跑二进制（有效实验 4–46 次）；proto=0 | `metrics_deep.csv` |
| **每次执行的信息量** | 更早读到对象语义状态（协议响应带 `stdout`，或自建 ASan 解释器/插桩） | 崩溃前通常只有"没崩"；语义读数出现在命中之后（env3）或晚 ~435 s（env3 的 `DBG_UNSAFE_UNSHARE`） | 深挖 §2.1 C 行、§3 |
| **迭代粒度** | 一个候选只改一个条件（注释即因果链） | 批量生成 + 参数网格（async 对 68 个程序、26 个循环） | 深挖 §2.2/§2.5 |
| **等价观测的成本** | async 世代：协议请求即可读回打印（15 次） | async 世代无工具链 → 自写 ptrace（673–1506 s）；plain 世代两者都要自建，差别只是**先后** | 深挖 §2.3、§3 |
| 反馈通道 | 每请求响应带 `coverage.focus`（`coverage`/`async-sidecar` 世代） | 无 focus 响应（只在 README 里见过） | transcript 文本计数 |
| 首次"读反馈"时刻 | 只有 8/96 个 run 有该记录，范围 66.8–1687.0 s；有效实验里最早一次 469.7 s（**晚于自己 406.7 s 的命中**） | — | `metrics_deep.first_feedback_read_t` |
| 提示约束 | 含"不得直连二进制"禁令（协议世代） | 无 | transcript 文本计数 |
| 时间结构 | 读源码 + 构造/协议轮（+ 挖反馈） | 造工具（ptrace/生成器/语料）+ 直跑 + fuzz 战役 | §3 时间线 |
| 契约失败形态 | `poc_path` 未逐字出现在 `reproduction_command`（6 例）/ 自造 `poc_kind`（4 例） | 自造 `poc_kind`（12 例） | §4.2 |
| 求解器会话耗时（`symcc_session_s`，含义随世代不同） | async 297.8 s（该臂 476 s 的 62.6%）；env3 468.4/467、hybrid 1011.0/1009（≈100%，字段在这些世代覆盖整段动态阶段）；62290 v5 120.1 s（6.7%）；anchor g2 1.2 s（0.6%） | —（无该字段） | `pairs2.csv` |

**结论**：两臂不是"同策略 ± 求解器"，而是两套执行/反馈/契约系统；配对差异必须按这套结构解释，
且**"观测更便宜"只在 async 世代（对照组无工具链）成立**——plain/provider-trace 世代是"先测量
vs 先搜索"的次序差异。

---

## 7. 机制判定矩阵（本版）

| 机制 | 判定 | 等级 | 依据 |
|---|---|---|---|
| M1 求解器给答案 | **否证**：harness 采信的 ASan 崩溃 0 例（46 例 core dump 未定性，§2 已披露） | 强 | §2 |
| M2 反馈改变策略 | 报告正确时是正资产（anchor 波）；报告错误时是负资产（被剔除组，§4.3） | 中 | §4.3、§5 |
| M3 机械替代（把回合换成廉价执行） | **仅在 async 世代成立**：该世代对照组**无 ruby/rake**，只能自写 ptrace（673–1506 s）；SymCC 臂用 15 次协议请求 | 中 | §3 · 深挖 §2.3 |
| M4 执行契约/提示不对称 | **成立但非单向**：`invalid_submission` SymCC 19 : 对照 14；协议臂特有 `path-verbatim`（6:0），对照臂自有"自造 `poc_kind`"（12:4）；另 offload 回读 5–11 s、异步往返 ≈162 s | 强 | §6、§4.2 |
| M5 方差 vs 信号 | 有效实验内"快"的方向稳定（4/4 长对）；"慢"两对都不是通道劣势（伪影/自愿验证，§4.1） | 中 | §3/§4.1 |
| M6 先测量 vs 先搜索 | **成立**：两臂工具相同（env3/hybrid）时，谁先建立语义读数谁先命中 | 中 | 深挖 §3/§4 |
| AQ7 契约损失 | 成立，且协议臂更重 | 中 | §4.2 |
| **"更快"的条件** | **漏洞抗乱撞 + 报告正确 + agent 早建立语义读数并逐条件补齐 → SymCC 更快（5/5）** | 中 | §3 · 深挖 §10/§11 |

---

## 8. 局限

- 有效实验的可比对数 = 7（其中 3 对是 <2 分钟的短对），mruby 占多数；结论对小样本敏感；
- 剔除规则基于"报告是否指真根因"（依据见 §5 与各波文档）；判定本身是人工标注，非自动；
- `calls/craft/mine/direct` 为命令文本启发式计数；`protocol_requests/proto_s` 取自 harness 计时字段；
- **`first_asan` 时间戳在短程实验里测的是管道而非崩溃时刻**：协议响应会被 offload 到文件后再被读回，
  实测延迟 5–11 s；agent 自建工具（`LD_PRELOAD` 探针等）也可能打印 ASan 字样。
  → 本版 §4.1 已按"首次产出崩溃的执行命令时刻"重算；引用任何 <200 s 的 `ratio` 前必须按 §1.4(5)(6) 核对；
- 深挖覆盖 7 对有效 + 4 对单侧（mruby / freeradius / libavc 三个目标）；其余目标的机制外推未验证；
- **M1 的"0 例"成立于 ASan 口径**：另有 46 例 core dump（无 ASan 头）因目标二进制对空输入也 SEGV
  而无法定性，需把那些字节在真实目标上重放才能定论（本审计环境不具备）；
- 除 2 个 codex PoC 外未做重放复验；
- codex 世代提示词的"1800 秒"硬编码已修（`c9648f858`），不影响本报告结论。

---

## 9. 下一步

1. **按"条件"设计预注册 A/B**（验证 §0.3/§0.4 的因果，而非仅相关）：选两个目标——
   (a) 抗乱撞 + 报告正确（预期 SymCC 快），(b) fuzz 友好 + 报告正确（预期无差别或更慢）——各 3 对；
   判定规则（命中口径 = 目标类 ASan、时刻 = 首次产出崩溃的执行、band = 噪声 ±30 s）先写死再跑。
2. **修契约**（收益最直接）：枚举合法 `poc_kind` 并在报错时回显合法取值；接受协议重现命令
   （`poc_path` 逐字规则对 `run-input` 例外）。目标：把 `invalid_submission` 从 33 例压到个位数。
3. **修反馈**：给 focus 加"无梯度检测"——命中率≈100% 或 `new_lines` 单调枯竭时显式标注"该锚点无
   区分度"，避免 71 轮锚定类失败。
4. **报告质量前置**：把"报告锚点是否落在真根因/真 sink"作为进入统计的前置条件（§5）；不过关的组
   按 §1.3 规则整组剔除，并在实验清单里标注剔除原因。
   报告契约已加 `target_function`/`target_file` 两个显式字段（旧报告仍可从 `location` 兜底解析），
   检查清单见 [`../../guides/running-experiments.md`](../../guides/running-experiments.md) §3.0。
5. **口径固化**：把本轮修好的口径做成脚本（臂别分类、`invalid_submission` 分型、
   "首次产出崩溃的执行时刻"、回放崩溃分类），避免下次再靠人工判断（§1.5）。
