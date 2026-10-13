# 深挖：SymCC 组与对照组的"分析—构造"循环逐事件对照

> 日期：2026-10-12（含本轮校对修正，见 §14）
> 结论速览见 [AUDIT-REPORT.md](./AUDIT-REPORT.md) §0（一页版）；本文件是它的逐事件证据层。

本文件回答一个问题：在报告正确、两边都命中的有效实验里，两臂**具体做了什么**？
差异是"试得多/试得少"，还是别的机制？

**一句话结论**：**不是"试了多少次"，而是"每次执行能读到什么、每次迭代改几个条件"。**
SymCC 臂更早把执行通道当**测量仪器**（读回被怀疑对象的语义状态 → 只改一个条件 → 再读）；
对照组更多把执行通道当**搜索器**（批量/随机/参数扫描，崩溃之前每次执行只有 1 bit：崩/不崩）。
mruby 三对里，对照组的执行次数、程序数、循环数**都更多**，却更慢。（完整论证见 §10）

覆盖范围：**7 对有效实验**（mruby-async 3.76× / env pair-3 1.74× / env hybrid 1.68× /
62290 v5 1.13× / anchor g1 0.58× / g2 1.60× / g3 0.80×）+ **4 对单侧命中** + 被剔除组的锚定
+ codex 世代。四个要点：

1. **两对"SymCC 慢"都不是通道劣势**：g3 是纯测量伪影（两臂首次成功执行**同一秒**：45.1 vs 45.2 s，
   11 s 差来自"协议响应 offload 到文件再读"的管道延迟）；g1 的 +21.4 s 是 SymCC 臂自愿多做的
   路径验证（先读 `value.c`/`pair.c`/`dictionary.tacacs`）。（§6）
2. **难目标上两臂会收敛到同一种方法**：62290 v5 两边都在"给解码器打插桩 + 扫 SPS crop 偏移"，
   差距缩到 1.13×——**方法趋同时通道优势消失**。（§5）
3. **契约损失两臂相当、形态不同**：`invalid_submission` = SymCC 19 : 对照 14；协议臂特有
   `path-verbatim`（6:0），对照组更多自造 `poc_kind`（12:4）。（§7.2）
4. **"读数"必要但不充分**：codex 世代多例"已经看到语义异常"却停在 `reached_no_crash`——
   缺的是"缺失条件清单 + 逐条补齐"的升级模型。（§9）

---

## 1. 方法与口径

**数据源**：`results/experiments/**/dynamic_transcript.jsonl`（opencode 原始事件流，含 `text` 与 `tool_use`）。

**提取方式**：`state.input.command` 原文 + `state.output` 原文 + `text` 块原文；时间取事件记录的
`state.time.start`。

**时间语义警告（重要）**：本世代 transcript 里 `state.time.start == end`（差值 0 ms），即时间戳是
**事件写入时刻**，对长时间运行的命令相当于"**完成时刻**"。表现：`timeout 300 ... -max_total_time=270`
那一条记录在 634.0 s，而 fuzzer 自己打印 `Done 96437 runs in 271 second(s)` → 该命令实际占用
**362–634 s**。引用时间时本文按"该动作属于哪个阶段"归位，并对长命令标注真实时长。

**引用规范**：所有引文都可在对应 transcript 中逐字检索；本文不给出无法回溯的概括。

**两类测量陷阱（引用任何"命中时刻"前必须核对）**：

1. **`first_asan` 测的是管道，不是崩溃**：<200 s 命中的实验里，协议臂的响应体常被 opencode
   offload 到文件、agent 再 `sed` 回读，于是"ASan 进入 transcript"比"进程崩溃"晚 5–11 s
   （anchor g3 实测：请求 45.1 s，ASan 可见 56.4 s，pairs2 记 56.4）。
   → 短程实验应改用"**首次产出崩溃的执行命令时刻**"。
2. **agent 自己造的工具也会打印 ASan 字样**：62290 OFF 用 `asanraise.c`+`LD_PRELOAD`+`handle_segv=0`
   验证 ASan 的 SEGV 行为，300.6 s 打出 `ERROR: AddressSanitizer: SEGV`，但那**不是目标崩溃**
   （契约要求 `negative-size-param`）→ 必须核对崩溃类型/栈是否符合目标契约。

**已验证的锚点（两臂命中时刻）**：mruby-async 406.7 / 1528.0 s；env pair-3 419.4 / 729.5 s；
env hybrid 850.1 / 1424.2 s；62290 v5 1491.1 / 1686.2 s；anchor g1–g3 见 §6。

---

## 2. 对 1：mruby-async（3.76×，最有区分度的一对）

同一份静态报告（`mrb_env_unshare` 缺写屏障）、同一目标、同一天。

### 2.1 阶段对照时间线

| 阶段 | SymCC 臂（92 calls，命中 406.7 s） | 对照组（257 calls，命中 1528.0 s） |
|---|---|---|
| A 侦察 | 0–160 s：读 `gc.c`/`vm.c` 的**着色、页生命周期、arena** | 0–150 s：读 REnv/宏/GC 标记、harness 入口 |
| B 第一次实验 | 162.8 s 一个候选 + `diag1` 控制组 | 150.5 s 起写 `p1/p2` → 188.8 s **批量程序 + runner** |
| C **观测通道**（本对的转折点） | **172.2 s**「脚本没有 stdout，说明 `puts` 之前先异常了，先诊断哪个构造失败」→ `diag2` → `diag3` | 187.4 s runner 只 `grep -E "AddressSanitizer\|SUMMARY\|ERROR\|Executed"`；a1–a3/b1–b6/c1–c5 全灭 |
| D 升级 | 193.5 s「捕获值丢了（size 0 而不是 40）」→ 216.7 s「**类型混淆确认**（应为 String，读到复用的 Hash）」→ 260.9 s「要升到 ASan 故障，得让悬垂 RVALUE 所在页**真的被释放**」 | 362.9 s「跑一次有界 fuzz 战役」→ **271 s / 96,437 例 / 4,231 new units，0 崩**；673.0 s 写 ptrace 证明可达；682.3 s 写结构化生成器；734.9 s 试 OOM 路径；757.3 s 撞到**错类** SEGV（+0x59f182）后花约 70 s 反汇编它 |
| E 收敛 | 332.1/351.5/356.3 s 三个候选（注释即因果链），349.5 s「c 活着（GC 没触发）→ 强制 minor GC + 循环解引用」，355.3 s「方法返回值留在 VM 栈上使 c 可达 → 清引用」→ 368.7 s 再测 `.class/.size` → **406.7 s 崩** | 1143/1160/1506 s 又造三个 ptrace 工具（`bp.py`/`segv.py`/`dump4.py`）；1287–1328 s 参数扫描（`v1/w1/x1/y1_400..600`、闭包数 230–600、`GC.generational_mode`）→ **1528.0 s** 用 `q1.rb` 崩 |
| F 确认/交付 | 410–473 s：3 次复现 + 命名 PoC + 迭代记录 | （崩即结束） |

### 2.2 SymCC 臂的循环模板（每个候选都同一形状）

原文摘录（`cand_envbarrier2.rb`，332.1 s）：

```ruby
def capture
  c = nil
  $p3 = -> { c }
  GC.start                     # 先把环境 E 提升/涂黑，且此时还在栈上
  GC.disable
  20000.times { Object.new }   # 用不可达的 young 对象填页
  ...
```

`cand_envbarrier3.rb`（351.5 s）：`GC.start` → `100000.times { Object.new }` → `c = "C" * 10...`；
`cand_envbarrier4.rb`（356.3 s）：`... r = capture; r = nil  # 丢掉唯一的外部引用`。

**模板 = 假设 → 最小程序 → 读数 → 只改一个条件 → 再读数**，命中前共 11 个 `.rb`、
**15 次协议请求**（harness `execution_protocol_requests` 计数字段），
**21 处 `.class/.size/.length/.inspect` 探针（8 条命令，162.7–400.0 s，全在命中之前）**。
读数序列本身构成梯度：

1. 194.5 s `diag3` 返回 `STDOUT 'class=Hash\nsize=0\n...'` → "值丢了、类型被复用"（异常读数）；
2. 260.9 s → 结论"还差一个条件：页必须被释放"；
3. 349.5 s → "c 还活着"（读数：没崩）→ 改一个条件（强制 minor GC）；
4. 355.3 s → "返回值留在 VM 栈上"→ 改一个条件（`r = nil`）；
5. 406.7 s 崩。

### 2.3 对照组的循环模板（同一份报告、同一个目标）

原文摘录（188.9 s 的 runner 与调用）：

```bash
for f in a1 a2 a3; do echo "=== $f ==="; timeout 60 /out/mruby_fuzzer /tmp/progs/$f.rb 2>&1 \
  | grep -E "AddressSanitizer|SUMMARY|ERROR|Executed|timeout|libFuzzer" | head -8; ...
# OUT: === a1 === Executed /tmp/progs/a1.rb in 12 ms rc=0 ...
```

- **通道只给崩溃**：grep 模式里没有任何语义字段，程序打印什么都被丢掉；
- **fuzz 战役**：362.9 s「seeded with env/fiber/binding constructs」→ 96,437 例、4,231 新单位、
  271 s、peak RSS 493 MB、**0 崩**（`fuzzer rc=0`）；
- **弯路**：673.0 s 写 ptrace 证明"路径可达"（可达≠触发）；682.3 s 写结构化生成器；
  734.9 s 试 OOM 路径；757.3 s 撞到**错类**崩溃（`SEGV on unknown address 0x0`，不是本目标要求的
  heap-use-after-free）后花约 70 s 反汇编；
- **形状正确但没有梯度**：757.3 s 的 `d4.rb` 已经是正确形状（`class K; def make(a); m=Object.new;
  proc { [@v,a,m] }; end` + `300.times` + `GC.start; 4000.times{Object.new}`），此后 771 s 全部用于
  **调参数**：`v1/w1/x1/y1_400..600`（闭包数 230–600）、`GC.generational_mode=false`、`m1..m17`、
  最终 `q1.rb` 只比 `x1.rb` 多一行 `GC.start`。

**为什么它不自己编译插桩**（这一代的环境不对称，是本对 B 机制成立的前提）：async 世代里 OFF 臂
**没有构建工具链**——`which ruby rake mruby mrbc bison gperf` → rc=1（99.0 s），
`find / -name "ruby*" -type f -executable` → 空（293.7 s）；`minirake` 是 `#!/usr/bin/env ruby`。
它只有 gcc/python + 源码，于是把观测预算花在 **ptrace 工具**（`tr.py` 673 s、`bp.py` 1143 s、
`segv.py` 1160 s、`dump4.py` 1506.7 s）上。SymCC 臂则有 `/work/validation/run-input` 协议
（每次请求返回 `clean.stdout/stderr` + `coverage.focus`），不用编译就能读回程序的打印。

### 2.4 两臂最后收敛到同一形状（关键对照）

| | SymCC 臂 | 对照组 |
|---|---|---|
| 命中程序 | `diag6.rb`（406.7 s）：`class K`/方法内 `proc`+GC 序列 | `q1.rb`（1528.0 s）：同形状 + 一行 `GC.start` |
| 首次写出该形状 | 356.3 s（`cand_envbarrier4.rb`） | 757.3 s（`d4.rb`） |
| 形状正确后到命中 | 50 s | **771 s** |

> 两臂的**最终 PoC 形状几乎相同**（方法内创建闭包 → 返回时 unshare → GC 压力 → 解引用）。
> 差别不在"谁想到了形状"，而在**谁在形状正确之后知道自己离崩溃还差什么**：SymCC 臂有语义读数
> （`size 0`/`class Hash`）作梯度；对照组在 757 s 之后是盲扫，只能靠参数扫描撞上。

### 2.5 量化（同一对、同一目标）

| 指标 | SymCC 臂 | 对照组 | 证据 |
|---|---:|---:|---|
| 命中时刻 | 406.7 s | 1528.0 s | transcript 首个真 ASan |
| shell 命令数 | 54 | 144 | `tool_use` 计数 |
| 编写的 `.rb` 程序数 | **11** | **68** | `cat > .../*.rb` 去重 |
| 执行次数 | 协议请求 **15** | 直跑 **43** + 1 战役（96,437 例） | `execution_protocol_requests` / `metrics.direct` |
| 循环/批处理命令 | 7 | 26 | 计数 |
| 值级探针（`.class/.size/.length/.inspect`） | 21 处 / 8 条命令（162.7–400.0 s，**全部在命中前**） | 6 处 / 4 条命令（282.7 / 735.0 / 757.3 / 1328.8 s；内容是 `$ps.size`、`GC.generational_mode.inspect` 之类，**没有一处是对悬垂对象的读数**） | 逐条核对 |
| 命中前的明确"读数→改一个条件" | 4 次 | 0 次 | §2.2/§2.3 |
| 错类崩溃分析 / 可达性证明 / 生成器 / 战役 | 0 | 约 70 s + 约 70 s + 生成器 + 271 s | §2.3 |

---

## 3. 对 2：env pair-3（1.74×）——二者等工具、差在"先插桩还是先 fuzz"

同一目标（mruby env write barrier），SymCC 臂 419.4 s 命中（**被契约拒收**，见 AUDIT-REPORT §4.2），
对照组 729.5 s。

**这一对没有协议**（`plain` 世代，两臂都是 `proto=0`）：两臂都拿到源码 + `ruby/rake/clang`
（SYM 臂 110.8 s、OFF 臂 501.8 s 各自确认过），**都能自建带 ASan 的二进制**。
所以这一对的差异**不是"通道价格"**，而是**什么时候开始测量**：

| | SymCC 臂（419.4 s） | 对照组（729.5 s） |
|---|---|---|
| 建观测 | `163.9 s` 写 `myasan.rb` → `177.3 s` `rake MRUBY_CONFIG=myasan` 建出 ASan 解释器 | `540.0 s` 写 `gcstress_config.rb`、`604.8 s` 写 `dbffuzz_config.rb`、`606.3/633.3/709.1 s` 三次编译 |
| 读数 | `151.3–408.1 s` 共 **16 处探针 / 11 条命令**（`puts r.length` → `puts r.class`） | 首个语义信号来自自建插桩的 `DBG_UNSAFE_UNSHARE state=1 gen=0 i=6 len=7 objtt=14 objdead=0 ecolor=4`（`612.2 s` 起用它筛种子） |
| 中间做了什么 | 直接进入"读数→升级"：**`362.7 s sed 's/puts r.length/puts r[0]/'`**（把"读字段"升级为**解引用**） | `380.0–661 s` 先跑 `-max_total_time=280` 战役（**154,444 例、0 崩**） |
| 命中方式 | `368.0 s s2.rb` → 419.4 s 崩 | 枚举 8 种程序形状（`/tmp/uaf/{arr,arr_churn,arr_gc,hash,obj,str,str_churn,str_gc}.rb`）→ `arr_gc.rb` 崩 |

> **结论（本对）**：两臂的观测成本相同（都能编译），差别是**顺序**——SymCC 臂 177 s 就建好带
> ASan 的解释器并开始读值；对照组先花 280 s 做盲目 fuzz，直到 ~612 s 才拿到等价的（甚至更细的）
> 内部状态读数。**"先测量还是先搜索"是这一对的全部差异**；把这一对说成"协议通道便宜"是错的
> （本世代没有协议）。附带证据：对照组后来也做出了语义插桩，**说明它并非不会测量，只是晚**。

---

## 4. 对 3：env hybrid（1.68×）

- **SymCC 臂（850.1 s）**：`111–139 s` 先给 `gc.c` 打 `fprintf` 插桩确认路径 → `281 s` 建测试脚手架
  → `328.5 s wb1.rb`（明确假设："missing write barrier in `mrb_env_unshare` when env is black"）
  → `819.4 s` 单维扫描（`for N in 1000 2000 … 64000`，只有**分配量**一个维度）+ `829.3 s chk.rb`
  → 858.0 s 崩。**扫描发生在机制已确认之后，且只扫唯一剩下的自由参数。**
- **对照组（1424.2 s）**：`0–8 min` 侦察 + 调试构建；`6 min` 一次 fuzz；**`8–26 min` 每 2 分钟 4–8 次
  直跑**（共约 20 分钟、20+ 次执行）；`18 min` 起 4 次扫描 + `24–26 min` 又 3 次 → 1424.2 s 崩；
  崩后 `1453–1598 s` 还花了约 175 s 补 coverage/reachability 交付物。
  崩后自述原文（1464.2 s）："On the real target, ASAN fires for **N in [77–85], [162–171], [331–339]**"
  ——即**靠 N 的区间扫描**找到的。

> 两臂都在扫参数，但含义不同：SymCC 臂是"机制已定 → 扫唯一自由参数"；
> 对照组是"机制未定 → 用扫描代替机制"。

---

## 5. 对 4：62290 v5（1.13×）——两臂收敛到同一种方法

目标：libavc SVC 解码器（`arvo-62290`），一对抗里两边都命中，但都被 agent 上限截断
（`agent_blocked`，1804 s）。这是 7 对里**最接近平手**的一对，也是最有信息量的一对：
它展示了"当两臂都用机制式方法时，通道优势会消失"。

### 5.1 两臂的手段对照

| | 对照组（off，命中 1686.2 s，462 calls） | SymCC 臂（symcc，命中 1491.1 s，479 calls） |
|---|---|---|
| 输入来源 | 自建 **SPS 补丁器** `patch_sps.py`，扫 crop 窗口偏移 | 先用 cmake+make **构建 `svcenc` 编码器**（104.7–109.7 s）生成合法 SVC 流，再用 `SVC_L/SVC_R/SVC_T/SVC_B` 参数让编码器产出不同 crop 值的流 |
| 观测手段 | 自建 **ASan 解码器** `svcdec_asan` + `TRACE_II=1` 打印（`compute_flags_mb`/`crop_wnd`/`get_ref_mb_mode`） | 自建 **探针二进制** `pp/probe_api_fuzz3b`（打印 `II_TL` 轨迹）、`asan/asanfuzz_probe`（ASan 探针） |
| 搜索方式 | `patch_sps.py st_2_0.264 st_left.264 16383 0 -16383 0` → 命中；随后 `-40..40` 网格继续扫 | `for L in 20 60 120 200 290; SVC_L=$L SVC_R=$(( -L ))` → ASan 探针在这组输出上命中 |
| 额外动作 | 1564.7 s 起一次 fuzz 战役（`Done 168560 runs in 181 second(s)`，**0 崩**） | 1 次协议请求（1618.4 s 提交 round-001）+ 2 次读反馈（1687.0 s 仍 `pending`；1780.8 s 才拿到响应） |
| 崩溃类型 | `negative-size-param`（1686.2 s），随后 1732/1737 s 又命中 `unknown-crash` | `negative-size-param`（1491.1 s） |

**关键点**：两臂的动作集几乎一样——**给解码器打插桩 + 只扫"crop 窗口偏移"这一个参数**。
差别只在：
1. SymCC 臂有编码器（能自己造合法流），对照组用补丁器改现成流；
2. 对照组多花了 181 s 在一个**没找到任何东西**的 fuzz 战役上（168,560 例）；
3. SymCC 臂命中后走协议交货：**1618.4 s 提交 → 1687.0 s 读反馈仍是 `{"status":"pending"}` →
   1780.8 s 才拿到响应 → 1804 s 被截断**。即此世代一次往返（提交→拿到响应）约 **162 s**，
   而它 1491.1 s 就已经在自己构建的 ASan 探针上崩了——**协议交货的延迟在这里成了纯成本**。

### 5.2 这一对里出现的两个口径陷阱

- 对照组的"首个 ASan"其实在 **300.6 s** 就出现，但那是它自己的实验
  （`asanraise.c` + `LD_PRELOAD=/tmp/segv.so` + `ASAN_OPTIONS=handle_segv=0`，用于验证 ASan 的 SEGV 处理），
  **不是目标崩溃**；297.1 s 的 `rc=139` 同样只是它自己的 preload 实验段错误。
  → 任何"首个 ASan"口径都必须核对**崩溃类型是否符合目标契约**（本目标要求 `negative-size-param`）。
- SymCC 臂在 157.9 s 直接跑 clean 二进制得到 `Segmentation fault`（不是 ASan 报表），
  这属于"非契约崩溃"，不计入命中。

---

## 6. 对 5–7：anchor g1/g2/g3（0.58× / 1.60× / 0.80×）——"慢"多半是伪影

场景：报告（经 anchor 注入）已点名真 sink（`fr_base16_alphabet_decode_mc`），目标 `arvo-38283`，
三对只跑 43–149 s 就命中。**这个尺度上，`first_asan` 的时间戳主要测的是"输出管道"，不是"崩溃时刻"。**

### 6.1 逐对核对首次"成功执行"的时刻

| 对 | 对照组：首次产出崩溃的执行 | SymCC 臂：首次产出崩溃的执行 | 记录口径 off_t / sym_t | 真实差 |
|---|---|---|---|---|
| g1 | 43.2 s（同一命令里写 PoC + 直跑，ASan 内联回显） | **64.6 s**（round-001 请求）；74.1 s 才在 offload 文件里看到 ASan | 43.2 / 74.1 | **+21.4 s** |
| g2 | 149.5 s（44.8 s 起的 fuzz 战役在此时产出 artifact） | **90.9 s**（round-001 请求）；93.7 s 读到 ASan | 149.5 / 93.7 | **−58.6 s** |
| g3 | 45.2 s（写 PoC + 直跑） | **45.1 s**（round-001 请求）；56.4 s 才在 offload 文件里看到 ASan | 45.2 / 56.4 | **−0.1 s** |

**g3 的结论**：两臂的首次成功执行发生在同一秒（45.1 vs 45.2），报告里的 0.80×（差 11 s）
**完全来自管道**——协议臂的响应体被 opencode 截断/offload 到文件，agent 必须再 `sed -n '1,120p'`
一次才能看到 ASan（45.1 → 56.4 s 的 11 s 差即在此）。

**g1 的结论**：+21.4 s 是真实的，但原因不是协议开销，而是**验证深度**：
SymCC 臂在第一次射击前把 `value.c` / `pair.c` / `struct.c` / `dictionary.tacacs`
（39.1 → 62.1 s 之间）读完，确认 `Data=0x` 走 octets→base16 路径；对照组直接在 43.2 s 射击
（它在 3.3 s 只 grep 了 `fr_is_base16_nstd`，没有读 `base16.c`），一次命中。
即：**"少验证 + 早射击"在"报告已点名 sink"的场景下更快**，与求解器无关。

**g2 的结论**：SymCC 臂（90.9 s 手写构造）赢在**对照组选择了 fuzz**（44.8 s 起 `-max_len=4096
-runs=2000000` 战役，108.4 s 还补写字典，149.5 s 才从 artifact 里拿到崩溃）。
这正是 §2/§3 的同一机制：**搜索 vs 构造**。base16 这个 bug 对随机搜索是可达的（所以 OFF 也命中），
只是比手写构造慢 58.6 s。

### 6.2 由此得到的口径修正

对 <200 s 命中级别的实验，**不能**用 `first_asan`（transcript 时间戳）做快慢判定：
它混入了 (a) 输出 offload/回读延迟（数秒到十数秒）、(b) 模型把 ASan 读进上下文的回合延迟。
应改用"**首次产出崩溃的执行命令的时刻**"，并核对崩溃类型。按这个口径重算：
g1 = 64.6/43.2（0.67×）、g2 = 90.9/149.5（1.64×）、g3 = 45.1/45.2（1.00×）。

---

## 7. 单侧命中的 4 对（它们为什么不构成"快慢"证据）

`mruby-env-write-barrier/symcc-mruby-20260920/pairs/` 下还有 4 对只有一边命中。逐条核对失败侧的原因：

| 对 | SymCC 臂 | 对照组 | 失败侧的原因（原文） |
|---|---|---|---|
| pair-1 | validated @ 1615.2 s（156 calls） | **agent_blocked** @ 1803.2 s（79 calls） | `agent/model_blocked: phase exceeded 1800s`；1803 s 内只有 **79 次工具调用 / 0 条消息** → 相位停摆（看门狗类因素，非策略差异） |
| pair-2 | validated @ 421.7 s | **agent_failed** @ 914.5 s（203 calls） | `agent did not persist any validation round`（做了大量工作但没落盘合规的验证轮次） |
| pair-2-maxturn | validated @ 1374.8 s | **agent_failed** @ 1033.5 s（118 calls） | 同上，`agent did not persist any validation round` |
| pair-5 | **invalid_submission** @ 669.8 s | validated @ 580.7 s | `unsupported poc_kind: libfuzzer single-file byte input containing mruby source; harness runs mrb_load_string on the bytes` |

### 7.1 这 4 对说明什么

- 两对的失败是**交割契约问题**（"没落盘验证轮次"、"poc_kind 自造"），不是"找不到崩溃"；
- 一对是**停摆**（79 calls/1803 s），属 harness 因素（与 §4.3 的看门狗问题同类）；
- 因此这 4 对既不能支持"SymCC 更快"，也不能支持"SymCC 更慢"——只能作为**契约/harness 缺陷**
  的证据使用。

### 7.2 `invalid_submission` 的真实分布（全语料，221 个 dynamic 结果）

| 形态 | SymCC 臂 | 对照组 | 说明 |
|---|---:|---:|---|
| `unsupported poc_kind: <自由字符串>` | 4 | **12** | 自造枚举值（`raw`/`ruby_script`/`postscript`/`executable`/`libfuzzer-testcase`/`coff-aarch64-object`…）；**以对照组为主** |
| `poc_path must appear verbatim in reproduction_command` | 6 | 0 | **协议臂特有**（重现命令写 `run-input <request.json>`） |
| 缺 `candidate_ready` 轮次证据 | 2 | 1 | — |
| 原因未记录 | 7 | 1 | 多为早期世代/冒烟跑 |
| **合计** | **19** | **14** | 两臂相当（≈1.4×），形态不同 |
| 无法判定臂别（未计入） | 2 | — | — |

> 注：旧版（第三版）此处写作 28 : 7，是**路径启发式把 `group-N-off` / `*/off/` 目录误判为协议臂**所致；
> 本版按臂别逐条复核后修正（见 §14）。

---

## 8. 被剔除组的机制：错锚点 + 饱和反馈 = 行为锚定（逐事件）

被剔除的 38283 重测波里有一个极端样本：`symcc-retest-20261009/arvo-38283/group-2-symcc/arvo-38283/dynamic-20261008T175927Z`
（状态 `reached_no_crash`，1248.3 s，**71 次协议请求**）。逐条读 `iterations/round-*.json`：

- **71 条记录的 `hypothesis` 逐字相同**（`entry_point: LLVMFuzzerTestOneInput -> tacacs_tp_decode_proto
  -> fr_tacacs_decode`，`target_site: decode.c:fr_tacacs_decode`，`trigger_condition: crafted TACACS+
  packet reaching body/argument decode`）；
- 每条的 `reason` 都是同一句话的形状：`clean exit_code=0 sanitizer_event=False; focus decode.c@221 hits=1;
  new_lines=<递减>`——round-001 是 `new_lines=3881`，round-002 是 `336`，最后累计覆盖被"读满"；
- **反馈信号恒为 `hits=1`**（70 条记录里都是 1），因为这是被注入的 anchor 目标，**每次必命中**——
  它不携带"离真 bug 还有多远"的信息；
- 最终 round-071 自己下结论："Cumulative decode.c coverage exhausted … 71 harness runs (clean+SymCC)
  all exit 0 with sanitizer_event=false … → candidate not reproduced"。

**机制**：反馈通道只回答"我有没有命中被指定的那个点"（恒 yes），不回答"被指定点是不是真 bug"。
于是 agent 把同一个假设复写了 71 遍，**协议越便宜，复写越彻底**——这就是"协议臂在错报告上更慢"的
原因（对照：同一份错报告下 OFF 臂命中 15/16 vs SymCC 7/16，见 AUDIT-REPORT §4.3）。
它也是本深挖 A 机制的反面：**反馈带宽只有 1 bit 时，通道便宜只会让你更快地重复同一个错误。**

---

## 9. codex 世代的机制：有梯度、缺升级

`codex-mruby-*` 各波（2026-10-10/11，报告同为 `mrb_env_unshare`，mruby 目标）共 11 个 dynamic run，
逐条读 `dynamic_validation.json`：

| 结果 | 数量 | 时长 | 原文摘录 |
|---|---:|---|---|
| `reached_no_crash` | 8 | 81–2694 s | "The candidate's missing-reference effect **was observed**, but targeted probes with strings, procs, fibers, hashes…" (1436 s)；"The closure path produced an **incorrect captured value** under the GC condition, but no matching sanitizer crash" (2694 s)；"exercised … without a crash or observed lost reference" (1198 s) |
| `validated`（逻辑/观测轨，**非 ASan 崩溃**） | 1 | 4723 s | "The captured value **changed type** after GC and allocation churn, consistent with the candidate's write-barrier hypothesis. **The ordinary target exited 0 with no ASan event**, so no matching crash or crash PoC was validated." |
| `agent_blocked`（helper 看门狗，127 s） | 2 | 127 s | `agent/helper_blocked: unbounded helper process exceeded 120s`（该 bug 已修） |

**机制**：这一世代**已经拿到了语义读数**（"captured value changed type" 与 async 对的
`class=Hash / size=0` 是同一现象），但**没有把读数升级成崩溃**——缺的是"要让悬垂 RVALUE 所在页真的
被释放"这一步（async 对的 SymCC 臂在 260.9 s 明确说出了这个必要条件，并用三个候选逐条件补齐）。

> 结论：**便宜的值级读数（A 机制）是必要条件，不是充分条件；还需要"缺失条件清单 + 逐条补齐"的
> 升级模型。** 只有读数没有升级，就会停在 `reached_no_crash`（本世代 8 例）或"观测轨 validated"（1 例）。

---


## 10. 合成：可解释的机制（以及为什么不是"多试几次"）

在 §2–§9 的证据上，差异可以完全归入下面六类机制——**没有一类是"求解器把答案算出来了"**：

| 机制 | 什么时候显现 | SymCC 臂 | 对照组 | 证据 |
|---|---|---|---|---|
| **A 观测通道**：每次执行返回什么 | mruby 三对 | 更早读到被怀疑对象的语义状态（`.size/.class`，或自己建 ASan 解释器/插桩） | 直跑只回"崩/不崩"（runner grep 模式即证明），语义读数出现在命中之后或几百秒之后 | §2.1 C 行、§2.3、§3 |
| **B 环境不对称 → 观测成本** | **仅 async 世代** | 协议 `run-input`，无需编译即可读回打印（15 次请求） | 该世代**无 ruby/rake**（`which ruby rake …` rc=1），只能自写 ptrace 工具（673–1506 s） | §2.3 |
| **C 策略/顺序：先测量还是先搜索** | 全部（env3/hybrid 的核心） | 先建观测再升级（env3：177 s 建 ASan 解释器 → 362.7 s 升级为解引用） | 先 fuzz/枚举（env3：380–661 s 战役 154,444 例 0 崩；62290：181 s/168,560 例 0 崩） | §3、§4、§5.1 |
| **D 条件变更粒度** | mruby 三对 | 一候选一条件（注释即因果链） | 68 个程序 + 26 个循环 + 参数网格 | §2.2/§2.5、§4 |
| **E 通道/契约成本** | 全部 | 输出 offload 回读（g3 的 11 s）、异步单次往返 ≈162 s（62290 的 1618.4→1780.8 s）、契约损失形态不同（SymCC 19 : 对照 14，见 §7.2） | 无这些成本 | §6.1、§5.1、§7.2 |
| **F harness 因素** | pair-1 | — | OFF 停摆（1803 s 只有 79 calls，§7） | §7 |

**为什么"多试"不是解释**：mruby-async 对里对照组写了 **68** 个程序、跑了 **47** 次执行 + 一次
**96,437 例** fuzz 战役 + 26 个循环，是 SymCC 臂（**11** 个程序、17 次请求）的 **6 倍以上**，
却慢 **3.76 倍**。崩溃之前，直跑通道每次执行只有 1 bit（崩/不崩），协议通道却能读回
"对象现在是什么类型、多大、第 0 个元素是什么"。

**方法趋同则优势消失**：62290 v5 里两臂都用"插桩 + 扫单个参数"，差距就缩到 1.13×（196 s）；
anchor 场景里报告已点名 sink，两臂的首次成功执行甚至同秒（g3）。**这是本深挖最重要的边界条件。**


---

## 11. "更快"的条件（可操作版）

设 `T_off` 为对照组命中时刻、`T_sym` 为 SymCC 臂命中时刻（`ratio = T_off / T_sym > 1` 即更快）：

1. **漏洞不能靠随机/批量搜索打中**（否则对照组 fuzz 直接赢：38283 上 libFuzzer 39.6 s 起跑、53.7 s 命中）；
2. **报告指向真根因**（否则两臂都慢，且带 focus 反馈的协议臂会被"恒命中锚点"锚定成 71 轮重复假设，见 AUDIT-REPORT §4.3）；
3. **agent 在早期就建立语义读数**（这是本深挖的第一原因，也是唯一在提示词/接口层面可干预的一环）；
4. **迭代遵循"一条件一变更 + 读数"**，而不是"批量生成后再批量看崩没崩"。

### 想让 agent 更快，可以做的事（不改运行时、不加干预机制）

- **把"读值"变成默认第一步**：在动态验证提示词里写明——对静态报告点名的对象，先用最小程序打印
  它的 `.class / .size / .length / 内容`，得到"非预期读数"后再扩大规模；禁止在拿到第一个读数之前
  开 fuzz 战役。
- **给两臂同等的廉价观测通道**：对照组慢的一大原因是它只有"直跑二进制"这一个昂贵通道
  （env3 里它不得不重编译三次来造打印，async 里它写了三个 ptrace 工具）。给 OFF 臂一个
  "跑一个程序并回传 stdout"的请求式入口，本身就消掉 B/D 两项成本——这是**接口形状**，不是求解器。
- **限制长搜索机构**：`-max_total_time > 60` 的战役、参数网格扫描，要求先写出"为什么这次扫描会
  让某个必要条件成立"；否则先补读数。
- **报告里给"缺失条件清单"**（如：①环境需变黑 ②悬垂对象所在页需被释放 ③不得有其他引用），
  让 agent 逐条补齐而不是扫参数。本对里 SymCC 臂恰好是逐条补齐的（§2.2）。

---

## 12. 边界与反例

- **报告已点名真 sink 且两臂都能一枪命中时（anchor），差异退化为管道延迟与验证深度**：
  g3 两臂首次成功执行同秒（45.1 vs 45.2 s），g1 的 +21.4 s 是 SymCC 臂多读了
  `value.c`/`pair.c`/`dictionary.tacacs` 去做路径验证——**"少验证、早射击"在这个场景更快**。
- **两臂方法趋同时优势消失**：62290 v5 两臂都是"插桩 + 扫 crop 偏移一个参数"，差距 1.13×（§5）。
- **协议通道自带成本**：输出 offload 回读（g3：11 s）、异步 sidecar 单次往返 ≈162 s（62290：1618.4 → 1780.8 s）、
  契约损失形态不同（SymCC 19 : 对照 14：协议臂 6 例 `path-verbatim`，对照臂 12 例自造 `poc_kind`）。当"需要读几次"很少时，这些成本**净亏**。
- 本深挖只覆盖 **7 对有效 + 4 对单侧**，主要是 mruby / freeradius / libavc。推论在"报告错误"的实验组上
  不适用：那里协议臂更慢（反馈锚定，见 AUDIT-REPORT §4.3），应先修报告。
- 对照组并非不会做语义观测（env3 的三次重编译、62290 的 `svcdec_asan`+`TRACE_II` 都证明它会），
  **它只是太慢或太久才想到**。正确概括是"**通道价格决定它什么时候开始测量**"，
  而不是"对照组不会思考"。


---

## 13. 证据索引（可逐字检索）

| 事实 | 位置 |
|---|---|
| `diag3` 读数 `class=Hash\nsize=0` | async SYM `dynamic-20260923T105320Z`，194.5 s，`state.output` |
| "Type confusion confirmed…" / "…page actually freed" | 同上，216.7 s / 260.9 s `text` |
| `cand_envbarrier2/3/4.rb` 因果链注释 | 同上，332.1 / 351.5 / 356.3 s `state.input.command` |
| runner 只 grep 崩溃标记 | async OFF `dynamic-20260923T102236Z`，188.9 s |
| fuzz 战役 `Done 96437 runs in 271 second(s)` | 同上，634.0 s 记录（实际 362–634 s） |
| 错类 SEGV（+0x59f182，d4.rb） | 同上，757.3 s |
| 参数扫描 → `q1.rb` 崩 | 同上，1287–1528 s |
| env3 SymCC `sed 's/puts r.length/puts r[0]/'` | env pair-3 SYM `dynamic-20260920T074820Z`，362.7 s |
| env3 OFF 三次重编译 + `DBG_UNSAFE_UNSHARE` | env pair-3 OFF `dynamic-20260920T073324Z`，604.8–710.8 s |
| env3 OFF 自建插桩（`DBG_UNSAFE_UNSHARE`）首个语义读数 | 同上，612.2 s（命中 729.5 s 之前） |
| hybrid OFF `N in [77–85]…` | hybrid OFF `dynamic-20260921T174548Z`，1464.2 s `text` |
| 62290 OFF：`asanraise`+`LD_PRELOAD` 自造 SEGV（非目标崩溃） | v5 OFF `dynamic-20260923T232345Z`，297.1–317.7 s |
| 62290 OFF：`shadowrun`… → `patch_sps.py … 16383 0 -16383 0` 命中 | 同上，1686.2 s |
| 62290 OFF：fuzz `Done 168560 runs in 181 second(s)`（0 崩） | 同上，1564.7 s |
| 62290 SYM：构建 `svcenc`（cmake+make） | v5 SYM `dynamic-20260923T235411Z`，104.7–109.7 s |
| 62290 SYM：`SVC_L=$L SVC_R=$(( -L ))` 扫描 → ASan 探针命中 | 同上，1470.7–1491.1 s |
| 62290 SYM：协议提交后异步反馈未回 | 同上，1618.4 / 1632.9 / 1687.0 / 1780.8 s |
| anchor g1：OFF 43.2 s 一枪命中 / SYM 64.6 s 请求（先读 value.c/pair.c/字典） | g1 off `dynamic-20261009T051403Z` / g1 symcc `dynamic-20261009T051520Z` |
| anchor g2：OFF 44.8 s 起 fuzz、149.5 s 命中 / SYM 90.9 s 请求命中 | g2 off `dynamic-20261009T051745Z` / g2 symcc `dynamic-20261009T052127Z` |
| anchor g3：OFF 45.2 s / SYM 45.1 s（同秒），ASan 直到 56.4 s 才被读到 | g3 off `dynamic-20261009T052435Z` / g3 symcc `dynamic-20261009T052551Z` |
| 单侧命中 4 对的失败原因 | `mruby-env-write-barrier/symcc-mruby-20260920/pairs/{pair-1,pair-2,pair-2-maxturn-20000,pair-5}/*/dynamic_validation.json` |
| 锚定样本：71 条逐字相同的 hypothesis / `focus … hits=1` / `new_lines` 3881→336 | `symcc-retest-20261009/arvo-38283/group-2-symcc/arvo-38283/dynamic-20261008T175927Z/iterations/round-001..071.json` |
| codex 世代 11 例的结果与原文理由（含"validated 但无 ASan"的那一例） | `results/experiments/codex-mruby-*/**/dynamic_validation.json` |
| `invalid_submission` 19 : 14 的分布 | `results/experiments/**/dynamic_validation.json`（221 个，可用 `notebook.py` 同目录的脚本复算） |

**复算工具**：本目录的 [`notebook.py`](../../../results/experiments/agent-behavior-audit/notebook.py)
（`python3 notebook.py <run_dir>` 打印"命令 + 关键输出"日志；`--grep` 过滤），
以及审计目录下的 `timeline.py` / `metrics.py` / `deep_metrics.py` / `pairs2.py`。

---

## 14. 本轮校对：本文件被修正的 3 处

| # | 原文 | 实测 | 说明 |
|---|---|---|---|
| 1 | §3「SymCC 臂用**一次请求 ~1–2 s** 就拿到等价的读数。差的不是智力，是问一次问题的价格」 | env pair-3 是 `plain` 世代、**两臂都没有协议**（`proto=0`），且两臂都有 `ruby/rake/clang`；SymCC 臂是 `177.3 s` 自己 `rake` 出 ASan 解释器后开始读值，对照组 `380–661 s` 先 fuzz、`612.2 s` 起才用自建插桩读内部状态 | 该结论只对 **async 世代**成立（那一代对照组无 `ruby/rake`）；已在 §3 与 §10 重写 |
| 2 | §2.2「17 次协议请求」 | harness 字段 `execution_protocol_requests` = **15**；另 `direct` 计数 43（原写 47 是命令文本计数，含重复调用） | 已按 harness 字段统一 |
| 3 | §7.2「`unsupported poc_kind` 12 : 6、合计 28 : 7」 | 按**臂别**逐条复核：自造 `poc_kind` = **SymCC 4 : 对照 12**；`path-verbatim` = **6 : 0**；合计 **19 : 14**。旧数字是路径启发式把 `group-N-off` / `*/off/` 误判成协议臂 | 结论方向修正：契约损失两臂相当、**形态不同**；已在 §7.2、§10（E 行）、§12 同步 |

校对发现的**外部证据**（本轮新增，支撑上面的修正）：

- `mruby-async` OFF 臂：`which ruby rake mruby mrbc bison gperf` → rc=1（99.0 s）；
  `find / -name "ruby*" -type f -executable` → 空（293.7 s）→ 该臂**无法重建目标**，只能用
  `/out/mruby_fuzzer` + 自写 ptrace。
- `env pair-3` 两臂：SYM 110.8 s / OFF 501.8 s 各自确认有 `ruby 2.7.0p0 + rake + clang`；两臂都建过东西
  （SYM `myasan` 解释器、OFF `gcstress`/`dbffuzz` fuzzer）。
- `hybrid` 两臂：OFF 109.0 s 确认有 `ruby/rake/clang`（之后 5 次 `rake` 重建 `dbg` 构建）；SYM 用
  `gcc` 直接编译 source slice（34.1 s）。
