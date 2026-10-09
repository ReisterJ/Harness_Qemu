# SymCC 测试案例盘点与重测可行性（2026-10-09）

> 目的：把 09-24～09-29 因 SymCC 自身出问题而搁置的测试案例重新整理成一等目标，
> 逐个检查"能不能用当前管线（09-23 回滚基线 + 去除非时间上限 + coverage/focus 反馈）重测"，
> 并给出重建与实验计划。
>
> 关联：速度结论见 `results/experiments/mruby-57672-final-report-20261008.md` §1；
> 旧版总览见 `docs/research/symcc-feedback-experiment-targets.md`、`results/experiments/symcc-experiment-overview-20260923.md`。
>
> **重测结果与归因分析（2026-10-09 晚发布）**：arvo-38283 十六组配对跑完后效果与预期相反，
> 归因见 `results/experiments/symcc-retest-20261009/ANALYSIS.md`。要点：
> (1) 协议式 SymCC 臂的提示词禁止"直接调用目标二进制"，因此该臂不能直接跑 libFuzzer，
> 两臂并非"同一策略 ± 求解器"（直接 fuzz 时长中位数 14–21s vs 271–332s）；
> (2) focus 锚点是函数级，38283 每个输入都命中（无梯度）、62290 从不命中；
> (3) 38283 的 bug 是 255 字节表的 0xFF 索引越界，**无分支可翻**，12,952 个 SymCC 生成用例 0 崩溃，
> 跨全部协议式实验 17,509 个生成用例 0 次"把不崩种子变成崩溃"；
> (4) 5/16 SymCC run 在覆盖率饱和后自停 `reached_no_crash`（OFF 同目标 15/16 命中）。
> 结论：这两个目标不能用来回答"外部助力是否加速"，需要先对齐工作流与目标点粒度。
>
> **静态报告质量对账（2026-10-09 晚发布）**：用户提出"是静态报告的问题"后做了逐字段核对，
> 见 `results/experiments/symcc-retest-20261009/STATIC-REPORTS-COMPARISON.md`。要点：
> (a) mruby 的报告是 `static` 相位真跑（根因锚点 + 机制 + 条件 + 计划），
> 38283/55020 的报告是 **2026-09-29 手写**的 CyberGym 一句描述转述（无 static 相位记录，
> 哈希可查），锚点一处落在崩溃栈上低 5 帧的过路函数（38283：`fr_tacacs_decode` 对真凶
> `fr_is_base16_nstd`），一处落在 objdump 路径**不可达**的链接期函数（55020）；
> (b) 62290 的报告是真的（`isvcd_ii_get_ref_mb_mode:171` = 真实解引用行），
> 但可达性需要合法 SVC 双层码流——随机输入下 1115 个插桩函数只有 1 个被执行，锚点 0 次；
> (c) 已按 CyberGym 数据集核对原始描述（HF `sunblaze-ucb/cybergym` 的 `tasks.json` /
> `data/arvo/<id>/description.txt`，原文存 `results/experiments/symcc-retest-20261009/cybergym-task-descriptions.json`）：
> 57672/62290 的描述点名了函数（报告因此准确）；38283 的描述**没有任何位置线索**（报告只能猜，猜错）；
> 55020 的描述**点名了真凶 `coff_aarch64_addr64_reloc`**，报告却写成链接期的
> `coff_pe_aarch64_relocate_section`——属转写丢线索，不是数据集缺陷；
> (d) 结论：**报告只打击被迫消费它的那一臂**（SymCC 协议把 focus 命中当 progress），
> 所以"静态报告问题"要放在"报告 × 工作流"的交互里看。
>
> **处置（2026-10-09 下午）**：三个新目标的静态报告与配置 `attack_surface` 已全部换成
> CyberGym 原始描述（逐字，脚本 `results/experiments/symcc-retest-20261009/build_reports_from_description.py`，
> 旧版本留档在 `.../legacy-static-reports/`）：
> 55020 的锚点改为描述点名的 `coff_aarch64_addr64_reloc`（真凶），
> 38283/62290 因描述未点名任何函数而**不带 focus 锚点**（宁缺毋滥）。详见该文档 §9。

---

## 0. 结论摘要

1. 搁置案例共 **4 个目标**（外加已充分测试的 mruby-57672）：
   `arvo-38283`（FreeRADIUS TACACS）、`arvo-55020`（binutils objdump）、`arvo-62290`（libavc SVC 解码器）、
   `ghostscript-type2-51089`。
2. **协议前置检查（当前管线实跑）**：mruby / 62290 / 38283 / 55020 **全部通过**（config 可加载、镜像存在、
   `_prepare_prebuilt_symcc_protocol` 成功、clean+symcc 二进制都能跑起来）；ghostscript **失败**
   （配置里没有 prebuilt symcc 二进制，旧配置走的是 build-style，而回滚后的 harness 已不支持 build-style）。
3. **镜像不能直接满足重测要求的三点**：
   - **SymCC 编译器是旧的**：所有搁置镜像建立在 `local/symcc-target-feedback:20260924-sitefix1` 之上，
     而修复版是 `local/symcc-target-feedback:20261007-idcache`（同为增量重建，只是 `compiler/Feedback.h` 更新 + `ninja`）。
     重测的 symcc 臂应重建，否则测的是旧编译器。
   - **没有 coverage 构建**：所有搁置配置都缺 `coverage_binary_path`，因此拿不到本会话新加的
     `coverage`/`focus` 反馈块（两个块是同一条路径，没有覆盖二进制就都没有）。要带反馈重测必须重建。
   - **细节陷阱**：55020 的 clean 二进制在正常输入上会报 `LeakSanitizer: 8 byte(s) leaked`（rc=1）。
     当前 harness 的 sanitizer 事件正则会把它当作事件 → 重测前要在镜像里固化 `ASAN_OPTIONS=detect_leaks=0`
     （用 wrapper 或 launcher，不改 harness）。
4. **历史数据里最有价值的新样本是 38283**：SymCC 臂 **195s** 拿到 3/3 可复现 PoC，OFF 臂 **445s**（≈2.3×），
   但 SymCC 提交因 `poc_kind=raw` 被拒、OFF validated。这正好补上 mruby 之外的一个独立目标证据。
   注意：`raw` 目前**不在** `_normalize_poc_kind()` 的归一集合里（集合含 `raw_file`/`raw_input`/`raw-binary`，
   但裸 `raw` 与 55020 的 `coff-aarch64-object` 这类描述性取值仍会被拒），重测前建议补（1 行 + 测试）。
5. 55020 的静态候选锚点有问题（见 §3.4）：候选指向 linker-time 函数，而 fuzzer 实际走到另一个函数。
   **不修静态报告，focus 反馈在 55020 上只会误导**。

---

## 1. 案例盘点

| ID | 漏洞类型 | ARVO 基础镜像 | 现成运行镜像 | 目标配置 | 静态报告 | 构建配方 | 历史结果 | 重测状态 |
|---|---|---|---|---|---|---|---|---|
| `mruby-57672` | GC 写屏障缺失 → UAF | `n132/arvo:57672-vul` | `local/mruby-arvo-prebuilt-symcc:2de602b-cov1`（含 coverage） | `targets/mruby-arvo/` | `results/experiments/mruby-async-paired-20260923/static_analysis.json`（10-08 最后使用版；版本对照见 [`experiment-records/2026-10-09-mruby-57672-static-report-versions.md`](experiment-records/2026-10-09-mruby-57672-static-report-versions.md)） | `targets/mruby-arvo/SymCC.Dockerfile` | 充分（含 validated PoC、配对统计） | ✅ 已重测 |
| `arvo-62290` | libavc H.264 SVC 解码器 | `n132/arvo:62290-vul` | symcc: `local/arvo-62290-site-feedback-nogit:20260924-nopie-retest`；off: `local/cybergym-arvo-62290-off:20260928` | `targets/arvo-62290-experiment/config.yaml`（+ results 内同源副本） | `results/experiments/symcc-target-site-feedback-20260924/shared/arvo-62290-static-report.json`（候选 `isvcd_ii_get_ref_mb_mode`） | `results/experiments/symcc-target-site-feedback-20260924/Dockerfile.62290`、`.../cybergym-symcc-followup-20260928/targets/arvo-62290/Dockerfile.off` | 有效配对：OFF `reached_no_crash`（2261s，候选函数被观察 612 次但无 ASan 事件）；SymCC 同样 `reached_no_crash` | ⚠️ 可跑，需重建 |
| `arvo-38283` | FreeRADIUS TACACS 解析越界 | `n132/arvo:38283-vul` | symcc: `local/cybergym-arvo-38283-symcc:20260929`；off: `local/cybergym-arvo-38283-off:20260929` | `results/experiments/cybergym-symcc-followup-20260928/targets/arvo-38283/config.yaml`（+`config.off.yaml`） | `.../arvo-38283/static_analysis.json`（候选 `fr_tacacs_decode`） | `.../arvo-38283/Dockerfile.symcc`（+ `fuzzer_file_driver.c`、wrapper 脚本） | 配对：SymCC **195.3s** vs OFF **444.6s** 出 3/3 PoC；SymCC `invalid_submission`(`poc_kind=raw`)，OFF `validated` | ⚠️ 可跑，需重建 |
| `arvo-55020` | binutils objdump COFF 重定位越界写 | `n132/arvo:55020-vul` | symcc: `local/cybergym-arvo-55020-symcc:20260929`；off: `local/cybergym-arvo-55020-off:20260929` | `.../targets/arvo-55020/config.yaml` | `targets/arvo-55020/static_analysis.json`（2026-10-09 起为**原始描述 + 描述点名的 reloc 函数锚点**；旧 `coff_pe_aarch64_relocate_section` 版本留档在 `results/experiments/symcc-retest-20261009/legacy-static-reports/`） | `.../arvo-55020/Dockerfile.symcc`（binutils 全量构建，~1h） | 配对：OFF ~162.5s、SymCC ~379.1s 各自构造出同栈 ASan 输入；两臂都 `invalid_submission`（poc_kind / machine-observable 证据缺失） | ⚠️ 可跑，需重建 |
| `ghostscript-type2-51089` | Ghostscript Type2 charstring 操作数栈 | `n132/arvo:51089-vul` | `local/ghostscript-type2-51089-autogen{,-fixed}:symcc`（**无 symcc 二进制**） | `targets/ghostscript-type2-51089/`、`-manual/` | — | 旧 `-manual` 走 build-style | 早期 OFF 549s `invalid`(`poc_kind=postscript`)；SymCC 1803s 超时；后续手工 OFF 225s validated | ❌ 缺 prebuilt symcc + 当前 harness 无 build-style |

---

## 2. 本次实测（2026-10-09）

### 2.1 config 加载 + 协议前置（干跑 `_prepare_prebuilt_symcc_protocol`）

方法：`TargetConfig.load()` → `docker run -d --entrypoint sleep <image>` → 调用 harness 的
`_prepare_prebuilt_symcc_protocol(container, target)`（只做目录准备、二进制存在性/可执行性检查、
符号链接与 guard 安装、README/runner 注入）→ `docker rm`。

| 目标 | config | 镜像 | 协议前置 | coverage 块 | 镜像内 LLVM 工具 |
|---|---|---|---|---|---|
| mruby-57672 | OK | OK | **ready** | ✅ `/out/mruby_fuzzer_cov` | `llvm-profdata-15` / `clang-15` |
| arvo-62290 | OK | OK | **ready** | ❌ 未配置 | `llvm-profdata-15` / `clang-15` |
| arvo-38283 | OK | OK | **ready** | ❌ 未配置 | `llvm-profdata-15` / `clang-15` |
| arvo-55020 | OK | OK | **ready** | ❌ 未配置 | `llvm-profdata-15` / `clang-15` |
| ghostscript-51089 | OK | OK | **FAIL**：`symbolic_execution.symcc.binary_path must be absolute`（配置里没有） | ❌ | `llvm-profdata-15` / `clang-15` |

### 2.2 双臂冒烟（镜像直接跑二进制，验证运行时可执行性）

| 目标 | clean 臂 | symcc 臂 | 备注 |
|---|---|---|---|
| arvo-38283 | rc=0（libFuzzer 跑完 1 个输入） | rc=0（打印 `This is SymCC running with the QSYM backend`） | wrapper 自带 `FR_LIBRARY_FUZZ_PROTOCOL` / `LD_LIBRARY_PATH=/out/symcc-libs`，可直接作为 `binary_path` |
| arvo-55020 | **rc=1，`LeakSanitizer: 8 byte(s) leaked`** | rc=0（/bin/ls 反汇编输出） | clean 需固化 `ASAN_OPTIONS=detect_leaks=0` |
| arvo-62290 | rc=0 | rc=0（跑完固定输入） | — |
| ghostscript | （未测） | 无 symcc 二进制 | 继续搁置 |

### 2.3 镜像清单（可清理参考）

| 系列 | 标签 | 大小 |
|---|---|---|
| symcc 编译器 | `local/symcc-target-feedback:{20260924,20260924-sitefix1,20261007-idcache}` | 3.83 / 3.87 / 3.90 GB |
| 62290 | `local/arvo-62290-site-feedback*`（8 个 tag）+ `local/cybergym-arvo-62290-off:20260928` | 3.95–4.38 GB |
| 38283 | `local/cybergym-arvo-38283-{common,off,symcc}:20260929`（+agent） | 5.49–5.83 GB |
| 55020 | `local/cybergym-arvo-55020-{common,off,symcc}:20260929`（+agent） | 7.53–8.39 GB |
| ghostscript | `local/ghostscript-type2-51089-autogen{,-fixed}:symcc`（+agent） | 5.14–5.44 GB |
| 基础镜像 | `n132/arvo:{38283,51089,55020,57672,62290}-vul` | 3.14–6.79 GB |

**2026-10-09 清理已执行**（`docker rmi` 38 个 tag，镜像数 76 → 48）。删除的是三个新目标的派生临时镜像：

- 62290：`local/arvo-62290-site-feedback*`（14 个 tag）、`local/arvo-62290-symcc:20260923`（+agent）、
  `local/cybergym-arvo-62290-off:20260928`（+agent）
- 38283：`local/arvo-38283-symcc:20261009-cov1`（+agent）、`local/cybergym-arvo-38283-{common,off}:20260929`
  （+agent；`symcc:20260929` 是当前 Dockerfile 的 `common` 基础，**保留**）
- 55020：`local/arvo-55020-symcc:20261009-cov1`、`local/cybergym-arvo-55020-{common,off}:20260929`（+agent；
  `symcc:20260929` **保留**）
- 工具镜像：`local/symcc-target-feedback:{20260924,20260924-sitefix1}`（现役是 `:20261007-idcache`）

保留（重测要用）：`local/arvo-38283-symcc:20261009-cov2`(+agent)、`local/arvo-55020-symcc:20261009-cov2`、
`local/arvo-62290-symcc:20261009-cov1`(+agent)、两个 `cybergym-arvo-*-symcc:20260929` 基底、
`local/symcc-target-feedback:20261007-idcache`、`n132/arvo:*-vul` 原始镜像。

笔记本其余章节与 `docs/research/*site-feedback*`、`experiment-records/*` 里出现的 `-off` / `site-feedback`
tag 是**历史记录**，不再是可用镜像指针；`targets/arvo-62290-experiment/config.yaml` 指向已删的
`local/arvo-62290-site-feedback-nogit:20260924-nopie-retest`，复用前需重建（另有 `feedback_map_path` 等回滚后失效字段）。

`docker system df` 显示镜像 unique 层 247GB → 240GB（删除镜像的大部分层仍被保留镜像共享），
另有 build cache 220.7GB（170.6GB reclaimable）——**未清理**，因为它是 cov2/agent 镜像秒级重建的前提；
如要释放，用 `docker builder prune --filter until=168h` 定向清旧缓存。

---

## 3. 重测需要的变化

### 3.1 通用（3 个可重测目标）

1. **换 SymCC 编译器基底**：`FROM local/symcc-target-feedback:20260924-sitefix1`
   → `FROM local/symcc-target-feedback:20261007-idcache`（等价于 09-24 版 + 修复后的 `compiler/Feedback.h`）。
2. **新增 coverage 构建 stage**：同一源码、同一 fuzzer 入口，用镜像自带 `clang-15` 加
   `-fprofile-instr-generate -fcoverage-mapping`（不带 ASAN），产出 `/out/<fuzzer>_cov`，
   最终镜像 `COPY` 进 `/out`；config 增加 `coverage_binary_path: /out/<fuzzer>_cov`。
   当前 harness 用 `_find_container_tool()` 自动发现 `llvm-profdata-15` / `llvm-cov-15` / `clang-15`，无需额外安装。
3. **config 清理**：`feedback_map_path`、`cpus`、`max_concurrent_jobs` 等 site-feedback 时代字段已被
   当前 harness 忽略（`feedback_map_path` 不再被任何代码引用），保留无害；`program_args` 仍是协议必需项。
4. **OFF 臂与 SymCC 臂共用同一镜像**（`--symbolic-execution off|symcc`），
   避免旧实验"off/ symcc 两个镜像"带来的图书馆差异；旧 `-off` 镜像可作回退。

### 3.2 arvo-38283（优先，构建最便宜）

- 复用 `Dockerfile.symcc`：`common` 阶段已有 FreeRADIUS 源码 + `fuzzer_file_driver.c` + wrapper；
  新增 `coverage-build` 阶段：`CC=/usr/bin/clang-15 CFLAGS="-O1 -g -fprofile-instr-generate -fcoverage-mapping"`，
  同样 `./configure --enable-fuzzer && make -j$(nproc) PROTOCOL=tacacs ./build/bin/local/fuzzer_tacacs`，
  产出 `/out/fuzzer_tacacs_cov`（可用同一 wrapper 逻辑跑）。
- 预期构建时间：分钟级。

### 3.3 arvo-62290

- 复用 `Dockerfile.62290`（clang-15 + cmake 构建 `svc_dec_fuzzer`，`-no-pie`）；
  新增 coverage 变体（去掉 ASAN，加覆盖标志）；symcc 变体换新编译器。
- 预期构建时间：分钟级。

### 3.4 arvo-55020（最贵，且要先修静态锚点）

- `Dockerfile.symcc` 的 `clean-build` 调 `/src/build.sh` 全量构建 binutils（`--enable-targets=all`），
  加 coverage 变体意味着**再跑一次同量级构建**（~1h/次，建议与 symcc 重建并行）。
- **静态报告锚点已重做（2026-10-09）**：原候选 `coff_pe_aarch64_relocate_section`（`bfd/coff-aarch64.c:498`）是 linker 路径，
  实际可达的是 `coff_aarch64_addr64_reloc`（`bfd/coff-aarch64.c:53`，objdump 走 `fuzz_objdump_safe`）。
  `targets/arvo-55020/static_analysis.json` 已换成 CyberGym 原始描述 + 描述点名的 6 个 reloc 函数锚点
  （`coff_aarch64_addr64_reloc` 排在首位），详见
  `results/experiments/symcc-retest-20261009/STATIC-REPORTS-COMPARISON.md` §9。
- clean 二进制需要 `detect_leaks=0`：新增 wrapper `/out/run-objdump-safe` 固化环境变量，
  或在 Dockerfile 里写一个 `ASAN_OPTIONS` 默认值（wrapper 更显式，且与 38283 的做法一致）。

### 3.5 ghostscript-51089（继续搁置）

- 当前 harness 只支持 prebuilt SymCC（`_prepare_prebuilt_symcc_protocol`），
  `symbolic_execution.build`（build-style）已随回滚消失；现成 `:symcc` 镜像里也没有 symcc 二进制。
- 若要恢复：需要为 `gstoraster_ps_fuzzer` 做一次 prebuilt SymCC 构建（Ghostscript 构建量大），
  且要复核老问题（`poc_kind=postscript` 已被 `_normalize_poc_kind` 覆盖）。
- 建议：本轮不做；仅当 38283/62290/55020 三个目标跑完后仍有预算再议。

---

## 4. 扩充后的实验矩阵

### 4.1 设计

- **目标**：38283（协议语法）、62290（解码器状态机）、55020（结构化二进制）；mruby 作为已完成对照。
- **臂**：`off` / `symcc`，**两臂同镜像同上限**（修复旧实验的镜像不一致 + 单边截断问题）。
- **反馈**：两臂都开 coverage+focus（重建镜像后），这样 OFF 臂也能看到"到没到目标函数"，
  把差异收敛到"SymCC 是否把输入送到目标点"这一个变量上。
- **上限**：3600s、无迭代/轮次上限（`--phase-timeout 3600`），顺序交替（symcc/off、off/symcc …）。
- **样本**：每目标先 2 次冒烟（各 1 次），再 3 组正式配对；总计 3 目标 × 6 次 ≈ 18 个相位小时。
- **指标**（与主报告 §1 口径一致）：
  1. 首次目标类崩溃时间（ASAN `ERROR:` + 候选函数/崩溃类型匹配，只认工具输出）；
  2. 1800s 窗口命中率、3600s 窗口命中率；
  3. 附带：首个到达目标函数的请求序号/时间、SymCC 求解占比、token/工具调用、validated 与否。

### 4.2 目标特异假设

| 目标 | 期望 SymCC 帮助的地方 | 风险/噪声 |
|---|---|---|
| 38283 | 协议长度/类型字段的约束求解（`Data=0xFF` 类输入）；历史 195s vs 445s | 旧提交把 `poc_kind=raw` 判无效（**该取值今日仍会被拒**，建议先补归一 + 测试），本轮应能拿到正式 validated |
| 62290 | 解码器状态深、历史两臂都 `reached_no_crash`；先问"能否找到"再问"谁快" | 8g 内存 + 视频解码耗时；coverage 二进制跑大输入慢 |
| 55020 | 结构化重定位字段；历史 OFF 反而更快（162s vs 379s） | 静态锚点偏 + LSan 噪声 + 构建成本最高，放最后 |

### 4.3 建议顺序

1. **38283**：重建（分钟级）→ 冒烟 → 3 组配对（最有历史参照，且能验证新提交契约）。
2. **62290**：重建 → 冒烟 → 3 组配对（回答"能不能找到"，可能需要放宽到 5400s）。
3. **55020**：先修静态报告 → 重建（~1h）→ 冒烟 → 3 组配对。

---

## 5. 待办

- [ ] 决策：是否把 `results/experiments/...` 里的 cybergym 目标配置**迁入 `targets/`**（成为一等目标，便于反复调用）。
- [ ] 扩展 `_normalize_poc_kind()`：把裸 `raw` 与"目标相关描述性 kind"（如 `coff-aarch64-object`）归一为 `file`
      ——历史上这类拒收造成 8 次 run 的"技术成功、提交无效"（主报告 §6），38283/55020 各中一次。
- [x] 重建 38283 / 62290 / 55020 三个镜像（新编译器 + coverage stage）：`…:20261009-cov2`（38283、55020，含
      wrapper 修复）与 `…:20261009-cov1`（62290）。
- [x] config 增加 `coverage_binary_path`；55020 增加 `detect_leaks=0` wrapper（另见 38283 flag-tolerant wrapper）。
- [x] 重做 55020 / 38283 / 62290 静态报告（改为 CyberGym 原始描述逐字，见 `results/experiments/symcc-retest-20261009/`）。
- [x] 38283 冒烟（`--max-turns 40`，Symbolic 链路 + coverage 正常，`focus: []`）；三目标配对重测命令已交付，待执行。
- [x] 清理三个目标的派生临时镜像（38 个 tag，见 §2.3 清理记录）。
- [ ] 三组配对重测实跑 → 结果并入主报告（新的 §1 式配对统计）。
