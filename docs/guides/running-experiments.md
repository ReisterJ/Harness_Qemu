# 实验手册（Running experiments）

这份文档面向**做对照实验的人**：目标目录要放什么、每个文件填什么、命令怎么写、
跑完怎么读结果、哪里最容易踩坑。命令都以仓库根目录为工作目录。

> 相关文档：目标编写细则 [`targets/README.md`](../../targets/README.md) ·
> 预构建 SymCC 目标 [`../research/prebuilt-symcc-dynamic-workflow.md`](../research/prebuilt-symcc-dynamic-workflow.md) ·
> agent 后端与 goal 审计 [`../architecture/agent-backends.md`](../architecture/agent-backends.md) ·
> 沙箱与 egress [`../architecture/security.md`](../architecture/security.md) ·
> 历次实验记录 [`../research/experiment-records/`](../research/experiment-records/)

---

## 0. 三分钟版

```sh
# 0) 一次性准备
.venv/bin/pip install -e .            # 若 .venv 还没有 CLI 入口
export VULN_PIPELINE_MODEL=deepseek/deepseek-flash

# 1) 目标目录：targets/<name>/{config.yaml, Dockerfile}（见 §2）
#    镜像不存在时下面第一条命令会自动 docker build

# 2) 静态报告（见 §3）。已有报告可跳过，直接用别处的 static_analysis.json
.venv/bin/python -m harness.cli static targets/<name> \
  --model "$VULN_PIPELINE_MODEL" --results-dir results/experiments/<wave>/static \
  --dangerously-no-sandbox
#   → 产出 results/experiments/<wave>/static/<name>/<ts>/static_analysis.json
#   按 §3.0 核四条（commit 对得上、函数名写对、无触发配方、指真根因），
#   然后按 §3.1 冻结到 wave 根并记 sha256 —— 两臂都用这一个文件

WAVE=results/experiments/<wave>
cp results/experiments/<wave>/static/<name>/<ts>/static_analysis.json "$WAVE/static_analysis.json"
sha256sum "$WAVE/static_analysis.json" | tee "$WAVE/static_analysis.sha256"
REPORT="$WAVE/static_analysis.json"

# 3) 一个 wave = 同一份报告 + 两个 arm，只切换 --symbolic-execution
for arm in off symcc; do
  .venv/bin/python -m harness.cli dynamic targets/<name> \
    --static-report "$REPORT" \
    --candidate-id candidate_001 \
    --model "$VULN_PIPELINE_MODEL" \
    --phase-timeout 3600 --symbolic-execution $arm --instrumentation off \
    --results-dir "$WAVE/$arm" \
    --dangerously-no-sandbox
done

# 4) 读结果（见 §5）
.venv/bin/python results/experiments/agent-behavior-audit/metrics.py \
  --wave results/experiments/<wave>
```

---

## 1. 环境准备

| 需要什么 | 怎么准备 | 说明 |
|---|---|---|
| Docker | 系统装好 | 每个 agent 一个容器；`--parallel` 时约 1 GB 内存/run |
| gVisor（可选） | `bash scripts/setup_sandbox.sh` | 走 `bin/vp-sandboxed` 时必需；`--dangerously-no-sandbox` 不走它 |
| Python 环境 | `python3 -m venv .venv && .venv/bin/pip install -e .` | 所有命令用 `.venv/bin/python` |
| opencode 凭据 | `ANTHROPIC_API_KEY` / `DEEPSEEK_API_KEY` / `OPENAI_API_KEY`… | 由 `harness/auth.py` 解析并转发进容器；egress 白名单按 provider 推导 |
| codex 凭据 | `VULN_PIPELINE_CODEX_AUTH_FILE="$HOME/.codex/auth.json"` 或 `OPENAI_API_KEY` | 见 §4.2 |
| 模型 | `--model` 或 `VULN_PIPELINE_MODEL` | opencode 例：`deepseek/deepseek-flash`；codex 例：`luna` |

**沙箱 vs 直接跑**：正式实验建议走沙箱（`bin/vp-sandboxed vuln-pipeline ...`），
前提是 egress 代理已按后端放行。opencode 后端默认只放行 `api.anthropic.com:443`；
**codex 后端需要 `chatgpt.com:443` 与 `api.openai.com:443`**：

```sh
VP_EGRESS_ALLOW="chatgpt.com:443,api.openai.com:443" bash scripts/setup_sandbox.sh
```

本机快速迭代可以用 `--dangerously-no-sandbox`（信任边界变成你自己的 shell）。

---

## 2. 目标目录 `targets/<name>/`

### 2.1 必需文件

| 文件 | 作用 |
|---|---|
| `config.yaml` | 目标元数据：镜像 tag、二进制路径、源码路径、符号执行配置（§2.2） |
| `Dockerfile` | 构建 ASan 目标镜像；`prebuilt` 模式（`docker-params.yaml`）则引用已存在的镜像 |
| 其他构建上下文 | Dockerfile 会 COPY 的源码/脚本，例如 `entry.c`、`fuzzer_file_driver.c` |

镜像**不需要手工构建**：`dynamic` / `static` 在镜像不存在时会自己 `docker build`；
只有想强制重建时才走 `run`（它 `rebuild=True`）。手工等价命令是
`docker build -t <image_tag> targets/<name>`。

镜像里必须满足（agent 要在里面干活）：

* `{binary_path}` 存在且可执行，接受**一个输入文件参数**，检测到内存错误时 ASAN abort；
* `{source_root}` 是 agent 要读的源码树；
* 有 `gcc/python3/xxd/file/gdb`（agent 造输入要用）、`/bin/bash` 可用。

### 2.2 `config.yaml` 字段

必需（缺一个 loader 就报错）：

```yaml
image_tag: local/<name>:latest     # 构建/运行用的 docker tag
github_url: https://github.com/... # 进 prompt，让 agent 知道项目背景
commit: <full-sha>                 # 固定被测版本；symcc.commit 要和它一致
binary_path: /out/<binary>         # 容器内路径（clean/ASan 二进制）
source_root: /src/<project>        # 容器内源码路径
```

实验常用的可选字段：

| 字段 | 何时需要 | 说明 |
|---|---|---|
| `detector` | 非 ASan 目标 | `asan`（默认）/`logic`/`kasan`/`lms`/`qemu-asan` |
| `symbolic_execution` | 跑 SymCC 臂 | 见下 |
| `coverage_binary_path` | 要看覆盖率反馈 | 同一源码/commit 的覆盖率构建（无 ASan） |
| `coverage_objects` | 目标是共享库 | 让 lcov 把插桩过的 `.so` 也算进去 |
| `memory_limit` | 目标吃内存 | `docker --memory`，默认 `4g` |
| `agent_network` | 容器访问不了 API | 例如 `host`（本机有回环代理时用） |
| `build_command` / `test_command` | 要跑 `patch` | T0 重建 / T2 回归；`test_command` 缺省则跳过 T2 |
| `attack_surface` | 想让报告更聚焦 | 渲染进 prompt；**不要写触发配方** |
| `focus_areas` / `known_bugs` | 多 run / 防重复 | `known_bugs` 按**函数名**写，不要只写行号 |

SymCC 臂的最小配置（两臂唯一区别就是命令行里的 `--symbolic-execution`）：

```yaml
symbolic_execution:
  default: off            # 默认关闭；实验时显式 --symbolic-execution symcc
  providers: [symcc]
  symcc:
    binary_path: /out/<binary>-symcc   # 预构建的 SymCC 插桩二进制
    commit: <same-sha-as-above>        # 与目标 commit 一致，否则拒绝
    # program_args: ["{input_file}"]   # 仅当 SymCC 二进制需要不同参数时写
```

`binary_path` 与 `symcc.binary_path` 必须是**两个不同**的可执行文件；harness
不编译它们，只校验存在性与 commit。

### 2.3 目标自检（跑大实验前必做）

先给目标产出一份报告，再用它跑一次短时限的动态阶段（用 canary 最省时）：

```sh
# 1) 静态阶段 → results/smoke/canary/<ts>/static_analysis.json
.venv/bin/python -m harness.cli static targets/canary \
  --model "$VULN_PIPELINE_MODEL" --results-dir results/smoke --dangerously-no-sandbox

# 2) 用刚产出的报告跑一次短动态阶段（把 <ts> 换成实际目录名）
.venv/bin/python -m harness.cli dynamic targets/canary \
  --static-report results/smoke/canary/<ts>/static_analysis.json \
  --model "$VULN_PIPELINE_MODEL" --phase-timeout 900 \
  --results-dir /tmp/smoke --dangerously-no-sandbox
```

跑通 = 镜像能起、报告能被解析、agent 能在容器里读到源码并执行目标。
canary 有三个预置 bug，正常情况下短时限内就能命中一个——若连它都跑不出东西，
先查 §6 的坑再上大实验。

---

## 3. 静态报告 `static_analysis.json`

报告是动态阶段**唯一的先验输入**——两臂共用同一份文件，必须在开跑前就位。
它同时决定两件事：agent 从哪里入手（报告文本进 prompt），以及**反馈锚在哪**
（`coverage.focus` 只认函数名，见 §3.4）。

### 3.0 合格线（四条，逐条核）

| # | 要求 | 不满足会怎样 |
|---|---|---|
| 1 | **`commit` 与目标 `config.yaml` 的 `commit` 一致** | CLI 直接拒绝：`static report commit does not match target`（代码里唯一的硬校验之一） |
| 2 | **`target_function` 写对**（写源码里的真函数名），`target_file` 顺手写上；只有需要额外检查点时才用 `observability_targets` | 反馈变 `status: "unmatched"` + `not present in the coverage mapping (inlined, renamed, or wrong name)`，等于没有反馈 |
| 3 | **两臂共用同一份文件**，记录 sha256；报告里不得含触发配方、条件顺序、PoC 伪代码 | 等于给某一臂额外提示，结论作废 |
| 4 | 报告指向**真根因**（人工判断） | 错锚点 + 恒命中反馈会把带反馈的臂带偏（审计 §4.3 的"71 轮同一假设"），该组不能用于快慢结论 |

**解析器是宽容的，别把宽容当合规**：除 `candidate_id` 外字段缺失都不报错（实测
`from_dict({"candidate_id":"c"})` 返回 `location="unknown"`、`confidence=0`）。
所以第 2 条不会被任何报错提醒——它只在**反馈内容**里露出来：匹配不到时反馈里会多一条
`reported_file`，方便从反馈反查报告写没写对（写对函数名、文件写错不影响匹配）。

### 3.1 冻结流程（推荐做法）

第一次给某目标做出报告后，就把它**冻结**下来，之后所有 run（两臂、重复跑、换后端）
都指同一个文件：

```sh
WAVE=results/experiments/<wave>
mkdir -p "$WAVE"
cp <static 产出>/static_analysis.json "$WAVE/static_analysis.json"
sha256sum "$WAVE/static_analysis.json" | tee "$WAVE/static_analysis.sha256"
# 之后：--static-report "$WAVE/static_analysis.json"（写进 comparison.md 便于复算）
```

好处：commit 天然一致、两臂公平性天然满足、后续实验引用同一先验，不会被 agent
每次重新生成报告引入方差。每次 run 目录里也会自动存一份报告副本（`static_analysis.json`），
回看时以它为准。

### 3.2 顶层结构（字段说明）

```json
{
  "phase": "static_analysis",
  "status": "candidates_found",
  "candidate_count": 1,
  "selected_candidate_id": "candidate_001",
  "repository": "https://github.com/...",
  "commit": "<full-sha>",
  "findings": [ { ... 见 §3.3 ... } ]
}
```

`dynamic` 只读 `findings`：不传 `--candidate-id` 时取 `confidence` 最高的那条。

### 3.3 `findings[]` 每条填什么

| 字段 | 建议 | 填什么 | 注意 |
|---|---|---|---|
| `candidate_id` | ✅ | 稳定标识，如 `candidate_001` | 会用在迭代记录文件名里 |
| `bug_class` | ✅ | 崩溃类别，如 `heap-use-after-free` | 不知道写 `unknown` |
| `target_function` | ✅✅ | **源码里的真函数名**，如 `mrb_env_unshare` | 反馈锚只用它（见 §3.5）；写错等于没反馈 |
| `target_file` | ✅ | 该函数所在文件，如 `src/vm.c` | 只做展示与排错；匹配只看函数名 |
| `location` | ⭕ | 人读的位置描述 | 新报告不必再往里塞函数名（兼容旧报告时才解析） |
| `root_cause` | ✅ | 一两句机制描述 | 越具体越省 agent 时间；但别写成"补丁说明" |
| `verification_plan` | ✅ | 怎么验证（入口、观测什么） | 例：用 fuzz 入口构造输入并在 clean ASan 上复现 |
| `confidence` | ✅ | 0–1 的小数 | 只影响默认选哪条 |
| `static_call_chain` | ⭕ | 入口 → sink 的调用链 | 缺省空串；不参与反馈锚 |
| `entry_points` | ⭕ | 外部可达入口 | 同上 |
| `attacker_controlled_data` | ⭕ | 哪些字节可控 | |
| `reachability_evidence` | ⭕ | 静态可达性证据 | 没证据就写"未建立，需动态验证" |
| `required_conditions` | ⭕ | 触发前置条件 | ⚠️ 写太细 = 给答案，实验里慎用 |
| `observability_targets` | ⭕ | 额外检查点（函数/位点列表） | 优先级最高，只用在你确实要盯多个位点时 |
| `related_candidates` | ⭕ | 相关候选 id 列表 | 缺省空 |

*解析器是宽容的*（实测 `from_dict({"candidate_id":"c"})` 不报错）：除 `candidate_id` 外缺失字段
退化成空串/`0`/`unknown`，不会让整轮失败；但字段越空，agent 越难命中，反馈也越可能无效
（见 §3.5）。

**报告质量是实验结论的前提**：如果报告点错根因，带反馈的臂会被"恒命中锚点"带偏
（详见 [`../research/experiment-audits/AUDIT-REPORT.md`](../research/experiment-audits/AUDIT-REPORT.md) §4.3）——
错锚点 + `hits` 恒为 1 ⇒ 同一个假设被复写 71 轮。做快慢结论前先按"报告是否指向真根因"筛掉坏组。

### 3.4 报告从哪来

* **跑 pipeline 生成**：`vuln-pipeline static targets/<name> --model <m> --results-dir <dir>`
  → 产出 `<dir>/<target>/<ts>/static_analysis.json`（`<dir>` 是该命令的 `--results-dir`），
  然后按 §3.1 冻结到 wave；
* **外部导入**：把已有线索（CVE 描述、CyberGym 任务描述、你自己读源码得到的函数名）
  整理成 §3.2/§3.3 的结构——**在 `target_function`/`target_file` 里写出真函数名**。
  `targets/arvo-38283/static_analysis.json` 是最好的样例：主锚点是 `target_function`，
  额外的协议入口用 `observability_targets` 表达（一个候选要盯多个位点时才需要）；
* **复用旧波次**：只要**同目标同 commit**，直接指旧波的报告（现在 mruby 那几波都在复用
  `results/experiments/mruby-async-paired-20260923/static_analysis.json`，`commit=2de602b8…`）。

### 3.5 反馈锚是怎么定的（决定"反馈有没有用"）

反馈块 `coverage.focus` 的目标函数按**三层优先级**取（`harness/dynamic_validation.py:
_candidate_focus_functions`）：

1. **`observability_targets[].function`** —— 非空就只用它，后面两层被忽略；
2. **`target_function`**（配 `target_file` 一起带上）—— 报告显式写明的目标函数；
3. 否则从 **`location`** 这段自由文本里按三条正则抓函数名：
   `X in <file.ext>` / `function X` / `X(`；最多取 4 个。

第 3 层只留给旧报告：`location` 是散文（实测 235 条 finding 里 62 条抓不出函数名，
例如 `'entry.c:21'`、`'FreeRADIUS protocol decoding code'`），新报告请用第 2 层。
第 2 层只在**能过函数名合法性检查**时才生效，写坏了（`"parse chunk()"`）会自动落到第 3 层，
不会把可用的锚点一起丢掉。命中的函数名最多取 4 个（`_COVERAGE_MAX_FOCUS`）。

**`static_call_chain` 完全不参与**——它只作为 prompt 文本给 agent 看，不影响反馈。

两个实测例子：

| 报告 | 派生的 focus |
|---|---|
| `target_function='mrb_env_unshare'`、`target_file='gc.c'` | `{"name": "mrb_env_unshare", "file": "gc.c"}` → 反馈里 `status:"hit"`，`file`/`line` 由覆盖率构建补全（实为 `/src/mruby/src/vm.c:376`；**报告里写 `gc.c` 不影响匹配**，因为只按函数名匹配） |
| `location='mrb_env_unshare in gc.c'`（旧报告，无 target_function） | 同样 `{"name": "mrb_env_unshare"}`——第 3 层兜底 |
| `observability_targets=[{function:"fr_base16_decode_nstd",…},{function:"fr_tacacs_decode",…}]` | 两个函数都成为检查点 |

匹配规则是「符号名 `==` 目标名，或以 `:目标名` 结尾」，匹配不到就返回
`status:"unmatched"`。**这就是为什么 §3.0 第 2 条要单独核**：报告能跑通不代表反馈有用。

---

## 4. 跑一个 wave（对照实验）

### 4.1 目录布局约定

```text
results/experiments/<wave>/
├── static_analysis.json     # 两臂共用的报告（见 §3.1 冻结流程）
├── static_analysis.sha256   # 它的哈希（写进 comparison.md，便于复算）
├── off/                     # 对照组输出（--results-dir .../<wave>/off）
│   └── <target>/dynamic-<UTC ts>/
├── symcc/                   # 实验组输出
│   └── <target>/dynamic-<UTC ts>/
├── comparison.md            # 人写的结论（两臂数字、口径、异常说明）
└── target/                  # （可选）本波用的 config.yaml / docker-params.yaml 快照
```

### 4.2 两个 arm 的命令

```sh
# 对照组（无求解器）
.venv/bin/python -m harness.cli dynamic targets/<name> \
  --static-report results/experiments/<wave>/static_analysis.json \
  --candidate-id candidate_001 --model "$VULN_PIPELINE_MODEL" \
  --phase-timeout 3600 --max-iterations 8 \
  --instrumentation off --symbolic-execution off \
  --results-dir results/experiments/<wave>/off --dangerously-no-sandbox

# 实验组（SymCC）。除 --symbolic-execution 外，其他参数必须逐字相同
.venv/bin/python -m harness.cli dynamic targets/<name> \
  --static-report results/experiments/<wave>/static_analysis.json \
  --candidate-id candidate_001 --model "$VULN_PIPELINE_MODEL" \
  --phase-timeout 3600 --max-iterations 8 \
  --instrumentation off --symbolic-execution symcc \
  --results-dir results/experiments/<wave>/symcc --dangerously-no-sandbox
```

参数速查：

| 参数 | 作用 | 实验建议 |
|---|---|---|
| `--phase-timeout` | 动态阶段总时限（秒）。缺省 = 无总时限（看门狗仍会掐无界 helper） | 明确写死，两臂一致；写进提示词的就是这个值 |
| `--max-iterations` | 迭代轮数上限。缺省 = 不限 | 写死并记录 |
| `--max-turns` | agent 步数上限。缺省 = 不设 | 一般不设；设了要两臂一致 |
| `--instrumentation` | 观测 provider（`off`/`auto`/`llvm`） | 做 SymCC 对照时用 `off` |
| `--symbolic-execution` | `off`/`auto`/`klee`/`symcc` | **唯一允许变化的变量** |
| `--results-dir` | 输出根 | 按 §4.1 分臂 |
| `--dangerously-no-sandbox` | 不走 gVisor | 正式实验请用 `bin/vp-sandboxed` |

**codex 后端**（只换环境变量，其他不变）：

```sh
export VULN_PIPELINE_AGENT_BACKEND=codex
export VULN_PIPELINE_CODEX_MODEL=luna
export VULN_PIPELINE_CODEX_AUTH_FILE="$HOME/.codex/auth.json"
# 可选：VULN_PIPELINE_CODEX_REASONING=high|xhigh
```

### 4.3 多个 run / 并行

* `vuln-pipeline run <target> --runs N --parallel --stream`：find+grade 全流程，适合
  "N 次独立尝试"的统计（可用 `--auto-focus` 让 recon 先分区）；
* **`dynamic` 单臂不要并行**：容器名按目标固定（`dynamic_<target>_standalone`），
  并行会互相撞；要并行就顺序跑，或用 `run --runs N --parallel`（它给每个 run 单独开容器）。

### 4.4 公平性清单（每次实验照着核一遍）

- [ ] 报告过了 §3.0 的四条合格线（尤其：函数名写对、`commit` 与目标一致）；
- [ ] 两臂：同一镜像、同一 commit、**同一份报告文件**（sha256 记进 `comparison.md`）、
      同一模型、同样的 `--phase-timeout/--max-iterations/--max-turns`；
- [ ] 唯一变量 = `--symbolic-execution`（或你本波要测的那一个开关）；
- [ ] 报告不含触发配方/条件顺序/PoC 伪代码；
- [ ] 目标目录里的 `config.yaml` 快照存进 wave（便于复现）；
- [ ] 记录异常（看门狗击杀、契约拒收、相位截断）——它们不是"没找到"。

---

## 5. 产物怎么读

### 5.1 每个 run 目录里有什么

| 文件 | 内容 |
|---|---|
| `dynamic_validation.json` | 阶段结论：`result.status`（`validated`/`reached_no_crash`/`invalid_submission`/`agent_blocked`…）、`result.crash`、`result.iterations`、`timings`、`result.goal`（codex） |
| `dynamic_transcript.jsonl` | 逐事件流（`text` / `tool_use`，含 `state.input.command` 与 `state.output`） |
| `iterations/round-NNN.json` | agent 自述的每轮假设/观测/决策 |
| `static_analysis.json` | 本 run 实际用的报告副本（回看用） |
| `symbolic_execution/summary.json` | 协议请求、生成/回放的 testcase 数、SymCC 用时（有协议时） |
| `crash-result.xml` | 提交的 PoC 交付物（成功时） |
| `grade_*/` | 若跑了 grade 阶段 |

### 5.2 判定口径（避免自己骗自己）

1. **命中** = 真 ASan 头 `==<pid>==ERROR: AddressSanitizer: <type>`，**且崩溃类型符合目标契约**
   （例如 mruby 要 `heap-use-after-free`，62290 要 `negative-size-param`）；
   - 排除：模板文本回显、prompt 回显、agent 自建探针自己打印的 ASan（例：OFF 臂用
     `LD_PRELOAD` 实验打出的 SEGV）；
2. **命中时刻**取"**首次产出崩溃的那条执行命令**"的时刻。
   ⚠️ 别用"ASan 文本进入 transcript"的时刻：协议响应会被 offload 到文件、agent 再读回，
   短程实验会凭空多出 5–11 秒（anchor g3 实测两臂其实同秒命中）；
3. **`ratio = T_off / T_symcc`**，>1 表示实验组更快；只在**两臂都命中**时才算快慢；
4. 跑不出 `crash-result.xml` 但有可复现候选，是"未完成闭环"，不是"没找到"——分开统计。

### 5.3 一行汇总

```sh
.venv/bin/python - <<'PY'
import json, glob
for f in sorted(glob.glob("results/experiments/<wave>/*/*/dynamic-*/dynamic_validation.json")):
    j = json.load(open(f)); r, t = j["result"], j.get("timings", {})
    g = r.get("goal") or {}
    print(f"{f.split('/')[3]:6} | {r['status']:18} | {round(t.get('dynamic_validation', 0)):5}s | "
          f"calls={int(t.get('dynamic_agent_tool_calls', 0)):3} | goal={g.get('status','-')}")
PY
```

### 5.4 仓库里现成的分析工具

| 工具 | 用途 |
|---|---|
| `results/experiments/agent-behavior-audit/metrics.py` | 单 run 行为指标（协议请求、直跑次数、命中时刻…）；`--wave <dir>` 扫整波。注意：它取的是 transcript 时间戳，短程实验请按 §5.2 第 2 条换算 |
| `.../notebook.py` | 把一条 transcript 变成"命令 + 关键输出"的可读日志（`--grep` 过滤）——深挖首选 |
| `.../deep_metrics.py` / `pairs2.py` | 并入配对表、生成 `tables/pairs2.csv`（ratio 口径） |
| `.../collect_logs.py` | 把多波日志硬链接汇总到一处（零额外磁盘占用） |

---

## 6. 常见坑

| 症状 | 原因 / 处理 |
|---|---|
| `agent/helper_blocked: unbounded helper process exceeded 120s` | 前台跑了长命令/服务；用 `timeout Ns ...` 包住并装 cleanup trap；看门狗会把裸 python/ruby/node 命令当服务 |
| `unsupported poc_kind: <你编的词>` | 交付契约只认枚举值（`file` 等），从模板抄 |
| `poc_path must appear verbatim in reproduction_command` | 重现命令里必须逐字出现 PoC 路径；协议臂写 `run-input <request.json>` 会踩 |
| 两臂结果"差 11 秒" | 多半是管道延迟，不是真的更快；见 §5.2 第 2 条 |
| `static report commit does not match target` | 报告 `commit` 与 `config.yaml` 不一致（换过目标版本/复用了别的波次的报告）→ 重做或改用同 commit 的报告 |
| 反馈里 `status:"unmatched"` + `not present in the coverage mapping` | 报告里的函数名与覆盖率符号不一致（拼错、被内联、写的是宏）→ 按 §3.5 检查 `target_function`（旧报告看 `location`/`observability_targets`）；反馈里会附 `reported_file` 便于反查 |
| 报告点错根因 → 两边都很慢、`hits` 恒为 1 | 这组实验作废（不是"SymCC 慢"的证据），先修报告（§3.0 第 4 条） |
| 容器起不来 / API 不通 | egress 白名单没放行（§1）；codex 需要 `chatgpt.com` |
| 同一目标并行 `dynamic` 互相干扰 | 容器名固定；顺序跑或改用 `run --runs N --parallel` |
| 阶段被截断（`agent/model_blocked: phase exceeded Ns`） | 到时限了；这是"未完成"不是"没找到"，统计时单列 |

---

## 7. 一次实验的最小交付物

1. `results/experiments/<wave>/static_analysis.json` + `static_analysis.sha256`
   （报告是共同先验，必须可复算；哪些字段、怎么算合格见 §3）
2. `results/experiments/<wave>/{off,symcc}/<target>/dynamic-*/` 两臂全部产物
   （每个 run 目录里都自动带一份当次使用的报告副本，回看以它为准）
3. `results/experiments/<wave>/comparison.md`：两臂命令逐字、参数、报告 sha256、结果表、
   口径说明、异常与剔除理由
4. 若结论要长期引用：在 [`../research/experiment-records/`](../research/experiment-records/)
   留一份记录（格式参考该目录既有文件）
