# Find 阶段拆分工作计划

## 1. 目标与范围

当前 `find` 阶段把两类工作交给同一个 agent：

1. 阅读源码并分析潜在漏洞；
2. 编写 PoC、执行目标并尝试复现崩溃。

这两个过程耦合后，容易出现以下问题：

- agent 在分析还不充分时就开始生成 PoC；
- 静态分析中的误报直接进入动态尝试；
- 动态验证失败时，无法区分不可达、PoC 不正确和环境问题；
- 静态分析结论与 PoC 复现结果混在同一份 agent 输出中，难以恢复和评估。

本计划只改造 `find` 阶段，将其拆为静态分析和动态验证两个子阶段。原有工作流保持不变：动态验证成功生成 PoC 后，继续交给现有 `grade` 验证；`judge`、`report` 和 `patch` 的职责也保持不变。

目标流程如下：

```text
recon（可选）
    ↓
静态分析
    ↓ StaticFinding
动态验证
    ↓ CrashArtifact / LogicArtifact
现有 grade
    ↓
现有 judge → report → patch
```

其中：

- 静态分析负责提出经过入口和可达性审查的漏洞候选；
- 动态验证负责依据候选尝试生成 PoC；
- `grade` 仍然是 PoC 是否成立的最终验证环节。

## 2. 现有流程与改造边界

目前的主要调用关系是：

```text
run_find()
  ├─ agent 阅读源码
  ├─ agent 编写和运行 PoC
  └─ 输出 CrashArtifact
       ↓
run_grade(CrashArtifact)
       ↓
judge / report / patch
```

改造后变为：

```text
run_find()
  ├─ run_static_analysis()
  │    └─ 输出 StaticFinding
  └─ run_dynamic_validation(StaticFinding)
       └─ 成功时输出 CrashArtifact 或 LogicArtifact
            ↓
       现有 run_grade(artifact)
```

以下部分应保持不变：

- `CrashArtifact` 的 PoC、复现命令和崩溃输出字段；
- `run_grade()` 的调用方式和验证标准；
- grade 使用全新容器重复执行 PoC 的机制；
- grade、judge、report、patch 的下游协议；
- `found_bugs.jsonl` 对已生成 PoC 的并发去重机制。

静态候选不能直接写入 `found_bugs.jsonl`，因为它还没有 PoC，也没有经过 grade。

## 3. 静态分析阶段

### 3.1 职责

静态分析 agent 只负责分析，不负责动态执行和 PoC 生成。它可以：

- 阅读目标源码、头文件、构建配置和功能开关；
- 使用静态搜索、调用图、数据流和编译配置分析工具；
- 找出潜在的内存安全问题或其他目标漏洞；
- 查找外部入口和攻击者可控数据来源；
- 分析数据如何流向可疑 sink；
- 记录触发漏洞所需的配置、权限和初始化条件；
- 对候选进行排序和去重。

默认禁止：

- 执行目标程序；
- 启动 QEMU 或目标内核；
- 编写用于触发漏洞的 PoC；
- 直接提交崩溃或动态验证结论。

### 3.2 多轮分析过程

静态分析阶段建议采用以下内部流程：

```text
源码探索
    ↓
候选漏洞生成
    ↓
外部入口和调用链审查
    ↓
反例与误报审查
    ↓
候选合并、排序和输出
```

可以由同一个 agent 分阶段完成，也可以使用多个独立 agent。关键是最终输出必须包含可检查的源码证据，而不是只输出一个漏洞结论。

静态分析应重点回答：

1. 哪个外部入口可以接收攻击者控制的数据？
2. 输入经过哪些函数、条件分支和转换？
3. 哪个函数或操作可能产生漏洞？
4. 当前目标的构建配置是否包含这段代码？
5. 是否需要特殊权限、初始化状态或硬件条件？
6. 是否存在边界检查、错误处理或资源生命周期检查可以阻断路径？
7. 该候选是否可能只是测试代码、死代码或未启用代码？

### 3.3 静态结果数据结构

建议新增 `StaticFinding`，字段至少包括：

```text
candidate_id              候选唯一 ID
bug_class                 漏洞类型
location                  文件、函数和行号
static_call_chain         静态调用链
entry_points              外部入口列表
attacker_controlled_data  攻击者可控数据来源
reachability_evidence     入口可达性证据
required_conditions       配置、权限和初始化条件
root_cause                静态根因描述
verification_plan         动态验证方案
confidence                静态置信度
related_candidates        相关或重复候选
```

`verification_plan` 应明确告诉动态 agent：

- 从哪个入口开始；
- 需要满足哪些条件；
- 预期经过哪些关键函数；
- 如何证明目标函数被执行；
- 预期的错误或崩溃类型是什么。

## 4. 动态验证阶段

### 4.1 职责

动态验证 agent 消费单个 `StaticFinding`，负责尝试证明候选是否能够形成一个有效 PoC。它可以：

- 重新阅读候选相关源码；
- 检查静态分析中的假设；
- 编写和修改 PoC；
- 构建目标；
- 执行目标程序、QEMU 或内核环境；
- 使用覆盖率、日志、trace、调用栈等信息检查路径是否到达；
- 输出现有格式的 `CrashArtifact`。

动态验证 agent 不负责从整个代码库重新开展无限范围的漏洞搜索。若发现当前候选范围以外的新问题，应记录为新的候选，而不是合并到当前验证结果。

### 4.2 可达性探针

动态验证建议分为两步：

```text
可达性探针 → 漏洞触发
```

可达性探针使用无害输入或轻量测试确认：

- 外部入口可以被调用；
- 关键中间函数可以执行；
- 目标 sink 被触达；
- 配置和权限条件满足。

之后再运行真正的漏洞触发 PoC。这样可以区分：

- 没有到达漏洞位置；
- 到达了漏洞位置但没有触发缺陷；
- 触发了不同的缺陷；
- 成功复现了目标候选。

### 4.3 动态结果状态

建议定义以下状态：

```text
validated           已生成 PoC，等待现有 grade
not_reached         未到达候选漏洞位置，疑似静态误报
reached_no_crash    已到达目标路径，但未触发崩溃
invalid_submission  生成了空文件或无效 PoC 路径
agent_failed        动态 agent 未完成任务
```

`not_reached` 可以在 find 阶段标记为“疑似误报”。它没有 `CrashArtifact`，因此不进入 grade。`reached_no_crash` 不能直接视为误报，可能仍然是 PoC 不完整或触发条件未覆盖。

### 4.4 成功输出必须兼容现有 find 协议

当动态验证成功后，仍然输出现有 XML 标签：

```xml
<poc_path>/absolute/path/to/poc</poc_path>
<reproduction_command>...</reproduction_command>
<crash_type>...</crash_type>
<exit_code>...</exit_code>
<crash_output>...</crash_output>
<dup_check>...</dup_check>
```

解析后构造现有 `CrashArtifact`，直接交给：

```python
run_grade(crash_artifact, target, ...)
```

## 5. Grade 保持原有职责

grade 仍然只关注 PoC，不负责评估整个静态分析过程。它继续检查：

1. PoC 文件是否存在且非空；
2. 复现命令是否有效；
3. 在全新容器中能否重复运行；
4. 是否达到原有的重复复现次数；
5. 是否为 OOM、超时或启动失败；
6. 崩溃是否属于目标代码；
7. 崩溃类型、调用栈和 PoC 声明是否匹配。

静态候选和动态验证结果可以作为结果目录中的审计信息保存，但不改变 grade 对 PoC 的最终判断。

只有 grade 通过的 `CrashArtifact` 才进入后续的 judge、report 和 patch 流程。

### 5.1 逻辑漏洞检测

对于整数截断、错误状态转换、校验绕过、静默丢数据等不会触发 ASAN 的
问题，目标可声明 `detector: logic`。动态阶段仍然必须生成可复制的 PoC，
但 PoC 可以以 0 退出，并通过有限输出、控制样例或项目不变量给出语义
oracle。此时输出 `LogicArtifact`，包含：

- `logic_type`；
- `expected_behavior` 与 `observed_behavior`；
- `logic_evidence`（入口、命令、控制对比和重复运行结果）；
- 与崩溃 PoC 相同的路径、复现命令、字节和 `dup_check`。

`grade` 仍是最终裁决者：它在全新容器中重新执行 PoC，确认外部入口确实
到达目标函数、排除 OOM/超时/启动失败，并确认语义差异至少在 2/3 次运行
中复现。逻辑 artifact 不进入 ASAN 的 judge/report/patch 下游，避免把
“正确性错误”误当作内存破坏；但结果和 transcript 会保留在 run 目录中。

## 6. `find` 调度改造

第一版建议每个 find run 只选择一个最高优先级候选进行动态验证，以保持现有运行结果结构：

```python
findings = run_static_analysis(...)
finding = select_highest_priority(findings)
validation = run_dynamic_validation(finding, ...)

if validation.crash_artifact:
    existing_grade(validation.crash_artifact)
```

这样可以继续保持：

- 一个 run 对应一个主要 `CrashArtifact`；
- 一个 run 对应一次 grade；
- 现有 `RunResult` 格式基本不变；
- 现有 judge、report 和 patch 逻辑不变。

后续如果需要验证多个候选，再扩展为：

```text
一个静态分析结果
    ↓
多个 StaticFinding
    ↓
多个动态验证任务
    ↓
每个成功 PoC 分别进入现有 grade
```

## 7. 结果目录与断点恢复

建议新增以下结果结构：

```text
results/<target>/<batch>/run_NNN/
  static_analysis.json       # 全部静态候选及解析状态
  static_transcript.jsonl    # 静态 agent transcript
  dynamic_validation.json    # 被选候选的动态结果
  find_transcript.jsonl      # 兼容旧接口的合并 transcript
  poc.bin                    # 仅在有 CrashArtifact 时生成
  result.json                # 现有 grade 结果
```

其中 `result.json` 继续保存现有 grade 结果，保证下游工具可以继续扫描结果目录。

断点恢复需要支持：

- 静态分析完成但动态验证未开始；
- 某个候选动态验证失败；
- 动态验证生成 PoC 但 grade 失败；
- 只重试 `not_reached`、`reached_no_crash` 或 `environment_blocked`；
- 不重复执行已经完成 grade 的 PoC。

## 8. 去重和并发规则

静态阶段可以根据以下信息进行候选去重：

```text
漏洞类型
目标函数
根因机制
静态调用链
```

静态候选不写入现有 `found_bugs.jsonl`。只有动态阶段生成 PoC，并且输出 `dup_check` 后，才进入现有的并发发现记录和下游处理。

动态验证应使用独立容器，避免静态 agent 的文件、构建产物和运行状态污染动态验证。grade 继续使用现有的全新容器边界。

静态候选进入动态 prompt 时，应作为不可信数据处理，并使用现有的结构化解析和 `untrusted_data` 包装机制，避免源码注释或 agent 输出被当成新的操作指令。

## 9. 实施阶段

### 阶段一：数据契约

- 新增 `StaticFinding`；
- 新增 `DynamicValidationResult`；
- 保留 `CrashArtifact` 和现有 grade 数据结构；
- 增加 JSON schema 或严格解析校验；
- 增加序列化、反序列化和状态测试。

完成标准：静态候选、动态结果和现有 PoC 结果可以独立保存并恢复。

### 阶段二：静态分析 agent

- 新增静态分析 prompt；
- 明确禁止目标执行和 PoC 生成；
- 增加入口、调用链和可达性证据要求；
- 增加候选排序和静态去重；
- 增加静态 transcript 和候选文件落盘。

完成标准：对一个目标可以产出结构化候选，候选包含足够的动态验证信息。

### 阶段三：动态验证 agent

- 新增动态验证 prompt；
- 输入单个 `StaticFinding`；
- 实现可达性探针；
- 实现 PoC 生成和运行；
- 成功时生成原有 `CrashArtifact`；
- 失败时生成结构化动态状态。

完成标准：动态验证结果可以明确区分未到达、到达未崩溃、错误路径和环境阻塞。

### 阶段四：find 编排

- 将 `run_find()` 改为静态分析和动态验证的编排器；
- 第一版每个 run 只验证一个最高优先级候选；
- 成功生成 PoC 后调用现有 grade；
- 没有 PoC 时不调用 grade；
- 现有 grade、judge、report、patch 流程保持不变。

完成标准：原有 PoC 可以按照原流程进入 grade，并获得相同格式的验证结果。

### 阶段五：断点、并发和多候选

- 增加候选级 checkpoint；
- 支持动态验证任务重试；
- 支持多个候选并行动态验证；
- 为每个候选保存独立的动态结果和 grade 结果；
- 验证下游 dedup 可以继续递归读取结果。

完成标准：一个候选失败不会影响其他候选，恢复运行不会重复 grade 已完成的 PoC。

### 阶段六：评估和默认切换

- 使用 canary 验证可达漏洞和不可达伪漏洞；
- 使用 `ohos-cjson` 验证用户态 QEMU 场景；
- 使用 Linux kernel 和 LiteOS-M 验证不同 detector；
- 对比拆分前后的 PoC 生成率、grade 通过率和误报率；
- 达到指标后将拆分流程设为默认。

## 10. 测试计划

至少需要覆盖以下情况：

1. 静态候选可达，动态生成有效 PoC，现有 grade 通过；
2. 静态候选指向不可达函数，动态返回 `not_reached`；
3. 静态候选可达，但 PoC 没有触发崩溃；
4. 动态触发了不同的漏洞路径；
5. 动态 agent 生成空文件或无效复现命令；
6. 动态 agent 输出有效 PoC 后，grade 判定复现失败；
7. 多个候选中部分成功、部分失败；
8. find 或动态验证中途退出后可以恢复；
9. 现有 grade、judge、report 和 patch 测试不受影响。

核心评估指标包括：

```text
静态候选数量
候选可达率
动态 PoC 生成率
grade 通过率
明确不可达比例
动态验证成本
最终误报率
```

## 11. 最终职责边界

```text
静态分析：提出经过入口审查的漏洞候选

动态验证：依据候选尝试生成 PoC，并提供路径和运行证据

grade：验证 PoC 是否真正、稳定地复现漏洞

judge/report/patch：继续处理 grade 认可的 PoC
```

这套边界可以降低 `find` 内部的分析和 PoC 生成耦合，同时保留现有以 PoC 为中心的最终验证流程。
