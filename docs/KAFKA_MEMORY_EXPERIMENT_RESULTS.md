# Kafka 记忆实验 — 观测结果（Java 靶标，第二轮）

> 日期: 2026-09-02
> 靶标: Apache Kafka **4.4.0-rc0**（kafka-clients，纯 Java）
> 模型: `deepseek/deepseek-v4-flash`
> 提示词: **新版本**（禁 fuzz + INDEX-FIRST 索引优先工作流）
> 设计: 组 A（无记忆） vs 组 B（函数摘要记忆），各 3 runs × 100 turns

## 1. 实验设置

| 组 | 记忆 | 检测 |
|---|---|---|
| A | 关闭 | JVM 紧堆检测（`-Xmx512m -XX:MaxDirectMemorySize=256m -XX:+ExitOnOutOfMemoryError -ea`）|
| B | `--memory`（函数摘要 + prior 传导） | 同上 |

- **入口**：`/work/run_harness.sh <file>` → Harness 把输入字节喂给 `MemoryRecords.readableRecords(...).batches()`（RecordBatch 解析）
- **Java "崩溃"定义**：未捕获的内存类异常（OOM/StackOverflow/ByteBuffer 越界/数组越界）→ `ExitOnOutOfMemoryError` 使 JVM 非零退出
- **优雅拒绝**（SchemaException/IllegalArgumentException/CorruptRecordException）= 正确行为，不算 bug

## 2. 结果总览

| run | A（无记忆） | B（有记忆） |
|---|---|---|
| run_000 | ✅ crash_found `OutOfMemoryError` (229s) | ✅ crash_found `OutOfMemoryError` (225s) |
| run_001 | ❌ crash_rejected `NegativeArraySizeException` (288s) | ✅ crash_found `IndexOutOfBoundsException` (656s) |
| run_002 | ✅ crash_found `OutOfMemoryError` (212s) | ✅ crash_found `OutOfMemoryError` (532s) |
| **命中率** | **2/3** | **3/3** |
| **崩溃类型** | OOM ×2 | OOM ×2 + **IndexOutOfBounds**（更广） |
| find 时长均值 | 243s | 471s（+94%，更深入） |

## 3. 记忆传导（核心观测）

### 3.1 记忆产出（B 组）

| run | MEMORY.md 条目 | 覆盖层 |
|---|---|---|
| run_000 | 5 条（CONFIRMED 1 + EXPLORED 4） | record 层（DefaultRecordBatch/ByteBufferLogInputStream/DefaultRecord） |
| run_001 | 10 条（全部 EXPLORED） | **protocol 层**（ByteBufferAccessor/Type/ArrayOf/CompactArrayOf）|
| run_002 | 4 条（CONFIRMED 1） | utils/record 深化（ByteUtils/AbstractLegacyRecordBatch） |

### 3.2 传导的两个阶段

- **run_000 → run_001（断裂）**：run_000 用 `File.java | func`（管道分隔）而非 `:func`，旧解析器不识别 → ledger 空 → run_001 拿不到 prior。**已修复**（解析器支持两种分隔符，规范化 func）。
- **run_001 → run_002（成功）**：run_002 拿到 run_001 的 11 条 prior 后：
  - 记忆里显式标记 **"dup, 不提交"**（`DefaultRecord.readFrom` 已知 bug）→ **避免重复提交**（索引核心价值）
  - 深入 `AbstractLegacyRecordBatch.DataLogInputStream` 的无上限 allocate 并 **CONFIRMED**（新发现）

### 3.3 记忆内容质量（Java 版）

run_000 的 `DefaultRecordBatch.java:iterator` 条目是教科书级：
> 安全关注: `new ArrayList<>(count())` at line 332 — count is input-controlled, NO upper-bound validation before allocation.
> 已验证: 71-byte magic-v2 batch, recordsCount=0x7FFFFFFF → OOM at ArrayList.<init> <- DefaultRecordBatch.iterator:332. 3/3, exit=3.
> 可疑点: CONFIRMED OOM. count used as ArrayList initial capacity without cap.

## 4. Agent 行为对比（新提示词下）

| 源码分析强度（cat源码+grep源码+read工具） | A 均值 | B 均值 |
|---|---|---|
| run_000 | 22 | 10 |
| run_001 | 34 | **76**（深入 protocol 层）|
| run_002 | 21 | 26 |
| **均值** | **25.7** | **37.3（+45%）** |

- **A 组**倾向黑盒（构造输入 → 跑 harness），源码阅读少；run_001 甚至在容器里花 11 个 bash 调用找 JDK（`which java`、`apt-get install openjdk`——不知道 JDK 已装于 `/opt/java/openjdk`）
- **B 组** run_001 源码分析最强（cat 17 + grep 26 + read 33），对应更广的 protocol 层探索

## 5. 假设验证（新提示词下）

| 假设 | 结论 | 证据 |
|---|---|---|
| 禁 fuzz 生效 | ✅ | 两组均无 fuzzer/无 fuzzing 循环，agent 用结构化输入构造验证 |
| 索引优先工作流 | ✅ | B 组 agent 用记忆标记 dup/不提交，避免重复探索已知 bug |
| 记忆提升挖掘稳定性 | ✅（弱） | B 3/3 命中 vs A 2/3；B 崩溃类型更多样 |
| 记忆提升源码分析深度 | ✅ | B 源码接触 +45%（37.3 vs 25.7）|
| 记忆代价（时长） | ⚠️ | B 更慢（471s vs 243s）——更深入分析的开销 |

## 6. 发现的真实 bug 类（附带成果）

1. `DefaultRecordBatch.iterator`（line 332）：压缩批次路径 `new ArrayList<>(count())`，count 为输入可控且无上限 → OOM（A/B 两组都找到）
2. `DefaultRecord.readFrom`（line 286）：`ByteBuffer.allocate(sizeOfBodyInBytes)` 无防护（InputStream 路径）→ OOM
3. `AbstractLegacyRecordBatch.DataLogInputStream`：无上限 allocate → OOM（B run_002 CONFIRMED）
4. `CompactArrayOf.read` → `NegativeArraySizeException`（A run_001 提出，被 grader 拒绝——需确认是否优雅拒绝）

> 注：这些多为"输入可控分配 → OOM"类（DoS 型）。对 Java 无 ASAN 的检测语境，这是主要的内存错误形态。真实世界影响需结合调用方是否限制输入大小判断。

## 7. 关键教训（已修复）

1. **记忆解析器需宽容格式**：agent 对 `File:func` 分隔符理解不统一（`:` vs ` | ` vs 空格）→ `_ENTRY_RE` 已支持多种分隔符 + func 规范化
2. **文件扩展名**：`_ENTRY_RE` 原只匹配 `.c/.h`，`.java` 解析不了 → 已支持 `.java`
3. **JVM prompt 需指明 JDK 位置**：agent 浪费 turns 找 java → prompt 已明确 `/opt/java/openjdk` 已装 + 强调用 cat 读源码
4. **观测器**：Kafka agent 用 ls/find/grep 探索，`_extract_cat_paths` 提不到源码读取 → 已加 Kafka region 规则，但 ls/find 类探索仍难统计（行为对比用独立脚本）

## 8. 局限

1. 样本小（3 runs/组），B run_001 的突出表现（76 次源码接触）可能有随机性成分
2. run_000→run_001 传导因解析 bug 断裂，等于 B 组只享受了"半程传导"——若全通，差异可能更大（或更小）
3. crash 多为同源（OOM 分配路径），类型多样性有限
4. 观测器对 Java 的源码读取统计不完整（ls/find 探索方式）

## 9. 复现

```bash
# 组 A（无记忆）
VULN_PIPELINE_DOCKER_BUILD_NETWORK=host .venv/bin/vuln-pipeline run targets/kafka-exp-a \
  --dangerously-no-sandbox --model deepseek/deepseek-v4-flash --max-turns 100 --runs 3 \
  --results-dir results/kafka/exp-A

# 组 B（有记忆）
VULN_PIPELINE_DOCKER_BUILD_NETWORK=host .venv/bin/vuln-pipeline run targets/kafka-exp-b \
  --dangerously-no-sandbox --model deepseek/deepseek-v4-flash --max-turns 100 --runs 3 --memory \
  --results-dir results/kafka/exp-B

# 行为对比
python3 tools/compare_behavior.py results/kafka/exp-A/kafka-exp-a/<ts>/ results/kafka/exp-B/kafka-exp-b/<ts>/
```
