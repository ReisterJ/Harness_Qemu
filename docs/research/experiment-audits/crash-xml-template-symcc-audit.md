# Crash XML 模板协议与 SymCC 对照实验记录

## 1. 背景

此前动态验证的 crash 提交依赖 agent 最终回复中的 XML 标签。实际实验中，
agent 有时已经生成了 PoC，却没有稳定地产生可解析的最终 XML，导致有效结果
被当成提交失败。

本次修复采用“只对成功的 crash 提交使用文件协议”的设计：

- 动态容器启动时由宿主机写入固定模板
  `/work/validation/crash-result-template.xml`；
- agent 只有在 crash 已经稳定复现后，才通过文件操作复制模板并填写
  `/work/validation/crash-result.xml`；
- 宿主机检查文件是否存在、严格解析固定 XML schema、校验候选 ID，并继续校验
  PoC 文件非空、路径出现在复现命令中以及迭代记录中的 `candidate_ready` 证据；
- 未到达、未崩溃和逻辑漏洞结果仍然使用原有的 inline 状态标签，不要求创建
  空的 crash XML 文件。

这样文件协议解决的是 crash 提交的可靠性，不改变后续原始 `grade` 流程。

## 2. 对照实验设置

实验目标使用仓库自带的小型 `canary`，静态报告只选择 Alpha parser 的
heap-buffer-overflow 候选。每组使用相同模型、目标镜像、静态报告、动态迭代上限
和容器资源，分别关闭和启用 SymCC，各运行 3 次。每次动态结果随后都送入原始
grade 的新容器进行独立验收。

使用的模型为 `deepseek-flash`，动态验证上限为 200 turns，迭代上限为 8。

## 3. 结果

动态阶段墙钟时间如下：

| 对照组 | 第 1 次 | 第 2 次 | 第 3 次 | 平均 |
| --- | ---: | ---: | ---: | ---: |
| SymCC 关闭 | 25.413 s | 32.981 s | 28.701 s | **29.032 s** |
| SymCC 启用 | 43.542 s | 36.991 s | 38.435 s | **39.656 s** |

SymCC 相对关闭组的平均增加为 **10.624 s**，约为关闭组平均时间的 **1.366 倍**。
在这组小型目标上，SymCC 没有降低总动态墙钟时间；它的价值体现在为 agent
提供了可执行的约束求解和候选输入。三次 SymCC 会话分别产生 20、20、21 个
测试样例，并辅助找到 Alpha parser 的越界长度条件。

6/6 次动态结果状态均为 `validated`，6/6 份 crash XML 均存在且可以被严格解析。
6/6 次原始 grade 均 `passed=true`、score 为 1.0；每次 grade 的 5 个内存崩溃
标准均通过，逻辑漏洞专用的第 6 个标准对本实验不适用。

## 4. 结果位置

三轮正式对照结果位于：

```text
results/experiments/canary-klee/template-paired/
```

每个正式结果目录中包含：

- `dynamic_validation.json`：动态阶段结果和计时；
- `crash-result.xml`：宿主机保存的 agent 最终 crash 文件；
- `dynamic_transcript.jsonl`：agent 动态过程；
- `grade_validation.json`：本次独立 grade 验收摘要；
- `grade_transcript.jsonl`：grade agent 的实际复核过程。

例如第一轮关闭 SymCC 的结果为：

```text
results/experiments/canary-klee/template-paired/pair-1/off/canary/dynamic-20260920T053521Z/
```

第一轮启用 SymCC 的结果为：

```text
results/experiments/canary-klee/template-paired/pair-1/symcc/canary/dynamic-20260920T053607Z/
```

## 5. 解释与限制

这不是证明 SymCC 在所有真实项目上都会降低 PoC 时间的实验。`canary` 很小，
候选和输入格式都比较简单，关闭 SymCC 的 agent 也能直接构造 PoC；因此本次数据
显示的是额外工具开销，而不是 SymCC 的普遍效果。

后续如果要衡量“首次有效 PoC 时间”，还应单独记录 agent 首次写入合格
`crash-result.xml` 的时间，并在更复杂、仅靠手工试探难以满足约束的目标上进行
多轮交错实验。无论是否启用 SymCC，最终判断仍应以原始 grade 在干净容器中的
独立复现为准。
