# mruby/arvo 真实目标 SymCC 对照实验记录

## 1. 实验范围

本次实验使用真实 mruby/arvo 漏洞镜像，不把 canary 结果计入正式结论。

- 请求的镜像别名：`132/arvo:57672-vul`
- 实际可用并由目标配置使用的镜像：`n132/arvo:57672-vul`
- 目标 commit：`2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b`
- 动态入口：`/out/mruby_fuzzer`
- 静态报告：只提供“`mrb_env_unshare` 存在写屏障问题”的 root cause，未提供完整调用链或 PoC
- 模型：`deepseek-flash`
- 动态上限：200 turns、8 次迭代、1800 秒级超时
- 每个成功 crash 结果都继续送入原始 grade 流程

宿主机不存在 `132/arvo:57672-vul` 这个 tag，只有
`n132/arvo:57672-vul`，因此正式实验实际使用后者。没有通过重新打 tag
伪造用户请求的别名。

## 2. 三轮结果

| 轮次 | SymCC | 动态状态 | 动态耗时 | crash XML | grade |
| --- | --- | --- | ---: | --- | --- |
| 1 | off | `agent_blocked`，超过 1800 秒 | 1803.201 s | 否 | 未执行 |
| 1 | on | `validated`，heap-use-after-free | 1615.162 s | 是 | `passed=true` |
| 2 | off | `agent_failed`，达到 200 turns | 914.451 s | 否 | 未执行 |
| 2 | on | `validated`，heap-use-after-free | 421.720 s | 是 | `passed=true` |
| 3 | off | `validated`，heap-use-after-free | 783.450 s | 是 | `passed=true` |
| 3 | on | `invalid_submission` | 467.476 s | 是，但字段不合规 | 未执行 |

SymCC 第 3 轮的 transcript 中确实出现了 ASAN UAF 和候选 PoC，但 agent 将
`poc_kind` 写成了自然语言说明，而不是协议允许的值；主流程因此拒绝了该结果。
此外这一轮的 SymCC summary 显示 `jobs: []`，agent 实际没有提交 SymCC job，
所以它不能作为一次有效的 SymCC 加速测量。

## 3. 可接受结果与独立验收

三轮 `off` 中有 1/3 次完成了可验收的 PoC；三轮 SymCC 中有 2/3 次完成了
可验收的 PoC。3 次通过的真实 PoC 都是 mruby Ruby 输入触发的
`heap-use-after-free`，并且动态迭代记录包含：

- `site_reached=true`
- `matched_candidate=true`
- `sanitizer_event=true`
- `bad_state_observed=true`
- `bad_effect_observed=true`

第 3 轮 `off` 的 grade 已独立运行 3 次 PoC 复现，5 个通用内存漏洞验收条件
全部通过，score 为 1.0。SymCC 第 1、2 轮也均通过相同的独立 grade。

有效结果目录：

```text
results/experiments/mruby-env-write-barrier/symcc-mruby-20260920/pairs/pair-1/
results/experiments/mruby-env-write-barrier/symcc-mruby-20260920/pairs/pair-2/
results/experiments/mruby-env-write-barrier/symcc-mruby-20260920/pairs/pair-3/
```

## 4. 结论与限制

在这个目标上，SymCC 的主要可见收益是提高了在 agent 探索预算内得到可验收
结果的概率：接受率从 `1/3` 提高到 `2/3`。但由于 `off` 组两次没有完成，
不能把 SymCC 的有效成功时间与 `off` 做严格的平均耗时比较。两次有效 SymCC
耗时的平均值为约 1018.441 秒；`off` 只有一次有效样本，耗时为 783.450 秒。

因此，本实验支持“SymCC 可能帮助复杂 GC/状态条件下的动态探索”，不支持
“SymCC 在该目标上一定更快”的结论。第 3 轮还暴露了一个需要后续修复的
协议协作问题：agent 能够找到真实 crash，但没有按模板填写合规的
`poc_kind`，导致有效证据被主流程拒绝。该次结果应保留为失败样本，不能手工
改写为成功样本。

## 5. 脱离 agent 的手动 PoC 复现

为确认问题不只是 agent 的报告错误，将三个 SymCC 组产生的 PoC 直接挂载到
同一个 `n132/arvo:57672-vul` 容器中执行，每个 PoC 连续运行 3 次：

| PoC | 大小 | 结果 |
| --- | ---: | --- |
| pair-1 SymCC | 198 bytes | 3/3，退出码 1，ASAN heap-use-after-free |
| pair-2 SymCC | 280 bytes | 3/3，退出码 1，ASAN heap-use-after-free |
| pair-3 SymCC | 111 bytes | 3/3，退出码 1，ASAN heap-use-after-free |

pair-1 的崩溃栈落在 `src/string.c:1230` 的 `str_escape`，pair-2 和 pair-3
均在 `__asan_memcpy` 报告 UAF。执行时使用了独立容器、`--network none` 和
4 GB 内存限制，没有依赖 agent 会话中的临时状态。因此，从漏洞发现和 PoC
可用性角度，三份 PoC 均可以独立复现目标漏洞。

## 6. 时间与 token 统计

token 统计来自动态 transcript 中各个 `step_finish.tokens` 的累加。`total`
包含 cache read；其余字段分别表示新输入、输出和 reasoning，不能再与
`total` 相加。

| 轮次 | 模式 | 动态耗时 | 工具调用 | token total | input | output | reasoning | cache read |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | off | 1803.201 s | 79 | 3,530,176 | 57,111 | 6,231 | 38,098 | 3,428,736 |
| 1 | SymCC | 1615.162 s | 156 | 9,358,457 | 239,715 | 26,978 | 100,788 | 8,990,976 |
| 2 | off | 914.451 s | 203 | 12,500,486 | 224,389 | 29,557 | 116,492 | 12,130,048 |
| 2 | SymCC | 421.720 s | 103 | 4,305,287 | 123,818 | 16,573 | 55,456 | 4,109,440 |
| 3 | off | 783.450 s | 130 | 6,352,856 | 142,774 | 21,816 | 54,890 | 6,133,376 |
| 3 | SymCC | 467.476 s | 109 | 4,936,992 | 125,008 | 17,219 | 60,045 | 4,734,720 |

三轮合计，off 为 3501.102 秒、22,383,518 tokens；SymCC 为 2504.358 秒、
18,600,736 tokens。SymCC worker 的实际 job 时间远小于驻留时间：第 1 轮
为 17.830 秒（1 次编译失败、1 次成功，64 个 testcase），第 2 轮为 6.138
秒（96 个 testcase），第 3 轮没有提交 job。worker 驻留时间分别为
1616.121、422.683 和 468.437 秒，主要包含 agent 的动态探索时间。

独立 grade 的 token 和耗时记录在结果目录的 `experiment-summary.json` 中；
grade 不计入上面的动态阶段对比。

本实验六次动态运行都使用 1800 秒的外层 phase 上限、200 agent turns 和 8
次迭代上限。1800 秒是最大预算，不要求每次运行满时：成功生成 PoC 或达到
agent steps 上限都会提前结束。pair-2 off 在 914.451 秒达到 steps 上限，
pair-3 off 在 783.450 秒完成，pair-2/3 SymCC 在 421.720/467.476 秒结束；
只有 pair-1 off 实际触发 phase watchdog，记录的 1803.201 秒包含收尾开销。

随后将动态默认 steps 提高到 20000，并在不传递 `--max-turns` 的情况下重跑
pair-2。off 运行耗时 1033.492 秒、使用 118 次工具调用和 5,521,804 tokens，
最终因模型上下文长度达到上限而退出，没有生成 PoC。SymCC 运行耗时 1374.777
秒、使用 157 次工具调用和 8,049,105 tokens；实际 SymCC job 耗时 5.610 秒，
生成 64 个 testcase，最终 PoC 通过独立 grade（16.207 秒，score 1.0）。
这说明提高 max-turns 确实消除了旧的 200-turn 提前终止，但它不能突破模型
上下文长度限制；新的有效上限转移到了 context length 和 1800 秒 phase watchdog。
