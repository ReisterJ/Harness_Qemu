# 从"可疑"到"确认"：一个可适配的 LLM 自主漏洞验证框架

> 发现不是瓶颈，验证才是。本文介绍一个通用、可适配的 LLM 自主验证框架：把一份漏洞
> 报告（或一个崩溃假设）交给 agent，让它自己写 PoC、自己搭环境、把目标跑崩，再由
> 独立判定者在全新环境对照官方签名给出结论。**内核定向测试只是这个框架适配到 Linux
> 内核域之后的一个功能——真正被利用的能力，都在框架本身。**

## 核心论点

静态分析、代码审计、模糊测试能轻易制造海量"可疑发现"，但"哪一条是真的"才是真正的
成本。传统验证靠安全工程师手工完成：读源码、理解触发条件、写 PoC、搭环境、跑复现、
对照官方崩溃签名。这一步耗时、枯燥、容易被搁置——于是报告堆积，真伪不分。

本框架把这条链路自动化，并且**与具体漏洞领域解耦**。框架提供的是一组通用能力：

1. **执行者（find）**：读一份报告 → 读目标源码 → 写 PoC → 自己搭环境、把目标跑崩；
2. **判定者（grade）**：在全新环境拿到 PoC，独立复跑 3 次，对照官方签名判定
   `CONFIRMED / PARTIAL / NOT_REPRODUCED`。

框架的能力都在框架本身：双容器信任边界、agent 自主执行、信息隔离、自包含交付、
多阶段流水线、可替换后端、可适配新域。下面的章节逐一展开这些"与领域无关"的能力，
最后用一个真实用例（内核定向测试）展示框架被适配到新域时的样子。

## 框架的能力（与领域无关）

### 双容器信任边界：防的是"预置答案"

find 和 grade 运行在相互隔离的容器里，两者之间**只传递 PoC 字节**：

- find 永远看不到官方签名——它必须靠自己把崩溃跑出来；
- grade 永远看不到 find 的推理过程——它必须独立复跑，不能"信了"find。

这从结构上杜绝了 agent 通过预置状态糊弄判定的可能性，是所有"可信验证"的根基。

### agent 自主执行：框架不写 driver

框架不替每个目标写死"驱动脚本"。agent 自带 Read/Write/Bash 工具，自己决定怎么
编译、怎么运行、怎么观测崩溃信号。适配一个目标只需要告诉它"目标在哪、怎么跑"，
剩下的探索与迭代全部交给 agent。这也让框架能平滑面对同一个目标内部的无数种触发
方式——agent 会自己试错，而不是依赖人预先枚举。

### 信息隔离 / 答案剥离：验证"理解"，而不是"照抄"

要让验证有意义，执行者拿到的问题必须是"中性"的：只描述**哪里坏了**（函数、机制、
崩溃类），不给**怎么走到那里**（触发步骤、参数序列、官方签名）。更隐蔽的泄露也要防：

- **CVE 编号要删**——模型很可能在训练数据里见过公开 PoC，看到编号就"回忆"而不是
  "推导"；
- **触发步骤要删**——把 `socket(AF_ALG) → setsockopt → sendmsg(ASSOCLEN=0)` 写进
  问题，等于把答案直接递给 agent；
- **模板示例也要查**——早期版本在 prompt 模板的"输出格式示例"里硬编码过真实签名，
  这同样是泄露，示例必须用占位符。

判定标准（官方签名）只给判定者。这个原则的回报在实战中看得很清楚：find agent
经常推导出**与官方 PoC 不同、但同样有效**的触发方案——这是"理解"而非"照抄"。

### 自包含交付物

框架的产物不是一篇"分析报告"，而是一个**独立的复现脚本**：内嵌 PoC 源码、目标
启动逻辑、崩溃检测，在任何同镜像环境里跑一次就能复现崩溃。交付物可审计、可复核、
可交给下游（修复、回归测试）。

### 多阶段流水线

recon（自动发现攻击面分区）→ find（执行复现）→ grade（独立判定）→ judge（去重 /
新颖性）→ report（利用性分析）→ patch（生成并验证修复）。每个阶段都是独立 agent
容器，可单独运行、可断点恢复——框架不止"验证"，还覆盖了从发现到修复的整条链路。

### 鲁棒性：为真实世界的 LLM 而设计

- 模型偶发输出文本格式的工具调用（opencode 只认原生 function call）→ 系统提示词
  强令 + 运行时"零工具调用早退"自动带纠正提示恢复会话；
- 网络 / API 抖动 → 会话级恢复（resume），近满配额运行也不丢工作；
- 多 run 去重 → 避免同一崩溃被反复提交；
- 流式报告 → 第一个结果几分钟内落盘，不被最慢的 straggler 阻塞；
- 每步工具调用与 agent 推理都有完整 transcript 落盘——可审计，可复盘。

### 可替换后端 + 极简配置

agent 后端是插件式的。本实现用 **opencode CLI** + **DeepSeek**（
`deepseek/deepseek-v4-flash`）——不依赖任何专有账号体系，只要一个
`DEEPSEEK_API_KEY` 放进仓库根的 `.env`，CLI 启动时自动加载。agent 文件（系统提示词
+ 工具权限 + 步数上限）由流水线按阶段生成并注入容器。

## 可适配性：一个框架，多种目标

框架对"目标"的抽象只有一个目录：

```
targets/<name>/
  config.yaml    # 目标元数据 + 执行者拿到的报告（attack_surface）+ 判定标准（grade_reference）
  Dockerfile     # 目标镜像 + agent 运行时
```

- **原生目标**：C/C++ 用户态程序（ASAN 构建），agent 直接跑二进制、读崩溃输出；
- **内核目标**：把内核镜像 + QEMU + agent CLI 打进同一个容器，agent 自己开虚拟机
  （QEMU/KVM + 串口）引导内核、传 PoC、抓崩溃。适配点只有三处——镜像构建、
  内核崩溃解析（KASAN/oops）、内核专用 prompt——**框架核心零改动**；
- **其他域同理**：只要目标能在容器里被 agent 运行、并产生可观测的"崩溃信号"，
  就能接入。

适配一个新域的成本，就是写一个 `targets/` 目录。

## 实战：框架在内核域的一个功能

下面三个案例与其说是"内核测试"，不如说是**框架被适配到 Linux 内核域之后的成果**——
它验证的是框架的可适配性和验证能力本身（镜像适配、QEMU 驱动、无 KASAN 签名适配、
prompt 定制，全部在靶标目录里完成，不动框架核心）。

### 1. CVE-2025-40019 — crypto/essiv 整数下溢 ✅ CONFIRMED

`essiv_aead_crypt` 未检查 `assoclen < ivsize`，减法下溢成 `0xfffffff0`，流入
`scatterwalk_ffwd` 导致空指针解引用。官方崩溃是 KASAN 报告；本镜像无 KASAN，
表现为普通 oops。

- find agent 从中性报告出发，自己推导出 AF_ALG AEAD 路径，**3/3 + 额外 1 次冷启动
  全部崩溃一致**，签名与官方逐帧吻合；
- grade 判定 **6/6 全过，score 1.0，`CONFIRMED`**。

### 2. syzbot buildid — filemap_read_folio 空指针解引用 ✅ CONFIRMED

`lib/buildid.c` 睡眠上下文 build-ID 读取经 `read_cache_folio()` 走 page-cache 读路径，
对读路径缺失的映射触发 NULL deref（`RIP: 0x0` 指令取指崩溃）。触发入口是
`PROCMAP_QUERY` ioctl。

- find agent 从零推导出触发方式，而且**用了与官方 PoC 不同的方案**：官方用
  BPF map 的 mmap，agent 用"无 `->read_folio` 的 shmem memfd" + `PROCMAP_QUERY`。
  ——这是"理解根因而非照抄"的明证；
- **6/6 全过，`CONFIRMED`**，调用链逐帧匹配官方。

### 3. CVE-2025-39682 — net/tls 零长度记录 UAF ⚠️ PARTIAL（最有价值的一次）

`tls_sw_recvmsg` 在 `copied == 0` 时继续收包，零长度记录导致 `strp->anchor` 在
`darg.zc == 1` 时被错误排入 `rx_list`，留下悬垂 `frag_list`。

- find agent 复现了**同一 UAF 的另一条崩溃路径**：通过 close 走**释放路径**
  （`skb_release_data → kfree_skb_list_reason → ...`）触发 NULL deref——这与官方
  `vulnerability.md` 的 KASAN trace（`kfree_skb_list_reason`）**完全同路径**；
- 但判定标准只覆盖了官方 PoC 的 **splice 读路径**（`__skb_splice_bits`），顶层函数
  不匹配 → 判 `PARTIAL`。

**教训：同一漏洞可以有多个可观测崩溃路径。** 一个 UAF 既能在释放路径崩，也能在
读路径崩。`grade_reference` 必须覆盖同根因的**所有**合法崩溃形态，否则一次真实、
有效的复现会被误判。这与其说是框架的缺陷，不如说是"验证"这件事本身的语义问题：
**你要验证的是"报告里描述的那个崩溃"，还是"报告的根因"？** 我们的结论是后者——
根因一致的不同路径崩溃，应当被接受为确认。

## 成本与时间

| 靶标 | find | grade | 结果 |
|---|---|---|---|
| essiv（AF_ALG） | ~20–41min | ~2min | CONFIRMED |
| buildid（procmap） | ~44min | ~2min | CONFIRMED |
| net/tls（UAF） | ~68min | ~17min | PARTIAL |

- **grade 的 3 次目标冷启动是固定成本**（内核域每次 QEMU boot 约 5–6min），一个
  多小时主要花在 find 的探索与构造上；
- TLS 类漏洞尤其耗时：构造合法的加密 TLS 记录需要正确实现 AES-GCM（agent 手写
  加密，首崩前约 20min）。这不是"三次复现"慢，是"找到并构造"慢。

## 上手：把框架跑起来

```bash
# 一次性：在仓库根 .env 写入 DEEPSEEK_API_KEY（CLI 自动加载）
cp .env.example .env

# 制作靶标：一个目录 = config.yaml + Dockerfile（见"可适配性"一节）
# 启动（单 run，验证类测试的统一约定）
export VULN_PIPELINE_DOCKER_BUILD_NETWORK=host
nohup .venv/bin/vuln-pipeline run targets/<target> \
    --dangerously-no-sandbox --model deepseek/deepseek-v4-flash --max-turns 1000 \
    > /tmp/run.log 2>&1 &
```

结果落在 `results/<target>/<时间戳>/`：`result.json`（判定）、`poc.bin`（自包含复现
脚本）、完整 transcript（执行者与判定者的全部推理与工具调用，可审计）。

## 局限与展望

- **答案剥离还是人工劳动**。每个新报告都要手工中性化，还要防模板级泄露。可以自动化：
  用一个小模型做"答案审查"，在报告进入执行者之前先做一次泄漏扫描。
- **判定标准覆盖不全会误判**。上面的 PARTIAL 案例说明，签名覆盖不全会把有效复现
  判错。可以改为"按根因聚合"的判定：崩溃类一致、且落在同一条已知缺陷链上，就接受
  不同路径。
- **成本**。每次验证数十到上百分模型调用 + 多次目标启动。对大规模报告批次，可先做
  轻量静态预筛（函数/路径匹配），只把值得执行验证的送进流水线。
- **闭环**。把验证结论自动回填到报告系统（`已验证 / 待验证 / 误报`），形成
  "扫描 → 验证 → 标记"的闭环，让扫描产出真正可消费。
- **更多域**。驱动、固件、复杂的用户态应用……只要目标能在容器里被 agent 运行并产生
  可观测的崩溃信号，就能接入同一框架。

---

*框架基于 [defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness)
的 `vuln-pipeline`；内核域的适配细节与测试记录见 `docs/kernel/kernel-validation.md`，靶标在
`targets/`（`kernelval`、`syzbot-buildid`、`tls-uaf`）。*

