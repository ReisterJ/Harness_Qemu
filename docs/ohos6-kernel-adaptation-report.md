# OpenHarmony 6.0 内核漏洞检测


## 简介

把仓库原有的一套自动化漏洞挖掘工具（原本针对用户态 C/C++ 程序，ASAN 检测）扩展到了 Linux 内核场景（KASAN 检测），并已跑通 OpenHarmony 6.0 内核的完整链路：内核编译、QEMU/KVM 引导。

## 一、背景

原有工具的工作方式是：agent 读源码 → 构造输入 → 跑 ASAN 编译的二进制 → 3/3 复现 → 记录崩溃；后续自动完成验证、去重、报告、补丁。

但它只能覆盖用户态程序，无法测试内核。

## 二、挑战

难点都是内核场景特有的，也是本次工作的主要部分：

1. **运行方式完全不同。** 用户态程序编译好直接 exec 即可；内核必须整体 boot 进 QEMU/KVM 虚拟机，PoC 通过串口传进 guest 执行，崩溃要从串口日志里识别。agent 容器需要访问宿主机 `/dev/kvm` 做硬件加速，并支持快速反复重启虚拟机。
2. **检测机制不同。** ASAN 是编译器插桩的用户态内存检测；内核有自己的 KASAN，崩溃输出形态也完全不一样（KASAN report / oops / panic + call trace），解析逻辑需要重写。
3. **内核编译配置受运行环境影响。** 例如 guest 的隔离环境（nsjail）依赖内核开启命名空间相关配置，默认配置下根本跑不起来。

## 三、实现


### ① Build —— 目标从「ASAN 二进制」变成「KASAN 内核镜像」

**原状**：构建运行环境时每个 target 一个 Dockerfile

**改动**：

- **新增 `targets/ohos6-kernel/`**（本次"新目标"）：
  - `config.yaml`：声明 `detector: kasan`、`devices: [/dev/kvm]`、`agent_prebuilt`、host 网络。这些是 `config.py` 为内核场景新增的字段，全部由 yaml 驱动，管线代码不用改；
  - `build_kernel.sh`：固定 commit 拉取鸿蒙 `kernel_linux_5.10`（Linux 5.10.210 + 鸿蒙定制）源码，编译出带 KASAN 的 bzImage（含一个 compat 补丁，解决 5.10.210 一个函数改名未同步导致的编译失败）；
  - `Dockerfile`：把 bzImage、鸿蒙源码（`/src/linux`）、一份**纯净上游 5.10.210 源码**（`/src/upstream`）一起打进镜像——agent 直接 diff 两份源码就能圈出鸿蒙定制/backport 的攻击面，这也是后续定向挖掘的重点。


### ② Recon —— 逻辑没动

原本是 agent 读源码、提议攻击面分区。现在源码在镜像里（`/src/linux`），`attack_surface` 描述补充了内核环境说明（KASAN 开启、源码布局、上游源码可 diff）。分区逻辑本身一行没改。

### ③ Find —— 核心改动：从「二进制」到「boot 内核」

- **崩溃解析（find 判读崩溃要用）**：新增 `harness/kasan.py`，认识内核崩溃的三类形态——`BUG: KASAN: <类型> in <函数>`、`BUG: kernel ...`/`RIP: 0010:函数`、`Kernel panic`，以及内核 call trace 的帧格式（`func+0x2b/0x60`）。接入方式很轻：`asan.py` 对外就四个函数（提取崩溃帧、取栈顶函数、崩溃原因、生成摘要），每个函数开头加一句嗅探——输出带内核特征就转给 `kasan.py`。

  实际例子，内核崩溃原文：
  ```
  BUG: KASAN: null-ptr-deref in scatterwalk_ffwd+0x43/0x150
  Call Trace:
    <TASK>
     scatterwalk_ffwd+0x43/0x150
  ```
  解析出崩溃类型 `null-ptr-deref`、栈顶函数 `scatterwalk_ffwd`——和用户态 ASAN 提取的"类型 + 函数"是**同一套结构**，所以下游判重、写报告的字段完全没变。

- **agent 指令**：`find_prompt.py` 新增 `KERNEL_FIND_TEMPLATE`，教 agent 一套全新流程：
  1. QEMU/KVM 引导目标内核（模板里给了可直接抄的命令，串口走 unix socket）：
     ```
     qemu-system-x86_64 -enable-kvm -cpu host -m 3.5G -nographic \
       -kernel /kernel/bzImage -initrd /images/ramdisk_v1.img \
       -serial unix:/tmp/q.sock,server=on,wait=off -append "console=ttyS0 ..."
     ```
  2. PoC 用 base64 编码、按 ≤1200 字符分块，通过串口写进 guest，`wc -c` 校验长度一致后再解码、编译、运行；
  3. 从串口输出判读崩溃（`BUG: KASAN` / `RIP:` / `Kernel panic`），并**区分"内核崩溃“”PoC程序自己崩溃"**，后者不算。
- **容器启动**：`find.py` 把 config 里的 `devices`/`agent_network`/`agent_prebuilt` 透传给 docker（映射为 `--device /dev/kvm` + `--network host`）。没有 `/dev/kvm`，QEMU 只能纯软件模拟，一次引导要几分钟，批量测试跑不动。

### ④ Grade —— 验证方式：每次 boot 全新 VM

- `grade.py` 同样透传容器参数；
- `grade_prompt.py` 新增 `KERNEL_GRADE_PROMPT_TEMPLATE`：验证时**每次引导全新 VM**（杜绝跨 boot 的侥幸复现），并对照 `grade_reference`（官方崩溃签名）核对根因。`grade_reference` 是 `config.py` 新增字段，这部分只注入 grade 的 prompt，find 永远看不到。

### ⑤ Judge —— 零逻辑改动

内核崩溃经 `kasan.py` 归一化成与 ASAN 相同的"类型 + 函数"结构后，判重逻辑原样跑。只改了 prompt 措辞（"ASAN excerpt" → "Crash excerpt"），纯术语，不涉及内核知识。

### ⑥ Report —— 零逻辑改动

### ⑦ Patch —— 暂无改动


## 四、下一步

1. 观察能否挖出第一个真实内核漏洞；

