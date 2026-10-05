# MRuby bignum right-shift `allocation-size-too-big` ASan 事件记录

本文记录一次在 MRuby 57672 supervisor ablation 实验中发现的独立 ASan 事件。该事件不是原始目标候选 `candidate_001` 的复现结果，但它是一个稳定可复现的额外崩溃，应作为 additional finding 继续保留和后续分析。

## 1. 发现背景

实验目录：

```text
results/experiments/mruby-57672-supervisor-ablation/supervisor-rules/mruby-arvo-feedback/dynamic-20261004T183545Z
```

原始验证目标：

```text
candidate_001
MRuby heap-use-after-free
src/vm.c:398
mrb_env_unshare / stack_copy
```

实验过程中，agent 在一次 broad fuzzing 后发现并 replay 了一个 ASan crash。该 crash 的调用栈不包含 `mrb_env_unshare`，因此不能作为 `candidate_001` 的 PoC；但它可以独立稳定触发 ASan。

## 2. 目标环境

本地目标配置：

```text
target: targets/mruby-arvo-feedback
image: local/arvo-57672-site-feedback-nogit:20260924-sitefix1
source: https://github.com/mruby/mruby
commit: 2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b
binary: /out/mruby_fuzzer
detector: ASan
```

## 3. PoC 输入

输入长度为 72 字节。

十六进制：

```text
6465653d203737373737373737373737373737203d7e3737373737373737373737373737373737373737373737203e3e373737373737372000000437373100000004413737316632
```

可用以下脚本重建：

```python
from pathlib import Path

poc = bytes.fromhex(
    "6465653d203737373737373737373737373737203d7e"
    "3737373737373737373737373737373737373737373737203e3e"
    "373737373737372000000437373100000004413737316632"
)

assert len(poc) == 72
Path("mruby-bignum-alloc-size-poc.bin").write_bytes(poc)
```

输入的可打印近似形式：

```text
dee= 77777777777777 =~77777777777777777777777 >>7777777 \x00\x00\x04771\x00\x00\x00\x04A771f2
```

## 4. 复现命令

```sh
python3 - <<'PY'
from pathlib import Path
poc = bytes.fromhex(
    "6465653d203737373737373737373737373737203d7e"
    "3737373737373737373737373737373737373737373737203e3e"
    "373737373737372000000437373100000004413737316632"
)
assert len(poc) == 72
Path("/tmp/mruby-bignum-alloc-size-poc.bin").write_bytes(poc)
PY

docker run --rm \
  -v /tmp/mruby-bignum-alloc-size-poc.bin:/work/poc.bin:ro \
  local/arvo-57672-site-feedback-nogit:20260924-sitefix1 \
  sh -lc 'ASAN_OPTIONS=detect_leaks=0 timeout 30 /out/mruby_fuzzer /work/poc.bin'
```

本地重复验证结果：

```text
3/3 reproduced
exit code: 1
ASan type: allocation-size-too-big
```

## 5. ASan 现象

核心 ASan 报告：

```text
ERROR: AddressSanitizer: requested allocation size 0xfffffffffff12a50
exceeds maximum supported size of 0x10000000000

SUMMARY: AddressSanitizer: allocation-size-too-big
```

符号化后的关键调用链：

```text
realloc
mrb_default_allocf
mrb_realloc
mpz_div_2exp
mrb_bint_rshift
int_rshift
mrb_vm_exec
mrb_vm_run
mrb_top_run
mrb_load_exec
mrb_load_nstring_cxt
mrb_load_string
LLVMFuzzerTestOneInput
```

本地 `nm` 映射结果：

```text
0x53083c -> realloc + 0xfc
0x56daf3 -> mrb_default_allocf + 0x43
0x57765a -> mrb_realloc + 0x8a
0x5edb57 -> mpz_div_2exp + 0x217
0x5eeed5 -> mrb_bint_rshift + 0x105
0x64d8e4 -> int_rshift + 0x3c4
0x5a0778 -> mrb_vm_exec + 0x12b18
0x58d9fc -> mrb_vm_run + 0x53c
0x58a8c8 -> mrb_top_run + 0x1e8
0x60bec1 -> mrb_load_exec + 0xa31
0x60d146 -> mrb_load_nstring_cxt + 0x2d6
0x60d2fb -> mrb_load_string + 0x3b
0x56d8ef -> LLVMFuzzerTestOneInput + 0x7f
```

## 6. 与原始候选的关系

该 ASan 事件与原始目标候选无关。

原因：

- 原始候选位于 `mrb_env_unshare` / `stack_copy`；
- 本事件调用栈进入 `mpz_div_2exp -> mrb_bint_rshift -> int_rshift`；
- 栈中未出现 `mrb_env_unshare`；
- ASan 类型是 `allocation-size-too-big`，不是原始候选描述的 heap-use-after-free。

因此该输入不能让 `candidate_001` 通过动态验证或 Grade。它应作为独立 additional finding 处理。

## 7. 对框架的启示

这次事件暴露了两个框架问题：

1. additional crash 提交流程需要更强约束。

   本轮 agent 实际写入了 `/work/validation/additional-crashes.jsonl`，但 JSONL 不符合 schema，导致 harness 未收录该 finding。后续应提供更明确的模板，并要求 agent 将 PoC 复制到：

   ```text
   /work/validation/additional-crashes/<finding_id>/poc.bin
   ```

2. supervisor 应从事后纠偏升级为执行前拦截。

   本事件是在 broad fuzzing 后发现的。虽然发现额外 crash 是有价值的，但 supervisor 当前只能在命令执行完成后纠偏，无法阻止 300s fuzzing 预算消耗。后续应考虑将 Bash 执行切换到 harness-managed wrapper，使 supervisor 能在命令执行前拒绝 broad fuzzing，并返回修改后的具体输入构造策略。

## 8. 当前状态

```text
primary candidate: not reproduced
additional finding: stable ASan allocation-size-too-big
reproduction: local image 3/3 stable
upstream/latest: not checked
deduplication: not checked
security impact: not assessed
```

后续如果要正式报告该问题，需要进一步确认：

- 是否存在于 upstream 最新版本；
- 是否是已知 MRuby bignum 问题；
- 是否能在非 fuzzing harness 的正常 MRuby CLI/API 中触发；
- 是否属于可接受的资源异常、DoS，还是更严重的整数/大小计算缺陷。
