# 实验记录台账

本目录用于维护动态验证、supervisor、target-site feedback、SymCC/插桩反馈等实验的统一记录，避免实验数量增多后只剩零散 result 目录和 transcript，难以后续复盘。

它和 `docs/research/experiment-audits/` 的区别是：

- `experiment-records/`：每次实验的结构化台账，记录实验目的、变量、命令、结果、结论和后续动作；
- `experiment-audits/`：针对某次实验异常、泄漏、误判或重要发现的深入审计。

## 记录规则

每次开始新的受控实验前，应先确定：

1. 实验问题；
2. 对照变量；
3. 固定变量；
4. 成功/失败分类；
5. 结果目录命名。

实验完成后，应新增或更新一条记录，至少包含：

- 结果目录；
- 目标、模型、时间预算、最大迭代数；
- 是否开启 supervisor；
- 是否开启 target-site feedback / SymCC；
- 主要结果；
- 是否生成 primary PoC；
- 是否发现 additional finding；
- 是否存在 infrastructure / submission failure；
- 后续动作。

建议文件名：

```text
YYYY-MM-DD-<target>-<experiment-topic>.md
```

例如：

```text
2026-10-04-mruby-57672-supervisor-ablation.md
```

## 状态分类

| 字段 | 含义 |
| --- | --- |
| `primary_success` | 是否复现本次静态候选/目标漏洞 |
| `additional_finding` | 是否发现独立额外缺陷 |
| `submission_failure` | 是否技术上发现 PoC/crash，但提交协议失败 |
| `infrastructure_failure` | 是否受到 API、镜像、Docker、runner、网络、余额等基础设施问题影响 |
| `analysis_value` | 是否对工作流设计或研究假设有解释价值 |

## 当前记录索引

| 日期 | 记录 | 实验问题 | Primary | Additional | 主要结论 |
| --- | --- | --- | --- | --- | --- |
| 2026-10-04 | [MRuby 57672 supervisor ablation](2026-10-04-mruby-57672-supervisor-ablation.md) | supervisor 是否减少无意义搜索 | 否 | 是 | supervisor 显著减少 broad fuzzing 时间；未复现目标 UAF，但发现稳定 bignum ASan crash |
| 2026-10-05 | [MRuby 57672 supervisor postfix rerun](2026-10-05-mruby-57672-supervisor-postfix-rerun.md) | 修复后 supervisor 是否按预期纠偏 | 否 | 否 | supervisor 成功拦截后台 fuzz / broad fuzzing；但 off 组暴露 SymCC 产物，不能作为干净对照 |
| 2026-10-06 | [MRuby 57672 clean off / supervisor ablation](2026-10-06-mruby-57672-clean-supervisor-ablation.md) | 干净 off 条件下 supervisor 是否改变已知漏洞复现过程 | 否 | 未确认 | 两组均未产出目标 UAF PoC；rules 组有未验收的逻辑异常线索，时间差约 100 秒，单次实验不足以支持效果结论 |

## 待回填

已有部分历史实验散落在 `results/experiments/` 和 `docs/research/*` 中，后续如需写报告，可按优先级回填：

- MRuby 57672 SymCC 多轮对比；
- Ghostscript 51089 target-site feedback 实验；
- arvo-62290 target anchor / PIE noise / additional crash 实验；
- arvo-38283、arvo-55020 CyberGym follow-up 实验。
