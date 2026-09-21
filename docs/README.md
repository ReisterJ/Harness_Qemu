# 文档导航

本目录按用途组织参考文档。根目录的 [`README.md`](../README.md) 提供项目简介和
快速开始；本文档用于在进入具体主题前找到相应说明。

## 工作流与架构

- [architecture/pipeline.md](architecture/pipeline.md) — 原始 recon → find → grade → report → patch 流程
- [build/target-build-workflow.md](build/target-build-workflow.md) — 从仓库生成 target Dockerfile、配置和入口的构建计划
- [build/extensible-target-workflow-plan.md](build/extensible-target-workflow-plan.md) — 支持多语言、Web 服务和 QEMU 目标的可扩展构建与运行工作计划
- [guides/customizing.md](guides/customizing.md) — 将工作流适配到自己的项目和基础设施
- [guides/troubleshooting.md](guides/troubleshooting.md) — 运行、恢复、限流和常见故障

## Agent 与安全边界

- [architecture/agent-sandbox.md](architecture/agent-sandbox.md) — gVisor、网络隔离和 agent 容器
- [architecture/security.md](architecture/security.md) — 凭据、挂载、构建和执行阶段的安全边界
- [architecture/threat-model.md](architecture/threat-model.md) — 威胁模型和安全研究范围
- [research/best-practices.md](research/best-practices.md) — 验证、规模化、去重和迭代原则
- [research/prompting.md](research/prompting.md) — agent prompt 和任务拆分方法

## Find、验证与结果处理

- [research/find-phase-split-plan.md](research/find-phase-split-plan.md) — find 阶段静态分析与动态验证拆分方案
- [research/experimental-target-selection.md](research/experimental-target-selection.md) — C/Rust 和 sanitizer 实验目标选择
- [research/experiment-audits/curl-socks5-instrumentation-audit.md](research/experiment-audits/curl-socks5-instrumentation-audit.md) — curl SOCKS5 插桩对照实验审计记录
- [research/iterative-dynamic-validation.md](research/iterative-dynamic-validation.md) — 内存与逻辑漏洞通用的动态验证迭代设计
- [research/triage.md](research/triage.md) — 发现分组、排序和人工分诊
- [research/patching.md](research/patching.md) — 生成、验证和重新攻击补丁
- [guides/other-use-cases.md](guides/other-use-cases.md) — 二进制、嵌入式和其他使用场景

## Kernel 与专项记录

- [kernel/kernel-validation.md](kernel/kernel-validation.md) — Linux kernel 报告的 QEMU/KVM 验证
- [kernel/kernel-validation-blog.md](kernel/kernel-validation-blog.md) — kernel 验证过程记录
- [kernel/ohos6-kernel-adaptation-report.md](kernel/ohos6-kernel-adaptation-report.md) — OpenHarmony kernel 适配记录
- [kernel/cve-2026-23398-ohos-master-report.md](kernel/cve-2026-23398-ohos-master-report.md) — OpenHarmony CVE 调研记录
- [kernel/ohos6-kernel-architecture.svg](kernel/ohos6-kernel-architecture.svg) — kernel 目标架构图
- [kernel/ohos6-kernel-system-architecture.svg](kernel/ohos6-kernel-system-architecture.svg) — 系统部署架构图
- [kernel/ohos6-kernel-find-flow.svg](kernel/ohos6-kernel-find-flow.svg) — kernel find 流程图

## Detection & Response

- [detection-response/detection-response.md](detection-response/detection-response.md) — 检测与响应工作流

## 背景材料

- [background/blog-post.md](background/blog-post.md) — 项目背景和方法论总结
