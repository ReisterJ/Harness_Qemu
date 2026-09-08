# secrun flex 端到端验证记录

日期：2026-09-08。实现前回滚点：`5fcacd1`。

## 结论

已经完成“远端仓库 → 文档阅读 → 自动生成方案 → 镜像构建 → 自动修复 →
最终镜像功能验收”的真实测试，未调用 find/grade。
另一次新任务验证了远端提交检查、同提交方案复用和缓存复验，约 5.37 秒完成。

仓库：`https://github.com/westes/flex.git`。自动识别默认分支为 `master`。
实际取得的提交：`4fcc71489ae298c35b0b786114ad524945f2cf95`。

## 实际产物

| 项目 | 位置/内容 |
| --- | --- |
| 自动生成及修复任务 | `results/images/flex/20260908T073351-7793e388/` |
| 新任务缓存复验 | `results/images/flex/20260908T093436-a998e06d/` |
| 最终上下文 | `targets/flex/image/versions/20260908T093436-a998e06d-01/` |
| 最近通过的版本指针 | `targets/flex/image/current.json` |
| 最终镜像标签 | `secrun/flex:4fcc71489ae2-a998e06d-1` |

生成目录、源码快照和完整日志保留在工作区，按设计不加入 Git。

启动：

```bash
docker run --rm secrun/flex:4fcc71489ae2-a998e06d-1
```

默认输出 `flex 2.6.4`。也可以将 flex 参数作为镜像运行命令：

```bash
docker run --rm -i secrun/flex:4fcc71489ae2-a998e06d-1 flex -t < example.l
```

## 验收证据

两项测试均在最终镜像创建的新容器中运行，没有挂载构建源码，也没有临时补装依赖。

| 用例 | 实际执行 | 结果 |
| --- | --- | --- |
| `version_startup` | 默认 CMD | 退出码 0；stdout 为 `flex 2.6.4\n` |
| `generate_compile_run` | 写入小型词法规则；flex 生成 C；cc 编译；输入 `a\nb\n` | 退出码 0；stdout 为 `2 lines\n` |

原始任务 `attempt_01/plan.json` 与最终 `attempt_06/plan.json` 中的
acceptance 数据完全相同。自动修复没有改变输入、测试步骤或预期输出。
详细报告在各任务的 `acceptance.json`。

## 实验中发现并修复的问题

初期集成测试并非第一次就成功；失败记录全部保留。

1. 模型达到工具步数上限后只返回总结：增加无工具的结构化收尾步骤，复用已读证据。
2. 完整 JSON 偶尔没有标签：接受完整的裸 JSON / fenced JSON，仍拒绝从散文中拼凑半截对象。
3. 修复模型重写验收字段：修复协议改为仅提交打包改动，原验收条件由程序保管并注入。
4. Docker 的长堆栈遮盖根因：错误摘要保留关键错误及邻近上下文，而不只截最后几千字符。
5. flex 缺少 `autopoint`：自动修复在 builder 中补齐依赖；运行阶段同时保留 flex 需要的 `m4`。
6. flex 自举阶段的并行竞态：日志显示 `stage1scan.o` 被两个 make 进程重复编译，导致
   `.deps/stage1scan.Tpo` 消失。模型阅读 `src/Makefile.am` / `configure.ac` 后采用
   项目提供的 `--disable-bootstrap` 配置。没有修改上游源码。

`--disable-bootstrap` 跳过 flex 的自举比较，仍从该提交的源文件编译并安装 flex。
`configure.ac` 明确提供此选项来绕过自举问题。因此本次结果证明镜像基本功能可用，
不代表自举比较或整个上游测试套件通过。

## 重新运行

本虚拟机使用 host 网络访问构建依赖；模型凭据沿用项目已有 `.env`。

```bash
source .venv/bin/activate
secrun --name flex --repo https://github.com/westes/flex.git \
  --agent-network host --build-network host
```

这会重新获取远端最新提交。同提交默认复用已验证方案并重新验收；若要重新测试
从文档自动生成方案，可以增加 `--replan`，或使用一个新的 `--name`。
指定分支可增加 `--branch master`。

## 自动化回归

```bash
SECRUN_DOCKER_TESTS=1 .venv/bin/pytest -q
```

新增回归覆盖源码提交变化、错误提交/远端失败、协议约束、冻结验收、双流日志、
超时/取消及后代进程清理、CLI 与 HTTP 的真实 Docker 验收、缓存复验和构建超时不发布。
使用方式和功能边界见 [secrun 文档](secrun.md)。
