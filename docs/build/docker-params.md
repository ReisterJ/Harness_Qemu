# Docker 参数文件

`docker-params.yaml` 是目标目录之外的 Docker 执行层配置。它不替代
`target-manifest.yaml`：manifest 描述程序如何运行，Docker 参数文件描述
宿主机需要给容器什么资源。

## 使用方式

构建新目标时显式提供文件：

```bash
vuln-pipeline build demo \
  --repo https://example.invalid/project.git \
  --branch main \
  --model "$VULN_PIPELINE_MODEL" \
  --docker-params ./docker-params.yaml \
  --dangerously-no-sandbox
```

构建成功后，文件会被复制到 `targets/demo/docker-params.yaml`。之后运行
`vuln-pipeline run demo` 会自动读取它；临时覆盖可以使用：

```bash
vuln-pipeline run demo --docker-params ./qemu-on-kvm.yaml \
  --model "$VULN_PIPELINE_MODEL" --dangerously-no-sandbox
```

Docker 参数是结构化字段，不支持拼接任意 `docker run` 命令。配置文件
格式如下：

```yaml
schema_version: 1

# generated 使用工作流构建出的 image_tag；prebuilt 用于已经准备好的镜像。
image:
  mode: generated
  # mode: prebuilt 时必须填写；镜像必须已经在本机，或配合 pull: true。
  # reference: registry.example/project-qemu:2026-09-10
  # pull: false

build:
  network: host          # 也可以是 none、bridge 或用户的 Docker 网络
  platform: linux/amd64
  pull: false
  args:
    BUILD_VARIANT: debug
  # target: runtime

run:
  network: none
  memory: 4g
  shm_size: 128m
  # cpus: "2"
  # devices:
  #   - /dev/kvm
  # privileged: true
  # cap_add: [NET_ADMIN]
  # security_opt: [seccomp=unconfined]
  # env: {TARGET_BOARD: qemu-virt}
  # mounts:
  #   - source: ./artifacts
  #     target: /artifacts
  #     read_only: true
  # command: ["/bin/sh", "-c", "sleep infinity"]
  # entrypoint: ["/usr/local/bin/launcher"]

# 每个阶段只覆盖需要不同的设置；未填写字段继承 run。
phases:
  probe:
    memory: 512m
  agent:
    network: host
  grade:
    network: none
```

## QEMU 和硬件目标

不需要硬件加速的 QEMU TCG 目标通常只需要配置内存、共享内存和网络：

```yaml
schema_version: 1
run:
  network: none
  memory: 2g
  shm_size: 128m
```

需要 KVM 或开发板设备时，使用：

```yaml
schema_version: 1
run:
  network: host
  devices:
    - /dev/kvm
  privileged: false
```

设备透传和 `privileged` 会被明确禁止在 gVisor agent 容器中使用。此时
必须在隔离的虚拟机内使用 `--dangerously-no-sandbox`，否则工作流会在启动
agent 前失败，而不是悄悄忽略设备配置。

`mounts.source` 是宿主机路径；相对路径相对于参数文件所在目录解析，并且
在 `docker run` 前检查是否存在。容器内的 `target` 必须是绝对路径。

## 结果和验收

参数文件会同时作用于：

1. `build` 阶段的 Docker 网络、平台、build args 等设置；
2. 目标镜像的 contract probe；
3. static/recon/find/grade/report/patch 所使用的目标-agent 容器。

因此 QEMU 启动、动态验证和 grade 使用的是同一套宿主机约束。目标的
`target-manifest.yaml` 仍然负责 `start`、`ready`、`reset`、`collect` 等
容器内生命周期命令，Docker 参数文件不把这些行为硬编码进工作流。

构建日志中的 `build.json` 只记录参数文件路径和 SHA-256，不记录环境变量
值。不要把密钥放入 `env`；认证和代理变量仍由 harness 管理。
