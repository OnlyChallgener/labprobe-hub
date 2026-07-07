# 群晖 DSM 部署 Labprobe Hub v0.7.8

你的 NAS 目录通常是：

```text
/volume1/docker/labprobe-hub/
├── docker-compose.yaml
├── config.yaml
└── data/
```

`data/` 是设备状态和历史数据，不要删除。

## 推荐方式：在 GitHub 发 Hub 包后由 Docker 重新构建/拉取

不要在 DSM File Station 里直接替换容器内部的 `hub.py`。

### 如果你用 Container Manager 项目
1. 停止 `labprobe-hub` 项目。
2. 用本包源码重新构建镜像，或把镜像 tag 更新为 `v0.7.8`。
3. 启动项目。

### 如果可以用任务计划执行命令
控制面板 → 任务计划 → 新增 → 触发的任务 → 用户定义脚本，用户选 root：

```sh
cd /volume1/docker/labprobe-hub
docker compose down
docker compose up -d --force-recreate
```

如果系统不支持 `docker compose`，改用：

```sh
cd /volume1/docker/labprobe-hub
docker-compose down
docker-compose up -d --force-recreate
```

## 验证 IPv6 合并
浏览器访问：

```text
http://NAS_IP:58443/api/ipv6-neighbors
```

需要带 token 的环境，请用 APP 或 curl 带上 `X-LabProbe-Token`。
