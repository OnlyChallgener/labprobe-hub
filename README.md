# LabProbe Hub 0.9.6

LabProbe Hub 可部署在任意 Linux AMD64/ARM64 宿主机，包括服务器、小主机、NAS 和软路由。Hub 使用 SQLite 保存数据；已适配锐捷路由器上的 Rust Agent 继续以 `dev_sta/user_list` 为核心数据源。

版本变化统一记录在 [`CHANGELOG.md`](CHANGELOG.md)。旧 DSM/NAS 部署文档和旧 Shell 采集入口已归档到 Git 历史，请勿用于新安装。


## 运行目录

- `./data`：SQLite 数据库 `labprobe.db`
- `./config`：`config.yaml`
- `./backups`：旧 JSON 首次迁移备份
- `./logs`：Hub 轮转日志

不再依赖厂商目录、固定 IP 或特定设备名称。


## 配置与 Docker

```sh
cp .env.example .env
mkdir -p data config backups logs
cp config.example.yaml config/config.yaml
```

推荐环境变量：

```dotenv
HUB_NAME=LabProbe Hub
PRIMARY_ROUTER_NAME=
APP_TOKEN=请改为长随机令牌
HOOK_TOKEN=请改为另一条长随机令牌
HUB_ADVERTISE_URL=http://192.168.1.20:58443
HUB_HOST_IPV4=192.168.1.20
HUB_HOST_IPV6=
HUB_HOST_MAC=
# 可选：留空使用内置 Lucky 更新仓；私有更新仓才填写。
UPDATE_REPOSITORY_ROOT=
```

公网反向代理可使用 `https://hub.example.com`。`PRIMARY_ROUTER_NAME` 可留空，Hub 会优先使用 Rust Agent 实际上报的路由器名。旧 `NAS_IPV4`、`NAS_IPV6`、`NAS_MAC` 和 `PORTMAP_ROUTER_NAME` 仍兼容。

Host 网络适合需要局域网广播 WOL 的部署：

```sh
docker compose -f docker-compose.host.yml up -d --build
```

Bridge 网络适合普通服务器部署：

```sh
docker compose -f docker-compose.bridge.yml up -d --build
```

CI 使用 Buildx 同时构建 `linux/amd64` 和 `linux/arm64`，容器内置 `/health` HEALTHCHECK。


## JSON 到 SQLite

首次启动会扫描 `./data` 下全部 JSON（包括备注子目录），先复制到 `./backups/json-migration-时间/`，再在事务中写入 `./data/labprobe.db`。写入后校验文档数量并执行 SQLite `integrity_check`；失败会删除未完成的新数据库，旧 JSON 和备份不变。

迁移后旧 JSON 不再写入，只作为只读恢复材料。数据库启用 WAL、外键、事务、忙等待、schema version 和索引。

从 Hub 0.9.5 起，SQLite 增量历史采用有界保留：默认最多 5000 条且不超过 7 天。`device_archive.json`、端口运行状态、端口历史、Agent 状态、每日在线采样、地理缓存和路由器仪表盘等高频文档只保存最新值，不再将整份 JSON 复制进 `revisions`。设备 RSSI、流量和在线时长变化也不会单独创建永久 revision；APP 每 5 分钟完整校准，revision 被裁剪时会自动执行完整同步。可通过 `REVISION_MAX_ROWS`、`REVISION_MAX_AGE_DAYS` 和 `REVISION_PRUNE_INTERVAL_SEC` 调整保留策略。

```sh
docker exec labprobe-hub python /app/hub.py doctor
docker exec labprobe-hub python /app/hub.py status
docker exec labprobe-hub python /app/hub.py test-hub
```

旧版本数据库曾因无界 revision 膨胀时，应先停止 Hub，再执行一次压缩维护：

```sh
docker exec labprobe-hub python /app/scripts/repair_storage.py --vacuum
```

脚本会先在 `/app/backups` 创建 SQLite 在线备份，再仅裁剪旧 revision 并压缩数据库；当前设备、备注、关注、事件和端口映射文档不会删除。数据库已正常且体积较小时无需反复执行。


## Token 鉴权

Hub 使用两个必须自行设置的独立令牌：

- `APP_TOKEN`：供 Android APP 的管理、状态与同步请求使用。
- `HOOK_TOKEN`：供 LabRelay、Lucky 和 Webhook 上报及路由器接口使用。

在 `.env` 或 `config/config.yaml` 中填写强随机值，重启 Hub 后，APP 只填写相同的 `APP_TOKEN`；安装 LabRelay 时填写相同的 `HOOK_TOKEN`。

## 同步协议

旧 API 不变，新 APP 使用：

- `GET /api/sync/snapshot`：完整状态、关注设备、在线设备、事件。
- `GET /api/sync/changes?since=REVISION`：按 sequence 返回新增、更新、离线和删除。
- `GET /api/sync/revision`：轻量 revision 校准。

设备、事件和状态与 revision 在同一 SQLite 事务中写入。APP首次、重连、前台恢复、网络切换和每 5 分钟完整校准，其余刷新仅应用增量。


## 锐捷 Rust Agent

SSH 登录已适配的锐捷路由器后执行：

```sh
wget -O /tmp/labprobe-install.sh https://lab.net86.dynv6.net:27772/agent/install.sh \
&& sh /tmp/labprobe-install.sh
```

安装器兼容 BusyBox ash，会检测锐捷环境、CPU、空间、Hub 和 SHA256，并在首次安装或重新配置时要求输入 Hub 的 `HOOK_TOKEN`。也可以预先设置 `HOOK_TOKEN` 与 `HUB_URL` 环境变量。Rust 接管 `dev_sta/user_list` 采集、上线/离线事件、IPv6 邻居、端口映射、重试与日志；Shell 只负责安装、启动和卸载。

```sh
labrelay doctor
labrelay status
labrelay test-hub
sh /tmp/labprobe-install.sh upgrade
sh /tmp/labprobe-install.sh repair
sh /tmp/labprobe-install.sh configure
sh /tmp/labprobe-install.sh uninstall
```

Hub 通过 `LOG_LEVEL`、`LOG_RETENTION_DAYS` 控制日志级别和保留天数，并自动脱敏 Token。Rust 日志默认位于 `/tmp/labprobe/labrelay-agent.log`。

## 更新仓与发版文件

Hub 从统一的 `UPDATE_REPOSITORY_ROOT` 读取 Rust `latest.json`，APP 评分详情页可查询 Agent 当前版本并经 Hub 下发更新指令。锐捷 Rust Agent 仅发布 ARM64 程序；安装脚本会显示下载进度并校验 `checksums.txt`。Hub Docker 镜像仍同时支持 linux/amd64 和 linux/arm64。

`scripts/build_update_bundle.py` 会生成同一份可上传到本地、GitHub 和 Lucky 的目录：

```sh
python scripts/build_update_bundle.py \
  --app-apk LabProbeApp.apk --app-version-name 0.10.5 --app-version-code 133 \
  --agent-arm64 labrelay-linux-arm64 --agent-version 0.2.7 \
  --output update-bundle
```

输出固定为 `app/update.json`、版本化 APK、`agent/latest.json`、`agent/install.sh`、ARM64 Agent 程序和 `agent/checksums.txt`。JSON 中 Lucky 为主地址、GitHub Release 为备用地址，SHA256、大小和更新内容保持一致。
