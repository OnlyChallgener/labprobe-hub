# LabProbe Hub 0.9

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
PRIMARY_ROUTER_NAME=Ruijie
HUB_ADVERTISE_URL=http://192.168.1.20:58443
HUB_HOST_IPV4=192.168.1.20
HUB_HOST_IPV6=
HUB_HOST_MAC=
UPDATE_REPOSITORY_ROOT=https://lab.net86.dynv6.net:27772
```

公网反向代理可使用 `https://hub.example.com`。旧 `NAS_IPV4`、`NAS_IPV6`、`NAS_MAC`、`APP_TOKEN`、`HOOK_TOKEN` 和 `PORTMAP_ROUTER_NAME` 仍兼容。

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

```sh
docker exec labprobe-hub python /app/hub.py doctor
docker exec labprobe-hub python /app/hub.py status
docker exec labprobe-hub python /app/hub.py test-hub
```

## 配对与 Token

首次启动日志显示有效期 10 分钟、只能使用一次的 APP 和 Agent 配对码：

```sh
docker logs labprobe-hub
```

APP 在原 Token 输入框填写 `APP-123456`，连接时自动换取独立 Client Token并用 Android Keystore保存。Agent 使用 `AGT-123456`。Hub 只保存 Token 哈希，连续错误配对会限流。

```sh
docker exec labprobe-hub python /app/hub.py pairing-code --role agent
```

可通过 `GET /api/clients` 查看客户端、`DELETE /api/clients/{clientId}` 单独吊销。旧 `APP_TOKEN`、`HOOK_TOKEN` 保持兼容。

## 同步协议

旧 API 不变，新 APP 使用：

- `GET /api/sync/snapshot`：完整状态、关注设备、在线设备、事件。
- `GET /api/sync/changes?since=REVISION`：按 sequence 返回新增、更新、离线和删除。
- `GET /api/sync/revision`：轻量 revision 校准。

设备、事件和状态与 revision 在同一 SQLite 事务中写入。APP首次、重连、前台恢复、网络切换和每 5 分钟完整校准，其余刷新仅应用增量。

## 锐捷 Rust Agent

在 Hub 创建 Agent 配对码后执行：

```sh
wget -O /tmp/labprobe-install.sh https://lab.net86.dynv6.net:27772/agent/install.sh \
&& sh /tmp/labprobe-install.sh
```

安装器兼容 BusyBox ash，会检测锐捷环境、CPU、空间、Hub和SHA256。下载 Rust 程序时优先使用 `curl --progress-bar --fail --location`，否则使用带默认进度输出的 BusyBox `wget`；不会使用静默参数，并会显示下载完成大小或明确的失败原因。首次安装只询问是否安装、自动发现的Hub是否正确、Agent配对码和最终确认。Rust接管 `dev_sta/user_list` 采集、上线/离线事件、IPv6邻居、端口映射、重试与日志；Shell只负责安装、启动和卸载。

```sh
labrelay doctor
labrelay status
labrelay test-hub
sh /tmp/labprobe-install.sh upgrade
sh /tmp/labprobe-install.sh repair
sh /tmp/labprobe-install.sh re-pair
sh /tmp/labprobe-install.sh uninstall
```

Hub通过 `LOG_LEVEL`、`LOG_RETENTION_DAYS` 控制日志级别和保留天数，并自动脱敏 Token。Rust日志默认位于 `/tmp/labprobe/labrelay-agent.log`。

## 更新仓与发版文件

Hub 从统一的 `UPDATE_REPOSITORY_ROOT` 读取 Rust `latest.json`，APP 评分详情页可查询 Agent 当前版本并经 Hub 下发更新指令。Agent 会下载最新 `install.sh`，再由安装脚本按 arm64/amd64 下载对应程序、显示进度并校验 `checksums.txt`。

`scripts/build_update_bundle.py` 会生成同一份可上传到本地、GitHub 和 Lucky 的目录：

```sh
python scripts/build_update_bundle.py \
  --app-apk LabProbeApp.apk --app-version-name 0.10.0-alpha1 --app-version-code 126 \
  --agent-arm64 labrelay-linux-arm64 --agent-amd64 labrelay-linux-amd64 --agent-version 0.2.0 \
  --output update-bundle
```

输出固定为 `app/update.json`、版本化 APK、`agent/latest.json`、`agent/install.sh`、两个架构程序和 `agent/checksums.txt`。JSON 中 Lucky 为主地址、GitHub Release 为备用地址，SHA256、大小和更新内容保持一致。
