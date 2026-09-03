# LabProbe Hub 0.11.5

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

推荐一律使用请求头传递 Token：APP 使用 `Authorization: Bearer <APP_TOKEN>`，Agent 与脚本使用 `X-LabProbe-Token`。URL 查询参数形式仅作兼容保留，命中时 Hub 会在日志记录弃用告警，后续版本将移除；新增接入请勿使用。

轮换 Token 可零停机：把旧值填入 `APP_TOKEN_PREVIOUS`（或 `HOOK_TOKEN_PREVIOUS`），带新值重启 Hub，更新所有客户端后再删除 PREVIOUS 变量并重启。Hub 对连续 Token 认证失败有防爆破限流（同一来源 10 分钟内失败 15 次将临时拒绝 10 分钟），正常客户端不受影响。

## 同步协议

旧 API 不变，新 APP 使用：

- `GET /api/sync/snapshot`：完整状态、关注设备、在线设备、事件。
- `GET /api/sync/changes?since=REVISION`：按 sequence 返回新增、更新、离线和删除。
- `GET /api/sync/revision`：轻量 revision 校准。

设备、事件和状态与 revision 在同一 SQLite 事务中写入。APP首次、重连、前台恢复、网络切换和每 5 分钟完整校准，其余刷新仅应用增量。

## AI 助手

AI API Key 由 Hub 加密托管，APP 不保存原文。首次配置时若没有单独设置 `LABPROBE_AI_MASTER_KEY`，Hub 会基于必填的 `APP_TOKEN` 安全派生凭证加密密钥，因此不会再因缺少额外环境变量拒绝 DeepSeek 配置。轮换 `APP_TOKEN` 时先把旧值临时放入 `APP_TOKEN_PREVIOUS`；Hub 在读取或使用 AI 配置时会自动用新 Token 重加密，确认配置显示可用后即可移除旧值并重启。DeepSeek 默认使用官方兼容地址 `https://api.deepseek.com` 与模型 `deepseek-v4-flash`。`GET /api/ai/usage` 同时返回今日、累计和最近单次任务 Token 明细；每次对话任务记录模型、输入、输出、总 Token 以及成功/失败状态。

AI 对话、工具确认、每日记录和 Token 统计均由 Hub 提供。APP 不保存 API Key 原文，涉及路由器写入的指令仍需在 APP 内二次确认。

助手能力按域组织，写入操作一律需 APP 确认：

- **relay 域**：查询 Agent 状态、新增/删除 STUN 穿透规则、下发 Agent 升级指令。
- **router 域**：查询路由器状态与防火墙/端口映射，创建/删除/启停 IPv6 端口映射。
- **app 域**：让 APP 跳转页面、触发完整同步（以 `clientAction` 返回给 APP 本地执行）。
- **扩展接口**：新能力域通过 `assistant.extend.register_domain(hub, specs, handlers, previews)` 在 `hub_entry` 安装阶段注册，无需修改 assistant 核心；执行与确认策略与内置工具完全一致。


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
  --agent-arm64 labrelay-linux-arm64 --agent-version 0.2.8 \
  --output update-bundle
```

输出固定为 `app/update.json`、版本化 APK、`agent/latest.json`、`agent/install.sh`、ARM64 Agent 程序和 `agent/checksums.txt`。JSON 中 Lucky 为主地址、GitHub Release 为备用地址，SHA256、大小和更新内容保持一致。


## 测试发布（test-bundle tag）

三端共用一个专用测试 tag：`test-bundle/<日期-序号>`。同名 tag 同时推送到 `labprobe-hub` 和 `LabProbeApp` 两个仓库，即触发三套测试构建，全部发布为 prerelease，不覆盖正式镜像和正式 Release：

```sh
TAG=test-bundle/20260828-1
git tag "$TAG" && git push origin "$TAG"        # 本仓库：Hub 测试镜像 + LabRelay 预发布
cd ../LabProbeApp
git tag "$TAG" && git push origin "$TAG"        # APP 测试 APK（同一发布签名）
```

产出：

- **Hub 测试镜像**：`<DOCKERHUB用户>/labprobe-hub:test-<tag后缀>`（如 `test-20260828-1`），只推该 tag，不动 `latest`。
- **LabRelay**：本仓库 GitHub prerelease 附 `labrelay-linux-arm64`、`install.sh`、`latest.json`、`checksums.txt` 与完整 tar 包；`latest.json` 内的下载地址指向该测试 Release，安装脚本会校验 SHA256。
- **APP**：`LabProbeApp` GitHub prerelease 附 `LabProbe-v<版本>-build<码>-test.apk`，与正式版同签名可直接覆盖安装；如需原地升级，先在测试分支把 `versionCode` +1 再打 tag。

测试 tag 可指向任意分支提交（不要求在 main 历史内），也不做正式发布的 tag/版本一致性检查；正式流水线（`v*` 与 `v*-build*` tag）不受影响。
