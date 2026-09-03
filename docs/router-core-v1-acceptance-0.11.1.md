# Router Core v1 生产接管验收报告（Hub 0.11.1）

## 1. 结论

Router Core v1 已在 `refactor/router-core-v1` 完成生产接管。LabProbeApp 与 LabRelay 未修改。

生产路由数据链路现为：

```text
BE72 eWeb auth / signed CMD / WebSocket
  -> ReyeeSessionManager
  -> ReyeeRpcClient
  -> ReyeeEWebDriver
  -> RouterService / RouterRealtimeEngine
  -> Hub API / WSS
  -> LabProbeApp
```

LabRelay 继续负责 DDNS 地址上报、STUN、WireGuard、IPv6/端口映射扩展、路由器侧防火墙自动化和 Agent 状态。RouterLite 只保留现有 Relay demand/ack 控制端点，不再接收或发布 Router/Device 实时数据，因此生产链路不存在双实时数据源。

## 2. 根因

1. Router Core 的登录实现没有遵循 BE72 已验证的 eWeb 登录协议：字段、AES 密钥使用方式、序列号会话 Cookie 和 SID 有效性校验不完整。
2. `/api/cmd` 缺少 BE72 所需的请求签名，部分 RPC 又把 module 字符串直接作为 params 发送，真实硬件会拒绝或无法解析。
3. Core 实例虽然已创建，但 Dashboard 路由、Realtime WSS 和设备实时发布仍有旧 RouterLite/旧 Hub 路由参与，生产所有权没有真正收口。
4. WebSocket 监控器向路由器发送未经固件验证的 JSON keepalive，且 fast 数据停滞时不能足够快地重连。
5. APP 所需的 NAT/Beta 状态查询路由在 Core Blueprint 中不完整。

这组问题会造成 Hub WSS 可以完成连接并发送 `ready`，但 BE72 的 `fast` 帧未进入 APP 所订阅的 Router Core 实时引擎，最终表现为“实时链路已连接，等待首帧数据”。

## 3. 修改内容

### BE72 Driver

- 登录使用固件实际载荷：`password/time/encry/limit/setInit`。
- 使用动态页面密钥；页面未内嵌密钥的 BE72 固件使用其浏览器包固定 AES 密钥。
- 使用 `SN=SID` Cookie，并通过 overview API 验证 SID 后才建立会话。
- `/api/cmd` 使用紧凑 JSON 原文、正确的 module/data/noParse envelope，以及 `Content-Accept`/`Contents-Accept` 签名。
- 保留单次重新认证；签名错误不会被误判为会话过期并进入重复登录。
- 设备、Dashboard、IPv6、端口映射、UPnP、防火墙、DDNS、NAT、自检与 Beta 查询迁移到旧 main 已验证的原生 eWeb module。
- 配置写入后读取真实状态，避免只返回乐观结果。

### Router Core 生产所有权

- `/api/router/dashboard` 与 refresh 由 Core Blueprint 唯一注册。
- RouterTaskManager 直接持有 Core Driver。
- Hub WSS 的 Router 数据服务绑定 `RouterRealtimeEngine`。
- BE72 WebSocket `fast` 处理器直接绑定 `RouterRealtimeEngine.accept_router_fast`。
- 设备实时轮询直接发布到 Core Engine；Relay push 只校验并返回控制应答。
- APP contract 保持 `uploadBps`、`downloadBps`、`cpuPercent`、`memoryPercent`、`sampleEpochMs`，APP 无需修改。
- fast 流启动或运行中超过 8 秒无数据即重连，重试间隔不超过 2 秒。

### API 覆盖

Core 负责 Dashboard、Status、Realtime、Devices、IPv6 status/config/clients、Port Mapping、UPnP、Firewall、DDNS、Diagnostic、NAT、Beta 和 Tasks。防火墙自动化、STUN、WireGuard、Relay Agent/端口映射扩展端点保持原职责和原路径。

## 4. 修改文件

- 启动与生产路由：`hub.py`、`hub_entry.py`、`router_compat.py`
- Core Driver：`router_core/driver/reyee_session.py`、`router_core/driver/reyee_rpc.py`、`router_core/driver/reyee.py`
- Core 服务：`router_core/cache/router_cache.py`、`router_core/realtime/router_realtime.py`、`router_core/service/router_service.py`、`router_core/service/blueprint.py`
- 实时同步：`router_ws_patch.py`、`router_device_live_sync_patch.py`、`router_lite_realtime_patch.py`
- 发布配置：`.github/workflows/ci.yml`、`.github/workflows/docker.yml`、`docker-compose.host.yml`、`docker-compose.bridge.yml`、`CHANGELOG.md`
- 测试：`tests/test_reyee_session_and_rpc.py`、`tests/test_router_core_production_cutover.py`、`tests/test_router_core_skeleton.py`、`tests/test_router_dashboard.py`、`tests/test_router_lite_realtime_patch.py`、`tests/test_hub_realtime_wakeup.py`

## 5. 验收结果

- 本地 Python 编译：通过。
- 本地 Hub 测试：`360 passed`。
- [GitHub Hub CI #32741607425](https://github.com/OnlyChallgener/labprobe-hub/actions/runs/32741607425)：通过；包含 Python 3.12 安装、源码编译、全量测试和版本一致性检查。
- [GitHub Docker Image #32741607435](https://github.com/OnlyChallgener/labprobe-hub/actions/runs/32741607435)：通过；包含相同 Hub 测试、AMD64/ARM64 构建和 Docker Hub 推送。
- 推送镜像：`onlychallgener/labprobe-hub:0.11.1`、`onlychallgener/labprobe-hub:v0.11.1`、`onlychallgener/labprobe-hub:latest`。
- 自动化验收覆盖：真实登录 wire contract、SID Cookie、CMD 签名、RPC module envelope、API 路由所有权、BE72 fast 帧到 Hub WSS 的首帧字段、Relay 控制端点不再成为数据源。

本次按项目确认，以 GitHub CI 和 Docker 多架构构建通过作为发布验收，不声明额外的现场真机测试结果。

## 6. 部署升级

生产 Compose 应使用不可变版本，不使用 `latest`：

```yaml
services:
  labprobe-hub:
    image: onlychallgener/labprobe-hub:0.11.1
    container_name: labprobe-hub
    network_mode: host
    restart: unless-stopped
```

如果使用仓库提供的 Compose，也可以在 `.env` 中固定：

```dotenv
LABPROBE_IMAGE=onlychallgener/labprobe-hub:0.11.1
```

保留当前 `APP_TOKEN`、`HOOK_TOKEN`、MQTT、`ROUTER_EWEB_URL`、`ROUTER_EWEB_PASSWORD`、volumes 和 `config/config.yaml`，只替换镜像并重建 Hub 容器：

```bash
docker compose pull labprobe-hub
docker compose up -d --no-deps --force-recreate labprobe-hub
docker compose ps
docker compose logs --tail=200 labprobe-hub
```

无需清理 `data`、`config`、`backups` 或 `logs`，也无需重新部署 App、Relay 或 MQTT。

## 7. 部署后检查

1. Hub 版本显示 `0.11.1`。
2. `/api/router/status` 显示 Core Driver 会话与路由连接正常。
3. `/api/router/realtime` 返回 `uploadBps`、`downloadBps` 和 `sampleEpochMs`。
4. APP 连接 WSS 后收到 `type=router` 首帧，不再停留在“等待首帧数据”。
5. Dashboard、设备、IPv6、端口映射、UPnP、防火墙、DDNS、NAT、自检与 Beta 状态可正常读取；配置操作按需验证写后读回。

## 8. 风险说明

- CI 已验证协议、路由所有权、数据契约和镜像构建，但无法代替特定现场网络对 BE72 固件版本、密码和可达性的验证。
- 如果 `ROUTER_EWEB_URL` 或 `ROUTER_EWEB_PASSWORD` 错误，Core 不会把 Relay 当作 Router 数据 fallback；这是单一数据源设计的预期行为。
- `latest` 同时发布仅用于现有部署兼容；生产 Compose 应固定 `0.11.1`，便于回滚和定位。
- 回滚时只需把镜像标签改回原版本并 force-recreate，持久化目录无需改动。
