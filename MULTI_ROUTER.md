# 同一 Hub 入口接入多台路由器

这是可选部署模式；原来的 `hub_entry.py`、单路由 Compose 和数据目录保持原样。本模式为每个明确的 `routerId` 启动一份单路由 Hub worker，前面的 nginx 以 `/r/{routerId}/` 转发 HTTP、SSE 与 WebSocket。旧根路径转发到 `defaultRouterId`，所以现有 App 的 Hub URL 可以暂时不变。

## 隔离边界

每个 worker 有独立的 `config/`、`data/`、`backups/`、`logs/`、SQLite 数据库、MQTT topic 前缀、APP_TOKEN 和 HOOK_TOKEN。每台路由的 eWeb 目标以网关配置为准；复制旧的受管配置或在 App 中修改地址都不能把 worker 指到另一台路由。worker 与路由列表服务仅监听 `127.0.0.1`。跨 worker 使用另一路由的 APP/HOOK 令牌会被拒绝；未知 `/r/...` 路径返回 404。路由 ID 必须在配置中显式给定，不能从名称或 IP 推断，且启用后不宜更改。本配置只接受 `platform: reyee`，每台锐捷都需要独立的 eWeb 地址。相同 eWeb URL 会被拒绝，防止两个 worker 错控同一台设备。若两处网络使用相同私网 IP，应为异地路由建立单独的本机隧道端口；示例中的 `127.0.0.1:18082` 就是第二台路由的入口。

`GET /api/routers` 仅接受默认 worker 的 APP_TOKEN，返回 `routerId`、`name`、`site`、`model`、`platform`、`online`、`basePath`，有设备缓存时还返回 `deviceCount`。它不会返回 worker token。App 在访问其他路由的 `/r/{routerId}/api/...` 时，应使用该 worker 自己的 APP_TOKEN。Agent 的 Hub URL 也必须指向对应的 `/r/{routerId}`，并使用该 worker 的 HOOK_TOKEN。

## 异地路由的链路前提

Hub worker 必须能从 NAS 容器内访问各自的 eWeb 入口。用户已确认 NAS 能访问两台异地锐捷的管理地址，因此示例中两台都使用 `ewebTransport: direct` 和各自的地址。若将来两处网络使用相同私网 IP，可选用 `ewebTransport: local_tunnel`，把第二台的入口设为 NAS 本机独立端口（例如 `http://127.0.0.1:18082`），由现场 VPN 或持续运行的反向 TCP 隧道负责转发；网关本身不创建或重连隧道。`local_tunnel` 强制使用回环地址和显式端口，两台 worker 不能共用同一入口。

配置检查 `--check` 只验证字段；`--probe` 从容器网络逐台连接 eWeb TCP 端口，任一不可达时返回非零状态。路由列表的 `online` 同时要求 Hub worker 健康和该 eWeb 端口可达，并单独返回 `hubOnline`、`ewebReachable`。TCP 可达不等于 eWeb 登录成功，切换现场前还需在对应工作区验证路由状态与设备数据。若 NAS 将来无法到达其中一台路由的 eWeb，本模式不能完成那台异地锐捷的全部管理功能。

## 准备与启动

1. 将 `multi-router.example.yaml` 复制为 `multi-router.yaml`，填写公开 Hub URL、稳定 routerId、worker 端口和每台路由的名称。若更改公开监听端口，也同步设置 Compose 的 `MULTI_ROUTER_GATEWAY_PORT`，让容器健康检查访问正确端口。容器内 `storageRoot` 保持 `/app/multi`；Compose 把本机 `multi-data/` 挂到这里。
2. 将 `multi-router.env.example` 复制为 `multi-router.env`，为每台路由设置四个互不相同、至少 24 字符的 APP/HOOK 令牌。若默认路由要沿用旧 App，可将旧 APP_TOKEN 填给默认 worker，但不要复用为其他 worker 的令牌。
3. 若锐捷密码仅通过旧环境变量 `ROUTER_EWEB_PASSWORD` 配置，可给它加 `ewebPasswordEnv: HOME_ROUTER_PASSWORD` 并在 `multi-router.env` 中设置；若旧 `router_eweb.json` 使用不同的 `ROUTER_CONFIG_KEY` 加密，则配置 `routerConfigKeyEnv` 指向该密钥。新配置不会自动读取旧进程的路由凭据。
4. 首先用 `docker compose -f docker-compose.multi.yml run --rm labprobe-multi-router python /app/multi_router_gateway.py --check` 校验配置，再用同一命令改为 `--probe` 检查两台路由的 eWeb 入口。检查不会启动 worker 或修改旧数据。
5. 如需保留单路由历史，先停旧 Hub 并备份，再把旧 `config/`、`data/`、`backups/` 中需要保留的内容复制到默认 worker 的 `multi-data/{routerId}/` 对应目录。此项目不会自动迁移或覆盖现场数据。保持原 MQTT broker 运行，停掉占用同一公开端口的旧 Hub 后，运行 `docker compose -f docker-compose.multi.yml up -d --build`。

请先在测试环境验证每台 Agent 的 hook 入库、App 读取、实时消息及 WebSocket，再切换生产入口。本仓库只提供配置与代码，不会自动部署。

## 当前限制

MQTT topic 已按路由分开，然而现有 Mosquitto 仍使用同一组 broker 用户名/密码且没有按 topic 的 ACL。互不信任的租户需要额外配置每路由 MQTT 账号/ACL，或关闭 broker 对外访问。共享 NAS 上的多个自有路由可先按上述方式做数据和 API 隔离。更换路由 ID 会改变路径、存储目录和 topic，必须作为显式迁移处理。
