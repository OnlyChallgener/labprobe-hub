# LabProbe Hub 0.9.8 + LabRelay 0.2.9

目标分支：`codex/router-rpc-v098-relay-v029`

## 版本

- Hub：`0.9.8`
- LabRelay：`0.2.9`
- Android 配套：`0.10.11` / build `141`

## 最终架构

```text
APP现有页面 → Hub 0.9.8 → 锐捷/Reyee eWeb RPC
                         ↘ Relay：IPv6映射、IPv6邻居、Shell补充
```

Hub 直接更新原有接口：

```text
/api/router/dashboard
/api/devices
```

所以 APP 的路由器状态页和终端列表不用重做，只更换数据来源。终端 IPv6 仍由 Relay 邻居数据按 MAC 合并。

Hub 只开放白名单业务接口，不开放任意 `method/module` 代理。路由器密码 AES-GCM 加密保存在 `config/router_eweb.json`；sid/stok 只保存在内存，不返回 APP，也不写普通日志。

## Docker 部署（推荐 host 网络）

```bash
git fetch origin
git checkout codex/router-rpc-v098-relay-v029
cp .env.example .env
```

编辑 `.env`：

```dotenv
APP_TOKEN=请使用长随机字符串
HOOK_TOKEN=请使用另一条长随机字符串
ROUTER_EWEB_URL=http://192.168.5.1
ROUTER_SESSION_TIME=3600
ROUTER_RPC_PRIMARY=true
ROUTER_DASHBOARD_POLL_SEC=3
ROUTER_DEVICE_POLL_SEC=5
ROUTER_CONFIG_KEY=请使用长随机字符串
```

`ROUTER_EWEB_PASSWORD` 可以留空，安装 APP 后在“路由器功能”右侧的小设置图标中输入管理密码并测试连接。

启动：

```bash
docker compose -f docker-compose.host.yml up -d --build
docker logs -f labprobe-hub
```

测试：

```bash
curl -H "Authorization: Bearer 你的APP_TOKEN" \
  http://127.0.0.1:58443/api/router/capabilities

curl -H "Authorization: Bearer 你的APP_TOKEN" \
  http://127.0.0.1:58443/api/router/dashboard
```

网页允许的会话范围为 `600-7200` 秒。RPC遇到 HTTP `401/403` 时，Hub会清除旧会话、重新登录，并将原请求最多重试一次。

## 路由器功能 API

### 数据

```text
GET /api/router/dashboard
GET /api/devices
GET /api/router/firewall
GET /api/router/port-mapping
GET /api/router/upnp
GET /api/router/ddns
GET /api/router/diagnostic
```

### 操作

```text
PUT    /api/router/config
POST   /api/router/firewall/rules
PUT    /api/router/firewall/rules/{uuid}
PATCH  /api/router/firewall/rules/{uuid}/enabled
DELETE /api/router/firewall/rules/{uuid}
POST   /api/router/firewall/reorder

POST   /api/router/port-mapping
PUT    /api/router/port-mapping/{ruleName}
DELETE /api/router/port-mapping/{ruleName}

PUT    /api/router/upnp
POST   /api/router/ddns
PUT    /api/router/ddns/{serviceId}
DELETE /api/router/ddns/{serviceId}
POST   /api/router/diagnostic
```

所有写操作统一执行：

```text
读取最新配置 → 写入 → 清短缓存 → 再GET验证 → 返回最新状态
```

网络超时不会盲目重复写入。

## 数据同步策略

```text
路由器状态：Hub每3秒RPC同步
终端列表：Hub每5秒RPC同步
手动刷新：立即绕过短缓存
终端IPv6：Relay继续低频补充
历史与离线事件：Hub继续持久化
```

当 `ROUTER_RPC_PRIMARY=true` 时，旧 Relay 路由器状态推送会被忽略，避免覆盖 Hub 直接获取的新数据；Relay 的 IPv6 邻居和 6to6 数据仍正常接收。

## Relay 构建

```bash
cd labrelay
cargo build --release
grep '^version' Cargo.toml
# version = "0.2.9"
```

Relay继续负责：

- IPv6 / 6to6 映射
- 终端 IPv6 邻居补充
- 路由器 RPC 不提供的 Shell 状态
- Agent 更新、清理和备用通道

## CI

`.github/workflows/router-rpc-ci.yml` 自动执行：

- Python语法编译
- 路由器配置加密与会话单元测试
- Docker镜像构建
- Relay版本校验
