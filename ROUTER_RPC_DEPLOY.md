# LabProbe Hub 0.9.8 + LabRelay 0.2.9

目标分支：`codex/router-rpc-v098-relay-v029`

## 版本

- Hub：`0.9.8`
- LabRelay：`0.2.9`
- Android 配套：`0.10.11` / build `141`

## 架构

```text
APP → Hub 0.9.8 → 锐捷/Reyee eWeb RPC
                 ↘ Relay 仅保留 IPv6映射、IPv6邻居、Shell补充能力
```

Hub 只开放白名单业务接口，不开放任意 `method/module` 代理。
路由器密码加密保存在 `config/router_eweb.json`；sid/stok 只保存在内存，不返回 APP，也不写普通日志。

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
ROUTER_EWEB_PASSWORD=你的路由器管理密码
ROUTER_SESSION_TIME=3600
# 可选；建议填写独立随机值，用于加密本地路由器凭据
ROUTER_CONFIG_KEY=请使用长随机字符串
```

启动：

```bash
docker compose -f docker-compose.host.yml up -d --build
docker logs -f labprobe-hub
```

测试 Hub：

```bash
curl -H "Authorization: Bearer 你的APP_TOKEN" \
  http://127.0.0.1:58443/api/router/capabilities

curl -X POST \
  -H "Authorization: Bearer 你的APP_TOKEN" \
  http://127.0.0.1:58443/api/router/session/test
```

成功后会返回路由器 SN 和会话时间。网页允许的会话范围为 `600-7200` 秒。

## 路由器 API

### 数据

```text
GET /api/router/dashboard
GET /api/router/devices
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

每次写操作统一执行：

```text
写入 → 清除短缓存 → 再GET → 返回验证后的最新数据
```

HTTP `401/403` 会清除旧会话、重新登录，并将原请求最多重试一次。
普通网络超时不会盲目重复写入。

## Relay 构建

```bash
cd labrelay
cargo build --release
```

版本确认：

```bash
grep '^version' Cargo.toml
# version = "0.2.9"
```

Relay 继续负责：

- IPv6 / 6to6 映射
- 终端 IPv6 邻居补充
- 路由器 RPC 不提供的 Shell 状态
- Agent 更新、清理和备用通道

终端在线列表、实时网速、连接数不再依赖 Relay 完整推送。

## CI

分支已加入 `.github/workflows/router-rpc-ci.yml`，自动执行：

- Python 语法编译
- `tests/test_router_rpc.py`
- Docker 镜像构建
- Relay 版本校验
