# LabProbe Hub

LabProbe Hub 是给 **LabProbe / 极客网探** 使用的轻量家庭网络状态同步服务。

它的定位很简单：

- 接收 Lucky Webhook，例如 STUN / DDNS 地址变化。
- 手动刷新时检测 NAS 出口 IPv4 / IPv6。
- 可选读取锐捷路由器终端 API，显示关注设备在线状态。
- 给 Android APP 提供统一 JSON 接口。
- 不提供 SSH 远程执行接口，避免安全风险。

---

## 1. 项目文件

```text
labprobe-hub/
├── Dockerfile
├── requirements.txt
├── hub.py
├── config.example.yaml
├── docker-compose.yml
├── scripts/test-webhook.sh
└── .github/workflows/docker.yml
```

---

## 2. Docker Hub 自动构建

在 GitHub 仓库设置：

### Variables

```text
DOCKERHUB_USERNAME = 你的 Docker Hub 用户名
```

### Secrets

```text
DOCKERHUB_TOKEN = 你的 Docker Hub Personal Access Token
```

然后推送到 `main` 分支，GitHub Actions 会自动构建并推送：

```text
你的DockerHub用户名/labprobe-hub:latest
你的DockerHub用户名/labprobe-hub:0.1.0
```

---

## 3. 绿联 NAS 部署

SSH 进入绿联 NAS：

```bash
mkdir -p /volume1/docker/labprobe-hub/data
cd /volume1/docker/labprobe-hub
```

如果你的绿联 Docker 目录不是 `/volume1/docker`，换成你的实际路径。

复制示例配置：

```bash
nano config.yaml
```

可以从 `config.example.yaml` 修改。

新建 `docker-compose.yml`：

```yaml
services:
  labprobe-hub:
    image: 你的DockerHub用户名/labprobe-hub:latest
    container_name: labprobe-hub
    network_mode: host
    restart: unless-stopped
    environment:
      - APP_TOKEN=改成你的APP访问Token
      - HOOK_TOKEN=改成你的LuckyWebhookToken
      - PORT=58443
      - TZ=Asia/Shanghai
      - CONFIG_PATH=/app/config/config.yaml
      - DATA_DIR=/app/data
    volumes:
      - ./data:/app/data
      - ./config.yaml:/app/config/config.yaml:ro
```

启动：

```bash
docker compose up -d
```

查看日志：

```bash
docker logs -f labprobe-hub
```

健康检查：

```bash
curl http://127.0.0.1:58443/health
```

---

## 4. Lucky Webhook 配置

如果 Lucky 和 Hub 都在绿联 NAS 上，而且 Lucky 能访问宿主机网络，Webhook 地址填：

```text
http://127.0.0.1:58443/hook/lucky?token=你的LuckyWebhookToken
```

如果 Lucky 在 Docker 里，`127.0.0.1` 访问不到 Hub，就改成绿联 NAS 内网 IP：

```text
http://192.168.5.50:58443/hook/lucky?token=你的LuckyWebhookToken
```

### STUN / WireGuard 地址变化请求体

```json
{
  "source": "lucky",
  "type": "stun_changed",
  "name": "WireGuard",
  "address": "#{ipAddr}"
}
```

### DDNS 地址变化请求体

```json
{
  "source": "lucky",
  "type": "ddns_changed",
  "name": "net86.dynv6.net",
  "domain": "net86.dynv6.net",
  "address": "#{ipAddr}"
}
```

Lucky 里建议开启：

```text
仅在地址与上次不同时触发 Webhook
```

---

## 5. API

### 健康检查

```bash
curl http://127.0.0.1:58443/health
```

### 当前状态

```bash
curl -H "Authorization: Bearer 你的APP访问Token" \
  http://127.0.0.1:58443/api/status
```

### 事件记录

```bash
curl -H "Authorization: Bearer 你的APP访问Token" \
  "http://127.0.0.1:58443/api/events?after=0"
```

### 关注终端

```bash
curl -H "Authorization: Bearer 你的APP访问Token" \
  http://127.0.0.1:58443/api/devices
```

### 最新日报

```bash
curl -H "Authorization: Bearer 你的APP访问Token" \
  http://127.0.0.1:58443/api/daily/latest
```

---

## 6. Lucky 反代给 APP 访问

推荐由 Lucky 反代到 Hub：

```text
https://net86.dynv6.net/labprobe  →  http://127.0.0.1:58443
```

如果 Lucky 支持路径重写，需要把：

```text
/labprobe/api/status
```

转成：

```text
/api/status
```

APP 里填写：

```text
Agent 地址：https://net86.dynv6.net/labprobe
访问令牌：APP_TOKEN
```

---

## 7. 锐捷路由器 API 接入

先把 `config.yaml` 里的 router 改为 enabled：

```yaml
router:
  enabled: true
  api_url: "http://192.168.5.1/你的终端列表API"
  method: "GET"
  headers:
    Authorization: "Bearer your-token"
  schema:
    items_path: "data.list"
    mac_fields: ["mac", "macAddr", "macAddress"]
    name_fields: ["name", "hostName", "hostname", "deviceName"]
    ip_fields: ["ip", "ipv4", "ipAddr"]
    ipv6_fields: ["ipv6", "ipv6Addr"]
    online_fields: ["online", "isOnline", "status"]
    online_values: [true, 1, "1", "online", "ONLINE", "on", "connected"]
```

然后配置关注终端：

```yaml
watched_devices:
  - name: "小米 14 Pro"
    mac: "AA:BB:CC:DD:EE:FF"
  - name: "Mate60"
    mac: "11:22:33:44:55:66"
```

如果你把锐捷 API 返回 JSON 示例发给我，可以把 `items_path` 和字段名直接调准。

---

## 8. 数据持久化

数据保存在：

```text
./data/state.json
./data/events.json
./data/last_devices.json
```

事件最多保留最近 1000 条。

---

## 9. 安全建议

- `APP_TOKEN` 和 `HOOK_TOKEN` 分开设置。
- Lucky Webhook 尽量走 NAS 内网地址，不要公网暴露 Hook。
- 公网访问建议只通过 Lucky HTTPS 反代。
- Hub 不提供 SSH 执行接口。
- 不要把路由器 Cookie / Token 提交到 GitHub。

