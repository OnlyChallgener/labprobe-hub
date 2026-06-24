# LabProbe Hub v0.5.0

家庭网络状态同步 Hub。

## 本版重点

- 接收锐捷终端列表：`/hook/ruijie/devices`。
- 接收路由 WAN IPv6：`/hook/ruijie/router`。
- 严格过滤非公网 IPv6：`fe80::/10`、`fd/fc`、`ff`、`::1`。
- 保存关注终端在线时长、离线发现时间、最后在线时间。
- NAS IPv4 / IPv6 出口多源检测。
- Lucky Webhook 过滤 token-only 错误事件。

## 绿联部署

```bash
cd /volume1/docker/labprobe-hub
docker compose pull
docker compose up -d
curl http://127.0.0.1:58443/health
```

## 锐捷脚本

见 `scripts/ruijie_labprobe_install.sh`。
