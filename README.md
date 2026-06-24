# LabProbe Hub v0.6.6

本版为 v0.8.0 APP 配套稳定版：

- 保留 /hook/ruijie/device_event。
- 保留每日总结和每日备注接口。
- 保留事件软删除。
- 在线时长文案统一为“小时/分/秒”。
- 继续保留路由 WAN IPv6 stale 机制和运营商识别。

升级：覆盖仓库后运行 Docker Actions，绿联执行 `docker compose pull && docker compose up -d`。
