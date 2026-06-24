# labprobe-hub v0.6.4

本版新增锐捷 Agent 主动事件上报，解决记录页 IP / 信号 / 频段 / 在线时长缺失或乱填的问题。

## 主要变化

- 新增 `POST /hook/ruijie/device_event`
- 保存锐捷 `watch_devices.sh` 主动上报的完整事件字段
- `device_online` 记录 IP / rssi / band / rxrate / ssid
- `device_offline` 记录最后 IP / 最后信号 / 在线时长
- 快照推断仍保留兜底，Agent 事件优先
- VPN / STUN 继续按 service 分类保存
- Router WAN IPv6 stale 机制保留
- Geo 仍只返回本地标记 / 运营商 / ASN，不返回城市

## 锐捷脚本

`scripts/ruijie_labprobe_install.sh` 会安装：

- `/etc/labprobe/push_devices.sh`：每分钟推送终端快照
- `/etc/labprobe/push_router_wan6.sh`：每分钟推送 pppoe-wan IPv6
- `/etc/labprobe/watch_devices.sh`：5 秒轮询关注设备，上下线时主动推送 device_event

默认关注：

- 华为Mate60：`24:1a:e6:bb:16:d9`
- iQOO Neo3：`da:1f:85:0c:19:fc`

如需改设备，编辑 `/etc/labprobe/watch_devices.sh` 里的 `DEVICES` 行。
