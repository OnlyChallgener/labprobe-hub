# labprobe-hub v0.7.2

更新：
- 每日总结聚合增强：统计上线、下线、VPN/STUN、DDNS、备注。
- 终端情况按设备聚合，返回累计在线时长、上线次数、下线次数、最后 IP、最后信号。
- VPN/STUN 和网络变化保留服务名与地址字段，方便 APP 原样展示与复制。
- 继续兼容 Lucky / OpenVPN / EasyTier 的钉钉 text.content Webhook 格式。


## v0.7.2
- 新增 device_archive.json 长期归档关注终端最后有效信息。
- 离线超过半小时后仍保留最后 IP、SSID、频段、速率、信号、上线时间。
- /api/devices 返回 watched 视图时自动补齐离线设备历史字段。


## v0.7.2
- /api/status 会从最近 VPN/STUN 事件修复当前地址状态。
- Webhook 同地址不变化时，也能保证首页当前地址列表不丢。
