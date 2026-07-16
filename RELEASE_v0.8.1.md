# LabProbe Hub v0.8.1

- NAS IPv6 主地址改为优先采用 Hub 主机实际 IPv6 路由源地址，避免旧 EUI-64 地址误选。
- 路由器发现的 NAS IPv6 仅作为交叉验证，不再覆盖 Hub 本机主地址。
- 修正稳定随机 IID 被误判为临时 IPv6 的逻辑。
- 按 MAC 持久化统计当日在线时长；有线设备无 activeTime 时也可按快照累计。
