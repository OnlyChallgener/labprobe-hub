# LabProbe Hub v0.7.5 buildfix31

- 修复 v0.7.4 中 router push 把 NAS IPv6 清空的问题。
- /api/router/push 只更新 router.*，不再触碰 nas.exitIpv4 / nas.exitIpv6。
- NAS IPv6 与路由 WAN6 即使相同，也保留 NAS IPv6；这是桥接/同出口场景下的正常结果。
- 当 NAS 出口字段为空时，自动触发后台刷新，恢复 NAS IPv4 / NAS IPv6。
