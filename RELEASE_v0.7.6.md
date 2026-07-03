# LabProbe Hub v0.7.6 buildfix32

## 修复

- NAS IPv4 / NAS IPv6 只由 Hub/NAS 自己检测，或由手动配置 `NAS_IPV4` / `NAS_IPV6` 指定。
- `/api/router/push` 只更新 `router.*`，不会写入或清空 `nas.exitIpv4` / `nas.exitIpv6`。
- Hub 检测 NAS 出口失败时保留旧值，避免 APP 中 NAS IPv6 / WireGuard 地址突然消失。
- 支持 `NAS_IPV6=2409:.../64` 这种带前缀写法，内部会自动去掉 `/64`。
- 检测顺序：手动配置 > curl 外网出口 > host 网络模式下本机全局地址。
