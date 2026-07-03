# labprobe-hub v0.7.4

## v0.7.4 修复

- `/api/router/push` 只更新路由 WAN6 / 多 WAN6 列表，不再把路由侧 `wan_ipv6` 写入 NAS IPv6。
- 修复老状态里 NAS IPv6 被路由 WAN6 污染的问题：如果二者完全相同，会清空 NAS IPv6，等待 Hub 后台重新探测。
- 支持 `router_wan6_list`，APP 可展示“主用 WAN / 备用 WAN”，普通页面不显示 br-lan/br-wan 等接口名。

