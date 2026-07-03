# labprobe-hub v0.7.4

## v0.7.4 修复

- `/api/router/push` 只更新路由 WAN6 / 多 WAN6 列表，不再把路由侧 `wan_ipv6` 写入 NAS IPv6。
- 修复老状态里 NAS IPv6 被路由 WAN6 污染的问题：如果二者完全相同，会清空 NAS IPv6，等待 Hub 后台重新探测。
- 支持 `router_wan6_list`，APP 可展示“主用 WAN / 备用 WAN”，普通页面不显示 br-lan/br-wan 等接口名。



## NAS IPv6 手动固定（推荐）

如果 Docker 容器无法直接检测到 NAS 主机自己的 IPv6，可在 docker-compose 环境变量中加入：

```yaml
environment:
  - NAS_IPV6=2409:8a50:2e20:d210:9ffa:5687:75c2:2a79
  - NAS_IPV4=120.227.162.95
```

注意：路由器脚本推送的 `router_wan6` 只代表路由 WAN6，不会用于 NAS IPv6。
