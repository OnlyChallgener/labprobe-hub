# Labprobe Hub v0.7.8 · IPv6 Hydrate 安全优化版

## 修复
- `/api/devices?view=online` 和 `/api/devices?view=watched` 返回前都会按 MAC 从 `device_archive.json` 合并 IPv6 邻居归档。
- 支持 Router Agent 直接上报 `ipv6_neighbors` 数组，也支持上报 `ip -6 neigh show` 文本。
- 新增 `/api/ipv6-neighbors` 调试接口，便于检查 Hub 是否已经保存 MAC → IPv6。
- 不再建议在 NAS 上直接替换运行容器内的 `hub.py`；请通过 Docker 镜像/源码包重新构建。

## 目标
路由器已经能查到：

```text
6c:1f:f7:76:71:04 → 2409:8a50:22d2:da10:38bf:efb4:10de:54d1
```

Hub 会保存到 `data/device_archive.json` 并在 APP 拉取设备列表时回填到 `ipv6List`。
