# LabProbe Hub v0.7.9

修复：

- GET 调试接口鉴权兼容：`/api/devices`、`/api/ipv6-neighbors`、`/api/status` 可用 `APP_TOKEN` 或 `HOOK_TOKEN` 查询。
- 支持 Header：`Authorization: Bearer <token>`、`X-LabProbe-Token`、`X-Hook-Token`、`X-Api-Token`、`X-API-Key`。
- 支持 URL 参数：`?token=<token>`、`?key=<token>`。
- `/api/devices` 返回前按 MAC 合并 `device_archive.json` 里的 IPv6 邻居归档。
- 对每台设备额外输出 `ipv6` / `ipv6Address` / `globalIpv6`，兼容不同 APP 版本。

部署说明：

1. 不要删除 `/docker/labprobe-hub/data/`。
2. 用本包重新构建 Hub 镜像或替换仓库代码后通过 GitHub Actions 发版。
3. 路由器侧继续使用 `push_ipv6_neighbors.sh`，推送到 `/api/router/push`，`type=snapshot`。
