# LabProbe Hub v0.6.0

轻量 Flask Hub，用于接收锐捷终端列表、路由 WAN IPv6、Lucky Webhook，并为 LabProbe APP 提供状态接口。

## v0.6.0 更新

- 新增 `/api/geo?ip=`：Geo 分层识别。
  - 优先命中 `config.yaml` 的 `geo.local_prefixes` 本地前缀标记。
  - 其次通过公网 Geo 获取 ASN / 运营商 / 城市参考。
  - 城市只作为参考，运营商和本地标记优先级更高。
- 路由 WAN IPv6 同步失败时不再清空旧值，只标记为 stale/check_failed。
- 改进锐捷 WAN IPv6 推送脚本，空值不会覆盖旧地址。

## 重要配置：本地前缀标记

在 `/volume1/docker/labprobe-hub/config.yaml` 添加：

```yaml
geo:
  local_prefixes:
    - prefix: "2408:8252:3200:9231::/64"
      label: "家里路由前缀"
      location: "湖南衡阳"
      operator: "中国联通"
```

这样 DNS 查到你家 IPv6 前缀时，APP 会优先显示本地标记，而不是相信公网 Geo 的城市结果。

## 接口

- `GET /health`
- `GET /api/status`
- `GET /api/devices?view=online`
- `GET /api/events`
- `GET /api/geo?ip=2408:...`
- `POST /hook/ruijie/devices?token=...`
- `POST /hook/ruijie/router?token=...`
- `POST /hook/lucky?token=...`
