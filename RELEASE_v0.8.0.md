# LabProbe Hub v0.8.0

本版本补齐终端流量字段，供 LabProbeApp 的设备卡片、设备详情和“今日流量”排行榜使用。

## 变更

- 将锐捷 `dailyUp` / `dailyDown` 映射为 `todayUpload` / `todayDownload`。
- 将锐捷 `up` / `down` 映射为 `totalUpload` / `totalDownload`（路由器本次开机以来累计）。
- 同时输出 `todayTraffic`、`realtimeTraffic` 分组字段，兼容不同 APP 解析方式。
- 兼容 K/M/G、KB/MB/GB 和纯字节数值。
- 在线、关注、离线归档设备均保留流量字段；跨天时不会沿用昨天的今日流量。
- 不修改 WOL、事件、IPv6、Hub 鉴权和路由器推送方式。

## 返回示例

```json
{
  "todayUpload": 14742937,
  "todayDownload": 246320988,
  "totalUpload": 34330378,
  "totalDownload": 322625863,
  "todayTraffic": {
    "upload": 14742937,
    "download": 246320988
  },
  "realtimeTraffic": {
    "upload": 34330378,
    "download": 322625863
  }
}
```
