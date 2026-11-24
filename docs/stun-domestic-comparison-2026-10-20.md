# STUN 国内网络入口对照（2026-10-20）

## 方法

在 NAS 使用同一条 WAN 的 IPv4 TCP 连接，每十秒发送一次标准 STUN Binding 请求；同时对照六个入口。记录 DNS、TCP 建连、逐次响应延迟、对端断开及 XOR-MAPPED-ADDRESS 是否变化。每入口仅维持一个探测连接，不转发业务流量。结果只适用于本次网络路径和观察窗口。

## 五分钟结果

| TCP 入口 | 响应中位数 | P95 | 观察结果 |
| --- | ---: | ---: | --- |
| turn.cloud-rtc.com:80 | 19.21 ms | 19.93 ms | 约 300 秒，30 次响应，端口一致，无断连 |
| turn.cloudflare.com:3478 | 184.62 ms | 191.16 ms | 约 306 秒，30 次响应，端口一致，无断连 |
| turn.cloudflare.com:80 | 180.99 ms | 184.07 ms | 约 306 秒，30 次响应，端口一致，无断连 |
| stun.sonetel.com:3478 | 186.23 ms | 186.23 ms | 一次响应后，约 10 秒遭重置 |
| stun.voip.blackberry.com:3478 | 220.43 ms | 227.42 ms | 六次响应后，约 62 秒遭重置 |
| fwa.lifesizecloud.com:3478 | 233.59 ms | 233.86 ms | 六次响应后，约 62 秒遭重置 |

前面单独的三分钟探测中，腾讯云入口同样得到 19 次连续响应且端口一致。原 Nextcloud 入口在 2/5/10 秒三个保活间隔下都在首次响应后重置，不继续列为首选。

## 采用方式和限制

按本次实测选择 `turn.cloud-rtc.com:80` 作为 Hub 新建与既有 TCP STUN 规则的首选。Cloudflare TURN 两个入口作为已验证的替代选项；没有实现自动服务器故障切换。WG 的 UDP STUN 入口保留原值。

候选来自 NATMap 项目维护者及协作者的服务列表：[公开 STUN 服务记录](https://github.com/heiher/natmap/issues/18)。腾讯云入口身份及能力以该项目的记录为线索，本次以实际 TCP 连通、交易号匹配和响应数据作为通过依据，不能视为供应商的长期服务承诺。

路由器上的最终连续观察单独保存于恢复副本的 `evidence/stun-domestic-router-summary.json`。短期稳定不等于地址永不改变；验收重点是排除此前持续每十几秒重连换端口的现象。
