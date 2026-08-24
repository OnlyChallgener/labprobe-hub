# Router Core v1 生产修复验收报告（Hub 0.11.2）

## 结论

Hub `refactor/router-core-v1` 继续以 `ReyeeEWebDriver → RouterRealtimeEngine → Hub WSS` 为唯一路由器实时主链。LabRelay 只保留 DDNS 地址探测、STUN、WireGuard、端口映射扩展、防火墙自动化和 Agent 运维职责。

本版本恢复 Router Core v1 接管后遗漏的原生 DDNS、2.4G/5G 温度、宽带凭据读取与 Agent 命令下发，并新增由 APP 经 Hub 管理路由连接配置的正式接口。

## 根因

1. V1 启动入口没有安装旧 main 已验证的宽带凭据/Agent 命令路由接线。
2. Core realtime 数值白名单遗漏 `temperature2gC`、`temperature5gC`，Dashboard 也没有合并已认证 eWeb WebSocket 快照。
3. 原生 DDNS 读取没有处理 BE72 返回 JSON 字符串或嵌套 `data.list` 的情况。
4. Agent 更新准备阶段重新写入默认更新源，而不是清单实际成功解析的 GitHub/镜像源；陈旧待领取命令还会阻塞后续更新和清理。
5. 宽带凭据接线覆盖 Relay Dashboard ACK 后，没有继续保留 Relay 所属的 WireGuard 扩展状态。

## 修改与职责边界

- Router Core 直接读取原生 DDNS，密码字段在返回 APP 前清空。
- BE72 `/ws` 双频温度进入 Core realtime，并由生产 Hub WSS 按 APP 字段输出。
- Dashboard 只合并同一个 Core Driver 持有的 WebSocket 快照，不新增第二数据源。
- 宽带账号密码优先由 Hub Router Driver 直接读取，只驻内存、不写日志、不持久化。
- Agent 更新与清理继续由 Relay 执行；Hub 只负责任务排队、状态与下载地址下发。
- Relay Dashboard 推送中的路由遥测继续被忽略，只接受 LabProbe DDNS 地址与 WireGuard 扩展状态。
- `GET/PUT /api/router/config` 只允许 APP Token 调用；密码加密落盘，GET 不回显明文，空密码保存时保留旧密码。

## 自动验收

- Python 全量测试：以 CI 最终结果为准。
- APP 契约路由守卫：76 个 HTTP endpoint 必须全部存在于生产 Flask 路由表。
- BE72 回归覆盖：DDNS JSON 解包、双频温度 WSS、WebSocket Dashboard 合并、宽带凭据接线。
- Relay 回归覆盖：更新源解析、陈旧命令过期、清理命令可领取、WireGuard 扩展状态保留。
- Docker：GitHub Docker workflow 在构建镜像前重复执行完整测试与 Python 编译检查。

## 部署

Compose 固定镜像：

```yaml
image: onlychallgener/labprobe-hub:0.11.2
```

保留现有 `APP_TOKEN`、`HOOK_TOKEN`、MQTT 与卷挂载，勾选“拉取最新镜像”后重新部署。首次使用 APP 修改路由器连接信息后，Hub 会更新加密配置并重建 Core 会话与 eWeb WebSocket，无需修改 Relay。

## 风险

- CI 使用模拟的 BE72 wire payload，不能替代硬件环境本身；本次验收按要求以 CI 为发布门槛。
- APP 配置保存会立即测试新路由地址与密码；填写错误会返回认证/连接错误，需要改正后重新保存。
- 路由器固件若不通过 eWeb 暴露完整 PPPoE 密码，仍使用旧 main 已存在的路由器本地 Relay 扩展读取，不改变 Relay 的职责边界。
