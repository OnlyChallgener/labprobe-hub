# LabProbe Hub v0.8.4

配套版本：

- Hub `0.8.4`
- LabRelay `0.1.1`
- Router Agent `0.1.1`
- 端口映射协议 `v2`

## Hub

- 根目录 `VERSION` 统一驱动 `/health`、Docker 构建参数和镜像版本标签。
- 规则新增 `revision`、`desiredState`，并保留旧 `enabled` 字段兼容现有 APP。
- APP 查询同时返回 `desiredState`、`actualState`、`syncState`。
- 命令新增协议版本、规则版本、过期时间和结构化执行结果。
- 相同规则的旧命令自动覆盖或标记为 superseded，避免重复执行。
- Hub 按 Rust 实际规则进行自动对账；路由器重启或配置丢失后可重新下发。
- 已到期规则自动转为期望停止，但保留 `leaseSeconds`，再次启动可重新获得原时长。
- 新增 Agent 认证诊断接口：`/api/router/portmaps/auth-test`。
- 状态中返回 Hub、Agent、LabRelay 版本和能力。
- 命令历史限制为最近 200 条完成记录；流量历史按配置限制并清理旧数据。
- 默认端口范围仍为 `20000-20020`，可通过环境变量配置。

## LabRelay

- 规则持久化格式升级到 v2，并兼容旧 v1 配置。
- 支持规则 `revision` 和 `leaseSeconds`，重复命令不会反复重启监听。
- 永久规则及未到期规则在路由器启动后自动恢复；已到期规则不会启动。
- 增加结构化错误码、峰值连接数、最近连接时间和最近错误时间。
- IPv6 后缀解析失败时清空旧目标并保持等待状态。
- 停止规则时先停止新连接，已有连接进入短暂 draining 状态。
- 配置写入增加临时文件、fsync 和原子替换。

## Agent

- 上报 Agent 版本和协议版本。
- HTTP 错误区分 Token 错误、Hub 不可达、接口缺失和其他状态码。
- Token 错误默认退避 60 秒，避免持续刷日志。
- 相同错误 60 秒内合并，不重复写入日志。
- 新增：`labrelay_agent.sh test` 与 `labrelay_agent.sh version`。

## 安全边界

- 不提供公网控制端口。
- 不执行 Hub 下发的任意 Shell。
- 不自动修改防火墙。
- 不记录 HOOK_TOKEN 和业务转发正文。
