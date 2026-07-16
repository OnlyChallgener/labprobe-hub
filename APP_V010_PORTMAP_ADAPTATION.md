# 给 APP v0.10.x / Codex 的适配字段

APP 不需要修改创建规则和现有接口地址，只需增加状态展示。

## `GET /api/portmaps` 顶层新增

```text
protocolVersion
hubVersion
agentVersion
relayVersion
capabilities
```

## 每条规则新增

```text
desiredState   running / stopped
actualState    starting / running / waiting_target / draining / stopped / expired / error
syncState      synced / syncing / agent_offline / error
revision
```

旧字段 `enabled` 和 `runtime` 继续保留。

## 推荐显示逻辑

```text
syncState=agent_offline → 路由器 Agent 离线
syncState=syncing       → 正在同步
actualState=starting    → 启动中
actualState=running     → 运行中
actualState=waiting_target → 等待目标 IPv6
actualState=draining    → 正在停止现有连接
actualState=expired     → 已到期
actualState=error       → 执行失败
```

## 错误中文映射

```text
PORT_IN_USE       监听端口已被占用
LISTEN_PERMISSION 无权限监听该端口
TARGET_TIMEOUT    目标连接超时
TARGET_REFUSED    目标拒绝连接
IPV6_NOT_FOUND    未找到设备 IPv6
IPV6_AMBIGUOUS    IPv6 后缀对应多个设备
TARGET_OUTSIDE_LAN 目标不在允许的 LAN 路由中
MAX_CONNECTIONS   已达到最大连接数
RULE_EXPIRED      规则已到期
VERSION_MISMATCH  组件版本不兼容
```

点击启动后不要立即显示“运行中”；先显示“启动中/正在同步”，以 Hub 返回的实际状态为准。
