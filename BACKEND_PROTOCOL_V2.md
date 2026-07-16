# LabRelay 控制协议 v2

## Hub → Agent 命令

```json
{
  "id": "cmd-...",
  "action": "upsert",
  "protocolVersion": 2,
  "ruleRevision": 3,
  "expiresEpoch": 1784219000,
  "payload": {
    "rule": {
      "id": "nas-https",
      "revision": 3,
      "enabled": true,
      "leaseSeconds": 21600
    }
  }
}
```

支持操作：`upsert`、`start`、`stop`、`delete`。

## Agent → Hub ACK

```json
{
  "acks": [
    {
      "id": "cmd-...",
      "ok": true,
      "phase": "applied",
      "ruleRevision": 3,
      "errorCode": "",
      "error": "",
      "result": {}
    }
  ]
}
```

`phase`：

- `applied`
- `already_applied`
- `failed`

## Rust → Hub 状态

顶层新增：

```json
{
  "protocolVersion": 2,
  "relayVersion": "0.1.1",
  "capabilities": {
    "tcp6to4": true,
    "tcp6to6": true,
    "ipv6Suffix": true,
    "structuredErrors": true,
    "ruleRevision": true,
    "udp": false
  }
}
```

运行状态新增：

```text
peakConnections
lastConnectionAt
lastErrorAt
lastErrorCode
```

主要错误码：

```text
PORT_IN_USE
LISTEN_PERMISSION
LISTEN_FAILED
TARGET_TIMEOUT
TARGET_REFUSED
IPV6_NOT_FOUND
IPV6_AMBIGUOUS
TARGET_OUTSIDE_LAN
MAX_CONNECTIONS
IDLE_TIMEOUT
RULE_EXPIRED
RULE_NOT_FOUND
INVALID_RULE
RELAY_ERROR
```

## 兼容性

- Hub v0.8.4 保留旧 APP 使用的字段和接口。
- Hub 可识别协议 v1 的旧 Rust 状态，旧端不会因缺少 `revision`/`leaseSeconds` 被无限重复下发。
- Rust v0.1.1 可读取旧 relay.json，缺失字段使用默认值。
