# LabProbeApp ↔ Hub 契约审计纠偏报告 (Contract Corrections)

**审计基线代码**: OnlyChallgener/LabProbeApp (`main` 分支, 61 个 Kotlin 源码文件)  
**纠偏性质**: 机器精确级代码逆向对照 (逐行比对 URL 构造器、JSON 序列化、反序列化解析器、WSS 消息分发器)  
**生成日期**: 2026-08-24  
**机器可读基线文件**: [`docs/contracts/app-hub-contract-v1.json`](file:///d:/Github/labprobe-hub/docs/contracts/app-hub-contract-v1.json)

---

## 一、上一版报告中写错的 Endpoint 列表

| 序号 | 上一版错误记录 | 源码真实 Endpoint | HTTP 方法 | 纠偏原因与代码证据 |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `/api/portmaps/$id` (PUT/DELETE) | `/api/portmaps/$id` (`PUT`, `DELETE`), `/api/portmaps/$id/$action` (`POST`) | `POST` | 启停操作为独立动词路径 `/api/portmaps/$id/$action` (`PortMapping.kt:255`) |
| 2 | `/api/router/port-mapping` (DELETE) | `/api/router/port-mapping/$safe` | `DELETE` | 删除官方原生端口映射时，规则名称作为 URL Path 参数并经过 URL 编码 (`RouterControlApi.kt:153`) |
| 3 | `/api/router/port-mapping` (PUT) | `/api/router/port-mapping/$safe` | `PUT` | 更新官方原生端口映射时，旧规则名作为 Path 参数 (`RouterControlApi.kt:148`) |
| 4 | `/api/router/firewall/rules/$uuid/enabled` | `/api/router/firewall/rules/$uuid/enabled` | `PATCH` | 上一版误标为 `POST`/`PUT`，真实实现为 `PATCH` (`RouterControlApi.kt:173`) |
| 5 | `/api/wireguard/endpoints/$id` | `/api/wireguard/endpoints/$id` | `PATCH` | 上一版误标为 `PUT`，真实实现为 `PATCH` (`WireGuardClient.kt:590`) |
| 6 | `/api/router/diagnostic` (未分方法) | `/api/router/diagnostic` | `GET` (读取), `POST` (触发) | 诊断包含异步触发 (`POST`) 和进度读取 (`GET`) (`RouterControlApi.kt:243,246`) |
| 7 | `/api/router/beta-upgrade` | `/api/router/beta-upgrade?force=1` | `POST` | 真实调用强制带 Query 参数 `?force=1` (`RouterTaskRepository.kt:80`) |
| 8 | `/api/agent/cleanup/status` | `/api/agent/cleanup/status?commandId=...` | `GET` | 轮询清理状态时通过 Query 传 `commandId` (`MainActivity.kt:8120`) |
| 9 | `/api/sync/changes` | `/api/sync/changes?since=$since&limit=500` | `GET` | 增量同步请求显式指定 `limit=500` 与 `since` (`MainActivity.kt:7950`) |

---

## 二、上一版报告中写错的 Request JSON 字段 (命名法与类型纠偏)

**核心原则**：App 与 Hub 通信严格遵循 Kotlin 类中 `toJson()` 生成的真实键名（绝大多数为 `camelCase`），严禁手工改写为 `snake_case`。

| 业务模块 | 上一版写错字段 (snake_case/概括) | 源码真实 Request 字段 (camelCase/Exact) | 类型 (Type) | 源码证据位置 |
| :--- | :--- | :--- | :--- | :--- |
| **PortMapping** | `listen_port` | `listenPort` | `Int` | `PortMapping.kt:318` (`PortMapDraft.toJson()`) |
| **PortMapping** | `target_ip` (概括) | `targetIpv4` (6to4) / `targetIpv6` (6to6) | `String` | `PortMapping.kt:320-321` |
| **PortMapping** | `target_port` | `targetPort` | `Int` | `PortMapping.kt:324` |
| **PortMapping** | `target_mode` | `targetMode` (`"ipv4"`, `"ipv6_suffix"`, `"ipv6_full"`) | `String` | `PortMapping.kt:319` |
| **PortMapping** | `target_ipv6_suffix` | `targetIpv6Suffix` | `String` | `PortMapping.kt:323` |
| **PortMapping** | `target_mac` | `targetMac` | `String` | `PortMapping.kt:324` |
| **PortMapping** | `target_ipv6_snapshot` | `targetIpv6Snapshot` | `String` | `PortMapping.kt:322` |
| **PortMapping** | `transport_protocol` | `transportProtocol` (`"TCP"` / `"UDP"`) | `String` | `PortMapping.kt:326` |
| **PortMapping** | `prefer_current_prefix` | `preferCurrentPrefix` (`true`) | `Boolean` | `PortMapping.kt:327` |
| **PortMapping** | `expires_at` | `expiresAt` (支持 `null` / `JSONObject.NULL`) | `Long?` | `PortMapping.kt:328` |
| **PortMapping** | `lease_seconds` | `leaseSeconds` | `Long` | `PortMapping.kt:329` |
| **PortMapping** | `max_connections` | `maxConnections` | `Int` | `PortMapping.kt:330` |
| **PortMapping** | `idle_timeout` | `idleTimeoutSec` | `Int` | `PortMapping.kt:331` |
| **STUN** | `local_port` | `targetPort` (目标端口) + `targetIpv4` | `Int`, `String` | `StunPenetration.kt:177` (`StunDraft.toJson()`) |
| **STUN** | `protocol` | `transportProtocol` (`"TCP"` / `"UDP"`) | `String` | `StunPenetration.kt:176` |
| **STUN** | `service_type` | `serviceType` | `String` | `StunPenetration.kt:175` |
| **Firewall** | `src_ip`, `dest_port` | `srcIp`, `destPort`, `srcPort`, `destIp` | `String` | `RouterControlApi.kt:359` (`FirewallRule.toJson()`) |
| **Firewall** | `wan_inbound_allow` | `wanInboundAllow` (查询返回) / `scope` (`"wan"`) | `String` | `RouterControlApi.kt:353` |
| **FirewallAuto**| `mapping_id` | `mappingId`, `mappingKind`, `targetType`, `addressFamily`, `matchField` | `String` | `FirewallAutomation.kt:53` |
| **WireGuard** | `listen_port` | `listenPort`, `mtu`, `address`, `enabled`, `peers` | `Int`, `String` | `WireGuardClient.kt:572` |
| **WireGuard** | `endpoint_revision` | `endpointRevision`, `endpoint` | `Long`, `String` | `WireGuardClient.kt:590` |
| **Native DDNS** | `provider`, `domain` | `serviceId`, `provider`, `domain`, `username`, `password`, `enabled` | `String`, `Boolean`| `RouterControlApi.kt:418` |

---

## 三、上一版报告中写错的 Response JSON 字段与包装层

1. **官方 Router 控制 API 数据层包装**:
   - `RouterControlApi.kt` 中绝大多数官方接口返回均有一层 `{"data": { ... }}` 结构：
     - `/api/router/port-mapping` -> `root.optJSONObject("data").optJSONArray("rules")`
     - `/api/router/upnp` -> `root.optJSONObject("data")` (`enabled`, `wan`, `rules`)
     - `/api/router/firewall` -> `root.optJSONObject("data")` (`wanInboundAllow`, `rules`)
     - `/api/router/ddns` -> `root.optJSONObject("data").optJSONArray("services")`
     - `/api/router/ipv6/*` -> `root.optJSONObject("data")`
     - `/api/router/diagnostic` -> `root.optJSONObject("data").optJSONArray("List")`
   - 上一版报告中漏写了顶层 `data` 包装层。
2. **PortMapping 列表与状态返回**:
   - `/api/portmaps` 返回顶层包含：`rules` (数组), `portRange` (`min`/`max`), `agentOnline`, `agentLastSeenAt`, `protocolVersion`, `hubVersion`, `agentVersion`, `agentState`, `rulesLoaded`, `rulesRevision`, `revision`。
   - `rule` 内部嵌套 `runtime` 对象 (`state`, `resolvedTarget`, `activeConnections`, `activePeers`, `totalUploadBytes`, `totalDownloadBytes`, `totalUploadPackets`, `totalDownloadPackets`, `lastError`)。
3. **STUN 列表与状态返回**:
   - `/api/stun` 返回顶层：`rules`, `agentOnline`, `agentLastSeenAt`。
   - `rule` 内部嵌套 `runtime` 对象 (`publicEndpoint`, `publicIp`, `publicPort`, `mappingUpdatedAt`, `resolvedTarget`, `activeConnections`, `activePeers`, `totalUploadBytes`, `totalDownloadBytes`, `lastError`)。
   - 规则层包含状态组合：`actualState`, `firewallState`, `nativeMappingState`, `forwardMode`。

---

## 四、上一版报告中遗漏的 Endpoint

上一版报告遗漏了以下真实存在的客户端端点：
1. `GET /api/router/capabilities` (查询 Hub 启用的路由器特性开关: `dashboard`, `devices`, `firewall`, `nativePortMapping`, `upnp`, `ddns`, `diagnostic`)
2. `POST /api/router/firewall/reorder` (防火墙规则优先级重排序，传 `scope` 与 `uuids` 数组)
3. `PATCH /api/router/firewall/rules/{uuid}/enabled` (单条防火墙规则快捷启停)
4. `GET /api/ddns/providers` (获取自研 DDNS 支持的 8 大服务商元数据及鉴权表单字段)
5. `POST /api/ddns/{recordId}/update` (强制触发单条自研 DDNS 记录立即更新，传 `{"force": true}`)
6. `POST /api/router/firewall/automation/{firewallUuid}/sync` (触发单条防火墙联动规则即时同步)
7. `GET /api/portmaps/{id}/history?minutes={minutes}` (获取单条映射历史流量采样)
8. `GET /api/stun/{id}/addresses` (获取 STUN 穿透的历史公网 IP/端口记录)
9. `POST /api/router/beta-upgrade?force=1` (发起路由器 Beta 固件检测/升级)
10. `POST /api/agent/cleanup` 与 `GET /api/agent/cleanup/status?commandId=...` (路由器 Extension 存储空间清理与进度轮询)

---

## 五、WSS Contract 纠偏 (8 大 Frame Type、精确 Watchdog 与 Consumer 字段追踪)

### 5.1 Watchdog 看门狗参数精确纠偏
- **上一版错误描述**: “10 秒无帧看门狗”。
- **源码真实参数与机制** (`HubMqttClient.kt:270-280`):
  - **OkHttp 协议层 Ping 间隔**: `pingInterval = 10L` 秒 (`PING_INTERVAL_SECONDS = 10L`)。
  - **看门狗检查周期**: 协程每 `1L` 秒轮询一次 (`WATCHDOG_INTERVAL_MS = 1_000L`)。
  - **服务端无帧超时阈值**: `SERVER_FRAME_TIMEOUT_MS = 45_000L` (**45 秒**)。
  - **准确行为**: 任意有效服务端 Frame（包括 `keepalive`）更新 `lastFrameAt`；连续 **45 秒**未收到任何服务端 Frame 后，watchdog 执行 `webSocket.cancel()`，随后进入指数退避自动重连。

### 5.2 沿 Callback 深入 Consumer 的真实 Payload 字段映射
HubRealtimeWebSocketClient 仅按 `type` 分发 `data.toString()`。深入各业务模块 Consumer 源码分析提取的真正依赖字段如下：

| 帧类型 (`type`) | 真实消费函数与源文件 | 消费端实际通过 `optString`/`optLong`/`optDouble`/`optJSONObject` 读取的字段 |
| :--- | :--- | :--- |
| **`ready`** | `HubMqttClient.kt:182` -> `onRealtimeReady` | `{}` (通知 Session 就绪，触发 `calibrateRealtimeCache()`) |
| **`router`** | `RealtimeSmoothing.kt:47` (`acceptRouter`), `LiteRealtime.kt:33` | `uploadBps`, `downloadBps`, `cpuPercent`, `memoryPercent`, `temperatureC`, `totalUploadBytes`, `totalDownloadBytes`, `uptimeSeconds`, `onlineDeviceCount`, `ipv4Connections`, `ipv6Connections`, `ipv4HalfConnections`, `ipv6HalfConnections`, `cps`, `sampleEpochMs`, `sampleAgeMs`, `stale`, `temperature2gC`, `temperature5gC`, `storagePercent` |
| **`devices`** | `RealtimeSmoothing.kt:94` (`acceptDevices`) | `devices`: `[{ "mac", "uploadBps", "downloadBps", "connectionCount" }]`, `onlineDeviceCount`/`onlineCount`, `delta`, `sampleEpochMs`, `sampleAgeMs` |
| **`devices_snapshot`** | `MainActivity.kt:1200`, `DeviceCodec.kt:35` (`parseDevice`) | `devices`: `[{ "mac", "name"/"devRecommend", "hostname"/"hostName", "vendor", "type"/"devType", "interface"/"conType"/"port", "ip"/"ipv4", "ipv6", "signal"/"rssi", "band", "linkSpeed"/"rate", "online", "firstSeen", "lastSeen", "rxBytes", "txBytes", "rxRateBps", "txRateBps", "connectionCount", "accessPolicy", "guest", "blocked" }]`, `revision`, `updatedAt` |
| **`task`** | `RouterTaskRepository.kt:60` (`acceptRealtime`), `parse` | `task_id`/`taskId`/`id`, `kind` (`nat`/`diagnostic`/`beta`), `state` (`idle`/`queued`/`running`/`completed`/`failed`/`timeout`), `stage`, `progress`, `step`/`stageText`, `message`, `error`/`errorMessage`, `result`, `startedAt`, `finishedAt` |
| **`config`** | `RouterRepository.kt:100` (`acceptConfigRealtime`) | `resource` (`portMappings`/`firewall`/`ddns`/`upnp`), `data` (各模块配置对象), `source` (`sync`/`command`), `revision`, `updatedAt` |
| **`agent`** | `AgentPresenceStore.kt:28` (`acceptRealtime`) | `agentState` (`online`/`offline`), `agentOnline`, `router`, `agentLastSeenAt`, `agentLastSeenEpoch`, `agentAgeSeconds`, `agentVersion`, `agentRevision`, `capabilities`, `portRange` (`min`, `max`) |
| **`keepalive`** | `HubMqttClient.kt:187` (`onMessage`) | `{}` (更新 `lastFrameAt`，重置 45 秒看门狗) |

## 六、HTTP Realtime / Fallback 行为纠偏

- **上一版错误描述**: “普通读取走 HTTP，实时状态走 WSS；WSS 失败时降级为 HTTP 自动轮询”。
- **源码真实行为**:
  - **HTTP is calibration-only and is never an automatic realtime fallback.** (`MainActivity.kt:1072-1077, 1235-1250`)
  - **主通道**: 100% 依赖 WSS (`/api/realtime/ws`) 驱动 UI 渲染（通过 `RealtimeSmoothing.kt` 进行平滑动画推导）。
  - **HTTP 的真实调用场景**:
    1. **冷启动初次校准 (Initial Calibration)**: `startRealtime()` 启动时并发调用一次 `GET /api/router/realtime` 与 `GET /api/devices/realtime` 初始化平滑器基准。
    2. **WSS 重新连接握手就绪 (Reconnect Calibration)**: 收到 `ready` 帧后，静默执行一次 HTTP 状态校准 `calibrateRealtimeCache()`。
    3. **手动下拉刷新 (Manual Refresh)**: 用户在 UI 主动下拉触发 `refreshRouterDashboard()` 调取全量快照。
  - **结论**: WSS 断开时，App 状态变为 `Reconnecting`，**绝不会自动启动后台 HTTP 轮询**，避免打崩路由器与网络。

---

## 七、修正后的通信拓扑与进程关系

### 7.1 真实通信拓扑
```
[LabProbe Hub (Server)]
       ↕ HTTPS REST & WSS
[LabProbeApp (Android)]

[LabProbe Hub (Server)]
       ↕ HTTP REST (POST /api/hook, /api/agent/*)
[Router Agent Runtime (`labrelay agent`)]
       ↕ Local Unix Domain Socket (`/tmp/labrelay.sock`) [仅路由器本机内部!]
[LabRelay Data Plane Daemon (`labrelay daemon`)]
       ↕ Direct Linux Kernel / Netlink / Sockets
[Router Network Stack & Interfaces]
```

### 7.2 Binary 与 Process 调查结论
- **源码证据**: `labrelay/src/main.rs:188` 和 `labrelay/src/agent.rs:23`，以及 `scripts/labprobe-install.sh:314-315`。
- **结论**: 
  - **同单一二进制文件**: 路由器上仅安装一个二进制 `/usr/bin/labrelay`。
  - **不同运行时进程**: 通过 OpenWrt `procd` 启动两个独立的进程实例：
    - 实例 1 (数据平面): `/usr/bin/labrelay daemon --config /etc/labprobe/relay.json --socket /tmp/labrelay.sock --state /tmp/labprobe/relay-state.json`
    - 实例 2 (控制平面): `/usr/bin/labrelay agent --config /etc/labprobe/agent.json`

---

## 八、修正后的完整 Contract 统计与未确认项

- **修正后的完整 REST Endpoint 数量**: **74 个** (详见 `app-hub-contract-v1.json`)。
- **修正后的 WSS 消息帧类型数量**: **8 种** (`ready`, `router`, `devices`, `devices_snapshot`, `task`, `config`, `agent`, `keepalive`)。
- **仍然无法静态确认的边缘项**:
  1. `/api/ddns/providers` 接口中各特定 DNS 服务商（如 dynv6, IPv64）动态表单的校验规则（依赖第三方 API 约定）。
  2. 部分历史型号在 `/api/router/diagnostic` 返回的私有 `tips`/`advise` 错误码字典。
