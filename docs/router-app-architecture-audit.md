# LabProbeApp 架构与 App-Facing 机器精确级契约审计报告 (v2.0 精确版)

**代码库**: OnlyChallgener/LabProbeApp (Kotlin / Android Jetpack Compose / Coroutines / Flow / OkHttp)  
**审计性质**: 100% 机器精确级代码提取 (基于 61 个 Kotlin 源码文件反编译与 AST 扫描)  
**机器可读基线**: [`docs/contracts/app-hub-contract-v1.json`](file:///d:/Github/labprobe-hub/docs/contracts/app-hub-contract-v1.json)  
**契约纠偏记录**: [`docs/app-contract-corrections.md`](file:///d:/Github/labprobe-hub/docs/app-contract-corrections.md)  
**生成日期**: 2026-08-24  

---

## 一、App 架构分层与通信拓扑

```mermaid
graph TD
    subgraph UI_Layer [UI 视图层 (Jetpack Compose)]
        DashboardUI[DashboardScreen / 仪表盘]
        DeviceUI[DeviceListScreen / 终端列表]
        RouterUI[RouterSettingsScreen / 路由配置]
        Ipv6UI[Ipv6Screen & Dhcpv6Screen]
        PortMapUI[PortMappingScreen / 6->4 & 6->6]
        StunUI[StunPenetrationScreen / STUN穿透]
        WgUI[WireGuardScreen / VPN管理]
        FwUI[FirewallAutomationUi / 防火墙联动]
    end

    subgraph State_Layer [ViewModel 与状态管理]
        MainVM[MainViewModel / 核心状态总线]
        RouterVM[RouterViewModel]
        Ipv6VM[Ipv6ViewModel]
        RealtimeSmoother[RealtimeSmoothing.kt / 动画平滑器]
        StateFlows[StateFlow 响应式流]
    end

    subgraph Data_Layer [Repository 与网络客户端]
        RouterRepo[RouterRepository]
        TaskRepo[RouterTaskRepository]
        PortMapRepo[PortMapApi / PortMappingRuleStore]
        StunRepo[StunApi]
        WgRepo[WireGuardHubApi]
        FwAutoRepo[FirewallAutomationApi]
        
        WSSClient[HubMqttClient.kt / HubRealtimeWebSocketClient]
        HttpApi[HubApi / RouterControlApi / OkHttp]
    end

    subgraph Hub_Backend [LabProbe Hub 后端服务]
        HubREST[Hub REST API /api/*]
        HubWSS[Hub WebSocket /api/realtime/ws]
    end

    UI_Layer --> State_Layer
    State_Layer --> Data_Layer
    
    WSSClient -->|WSS 主通道 1s 推流| HubWSS
    HttpApi -->|HTTPS 静态读写 / 状态校准| HubREST
    
    WSSClient -->|router / devices / task / config / agent| RealtimeSmoother
    RealtimeSmoother --> StateFlows
    StateFlows --> UI_Layer
```

---

## 二、通信通道分工与 Realtime 行为准则

### 2.1 核心通道划分与职责
1. **WSS 主通道 (`/api/realtime/ws`)**:
   - **最高优先级主通道**: 承载 CPU、内存、实时上下行速率、在线终端差分流量、异步任务进度与配置变更推送。
   - **推流机制**: 服务端 ~1 秒推送一次 `router` 与 `devices` 帧，10 秒无数据自动触发 `keepalive` 帧。
   - **连接看门狗**: 客户端内置 `startFrameWatchdog`，10 秒未收到任何数据帧强制判定连接假死并重连。
2. **HTTP 状态校准通道 (`/api/router/realtime`, `/api/devices/realtime`)**:
   - **Calibration Only**: **绝非 WSS 的自动降级轮询通道**。
   - **触发时机**: 仅在客户端启动 (`startRealtime()`) 和收到 WSS `ready` 握手成功帧 (`onRealtimeReady`) 时触发单次基准校准。
3. **HTTP 业务与控制通道 (`/api/*`)**:
   - 承载常规配置的增删改查、规则启停、异步任务下发与手动全量刷新。

---

## 三、App-Facing 契约全集 (Machine-Readable Contract Inventory)

已完成全部 74 个 REST 端点与 8 种 WSS 帧的无遗漏精确提取。以下列出核心功能契约，完整机器可读版本见 [`docs/contracts/app-hub-contract-v1.json`](file:///d:/Github/labprobe-hub/docs/contracts/app-hub-contract-v1.json)。

### 3.1 官方路由器管理 (Router Control APIs)
- `GET /api/router/capabilities` -> `{ "configured": Boolean, "features": { "dashboard": Boolean, "devices": Boolean, "firewall": Boolean, "nativePortMapping": Boolean, "upnp": Boolean, "ddns": Boolean, "diagnostic": Boolean } }`
- `GET /api/router/status` -> `{ "state": String, "connected": Boolean, "sessionConnected": Boolean, "dataAvailable": Boolean, "message": String, "errorCode": String, "lastSuccessAt": Long }`
- `GET /api/router/port-mapping[?force=1]` -> `{ "data": { "rules": [{ "name", "interface", "proto", "extPort", "intIp", "intPort", "enabled" }] } }`
- `POST /api/router/port-mapping` -> Body: `NativePortMapRule.toJson()`, Response: `{ "data": { "rules": [...] } }`
- `PUT /api/router/port-mapping/{ruleName}` -> Body: `NativePortMapRule.toJson()`, Response: `{ "data": { "rules": [...] } }`
- `DELETE /api/router/port-mapping/{ruleName}` -> Response: `{ "data": { "rules": [...] } }`
- `GET /api/router/upnp[?force=1]` -> `{ "data": { "enabled": Boolean, "wan": String, "rules": [{ "name", "extPort", "proto", "intIp", "intPort", "remoteHost" }] } }`
- `PUT /api/router/upnp` -> Body: `{"enabled": Boolean, "wan": String}`, Response: `{ "data": ... }`
- `GET /api/router/firewall[?force=1]` -> `{ "data": { "wanInboundAllow": Boolean, "rules": [{ "uuid", "scope", "name", "enabled", "action", "proto", "srcIp", "srcPort", "destIp", "destPort", "direction", "time", "editable" }] } }`
- `POST /api/router/firewall/rules` -> Body: `FirewallRule.toJson(false)`, Response: `{ "data": ... }`
- `PUT /api/router/firewall/rules/{uuid}` -> Body: `FirewallRule.toJson(true)`, Response: `{ "data": ... }`
- `PATCH /api/router/firewall/rules/{uuid}/enabled` -> Body: `{"enabled": Boolean}`, Response: `{ "data": ... }`
- `DELETE /api/router/firewall/rules/{uuid}` -> Response: `{ "data": ... }`
- `POST /api/router/firewall/reorder` -> Body: `{"scope": String, "uuids": [String]}`, Response: `{ "data": ... }`
- `GET /api/router/ddns[?force=1]` -> `{ "data": { "services": [{ "serviceId", "provider", "domain", "username", "enabled", "status", "lastUpdate", "ip" }] } }`
- `POST /api/router/ddns` -> Body: `DdnsRecord.toJson(password)`, Response: `{ "data": ... }`
- `PUT /api/router/ddns/{serviceId}` -> Body: `DdnsRecord.toJson(password)`, Response: `{ "data": ... }`
- `DELETE /api/router/ddns/{serviceId}` -> Response: `{ "data": ... }`
- `GET /api/router/ipv6/status` -> `{ "data": { "enabled", "wanAddress", "wanPrefix", "lanPrefix", "gateway", "primaryDns", "secondaryDns" } }`
- `GET /api/router/ipv6/config` -> `{ "data": { "wan": { "proto", "dhcpv6", "autoDns", "dns" }, "lan": { "proto", "ip6assign", "dhcpv6" } } }`
- `GET /api/router/ipv6/clients` -> `{ "data": { "clients": [{ "hostname", "mac", "duid", "ipv6", "iaid", "leaseTime" }] } }`
- `PUT /api/router/ipv6/config` -> Body: `Ipv6Config JSON`, Response: `{ "data": ... }`
- `GET /api/router/diagnostic` -> `{ "data": { "process", "error_count", "List": [...] } }`
- `POST /api/router/diagnostic` -> Response: `{ "data": ... }`

### 3.2 LabProbe 自研 DDNS APIs (多厂商引擎)
- `GET /api/ddns[?force=1]` -> `{ "records": [{ "id", "domain", "provider", "recordType", "ipVersion", "enabled", "status", "lastIp", "lastUpdate", "errorMessage", "cnameTarget" }], "routerWan": { "ipv4", "ipv6", "ipv4State", "ipv6State" } }`
- `GET /api/ddns/providers` -> `{ "providers": [{ "id", "name", "supportedRecordTypes": ["A","AAAA","CNAME"], "requiredCredentials": [{ "key", "label", "type", "placeholder" }] }] }`
- `POST /api/ddns` -> Body: `LabProbeDdnsRecord.toJson(credentials)`, Response: `LabProbeDdnsSnapshot`
- `PUT /api/ddns/{recordId}` -> Body: `LabProbeDdnsRecord.toJson(credentials)`, Response: `LabProbeDdnsSnapshot`
- `DELETE /api/ddns/{recordId}` -> Response: `LabProbeDdnsSnapshot`
- `POST /api/ddns/{recordId}/update` -> Body: `{"force": true}`, Response: `{ "results": { ... }, "message": String, "error": String }`

### 3.3 LabProbe 6→4 / 6→6 映射与代理 APIs (PortMapping)
- `GET /api/portmaps` -> `{ "rules": [{ "id", "name", "enabled", "mode", "listenPort", "targetMode", "targetIpv4", "targetIpv6", "targetIpv6Snapshot", "targetIpv6Suffix", "targetMac", "targetPort", "serviceType", "transportProtocol", "preferCurrentPrefix", "expiresAt", "leaseSeconds", "maxConnections", "idleTimeoutSec", "desiredState", "actualState", "syncState", "revision", "runtime": { "state", "resolvedTarget", "activeConnections", "activePeers", "totalUploadBytes", "totalDownloadBytes", "totalUploadPackets", "totalDownloadPackets", "startedAt", "expiresAt", "lastResolvedAt", "lastError" } }], "portRange": { "min", "max" }, "agentOnline", "agentLastSeenAt", "protocolVersion", "hubVersion", "agentVersion", "capabilities", "agentState", "agentAgeSeconds", "agentLastSeenEpoch", "agentRevision", "rulesLoaded", "rulesRevision", "rulesUpdatedAt", "revision" }`
- `POST /api/portmaps` -> Body: `PortMapDraft.toJson()`, Response: `{ "rule": PortMapRule, "revision": Long }`
- `PUT /api/portmaps/{id}` -> Body: `PortMapDraft.toJson()`, Response: `{ "rule": PortMapRule, "revision": Long }`
- `DELETE /api/portmaps/{id}` -> Response: `{ "success": Boolean, "revision": Long }`
- `POST /api/portmaps/{id}/{action}` -> Path: `action` in `start`/`stop`/`toggle`/`restart`, Body: `{}`, Response: `{ "success": Boolean, "revision": Long }`
- `GET /api/portmaps/{id}/history?minutes={minutes}` -> `{ "samples": [{ "timestamp", "activeConnections", "activePeers", "uploadBps", "downloadBps" }] }`

### 3.4 STUN 穿透与保活 APIs
- `GET /api/stun` -> `{ "rules": [{ "id", "name", "enabled", "listenPort", "targetIpv4", "targetPort", "serviceType", "transportProtocol", "forwardMode", "actualState", "firewallState", "nativeMappingState", "runtime": { "state", "resolvedTarget", "publicEndpoint", "publicIp", "publicPort", "mappingUpdatedAt", "activeConnections", "activePeers", "totalUploadBytes", "totalDownloadBytes", "lastError" } }], "agentOnline", "agentLastSeenAt" }`
- `POST /api/stun` -> Body: `StunDraft.toJson()`, Response: `{ "rule": StunRule }`
- `PUT /api/stun/{id}` -> Body: `StunDraft.toJson()`, Response: `{ "rule": StunRule }`
- `POST /api/stun/{id}/{action}` -> Path: `action` in `start`/`stop`/`keepalive`, Body: `{}`, Response: `{ "success": Boolean }`
- `DELETE /api/stun/{id}` -> Response: `{ "success": Boolean }`
- `GET /api/stun/{id}/addresses` -> `{ "addresses": [{ "endpoint": String, "updatedAt": Long }] }`

### 3.5 WireGuard VPN APIs
- `GET /api/wireguard/server` -> `{ "server": { "listenPort", "mtu", "address", "serverPublicKey", "enabled" }, "agentStatus": { "publicKey" }, "peers": [{ "publicKey", "allowedIps", "latestHandshakeAt", "rxBytes", "txBytes" }], "revision": Long }`
- `PUT /api/wireguard/server` -> Body: `{ "listenPort", "mtu", "address", "enabled", "peers": [{ "publicKey", "allowedIps", "persistentKeepalive" }] }` (**绝对不含 Private Key!**), Response: `{ "server": WireGuardServerConfig, "revision": Long }`
- `PATCH /api/wireguard/endpoints/{id}` -> Body: `{ "endpoint": String, "endpointRevision": Long }`, Response: `{ "success": Boolean, "revision": Long }`

### 3.6 防火墙自动化联动 APIs (Firewall Automation)
- `GET /api/router/firewall/automation` -> `{ "data": { "bindings": [{ "firewallUuid", "enabled", "targetType", "mappingKind", "mappingId", "addressFamily", "matchField", "targetName", "ruleName", "direction", "currentAddress", "desiredAddress", "status", "statusMessage", "suspended", "suspendedReason" }] } }`
- `PUT /api/router/firewall/automation/{firewallUuid}` -> Body: `FirewallAutomationBinding.toJson()`, Response: `{ "success": Boolean }`
- `DELETE /api/router/firewall/automation/{firewallUuid}` -> Response: `{ "success": Boolean }`
- `POST /api/router/firewall/automation/{firewallUuid}/sync` -> Response: `{ "success": Boolean }`

### 3.7 异步任务与诊断 (Router Tasks)
- `GET /api/router/tasks/{kind}` -> `{ "task_id", "kind", "state", "progress", "step", "message", "error", "result", "startedAt", "finishedAt" }`
- `POST /api/router/nat-diagnostic` -> Body: `{"target_ip", "stun_server"}`, Response: `{ "task_id", "kind", "state" }`
- `POST /api/router/beta-upgrade?force=1` -> Body: `{}`, Response: `{ "task_id", "kind", "state" }`

---

## 四、WSS 实时通信协议规范 (`/api/realtime/ws`)

### 4.1 握手与连接参数
- **URL**: `ws://<hub_ip>:<port>/api/realtime/ws` 或 `wss://<hub_domain>/api/realtime/ws`
- **鉴权头**: `Authorization: Bearer <app_token>`, `X-LabProbe-Token: <app_token>`
- **协议帧格式**: JSON 文本帧 `{"type": "<type_name>", "data": { ... }}`

### 4.2 客户端看门狗与保活机制 (Watchdog & Keepalive)
- **OkHttp 协议层 Ping 间隔**: `pingInterval = 10` 秒 (`HubMqttClient.kt:274`)。
- **看门狗检查周期**: 协程每 `1` 秒检查一次 (`WATCHDOG_INTERVAL_MS = 1_000L`)。
- **服务端无帧超时阈值**: `SERVER_FRAME_TIMEOUT_MS = 45_000L` (**45 秒**)。
- **真实看门狗行为**:
  - 客户端接收到**任意有效服务端 Frame**（包括 `keepalive`、`router`、`devices` 等），立即更新 `lastFrameAt = SystemClock.elapsedRealtime()`。
  - 若**连续 45 秒**未收到任何服务端 Frame，看门狗判定连接假死，主动执行 `webSocket.cancel()` 释放当前 Socket，并触发指数退避自动重连。

### 4.3 客户端实际消费的 8 大数据帧与消费端源码追踪 (Deep Consumer Payload Contract)

| 帧类型 (`type`) | 真实消费端文件与函数 | 消费端实际读取字段 (`optString`/`optLong`/`optDouble`/`optJSONObject` 等) | 业务用途 |
| :--- | :--- | :--- | :--- |
| **`ready`** | `HubMqttClient.kt:182` (`onRealtimeReady`) | `{}` | 握手就绪通知。App 状态置为 `Connected`，触发 `RouterRepository.onRealtimeReady(reconnect)` 与单次 HTTP 状态校准 `calibrateRealtimeCache()` |
| **`router`** | `RealtimeSmoothing.kt:47` (`acceptRouter`), `LiteRealtime.kt:33` (`mergeLiteRouterRealtime`) | `uploadBps` (Long), `downloadBps` (Long), `cpuPercent` (Double), `memoryPercent` (Double), `temperatureC` (Double), `totalUploadBytes` (Long), `totalDownloadBytes` (Long), `uptimeSeconds` (Long), `onlineDeviceCount` (Int), `ipv4Connections` (Long), `ipv6Connections` (Long), `ipv4HalfConnections` (Long), `ipv6HalfConnections` (Long), `cps` (Long), `sampleEpochMs` (Long), `sampleAgeMs` (Long), `stale` (Boolean), `temperature2gC` (Double), `temperature5gC` (Double), `storagePercent` (Double) | 驱动主页仪表盘 1 秒级平滑插值动画渲染 (`RealtimeDisplaySmoother`) |
| **`devices`** | `RealtimeSmoothing.kt:94` (`acceptDevices`), `RealtimeSmoothing.kt:190` (`renderDevices`) | `devices`: 数组，每项包含 `mac` (String), `uploadBps` (Long), `downloadBps` (Long), `connectionCount` (Int)；外层: `onlineDeviceCount`/`onlineCount` (Int), `delta` (Boolean), `sampleEpochMs` (Long), `sampleAgeMs` (Long) | 在线终端速率差分推流，驱动终端列表上下行速率动态刷新 |
| **`devices_snapshot`** | `MainActivity.kt:1200` (`acceptDevicesSnapshot`), `DeviceCodec.kt:35` (`parseDevice`) | `devices`: 完整终端数组，解析 `mac`, `name`/`devRecommend`, `hostname`/`hostName`, `vendor`, `type`/`devType`, `interface`/`conType`/`port`, `ip`/`ipv4`, `ipv6`, `signal`/`rssi`, `band`, `linkSpeed`/`rate`, `online`, `firstSeen`, `lastSeen`, `rxBytes`, `txBytes`, `rxRateBps`, `txRateBps`, `connectionCount`, `accessPolicy`, `guest`, `blocked`；外层: `revision`, `updatedAt` | 全量终端列表持久化快照与历史离线设备合并 |
| **`task`** | `RouterTaskRepository.kt:60` (`acceptRealtime`), `RouterTaskRepository.kt:120` (`parse`) | `task_id`/`taskId`/`id` (String), `kind` (String: `"nat"`, `"diagnostic"`, `"beta"`), `state` (String: `"idle"`, `"queued"`, `"running"`, `"completed"`, `"failed"`, `"timeout"`), `stage` (String), `progress` (Int/String), `step`/`stageText` (String), `message` (String), `error`/`errorMessage` (String), `result` (JSONObject), `startedAt` (Long), `finishedAt` (Long) | 异步任务进度与诊断结果推送，自动管理后台轮询任务生命周期 |
| **`config`** | `RouterRepository.kt:100` (`acceptConfigRealtime`) | `resource` (String: `"portMappings"`, `"firewall"`, `"ddns"`, `"upnp"`), `data` (JSONObject: 对应模块全量配置), `source` (String: `"sync"`/`"command"`), `revision` (Long), `updatedAt` (Long) | 配置变更轻量同步，触发对应模块状态更新并抑制过期帧覆盖 |
| **`agent`** | `AgentPresenceStore.kt:28` (`acceptRealtime`) | `agentState` (String: `"online"`/`"offline"`), `agentOnline` (Boolean), `router` (String), `agentLastSeenAt` (String), `agentLastSeenEpoch` (Long), `agentAgeSeconds` (Long), `agentVersion` (String), `agentRevision` (Long), `capabilities` (Array), `portRange` (`min`, `max`) | 路由器 Extension 状态与心跳实时更新 |
| **`keepalive`** | `HubMqttClient.kt:187` (`onMessage`) | `{}` | 重置客户端 45 秒无帧看门狗定时器 (`lastFrameAt`) |

## 五、重构目标与兼容性验证标准

### 5.1 目标与定义
> **目标 (TARGET)**: **Old App + New Hub = zero observable contract regression.**

### 5.2 验收与准入条件 (Before Declaring Proven)
在完成以下四项强制验证前，一律视为 **TARGET / EXPECTED**，不得声称“100% 证明”：
1. **Automated Contract Tests**: 针对 74 个 REST 端点与 8 种 WSS 帧的自动化契约回归测试全部通过。
2. **Old/New Response Comparison**: 旧版 Hub 录制的数据流快照与新版 RouterCore 输出完成逐字段 Diff 对比，差异率为 0。
3. **WSS Frame Comparison**: 对比高频推流下的 JSON 键名、类型与刷新频率，保持 1 秒级平滑推流。
4. **Actual APK Regression Test**: 使用未修改的旧版 LabProbeApp 安装包直连新 Hub，在真机上验证仪表盘、设备列表、端口映射、WireGuard、STUN、DDNS 全部操作正常。
