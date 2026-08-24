# Router Core v1 迁移执行进度跟踪看板

**基线分支**: `refactor/router-core-v1`  
**基线测试数**: 324 passed  
**最新更新时间**: 2026-08-24  

---

## 一、当前阶段总览

| 阶段 | 名称 | 状态 | 交付物 / 核心变更 |
| :--- | :--- | :--- | :--- |
| **Phase 0** | 架构与固件全面审计 | **已完成 (Approved)** | 固件逆向、Hub 补丁、App 契约精准提取 |
| **Phase 1** | 建立 Router Core 兼容骨架 | **已完成 (Approved)** | `router_core` 架构边界、Contracts、Legacy Adapter、Contract Guard |
| **Stage 1** | ReyeeSessionManager & RpcClient | **进行中 (In Progress)** | 动态 Key、AES 兼容加密、Single-Flight 独占重登录、RPC Wire 引擎 |
| **Stage 2** | ReyeeEWebDriver 原生能力实现 | **待开始 (Pending)** | 12 大官方功能收口至 ReyeeEWebDriver |
| **Stage 3** | Hub Router Blueprint 正式切流 | **待开始 (Pending)** | `create_router_blueprint_v1` 正式挂载 |
| **Stage 4** | Realtime 聚合与 Cache 规范化 | **待开始 (Pending)** | 统一 Realtime 广播与 SWR 缓存调度 |
| **Stage 5** | 冗余旧 Patch 与历史文件安全清理 | **待开始 (Pending)** | 严格 NO PROOF = NO DELETE 清理无用文件 |

---

## 二、能力收口与路径状态表 (Capability Matrix)

| 能力模块 | 对应 API 端点 | 当前运行路径 | 目标收口模块 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| **Router Capabilities** | `GET /api/router/capabilities` | Legacy Path (`router_rpc_v010`) | `RouterService.get_capabilities` | 骨架已就绪 |
| **Router Status** | `GET /api/router/status` | Legacy Path (`router_rpc_v010`) | `RouterService.get_status` | 骨架已就绪 |
| **Dashboard Telemetry** | `GET /api/router/dashboard` | Legacy Path (`router_rpc_v010`) | `RouterService.get_dashboard` | 骨架已就绪 |
| **Connected Devices** | `GET /api/router/devices` | Legacy Path (`router_rpc_v010`) | `RouterService.get_devices` | 骨架已就绪 |
| **Native Port Mapping** | `GET/POST/PUT/DELETE /api/router/port-mapping*` | Legacy Path (`router_native_features_patch`) | `RouterService.*_port_mapping` | 骨架已就绪 |
| **Router UPnP** | `GET/PUT /api/router/upnp` | Legacy Path (`router_rpc_v010`) | `RouterService.*_upnp` | 骨架已就绪 |
| **Router Firewall** | `GET/POST/PUT/PATCH/DELETE /api/router/firewall*` | Legacy Path (`router_native_features_patch`) | `RouterService.*_firewall*` | 骨架已就绪 |
| **Router Native DDNS** | `GET/POST/PUT/DELETE /api/router/ddns*` | Legacy Path (`router_native_features_patch`) | `RouterService.*_ddns*` | 骨架已就绪 |
| **Router IPv6** | `GET/PUT /api/router/ipv6/*` | Legacy Path (`router_ipv6.py`) | `RouterService.*_ipv6*` | 骨架已就绪 |
| **Router Diagnostics** | `GET/POST /api/router/diagnostic` | Legacy Path (`router_native_features_patch`) | `RouterService.*_diagnostic*` | 骨架已就绪 |
| **LabProbe DDNS (KEEP)** | `GET/POST/PUT/DELETE /api/ddns*` | `lab_ddns.py` + Extension | `lab_ddns.py` + Extension | 保持资产 |
| **6→4 / 6→6 Mapping (KEEP)**| `GET/POST/PUT/DELETE /api/portmaps*` | `hub.py` + `labrelay` | `hub.py` + `labrelay` | 保持资产 |
| **STUN NAT Penetration (KEEP)**| `GET/POST/PUT/DELETE /api/stun*` | `stun_service.py` + `labrelay` | `stun_service.py` + `labrelay` | 保持资产 |
| **WireGuard VPN (KEEP)** | `GET/PUT/PATCH /api/wireguard/*` | `wireguard_service.py` + `labrelay` | `wireguard_service.py` + `labrelay` | 保持资产 |
| **Firewall Automation (KEEP)**| `GET/PUT/DELETE/POST /api/router/firewall/automation*` | `firewall_automation.py` | `firewall_automation.py` | 保持资产 |

---

## 三、临时兼容层与删除计划登记 (Temporary Duplication Registry)

> **原则**: 允许 temporary duplication，禁止 permanent duplication。每个增加的兼容层必须明确删除条件与预计删除阶段。

| 兼容层 / 适配器名称 | 所在文件 | 为什么存在 | 新路径 | 旧路径 | 预计删除阶段 | 删除条件 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `ReyeeEWebDriver (Legacy Adapter Mode)` | `router_core/driver/reyee.py` | Phase 1 骨架桥接旧 client，隔离业务风险 | `ReyeeEWebDriver (Native Mode)` | `StableRuijieRouterClient` | Stage 2 | Stage 2 完整原生能力测试通过 |
| `create_router_blueprint_v010` | `router_rpc_v010.py` | 当前生产 Blueprint 挂载点 | `create_router_blueprint_v1` | `create_router_blueprint_v099` | Stage 3 | Stage 3 Blueprint 切流测试通过 |

---

## 四、测试看板与质量门禁

- **Baseline Tests**: 317 passed
- **Phase 1 Tests**: 324 passed (0 failed, 0 skipped)
- **Current Tests**: 324 passed
- **Contract Guard Status**: PASS (74 REST + 8 WSS 0 漂移)
- **Performance Gate**: 0 增加 RPC, 0 增加 Background Loop
