# Router Core v1 迁移执行进度跟踪看板

**基线分支**: `refactor/router-core-v1`  
**基线测试数**: 317 passed  
**当前测试数**: **341 passed in 9.46s (100% pass, 0 failed, 0 skipped)**  
**最新更新时间**: 2026-08-24  

---

## 一、当前阶段执行看板

| 阶段 | 名称 | 状态 | 交付物 / 核心变更 | 对应提交 |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 0** | 架构与固件全面审计 | **已完成 (Approved)** | 固件逆向、Hub 补丁、App 契约精准提取 | `93f936e` |
| **Phase 1** | 建立 Router Core 兼容骨架 | **已完成 (Approved)** | `router_core` 架构边界、Contracts、Legacy Adapter、Contract Guard | `120dcbd` ~ `aa22f0a` |
| **Stage 1** | ReyeeSessionManager & RpcClient | **已完成 (Verified)** | 动态 Key 提取、EVP_BytesToKey AES-256-CBC、Single-Flight 独占锁、Idle Timeout 维护 | `4f1e266` |
| **Stage 2** | ReyeeEWebDriver 原生能力收口 | **已完成 (Verified)** | 双模 Driver：直连 `ReyeeRpcClient` 原生能力 + 兼容旧 client adapter | `45130e0` |
| **Stage 3** | Router Core Blueprint v1 | **已完成 (Verified)** | `create_router_blueprint_v1` 覆盖 74 REST 端点规范，统一错误分类与 HTTP 状态码 | `74babb3` |
| **Stage 4** | RouterCache SWR & RouterRealtime 聚合 | **已完成 (Verified)** | SWR 缓存与 Single-Flight 收敛，8 大 WSS 帧与 45s 看门狗契约 | `334e66a` |
| **Stage 5** | 架构收口与真机验证清单准备 | **已完成 (Verified)** | 契约零漂移守护、性能门禁校验、全量测试 341 项全通 | `current` |

---

## 二、能力收口与路径状态表 (Capability Matrix)

| 能力模块 | 对应 API 端点 | 当前运行路径 | 目标收口模块 | 验证状态 |
| :--- | :--- | :--- | :--- | :--- |
| **Router Capabilities** | `GET /api/router/capabilities` | `router_core.service.blueprint` | `RouterService.get_capabilities` | **100% 契约守护** |
| **Router Status** | `GET /api/router/status` | `router_core.service.blueprint` | `RouterService.get_status` | **100% 契约守护** |
| **Dashboard Telemetry** | `GET /api/router/dashboard` | `router_core.service.blueprint` | `RouterService.get_dashboard` | **100% 契约守护** |
| **Connected Devices** | `GET /api/router/devices` | `router_core.service.blueprint` | `RouterService.get_devices` | **100% 契约守护** |
| **Native Port Mapping** | `GET/POST/PUT/DELETE /api/router/port-mapping*` | `router_core.service.blueprint` | `RouterService.*_port_mapping` | **100% 契约守护** |
| **Router UPnP** | `GET/PUT /api/router/upnp` | `router_core.service.blueprint` | `RouterService.*_upnp` | **100% 契约守护** |
| **Router Firewall** | `GET/POST/PUT/PATCH/DELETE /api/router/firewall*` | `router_core.service.blueprint` | `RouterService.*_firewall*` | **100% 契约守护** |
| **Router Native DDNS** | `GET/POST/PUT/DELETE /api/router/ddns*` | `router_core.service.blueprint` | `RouterService.*_ddns*` | **100% 契约守护** |
| **Router IPv6** | `GET/PUT /api/router/ipv6/*` | `router_core.service.blueprint` | `RouterService.*_ipv6*` | **100% 契约守护** |
| **Router Diagnostics** | `GET/POST /api/router/diagnostic` | `router_core.service.blueprint` | `RouterService.*_diagnostic*` | **100% 契约守护** |
| **LabProbe DDNS (KEEP)** | `GET/POST/PUT/DELETE /api/ddns*` | `lab_ddns.py` + Extension | `lab_ddns.py` + Extension | **产品核心资产完好** |
| **6→4 / 6→6 Mapping (KEEP)**| `GET/POST/PUT/DELETE /api/portmaps*` | `hub.py` + `labrelay` | `hub.py` + `labrelay` | **产品核心资产完好** |
| **STUN NAT Penetration (KEEP)**| `GET/POST/PUT/DELETE /api/stun*` | `stun_service.py` + `labrelay` | `stun_service.py` + `labrelay` | **产品核心资产完好** |
| **WireGuard VPN (KEEP)** | `GET/PUT/PATCH /api/wireguard/*` | `wireguard_service.py` + `labrelay` | `wireguard_service.py` + `labrelay` | **产品核心资产完好** |
| **Firewall Automation (KEEP)**| `GET/PUT/DELETE/POST /api/router/firewall/automation*` | `firewall_automation.py` | `firewall_automation.py` | **产品核心资产完好** |

---

## 三、临时兼容层与删除计划登记 (Temporary Duplication Registry)

| 兼容层 / 适配器名称 | 所在文件 | 为什么存在 | 新路径 | 旧路径 | 状态 / 删除计划 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ReyeeEWebDriver (Adapter Mode)` | `router_core/driver/reyee.py` | 支持双模运行，便于平滑过渡与回滚 | `ReyeeEWebDriver(rpc_client=...)` | `StableRuijieRouterClient` | **已支持双模，待真机全功能联调后下线** |
| `create_router_blueprint_v010` | `router_rpc_v010.py` | 旧版本入口保持向后兼容 | `create_router_blueprint_v1` | `create_router_blueprint_v099` | **新 Blueprint v1 已就绪，保持共存回滚通道** |

---

## 四、质量门禁与性能指标

- **测试总数**: **341 passed in 9.46s (0 failed, 0 skipped, 0 warning)**
- **App-Facing Contract 契约守护**: **PASS (0 diff)**
  - 74 REST Endpoints 严格与 `docs/contracts/app-hub-contract-v1.json` 一致。
  - 8 大 WSS 帧类型与 45s 看门狗超时参数 100% 吻合。
- **并发锁机制**: Single-Flight 独占锁在高并发（20-30 线程）压力下将请求折叠为 1 次真实登录/采样。
- **性能门禁**:
  - Router RPC 额外调用数: **0**
  - 新增后台轮询线程: **0**
  - 内存缓存清理策略: TTL 自动过期 + 最大 256 元素 LRU 淘汰
