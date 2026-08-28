# Router Core v1 重构进度跟踪看板

**当前状态**: **Phase 2 生产切流已完成 (Production Cutover Active)**  
**当前分支**: `refactor/router-core-v1`  
**基线回滚锚点**: Tag `v0.10.12-pre-router-core-cutover` (Commit `99581bd`)  
**全量测试状态**: **345 / 345 PASSED (100% 通过, 耗时 9.64s)**  
**最后更新时间**: 2026-08-24  

---

## 一、生产启动链路切流现状 (Production Cutover Status)

| 架构层级 | 重构前状态 | 当前生产状态 | 验证结果 |
| :--- | :--- | :--- | :---: |
| **主启动入口** (`hub_entry.py`) | 注册 `create_router_blueprint_v010` + `create_ipv6_blueprint` | **直接注册 `create_router_blueprint_v1`** | **PASS** |
| **Router 服务承载** | 多层套娃 `patch -> bridge -> v099 -> v010` | **单一正式实现 `hub.ROUTER_SERVICE` (`RouterService`)** | **PASS** |
| **驱动核心** | 猴子补丁分散劫持 `requests.Session` / RPC | **`ReyeeEWebDriver` + `ReyeeRpcClient` + `ReyeeSessionManager`** | **PASS** |
| **SWR 缓存层** | 外部 `router_slow_cache_patch` | **`RouterCache` 原生集成** | **PASS** |
| **实时引擎** | 外部 `router_ws_patch` + `fast_watchdog` | **`RouterRealtimeEngine` 统一状态机与心跳分发** | **PASS** |
| **30 个 Router Native 端点** | 生产全部走 Legacy v010 | **生产 100% 走 Router Core v1** | **PASS** |

---

## 二、74 个 App Contract 端点流向与归属矩阵

依据冻结契约 `docs/contracts/app-hub-contract-v1.json`：

1. **30 个 Router Native 端点 (已全部切入 Router Core v1 接管)**:
   - `/api/router/capabilities`
   - `/api/router/status`
   - `/api/router/dashboard` (SWR 缓存 + live 聚合)
   - `/api/router/dashboard/refresh`
   - `/api/router/devices`
   - `/api/router/port-mapping` (GET / POST / PUT / DELETE)
   - `/api/router/upnp` (GET / PUT)
   - `/api/router/firewall` (GET / POST / PUT / PATCH / DELETE / REORDER)
   - `/api/router/ddns` (GET / POST / PUT / DELETE)
   - `/api/router/ipv6/status`
   - `/api/router/ipv6/config` (GET / PUT)
   - `/api/router/ipv6/clients` (GET)
   - `/api/router/diagnostic` (GET / POST)
   - `/api/router/tasks/{kind}` (GET / POST)
   - `/api/router/beta-upgrade` (POST)
   - `/api/router/nat-diagnostic` (POST)
   - `/api/router/realtime` (GET)

2. **25 个 LabRelay Extension 端点 (100% 完整保留，不得迁入 Reyee Driver)**:
   - `6` LabProbe DDNS (/api/ddns/*)
   - `7` Portmaps 6→4 / 6→6 Relay (/api/portmaps/*)
   - `5` STUN NAT Penetration (/api/stun/*)
   - `3` WireGuard VPN (/api/wireguard/*)
   - `4` Firewall Automation (/api/router/firewall/automation*)

3. **19 个 Hub Core / Meta / Update 端点 (100% 完整保留)**:
   - `/api/devices`, `/api/sync/*`, `/api/agent/*`, `/api/daily/*`, `/api/wol/*`, `/api/auth/*` 等。

---

## 三、BE72 真机 Shadow Validation 工具链

- **验证脚本**: `api/be72_shadow_validation.py`
- **安全机制**: 严格环境变量输入（`ROUTER_IP`, `ROUTER_PASSWORD`），无密码硬编码，未配置时 Fail-Closed。
- **验证项**:
  1. 动态 Key 提取（GET `/cgi-bin/luci/`）
  2. OpenSSL EVP_BytesToKey(MD5) AES-256-CBC 加密
  3. POST `/api/auth` 登录获取有效 SID / Cookie
  4. 首次 Wire RPC 与 Single-Flight 独占锁
  5. 12 大能力 Dual-Read Shadow 比较
  6. 安全可逆写操作门禁（`read before -> write -> read-back -> restore -> read after`）

---

## 四、测试演进历史

| 阶段 | 测试总数 | 通过数 | 耗时 | 说明 |
| :--- | :---: | :---: | :---: | :--- |
| **Phase 0 Baseline** | 317 | 317 | 10.5s | 重构前基线 |
| **Phase 1 Skeleton** | 324 | 324 | 10.2s | 引入 Compat Skeleton 与 Contract Guard |
| **Phase 1.5 Driver & Cache** | 341 | 341 | 10.2s | 完成 Session, RPC, Cache, Realtime 核心 |
| **Phase 2 Production Cutover** | **345** | **345** | **9.64s** | 生产切流完成，增加 E2E 切流集成测试 |
