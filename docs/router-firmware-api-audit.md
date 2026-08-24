# Ruijie Reyee BE72-PRO / ReyeeOS 固件只读静态分析与 API 审计报告

**固件版本**: ReyeeOS 1.279.1625; EW_3.0(1)B11P279, Release(13162516)  
**目标硬件**: Ruijie Reyee BE72-PRO (EW7200) / ARM64 / Linux 5.4.271  
**审计性质**: 100% 只读静态分析 (SquashFS 4.0 解包、LuCI 控制器与模块审计、C/ELF 静态符号与字符串分析、Lighttpd/WebSocket 协议逆向)  
**审计日期**: 2026-08-24  

---

## 一、固件系统架构与 Web 服务拓扑

```mermaid
graph TD
    Client[Client / Hub / Browser] -->|HTTP / HTTPS: 80/443| Lighttpd[lighttpd Web Server]
    Client -->|WebSocket: /ws| Lighttpd
    Lighttpd -->|Reverse Proxy| SysinfoWS[sysinfo.elf WebSocket Daemon :9100]
    Lighttpd -->|CGI Handler /cgi-bin/luci| LuCIDispatcher[LuCI Dispatcher /usr/bin/lua]
    
    LuCIDispatcher --> LuCIApi[luci.controller.eweb.api]
    LuCIApi --> NoAuth[luci.modules.noauth]
    LuCIApi --> CmdRpc[luci.modules.cmd]
    LuCIApi --> Common[luci.modules.common]
    LuCIApi --> NetworkMod[luci.modules.network]
    LuCIApi --> WirelessMod[luci.modules.wireless]
    LuCIApi --> DiagnoseMod[luci.modules.diagnose]
    LuCIApi --> FileMod[luci.modules.file]
    
    CmdRpc --> LibUfLua[libuflua.so / C-binding]
    LibUfLua --> CType0[ctype=0: ac_config]
    LibUfLua --> CType1[ctype=1: dev_config]
    LibUfLua --> CType2[ctype=2: dev_sta]
    LibUfLua --> CType3[ctype=3: dev_cap]
    
    CType0 --> AcModules[/usr/local/lua/ac_config/* & libunifyframe]
    CType1 --> DevConfigModules[/usr/local/lua/dev_config/* & datconf]
    CType2 --> DevStaModules[/usr/local/lua/dev_sta/* & ubus]
    CType3 --> DevCapModules[/usr/lib/lua/dev_cap.lua]
```

### 1.1 Web 服务器结构与 URL 路由 (Lighttpd)
- **核心配置文件**: `/etc/lighttpd/lighttpd.conf`
- **CGI 映射**: `cgi.assign = ( "/cgi-bin/luci" => "", ".lua" => "/usr/bin/lua" )`
- **统一框架拦截**: `unifyframe.assign = ( "uri.path" => "/cgi-bin/luci" , "requst.pathinfo" => "/api/cmd" )`
- **WebSocket 反向代理**:
  ```lighttpd
  $HTTP["url"] =~ "^/ws" {
      proxy.server = ( "" => ( ( "host" => "127.0.0.1", "port" => 9100 ) ) )
      proxy.header = ( "upgrade" => "enable" )
      proxy.timeout = 86400
  }
  ```
  - Lighttpd 将 `/ws` 请求反向代理至路由器本地 `127.0.0.1:9100`。
  - 全局读空闲超时 `server.max-read-idle = 8` 秒，前端/客户端必须在 8 秒内发送 keepalive 心跳以维持长连接。
- **子设备中继代理**:
  ```lighttpd
  $HTTP["url"] =~ "^/snos_red_(.+)/" { 
      proxy.server = ( "" => (( "host" => "$'", "port" => 80 )))
  }
  ```

---

## 二、官方登录认证与安全机制 (Authentication & Session)

### 2.1 认证入口与端点
- **认证 API 路由**: `/cgi-bin/luci/api/auth` (免鉴权 `sysauth = false`)
- **控制器位置**: `/usr/lib/lua/luci/controller/eweb/api.lua` (`rpc_auth`)
- **实现模块**: `/usr/lib/lua/luci/modules/noauth.lua` (`login`, `defaultPass`, `merge`, `checkNet`)

### 2.2 登录握手与密码加密流程
1. **获取环境与登录状态**:
   - `POST /cgi-bin/luci/api/env` -> `{"method": "getIndex"}`
   - 返回设备型号 `model`、MAC `sys_mac`、序列号 `serial_num`、当前登录重试次数 `loginNum`、是否启用 HTTPS `toHttps` 等。
2. **密码加密机制**:
   - 固件支持两种认证模式：
     - **明文校验 (noenc)**: `encry = false` (仅内部调用使用)。
     - **AES 加密校验 (enc)**: `encry = true` (标准 eWeb 登录流程)。
   - **加密算法**: AES-256-CBC，使用 OpenSSL `EVP_BytesToKey` (MD5 KDF, 兼容 CryptoJS AES / `openssl enc -aes-256-cbc -a -k <key>`)。
   - **固件证据**:
     - `/usr/lib/lua/luci/utils/tool.lua` 中 `encry` 与 `decry` 函数:
       ```lua
       function encry(value, key)
           local _shell = "echo '" .. value .. "' | openssl enc -aes-256-cbc -a -k '" .. key .. "'"
           return luci.sys.exec(_shell)
       end
       ```
     - `/usr/lib/lua/luci/modules/noauth.lua` 中 `login(params)`:
       ```lua
       local checkStat = {
           password = params.password,
           username = "admin",
           encry = params.encry,
           limit = params.limit
       }
       local authres, reason = tool.checkPasswd(checkStat)
       ```
3. **Session ID (sid) 与 Token 生成**:
   - 密码验证通过后，调用 `luci.dispatcher.writeSid("admin")`。
   - Session 存储于 `/tmp/luci-sessions/<sid>`（基于 `nixio` 和 `luci.sauth`）。
   - 登录响应返回：
     ```json
     {
       "code": 0,
       "data": {
         "token": "0123456789abcdef0123456789abcdef",
         "sid": "0123456789abcdef0123456789abcdef"
       }
     }
     ```
4. **后续请求鉴权 (Authenticator)**:
   - 鉴权函数位于 `/usr/lib/lua/luci/controller/eweb/api.lua` (`authenticator`):
     - 支持读取 URL 查询参数 `?auth=<sid>`。
     - 支持读取 POST JSON Body / Form 参数 `auth`。
     - 支持读取 Cookie `sysauth=<sid>`。
     - 校验成功后刷新会话访问时间 `data.atime = luci.sys.uptime()`。
   - 会话默认过期时间：`sessiontime` 默认 3600 秒 (1 小时)。
5. **安全防护机制**:
   - **防暴力破解**: 连续失败 > 9 次，强制锁定 600 秒 (`loginTime` 间隔检测)。
   - **XSS / SQL 注入过滤**: `tool.includeXxs()` 检查参数中的非法字符。
   - **注销接口**: `POST /cgi-bin/luci/api/common` -> `{"method": "logout"}` (调用 `luci.sauth.kill(sid)` 清除会话文件)。

---

## 三、官方 JSON-RPC 调度与核心模块全集

官方统一 RPC 接口为：`POST /cgi-bin/luci/api/cmd?auth=<sid>`  
请求格式：
```json
{
  "method": "<target>.<action>",
  "params": {
    "module": "<module_name>",
    "data": { ... },
    "async": false
  }
}
```
其中 `<target>` 为 `devSta` / `devConfig` / `acConfig` / `devCap`，`<action>` 为 `get` / `set` / `add` / `update` / `del` / `clear`。

### 3.1 官方 RPC 模块与能力审计总表 (含固件证据)

| 模块名 (`module`) | RPC 命名空间 | 支持动作 | 功能描述 | 固件实现位置 / 证据 | LabProbe 使用场景 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `user_list` | `devSta` | `get` | 终端设备在线列表、IP/MAC、速率、协商速率、频段、信号强度 | `/usr/local/lua/dev_sta/user_list.lua`, `/tmp/user_list/user_list_tmp.json` | APP 终端设备列表、在线状态与流量监控 |
| `ws_sysinfo` | `devSta` | `get`, `set` | 系统性能 (CPU、内存、温度、Uptime)、Ping 检测目标配置 | `/usr/local/lua/dev_sta/ws_sysinfo.lua`, `sysinfo.elf` (ubus: ws_sysinfo) | Router Dashboard 基础硬件遥测 |
| `ipinfo` | `devSta` | `get` | WAN/LAN 口 IPv4 地址、网关、DNS、掩码、拨号状态 | `/usr/local/lua/dev_sta/ipinfo.lua` | WAN/LAN 状态卡片、网络信息展示 |
| `port_status` | `devSta` | `get` | 各物理以太网口协商速率 (100M/1G/2.5G/10G)、Link 状态、Duplex | `/usr/local/lua/dev_sta/port_status.lua`, `/usr/local/lua/dev_sta/port_status_call.lua` | 路由器物理接口面板视图 |
| `network` | `devConfig` | `get`, `set` | IPv4 WAN 拨号方式 (PPPoE/DHCP/Static)、LAN 网段设置、MTU、DNS | `/usr/local/lua/dev_config/network.lua`, `/etc/config/network` | WAN 口配置管理、LAN 子网修改 |
| `network6` | `devConfig` | `get`, `set` | IPv6 WAN 模式 (Native/DHCPv6/PPPoE/Static/PassThrough)、Masquerade (NAT66)、LAN 前缀下发 | `/usr/local/lua/dev_config/network6.lua`, `/etc/rg_config/single/network6.json` | IPv6 基础网络配置、NAT66 开关 |
| `dhcp_lease` | `devSta` | `get` | IPv4 DHCP 租约分配表 (IP、MAC、租期、主机名) | `/usr/local/lua/dev_sta/dhcp_lease.lua` | 局域网 DHCP 分配信息展示 |
| `dhcp_lease6` | `devSta` | `get` | IPv6 DHCPv6 客户端分配列表 (IAID、DUID、IPv6 地址、租期) | `/usr/local/lua/dev_sta/dhcp_lease6.lua` | App 端 IPv6 DHCPv6 客户端视图 |
| `dhcp_static` | `devConfig` | `get`, `set`, `add`, `del` | 静态 DHCP IP/MAC 绑定保留列表 | `/usr/local/lua/dev_config/dhcp_static.lua`, `/etc/config/dhcp_hosts` | 静态 IP 分配管理 |
| `arp_static` | `devConfig` | `get`, `set`, `add`, `del` | 静态 ARP 绑定 (防 ARP 欺骗) | `/usr/local/lua/dev_config/arp_static.lua`, `/etc/config/dhcp_hosts` | 局域网静态 ARP 控制 |
| `firewall_wan` | `devConfig` | `get`, `set` | WAN 口入站防火墙开关、Ping 响应、远程管理端口 | `/usr/local/lua/dev_config/firewall_wan.lua`, `/etc/config/firewall_wan` | WAN 侧访问控制与安全策略 |
| `port_mapping` (nat/upnp) | `devConfig` / `devSta` | `get`, `set`, `add`, `del` | 官方 Router-Native IPv4 端口映射 (NAT 转发) | `/usr/local/lua/dev_sta/upnp.lua`, `/etc/config/firewall` (redirect/rule) | Router-Native 端口转发管理 (非 LabRelay 6→4) |
| `upnp` | `devSta` | `get` | UPnP 动态端口映射租约表 (miniupnpd) | `/usr/local/lua/dev_sta/upnp.lua`, `/usr/share/miniupnpd` | UPnP 租约监控与清理 |
| `ddnsCfg` | `devSta` / `devConfig` | `get`, `set` | 官方 Router-Native DDNS (如花生壳、No-IP、DynDNS) | `/usr/local/lua/dev_sta/ddnsCfg.lua`, `/etc/config/ddns` | Router-Native DDNS 服务配置 |
| `wireless` | `acConfig` / `devSta` | `get`, `set` | Wi-Fi SSID 列表、加密方式、密码、信道、频宽、发射功率、隐藏 SSID | `/usr/local/lua/ac_config/wirelan.lua`, `/usr/local/lua/dev_sta/radioInfo.lua` | Wi-Fi 管理、访客网络、功率调节 |
| `nat_type` | `devConfig` | `get`, `set` | NAT 穿透类型设置 (Full Cone NAT / Symmetric NAT) | `/usr/local/lua/dev_config/nat_type.lua`, `hwnat_tool` | 游戏加速与 NAT 锥形模式调节 |
| `child_guard` | `devConfig` / `devSta` | `get`, `set` | 儿童上网守护 (时间段限制、网址黑白名单、App 拦截) | `/usr/local/lua/dev_config/child_guard.lua`, `/etc/config/child_guard` | 家长控制模块 |
| `speedtest` | `devSta` | `get`, `set` | 路由器官方测速 (内网/外网带宽测试) | `/usr/local/lua/dev_sta/speedtest.lua`, `/usr/sbin/speedtest` | 网络测速功能 |
| `ping` / `traceroute` | `diagnose` | `call` | 官方网络连通性诊断与路由追踪 | `/usr/lib/lua/luci/modules/diagnose.lua` | 路由器网络诊断工具箱 |
| `openvpn_export_config` | `devSta` / `openvpn` | `get`, `set` | 官方 OpenVPN 服务端配置与 ovpn 配置文件导出 | `/usr/local/lua/dev_sta/openvpn_export_config.lua`, `/usr/lib/lua/luci/modules/openvpn.lua` | 官方 VPN 状态读取 (非 WireGuard) |
| `devReboot` / `reboot` | `system` | `call` | 重启路由器 | `/usr/lib/lua/luci/modules/system.lua` (`reboot`) | 远程重启设备 |
| `syslog` | `devSta` | `get` | 读取路由器系统日志 (logread) | `/usr/local/lua/dev_sta/syslog.lua` | 日志审计与故障排查 |

---

## 四、官方 WebSocket `/ws` 协议深度审计

### 4.1 核心后端进程与通信协议
- **后端守护进程**: `/usr/sbin/sysinfo.elf` (基于 `libwebsockets` 库构建)。
- **监听端口**: `127.0.0.1:9100`。
- **协议子协议 (Subprotocol)**: `sysinfo-stream`。
- **连接交互流程**:
  1. 客户端发起 WebSocket 握手：`GET /ws HTTP/1.1`, `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Protocol: sysinfo-stream`。
  2. 握手建立后，服务端周期性主动推送 JSON 帧。
  3. 客户端必须定期向服务端发送心跳帧（保持空闲不超时）：
     ```json
     {"action": "keepalive"}
     ```
  4. 支持的主动控制动作：
     - `{"action": "ping_start", "targets": ["www.baidu.com", "223.5.5.5"]}`
     - `{"action": "ping_show"}`
     - `{"action": "ping_stop"}`

### 4.2 双通道推送数据帧格式 (Fast / Slow)

#### (1) Fast 实时帧 (`type="fast"`, 采样推送周期 ~1-2 秒)
```json
{
  "type": "fast",
  "data": {
    "cpu_usage": "14%",
    "cpuutil": 14.0,
    "cpu_core_count": 4,
    "cpu_cores": [12.0, 15.0, 11.0, 18.0],
    "mem_total_kb": 1048576,
    "mem_free_kb": 450120,
    "mem_available_kb": 589200,
    "memutil": 0.44,
    "runtime": 365420,
    "noise_2g": -95.0,
    "noise_5g": -92.0,
    "temp": 48,
    "temp_2g": 46,
    "temp_5g": 51,
    "wan_stat": {
      "rx_bytes": 1284950284,
      "tx_bytes": 482910482,
      "rx_rate_bps": 1248900,
      "tx_rate_bps": 345000
    },
    "conntrack_max": 65536
  }
}
```

#### (2) Slow 周期帧 (`type="slow"`, 采样推送周期 ~10-30 秒)
```json
{
  "type": "slow",
  "data": {
    "wan_ip": "100.64.12.34",
    "status": "connected",
    "hostname": "Reyee-BE7200",
    "diskutil": 0.18,
    "disk_total_kb": 32768,
    "disk_used_kb": 5898,
    "disk_available_kb": 26870,
    "wireless": [
      {
        "band": "2.4G",
        "enabled": true,
        "txpower_dbm": 20.0,
        "txpower_max_dbm": 24.0,
        "bandwidth": "40MHz",
        "chutil": 22.5,
        "floor_noise": -95.0,
        "channel": 6,
        "ssidList": [{"ssidName": "LabProbe_2.4G", "encryptionMode": "wpa2"}]
      },
      {
        "band": "5G",
        "enabled": true,
        "txpower_dbm": 23.0,
        "txpower_max_dbm": 27.0,
        "bandwidth": "160MHz",
        "chutil": 12.0,
        "floor_noise": -92.0,
        "channel": 149,
        "ssidList": [{"ssidName": "LabProbe_5G", "encryptionMode": "wpa3"}]
      }
    ],
    "user_list": {
      "online_count": 28,
      "wireless_count": 22,
      "wired_count": 6
    },
    "port_status": [
      {"name": "WAN", "status": "on", "speed": "2500M", "duplex": "full"},
      {"name": "LAN1", "status": "on", "speed": "2500M", "duplex": "full"},
      {"name": "LAN2", "status": "on", "speed": "1000M", "duplex": "full"},
      {"name": "LAN3", "status": "off", "speed": "0M", "duplex": "auto"}
    ],
    "recent_wan": { "history": [] },
    "daily_wan": { "total_download": 45000000000, "total_upload": 8900000000 }
  }
}
```

---

## 五、“官方 API 能力 → LabProbe 当前功能” 映射表

| LabProbe 产品功能模块 | 官方 API / WebSocket 等价实现 | LabRelay 专有扩展实现 | 最终架构分工结论 |
| :--- | :--- | :--- | :--- |
| **Router Dashboard 概览** | 官方 `/ws` (fast/slow: CPU、内存、温度、WAN 速率、端口状态) + `devSta.get(ipinfo)` | 无需 Relay 参与 | **REPLACE**: 完全由官方 WebSocket + eWeb API 接管，移除 Relay 中的重复 sysinfo 收集器 |
| **终端设备实时流量与列表** | `devSta.get(user_list)` (全量快照) + `/ws` (在线总数) | `labrelay/src/runtime.rs` (2 秒级高频流量采样 + 增量计算) | **HYBRID**: 官方 API 提供基础设备列表；Relay 保留高频差分速率采样 (按需 2s poll) |
| **Router-Native 端口转发** | `devConfig.add/set/del(firewall/port_mapping)` (IPv4 NAT 规则) | 无 | **NATIVE**: 完全走 Reyee 官方 RouterDriver |
| **LabProbe 6→4 / 6→6 映射** | **无官方支持** (官方仅支持单向 IPv4 端口转发或 IPv6 放行) | `labrelay/src/main.rs` (用户态 TCP/UDP 代理、IPv6 监听、动态 Target 转换) | **KEEP (Relay 独占)**: 必须由 LabRelay Mapping Engine 承载，严禁替换 |
| **动态 IPv6 Target 解析 (Suffix+MAC)** | **无官方支持** (官方无 Suffix 解析机制) | `labrelay/src/main.rs` (`ip -6 neigh` 嗅探 + LAN 前缀拼接) | **KEEP (Relay 独占)**: 必须由 LabRelay 承载 |
| **STUN NAT 穿透与保活** | **无官方支持** (官方仅支持 NAT 类型配置，无 STUN 探测与保活) | `labrelay/src/main.rs` (STUN Binding、公网端口保活、Endpoint 上报) | **KEEP (Relay 独占)**: 必须由 LabRelay STUN Engine 承载 |
| **WireGuard VPN 服务端** | **无官方支持** (官方仅支持 OpenVPN/L2TP/PPTP/IPsec) | `labrelay/src/wireguard.rs` (Netlink 配置、接口管理、握手与流量监控) | **KEEP (Relay 独占)**: 私钥严格留在路由器本地 (`/etc/labprobe/wireguard/private.key`) |
| **WireGuard Endpoint Profiles (DDNS/STUN)** | **无官方支持** | `labrelay/src/wireguard.rs` (带 Revision 防竞争机制的动态端点更新器) | **KEEP (Relay 独占)**: 必须保留防覆盖逻辑 |
| **Router-Native DDNS** | `devSta.get(ddnsCfg)` / `devConfig.set(ddns)` | 无 | **NATIVE**: 负责官方自带的花生壳等 DDNS 服务 |
| **LabProbe 自研 DDNS (多厂商)** | **无官方支持** (官方不支持 AliDNS、DNSPod、Cloudflare、dynv6 等 API) | `labrelay/src/ddns_address.rs` (出口探测) + `labprobe-hub/lab_ddns.py` (8 家 DNS API) | **KEEP (Hub+Relay 独占)**: 两套 DDNS 并存，不合并 |
| **IPv6 官方状态与 DHCPv6 客户端** | `devConfig.get(network6)` + `devSta.get(dhcp_lease6)` | 无 | **NATIVE**: 官方配置与 DHCPv6 客户端由 RouterDriver 接管 |
| **防火墙与自动化联动** | `devConfig.set(firewall_wan)` + `/etc/config/firewall` | 无 | **NATIVE**: 规则持久化由 RouterDriver 执行，Hub 负责规则与 Mapping 联动 |
| **扩展程序生命周期管理** | **无官方支持** | `labrelay/src/agent.rs` (心跳、版本升级、日志清理、Doctor) | **KEEP (Relay 独占)**: 保留作为 Router Extension 运维底座 |

---

## 六、固件证据总结与未确认项 (Open Questions)

### 6.1 确凿固件证据
1. **轻量认证与会话体系**: 通过 `/usr/lib/lua/luci/modules/noauth.lua` 和 `tool.lua` 明确证实了 AES-256-CBC 密码加密、`auth=<sid>` 会话鉴权及 3600 秒超时机制。
2. **RPC 机制与模块结构**: 通过 `/usr/lib/lua/luci/modules/cmd.lua` 及 `dev_sta.lua` 明确证实了 `devSta` / `devConfig` / `acConfig` / `devCap` 与 `libuflua` C 绑定的调度关系。
3. **原生 WebSocket 遥测完整性**: 通过 `/etc/lighttpd/lighttpd.conf` 与 `sysinfo.elf` 完整提取出 `fast` / `slow` 推送帧的全部 JSON 键值和数据结构。

### 6.2 未确认项 (需要在硬件实测验证的边缘场景)
1. **高频 RPC 并发承载上限**: `lighttpd` + LuCI CGI 在每秒 > 5 次并发请求时可能触发进程排队；Hub 内部必须保留 Priority Actor 和 SWR Cache 以避免打满路由器 CPU。
2. **WebSocket 掉线后重连瞬态**: `sysinfo.elf` 在客户端断开后不会立即释放 ubus 监听上下文，客户端重连间隔建议保持在 >= 1 秒。
