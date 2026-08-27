# LabProbe 变更记录

## 0.11.6

- **路由器管理鉴权增强**：增加输入管理地址自动规范化清洗，防止子路径导致 404；支持从多种字段与 Cookie 宽容提取登录凭证，消除非 BE72 硬件或不同固件下的登录误判。
- **连通性测试探针通用化**：保存配置连通性测试改用通用探针，避免单路由模式下因不支持 AC 控制器模块阻断配置保存。
- **Relay 端口映射指令路由归一化**：增强 `api_router_portmap_commands` 与 `api_router_portmap_ack` 的别名解析，确保 Agent 以默认 `router` 名称轮询时与 Hub 设定的 `primary_router_name` 正确匹配，彻底解决端口映射指令下发跳过、操作失效的问题。

## 0.11.5

- **STUN 规则可靠性**：保留自定义内网目标端口，切换传输协议发生同协议监听冲突时安全重分配监听端口，并正确解析字符串布尔值。
- **执行状态可见**：向 App 返回 Agent 同步错误与路由器原生映射错误，停止规则不再被旧运行状态误报为已映射。
- **状态文件治理**：压缩已完成命令记录，删除规则时同步清理地址历史，避免长期运行后状态文件持续膨胀。

## 0.11.4

- **Router Native DDNS 身份修复**：读取时分别保留路由器原生记录 ID（`service`）与服务商名称（`service_name`），返回字段继续兼容现有 App 契约。
- **Router Native DDNS 开关修复**：写入时将 App 的 `enable` 映射为路由器原生 `enabled` 字段，并保持 `ddnsCfg` RPC envelope 与路由器 Web 管理端一致。
- **部署固定版本**：Docker Compose 默认镜像更新为 `onlychallgener/labprobe-hub:0.11.4`，发布仅更新 `latest`、`0.11.4` 与 `v0.11.4` 标签。

## 0.11.3

- **Router Native DDNS 解析修复**：修复 Reyee BE72 固件 `devSta.get ddnsCfg` 返回 JSON 数组字符串或列表对象时被误判为非 dict 导致返回空列表的问题；同时输出 `list` 与 `services` 保证对 App 的完全兼容。
- **部署固定版本**：Docker Compose 默认镜像更新为 `onlychallgener/labprobe-hub:0.11.3`。

## 0.11.2

- **Router Core 数据恢复**：原生 DDNS 正确解包 BE72 的 JSON/嵌套响应；eWeb WebSocket 的 2.4G、5G 温度和存储占用进入 Core realtime 与 Dashboard。
- **宽带凭据恢复**：重新接入旧 main 已验证的 Hub 直读凭据入口，保留凭据仅驻内存；Relay 只在固件未暴露完整字段时执行原有路由器本地扩展读取。
- **Agent 运维恢复**：更新命令使用实际解析成功的 GitHub/镜像源地址，过期命令不再阻塞“立即更新”和“一键清理”。
- **Relay 扩展边界**：继续忽略 Relay 路由遥测，同时保留 LabProbe DDNS 地址与 WireGuard 扩展状态上报。
- **路由连接设置**：新增受 APP Token 保护的 `GET/PUT /api/router/config`，配置加密落盘并在 Hub 内热切换 Router Core 会话与 WebSocket。
- **接口验收**：CI 逐项核对 APP 的 76 个 HTTP 契约与 Hub 生产路由表。
- **部署固定版本**：Docker Compose 默认镜像更新为 `onlychallgener/labprobe-hub:0.11.2`。

## 0.11.1

- **BE72 生产认证**：恢复固件实际使用的 AES 登录载荷、序列号会话 Cookie、SID 校验与签名 CMD 请求。
- **Router Core 唯一数据源**：Dashboard、路由状态、设备与配置 API 统一由 `ReyeeEWebDriver` 提供，RouterLite 只保留 Relay demand/ack 控制端点且不再接收实时数据。
- **实时首帧恢复**：BE72 `fast` WebSocket 帧直接进入 `RouterRealtimeEngine`，生产 WSS 输出 APP 契约字段，并在数据流停滞时快速重连。
- **原生能力接通**：设备、IPv6、端口映射、UPnP、防火墙、DDNS、NAT、自检和 Beta 查询均使用经旧版验证的 eWeb module envelope。
- **部署固定版本**：Docker Compose 默认镜像固定为 `onlychallgener/labprobe-hub:0.11.1`，保留既有 APP/HOOK Token、MQTT 与 `config.yaml` 配置。

## 0.11.1-rc1

- **Router Core 实时主链路**: Reyee eWeb `fast` 帧直接进入 `RouterRealtimeEngine`，生产 WSS 订阅 Core 引擎并向 APP 推送首帧与后续帧。
- **APP contract 修复**: 路由实时字段统一为 `uploadBps`、`downloadBps`、`cpuPercent`、`memoryPercent` 与 `sampleEpochMs`。
- **升级兼容**: Router Core 继续读取既有 `ROUTER_EWEB_*` Compose 变量与加密 `config/router_eweb.json`，保留 APP、HOOK 与 MQTT 配置行为。

## 0.11.0 / LabRelay 0.2.28

- **Router Core v1 架构生产切流**: 生产主干正式由 `RouterService` 与 `create_router_blueprint_v1` 接管，统一承载 30 个原生路由 API 端点；
- **单一职责实现收口**: 核心鉴权由 `ReyeeSessionManager`（动态 Key 提取 + EVP MD5 AES-256-CBC + 3600s Idle Timeout + Single-Flight 并发防重登录锁）统一收拢；
- **RPC 与缓存优化**: `ReyeeRpcClient` 原生对接 `/api/cmd?auth=<sid>` Wire 协议并内置断路器；引入 `RouterCache` SWR 引擎降低路由器 CPU 负载；
- **实时事件规范化**: `RouterRealtimeEngine` 提供 3.0s 空闲心跳广播，严密适配 Android Client 45s 断线看门狗容差；
- **BE72 Shadow 验证工具链就绪**: 提供 `api/be72_shadow_validation.py`，支持 12 大能力 Dual-Read 字段对比与安全可逆写操作门禁；
- **LabRelay 自研核心能力 100% 保留**: LabProbe DDNS、6→4/6→6 映射转发、STUN NAT 穿透、WireGuard VPN、Agent 双进程拓扑完整兼容，LabRelay 保持 0.2.28 不变。


## 0.10.12 / LabRelay 0.2.28

- WireGuard 服务端支持 `POST` 别名方法与 `enabled: false/true` 开关控制；
- 下发服务端停用命令时自动将 `labwg0` 接口置为 down 并释放相关防火墙规则，避免与官方固件或第三方服务端冲突；
- LabRelay 升级至 0.2.28，配套 APP v0.10.52 build 207。

## 0.9.19 / LabRelay 0.2.11

- APP v0.10.15 build152 使用轻量路由接口成功响应作为 5 秒实时连接租约；APP 与 Hub 失联后停止终端实时请求、200ms 平滑渲染和缓存计算。
- 断线期间 APP 只保留一个路由恢复探测，并按 3 / 5 / 10 / 15 秒逐级退避；连接恢复后自动恢复每秒采样和短时平滑显示。
- Hub 的实时样本写入同样受 APP 租约约束：租约过期后，Relay 的尾部推送只用于返回“停止采样”状态，不再覆盖或追加路由与终端缓存。
- Hub 继续保留最后一帧有效内存样本用于页面连续性，但不写 SQLite、revision 或历史曲线，也不会由 Relay 推送续租。
- APP 退到后台、被关闭、网络中断或认证失败时，5 秒租约自然到期；LabRelay 随后退出每秒 `dev_sta` 采集并恢复 55 秒长轮询。
- 配套版本：APP v0.10.15 build152、Hub 0.9.19、LabRelay 0.2.11。

## 0.9.18 / LabRelay 0.2.11

- 实时数据源改为路由器本地 LabRelay，不再由 Hub 高频调用 eWeb/CMD，也不依赖路由器 WSS 的实际推送周期。
- APP 首次请求 `/api/router/realtime` 或 `/api/devices/realtime` 时，Hub 通过 55 秒长轮询立即唤醒 Relay；APP 持续前台请求时维持 5 秒需求租约。
- Relay 在本机并行执行 `dev_sta get -m ws_sysinfo '{"get":"fast"}'` 与 `dev_sta get -m user_list '{"devType":"all","dataType":"timely"}'`，沿用此前 SSH 快速读取的本地执行路径。
- Relay 只上传网速、连接数、CPU、内存、温度、运行时间及终端 MAC/实时上下行/连接数等小字段，不上传完整 Dashboard 或完整终端资料。
- Hub 的 APP 接口只读取内存样本，正常请求不等待路由器；完整设备、配置、DDNS、NAT 等仍走原有低频 eWeb 同步，互不阻塞。
- APP 退出前台且 5 秒需求租约到期后，Relay 停止高频本地采集和推送，恢复长轮询，避免全天产生无效流量。
- 路由与终端命令并行执行，单次本地命令限制约 1.4 秒；一个命令失败或超时不会阻塞另一个样本。
- 配套 APP 使用 v0.10.15 build151；Hub 升级到 0.9.18，路由器 LabRelay 必须升级到 0.2.11。

## 0.9.15 / LabRelay 0.2.10

- 路由器实时仪表盘与终端列表拆成独立线程，慢速终端 RPC 不再阻塞 WSS 快数据刷新。
- WSS 快照默认每 1 秒归一化并写入 Hub 内存，APP 可连续读取最新速率、连接数、CPU、内存和温度。
- 瞬时空响应不再清空已有仪表盘，Hub 会深度合并新快照并保留上一份完整配置，避免刷新时页面变白。
- 手动刷新立即返回并在后台更新终端和配置，不再长时间占用 APP 刷新按钮。
- 路由器状态接口统一返回中文，并区分“已连接且数据正常”“已连接正在同步”“连接恢复中”。
- Hub 直接复用现有 eWeb 会话读取完整 PPPoE 账号密码；固件仅返回部分字段时，由轻量 Agent 指令长轮询触发路由器本地 `dev_config network` 兜底，凭证只保存在 Hub 内存。
- LabRelay 默认启用 Hub 直连模式，不再上传完整仪表盘、终端列表和设备事件；仅保留 IPv6 邻居、6to6、端口映射及按需凭证兜底。
- Relay 使用 55 秒长轮询维持约 1 分钟的 IPv6 检查节拍；账号密码刷新会立即唤醒，不需要等待下一轮。状态心跳和端口映射状态降为 5 分钟。
- IPv6 快照仅在地址或邻居内容变化、或 15 分钟心跳时发送；忽略 REACHABLE/STALE 状态抖动，避免每天产生数 MB 无效流量。
- Hub 与 Relay 均拒绝空账号、空密码或掩码密码；无效结果不会覆盖上一份有效内存缓存，也不会确认刷新序号，后续会自动重试。
- 路由 NAT 结果继续携带请求上下文用于诊断；APP 的最近检测按 RFC3489/RFC5780 协议分组，STUN 端口不参与历史分组。
- Hub 版本保持 0.9.15；LabRelay 提升至 0.2.10，需要同步更新路由器端 Agent。

## 0.9.14 / LabRelay 0.2.9

- 新增路由器原生 NAT 诊断接口，支持 RFC 3489、RFC 5780、WAN/WAN1、可选 STUN 服务器与检测结果轮询。
- 新增 ReyeeOS Beta 在线版本检查接口，读取当前版本和可用固件列表；在实际安装负载确认前不执行升级。
- NAT 诊断与 Beta 检查复用现有 eWeb SID、Cookie 和 CMD 签名链路，不创建第二套登录会话。
- APP 路由器状态页可每约 2 秒读取 Hub 内存中的最新 WebSocket 快照；配置类 CMD 仍保持低频校准。
- Hub 版本提升至 0.9.14；LabRelay 继续使用 0.2.9，无需更新。

## 0.9.13 / LabRelay 0.2.9

- 新增锐捷 eWeb 原生 `/ws` WebSocket 长连接，直接接收 `static`、`slow`、`fast`、`recent_wan` 与 `daily_wan` 数据。
- 路由器实时 CPU、内存、温度、运行时间、WAN 速率、连接数、端口和无线电状态改由 WebSocket 主动推送，减少高频 CMD 轮询。
- WebSocket 连接后自动发送 `get_recent_wan`、`get_daily_wan`、`ping`，并每 10 秒发送 `keepalive`；断线后指数退避自动重连。
- CMD 继续负责终端列表、无线配置、DDNS、防火墙、端口映射等查询和控制；仪表盘配置默认每 30 秒校准一次。
- 合并 `acConfig.get / wireless` 与 WebSocket 无线实时状态，避免 WebSocket 空 `ssidList` 覆盖真实 Wi-Fi 名称。
- 兼容 WebSocket `port_status.List`、2.4G/5G 实时信道与利用率，并继续保留 HTTP/CMD 作为断线兜底。
- Hub 版本提升至 0.9.13；镜像继续保持轻量 AMD64/ARM64 双架构，不引入浏览器内核。

## 0.9.12 / LabRelay 0.2.9

- 路由器 eWeb 登录改为直接 HTTP 会话：先读取 `/cgi-bin/luci/` 中的动态 GibberishAES 密钥，再加密管理密码并调用 `/cgi-bin/luci/api/auth`。
- 登录成功后在 Hub 内存中缓存 `sid`、Cookie、token、sn 与登录时间；后续业务接口统一使用 `?auth=<sid>` 并复用同一个 `requests.Session`。
- 同时兼容 `password/limit/setInit` 与 `username/pwd/isCheckReadAgreement` 两种登录参数格式，适配不同 ReyeeOS/eWeb 固件。
- 只有收到 401/403、登录页重定向或本地会话到期时才串行重新登录一次，避免高频轮询导致重复登录和持续 403。
- 删除 Playwright、Chromium、Firefox、Selenium 与独立 `router-browser` 容器，Hub 恢复轻量 AMD64/ARM64 镜像。
- Hub 版本保持 0.9.12；APP 与 LabRelay 版本不变。

## 0.9.7 / LabRelay 0.2.8

- LabRelay 每小时执行一次 `df -h /overlay`，优先上报可写 Overlay 分区的真实磁盘利用率。
- 磁盘采集失败时保留上一次有效值，并按小时重试，避免高频执行 SSH/系统命令。
- 配合 APP v0.10.10 build140 增加 SSH 执行记录三级页面及可选命令文本复制。

## 0.9.6 / LabRelay 0.2.7

- LabRelay 从 `ws_sysinfo fast` 归一化磁盘/存储利用率并随路由器实时状态上报。
- 配合 APP v0.10.9 build139 发布，统一提升 Hub 与 LabRelay 版本号。
- 本次 Hub 与 LabRelay 不改变采集、存储、清理、更新或推送逻辑。

## 0.9.5 / LabRelay 0.2.6

- 新增 Agent 一键清理指令链路：APP 经 Hub 下发，LabRelay 清理 `/etc/labprobe/backups`、非必要 `/tmp` 日志和失效安装临时文件。
- 清理结果回传已删除分类、项目数量、异常项和回收空间；配置、当前程序和状态数据不会删除。
- 修复 Agent 状态上报可能误将清理任务按更新任务提前完成的问题。
- 路由器状态页 WAN、网络配置和 AP 信息改为固定四卡片布局，并修复背景图层与网口视觉。
- WAN 运营商由 LabRelay/Hub 识别；新增 WAN/WAN1 接口显示、LAN MAC 与按需读取的宽带账号密码。
- LabRelay 日志仅写 `/tmp`，单文件 256 KB、只保留一份轮换；取消周期性成功日志并加入同类错误 5 分钟限频。
- Hub 抑制 fast telemetry、raw/debug 大字段和无意义 revision，缩短 revision 保留并定期截断 WAL。
- Hub 版本提升至 0.9.5，LabRelay 版本提升至 0.2.6。

## 0.9.3 / LabRelay 0.2.4

- 修复 SQLite `revisions` 无界增长：高频缓存文档不再复制整份 JSON 到增量历史。
- 设备 RSSI、流量、在线时长等采样字段不再触发永久 revision；IP、在线状态、名称等有效变化仍会同步。
- `state.json` 忽略时间戳和内嵌设备采样，仅在真实状态变化时产生 revision。
- revision 默认最多保留 5000 条且不超过 7 天，旧客户端自动回退完整同步。
- 保留端口映射历史和路由器仪表盘功能，但高频数据只保存最新状态，不再造成数据库爆炸。

## 0.9.2 / LabRelay 0.2.3

- 新增路由器状态仪表盘数据链路：实时 CPU、内存、温度、WAN 速率与在线设备数。
- LabRelay 分频采集 `ws_sysinfo fast/slow`、`dev_config network`，网络配置按敏感字段白名单脱敏。
- Hub 增加路由器仪表盘内存缓存、HTTP 接口和 MQTT retained 主题，避免高频写入 SQLite。
- 支持 APP 手动刷新请求，由 Relay 在下一次实时上报中领取并完成完整采集。

## 0.9.x（当前开发分支）

- Hub 改为通用 Linux AMD64/ARM64 部署，并统一相对数据目录。
- 数据存储迁移到 SQLite，加入版本迁移、备份和校验机制。
- APP 同步改为首次全量、后续增量和定期校准。
- 取消配对码和 Client Token，恢复 APP_TOKEN 与 HOOK_TOKEN 鉴权。
- 锐捷侧业务采集、推送、重试和诊断统一由 Rust Agent 接管。
- 安装、升级、修复、重新配置和卸载统一使用 `scripts/labprobe-install.sh`。
- APP 与 Rust 更新清单由 `scripts/build_update_bundle.py` 统一生成。

## 0.7.x–0.8.x（历史版本）

早期 DSM/NAS 专用部署说明、逐版本发布记录和 Shell 采集方案已合并归档。为避免继续误用旧入口，仓库不再保留这些分散文件；完整历史仍可从 Git 提交记录查看。
