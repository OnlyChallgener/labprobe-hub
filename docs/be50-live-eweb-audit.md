# BE50 官方固件 eWeb 实机核查

2026-09-30，仅执行登录和只读请求。设备通过节点小宝地址访问，未记录临时公网入口、会话或密码。

## 页面与认证

- 登录页只有密码输入框，但提交给 `/cgi-bin/luci/api/auth` 的字段与 BE72 不同：BE50 使用 `username=admin`、`pwd`、`time`、`encry=true`。`pwd` 使用当前登录页的动态密钥加密。BE72 Hub 原有的 `password` 字段不能复用。
- 登录后首页为 `/cgi-bin/luci/;stok=<sid>/ehr/home_overview`。它是动态加载的前端页面，静态脚本中出现某个功能名称不能单独证明该设备支持该功能。页面菜单由 `/cgi-bin/luci/api/common` 的 `getAuthority` 响应中的 `capacity`、工作模式及语言计算。
- 实机 `getAuthority` 返回型号 BE50、产品类型 `ehr`、`ROUTER` 工作模式。eWeb 前端能力表包含 IPv6、端口映射、`phddns`、`phtunnel`、`noip`、`firewall_wan` 标记；它们不等同于 LabProbe 现有 BE72 页面所需的接口。

## 已验证的只读路径

| 用途 | eWeb 请求 | 实机结果 |
| --- | --- | --- |
| 身份与菜单能力 | `common.getAuthority` | 成功，含型号、工作模式、`capacity` |
| 运行时间和内存 | `overview.getDeviceInfo` | 成功，含 `uptime`、`mem_total`、`mem_used` 等 |
| 在线设备 | `devSta.get user_list` | 成功，含设备列表与总数 |
| 路由概况 | `acConfig.get network_group`、`devSta.get ap_list`、`devConfig.get network`、`devSta.get ipinfo` 等 | Hub Core 的完整 dashboard 只读请求成功，WAN、无线、端口等字段有数据 |
| 原生 IPv4 映射 | `devConfig.get port_mapping` | 成功，含 `portMapping` |
| DDNS | `devConfig.get phddns`、`devConfig.get phtunnel` | 成功；BE50 的数据结构与 BE72 的 `ddnsCfg` 页面不同 |
| WAN 防护开关 | `devConfig.get firewall_wan` | 成功；LabProbe 规则防火墙使用的 `ip_firewall` 在 BE50 返回模块不存在 |

BE50 官方 Web 页确有 DDNS 相关能力，但当前 LabProbe 的 BE72 原生 DDNS 列表和编辑接口不能直接套用。APP 先只显示已实现的 LabProbe DDNS 与证书监控，BE50 原生 DDNS 需要独立适配。`firewall_wan` 是 WAN 开关，不是 BE72 的防火墙规则页。

## 状态链路

BE50 不依赖 BE72 eWeb WSS 作为实时源。当前设计为 BE50 本地 Relay 采样，再推送到专属 NAS Hub，再由 Hub 提供 `/api/router/realtime` 给 APP。Hub 的 eWeb 登录可用于只读配置和概况，但不能代替 Relay 实时样本。

实测本机可分别打开 BE50 eWeb 与 NAS Hub；BE50 到 NAS Hub 的 HTTP 请求超时且无响应字节，NAS 到 BE50 eWeb 也返回空响应。Hub 内最后的 BE50 Relay 样本已过期，故 APP 不应显示“实时同步正常”或据此判定 Router 故障。两端节点小宝转发恢复前，无法完成手机端实时状态验收。

## 2026-10-01 链路与防火墙复核

- 本机直连 NAS Hub 和 BE50 eWeb 均返回 HTTP 200；禁用代理后，从 NAS 请求 BE50 eWeb、从 BE50 请求 NAS Hub 均在 7 秒后超时，收到 0 字节。
- NAS Hub 监听 `0.0.0.0:58444`，Docker 使用 host 网络，本机访问 Hub 健康检查返回 200。运行容器仍使用旧代码，本地认证和能力适配尚待部署。
- NAS 的 nft 和 legacy 过滤表已检查，两端 INPUT/OUTPUT 均为 ACCEPT。探测前后 DROP/REJECT 规则计数没有增加，BE50 发往 NAS 的专用放行规则增加了计数。当前未发现防火墙拦截这两条请求的证据。
- NAS 的节点 TUN 地址为 `100.66.1.4/32`；BE50 本机 TUN 地址为 `10.222.222.1/32`，到 NAS 的路由走节点接口和 table 50，节点地址 `100.66.1.1` 由节点软件映射。
- NAS 节点进程连接本机 Hub 后出现 CLOSE-WAIT 和未读响应。Relay 样本会间歇更新，但复核时仍已过期；这些证据支持继续检查两端节点转发会话，尚不足以确认软件内部根因。
- BE72 通过局域网连接独立 Hub `192.168.5.46:58443`，上报和管理会话正常，实测实时样本年龄 59 毫秒。

以上检查没有修改防火墙或重启节点服务。

## BE50 实时监控修复

`RouterWebSocketMonitor` 现在读取 `routerEwebWss` 能力标记。BE50 / BE5100 不再启动 eWeb WebSocket 监控线程，也不会为不存在的 `/ws` 反复登录；BE72 继续使用原生实时接口。相关 12 项测试通过。

## 2026-10-01 BE50 专属 Hub 部署

- 镜像为 `labprobe-hub:be50-isolated-20261001-023043`，Hub 版本 0.13.32。所有运行模块已统一打包，编译、导入检查和入口依赖预检通过。
- 部署前在禁用网络的容器内，只读校验实际配置；名称为 BE50，入口和 Router Service 的管理地址均为 `http://100.66.1.1`，服务端口 58444。完整环境变量保留，并锁定 BE50 地址。
- 停止原容器后，备份 config/data/backups/logs/update-repository 五个实际持久目录（约 145.6 MB 源数据）；原容器和镜像保留，部署脚本具有失败自动回滚。
- 新服务健康检查、路由器身份、管理地址及八项不支持能力关闭的验收通过。部署未重启节点小宝服务，也未修改防火墙。实时样本与节点双向链路继续复查。

## 节点恢复与最终验收

- 精确清理已关闭的 58444 代理会话未能恢复两端请求。确认经 BE72→NAS 局域网的独立 SSH 登录和管理权限后，于 03:01:38–03:01:49 仅重启 NAS 的 `owjdxb-app-1` 一次；容器、镜像和持久挂载保持一致，未修改配置、防火墙或清理日志，未重启 BE50/BE72。
- 恢复后 PC→NAS Hub、NAS→BE50 eWeb、BE50→NAS Hub 各连续三次 HTTP 200，58444 CLOSE-WAIT 列表为空。BE50 有效 eWeb 密码与用户提供值一致，用户名为 admin；没有更改密码。
- 实机 Relay 更新周期约 8–9 秒。原 Core 3 秒阈值会错误地把正常 BE50 数据判为过期，现仅对 BE50 固件的 `agent_dashboard_push` 来源使用 10 秒窗口，其余来源和 BE72 保持 3 秒。9 秒正常、10 秒边界、10001 毫秒过期、旧时间戳和 RouterService 状态的相关 22 项测试通过。
- 最终镜像 `labprobe-hub:be50-freshness-20261001-031508` 仅覆盖上述新鲜度模块，已部署并保留前一容器、镜像及五目录一致备份。生产三次真实样本持续推进时间戳，年龄 8671/678/2685 毫秒均 `stale=false`；最慢样本仍 `ready/connected/dataAvailable=true` 且无错误码。
- CPU、内存、运行时间、上传/下载速率、IPv4 连接数均有真实变化数据，在线设备为 7。IPv6 状态正常读取 200 并返回地址、前缀、网关及 DNS；IPv6 连接数能力关闭，BE50 WSS 重试日志为 0。
- BE72 对照为 HTTP 200、`ready/connected/sessionConnected/dataAvailable=true`，来源 `router_eweb_ws_fast`，样本年龄 370 毫秒。临时维护隧道已关闭。

## 2026-10-01 Relay 0.2.72 快采样上线

- BE50 已部署 ARMv7 静态 Relay 0.2.72。独立快采样线程每 2 秒采集和发布真实 CPU、内存、运行时间、WAN 速率及 IPv4 会话；慢速配置读取不能阻塞或覆盖快采样。
- 实机 vendor fast 命令成功但无输出，现回落本机 procfs；空数据不再变成假零值。BE50 不上报不支持的 IPv6 会话数。
- 仅替换二进制并由 procd 重启 agent，新 PID 19047；转发进程 PID 14072、配置、节点服务与 BE72 保留。
- 通过本机节点地址 `100.66.1.4:58444` 持续 90 秒验收：91 次 GET、46 个真实样本，最大间隔 2 秒、最大样本年龄 1815 毫秒，过期和请求错误均为 0。
- 切换前建立的同一条实时连接全程未断；46 个新样本、最大年龄 83 毫秒，没有错误或服务端断开。CPU、内存、运行时间和上下行速率持续变化。
- 最终 BE50 状态 `ready/connected/sessionConnected/dataAvailable=true`，无错误码；BE72 原有 WSS 正常。NAS 候选测试容器均已退出，活跃编译进程为 0。
- 回滚备份：`/etc/labprobe/backups/relay-fast-0.2.72/20261001-044150-18699`。过滤后的完整记录位于 `build_artifacts/be50-relay-0272-candidate/deployment-acceptance.json`。
- APP 交付为 0.13.79（322），已修复路由器选择隔离、首卡遥测字段、实时与备用链路恢复及普通刷新。165 项 APP 相关测试、12 项 Relay 针对性测试通过；手机安装后的画面仍待用户实际复测。

## 2026-10-01 08:17 双 Hub 复核与 APP 时钟修正

- 用户报告 APP 先备用更新、随后等待路由器数据。新一轮外部节点只读检查持续 35 秒：两 Hub 各 36 次 GET 全部成功，BE50/BE72 分别收到 20/38 个 WS 路由样本，没有过期、断连或请求错误；未修改或重启任何设备服务。
- NAS 墙钟比 Windows 快约 202–224 毫秒。将真实样本代入 APP 0.13.79 的跨设备时间差门槛，会拒收 BE50 的 18/20 个 WS 样本、BE72 的 37/38 个样本，尽管 Hub 上报新鲜。HTTP 的稍旧样本较容易通过，形成备用读取与实时等待交替。
- APP 0.13.80（323）改用 Hub 样本年龄和本机单调经过时间，epoch 仅排序；重复旧样本不续期，并补会话切换的排队回包保护。修正规则能接受这轮全部正常帧，178 项相关 APP 测试通过。
- 实测过滤记录：`build_artifacts/current-dual-hub-ws-readonly.json`。APP 详细修复记录：`D:/Github/LabProbeApp/docs/BE50-BE72-clock-fix-0.13.80.md`。手机安装后画面仍待实际复测。
