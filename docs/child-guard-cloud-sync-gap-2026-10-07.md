# 儿童守护：官方同步机制与 0.13.83 名单分歧

核查日期：2026-10-07。本轮为只读分析：未新增 APK，未部署补丁，未增删守护成员。

## 一、已经确认的结论

官方 APP 的名单操作经过官方账号服务，路由器有独立的本地执行名单。固件接到云端同步命令后，下载完整名单并重建本地成员。LabProbe 0.13.83 完成了路由器本地增删与回读，尚未完成官方账号业务名单的写入。

证据来自项目保存的官方 APK、两台路由器当前文件、BE72 原生日志、官方当前下发配置的只读 GET，以及用户的官方 APP 验证。官方服务端源码不可见，消息 ACK 不能证明业务名单已修改。

### 当前分歧的直接证据

10 月 7 日约 16:30，经 BE72 只读请求日志中的原生 getSyncSetCfg 地址，未执行下载后的应用脚本：

| 数据源 | 成员数 | iPad | iQOO15 |
| --- | ---: | --- | --- |
| 官方当前下发的完整配置 | 6 | 无 | 有 |
| BE72 当前本地 UCI 名单 | 7 | 有 | 有 |

云端 6 个 UID 均在本地名单中，本地多出 iPad。GET 前后 UCI 内容逐字节一致。因此本地添加成功，官方下发配置尚未纳入 iPad。

此前 14:02 本地解除 iQOO15；14:11 固件下载的云端名单仍包含 iQOO15，随后重建本地成员。重新出现有固件和日志依据，不能只归因于 APP 缓存。

## 二、官方 APP 到云端：按操作发送请求

分析的是项目保存的 cn.com.ruijie.shinya2.apk。已有解码 manifest 标记版本 1.2.4；提取的 Hermes bundle 与 APK 内文件校验一致。不宣称样本就是用户手机当前官方 APP 的版本。

函数 #8573 提供生产地址 https://shinyaapp.ruijie.com.cn、tag=homewlan、tag2=api/v1。注册表证明 API 模块 #20132 使用请求模块 #20572。以下是已核对调用方和封装的完整路径：

| 操作 | 方法与路径 | 业务字段 | Hermes 函数证据 |
| --- | --- | --- | --- |
| 添加 | POST /homewlan/childProtection/addSta | staList: [{name, staMac, type, manufacturer}] | #33344、#33487、#20241；批量入口 #25326/#25331 |
| 新守护页面删除 | POST /api/v1/netguard/staGuard/deleteSta | mainApSn、staId | #36126、#20529 |
| 旧入口删除 | POST /homewlan/childProtection/deleteSta | staMac | #25703、#20245 |
| 名单查询 | GET /api/v1/netguard/staGuard/getProtectStaListPage | mainApSn、meshApSnList、mainApCreateTime、pageIndex、pageSize；单设备查询另带 staId/staMac | #24051、#36113、#20477 |
| 按小时上网时长 | GET /api/v1/netguard/onlineReport/getStaOnlineTimeDistPerHour | 对应设备与时间范围 | #20497 |
| 应用报告 | GET /api/v1/netguard/onlineReport/getStaAppReport | 对应设备与时间范围 | #20505 |
| 流量/时长列表 | GET /api/v1/netguard/onlineReport/getStaTimeFlowList | 对应设备与时间范围 | #20541 |

新版页面的新增仍调用 childProtection/addSta，删除与名单读取调用 netguard/staGuard；不能只根据 URL 前缀将新增接口判为废弃功能。

请求模块 #20576 从官方 APP 的 user.token 取得账号会话，设置 Authorization: Bearer …；从当前网络项目取得 projectId，放入请求头，POST 数据未指定时补入请求体；还带 type=shinyaApp。封装参数 data 最终序列化为 HTTP body，并非再额外包一层业务 data。

#20582 检查业务 code，仅 code=0 正常返回，其余抛错。新增 #33487、删除 #36126 在请求成功后立即发出 refreshProtectStaList 事件，由 #36045 触发刷新。这些增删处理函数没有等待五分钟的逻辑。

账号会话不同于 Hub APP_TOKEN、SSH 密码、eWeb 密码。本轮没有调用官方账号级增删接口，未取得它们的真实业务响应。

## 三、云端到路由器：命令触发，全量重建

shinya_mqlink_cmd.log 在 14:11:18、14:11:32、14:23:38、14:23:49 记录 dev_sta set -m child_sync，参数含目标 dev_sn 与官方下载 URL。

1. /usr/local/lua/dev_sta/child_sync.lua 调用 child_uci.main_proc("sync", obj)。
2. child_guard_uci.lua 的 child_sync（第 922 行）校验 dev_sn 与本机一致，再启动 child_guard_sync.sh。
3. 脚本下载 /api/v1/netguard/staGuard/getSyncSetCfg/{routerSn} 的完整 list，存入临时缓存。
4. 执行 dev_config set -m child_guard '{"sync":1}'。
5. child_set（第 794 行）读取完整 list，调用 user_set。
6. user_set（第 437 行）先 erase_all_user()，再逐个 user_add()。
7. 提交配置、发送 reload 事件，由固件更新运行时。

这里没有根据 LabProbe 最近的手动操作合并，也没有本地删除标记保护。云端仍有的成员可被恢复；仅本地新增的成员也可能在未来全量同步时被移除。本轮 iPad 仍在本地，不能写成它已经被云端删除。

已证实的是收到命令后同步，未证实名单固定每五分钟或十五分钟下发。Relay 源码“router pulls every 15 minutes”的注释没有本次证据支持，不应据此设计同步策略；本轮未改该文件。

## 四、路由器到云端：配置通知与名单确认不同

child_guard_reload.lua 的 uci_to_json（第 187 行）生成完整本地名单，携带 version/configTime/currentTime/configId。upload_to_cloud（第 333 行）调用 shinya_mqlink.config_notify，使用 bizid=child_guard_0、name=child_guard、mid=29、cid=configId、val=完整名单。

另有通用 cfg_child_guard_0 配置变化通知。iPad 新增时，这个通知的 data 是单次新增内容。官方随后也请求过 dev_config get --module child_guard；当时对应配置文件保存的是该次操作与元数据，不能等同于完整业务名单。

在本轮分析之前，15:56:47 曾做限定探测：经已有 mqlink.config_notify 发送当时完整七台名单；UCI 未变化，本地返回 code 0，约 0.3 秒后收到对应消息 ID/bizid 的 ACK。用户随后确认官方仍无 iPad，本轮 GET 官方下发配置也仍是六台。

因此 dev_config 成功、ubus 返回成功、MQTT ACK 都不能作为“官方守护名单已同步”的完成条件。通知究竟仅回报状态，还是在特定版本、来源或通道条件下可反向更新业务名单，尚缺服务端规则或成功实例。不能断言设备端永远无法反向写入，也不能继续盲目换通道当作修复。

## 五、五分钟对应统计上报

BE72 与 BE50 实机配置都是 child_report_upload.period=60、bus_upload.period=300。两台 child_report_upload.lua 完全相同：

- 每次读取 /proc/net/sniffer_flow，附时间戳并增加 dump_cnt。
- dump_cnt >= 5、文件达到 6 MB，或收到显式 upload 参数时，将记录移入后台上传目录。
- 后台上传调度周期为 300 秒。

这支持“统计按约五分钟批次上报”，并不保证官方页面严格每五分钟出现新值，还受上传、服务端处理及页面刷新影响。统计上报与名单增删是不同流程，不能用等待五分钟解释本次名单不同步。

## 六、BE50 与 BE72 对比

两台当前 child_guard_uci.lua、dev_sta/child_sync.lua、child_guard_sync.sh、child_report_upload.lua 逐字节相同。child_guard_reload.lua 文件存在差异，但名单生成与 shinya_mqlink.config_notify 上报代码相同。两台采集/上传周期都是 60/300 秒。

因此名单全量覆盖具有相同代码条件，不代表其它固件能力相同。云端六台、本地七台的本次业务实测仅针对 BE72。

## 七、当前实现缺失与下一步约束

labrelay/src/child_guard.rs 的 mutate_membership：新增时本地生成随机 UID，执行 dev_config add 并回读；删除按 UID/MAC 定位本地成员，执行 dev_config del 并回读。没有调用官方 addSta/deleteSta 账号业务接口。因此 0.13.83 不能保证官方列表变化，也不能阻止固件随后应用完整旧云端名单。

此前把原生配置上报当作能够完成官方名单同步，验证标准不充分。后续应满足：

1. 优先验证官方授权后的真正增删和名单回读，或先证明一个确实能更新业务名单的设备端通道。仅修改本地文件、补发通知不作为完成条件。
2. 分别记录用户操作已受理、路由器已执行、官方名单已确认；操作持久化，具有顺序和明确的目标路由器。立即反馈不等于后台步骤全完成。
3. 处理云端全量下发与待完成操作冲突；单靠 APP 隐藏已删成员，无法避免其在路由器上真实恢复守护。
4. 维护所属路由器、实际 MAC、官方 staId、本地 UID 的映射。官方新增请求不自行指定 UID；本地生成 UID 不能自动视为官方已注册。不同 MAC 的同名 Mate60 不按名称合并。
5. 名单操作保持高优先级，本 APP 快速统计继续走本地采集；分别验收两条链路。
6. 验收核对官方名单/下发配置、路由器配置与运行时、两个 APP，并经历后续一次云端全量同步，确认旧成员不恢复、新成员不丢失。

以上为后续条件，本轮未实施账号接入或生产改动。未知项包括：官方服务端处理设备上报的内部规则、用户当前官方 APP 是否与样本完全相同、账号接口写入后的实际下发时延。已确认的当前云端/本地分歧不依赖这些未知项。

## 八、本地取证索引

- 官方 APK 与提取结果：D:/Github/LabProbeApp/test/_analysis/；选定函数在 oct07-cloud-functions/，文件名为函数编号。
- bundle SHA-256：fe8407a4f3f799c1867322ed546d6e8640f27b118d86eb5c99511a17446a930d。
- 两台当前快照：D:/Github/labprobe-hub/build_artifacts/oct07-official-mechanism/；BE50 在 be50 子目录。
- 本次只读云端响应：be72-cloud-getSyncSetCfg-readonly.json；摘要 sanitized-findings.json。
- 早期命令日志：build_artifacts/oct07-cloud-protocol/shinya_mqlink_cmd.log。
- iPad 新增与此前通知探测：build_artifacts/oct07-ipad-audit/。

原始快照包含设备标识和内部 URL，留在本地忽略目录；本文保留脱敏机制与结论。
