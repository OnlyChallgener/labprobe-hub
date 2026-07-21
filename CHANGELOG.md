# LabProbe 变更记录

## 0.9.6 / LabRelay 0.2.7

- LabRelay 从 `ws_sysinfo fast` 归一化磁盘/存储利用率并随路由器实时状态上报。
- 配合 APP v0.10.9 build139 发布，统一提升 Hub 与 LabRelay 版本号。
- 本次 Hub 与 LabRelay 不改变采集、存储、清理、更新或推送逻辑。

## 0.9.5 / LabRelay 0.2.6

- 新增 Agent 一键清理指令链路：APP 经 Hub 下发，LabRelay 清理 `/etc/labprobe/backups`、非必要 `/tmp` 日志和失效安装临时文件。
- 清理结果回传已删除分类、项目数量、异常项和回收空间；配置、当前程序和状态数据不会被删除。
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

- Hub 0.9.5 hotfix: credentials refresh nonce now starts from epoch milliseconds, preventing a Hub restart from reusing a nonce already acknowledged by LabRelay.
- LabRelay 0.2.6 exposes `network.wan[].service` as `details.lan.broadbandRemark`; credentials remain memory-only.
