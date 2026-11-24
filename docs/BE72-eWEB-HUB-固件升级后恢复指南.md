# BE72 eWEB HUB：固件升级后快速恢复指南

更新时间：2026-10-20。当前扩展版本：`20261020-4`。

原路径的完整恢复副本合并至 `20261020-4`，包含 WireGuard、TCP 峰值测试、DDNS、STUN 穿透、IPv6 映射五个页面，**无需再查找或叠加各次增量目录**。当前部署文件、源码、补丁生成器、验证记录和本指南放在同一个恢复目录中；旧增量仅作历史记录，不再是恢复依赖。以 manifest 的现场回读结果为准。

已包含的后续改动：WG 自动切换 Kbps/Mbps、分别保留一位/两位小数；客户端与连接地址之间保留粗线、去掉细分隔线并收紧 8px；编辑弹窗采用全宽表单和 112px 标签区；TCP 整数刻度初始 0～5、五条可删除历史、成功连接地址下拉和回填（含停止或部分协议失败的测试）；IPv6 映射基础管理。

2026-10-20 补充：TCP 在一个输入框内以逗号分隔多个地址，最多八个；408px 自适应输入框，成功的地址组合整组保存为最多五组历史；测试结束曲线定格并保存在浏览器，下一次测试再清空。NAS TCP 模块按目标分别校验，不再把多地址当单个 IPv6 地址处理。STUN 归属记录清理修复已部署，完全匹配的已有放行条件可以复用，但不取得删除权限；TCP 服务器切换及稳定性结论详见排查文档。

## 一、恢复思路

这些页面由“固件菜单入口 + 网页资源 + 路由器 API 桥接 + NAS HUB 服务”组成。更新固件可能覆盖前三部分。NAS 未重建、数据目录未清空时，通常无需重新配置 NAS 上的规则和历史数据。

最快方式是：**先读取新固件版本和网页文件 → 判断是否兼容 → 将 HUB 扩展重新接入新固件 → 检查五个页面。**

不能保证任意新固件都能直接一键恢复。网页主包、模块编号、菜单结构、登录校验或 API 结构变化时，需先适配，再安装。不要把旧固件整个网页主包或整个 API 文件直接覆盖到新固件。

## 二、已经准备好的恢复材料

本地项目：`D:\Github\labprobe-hub`。

当前可用版本的独立副本：

`D:\Github\labprobe-hub\build_artifacts\be72-eweb-recovery-20261019`

| 目录或文件 | 用途 |
| --- | --- |
| `manifest.json` | 全部保存文件的 SHA-256、大小、版本及保存时间；包含部署文件与 NAS 模块的核对结果 |
| `router/` | 从当前 BE72 读取的已部署网页资源、API、桥接模块和 WireGuard 状态助手 |
| `reference/current-app.js` | 当前已部署主包的解压版本，用于比较已接入的 HUB 菜单及其他已有改动 |
| `reference/original/` | 已知兼容的原生主包与原生 API 基线 |
| `source/eweb/` | 五个页面、最新样式、图标、桥接模块及状态助手源码 |
| `source/scripts/` | 受版本校验的补丁生成器和文件传输工具 |
| `source/tcp_session_service.py` | 当前带五条测试历史、持久删除标记和历史删除接口的 TCP 服务实现，仅用于 NAS 代码恢复参考 |
| `source/stun_service.py` | 当前 NAS STUN 服务实现；含归属凭据保留、已有放行条件复用及 TCP 服务器迁移 |
| `router/usr/bin/labrelay`、`router/etc/init.d/labprobe` | 现场 Relay 0.2.78 与启动脚本；相关组件丢失或需升级时恢复，单补网页不重启 Relay |
| `source/labrelay/` | 对应已部署 Relay 的 Rust 源码及版本锁定文件 |
| `source/tests/` | 页面逻辑、补丁及隔离桥接检查 |
| `evidence/` | 脱敏后的接口验证与部署记录，包含 IPv6 停用规则增改删验证 |
| `恢复指南.md` | 与项目 docs 原路径同步的本指南 |

副本不包含密码、Token、DDNS 密钥或业务配置。请另行保存整个恢复目录；`build_artifacts` 是本地构建目录，不能假定 Git 会替你保存它。

合并时核对路由器实际文件和 NAS TCP/STUN 模块，再独立运行副本内的生成器；检查结果记录在 manifest。新固件仍须重新匹配版本。已部署的 Relay 0.2.78 程序、启动脚本与源码也收录于副本；0.2.78 两轮 12 万连接现场对比见 docs/tcp-diagnosis-2026-10-20.md，内网结果不代表公网固定降幅。

## 三、升级前保留什么

### 1. 私有配置

通过私有备份保存以下路由器文件，并保留原权限。不要把内容贴入本文、公开仓库或普通日志：

- `/etc/labprobe/agent.json`：Agent 连接和身份配置。
- `/etc/labprobe/eweb-hub.json`：eWEB 对应 HUB 和路由器绑定。
- `/etc/labprobe/eweb-hub.curl`：eWEB 请求 HUB 的凭据，权限必须为 `0600`。

升级时是否保留这些自定义文件，取决于固件升级机制。不要只凭“保留配置”选项就认定全部保留。恢复前检查文件存在、权限及绑定是否正确。

### 2. NAS

保留现有 `labprobe-gateway` 容器使用的配置、各路由器数据目录、镜像及启动配置。确认实际挂载和各工作进程的 `DATA_DIR`；不要只备份容器内部临时文件。

本次 NAS 更新已有备份：

- TCP：`/volume1/docker/labprobe-gateway/eweb-history-backups/20261020-103547/`
- STUN：`/volume1/docker/labprobe-gateway/stun-repair-backups/20261020-121323/`
- STUN 更新后镜像：`labprobe-hub:stun-repair-20261020-121323`

该恢复副本覆盖 eWEB 扩展及 TCP/STUN 模块，不是整套 NAS HUB 和业务数据的备份。STUN、IPv6 映射等依赖现有 HUB 服务、Relay 及防火墙能力；NAS 整体丢失时需先恢复原服务和数据目录。BE72 文档配置实际存储在 SQLite `labprobe.db` 的 documents 表内，不能仅检查同名 JSON 文件判断配置或任务是否存在。更新工作进程前必须确认没有活动 TCP 测试。

仅恢复路由器网页时，无需重装或重启 NAS HUB。

## 四、升级后的恢复流程

### 第一步：读取新固件，不先覆盖文件

1. 确认目标仍是 BE72；升级后 SSH、管理地址和端口可能变化。
2. 记录固件版本，读取网页入口 HTML，确定它实际引用的主包及依赖块文件名。
3. 下载新固件原生主包（可能是 `.gz`）和 `/usr/lib/lua/luci/controller/eweb/api.lua`，计算哈希，作为本次恢复的原始备份。
4. 检查 Vue、Element UI、ECharts 的加载方式、菜单结构、登录会话和原生弹窗样式。
5. 检查 Agent、`labwg0`、状态助手及三个私有配置文件是否保留。缺失组件分别补回，不能把“页面出现”当成服务已恢复。

### 第二步：分两种情况生成补丁

**A. 与已知原生基线完全相同**

原生主包名为 `app6894ab6e311358c0df7b.js`，解压后 SHA-256 为：

`a4623980f36bf95e300389a90b404d06ab87cbffe6c6251cb03ee566ba475a5a`

同时确认原生 API 与保存的基线逐字节相同。满足条件后，可以使用受版本校验的生成器生成候选文件。在 PowerShell 中执行：

```powershell
Set-Location D:\Github\labprobe-hub
python build_artifacts/be72-eweb-recovery-20261019/source/scripts/patch_be72_eweb_hub.py `
  build_artifacts/be72-eweb-recovery-20261019/reference/original `
  build_artifacts/be72-eweb-recovery-20261019/candidate `
  --wg-status build_artifacts/be72-eweb-recovery-20261019/router/usr/libexec/labprobe-wg-status
```

这条命令只生成候选文件，不连接或修改路由器。若还需保留原网页中的其他定制补丁，应从新固件当前文件增量接入，避免生成的整包覆盖其他改动。

**B. 文件名、哈希或结构变化**

以新固件原文件为基础更新生成器；不要删除版本校验后强行套用。只移植以下扩展：

- HUB 菜单及五个子入口。
- HUB 页面资源加载器、图标和标题对齐初始化。
- 原生 API 中的 `labprobe` 路由与 RPC 包装器。
- 独立的 `labprobe.lua` 桥接模块、页面 JS/CSS。

现有加载器含打包器模块编号和依赖块编号，这些编号在新固件可能不同，必须重新确认。WireGuard 状态助手也需确认 CPU 架构、执行权限和内核接口兼容性。

### 第三步：保持正确绑定和鉴权

当前已确认配置关系：

| 项目 | 当前值 |
| --- | --- |
| 路由器身份 | `BE72` |
| 网关路由器 ID | `be72` |
| 路由器访问 NAS HUB | `http://192.168.5.46:58443` |
| HUB 请求路径 | `/r/be72/api/...` |
| 浏览器原生 RPC | `/cgi-bin/luci/api/labprobe` |

恢复时重新核对实际环境，保留登录、同源、请求头、固定操作白名单及路由器身份检查。使用无路由器标识的 `/api/...` 根路径会再次触发 `multi_router_path_required`。BE72 页面不能误接入 BE50 或其他 HUB 的设备绑定。

### 第四步：备份、检查、安装

1. 在新固件上新建本次安装备份目录，保存每个即将修改文件的原件、权限、哈希和“原本不存在”的状态。
2. 生成与这次新固件备份配套的回滚脚本。
3. 本地检查主包及页面 JS 语法；路由器用 `loadfile` 检查候选 Lua 语法。
4. 在独立 Lua 进程运行 `tests/eweb_hub_read_fallback.lua`，检查显式 BE72 路由、缓存、鉴权失败及错误恢复。
5. 临时上传并校验哈希后，替换适配好的目标文件。压缩版与非压缩版存在时均应匹配，资源版本号应更新。
6. 清理本次修改对应的 LuCI 索引和模块编译缓存，不清业务配置。新固件模块路径变化时重新确定缓存名。
7. 浏览器强制刷新，避免旧主包或旧页面脚本缓存。

已知旧固件文件清单：

```text
/www/luci-static/eweb-ehr-exp/static/js/app6894ab6e311358c0df7b.js.gz
/www/luci-static/eweb-ehr-exp/static/labprobe/hub-pages.js
/www/luci-static/eweb-ehr-exp/static/labprobe/hub-pages.js.gz
/www/luci-static/eweb-ehr-exp/static/labprobe/hub-pages.css
/www/luci-static/eweb-ehr-exp/static/labprobe/hub-pages.css.gz
/usr/lib/lua/luci/controller/eweb/api.lua
/usr/lib/lua/luci/modules/labprobe.lua
/usr/libexec/labprobe-wg-status
```

**旧 `scripts/deploy_be72_eweb_hub.py` 不是跨固件恢复入口。** 它仍包含首次接入时的旧容器名 `labprobe-hub`、旧 DDNS 模块校验及 NAS 重启步骤；当前使用 `labprobe-gateway`。不要直接执行它来补页面，也不要用 `.tmp` 中的一次性发布脚本充当通用恢复脚本。

## 五、恢复验收

| 检查项 | 通过条件 |
| --- | --- |
| 原生页面 | 存储管理、网络、系统等既有页面和登录正常 |
| HUB 菜单 | 白色标题、对齐正确；WireGuard、TCP 峰值测试、DDNS、STUN 穿透、IPv6 映射五项都可进入 |
| 弹窗 | 沿用新固件原生组件；标签、边距、行距及按钮区一致 |
| WireGuard | 配置、实际握手与流量正常读取，版本冲突保护仍有效 |
| DDNS | 记录及服务商正常读取；密钥不会进入普通列表或日志 |
| TCP | 读取任务和最多五条结果历史；成功地址去重且可删除；运行时仍可停止 |
| STUN | 读取原有规则、公网地址和地址历史；状态不被误报 |
| IPv6 映射 | 读取现有映射；6to4/6to6、TCP/UDP 与实际状态正确；编辑不清除既有高级参数 |
| 绑定 | 每个 HUB 请求均明确选择 `be72`，不会跨路由器操作 |
| 失败处理 | 断网、登录过期、业务拒绝能提示，保留编辑内容，按钮不会永久锁住 |

读取通过后，再用专门临时对象检查写入并清理。WireGuard 删除应检查实际内核公钥是否移除；STUN 可先用停用规则检查增改删，避免为了验收修改现有穿透或新增公网暴露。不要为了补网页默认启动 TCP 压测。

## 六、回滚边界

新固件补丁失败时，只执行**本次新固件安装前备份**生成的回滚脚本。

2026-10-19 的旧备份 `/etc/labprobe/backups/eweb-enhancements-20261019-222212/rollback.sh` 只适用于当时固件和部署状态。升级后不能靠它回滚新固件，否则可能混入旧主包。

页面恢复一般不要求重启路由器或 NAS。只有确认服务组件确实缺失或异常时，才单独修复相应服务。

## 七、下次直接交给维护者的话

> 按 `docs/BE72-eWEB-HUB-固件升级后恢复指南.md` 恢复 BE72 原生 eWEB 的 HUB 五个页面。完整副本已经在原路径 `build_artifacts/be72-eweb-recovery-20261019` 合并至版本 20261020-4，无需叠加历史增量。先校验 manifest，再读取新固件及主包/API 版本，使用副本中的源码和参考基线进行适配，保留其他固件功能和已有定制。保留显式 `/r/be72` 绑定和原生鉴权，页面及弹窗遵循新固件原生样式。先备份并生成本次固件的回滚脚本，再安装和验证；仅补路由器页面时不要重新部署 NAS。报告实际通过项及未验证项。

## 本轮 Relay 与 STUN 补充

- Relay 0.2.77 已经用户同意切换，启用规则恢复、WG 配置与原 UDP 映射保留。500 条到 NAS 临时监听器的受控功能测试全部成功，临时系统设置全部恢复；这不是性能降幅对比。
- Hub 当前 TCP STUN 首选为 turn.cloud-rtc.com:80；国内入口对照结果见 docs/stun-domestic-comparison-2026-10-20.md。单独使用 Relay 且没有显式服务器时，裸程序默认是已验证的 Cloudflare TURN 入口；Hub 下发的明确规则优先。
- 更换 Relay 前检查没有活动 TCP 测试、备份旧程序并准备回滚。切换会重建 STUN 连接，不能把地址永久不变作为承诺。
- 完整恢复副本不含代理账号、Hook/App Token、WG 私钥或路由器业务规则；这些仍需私有备份。

- 0.2.78 修复 CPU 反馈与延迟补发突发，已部署并完成两轮 12 万连接零失败验证；当前程序、源码和记录已收录。
