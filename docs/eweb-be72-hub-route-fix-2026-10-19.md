# BE72 eWEB HUB 页面转接修复

范围：BE72 eWEB 的 DDNS、WireGuard、TCP 峰值测试。网页入口为用户提供的 5906 端口。

三个页面复用路由器上的 `luci.modules.labprobe` 桥接，再请求 NAS 的 LabProbe HUB。故障时三个读取操作都返回 `multi_router_path_required`，业务 HTTP 状态为 400。

原因：桥接仍请求 HUB 根路径 `/api/...`，而多路由器网关要求带所有者凭据的请求明确选择路由器。实际注册表确认 `be72` 对应 BE72，`be50` 对应 BE50。

修复：桥接请求使用 `/r/be72/api/...`；保留原有路由器名称、HUB 地址、登录、来源和操作白名单检查。已有安装未配置 routerId 时采用该 BE72 专用扩展的明确路由；如果配置了其他 routerId，则在发出请求前拒绝。原 Agent 地址和凭据保持原样。

仅部署了路由器的 Lua 桥接文件并清理该模块的编译缓存，没有重启路由器或服务。原文件及回滚脚本保存在：

`/etc/labprobe/backups/eweb-route-20261019-214007/`

验证：

- 通过外网 eWEB 登录后，wg.get、tcp.get、ddns.get 均返回业务成功和 HTTP 200。
- WireGuard 后端身份为 BE72，部署前后服务端配置哈希相同；DDNS 记录 ID 保持相同。
- 实际浏览器页面显示 WireGuard 连接、流量和客户端，以及 DDNS 记录。TCP 页浏览器检查受工具超时影响，已确认 API 读取成功。
- 未登录、缺少专用请求头、跨来源请求、缺少 WireGuard 配置版本、无效 TCP 目标均被拒绝。
- 4 项 Python 检查通过；在路由器 Lua 运行时执行的 9 项隔离路由、缓存与恢复检查通过，网络和文件均使用模拟对象。
- 未切换 WireGuard、修改 DNS、删除记录或启动真实 TCP 压测。

首次部署脚本的预检查也已改为明确的 BE72 路径，避免后续部署再次使用旧根地址。
