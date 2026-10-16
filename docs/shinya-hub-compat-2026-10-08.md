# 星耀家 Hub 协议适配记录

## 部署范围

2026-10-08 部署到 NAS 的 BE72 `labprobe-hub` 容器。仅新增
`/app/shinya_compat.py`，并在实时启动入口注册适配模块。
重载 Hub 容器后完成验证，路由器与 Relay 未重启。
BE50 容器未修改。

备份：`/volume1/docker/labprobe-hub/shinya-backups/20261008-171522`。
包含原启动文件、候选文件、适配模块及 `rollback.sh`。
原镜像标签：`labprobe-hub:pre-shinya-20261008-171522`。
新镜像标签：`labprobe-hub:shinya-compat-20261008-171522`。
已同步原容器使用的镜像标签，便于同配置重建容器。

## 已接入接口

| 功能 | 原协议路径 |
| --- | --- |
| Hub 登录 | `/api/v1/base/homeUser/accountPasswordLogin` |
| 用户信息、刷新令牌、退出 | `/api/v1/base/homeUser/{info,refreshToken,logout}` |
| 项目列表 | `/homewlan/apMonitor/getProjectList2` |
| 路由器信息 | `/homewlan/homeAp/getDeviceInfoList2` |
| 终端列表 | `/homewlan/homeAp/getStaList2`、`/homewlan/homeDetail/getStaList2` |
| 设备概况 | `/homewlan/experienceVisual/getApOverview` |

数据来自当前 worker 的 RouterService。项目标识为 `hub:<设备 SN>`。
按项目 ID、请求头和 SN 校验所属路由器；不会跨 worker 选择其他设备。
终端保留 MAC 和离线状态，不按名称合并。
未接入的配置操作返回协议错误码 501，不报告保存成功。

## 验证

- 本地 5 项适配测试通过。
- 部署后真实登录成功；错误 Token 被拒绝。
- 识别路由器 BE72，SN `G1TD8RX039025`。
- 适配终端列表与原生接口数量一致，验证时为 10 台。
- 其他项目请求被拒绝；未接入的无线写接口被拒绝。
- 容器启动后的初次温度采样为 0.0，遥测恢复后的复查中原生与适配接口均为 **53.52 °C**。
- 自动核对记录位于 `build_artifacts/shinya-hub-20261008/deployment.json`。

此记录确认服务端协议与数据读取，独立 APK 的实际手机画面和交互仍需实机验证。
无线配置、Mesh、其他固件功能及 Hub 的 WireGuard/TCP/DDNS 原生入口尚未完成 APP 接入。

