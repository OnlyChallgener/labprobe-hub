# LabProbe Hub IPv6 采集升级说明

本包只更新 Hub 数据层和路由器采集脚本，APP 界面保持兼容。

## 更新内容

- 路由器脚本 `scripts/ruijie_push_to_labprobe.sh`
  - 保留原来的锐捷 `dev_sta / user_list` 终端同步。
  - 自动识别 IPv6 模式：`server`、`relay`、`bridge`、`disabled`。
  - 分别上报：
    - 路由器自身 IPv6
    - WAN IPv6
    - LAN IPv6
    - LAN IPv6 前缀
    - IPv6 默认路由接口
    - `ip -6 neigh` 邻居表：MAC、IPv6、接口、ND 状态、采集时间
    - DHCPv6 Server 模式下的 DHCPv6 租约
- Hub `hub.py`
  - 兼容新旧路由器脚本推送格式。
  - 一台设备可保存多个 IPv6 记录。
  - 每个 IPv6 记录保存 `firstSeen`、`lastSeen`、`lastReachable`、来源、ND 状态、是否属于当前前缀。
  - 自动选择主 IPv6，并继续输出旧 APP 兼容的单个 `ipv6` 字段。
  - `STALE`、`FAILED` 只作为 IPv6 地址状态，不参与设备在线判断。
  - Hub/NAS 自身 IPv6 以 Hub 本机探查为准，路由器邻居表仅做交叉验证。
  - 今日流量页可使用 `todayOnlineDurationSec` / `todayOnlineDurationText`，按当天 00:00 截断计算。

## Hub 更新方法

1. 备份旧 Hub 目录里的 `config.yaml` 和 `/app/data`。
2. 用本包覆盖 Hub 程序文件，重点是：
   - `hub.py`
   - `scripts/ruijie_push_to_labprobe.sh`
3. 重启 Hub 容器或 Python 服务。

Docker Compose 场景通常是：

```sh
docker compose down
docker compose up -d --build
```

## 路由器脚本布置方法

推荐用升级脚本布置。它会温和停用旧脚本，避免新旧脚本同时跑。

把两个脚本上传到路由器：

```sh
scp scripts/ruijie_labprobe_install.sh root@192.168.5.1:/tmp/ruijie_labprobe_install.sh
scp scripts/ruijie_push_to_labprobe.sh root@192.168.5.1:/tmp/ruijie_push_to_labprobe.sh
```

登录路由器后运行升级脚本：

```sh
ssh root@192.168.5.1
sh /tmp/ruijie_labprobe_install.sh http://你的Hub地址:58443 你的HOOK_TOKEN BE72Pro
```

升级脚本会做这些事：

- 终止旧的 LabProbe 路由器脚本残留进程，但不误杀其他系统进程。
- 把旧 `/etc/labprobe/push_devices.sh`、`push_router_wan6.sh`、`watch_devices.sh` 重命名为 `.bak`。
- 清理旧 `/tmp` 状态、锁、PID、临时推送文件。
- 清理旧 cron 和 `rc.local` 里的 LabProbe 入口。
- 安装新的 `/etc/labprobe/ruijie_push_to_labprobe.sh`。
- 添加唯一 cron：
  `*/1 * * * * /etc/labprobe/ruijie_push_to_labprobe.sh >/tmp/labprobe_agent_cron.out 2>&1`
- 输出最终保留的脚本、cron、启动项和进程清单，方便核对。

如果你想手动核对配置：

```sh
grep -E '^(HUB_URL|ROUTER_NAME|LABPROBE_TOKEN)=' /etc/labprobe/ruijie_push_to_labprobe.sh
```

手动试跑：

```sh
/etc/labprobe/ruijie_push_to_labprobe.sh
cat /tmp/labprobe_agent.log
```

## 注意

- 新脚本是一次性 agent，不再启动常驻 watcher。
- 所有运行状态、缓存和日志都在 `/tmp`：
  - `/tmp/labprobe_agent/`
  - `/tmp/labprobe_agent.lock`
  - `/tmp/labprobe_agent.log`
- `/tmp/labprobe_agent.log` 超过 256KB 会自动只保留最后 128KB。
- 终端列表按约 45 秒节流；cron 每分钟触发也不会堆进程。
- IPv6 邻居/前缀/模式只有变化时推送，另外每 5 分钟完整校准一次。
- Hub 请求最多重试 3 次，带退避间隔；Hub 不可用时只保留最新一份待推送状态。
- 桥接或 relay 模式下，脚本不会把本机 DHCPv6 租约当权威终端 IPv6 数据。
- DHCPv6 Server 模式下，会尝试读取 `/tmp/hosts/odhcpd`、`/tmp/odhcpd.leases`、`/tmp/dhcp.leases`。
- 设备在线/离线仍由锐捷 `dev_sta / user_list` 决定，不由 IPv6 ND 状态决定。
- 如果 IPv6 前缀切换，旧前缀地址会保留为历史记录，但不会覆盖新主 IPv6。
