# LabRelay (Rust Router Agent & Relay Daemon)

LabRelay 是运行在已适配路由器（如锐捷 ReyeeOS / OpenWrt aarch64 等）上的高性能纯 Rust 采集代理与中继守护进程。

---

## 核心架构

- **`labrelay daemon`**：统一管理本地 UNIX Domain Socket (`/tmp/labrelay.sock`) 与状态文件 (`/tmp/labprobe/relay-state.json`)，承载本地穿透转发、双栈连接管理与秒级 TCP 峰值压测。
- **`labrelay agent`**：轻量级后台采集进程，定时与事件驱动采集终端清单 (`dev_sta/user_list`)、网口速率、WAN6 前缀与系统负载，通过 `HOOK_TOKEN` 上报 Hub。
- **系统级自愈**：由 OpenWrt `procd` 统一托管自启 (`/etc/init.d/labprobe`)，内存极低（< 15MB），断网与路由器重启后秒级自动重连。

---

## 快速安装与配置

在路由器 SSH 终端中执行一键安装脚本：

```sh
# 格式：sh install.sh <HUB_URL> <HOOK_TOKEN> [ROUTER_NAME]
wget -O /tmp/install.sh http://<你的Hub地址>:58443/agent/install.sh
sh /tmp/install.sh http://<你的Hub地址>:58443 YOUR_HOOK_TOKEN router
```

配置文件路径：`/etc/labprobe/agent.json`。

---

## 常用运维命令

```sh
# 1. 验证与 Hub 的通信连通性及鉴权
labrelay test-hub

# 2. 查看当前 Agent 采集状态与设备列表
labrelay status

# 3. 本地中继与连通性自检
labrelay doctor

# 4. 平滑热升级（保留现有配置）
sh /etc/labprobe/install.sh upgrade
```

详细多端协同安装与升级说明请参阅 [`INSTALL_AND_UPDATE_GUIDE.md`](../INSTALL_AND_UPDATE_GUIDE.md)。
