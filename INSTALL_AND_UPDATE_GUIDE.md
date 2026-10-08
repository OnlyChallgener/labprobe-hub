# LabProbe BE72 与 BE50 安装指南

适用版本：Hub 0.14.1、LabRelay 0.2.75。本文供首次部署用户使用，按 Docker Hub、路由器 Relay、Android APP 的顺序操作。目前已验证的路由器为 BE72 Pro 和 BE50；其他型号需单独验证。N1 盒子可以承担 Docker Hub，但必须运行 64 位 Linux。

## 1 安装前准备

- 一台常开的 Linux 主机或 N1 盒子，能连接路由器并运行 Docker。N1 的 S905D 为 64 位 ARM；登录盒子运行 `uname -m` 和 `getconf LONG_BIT`，应分别看到 `aarch64` 和 `64`。若系统为 32 位，先更换 64 位系统。
- 盒子的局域网 IP、足够的可用存储，以及 Docker Engine 和 Docker Compose 插件。安装命令以 Debian 基础的 Armbian 为例；Ubuntu 等系统使用其对应的 [Docker 官方安装说明](https://docs.docker.com/engine/install/)。
- BE72 Pro 或 BE50 路由器的 SSH 管理权限。路由器须能访问盒子上的 Hub 端口 `58443`。BE72 使用 ARM64 Relay，BE50 使用 ARMv7 Relay；安装脚本会自动识别。
- 两条不同的随机令牌：`APP_TOKEN` 供手机 APP 登录 Hub；`HOOK_TOKEN` 供路由器 Relay 上报。路由器的 EWEB 管理密码也请准备好。不要把真实令牌、密码和 `.env` 发给其他用户。
- 首次下载需要访问 Docker Hub 和 GitHub Release。原 NAS 域名当前不可用，本指南及默认安装器均不使用它。

| 准备项 | 在哪里填写 | 用途 |
| --- | --- | --- |
| Hub 地址，如 `http://192.168.1.20:58443` | Hub `.env`、路由器安装器、APP | 三端连接到同一台 Hub |
| `APP_TOKEN` | Hub `.env` 和 APP 的“APP Token” | 手机访问 Hub |
| `HOOK_TOKEN`（Relay Token） | Hub `.env` 和路由器安装器 | Relay 向 Hub 上报与领取任务 |
| `MQTT_PASSWORD` | Hub `.env` | Hub 内部消息服务密码，APP 无需手动填写 |
| 路由器 EWEB 地址、账号和密码 | Hub `.env` 或 APP 路由器配置 | 读取和管理固件功能 |

这里的“Docker Hub”指用 Docker 运行 LabProbe Hub 服务；镜像仓库为 `onlychallgener/labprobe-hub`。用户需要自己部署 Hub，示例 IP 必须替换成自己的地址。

在盒子上可运行两次 `openssl rand -hex 32`，把输出分别保存为自己的 APP_TOKEN 和 HOOK_TOKEN。后续每个设备填写相应令牌。

## 2 在 N1 或 Linux 主机安装 Docker Hub

### 2.1 检查架构与系统

```sh
uname -m
getconf LONG_BIT
cat /etc/os-release
```

N1 只有 `aarch64` 加 64 位 Linux 的组合适用本指南。普通 x86 主机应为 `x86_64` 加 64 位。Docker Hub 镜像提供 AMD64 和 ARM64 两种架构。

### 2.2 安装 Docker

若已安装，先运行 `docker version` 与 `docker compose version`。若尚未安装且系统为 Debian 或基于 Debian 的 Armbian，可按 [Docker 官方 Debian 安装方法](https://docs.docker.com/engine/install/debian/)执行：

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
printf 'Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.asc\n' "$VERSION_CODENAME" "$(dpkg --print-architecture)" | sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker version
sudo docker compose version
```

如果 `/etc/os-release` 表示 Ubuntu，请改用 [Docker 官方 Ubuntu 安装方法](https://docs.docker.com/engine/install/ubuntu/)，不要执行 Debian 软件源命令。以下步骤使用 `sudo docker`；以 root 登录时可去掉 `sudo`。

### 2.3 准备 Hub 配置并启动

将示例地址 `192.168.1.20` 改成 N1 或主机的实际局域网 IP。

```sh
git clone --branch v0.14.1 --depth 1 https://github.com/OnlyChallgener/labprobe-hub.git
cd labprobe-hub
cp .env.example .env
mkdir -p data config backups logs update-repository/agent
cp config.example.yaml config/config.yaml
chmod 600 .env
vi .env
```

在 `.env` 中至少修改以下项：

```dotenv
HUB_ADVERTISE_URL=http://192.168.1.20:58443
HUB_HOST_IPV4=192.168.1.20
APP_TOKEN=把第一条随机令牌填在这里
HOOK_TOKEN=把第二条随机令牌填在这里
MQTT_PASSWORD=另设一条随机密码
ROUTER_EWEB_URL=http://192.168.1.1
ROUTER_EWEB_PASSWORD=路由器实际管理密码
MQTT_PUBLIC_URL=
```

`ROUTER_EWEB_URL` 使用路由器在盒子所在网络可访问的地址。按本机实际网络修改；两条 Token 不能相同，也不要保留示例值。`APP_TOKEN` 以后填写到手机，`HOOK_TOKEN` 以后填写到路由器。

首次部署可让 `MQTT_PUBLIC_URL` 留空，APP 使用 Hub 的实时连接与备用读取。需要 MQTT 时，局域网可填写 `ws://192.168.1.20:9001/mqtt`；外网则填写自己反向代理后的 `wss://` 地址。APP 从 Hub 获取此配置。

```sh
sudo docker compose -f docker-compose.host.yml pull
sudo docker compose -f docker-compose.host.yml up -d --no-build
sudo docker compose -f docker-compose.host.yml ps
curl -fsS http://127.0.0.1:58443/health
```

健康检查应返回 `ok: true`。此时还可以在盒子上访问 `http://127.0.0.1:58443/agent/install.sh`，确认 Docker 容器正在提供路由器安装脚本。请保持 N1 的 IP 稳定，并允许局域网访问 TCP 58443。

## 3 在 BE72 或 BE50 安装路由器 Relay

通过 SSH 登录路由器，确认它能访问 N1 的局域网 IP。将下面的示例地址改成自己的 Hub 地址。安装过程中会提示输入 Hub 的 `HOOK_TOKEN`，不会使用 APP_TOKEN。

```sh
export HUB_URL=http://192.168.1.20:58443
wget -O /tmp/labprobe-install.sh "$HUB_URL/agent/install.sh" && sh /tmp/labprobe-install.sh
```

安装器会识别路由器架构、下载对应的 Relay、校验 SHA256、保存配置，并注册开机自启。BE72 Pro 使用 `labrelay-linux-arm64`，BE50 使用 `labrelay-linux-armv7`。默认二进制包从 [LabRelay GitHub Release](https://github.com/OnlyChallgener/labprobe-hub/releases/latest) 下载。

安装或升级只会启动／重启 LabProbe 服务，通常不需要重启整台路由器。原生 EWEB 的“更多 → HUB”页面属于另行安装的扩展页面，本文的一键命令安装 Relay，APP 管理功能通过 Hub 接入。

安装完成后检查：

```sh
labrelay version
labrelay status
labrelay test-hub
labrelay doctor
```

版本应为 `labrelay 0.2.75`。若路由器不能访问 GitHub，可先从 Release 下载对应架构二进制及 `checksums.txt`，放进 N1 的 `labprobe-hub/update-repository/agent/`，再在路由器运行 `export LABPROBE_UPDATE_ROOT="$HUB_URL"` 后重新执行安装脚本。Hub 将经 Docker 容器提供这些文件；请核对二进制与校验文件来自同一个 Release。

## 4 安装 APP 并填写设置

从 [LabProbeApp Releases](https://github.com/OnlyChallgener/LabProbeApp/releases) 下载当前 Android 安装包。打开 APP 的连接设置，填写：

- **Hub**：协议下拉框选 `http://`，右侧填写 `192.168.1.20:58443`，改成自己的 N1 IP。外网使用时选择对应协议并填写自己可访问的反向代理地址。
- **APP Token**：填写 Hub `.env` 中的 `APP_TOKEN`。不要填 Relay 使用的 `HOOK_TOKEN` 或路由器 EWEB 密码。
- **路由器配置**：名称填写 BE72 或 BE50；管理地址使用 Hub 能访问的路由器地址；账号一般为 `admin`，密码填写 EWEB 管理密码。Hub 路由标识可留空。

点击 APP 的“保存设置”，再点击“校准数据”，然后查看首页与终端列表。Hub 收到 Relay 上报后，状态、温度与终端信息才会逐步显示。安卓 APP 与修改版“星耀家 Hub”测试 APK 是不同客户端；首次给其他用户部署使用 LabProbeApp 正式 Release。

## 5 更新和排查

升级 Hub 前备份 `data/`、`config/` 和 `.env`。更新到新版本时按新 Release 的版本号修改 `LABPROBE_IMAGE`，重新执行 `docker compose pull` 与 `up -d --no-build`。升级路由器 Relay 可用：

```sh
sh /etc/labprobe/labprobe-install.sh upgrade
```

Hub 无法连接时，在 N1 上检查 `sudo docker compose -f docker-compose.host.yml ps`、`sudo docker logs --tail 100 labprobe-hub` 与 `curl -fsS http://127.0.0.1:58443/health`。Relay 失败时先核对 Hub 地址和 HOOK_TOKEN，再运行 `labrelay test-hub`。APP 登录失败时核对 Hub 地址、端口和 APP_TOKEN。请隐藏真实令牌与密码后再分享日志。

版本发布页：[Hub 源码与 Release](https://github.com/OnlyChallgener/labprobe-hub/releases/tag/v0.14.1)、[Relay 下载](https://github.com/OnlyChallgener/labprobe-hub/releases/tag/labrelay-v0.2.75)。
