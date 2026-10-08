# LabProbe BE72 与 BE50 安装指南

适用版本：Hub 0.14.1、LabRelay 0.2.75。本文供首次部署用户使用，按 Docker Hub、路由器 Relay、Android APP 的顺序操作。目前已验证的路由器为 BE72 Pro 和 BE50；其他型号需单独验证。N1 盒子可以承担 Docker Hub，但必须运行 64 位 Linux。

## 1 安装前准备

- 一台常开的 Linux 主机或 N1 盒子，能连接路由器并运行 Docker。N1 的 S905D 为 64 位 ARM；登录盒子运行 `uname -m` 和 `getconf LONG_BIT`，应分别看到 `aarch64` 和 `64`。若系统为 32 位，先更换 64 位系统。
- 盒子的局域网 IP、足够的可用存储，以及 Docker Engine。选择 Compose 方式时还需 Docker Compose 插件。安装命令以 Debian 基础的 Armbian 为例；Ubuntu 等系统使用其对应的 [Docker 官方安装说明](https://docs.docker.com/engine/install/)。
- BE72 Pro 或 BE50 路由器的 SSH 管理权限。路由器须能访问盒子上的 Hub 端口 `58443`。BE72 使用 ARM64 Relay，BE50 使用 ARMv7 Relay；安装脚本会自动识别。
- 两条不同的随机令牌：`APP_TOKEN` 供手机 APP 登录 Hub；`HOOK_TOKEN` 供路由器 Relay 上报。路由器的 EWEB 管理密码也请准备好。不要把真实令牌、密码和 `.env`／`run.env` 发给其他用户。
- 首次下载需要访问 Docker Hub 和 GitHub Release。原 NAS 域名当前不可用，本指南及默认安装器均不使用它。

| 准备项 | 在哪里填写 | 用途 |
| --- | --- | --- |
| Hub 地址，如 `http://192.168.1.20:58443` | Hub 配置文件、路由器安装器、APP | 三端连接到同一台 Hub |
| `APP_TOKEN` | Hub 配置文件和 APP 的“APP Token” | 手机访问 Hub |
| `HOOK_TOKEN`（Relay Token） | Hub 配置文件和路由器安装器 | Relay 向 Hub 上报与领取任务 |
| `MQTT_PASSWORD` | Hub 配置文件 | Hub 内部消息服务密码，APP 无需手动填写 |
| 路由器 EWEB 地址、账号和密码 | Hub 配置文件或 APP 路由器配置 | 读取和管理固件功能 |

Compose 方式的配置文件是 `.env`；docker run 方式的配置文件是 `run.env`，两种示例分别在 2.4 和 2.5。

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

若已安装，先运行 `docker version`；选择 Compose 方式时再检查 `docker compose version`。若尚未安装且系统为 Debian 或基于 Debian 的 Armbian，可按 [Docker 官方 Debian 安装方法](https://docs.docker.com/engine/install/debian/)执行：

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl openssl
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

### 2.3 准备目录和配置（两种安装方式通用）

以下文件直接在 N1 或 Linux 主机上创建。先完成本节，再选择 **2.4 的 Docker Compose** 或 **2.5 的 docker run**。一台主机只使用其中一种方式，以免容器名称或端口冲突。全部内容已在本文给出，无需下载源码。

```sh
mkdir -p ~/labprobe-hub
cd ~/labprobe-hub
mkdir -p data config backups logs update-repository/agent
```

将 `192.168.1.20` 改为 N1 的 IP，`192.168.1.1` 改为路由器的 EWEB 地址。分别运行三次 `openssl rand -hex 32`，将三个不同的输出用于 APP_TOKEN、HOOK_TOKEN 和 MQTT_PASSWORD；再准备 EWEB 密码。**Compose 用户**在此目录创建以下 `.env`；**docker run 用户**使用 2.5 给出的 `run.env`。

**文件：`~/labprobe-hub/.env`**

```dotenv
LABPROBE_IMAGE=onlychallgener/labprobe-hub:v0.14.1
LABRELAY_RELEASE_VERSION=0.2.75
PORT=58443
TZ=Asia/Shanghai
HUB_NAME='LabProbe Hub'
HUB_ADVERTISE_URL=http://192.168.1.20:58443
HUB_HOST_IPV4=192.168.1.20

APP_TOKEN=''
HOOK_TOKEN=''

ROUTER_EWEB_URL=http://192.168.1.1
ROUTER_USERNAME=admin
ROUTER_EWEB_PASSWORD=''

MQTT_USERNAME=labprobe
MQTT_PASSWORD=''
MQTT_PUBLIC_URL=''
MQTT_TOPIC_PREFIX=labprobe/hub
```

Compose 的 `.env` 保留密码外面的单引号，在引号内填值；密码本身若含单引号，写成 `\'`。有关引号规则可查看 [Docker 官方说明](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/#env-file-syntax)。

`APP_TOKEN` 填到手机，`HOOK_TOKEN` 填到路由器安装器。首次部署可让 `MQTT_PUBLIC_URL` 留空，APP 使用 Hub 的实时连接与备用读取；需要 MQTT 时，局域网可填 `ws://192.168.1.20:9001/mqtt`，外网填自己反向代理后的 `wss://` 地址。

两种方式都创建以下基础配置：

```sh
cat > config/config.yaml <<'EOF'
home:
  name: LabProbe Hub
router:
  enabled: true
  mode: push
watched_devices: []
polling:
  enabled: false
  interval_seconds: 60
EOF
```

### 2.4 方式一：完整 Docker Compose 示例（推荐）

**文件：`~/labprobe-hub/compose.yaml`**

```yaml
services:
  labprobe-mqtt:
    image: eclipse-mosquitto:2
    container_name: labprobe-mqtt
    user: "0:0"
    network_mode: host
    restart: unless-stopped
    environment:
      MQTT_USERNAME: ${MQTT_USERNAME:-labprobe}
      MQTT_PASSWORD: ${MQTT_PASSWORD:?请在 .env 填写 MQTT_PASSWORD}
    entrypoint:
      - /bin/sh
      - -ec
      - |
        mkdir -p /mosquitto/config/runtime /mosquitto/data
        rm -f /mosquitto/config/runtime/passwords /mosquitto/config/runtime/passwords.tmp
        mosquitto_passwd -b -c /mosquitto/config/runtime/passwords "$$MQTT_USERNAME" "$$MQTT_PASSWORD"
        {
          echo "user mosquitto"
          echo "persistence true"
          echo "persistence_location /mosquitto/data/"
          echo "log_dest stdout"
          echo "log_timestamp true"
          echo "connection_messages true"
          echo "log_type error"
          echo "log_type warning"
          echo "log_type notice"
          echo "log_type information"
          echo ""
          echo "listener 1883 127.0.0.1"
          echo "protocol mqtt"
          echo "allow_anonymous false"
          echo "password_file /mosquitto/config/runtime/passwords"
          echo ""
          echo "listener 9001 0.0.0.0"
          echo "protocol websockets"
          echo "allow_anonymous false"
          echo "password_file /mosquitto/config/runtime/passwords"
        } > /mosquitto/config/runtime/mosquitto.conf
        chown -R 1883:1883 /mosquitto/config/runtime /mosquitto/data
        chmod 600 /mosquitto/config/runtime/passwords
        chmod 644 /mosquitto/config/runtime/mosquitto.conf
        exec mosquitto -c /mosquitto/config/runtime/mosquitto.conf
    volumes:
      - ./config/mqtt:/mosquitto/config/runtime
      - ./data/mqtt:/mosquitto/data
    healthcheck:
      test: ["CMD-SHELL", "mosquitto_pub -h 127.0.0.1 -p 1883 -u \"$$MQTT_USERNAME\" -P \"$$MQTT_PASSWORD\" -t labprobe/health -m ping -q 1"]
      interval: 20s
      timeout: 5s
      retries: 5
      start_period: 10s

  labprobe-hub:
    image: ${LABPROBE_IMAGE:-onlychallgener/labprobe-hub:v0.14.1}
    container_name: labprobe-hub
    network_mode: host
    restart: unless-stopped
    depends_on:
      labprobe-mqtt:
        condition: service_healthy
    environment:
      PORT: ${PORT:-58443}
      TZ: ${TZ:-Asia/Shanghai}
      HUB_NAME: ${HUB_NAME:-LabProbe Hub}
      HUB_ADVERTISE_URL: ${HUB_ADVERTISE_URL:?请在 .env 填写 HUB_ADVERTISE_URL}
      HUB_HOST_IPV4: ${HUB_HOST_IPV4:?请在 .env 填写 HUB_HOST_IPV4}
      APP_TOKEN: ${APP_TOKEN:?请在 .env 填写 APP_TOKEN}
      HOOK_TOKEN: ${HOOK_TOKEN:?请在 .env 填写 HOOK_TOKEN}
      ROUTER_EWEB_URL: ${ROUTER_EWEB_URL:?请在 .env 填写 ROUTER_EWEB_URL}
      ROUTER_USERNAME: ${ROUTER_USERNAME:-admin}
      ROUTER_EWEB_PASSWORD: ${ROUTER_EWEB_PASSWORD:?请在 .env 填写 ROUTER_EWEB_PASSWORD}
      ROUTER_SESSION_TIME: "3600"
      ROUTER_RPC_PRIMARY: "true"
      ROUTER_DASHBOARD_POLL_SEC: "3"
      ROUTER_DEVICE_POLL_SEC: "5"
      CONFIG_PATH: /app/config/config.yaml
      CONFIG_DIR: /app/config
      DATA_DIR: /app/data
      BACKUPS_DIR: /app/backups
      LOGS_DIR: /app/logs
      UPDATE_REPOSITORY_DIR: /app/update-repository
      LABRELAY_RELEASE_VERSION: ${LABRELAY_RELEASE_VERSION:-0.2.75}
      MQTT_PUBLIC_URL: ${MQTT_PUBLIC_URL:-}
      MQTT_INTERNAL_HOST: 127.0.0.1
      MQTT_INTERNAL_PORT: "1883"
      MQTT_USERNAME: ${MQTT_USERNAME:-labprobe}
      MQTT_PASSWORD: ${MQTT_PASSWORD:?请在 .env 填写 MQTT_PASSWORD}
      MQTT_TOPIC_PREFIX: ${MQTT_TOPIC_PREFIX:-labprobe/hub}
      LOG_LEVEL: INFO
      LOG_RETENTION_DAYS: "14"
    volumes:
      - ./data:/app/data
      - ./config:/app/config
      - ./backups:/app/backups
      - ./logs:/app/logs
      - ./update-repository:/app/update-repository:ro
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:$${PORT}/health >/dev/null || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 40s
```

这份示例使用 Linux 的 host 网络：Hub 监听 TCP 58443，MQTT WebSocket 监听 TCP 9001，内部 MQTT 1883 只监听本机。没有 `ports:` 映射；主机上的这些端口应空闲。镜像会自动选择 AMD64 或 ARM64，无需在 N1 上手动指定架构。MQTT 配置和密码文件会在启动时自动生成。

在同一目录校验、下载并启动：

```sh
cd ~/labprobe-hub
chmod 600 .env
sudo docker compose config --quiet
sudo docker compose pull
sudo docker compose up -d --no-build
sudo docker compose ps
curl -fsS http://127.0.0.1:58443/health
```

`config --quiet` 成功时没有输出；若提示缺少某个变量，先补全 `.env`。首次启动时等两个容器显示 `healthy`。健康接口应返回 `ok: true`。查看日志：

```sh
sudo docker compose logs --tail 100 labprobe-hub labprobe-mqtt
```

### 2.5 方式二：完整 docker run 示例

不使用 Compose 时，仍先完成 **2.3 的目录和基础配置**。以下步骤在 `~/labprobe-hub` 中执行。这种方式不需要 Compose 插件。

**文件：`~/labprobe-hub/run.env`**

复制下列完整内容，填写地址和四个空白的令牌／密码项。这里由 Docker 直接读取，**等号后不要加包裹用的引号，也不要给 `$` 或 `#` 添加转义**；密码中原有的字符保持原样。两种配置文件的读取规则不同，不要把 Compose 的 `.env` 直接作为 `--env-file` 使用。格式见 [Docker 官方说明](https://docs.docker.com/reference/cli/docker/container/run/#set-environment-variables--e---env---env-file)。

```dotenv
PORT=58443
TZ=Asia/Shanghai
HUB_NAME=LabProbe Hub
HUB_ADVERTISE_URL=http://192.168.1.20:58443
HUB_HOST_IPV4=192.168.1.20
APP_TOKEN=
HOOK_TOKEN=
ROUTER_EWEB_URL=http://192.168.1.1
ROUTER_USERNAME=admin
ROUTER_EWEB_PASSWORD=
ROUTER_SESSION_TIME=3600
ROUTER_RPC_PRIMARY=true
ROUTER_DASHBOARD_POLL_SEC=3
ROUTER_DEVICE_POLL_SEC=5
CONFIG_PATH=/app/config/config.yaml
CONFIG_DIR=/app/config
DATA_DIR=/app/data
BACKUPS_DIR=/app/backups
LOGS_DIR=/app/logs
UPDATE_REPOSITORY_DIR=/app/update-repository
LABRELAY_RELEASE_VERSION=0.2.75
MQTT_USERNAME=labprobe
MQTT_PASSWORD=
MQTT_PUBLIC_URL=
MQTT_INTERNAL_HOST=127.0.0.1
MQTT_INTERNAL_PORT=1883
MQTT_TOPIC_PREFIX=labprobe/hub
LOG_LEVEL=INFO
LOG_RETENTION_DAYS=14
```

`APP_TOKEN`、`HOOK_TOKEN`、`MQTT_PASSWORD`、`ROUTER_EWEB_PASSWORD` 必须填好；令牌与 Compose 方式的用途相同。若使用 MQTT 实时同步，将 `MQTT_PUBLIC_URL` 改成手机能访问的 `ws://` 或 `wss://` 地址。

然后创建 MQTT 启动脚本：

```sh
cd ~/labprobe-hub
chmod 600 run.env
mkdir -p config/mqtt data/mqtt
cat > config/mqtt/start.sh <<'EOF'
#!/bin/sh
set -eu
: "${MQTT_USERNAME:?MQTT_USERNAME is required}"
: "${MQTT_PASSWORD:?MQTT_PASSWORD is required}"
mkdir -p /mosquitto/config/runtime /mosquitto/data
rm -f /mosquitto/config/runtime/passwords /mosquitto/config/runtime/passwords.tmp
mosquitto_passwd -b -c /mosquitto/config/runtime/passwords "$MQTT_USERNAME" "$MQTT_PASSWORD"
cat > /mosquitto/config/runtime/mosquitto.conf <<'CONF'
user mosquitto
persistence true
persistence_location /mosquitto/data/
log_dest stdout
log_timestamp true
connection_messages true
log_type error
log_type warning
log_type notice
log_type information

listener 1883 127.0.0.1
protocol mqtt
allow_anonymous false
password_file /mosquitto/config/runtime/passwords

listener 9001 0.0.0.0
protocol websockets
allow_anonymous false
password_file /mosquitto/config/runtime/passwords
CONF
chown -R 1883:1883 /mosquitto/config/runtime /mosquitto/data
chmod 600 /mosquitto/config/runtime/passwords
chmod 644 /mosquitto/config/runtime/mosquitto.conf
exec mosquitto -c /mosquitto/config/runtime/mosquitto.conf
EOF
```

下载镜像并启动 MQTT：

```sh
sudo docker pull eclipse-mosquitto:2
sudo docker pull onlychallgener/labprobe-hub:v0.14.1

sudo docker run -d \
  --name labprobe-mqtt \
  --restart unless-stopped \
  --network host \
  --user 0:0 \
  --env-file ./run.env \
  -v "$PWD/config/mqtt:/mosquitto/config/runtime" \
  -v "$PWD/data/mqtt:/mosquitto/data" \
  --health-cmd='mosquitto_pub -h 127.0.0.1 -p 1883 -u "$MQTT_USERNAME" -P "$MQTT_PASSWORD" -t labprobe/health -m ping -q 1' \
  --health-interval=20s --health-timeout=5s --health-retries=5 --health-start-period=10s \
  --entrypoint /bin/sh \
  eclipse-mosquitto:2 /mosquitto/config/runtime/start.sh
```

检查 MQTT：

```sh
sudo docker inspect --format '{{.State.Health.Status}}' labprobe-mqtt
sudo docker logs --tail 30 labprobe-mqtt
```

等 MQTT 显示 `healthy` 后，仍在 `~/labprobe-hub` 目录启动 Hub：

```sh
sudo docker run -d \
  --name labprobe-hub \
  --restart unless-stopped \
  --network host \
  --env-file ./run.env \
  -v "$PWD/data:/app/data" \
  -v "$PWD/config:/app/config" \
  -v "$PWD/backups:/app/backups" \
  -v "$PWD/logs:/app/logs" \
  -v "$PWD/update-repository:/app/update-repository:ro" \
  onlychallgener/labprobe-hub:v0.14.1

sudo docker inspect --format '{{.State.Health.Status}}' labprobe-hub
sudo docker logs --tail 100 labprobe-hub
curl -fsS http://127.0.0.1:58443/health
```

Hub 使用镜像自带的健康检查，首次启动可能显示 `starting`，稍后应为 `healthy`。

两种方式启动成功后，都可访问 `http://127.0.0.1:58443/agent/install.sh` 获取路由器安装脚本。请保持 N1 的 IP 稳定，允许局域网访问 TCP 58443；启用 MQTT WebSocket 时也允许 TCP 9001。

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
- **APP Token**：填写 Hub `.env` 或 `run.env` 中的 `APP_TOKEN`。不要填 Relay 使用的 `HOOK_TOKEN` 或路由器 EWEB 密码。
- **路由器配置**：名称填写 BE72 或 BE50；管理地址使用 Hub 能访问的路由器地址；账号一般为 `admin`，密码填写 EWEB 管理密码。Hub 路由标识可留空。

点击 APP 的“保存设置”，再点击“校准数据”，然后查看首页与终端列表。Hub 收到 Relay 上报后，状态、温度与终端信息才会逐步显示。安卓 APP 与修改版“星耀家 Hub”测试 APK 是不同客户端；首次给其他用户部署使用 LabProbeApp 正式 Release。

## 5 更新和排查

### 5.1 更新 Hub

先备份 `~/labprobe-hub/data/`、`config/`，以及所用的 `.env`／`run.env` 和 Compose 文件。

**Compose 用户：**按新 Release 的版本号修改 `.env` 中的 `LABPROBE_IMAGE`，然后执行：

```sh
cd ~/labprobe-hub
sudo docker compose config --quiet
sudo docker compose pull
sudo docker compose up -d --no-build
sudo docker compose ps
```

**docker run 用户：**先将下面下载命令和 2.5 中 Hub 启动命令末尾的 `v0.14.1` 改为目标版本，再执行。只移除旧 Hub 容器：

```sh
cd ~/labprobe-hub
sudo docker pull onlychallgener/labprobe-hub:v0.14.1
sudo docker stop labprobe-hub
sudo docker rm labprobe-hub
```

然后重新执行 **2.5 中启动 Hub 的完整 `docker run` 命令**。MQTT 容器保持运行；挂载在主机目录中的配置和数据继续使用。若改了 MQTT 用户名或密码，也需停止并移除 `labprobe-mqtt`，按 2.5 重新创建 MQTT，再重新创建 Hub。

### 5.2 更新路由器 Relay

在路由器 SSH 终端执行：

```sh
sh /etc/labprobe/labprobe-install.sh upgrade
```

### 5.3 连接排查

修改 `.env`／`run.env` 后也要按对应方式重新创建容器，单纯 `docker restart` 不会载入修改后的环境变量。

Hub 无法连接时，在 N1 上执行：

```sh
sudo docker ps -a --filter name=labprobe-
sudo docker logs --tail 100 labprobe-hub
sudo docker logs --tail 100 labprobe-mqtt
curl -fsS http://127.0.0.1:58443/health
```

Compose 用户也可在 `~/labprobe-hub` 执行 `sudo docker compose ps`。端口若改过，健康检查和 APP 地址也要使用新端口。Relay 失败时先核对 Hub 地址和 HOOK_TOKEN，再运行 `labrelay test-hub`。APP 登录失败时核对 Hub 地址、端口和 APP_TOKEN。请隐藏真实令牌与密码后再分享日志。

版本发布页：[Hub 源码与 Release](https://github.com/OnlyChallgener/labprobe-hub/releases/tag/v0.14.1)、[Relay 下载](https://github.com/OnlyChallgener/labprobe-hub/releases/tag/labrelay-v0.2.75)。
