# LabProbe Hub v0.2.0

LabProbe Hub 是 LabProbe / 极客网探的家庭网络状态中转服务。

当前版本重点支持：

- Lucky Webhook：STUN / WireGuard / DDNS 地址变化记录
- 锐捷 BE72 本机脚本推送终端列表
- 关注终端在线 / 离线状态
- NAS 出口 IPv4 / IPv6 检测
- DDNS A / AAAA 解析匹配检测
- APP 手动刷新接口
- Docker Hub 多架构镜像构建

## GitHub Actions 推送 Docker Hub

需要在 GitHub 仓库设置：

Variables:

```text
DOCKERHUB_USERNAME=你的DockerHub用户名
```

Secrets:

```text
DOCKERHUB_TOKEN=你的DockerHub Personal Access Token
```

然后进入 GitHub：

```text
Actions -> Docker Image -> Run workflow
```

或者推送到 `main` 分支自动运行。

成功后 Docker Hub 会出现：

```text
你的DockerHub用户名/labprobe-hub:latest
你的DockerHub用户名/labprobe-hub:0.2.0
```

## 绿联 NAS 部署

路径：

```bash
mkdir -p /volume1/docker/labprobe-hub/data
cd /volume1/docker/labprobe-hub
```

复制 `config.example.yaml` 为：

```bash
cp config.example.yaml /volume1/docker/labprobe-hub/config.yaml
```

修改 `config.yaml` 里的域名和关注设备 MAC。

创建 `docker-compose.yml`，参考项目内文件。启动：

```bash
cd /volume1/docker/labprobe-hub
APP_TOKEN=你的APP_TOKEN HOOK_TOKEN=你的HOOK_TOKEN DOCKERHUB_USERNAME=你的DockerHub用户名 docker compose up -d
```

测试：

```bash
curl http://127.0.0.1:58443/health
```

## 锐捷脚本

把 `scripts/ruijie_push_to_labprobe.sh` 复制到锐捷，修改里面的 `HOOK_TOKEN`。

测试：

```bash
/root/labprobe_ruijie_push.sh
```

定时任务：

```bash
crontab -l > /tmp/labprobe_cron 2>/dev/null
grep -v "labprobe_ruijie_push.sh" /tmp/labprobe_cron > /tmp/labprobe_cron_new
echo "*/1 * * * * /root/labprobe_ruijie_push.sh >/dev/null 2>&1" >> /tmp/labprobe_cron_new
crontab /tmp/labprobe_cron_new
crontab -l
```

## API

读取状态：

```bash
curl -H "Authorization: Bearer 你的APP_TOKEN" http://127.0.0.1:58443/api/status
```

读取关注终端：

```bash
curl -H "Authorization: Bearer 你的APP_TOKEN" http://127.0.0.1:58443/api/devices
```

读取全部在线终端：

```bash
curl -H "Authorization: Bearer 你的APP_TOKEN" "http://127.0.0.1:58443/api/devices?view=online"
```

读取事件：

```bash
curl -H "Authorization: Bearer 你的APP_TOKEN" http://127.0.0.1:58443/api/events
```
