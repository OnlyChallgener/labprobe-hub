# Hub v0.8.4 + LabRelay/Agent v0.1.1 部署顺序

## 1. 更新 Hub

Docker Compose 镜像：

```yaml
image: onlychallgener/labprobe-hub:0.8.4
```

更新：

```sh
docker compose pull
docker compose up -d --force-recreate
curl -s http://127.0.0.1:58443/health
```

应返回版本 `0.8.4`。

Hub v0.8.4 兼容旧 Rust，建议先更新 Hub。

## 2. 构建路由器安装包

GitHub Actions：

```text
Build LabRelay Router Binary
```

产物：

```text
labrelay-router-aarch64-v0.1.1
labrelay-router-aarch64-v0.1.1.tar.gz
```

## 3. 安装到 BE72

解压后执行：

```sh
sh install_labrelay.sh \
  http://192.168.5.46:58443 \
  '真实HOOK_TOKEN' \
  BE72Pro \
  ./labrelay-aarch64-musl
```

安装器会：

- 保留 `/etc/labprobe/relay.json`
- 保留 `/etc/labprobe/labrelay.conf`
- 验证新二进制
- 失败时回滚旧二进制
- 不修改防火墙

## 4. 检查

```sh
/usr/bin/labrelay version
/etc/labprobe/labrelay_agent.sh version
/etc/labprobe/labrelay_agent.sh test

/etc/init.d/labrelay running && echo LabRelay正常
/etc/init.d/labrelay_agent running && echo Agent正常

/usr/bin/labrelay ctl '{"action":"status"}'
tail -80 /tmp/labrelay-agent.log
```

预期：

```text
labrelay 0.1.1
labrelay-agent 0.1.1 protocol 2
```

## 5. 可配置项

`/etc/labprobe/labrelay.conf`：

```sh
PORT_MIN='20000'
PORT_MAX='20020'
LAN_IF='br-lan'
```

修改后：

```sh
/etc/init.d/labrelay restart
```

防火墙需要手动放行对应 IPv6 INPUT TCP 端口范围。
