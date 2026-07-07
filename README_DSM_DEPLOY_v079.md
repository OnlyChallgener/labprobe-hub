# DSM / Docker 部署 LabProbe Hub v0.7.9

当前群晖目录一般是：

```text
/volume1/docker/labprobe-hub/
├── docker-compose.yaml
├── config.yaml
└── data/
```

`data/` 是数据目录，不要删除。

## 推荐部署方式

把本包作为 Hub 仓库新版本提交并构建 Docker 镜像，然后在 DSM Container Manager 里重新创建容器。

## 验证

路由器上：

```sh
TOKEN="$(grep '^HOOK_TOKEN=' /etc/labprobe/config.conf | cut -d= -f2- | tr -d '"')"

curl -s \
  -H "X-LabProbe-Token: $TOKEN" \
  "http://192.168.5.46:58443/api/ipv6-neighbors"

curl -s \
  -H "X-LabProbe-Token: $TOKEN" \
  "http://192.168.5.46:58443/api/devices?view=online" | grep -i "6c:1f:f7:76:71:04\|2409"
```

也可以浏览器临时验证：

```text
http://192.168.5.46:58443/api/ipv6-neighbors?token=你的HOOK_TOKEN
```
