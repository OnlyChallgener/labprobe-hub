# 在 ARM64 NAS 重新构建 BE72 精简包

本目录包含固定版本的官方源码归档、网页发布归档、校验值和打包脚本。首次构建会下载并校验 Go 1.26.10。构建工具在临时容器中使用；生成的软件包只交付给路由器，不会安装为 NAS 服务。

在本目录执行：

```sh
docker build -t be72-mihomo-builder .
docker run --rm --cpus 2 --memory 3g \
  --tmpfs /tmp:rw,size=1g \
  --tmpfs /work/go-cache:rw,size=1g \
  -v "$PWD:/work" be72-mihomo-builder \
  -c 'sh /work/build-compact.sh && python3 /work/package.py --binary /work/out-compact/mihomo --profile compact --output /work/release'
```

结果位于 `release/`，包含 IPK、中文安装说明、SHA256SUMS 和实际体积清单。临时构建缓存使用内存，容器退出后释放；源码、工具链归档与输出文件保留在本目录。请在 NAS 有足够空闲内存时执行。

精简构建保留常用代理协议，关闭内置 EasyTier、ZeroTier、Tailscale 出站与 gVisor。若以后升级版本，需要同步更新源码/网页/工具链的固定版本与校验值，再重新构建和验收；不要只修改包名。安装或升级步骤见生成的 `README.zh-CN.md`。

构建标签不会把代理解密移交给硬件 NAT。CPU 支持的 AES 指令由运行库自动检测，实际代理速度仍需结合节点与线路测试。
