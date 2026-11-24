# BE72：Mihomo + MetaCubeXD 独立 Web 管理页

<!-- PACKAGE_PROFILE_AND_SIZE -->

这是原生 `opkg` 安装包，包含静态 ARM64 Mihomo 内核、离线 MetaCubeXD 页面和 `procd` 服务。内核以 gzip 压缩形式存放于闪存，启动时校验并解压到私有内存目录，再执行原始内核；没有使用 UPX 或修改内核功能。版本及下载来源见同目录 `versions.json`。无需锐捷私有软件源、LuCI 或 ShellClash。

支持在浏览器查看和选择节点、刷新节点订阅、查看规则、连接和日志。此包默认提供手动 HTTP/SOCKS 代理；安装和启动不会创建透明代理规则、接管路由器 DNS 或修改路由、防火墙。若要让整个局域网自动分流，需要另外适配 BE72 固件的转发、DNS 和防火墙，不能只在面板打开 TUN 后就视为完成。

## 安装及首次使用

1. 将 `mihomo-web_版本_aarch64_cortex-a53.ipk` 上传到 BE72 的 `/tmp/`。请用本次包的准确文件名，避免同时匹配多个历史包。
2. 在路由器 SSH 中执行：

   ```sh
   opkg install /tmp/mihomo-web_1.19.33-1_aarch64_cortex-a53.ipk
   /etc/init.d/mihomo-web enable
   /etc/init.d/mihomo-web start
   mihomo-web access
   ```

3. 最后一条命令会显示本机 Web 地址、API 地址和随机密钥。例如 LAN 地址为 `192.168.110.1`，页面是 `http://192.168.110.1:9090/ui/`。
4. 在 MetaCubeXD 中添加后端：使用命令显示的 API 地址及 Secret。密钥保存在路由器 `/etc/mihomo/api.secret`，每台设备首次启动时独立生成，安装包中没有通用密码。
5. 配置自己的节点/订阅后，终端可以手动设置 HTTP 或 SOCKS5 代理：服务器为路由器 LAN IP，端口 `7890`。原始示例只有 DIRECT，未提供任何付费或公共代理节点。

`mihomo-web` 默认只绑定 UCI `network.lan.ipaddr` 中的 LAN IPv4 地址；无法识别时直接停止启动，不回退到 `0.0.0.0` 或 WAN。9090 为管理端口，7890 为手动代理端口。路由器 WAN/LAN 防火墙策略由原固件管理。请在局域网访问页面；不要将管理接口做外网端口映射。

修改 LAN 地址后，重启服务会更新管理页监听地址。已生成配置中的 `bind-address` 属于用户配置，若要继续使用 LAN 手动代理，也应将它改为新的 LAN IP。

## 导入节点或订阅

主配置：`/etc/mihomo/config.yaml`。可上传自己的 Mihomo/Clash YAML 配置替换此文件，再检查、重启：

```sh
mihomo-web check
/etc/init.d/mihomo-web restart
```

导入配置时保留 `tun.enable: false`、`dns.enable: false`，并将 `allow-lan: true` 和 `bind-address` 设置为本机 LAN 地址。控制接口地址、Secret 以及 Web 文件目录由服务参数统一设置，优先于 YAML 中的同名配置。

只添加订阅时，可保留原文件的基础设置，替换末尾 `proxies`、`proxy-groups` 和 `rules` 部分为：

```yaml
proxy-providers:
  subscription:
    type: http
    url: "https://你的服务商/Clash订阅地址"
    path: ./providers/subscription.yaml
    interval: 86400
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 600

proxy-groups:
  - name: PROXY
    type: select
    use:
      - subscription
    proxies:
      - DIRECT

rules:
  - MATCH,PROXY
```

订阅必须是 Mihomo/Clash 支持的代理列表或兼容 YAML，普通 Base64 分享链接集合不能直接当作 `proxy-provider` 使用。这里不内置第三方订阅转换服务。Web 面板的代理集合/订阅页面可以手动刷新已配置的 provider，在代理页面选择节点。

首次下载 HTTPS 订阅会校验服务端证书，固件需要有效的 CA 证书和正确系统时间；软件包不会关闭证书校验。若服务商仅支持经代理获取订阅，需先配置一个可用节点以完成首次下载。

## 常用管理与升级

```sh
/etc/init.d/mihomo-web status
logread -e mihomo
mihomo-web check
mihomo-web access
/etc/init.d/mihomo-web stop
/etc/init.d/mihomo-web restart
```

可用 UCI 调整管理端口（1024～65535）：

```sh
uci set mihomo_web.main.controller_port='9091'
uci commit mihomo_web
/etc/init.d/mihomo-web restart
```

升级前备份 `/etc/mihomo/` 和 `/etc/config/mihomo_web`，上传新版同名安装包后执行 `opkg install /tmp/准确的新包名.ipk`，再执行 `mihomo-web check` 和 `/etc/init.d/mihomo-web restart`。不需要先卸载，也不需要更新锐捷私有源。配置文件按 opkg conffile 规则保留；自动生成的 API 密钥、订阅缓存和选择状态不在安装包中，不会被升级覆盖。若 opkg 生成 `.opkg-new` 文件，可手动对比新版示例后合并设置。

初次安装不会自动启动服务。升级会停止旧进程，完成检查后按上述命令手动重启。

本包使用 gzip 存储内核，并保留完整离线 Web 页面。交付指南开头会按实际二进制列出原始内核、gzip 内核和页面体积。最终 IPK 大小、闪存安装占用和压缩内核大小也分别记录在 `build-result.json` 的 `bytes`、`installed_bytes` 和 `binary_archive_bytes`；`installed_bytes` 是安装归档解压大小，不是原始内核加页面的总大小。

`/usr/bin/mihomo` 是原生服务的启动入口，先校验压缩内核 SHA-256，再解压和校验原始内核 SHA-256，最后执行 `/tmp/mihomo-web-core/内核哈希/mihomo`。目录仅 root 可进入，并拒绝符号链接或错误属主/权限的缓存。并发启动通过 `flock` 锁协调，不重复写入半个内核。已验证缓存会复用；每次路由器重启后首次启动重新解压。

独立页面目录位于配置目录 `/etc/mihomo` 之外，因此启动入口只将 `/usr/share/mihomo-web/ui` 加入内核 `SAFE_PATHS` 白名单，同时保留调用环境已有的条目。配置检查和服务运行使用同一入口；不会全局关闭内核的路径安全检查。

内核文件缓存额外占用的 `/tmp` 内存空间等于本次原始内核大小（见交付指南开头），运行中的连接和 Go 堆还需要内存；这个文件大小不能当作进程总内存。升级到不同内核时使用独立哈希目录，旧缓存会在路由器重启后清除。节点订阅、规则集和 GeoIP/GeoSite 数据会额外占用存储与内存。默认示例不下载这些数据库；请根据 BE72 剩余空间选择订阅和规则集，避免堆积大型数据库。

Mihomo 的转发、规则匹配和代理加密在 CPU 中执行。BE72 的硬件 NAT 主要加速直接转发，无法直接卸载这些代理处理；软件包保留 ARM64 CPU 的密码指令支持，不能据此承诺千兆代理性能。安装包的可执行、页面/API 和配置检查结果也不等同于经代理节点的实测带宽。

## 构建与来源

在本次 ARM64 NAS 或其他 ARM64 Linux 环境执行 `build.sh` 构建，参数和固定版本见脚本与 `versions.json`，随后在本地执行：

```sh
python package.py --binary /path/to/mihomo --output /path/to/output
```

标准版使用默认 `--profile standard`；精简版使用 `--profile compact`，对应安装包发行号 `-2`。选择的二进制必须来自同一配置的构建，不能只对标准版内核更换 profile 标签。精简版构建标签和裁剪内容见生成的交付指南及 `build-result.json`；Web 页面保持完整。

打包器校验源码及页面归档 SHA-256、原始 ELF ARM64 架构和静态链接状态，并拒绝危险归档路径。启动入口中的原始及 gzip SHA-256 按本次二进制生成，不依赖在线校验服务。IPK 使用已在 BE72 `opkg` 验证的 gzip/tar 包装格式，包含 `debian-binary`、`control.tar.gz`、`data.tar.gz`。

- Mihomo 官方源码：<https://github.com/MetaCubeX/mihomo>，GPL-3.0，许可证随包保存在 `/usr/share/licenses/mihomo-web/mihomo-LICENSE`。
- MetaCubeXD 官方页面：<https://github.com/MetaCubeX/metacubexd>，MIT，许可证随包保存在 `/usr/share/licenses/mihomo-web/metacubexd-LICENSE`。
- 随交付包提供固定版本源码及构建/打包脚本；可用相同脚本升级构建，不依赖厂商软件源。

本包不是锐捷官方软件。服务安装脚本不会安装、卸载或更改原固件的 EWEB、STUN、WireGuard 或 ZeroTier 服务。
