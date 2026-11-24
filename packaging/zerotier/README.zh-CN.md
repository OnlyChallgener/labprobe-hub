# BE72 / BE50 ZeroTier One 1.16.2

这是为已核对的锐捷固件构建的静态客户端 IPK。无需可用的锐捷软件源，不执行 `opkg update`，不替换系统 C/C++ 库。

| 设备 | IPK 架构 | 主程序 | 包大小 |
| --- | --- | --- | --- |
| BE72 | aarch64_cortex-a53 | ARM64，静态 musl | 约 1.18 MB |
| BE50 | arm_cortex-a7 | ARM32 EABI，软浮点，静态 musl | 约 0.91 MB |

准确字节数及 SHA256 见 `build-result.json` 和 `SHA256SUMS`。BE72 已核对内核 5.4.271 / ReyeeOS 1.279.2015；BE50 已核对内核 5.4.55 / ReyeeOS 1.380.1307。其他型号、其他固件需要重新确认。

## 首次安装：一条命令

将**整个解压目录**上传到路由器 `/tmp/ZeroTier-1.16.2-BE72-BE50`，用 root 权限执行：

```sh
sh /tmp/ZeroTier-1.16.2-BE72-BE50/install.sh
```

脚本自动识别架构，检查签名、包大小和 SHA256，安装本机对应包并验证本地服务。默认启动，并保存当前 IPK 供以后升级回退。至少预留 16 MB overlay 空间。

初始压缩包及内附公钥应通过可信渠道取得。首次安装信任这份公钥；以后升级使用路由器内已固定的公钥。

也可以手动 `opkg install /tmp/对应型号.ipk`，但此方式不会缓存原 IPK，升级工具会在缺少回退包时拒绝升级。推荐首次就使用 `install.sh`。

已有其他来源的 ZeroTier 包、进程或身份文件时会拒绝直接覆盖，需要先安排迁移。包内没有任何预设节点私钥、账号密码或已加入的网络。

本次 BE72 临时测试进程仍在运行，首次正式安装前请先按 `验证报告.md` 中的命令停止它。正式包使用 `/etc/zerotier-one/`；临时测试使用 RAM 目录，两者身份独立，直接首次安装会生成新节点并需要重新授权。若要保留已授权的临时节点身份，应先安排迁移。

## 如何加入网络

浏览器登录 ZeroTier Central，创建网络并复制 16 位 Network ID。在路由器执行：

```sh
zerotier-cli info
zerotier-cli join 你的16位NetworkID
zerotier-cli listnetworks
```

随后在 Central 对照 `info` 显示的 10 位节点 ID 授权。`ACCESS_DENIED` 表示等待网络授权；`ONLINE` 表示节点能联系 ZeroTier 基础设施，不能单独证明某个网络已授权。

本包提供命令行管理，不包含 eWEB / LuCI 网页插件。它是网络客户端，未编入非自由许可的内置网络控制器和桌面 SSO；可连接现有 ZeroTier Central 或其他兼容控制器。

**路由器加入前请检查 Central 下发路由。** 尤其不要把与本机 LAN 相同的网段再经远端节点导入。本次临时测试发现网络下发的 `192.168.5.0/24` 与 BE72 本地 LAN 重叠，因此对临时节点设置了仅允许虚拟网段的白名单。正式安装不会自动修改你的网络控制器、LAN、防火墙或默认网关。远程访问整个 LAN 还需要单独安排转发规则和回程路由。

## 后续升级

拿到同一签名公钥发布的新版本完整目录，上传后运行：

```sh
zerotier-update /tmp/新的完整发布目录
```

预检查、但不安装：

```sh
zerotier-update --check /tmp/新的完整发布目录
```

若以后将发布目录放到自己的 HTTPS 静态站点，可配置一次更新地址：

```sh
uci set zerotier_static.main.update_url='https://你的站点/zerotier/stable'
uci commit zerotier_static
zerotier-update --check
zerotier-update
```

站点目录保留 `aarch64_cortex-a53/` 和 `arm_cortex-a7/` 两个子目录，各含 `manifest`、`manifest.sig` 和相应 IPK。脚本固定公钥验签，不接受 HTTP 或降级版本。

**目前未部署在线更新站点。** 官方发布新版本后，仍需先构建、测试并签名适配 IPK，再发布到上述地址；脚本不会直接把官方其他架构文件装到路由器上。

安装失败、健康检查失败或节点身份发生变化时，工具尝试恢复上一版本和备份配置。普通失败回退已通过隔离故障测试；断电、存储损坏、强制杀死全部进程不保证自动恢复。仍保留的恢复文件会打印路径。

## 配置、身份及备份

- 服务：`/etc/init.d/zerotier-static`
- UCI：`/etc/config/zerotier_static`
- 节点身份、网络：`/etc/zerotier-one/`
- 固定更新公钥：`/etc/zerotier-static/update.pub`
- 当前 IPK 缓存：`/etc/zerotier-static/cache/current.ipk`
- 上一版本与状态备份：`/etc/zerotier-static/rollback/`

节点目录和升级状态备份包含私钥，请只保存在自己的设备或私密备份中，不要上传到网页或公开仓库。普通重启及本工具升级保留身份；厂商固件升级是否保留 overlay 取决于厂商的升级方式，升级固件前应另做离机备份。包已提供 OpenWrt 的 keep.d 条目，但不能保证厂商固件遵循该机制。

暂停或恢复服务：

```sh
uci set zerotier_static.main.enabled='0'
uci commit zerotier_static
/etc/init.d/zerotier-static restart
```

恢复时把 `enabled` 改为 `1`，再执行后两行。

## 构建和验证依据

构建在 NAS 的独立 Docker 容器内进行，不依赖路由器私有源。BE72 使用原生 GCC / musl；BE50 使用 Zig 0.14.1 的 ARM32 musl EABI 软浮点交叉编译。均关闭 SSO 与非自由控制器，启用静态链接。

上游源码 SHA256：

```text
2c607f573c6e38815433af289d364a689a203b18b51125f06c4472014d0657f0
```

该值与 OpenWrt 包配方一致。源码未修改；本目录的 `source/` 提供构建、封装和测试脚本。签名私钥不在发布包中。未来发布需使用原签名私钥，或进行明确的公钥迁移。

已执行的验证及其边界见 `验证报告.md`。两台设备均只做临时可执行文件版本检查和 `opkg --noaction` 检查；BE72 另按用户要求做临时真实入网。未在 NAS、BE50 安装或替换服务，也未在 BE72 执行 IPK 安装。临时入网状态及清理情况以报告为准。

上游资料：

- [ZeroTier 1.16.2 源码及发布](https://github.com/zerotier/ZeroTierOne/releases/tag/1.16.2)
- [ZeroTier 官方接入指南](https://docs.zerotier.com/quickstart/)
- [OpenWrt ZeroTier 包配方](https://github.com/openwrt/packages/blob/master/net/zerotier/Makefile)

