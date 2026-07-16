# LabRelay v0.1.0

面向 LabProbe / 极客网探的轻量 Rust 四层 TCP 反代服务。

## 第一版范围

- 公网 IPv6 TCP → 内网 IPv4（6→4）
- 公网 IPv6 TCP → 内网 IPv6（6→6）
- 6→6 完整 IPv6、MAC + IPv6 后缀动态匹配
- 多规则、启停、编辑、自动到期
- 最大连接数、空闲超时、当前连接数、上下行字节统计
- Unix Socket 结构化控制
- 不支持 UDP、4→4、HTTP Host/SNI、TLS 解密
- 不修改防火墙

## 路由器要求

- Linux aarch64
- `ip`、`curl`、OpenWrt `procd`
- 手动放行 WAN6 → 路由器 INPUT TCP 20000–20020

## 本机测试

```sh
cargo run -- daemon --config ./relay.json --socket /tmp/labrelay-test.sock --state /tmp/labrelay-state.json
cargo run -- ctl --socket /tmp/labrelay-test.sock '{"action":"status"}'
```

## 编译 BE72 静态程序

GitHub Actions 运行 `Build LabRelay Router Binary`，下载 `labrelay-router-aarch64-v0.1.0`。
