# LabRelay v0.1.1

面向 OpenWrt/嵌入式 Linux 路由器的轻量 TCP IPv6 四层反代。

支持：

- TCP IPv6 → IPv4
- TCP IPv6 → IPv6
- MAC + IPv6 后 64 位动态目标解析
- 持久化规则和开机自动恢复
- 规则 revision 幂等执行
- 结构化错误码
- 当前/峰值连接和累计流量
- 本机 Unix Socket 控制

不包含：

- UDP
- 4→4
- 任意 Shell 执行
- 自动防火墙修改
- HTTPS 证书终止

构建：

```sh
cargo test --all-targets
cargo build --release --target aarch64-unknown-linux-musl
```

GitHub Actions 产物：

```text
labrelay-router-aarch64-v0.1.1
```

运行状态：

```sh
/usr/bin/labrelay version
/usr/bin/labrelay ctl '{"action":"status"}'
```
