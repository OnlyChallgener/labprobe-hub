# LabProbe Hub v0.8.2

仅新增端口映射控制链路：

- 端口映射规则 API：6→4、6→6、6→6 IPv6 后缀匹配。
- APP → Hub → BE72 Agent → Rust LabRelay 的结构化命令队列。
- 路由器状态、连接数、上下行流量与 60 秒采样历史。
- 不接受任意 Shell 命令，不自动修改防火墙。
- 内置 LabRelay v0.1.0 Rust 源码与 aarch64-musl GitHub Actions 构建。
