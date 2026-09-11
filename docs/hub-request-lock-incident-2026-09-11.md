# Hub 502 / 请求锁阻塞修复日志（2026-09-11）

## 现象

- APP 首页、设置、WireGuard 与 STUN 请求统一显示 502 或“上游服务暂不可用”。
- 重启 Hub 后立即恢复。
- 故障期间路由 Dashboard 与 realtime 接口仍返回 200，进程没有崩溃。

## 日志证据

- 2026-09-10 14:07:14：`GET /health` 最后一次返回 200。
- 14:07:32 后：普通同步、Agent、STUN、WireGuard 与健康检查停止完成响应。
- 14:08 至 15:27：绕过全局数据锁的 Dashboard / realtime 仍持续返回 200。
- 2026-09-11 11:17:35：Hub v0.12.2 重新启动；健康检查与全部 Agent 通道恢复 200。

结论：旧进程没有退出，而是一个未完成的普通请求长期占用了 request-wide `DATA_LOCK`。故障前 APP 正在读取/操作 STUN，且 Agent 的 STUN 状态上报会同步执行路由器原生映射与防火墙 RPC，因此 STUN/WireGuard 外部 I/O 是首要触发候选；访问日志只记录已完成请求，无法从现有日志唯一确认具体请求。

## 修复

1. AI chat / 通知流、STUN、WireGuard、TCP 测试改用各自的服务锁，不再持有全 Hub 请求锁等待流式响应或路由器 I/O。
2. STUN 与 WireGuard 的读取也纳入各自服务锁，避免解除全局锁后出现不一致快照。
3. WireGuard 调用 STUN 防火墙生命周期时显式获取 STUN 服务锁，保持跨服务写入串行。
4. 仍使用旧全局锁的接口最多等待 3 秒；超时返回 `503 HUB_DATA_BUSY` 与 `Retry-After: 2`，便于 APP 重试并让健康检查暴露真实拥堵。

## 验证

- `tests/test_request_lock_isolation.py`：覆盖隔离路径、路径边界、普通接口仍串行，以及锁被占用时的有界 503。
- `tests/test_stun_service.py`、`tests/test_wireguard_service.py`：覆盖规则增删改、回滚、端口联动、防火墙生命周期及并发修订。
- 2026-09-11：上述定向测试共 82 项通过；完整 Python 测试共 621 项通过；`py_compile` 与 Git 差异检查通过。
- 2026-09-11：首次 GitHub CI 的 621 项 Hub 测试全部通过；随后发现 CI 仍校验旧 LabRelay `0.2.40`，已同步为仓库当前 `0.2.46` 后重新验证。
- 本地仅运行 Python 测试；不安装或运行 Android SDK、Gradle、模拟器。Android 与镜像构建交由 GitHub Actions。

## 部署观察

- 升级后关注日志中的 `request data lock timeout`；该记录会给出被保护接口的 method/path。
- 若再次出现 STUN/WireGuard 单页繁忙，收集该时段 Hub 与路由器 RPC 日志；其它 APP 页面与 `/health` 应保持可用或快速返回明确 503，不应再次整体 502。
