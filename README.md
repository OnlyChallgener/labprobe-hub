# labprobe-hub v0.7.3

LabProbe Docker 服务端，用于接收路由器/NAS 推送并给 App 提供状态、事件、每日总结接口。

## v0.7.3 修复

- `/api/status` 改为缓存优先，不再在 App 刷新时同步执行公网 IP / DDNS 慢联网任务。
- 慢任务改为后台刷新，避免“服务连通但刷新不出数据，重启才恢复”。
- JSON 写入改成原子写入，降低并发推送和 App 刷新时的文件损坏/覆盖风险。
- 增加 `/api/status/refresh` 手动后台刷新接口。
- 增加 `/api/router/push` 极简路由推送入口，支持 snapshot 和 device_event。
- 每日统计使用规范化设备事件，过滤连续离线和在线 0 秒异常离线。

## 典型接口

- `GET /health`
- `GET /api/status`
- `POST /api/status/refresh`
- `POST /api/router/push`
- `GET /api/devices`
- `GET /api/events`
- `GET /api/daily/latest`
