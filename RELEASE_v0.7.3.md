# labprobe-hub v0.7.3

## 修复

1. 状态刷新卡住
   - `/api/status` 不再阻塞等待公网 IP / DDNS 查询。
   - 改为缓存优先返回，后台按 TTL 刷新。

2. 文件写入稳定性
   - `state.json`、`devices.json`、`events.json` 等改为加锁 + 原子写入。

3. 路由端最简推送
   - 新增 `/api/router/push`，路由器只需要 POST JSON 到 Docker。

4. 每日统计去重
   - 连续离线不重复计数。
   - 在线 0 秒的异常离线不计入每日统计。
