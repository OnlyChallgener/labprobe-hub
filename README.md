# LabProbe Hub v0.6.7

本版为 Lucky Webhook 简化兼容版。

## 更新

1. `/hook/lucky` 支持钉钉文本格式：`{"msgtype":"text","text":{"content":"Lucky：#{ipAddr}"}}`。
2. `#{ipAddr}` 按 Lucky 原样输出保存，不拆 IP / 端口。
3. 收到 Lucky 后写入 `state.vpn.lucky`、`state.luckyStun` 和兼容字段 `state.stun.publicAddress`。
4. `/api/status` 返回后 APP 首页可显示 Lucky STUN 地址。

## Lucky 填法

接口地址：`http://192.168.5.46:58443/hook/lucky?token=你的HookToken`

请求方法：`POST`

请求头建议填：`Content-Type: application/json`

请求体：

```json
{
  "msgtype": "text",
  "text": {
    "content": "Lucky：#{ipAddr}"
  }
}
```
