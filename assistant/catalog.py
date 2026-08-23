"""Versioned, allow-listed assistant capabilities.

The catalog is descriptive only. A tool is not executable until a server-side
handler with the same id is registered and its risk/confirmation policy passes.
"""

from __future__ import annotations

from typing import Any, Dict, List

CATALOG_REVISION = "2026-08-23.2"

_TOOLS: List[Dict[str, Any]] = [
    {
        "id": "status.get",
        "version": "1",
        "name": "查询 Hub 状态",
        "description": "查询 Hub、路由器和公网出口的当前连接状态。",
        "examples": ["查看当前网络状态", "Hub 和路由器连接正常吗"],
        "risk": "read",
        "confirmation": "none",
        "scope": "status.read",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "id": "devices.list",
        "version": "1",
        "name": "查询设备",
        "description": "列出在线、关注和最近活动设备。",
        "examples": ["有哪些设备在线", "列出我关注的设备"],
        "risk": "read",
        "confirmation": "none",
        "scope": "devices.read",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "id": "device.ipv6",
        "version": "1",
        "name": "查询设备 IPv6",
        "description": "按设备名称、MAC 或别名查询当前 IPv6 地址。",
        "examples": ["告诉我 Mate60 的 IPv6 地址"],
        "risk": "read",
        "confirmation": "none",
        "scope": "devices.read",
        "inputSchema": {
            "type": "object",
            "properties": {"device": {"type": "string", "maxLength": 128}},
            "required": ["device"],
            "additionalProperties": False,
        },
    },
    {
        "id": "daily.summary",
        "version": "1",
        "name": "查询每日记录",
        "description": "查询指定日期的设备、流量和网络变化摘要。",
        "examples": ["查看今天的每日记录", "总结昨天的网络变化"],
        "risk": "read",
        "confirmation": "none",
        "scope": "daily.read",
        "inputSchema": {
            "type": "object",
            "properties": {"date": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"}},
            "additionalProperties": False,
        },
    },
    {
        "id": "router.firewall.list",
        "version": "1",
        "name": "查询防火墙规则",
        "description": "列出当前防火墙规则和启用状态。",
        "examples": ["查看当前防火墙规则"],
        "risk": "read",
        "confirmation": "none",
        "scope": "router.read",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "id": "router.portmap.list",
        "version": "1",
        "name": "查询端口映射",
        "description": "列出路由器和 Hub 的端口映射。",
        "examples": ["查看当前端口映射"],
        "risk": "read",
        "confirmation": "none",
        "scope": "router.read",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "id": "device.wol",
        "version": "1",
        "name": "唤醒设备",
        "description": "向指定已登记设备发送 Wake-on-LAN 唤醒请求。",
        "examples": ["唤醒 ANS"],
        "risk": "write",
        "confirmation": "always",
        "scope": "devices.wol",
        "inputSchema": {
            "type": "object",
            "properties": {"device": {"type": "string", "maxLength": 128}},
            "required": ["device"],
            "additionalProperties": False,
        },
    },
    {
        "id": "app.settings.get",
        "version": "1",
        "name": "查看 APP 设置",
        "description": "查看允许 AI 读取的 APP 显示与收藏偏好，不包含 Token 或密码。",
        "examples": ["查看当前 APP 设置"],
        "risk": "read",
        "confirmation": "none",
        "scope": "app.settings.read",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "id": "app.setting.update",
        "version": "1",
        "name": "修改 APP 设置",
        "description": "修改允许列表内的 APP 设置：隐私模式、收藏网络模式或路由器显示名称。",
        "examples": ["打开隐私模式", "把收藏默认切换成外网", "把路由器显示名称改成主路由"],
        "risk": "write",
        "confirmation": "always",
        "scope": "app.settings.write",
        "inputSchema": {
            "type": "object",
            "properties": {
                "setting": {"type": "string", "enum": ["privacyMode", "favoriteNetworkMode", "routerDisplayName"]},
                "value": {"type": "string", "maxLength": 128},
            },
            "required": ["setting", "value"],
            "additionalProperties": False,
        },
    },
    {
        "id": "app.favorite.list",
        "version": "1",
        "name": "查看收藏地址",
        "description": "列出 APP 当前收藏的服务名称和允许展示的地址。",
        "examples": ["列出我的收藏地址"],
        "risk": "read",
        "confirmation": "none",
        "scope": "app.favorites.read",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "id": "app.favorite.add",
        "version": "1",
        "name": "增加收藏地址",
        "description": "在 APP 增加一个手动收藏，可填写内网地址、外网地址和服务类型。",
        "examples": ["收藏 Home Assistant，内网地址是 http://192.168.1.2:8123"],
        "risk": "write",
        "confirmation": "always",
        "scope": "app.favorites.write",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "maxLength": 64},
                "description": {"type": "string", "maxLength": 160},
                "localUrl": {"type": "string", "maxLength": 512},
                "remoteUrl": {"type": "string", "maxLength": 512},
                "serviceType": {"type": "string", "maxLength": 32},
            },
            "required": ["title"],
            "additionalProperties": False,
        },
    },
    {
        "id": "app.favorite.remove",
        "version": "1",
        "name": "删除收藏地址",
        "description": "按名称或 ID 删除一个 APP 收藏。",
        "examples": ["删除 Home Assistant 收藏"],
        "risk": "write",
        "confirmation": "always",
        "scope": "app.favorites.write",
        "inputSchema": {
            "type": "object",
            "properties": {"favorite": {"type": "string", "maxLength": 128}},
            "required": ["favorite"],
            "additionalProperties": False,
        },
    },
]


def catalog() -> Dict[str, Any]:
    return {"revision": CATALOG_REVISION, "tools": [dict(tool) for tool in _TOOLS]}


def tool_spec(tool_id: str) -> Dict[str, Any] | None:
    return next((dict(tool) for tool in _TOOLS if tool["id"] == tool_id), None)


def function_name(tool_id: str) -> str:
    return tool_id.replace(".", "_").replace("-", "_")


def tool_id_from_function(name: str) -> str | None:
    return next((tool["id"] for tool in _TOOLS if function_name(tool["id"]) == name), None)


def provider_tools() -> List[Dict[str, Any]]:
    return [{
        "type": "function",
        "function": {
            "name": function_name(tool["id"]),
            "description": tool["description"],
            "parameters": tool["inputSchema"],
        },
    } for tool in _TOOLS]
