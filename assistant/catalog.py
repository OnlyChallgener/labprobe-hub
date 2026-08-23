"""Versioned, allow-listed assistant capabilities.

The catalog is descriptive only. A tool is not executable until a server-side
handler with the same id is registered and its risk/confirmation policy passes.
"""

from __future__ import annotations

from typing import Any, Dict, List

CATALOG_REVISION = "2026-08-23.1"

_TOOLS: List[Dict[str, Any]] = [
    {
        "id": "status.get",
        "version": "1",
        "name": "查询 Hub 状态",
        "description": "查询 Hub、路由器和公网出口的当前连接状态。",
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
]


def catalog() -> Dict[str, Any]:
    return {"revision": CATALOG_REVISION, "tools": [dict(tool) for tool in _TOOLS]}

