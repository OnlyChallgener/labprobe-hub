"""Allow-listed assistant tool execution against cached Hub state."""

from __future__ import annotations

import json
import re
from datetime import date
from typing import Any, Dict, Iterable, List

from .catalog import tool_spec


class ToolError(RuntimeError):
    def __init__(self, message: str, code: str = "TOOL_ERROR", status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


_SENSITIVE_PARTS = ("token", "password", "secret", "api_key", "apikey", "authorization", "cookie", "credential", "privatekey", "presharedkey", "psk")
_DEVICE_FIELDS = (
    "name", "alias", "deviceAliasName", "hostName", "mac", "ip", "lastIp",
    "ipv6", "ipv6List", "online", "lastSeenAt", "onlineSince", "offlineAt",
    "connectType", "band", "rssi", "ssid",
)


def _sanitized(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _sanitized(item)
            for key, item in value.items()
            if not any(part in str(key).lower() for part in _SENSITIVE_PARTS)
        }
    if isinstance(value, list):
        return [_sanitized(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _rows(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [dict(row) for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        for key in ("list", "rules", "data", "items"):
            if isinstance(value.get(key), list):
                return [dict(row) for row in value[key] if isinstance(row, dict)]
    return []


class ToolExecutor:
    def __init__(self, hub_runtime: Any):
        self.hub = hub_runtime
        self._handlers: Dict[str, Any] = {}
        self._previews: Dict[str, Any] = {}

    def register_handler(self, tool_id: str, handler) -> None:
        """Extension point for feature modules: attach an executable handler
        for a catalogued tool id; the same risk/confirmation policy applies."""
        if tool_spec(tool_id) is None:
            raise ValueError(f"cannot register handler for unknown tool id: {tool_id}")
        self._handlers[tool_id] = handler

    def register_preview(self, tool_id: str, preview) -> None:
        """Extension point: confirmation-card builder for a write tool."""
        if tool_spec(tool_id) is None:
            raise ValueError(f"cannot register preview for unknown tool id: {tool_id}")
        self._previews[tool_id] = preview

    def validate(self, tool_id: str, arguments: Any) -> tuple[Dict[str, Any], Dict[str, Any]]:
        spec = tool_spec(tool_id)
        if spec is None:
            raise ToolError("不支持该指令", "TOOL_NOT_FOUND", 404)
        if not isinstance(arguments, dict):
            raise ToolError("指令参数必须是对象", "INVALID_ARGUMENTS")
        schema = spec.get("inputSchema") or {}
        properties = schema.get("properties") or {}
        required = schema.get("required") or []
        unknown = set(arguments) - set(properties)
        if schema.get("additionalProperties") is False and unknown:
            raise ToolError("包含不支持的参数", "INVALID_ARGUMENTS")
        for name in required:
            if name not in arguments or arguments[name] in (None, ""):
                raise ToolError(f"缺少参数：{name}", "INVALID_ARGUMENTS")
        clean: Dict[str, Any] = {}
        for name, value in arguments.items():
            rule = properties.get(name) or {}
            if rule.get("type") == "string":
                if not isinstance(value, str):
                    raise ToolError(f"参数 {name} 必须是文本", "INVALID_ARGUMENTS")
                value = value.strip()
                if len(value) > int(rule.get("maxLength") or 4096):
                    raise ToolError(f"参数 {name} 过长", "INVALID_ARGUMENTS")
                if rule.get("pattern") and not re.fullmatch(str(rule["pattern"]), value):
                    raise ToolError(f"参数 {name} 格式错误", "INVALID_ARGUMENTS")
                if rule.get("enum") and value not in rule["enum"]:
                    raise ToolError(f"参数 {name} 不在允许范围", "INVALID_ARGUMENTS")
            clean[name] = value
        return spec, clean

    @staticmethod
    def _client_context(client_context: Any) -> Dict[str, Any]:
        if not isinstance(client_context, dict):
            return {"settings": {}, "favorites": []}
        settings = client_context.get("settings") if isinstance(client_context.get("settings"), dict) else {}
        favorites = client_context.get("favorites") if isinstance(client_context.get("favorites"), list) else []
        safe_settings = {
            key: settings.get(key)
            for key in ("privacyMode", "favoriteNetworkMode", "routerDisplayName")
            if settings.get(key) is not None
        }
        safe_favorites = []
        for item in favorites[:100]:
            if not isinstance(item, dict):
                continue
            safe_favorites.append({
                key: item.get(key)
                for key in ("id", "title", "description", "localUrl", "remoteUrl", "serviceType")
                if item.get(key) not in (None, "")
            })
        return {"settings": safe_settings, "favorites": safe_favorites}

    def _device_documents(self) -> List[Dict[str, Any]]:
        document = self.hub.load_json(self.hub.DEVICES_FILE, {"online": [], "watched": []})
        archive = self.hub.load_device_archive()
        candidates: List[Dict[str, Any]] = []
        for key in ("online", "watched"):
            candidates.extend(dict(row) for row in (document.get(key) or []) if isinstance(row, dict))
        candidates.extend(dict(row) for row in archive.values() if isinstance(row, dict))
        unique: Dict[str, Dict[str, Any]] = {}
        for row in candidates:
            key = str(row.get("mac") or row.get("name") or row.get("hostName") or json.dumps(row, sort_keys=True))
            previous = unique.get(key, {})
            unique[key] = {**previous, **row}
        return list(unique.values())

    def _device_view(self, row: Dict[str, Any]) -> Dict[str, Any]:
        result = {key: row.get(key) for key in _DEVICE_FIELDS if row.get(key) not in (None, "")}
        raw_ipv6 = row.get("ipv6List") or row.get("ipv6") or []
        normalize = getattr(self.hub, "normalize_ipv6_list", None)
        ipv6 = normalize(raw_ipv6) if callable(normalize) else (raw_ipv6 if isinstance(raw_ipv6, list) else [raw_ipv6])
        if ipv6:
            result["ipv6List"] = ipv6
        return _sanitized(result)

    @staticmethod
    def _device_terms(row: Dict[str, Any]) -> Iterable[str]:
        for key in ("name", "alias", "deviceAliasName", "hostName", "mac", "ip", "lastIp"):
            value = str(row.get(key) or "").strip().lower()
            if value:
                yield value

    def resolve_device(self, query: str) -> Dict[str, Any]:
        needle = str(query or "").strip().lower()
        if not needle:
            raise ToolError("请提供设备名称或 MAC", "DEVICE_REQUIRED")
        rows = self._device_documents()
        exact = [row for row in rows if needle in set(self._device_terms(row))]
        matches = exact or [row for row in rows if any(needle in term for term in self._device_terms(row))]
        if not matches:
            raise ToolError(f"没有找到设备：{query}", "DEVICE_NOT_FOUND", 404)
        if len(matches) > 1:
            names = [str(row.get("name") or row.get("hostName") or row.get("mac") or "未知") for row in matches[:5]]
            raise ToolError("设备名称不唯一：" + "、".join(names), "DEVICE_AMBIGUOUS", 409)
        return matches[0]

    def preview(self, tool_id: str, arguments: Any, client_context: Any = None) -> Dict[str, Any]:
        spec, args = self.validate(tool_id, arguments)
        if spec["risk"] != "write":
            raise ToolError("只读指令无需确认", "CONFIRMATION_NOT_REQUIRED", 409)
        preview_fn = self._previews.get(tool_id)
        if preview_fn is not None:
            return preview_fn(self, args, client_context)
        if tool_id == "device.wol":
            device = self.resolve_device(args["device"])
            mac = str(device.get("mac") or "").strip()
            if not mac:
                raise ToolError("该设备没有可用 MAC 地址", "DEVICE_MAC_MISSING", 409)
            name = str(device.get("name") or device.get("hostName") or mac)
            return {
                "toolId": tool_id,
                "title": "确认唤醒设备",
                "summary": f"向 {name}（{mac}）发送 Wake-on-LAN 广播包",
                "arguments": {"device": args["device"], "mac": mac, "name": name},
                "expiresInSeconds": 300,
            }
        if tool_id == "app.setting.update":
            labels = {
                "privacyMode": "隐私模式",
                "favoriteNetworkMode": "收藏默认网络",
                "routerDisplayName": "路由器显示名称",
            }
            return {
                "toolId": tool_id,
                "executor": "app",
                "title": "确认修改 APP 设置",
                "summary": f"将{labels[args['setting']]}修改为：{args['value']}",
                "arguments": args,
                "expiresInSeconds": 300,
            }
        if tool_id == "app.favorite.add":
            if not args.get("localUrl") and not args.get("remoteUrl"):
                raise ToolError("收藏至少需要一个内网或外网地址", "FAVORITE_URL_REQUIRED")
            return {
                "toolId": tool_id,
                "executor": "app",
                "title": "确认增加收藏",
                "summary": f"增加收藏：{args['title']}",
                "arguments": args,
                "expiresInSeconds": 300,
            }
        if tool_id == "app.favorite.remove":
            context = self._client_context(client_context)
            needle = args["favorite"].lower()
            matches = [row for row in context["favorites"] if needle in {
                str(row.get("id") or "").lower(), str(row.get("title") or "").lower()
            }]
            if not matches:
                raise ToolError("没有找到该收藏", "FAVORITE_NOT_FOUND", 404)
            if len(matches) > 1:
                raise ToolError("收藏名称不唯一，请提供更准确的名称", "FAVORITE_AMBIGUOUS", 409)
            target = matches[0]
            clean_args = {"favorite": str(target.get("id") or args["favorite"]), "title": str(target.get("title") or args["favorite"])}
            return {
                "toolId": tool_id,
                "executor": "app",
                "title": "确认删除收藏",
                "summary": f"删除收藏：{clean_args['title']}",
                "arguments": clean_args,
                "expiresInSeconds": 300,
            }
        raise ToolError("该写入指令尚未开放", "TOOL_NOT_IMPLEMENTED", 501)

    def execute(self, tool_id: str, arguments: Any, allow_write: bool = False,
                client_context: Any = None) -> Dict[str, Any]:
        spec, args = self.validate(tool_id, arguments)
        if spec["risk"] == "write" and not allow_write:
            raise ToolError("该操作需要二次确认", "CONFIRMATION_REQUIRED", 409)
        handler = self._handlers.get(tool_id)
        if handler is not None:
            return _sanitized(handler(self, args, client_context))
        if tool_id == "status.get":
            return {"status": _sanitized(self.hub.status_document())}
        if tool_id == "devices.list":
            document = self.hub.load_json(self.hub.DEVICES_FILE, {"online": [], "watched": [], "updatedAt": None})
            online = [self._device_view(row) for row in (document.get("online") or []) if isinstance(row, dict)]
            watched = [self._device_view(row) for row in (document.get("watched") or []) if isinstance(row, dict)]
            return {"updatedAt": document.get("updatedAt"), "online": online[:100], "watched": watched[:100]}
        if tool_id == "device.ipv6":
            device = self.resolve_device(args["device"])
            view = self._device_view(device)
            return {"device": view, "ipv6List": view.get("ipv6List") or []}
        if tool_id == "daily.summary":
            day = args.get("date") or date.today().isoformat()
            return {"daily": _sanitized(self.hub.aggregate_daily(day))}
        if tool_id == "router.portmap.list":
            document, loaded = self.hub._load_portmap_rules_document()
            status = self.hub.load_json(self.hub.PORTMAP_ROUTER_STATUS_FILE, {})
            return {"loaded": bool(loaded), "rules": _sanitized(document.get("rules") or []), "routerStatus": _sanitized(status)}
        if tool_id == "router.firewall.list":
            sync = getattr(self.hub, "ROUTER_CONFIG_SYNC", None)
            frame = sync.snapshot("firewall") if sync is not None else {}
            data = frame.get("data") if isinstance(frame, dict) else None
            if not isinstance(data, (dict, list)):
                raise ToolError("防火墙缓存尚未同步，请稍后重试", "SNAPSHOT_UNAVAILABLE", 503)
            return {"revision": frame.get("revision"), "updatedAt": frame.get("updatedAt"), "rules": _sanitized(_rows(data))}
        if tool_id == "events.list":
            events = self.hub.load_json(self.hub.EVENTS_FILE, [])
            rows = [dict(row) for row in events if isinstance(row, dict) and not row.get("deleted")]
            try:
                limit = int(args.get("limit") or 30)
            except (TypeError, ValueError):
                limit = 30
            limit = max(1, min(100, limit))
            return {"events": [_sanitized(row) for row in reversed(rows[-limit:])], "total": len(rows)}
        if tool_id == "agent.status":
            snapshot = getattr(self.hub, "agent_presence_snapshot", None)
            if not callable(snapshot):
                raise ToolError("Agent 状态尚未就绪", "AGENT_SNAPSHOT_UNAVAILABLE", 503)
            return {"agent": _sanitized(snapshot())}
        if tool_id == "stun.rules.list":
            service = getattr(self.hub, "STUN_SERVICE", None)
            if service is None:
                raise ToolError("STUN 服务未启用", "SERVICE_UNAVAILABLE", 503)
            document = service.rules_snapshot()
            return {
                "revision": document.get("revision"),
                "updatedAt": document.get("updatedAt"),
                "rules": _sanitized(document.get("rules") or []),
            }
        if tool_id == "wireguard.status":
            service = getattr(self.hub, "WIREGUARD_SERVICE", None)
            if service is None:
                raise ToolError("WireGuard 服务未启用", "SERVICE_UNAVAILABLE", 503)
            return {"wireguard": _sanitized(service.document())}
        if tool_id == "app.settings.get":
            return {"settings": self._client_context(client_context)["settings"]}
        if tool_id == "app.favorite.list":
            return {"favorites": self._client_context(client_context)["favorites"]}
        if tool_id.startswith("app.") and spec["risk"] == "write":
            raise ToolError("该操作必须由 APP 在本机确认执行", "CLIENT_EXECUTION_REQUIRED", 409)
        if tool_id == "device.wol":
            mac = str(args.get("mac") or "").strip()
            if not mac:
                device = self.resolve_device(args["device"])
                mac = str(device.get("mac") or "").strip()
            return _sanitized(self.hub.send_wol(mac))
        raise ToolError("该指令尚未实现", "TOOL_NOT_IMPLEMENTED", 501)
