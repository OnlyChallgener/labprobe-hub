"""Capability domains exposed to the assistant.

Three domains are wired through assistant.extend:

- ``relay.*``   LabRelay agent control: STUN penetration rules and agent upgrade.
- ``router.*``  Router-native control via the Hub command queue: IPv6 port
                mappings and router status.
- ``app.*``     APP-local actions returned to the client as ``clientAction``
                payloads (navigation, full sync).

Every write tool is risk="write" with confirmation="always" and reuses the
exact primitives the HTTP routes use (validation, conflict checks, command
queue, event log), so AI-initiated changes behave identically to APP-initiated
ones and stay visible in the APP. Future domains register the same way via
``assistant.extend.register_domain``.
"""

from __future__ import annotations

import secrets
import time
from typing import Any, Dict, List

from . import catalog
from .tools import ToolError

NAVIGATE_ROUTES = ("home", "devices", "router", "tools", "ai_chat", "favorites", "settings",
                   "stun", "wireguard", "ipv6", "portmap", "ddns", "nat", "wol")


def _spec(tool_id: str, name: str, description: str, examples: List[str], scope: str,
          risk: str, confirmation: str, input_schema: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": tool_id,
        "version": "1",
        "name": name,
        "description": description,
        "examples": examples,
        "risk": risk,
        "confirmation": confirmation,
        "scope": scope,
        "inputSchema": input_schema,
    }


_SPECS: List[Dict[str, Any]] = [
    _spec(
        "relay.stun.rule.add", "新增 STUN 穿透规则",
        "在路由器上新增一条 STUN 端口穿透规则，经 APP 二次确认后执行。",
        ["给 192.168.5.30 的 NAS 开一条 UDP 5001 的 STUN 穿透"],
        "relay.write", "write", "always",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 64},
                "serviceType": {"type": "string", "maxLength": 32},
                "transportProtocol": {"type": "string", "enum": ["TCP", "UDP"]},
                "targetIpv4": {"type": "string", "maxLength": 64},
                "targetPort": {"type": "integer"},
                "enabled": {"type": "boolean"},
            },
            "required": ["targetIpv4"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "relay.stun.rule.remove", "删除 STUN 穿透规则",
        "按 ID 或名称删除一条 STUN 穿透规则，并清理路由器侧映射与防火墙，经 APP 二次确认后执行。",
        ["删除 NAS 的 STUN 穿透规则"],
        "relay.write", "write", "always",
        {
            "type": "object",
            "properties": {"rule": {"type": "string", "maxLength": 128}},
            "required": ["rule"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "relay.agent.upgrade", "升级 LabRelay Agent",
        "向指定路由器下发 LabRelay Agent 升级指令（升级到更新仓最新版本），经 APP 二次确认后执行。",
        ["把路由器上的 Agent 升级到最新版"],
        "relay.write", "write", "always",
        {
            "type": "object",
            "properties": {"router": {"type": "string", "maxLength": 64}},
            "additionalProperties": False,
        },
    ),
    _spec(
        "router.status", "查询路由器状态",
        "查询路由器连接模式、在线设备数和数据更新时间。",
        ["路由器现在是什么模式", "路由器数据多久没更新了"],
        "router.read", "read", "none",
        {"type": "object", "properties": {}, "additionalProperties": False},
    ),
    _spec(
        "router.portmap.create", "创建端口映射",
        "创建一条 IPv6 端口映射规则（监听端口 20000-20020），经 APP 二次确认后执行。",
        ["给 NAS 创建一条 20001 到 5001 的端口映射"],
        "router.write", "write", "always",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 64},
                "listenPort": {"type": "integer"},
                "targetIpv4": {"type": "string", "maxLength": 64},
                "targetPort": {"type": "integer"},
                "transportProtocol": {"type": "string", "enum": ["TCP", "UDP"]},
                "mode": {"type": "string", "enum": ["6to4", "6to6"]},
                "serviceType": {"type": "string", "maxLength": 24},
            },
            "required": ["name", "listenPort", "targetIpv4", "targetPort"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "router.portmap.remove", "删除端口映射",
        "按 ID 或名称删除一条端口映射规则，经 APP 二次确认后执行。",
        ["删除 NAS 的端口映射"],
        "router.write", "write", "always",
        {
            "type": "object",
            "properties": {"rule": {"type": "string", "maxLength": 128}},
            "required": ["rule"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "router.portmap.toggle", "启用或停用端口映射",
        "按 ID 或名称启用或停用一条端口映射规则，经 APP 二次确认后执行。",
        ["停用 NAS 的端口映射", "重新启用 20001 的映射"],
        "router.write", "write", "always",
        {
            "type": "object",
            "properties": {
                "rule": {"type": "string", "maxLength": 128},
                "enabled": {"type": "boolean"},
            },
            "required": ["rule", "enabled"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "app.navigate", "打开 APP 页面",
        "让 APP 跳转到指定页面。理解近似说法：IPv6 设置、网络自检、NAT 诊断、端口映射、DDNS、STUN、WireGuard、WOL 等，映射到最接近的页面。",
        ["打开ipv6设置", "去网络自检", "看看NAT诊断", "打开端口映射"],
        "app.action", "read", "none",
        {
            "type": "object",
            "properties": {"route": {"type": "string", "enum": list(NAVIGATE_ROUTES)}},
            "required": ["route"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "app.refresh", "刷新 APP 数据",
        "触发 APP 执行一次完整数据校准同步。",
        ["刷新一下数据", "同步最新设备状态"],
        "app.action", "read", "none",
        {"type": "object", "properties": {}, "additionalProperties": False},
    ),
]


def _require_service(executor, attr: str):
    service = getattr(executor.hub, attr, None)
    if service is None:
        raise ToolError("该服务未启用", "SERVICE_UNAVAILABLE", 503)
    return service


def _rule_view(rule: Dict[str, Any], fields: tuple) -> Dict[str, Any]:
    return {key: rule.get(key) for key in fields if rule.get(key) not in (None, "")}


STUN_VIEW_FIELDS = ("id", "name", "listenPort", "targetIpv4", "targetPort", "transportProtocol", "serviceType", "enabled")
PORTMAP_VIEW_FIELDS = ("id", "name", "mode", "listenPort", "targetIpv4", "targetPort", "transportProtocol", "enabled", "updatedAt")


def _normalize_rule_text(value: Any) -> str:
    return "".join(str(value or "").lower().split())


def _resolve_rule(rows: List[Dict[str, Any]], needle: str, kind: str) -> Dict[str, Any]:
    query = _normalize_rule_text(needle)
    if not query:
        raise ToolError(f"请提供{kind}规则 ID 或名称", "RULE_REQUIRED")
    def keys(row: Dict[str, Any]) -> set:
        return {_normalize_rule_text(row.get("id")), _normalize_rule_text(row.get("name"))}
    matches = [row for row in rows if query in keys(row)]
    if not matches:
        matches = [row for row in rows if query in _normalize_rule_text(row.get("name"))]
    if not matches:
        raise ToolError(f"没有找到{kind}规则：{needle}", "RULE_NOT_FOUND", 404)
    if len(matches) > 1:
        names = [str(row.get("name") or row.get("id")) for row in matches[:5]]
        raise ToolError("规则名称不唯一，请提供规则 ID：" + "、".join(names), "RULE_AMBIGUOUS", 409)
    return matches[0]


def _stun_add(executor, args, client_context) -> Dict[str, Any]:
    service = _require_service(executor, "STUN_SERVICE")
    with service.lock:
        rule = service.clean_rule(dict(args))
        if rule.get("enabled") and service._is_native_forward(rule):
            mapping = service.ensure_native_mapping(rule)
            if (mapping or {}).get("state") != "ready":
                message = str((mapping or {}).get("message") or "").strip()
                raise ToolError(message or "路由器端口映射未就绪", "NATIVE_MAPPING_NOT_READY", 409)
        doc = service._document()
        saved = service._save_rules([*doc["rules"], rule])
        service.queue("upsert", {"rule": rule}, revision=saved["revision"])
    return {"ok": True, "rule": _rule_view(rule, STUN_VIEW_FIELDS), "revision": saved["revision"]}


def _stun_remove(executor, args, client_context) -> Dict[str, Any]:
    service = _require_service(executor, "STUN_SERVICE")
    with service.lock:
        doc = service._document()
        target = _resolve_rule(doc["rules"], args["rule"], "STUN 穿透")
        rule_id = str(target.get("id"))
        try:
            service.remove_native_mapping(rule_id)
            service.remove_firewall(rule_id)
        except Exception as error:
            raise ToolError(f"清理路由器侧配置失败：{error}", "CLEANUP_FAILED", 409)
        saved = service._save_rules([row for row in doc["rules"] if str(row.get("id")) != rule_id])
        service.queue("delete", {"id": rule_id}, revision=saved["revision"])
        history = service._history()
        if rule_id in history:
            history.pop(rule_id, None)
            service.hub.save_json(service.history_path, history)
    return {"ok": True, "deleted": True, "id": rule_id, "name": target.get("name")}


def _agent_upgrade(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    router = hub.resolve_agent_router(hub.clean_saved_value(args.get("router")) or hub.primary_router_name()) or "router"
    try:
        manifest = hub.agent_release_manifest(force=True)
    except Exception as error:
        raise ToolError(f"更新仓检查失败：{error}", "MANIFEST_UNAVAILABLE", 502)
    target = hub.clean_saved_value(manifest.get("versionName") or manifest.get("version"))
    command = {
        "id": secrets.token_hex(12), "router": router, "action": "update", "state": "pending",
        "targetVersion": target,
        "repositoryRoot": manifest.get("_repositoryRoot") or hub.UPDATE_REPOSITORY_ROOT,
        "manifestUrl": manifest.get("_manifestUrl") or hub.AGENT_MANIFEST_URL,
        "installerUrl": manifest.get("_installerUrl") or hub.AGENT_INSTALLER_URL,
        "createdAt": hub.now_str(), "updatedAt": hub.now_str(),
        "message": "等待路由器领取更新指令（AI 助手下发）",
    }
    data = hub.load_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": []})
    commands = data.get("commands", []) if isinstance(data, dict) else []
    commands.append(command)
    hub.save_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": commands[-100:]})
    hub.notify_agent_commands_changed()
    return {"ok": True, "commandId": command["id"], "router": router, "targetVersion": target,
            "message": "Rust Agent 更新指令已发送"}


def _router_status(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    document = hub.load_json(hub.STATE_FILE, {})
    router = document.get("router") if isinstance(document.get("router"), dict) else {}
    return {"router": router, "updatedAt": document.get("updatedAt")}


def _portmap_create(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    rule = hub._clean_portmap_rule(dict(args))
    rows = hub._load_portmap_rules()
    hub._portmap_check_conflict(rows, rule)
    rows.append(rule)
    hub._save_portmap_rules(rows)
    hub._queue_portmap_command("upsert", {"rule": rule})
    hub.add_event({"type": "portmap_created", "title": f"端口映射已创建（AI）：{rule['name']}",
                   "name": rule["name"], "newValue": f"IPv6:{rule['listenPort']}"})
    return {"ok": True, "rule": _rule_view(rule, PORTMAP_VIEW_FIELDS)}


def _portmap_remove(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    rows = hub._load_portmap_rules()
    target = _resolve_rule(rows, args["rule"], "端口映射")
    rule_id = target.get("id")
    hub._save_portmap_rules([row for row in rows if row.get("id") != rule_id])
    hub._queue_portmap_command("delete", {"id": rule_id})
    hub.add_event({"type": "portmap_deleted", "title": f"端口映射已删除（AI）：{target.get('name')}",
                   "name": target.get("name"), "oldValue": str(target.get("listenPort"))})
    return {"ok": True, "deleted": True, "id": rule_id, "name": target.get("name")}


def _portmap_toggle(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    rows = hub._load_portmap_rules()
    target = _resolve_rule(rows, args["rule"], "端口映射")
    enabled = bool(args["enabled"])
    rule = dict(target)
    rule_id = rule.get("id")
    if enabled:
        expires_at = hub._portmap_epoch(rule.get("expiresAt"))
        lease_seconds = max(0, hub.to_int(rule.get("leaseSeconds"), 0))
        now_epoch = int(time.time())
        # Same lease re-arm rule as the APP start action: an expired timed rule
        # restarts with the previously selected duration.
        if expires_at is not None and expires_at <= now_epoch:
            if lease_seconds <= 0:
                raise ToolError("旧规则缺少有效期时长，请在 APP 中编辑后重新选择有效期", "LEASE_REQUIRED", 400)
            rule["expiresAt"] = now_epoch + lease_seconds
    rule["enabled"] = enabled
    rule["updatedAt"] = hub.now_str()
    hub._save_portmap_rules([rule if row.get("id") == rule_id else row for row in rows])
    hub._queue_portmap_command("upsert" if enabled else "stop", {"rule": rule} if enabled else {"id": rule_id})
    return {"ok": True, "rule": _rule_view(rule, PORTMAP_VIEW_FIELDS), "action": "start" if enabled else "stop"}


def _app_navigate(executor, args, client_context) -> Dict[str, Any]:
    return {"clientAction": {"type": "navigate", "route": args["route"]}}


def _app_refresh(executor, args, client_context) -> Dict[str, Any]:
    return {"clientAction": {"type": "refresh", "scope": "full"}}


HANDLERS: Dict[str, Any] = {
    "relay.stun.rule.add": _stun_add,
    "relay.stun.rule.remove": _stun_remove,
    "relay.agent.upgrade": _agent_upgrade,
    "router.status": _router_status,
    "router.portmap.create": _portmap_create,
    "router.portmap.remove": _portmap_remove,
    "router.portmap.toggle": _portmap_toggle,
    "app.navigate": _app_navigate,
    "app.refresh": _app_refresh,
}


def _preview_stun_add(executor, args, client_context) -> Dict[str, Any]:
    protocol = str(args.get("transportProtocol") or "UDP").upper()
    target_port = args.get("targetPort")
    target = f"{args['targetIpv4']}:{target_port if target_port is not None else '默认端口'}"
    return {
        "toolId": "relay.stun.rule.add",
        "executor": "hub",
        "title": "确认新增 STUN 穿透",
        "summary": f"新增 {protocol} STUN 穿透规则：{target}",
        "arguments": args,
        "expiresInSeconds": 300,
    }


def _preview_stun_remove(executor, args, client_context) -> Dict[str, Any]:
    service = _require_service(executor, "STUN_SERVICE")
    doc = service._document()
    target = _resolve_rule(doc["rules"], args["rule"], "STUN 穿透")
    return {
        "toolId": "relay.stun.rule.remove",
        "executor": "hub",
        "title": "确认删除 STUN 穿透",
        "summary": f"删除 STUN 穿透规则：{target.get('name')}（{target.get('id')}）",
        "arguments": {"rule": str(target.get("id"))},
        "expiresInSeconds": 300,
    }


def _preview_agent_upgrade(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    router = hub.resolve_agent_router(hub.clean_saved_value(args.get("router")) or hub.primary_router_name()) or "router"
    try:
        manifest = hub.agent_release_manifest(force=True)
        target = hub.clean_saved_value(manifest.get("versionName") or manifest.get("version")) or "最新版"
    except Exception as error:
        raise ToolError(f"更新仓检查失败：{error}", "MANIFEST_UNAVAILABLE", 502)
    return {
        "toolId": "relay.agent.upgrade",
        "executor": "hub",
        "title": "确认升级 LabRelay Agent",
        "summary": f"将 {router} 上的 LabRelay Agent 升级到 {target}",
        "arguments": {"router": router},
        "expiresInSeconds": 300,
    }


def _preview_portmap_create(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    rule = hub._clean_portmap_rule(dict(args))
    hub._portmap_check_conflict(hub._load_portmap_rules(), rule)
    return {
        "toolId": "router.portmap.create",
        "executor": "hub",
        "title": "确认创建端口映射",
        "summary": f"创建端口映射：{rule['name']}（{rule['listenPort']} → {rule.get('targetIpv4')}:{rule.get('targetPort')}）",
        "arguments": args,
        "expiresInSeconds": 300,
    }


def _preview_portmap_remove(executor, args, client_context) -> Dict[str, Any]:
    rows = executor.hub._load_portmap_rules()
    target = _resolve_rule(rows, args["rule"], "端口映射")
    return {
        "toolId": "router.portmap.remove",
        "executor": "hub",
        "title": "确认删除端口映射",
        "summary": f"删除端口映射：{target.get('name')}（{target.get('id')}）",
        "arguments": {"rule": str(target.get("id"))},
        "expiresInSeconds": 300,
    }


def _preview_portmap_toggle(executor, args, client_context) -> Dict[str, Any]:
    rows = executor.hub._load_portmap_rules()
    target = _resolve_rule(rows, args["rule"], "端口映射")
    action = "启用" if args["enabled"] else "停用"
    return {
        "toolId": "router.portmap.toggle",
        "executor": "hub",
        "title": f"确认{action}端口映射",
        "summary": f"{action}端口映射：{target.get('name')}（{target.get('id')}）",
        "arguments": {"rule": str(target.get("id")), "enabled": bool(args["enabled"])},
        "expiresInSeconds": 300,
    }


PREVIEWS: Dict[str, Any] = {
    "relay.stun.rule.add": _preview_stun_add,
    "relay.stun.rule.remove": _preview_stun_remove,
    "relay.agent.upgrade": _preview_agent_upgrade,
    "router.portmap.create": _preview_portmap_create,
    "router.portmap.remove": _preview_portmap_remove,
    "router.portmap.toggle": _preview_portmap_toggle,
}


def register_builtin(executor) -> int:
    """Bind the built-in capability domains to a ToolExecutor (idempotent)."""
    registered = 0
    for spec in _SPECS:
        if catalog.tool_spec(spec["id"]) is None:
            catalog.register_tool(spec)
            registered += 1
    for tool_id, handler in HANDLERS.items():
        executor.register_handler(tool_id, handler)
    for tool_id, preview in PREVIEWS.items():
        executor.register_preview(tool_id, preview)
    return registered
