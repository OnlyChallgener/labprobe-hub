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
        "router.capabilities", "查询路由器能力",
        "查询 Router Core 当前是否已配置，以及路由器支持的状态、UPnP、防火墙、原生端口映射、DDNS 和诊断能力。",
        ["路由器支持哪些功能", "查看路由器能力"],
        "router.read", "read", "none",
        {"type": "object", "properties": {}, "additionalProperties": False},
    ),
    _spec(
        "router.upnp.get", "查询路由器 UPnP",
        "直接读取 Router Core 的 UPnP 开关、WAN 接口和动态映射规则。",
        ["查看路由器 UPnP 状态", "UPnP 开着吗"],
        "router.read", "read", "none",
        {"type": "object", "properties": {}, "additionalProperties": False},
    ),
    _spec(
        "router.upnp.set", "设置路由器 UPnP",
        "经二次确认后，通过 Router Core 启用或停用路由器 UPnP，并回读当前状态。",
        ["关闭路由器 UPnP", "在 WAN1 开启 UPnP"],
        "router.write", "write", "always",
        {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "wan": {"type": "string", "enum": ["WAN", "WAN1", "wan", "wan1"]},
            },
            "required": ["enabled", "wan"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "router.native_portmap.list", "查询路由器原生端口映射",
        "直接读取 Router Core 的路由器原生 IPv4/NAT 端口映射；它与 LabRelay IPv6 PortMap 规则不同。",
        ["查看路由器原生端口映射", "列出路由器 NAT 转发规则"],
        "router.read", "read", "none",
        {"type": "object", "properties": {}, "additionalProperties": False},
    ),
    _spec(
        "router.native_portmap.create", "创建路由器原生端口映射",
        "经二次确认后，通过 Router Core 创建一条路由器原生 IPv4/NAT 端口映射。",
        ["把公网 TCP 8443 转发到 192.168.5.30:443"],
        "router.write", "write", "always",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 64},
                "interface": {"type": "string", "enum": ["WAN", "WAN1", "wan", "wan1"]},
                "proto": {"type": "string", "enum": ["tcp", "udp", "TCP", "UDP"]},
                "extPort": {"type": "integer"},
                "intIp": {"type": "string", "maxLength": 64},
                "intPort": {"type": "integer"},
                "enabled": {"type": "boolean"},
            },
            "required": ["name", "interface", "proto", "extPort", "intIp", "intPort"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "router.native_portmap.remove", "删除路由器原生端口映射",
        "按名称删除一条路由器原生 IPv4/NAT 端口映射；确认卡会固定实际匹配的规则。",
        ["删除路由器上的 NAS-HTTPS 原生映射"],
        "router.write", "write", "always",
        {
            "type": "object",
            "properties": {"rule": {"type": "string", "maxLength": 128}},
            "required": ["rule"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "router.ddns.list", "查询路由器 DDNS",
        "直接读取 Router Core 的路由器 DDNS 服务状态；密码、令牌等敏感字段不会返回给模型。",
        ["查看路由器 DDNS", "路由器 DDNS 更新正常吗"],
        "router.read", "read", "none",
        {"type": "object", "properties": {}, "additionalProperties": False},
    ),
    _spec(
        "router.ipv6.inspect", "查询路由器 IPv6",
        "直接读取 Router Core 的 IPv6 状态、WAN/LAN 配置与 DHCPv6 客户端；不会修改 IPv6 配置。",
        ["查看路由器 IPv6 状态和配置", "列出 DHCPv6 客户端"],
        "router.read", "read", "none",
        {"type": "object", "properties": {}, "additionalProperties": False},
    ),
    _spec(
        "router.firewall.toggle", "启用或停用防火墙规则",
        "按 UUID 或名称匹配防火墙规则，经二次确认后通过 Router Core 启用或停用，并回读结果。",
        ["停用 Sun 防火墙规则", "启用指定 UUID 的防火墙规则"],
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
        "router.nat.diagnostic", "执行路由器 NAT 检测",
        "实际调用 Hub Router Core 在路由器上执行 NAT 检测，并返回任务进度或检测结果；这是检测操作，不会打开或跳转 APP 页面。",
        ["NAT检测", "执行路由器NAT检测", "检测当前NAT类型"],
        "router.read", "read", "none",
        {
            "type": "object",
            "properties": {
                "host": {"type": "string", "maxLength": 253},
                "port": {"type": "integer"},
                "interface": {"type": "string", "enum": ["wan", "wan1"]},
                "mode": {"type": "string", "enum": ["classic", "5780"]},
            },
            "additionalProperties": False,
        },
    ),
    _spec(
        "router.diagnostic", "执行路由器网络自检",
        "实际调用 Hub Router Core 在路由器上执行网络自检，并返回任务进度或自检结果；这是路由器自检，不会打开或跳转 APP 页面。",
        ["路由网络自检", "路由器自检", "路由设置-网络自检"],
        "router.read", "read", "none",
        {"type": "object", "properties": {}, "additionalProperties": False},
    ),
    _spec(
        "network.self_check", "执行 Hub 综合网络自检",
        "采集 Hub、路由器、Agent、端口映射、STUN 与 WireGuard 的当前状态并汇总；这是综合状态检查，不会启动路由器内置自检，也不会跳转 APP 页面。",
        ["网络自检", "检查一下当前网络状态"],
        "network.read", "read", "none",
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
        "仅当用户明确要求打开、进入或跳转页面时，让 APP 跳转到指定页面。网络自检、路由器自检和 NAT 检测属于实际检测操作，不使用本工具。",
        ["打开ipv6设置页面", "进入端口映射页面"],
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
        return {
            _normalize_rule_text(row.get("id")),
            _normalize_rule_text(row.get("uuid")),
            _normalize_rule_text(row.get("name")),
        }
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
    service = getattr(hub, "ROUTER_SERVICE", None)
    if service is not None and callable(getattr(service, "get_status", None)):
        try:
            return {"router": _router_data(service.get_status())}
        except Exception as error:
            raise _router_core_error(error, "ROUTER_STATUS_FAILED") from error
    document = hub.load_json(hub.STATE_FILE, {})
    router = document.get("router") if isinstance(document.get("router"), dict) else {}
    return {"router": router, "updatedAt": document.get("updatedAt")}


def _router_core(executor):
    return _require_service(executor, "ROUTER_SERVICE")


def _router_core_error(error: Exception, fallback_code: str) -> ToolError:
    return ToolError(
        str(error or "").strip() or "路由器操作失败",
        str(getattr(error, "code", "") or fallback_code),
        int(getattr(error, "status_code", 0) or 502),
    )


def _router_data(value: Any) -> Any:
    """Unwrap RouterService's public data envelope without changing it."""
    if isinstance(value, dict) and "data" in value:
        return value.get("data")
    return value


def _router_rows(value: Any, *keys: str) -> List[Dict[str, Any]]:
    data = _router_data(value)
    if isinstance(data, list):
        return [dict(row) for row in data if isinstance(row, dict)]
    if isinstance(data, dict):
        for key in keys:
            rows = data.get(key)
            if isinstance(rows, list):
                return [dict(row) for row in rows if isinstance(row, dict)]
    return []


def _required_bool(args: Dict[str, Any], key: str) -> bool:
    value = args.get(key)
    if not isinstance(value, bool):
        raise ToolError(f"参数 {key} 必须是布尔值", "INVALID_ARGUMENTS")
    return value


def _required_port(args: Dict[str, Any], key: str) -> int:
    value = args.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ToolError(f"参数 {key} 必须是 1-65535 的端口号", "INVALID_ARGUMENTS")
    return value


def _router_capabilities(executor, args, client_context) -> Dict[str, Any]:
    try:
        return {"capabilities": _router_data(_router_core(executor).get_capabilities())}
    except Exception as error:
        raise _router_core_error(error, "ROUTER_CAPABILITIES_FAILED") from error


def _router_upnp_get(executor, args, client_context) -> Dict[str, Any]:
    try:
        return {"upnp": _router_data(_router_core(executor).get_upnp(force=False))}
    except Exception as error:
        raise _router_core_error(error, "ROUTER_UPNP_READ_FAILED") from error


def _router_upnp_set(executor, args, client_context) -> Dict[str, Any]:
    enabled = _required_bool(args, "enabled")
    try:
        result = _router_core(executor).set_upnp(enabled, str(args["wan"]).upper())
    except Exception as error:
        raise _router_core_error(error, "ROUTER_UPNP_WRITE_FAILED") from error
    return {"ok": True, "upnp": _router_data(result)}


def _router_native_portmap_list(executor, args, client_context) -> Dict[str, Any]:
    try:
        result = _router_core(executor).get_port_mappings(force=False)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_PORTMAP_READ_FAILED") from error
    return {"rules": _router_rows(result, "rules", "list", "items")}


def _native_portmap_payload(args: Dict[str, Any]) -> Dict[str, Any]:
    enabled = args.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ToolError("参数 enabled 必须是布尔值", "INVALID_ARGUMENTS")
    return {
        "name": str(args["name"]).strip(),
        "interface": str(args["interface"]).upper(),
        "proto": str(args["proto"]).lower(),
        "extPort": _required_port(args, "extPort"),
        "intIp": str(args["intIp"]).strip(),
        "intPort": _required_port(args, "intPort"),
        "enabled": enabled,
    }


def _router_native_portmap_create(executor, args, client_context) -> Dict[str, Any]:
    rule = _native_portmap_payload(args)
    try:
        result = _router_core(executor).add_port_mapping(rule)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_PORTMAP_CREATE_FAILED") from error
    return {"ok": True, "rule": rule, "portMappings": _router_data(result)}


def _native_portmap_rules(executor) -> List[Dict[str, Any]]:
    try:
        result = _router_core(executor).get_port_mappings(force=False)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_PORTMAP_READ_FAILED") from error
    return _router_rows(result, "rules", "list", "items")


def _router_native_portmap_remove(executor, args, client_context) -> Dict[str, Any]:
    target = _resolve_rule(_native_portmap_rules(executor), args["rule"], "路由器原生端口映射")
    rule_name = str(target.get("name") or "").strip()
    if not rule_name:
        raise ToolError("原生端口映射缺少可删除的名称", "RULE_NAME_MISSING", 409)
    try:
        result = _router_core(executor).delete_port_mapping(rule_name)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_PORTMAP_DELETE_FAILED") from error
    return {"ok": True, "deleted": True, "name": rule_name, "portMappings": _router_data(result)}


def _router_ddns_list(executor, args, client_context) -> Dict[str, Any]:
    try:
        result = _router_core(executor).get_ddns(force=False)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_DDNS_READ_FAILED") from error
    return {"services": _router_rows(result, "services", "list", "items")}


def _router_ipv6_inspect(executor, args, client_context) -> Dict[str, Any]:
    service = _router_core(executor)
    try:
        status = _router_data(service.get_ipv6_status())
        config = _router_data(service.get_ipv6_config())
        clients = _router_rows(service.get_dhcpv6_clients(), "clients", "list", "items")
    except Exception as error:
        raise _router_core_error(error, "ROUTER_IPV6_READ_FAILED") from error
    return {"status": status, "config": config, "clients": clients}


def _firewall_rules(executor) -> List[Dict[str, Any]]:
    try:
        result = _router_core(executor).get_firewall(force=False)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_FIREWALL_READ_FAILED") from error
    return _router_rows(result, "rules", "list", "items")


def _router_firewall_list(executor, args, client_context) -> Dict[str, Any]:
    try:
        result = _router_core(executor).get_firewall(force=False)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_FIREWALL_READ_FAILED") from error
    data = _router_data(result)
    return {"firewall": data, "rules": _router_rows(result, "rules", "list", "items")}


def _router_firewall_toggle(executor, args, client_context) -> Dict[str, Any]:
    target = _resolve_rule(_firewall_rules(executor), args["rule"], "防火墙")
    uuid = str(target.get("uuid") or target.get("id") or "").strip()
    if not uuid:
        raise ToolError("防火墙规则缺少 UUID", "RULE_UUID_MISSING", 409)
    enabled = _required_bool(args, "enabled")
    try:
        result = _router_core(executor).set_firewall_rule_enabled(uuid, enabled)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_FIREWALL_WRITE_FAILED") from error
    return {"ok": True, "uuid": uuid, "enabled": enabled, "firewall": _router_data(result)}


def _router_task_error(error: Exception, fallback_code: str) -> ToolError:
    message = str(error or "").strip() or "路由器检测任务启动失败"
    return ToolError(
        message,
        str(getattr(error, "code", "") or fallback_code),
        int(getattr(error, "status_code", 0) or 502),
    )


def _router_nat_diagnostic(executor, args, client_context) -> Dict[str, Any]:
    manager = _require_service(executor, "ROUTER_TASK_MANAGER")
    try:
        task = manager.start_nat(dict(args))
    except Exception as error:
        raise _router_task_error(error, "NAT_DIAGNOSTIC_FAILED") from error
    return {
        "ok": True,
        "kind": "nat",
        "message": ("路由器 NAT 检测已启动，通常需要几十秒；完成后用户可追问“NAT诊断结果”获取最终类型"
                    if task.get("state") in {"queued", "running"} else "已取得路由器 NAT 检测结果"),
        "task": task,
    }


def _router_diagnostic(executor, args, client_context) -> Dict[str, Any]:
    manager = _require_service(executor, "ROUTER_TASK_MANAGER")
    try:
        task = manager.start_diagnostic()
    except Exception as error:
        raise _router_task_error(error, "ROUTER_DIAGNOSTIC_FAILED") from error
    return {
        "ok": True,
        "kind": "diagnostic",
        "message": ("路由器网络自检已启动，路由器执行约需十几秒；完成后用户可追问“路由器网络自检结果”查看明细"
                    if task.get("state") in {"queued", "running"} else "已取得路由器网络自检结果"),
        "task": task,
    }


def _network_self_check(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    status = hub.status_document() if callable(getattr(hub, "status_document", None)) else {}
    state = hub.load_json(hub.STATE_FILE, {}) if hasattr(hub, "STATE_FILE") else {}
    router = state.get("router") if isinstance(state, dict) and isinstance(state.get("router"), dict) else {}
    presence = hub.agent_presence_snapshot() if callable(getattr(hub, "agent_presence_snapshot", None)) else {}
    try:
        portmap_document, portmap_loaded = hub._load_portmap_rules_document()
        portmaps = portmap_document.get("rules") if isinstance(portmap_document, dict) else []
    except Exception:
        portmap_loaded, portmaps = False, []
    stun_service = getattr(hub, "STUN_SERVICE", None)
    try:
        stun_document = stun_service.rules_snapshot() if stun_service is not None else {}
        stun_rules = stun_document.get("rules") if isinstance(stun_document, dict) else []
    except Exception:
        stun_rules = []
    wireguard_service = getattr(hub, "WIREGUARD_SERVICE", None)
    try:
        wireguard = wireguard_service.document() if wireguard_service is not None else {}
    except Exception:
        wireguard = {}
    summary = {
        "router": router,
        "agent": presence,
        "portmapRules": len(portmaps or []) if portmap_loaded else None,
        "stunRules": len(stun_rules or []),
        "wireguardEnabled": bool((wireguard or {}).get("enabled")),
    }
    return {
        "ok": True,
        "kind": "network",
        "message": "Hub 综合网络状态已采集（非路由器内置自检）",
        "summary": summary,
        "hub": status,
    }


def _portmap_create(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    rule = hub._clean_portmap_rule(dict(args))
    rows = hub._load_portmap_rules()
    hub._portmap_check_conflict(rows, rule)
    rows.append(rule)
    hub._save_portmap_rules(rows)
    hub._queue_portmap_command("upsert", {"rule": rule}, reactivate=True)
    hub.add_event({"type": "portmap_created", "title": f"端口映射已创建（AI）：{rule['name']}",
                   "name": rule["name"], "newValue": f"IPv6:{rule['listenPort']}"})
    return {"ok": True, "rule": _rule_view(rule, PORTMAP_VIEW_FIELDS)}


def _portmap_remove(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    rows = hub._load_portmap_rules()
    target = _resolve_rule(rows, args["rule"], "端口映射")
    rule_id = target.get("id")
    hub._save_portmap_rules([row for row in rows if row.get("id") != rule_id])
    hub._queue_portmap_command("delete", {"id": rule_id}, reactivate=True)
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
    hub._queue_portmap_command(
        "upsert" if enabled else "stop",
        {"rule": rule} if enabled else {"id": rule_id},
        reactivate=True,
    )
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
    "router.capabilities": _router_capabilities,
    "router.upnp.get": _router_upnp_get,
    "router.upnp.set": _router_upnp_set,
    "router.native_portmap.list": _router_native_portmap_list,
    "router.native_portmap.create": _router_native_portmap_create,
    "router.native_portmap.remove": _router_native_portmap_remove,
    "router.ddns.list": _router_ddns_list,
    "router.ipv6.inspect": _router_ipv6_inspect,
    "router.firewall.toggle": _router_firewall_toggle,
    "router.firewall.list": _router_firewall_list,
    "router.nat.diagnostic": _router_nat_diagnostic,
    "router.diagnostic": _router_diagnostic,
    "network.self_check": _network_self_check,
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


def _preview_router_upnp_set(executor, args, client_context) -> Dict[str, Any]:
    enabled = _required_bool(args, "enabled")
    wan = str(args["wan"]).upper()
    return {
        "toolId": "router.upnp.set",
        "executor": "hub",
        "title": f"确认{'启用' if enabled else '停用'}路由器 UPnP",
        "summary": f"在 {wan} 上{'启用' if enabled else '停用'} UPnP",
        "arguments": {"enabled": enabled, "wan": wan},
        "expiresInSeconds": 300,
    }


def _preview_native_portmap_create(executor, args, client_context) -> Dict[str, Any]:
    rule = _native_portmap_payload(args)
    return {
        "toolId": "router.native_portmap.create",
        "executor": "hub",
        "title": "确认创建路由器原生端口映射",
        "summary": (
            f"创建 {rule['proto'].upper()} {rule['interface']}:{rule['extPort']} → "
            f"{rule['intIp']}:{rule['intPort']}（{rule['name']}）"
        ),
        "arguments": rule,
        "expiresInSeconds": 300,
    }


def _preview_native_portmap_remove(executor, args, client_context) -> Dict[str, Any]:
    target = _resolve_rule(_native_portmap_rules(executor), args["rule"], "路由器原生端口映射")
    rule_name = str(target.get("name") or "").strip()
    if not rule_name:
        raise ToolError("原生端口映射缺少可删除的名称", "RULE_NAME_MISSING", 409)
    return {
        "toolId": "router.native_portmap.remove",
        "executor": "hub",
        "title": "确认删除路由器原生端口映射",
        "summary": f"删除路由器原生端口映射：{rule_name}",
        "arguments": {"rule": rule_name},
        "expiresInSeconds": 300,
    }


def _preview_firewall_toggle(executor, args, client_context) -> Dict[str, Any]:
    target = _resolve_rule(_firewall_rules(executor), args["rule"], "防火墙")
    uuid = str(target.get("uuid") or target.get("id") or "").strip()
    if not uuid:
        raise ToolError("防火墙规则缺少 UUID", "RULE_UUID_MISSING", 409)
    enabled = _required_bool(args, "enabled")
    name = str(target.get("name") or uuid)
    return {
        "toolId": "router.firewall.toggle",
        "executor": "hub",
        "title": f"确认{'启用' if enabled else '停用'}防火墙规则",
        "summary": f"{'启用' if enabled else '停用'}防火墙规则：{name}（{uuid}）",
        "arguments": {"rule": uuid, "enabled": enabled},
        "expiresInSeconds": 300,
    }


PREVIEWS: Dict[str, Any] = {
    "relay.stun.rule.add": _preview_stun_add,
    "relay.stun.rule.remove": _preview_stun_remove,
    "relay.agent.upgrade": _preview_agent_upgrade,
    "router.portmap.create": _preview_portmap_create,
    "router.portmap.remove": _preview_portmap_remove,
    "router.portmap.toggle": _preview_portmap_toggle,
    "router.upnp.set": _preview_router_upnp_set,
    "router.native_portmap.create": _preview_native_portmap_create,
    "router.native_portmap.remove": _preview_native_portmap_remove,
    "router.firewall.toggle": _preview_firewall_toggle,
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
