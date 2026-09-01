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

import json
import secrets
import time
from typing import Any, Dict, List

from . import catalog
from .tools import ToolError

NAVIGATE_ROUTES = ("home", "devices", "router", "tools", "ai_chat", "favorites", "settings",
                   "stun", "wireguard", "ipv6", "portmap", "ddns", "nat", "wol", "tcp_peak")


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
        "agent.cleanup", "一键清理 Agent",
        "清理路由器上 Agent 的全部备份和非必要临时日志，不影响配置与映射规则，经 APP 二次确认后执行。",
        ["清理 agent", "一键清理路由器 Agent"],
        "relay.write", "write", "always",
        {
            "type": "object",
            "properties": {"router": {"type": "string", "maxLength": 64}},
            "additionalProperties": False,
        },
    ),
    _spec(
        "agent.cleanup.status", "查询 Agent 清理结果",
        "查询最近一次 Agent 一键清理任务的执行状态与释放空间。",
        ["清理完成了吗", "上次 Agent 清理释放了多少空间"],
        "relay.read", "read", "none",
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
        "router.firewall.rule.create", "新建防火墙规则",
        "经二次确认后在路由器上新建一条防火墙规则，支持转发/入站/出站方向、IPv4/IPv6、协议、"
        "允许/丢弃动作、源目的 IP 与 IPv6 后缀、源目的端口和入出接口。",
        ["新建一条转发规则放行 TCP 9443", "加一条 IPv6 防火墙规则允许 UDP 51820"],
        "router.write", "write", "always",
        {
            "type": "object",
            "properties": {
                "ruleName": {"type": "string", "maxLength": 24},
                "direction": {"type": "string", "enum": ["forward", "inbound", "outbound"]},
                "ipVersion": {"type": "string", "enum": ["ipv4", "ipv6", "dual"]},
                "proto": {"type": "string", "enum": ["tcp", "udp", "icmp", "any"]},
                "srcIP": {"type": "string", "maxLength": 80},
                "destIP": {"type": "string", "maxLength": 80},
                "srcPort": {"type": "string", "maxLength": 96},
                "destPort": {"type": "string", "maxLength": 96},
                "target": {"type": "string", "enum": ["ACCEPT", "DROP"]},
                "enabled": {"type": "boolean"},
                "ipv6SuffixSrc": {"type": "string", "maxLength": 80},
                "ipv6SuffixDest": {"type": "string", "maxLength": 80},
                "inIface": {"type": "string", "enum": ["wan", "lan"]},
                "outIface": {"type": "string", "enum": ["lan", "wan"]},
            },
            "required": ["ruleName"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "router.firewall.rule.update", "修改防火墙规则",
        "按 UUID 或名称匹配防火墙规则，经二次确认后修改其字段（端口、协议、动作、接口等）。",
        ["把 L3 规则的目的端口加上 9001", "把 Sun 规则改成丢弃"],
        "router.write", "write", "always",
        {
            "type": "object",
            "properties": {
                "rule": {"type": "string", "maxLength": 128},
                "ruleName": {"type": "string", "maxLength": 24},
                "direction": {"type": "string", "enum": ["forward", "inbound", "outbound"]},
                "ipVersion": {"type": "string", "enum": ["ipv4", "ipv6", "dual"]},
                "proto": {"type": "string", "enum": ["tcp", "udp", "icmp", "any"]},
                "srcIP": {"type": "string", "maxLength": 80},
                "destIP": {"type": "string", "maxLength": 80},
                "srcPort": {"type": "string", "maxLength": 96},
                "destPort": {"type": "string", "maxLength": 96},
                "target": {"type": "string", "enum": ["ACCEPT", "DROP"]},
                "enabled": {"type": "boolean"},
                "ipv6SuffixSrc": {"type": "string", "maxLength": 80},
                "ipv6SuffixDest": {"type": "string", "maxLength": 80},
                "inIface": {"type": "string", "enum": ["wan", "lan"]},
                "outIface": {"type": "string", "enum": ["lan", "wan"]},
            },
            "required": ["rule"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "router.firewall.rule.remove", "删除防火墙规则",
        "按 UUID 或名称删除一条防火墙规则；确认卡会固定实际匹配的规则。",
        ["删除防火墙里的 Drop 规则", "删除 UUID 开头是 fw-sun 的防火墙规则"],
        "router.write", "write", "always",
        {
            "type": "object",
            "properties": {"rule": {"type": "string", "maxLength": 128}},
            "required": ["rule"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "assistant.confirmations.list", "查询确认单状态",
        "查询最近的工具确认单及其真实状态（等待确认/已执行成功/执行失败/已过期未执行），"
        "用于核实历史确认请求是否真的执行过，而不是凭对话记忆断言。",
        ["之前让我确认的操作做了吗", "有哪些确认单还没处理"],
        "assistant.read", "read", "none",
        {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 20}},
            "additionalProperties": False,
        },
    ),
    _spec(
        "router.firmware.status", "查询固件版本快照",
        "查询最近一次路由器 Beta 固件检测结果（当前版本、可用版本与更新内容），不会发起新检测。"
        "用户问路由器固件/Beta 固件版本时使用本工具，不要回答 Agent 版本。",
        ["路由器固件是什么版本", "Beta 固件有更新吗"],
        "router.read", "read", "none",
        {"type": "object", "properties": {}, "additionalProperties": False},
    ),
    _spec(
        "router.firmware.check", "检测路由器固件更新",
        "实际向路由器发起一次 Beta 固件版本检测（约十几秒），返回当前版本、是否有更新与中文更新内容；"
        "这是检测操作，不会升级固件，也不会跳转 APP 页面。",
        ["检测固件更新", "路由器有新固件吗"],
        "router.read", "read", "none",
        {"type": "object", "properties": {}, "additionalProperties": False},
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
        "tcp.peak.status", "查询 TCP 峰值连接数测试",
        "查询本机 APP 或 Relay 最近一次 TCP 峰值连接数测试的状态与正式排版结果。",
        ["查询 Relay TCP 峰值连接数测试结果", "本机 TCP 连接测试完成了吗"],
        "tcp_peak.read", "read", "none",
        {
            "type": "object",
            "properties": {"side": {"type": "string", "enum": ["app", "relay"]}},
            "additionalProperties": False,
        },
    ),
    _spec(
        "tcp.peak.start", "启动 TCP 峰值连接数测试",
        "使用 APP 设置中的同类目标参数启动一次本机 APP 或 Relay 测试；Relay 目标作为一次性任务参数下发。",
        ["用 Relay 测试 example.com:443 的 IPv4 TCP 峰值连接数", "在本机分别测试 IPv4 和 IPv6 TCP 峰值连接数"],
        "tcp_peak.write", "write", "always",
        {
            "type": "object",
            "properties": {
                "side": {"type": "string", "enum": ["app", "relay"]},
                "host": {"type": "string", "minLength": 1, "maxLength": 253},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "family": {"type": "string", "enum": ["ipv4", "ipv6", "both"]},
                "targetConnections": {"type": "integer", "minimum": 1, "maximum": 65535},
                "cps": {"type": "integer", "minimum": 1, "maximum": 2000},
                "connectTimeoutMs": {"type": "integer", "minimum": 300, "maximum": 10000},
                "maxDurationSeconds": {"type": "integer", "minimum": 10, "maximum": 300},
            },
            "required": ["side", "host", "port", "family", "targetConnections", "cps"],
            "additionalProperties": False,
        },
    ),
    _spec(
        "tcp.peak.stop", "停止 TCP 峰值连接数测试",
        "停止 Relay 当前测试；Relay 会取消待建立连接、关闭全部测试连接并确认资源回落。本机测试在正式测试页停止。",
        ["停止当前 Relay TCP 峰值连接数测试"],
        "tcp_peak.write", "write", "always",
        {
            "type": "object",
            "properties": {
                "side": {"type": "string", "enum": ["relay"]},
                "taskId": {"type": "string", "maxLength": 80},
            },
            "required": ["side"],
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
    return {"ok": True, "rule": _rule_view(rule, STUN_VIEW_FIELDS), "revision": saved["revision"],
            "message": (f"已新增 STUN 穿透规则：{rule.get('name')}"
                        f"（{rule.get('transportProtocol')} {rule.get('targetIpv4')}:{rule.get('targetPort')}）")}


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
    return {"ok": True, "deleted": True, "id": rule_id, "name": target.get("name"),
            "message": f"已删除 STUN 穿透规则：{target.get('name')}"}


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


def _agent_cleanup(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    router = hub.resolve_agent_router(hub.clean_saved_value(args.get("router")) or hub.primary_router_name()) or "router"
    command = {
        "id": secrets.token_hex(12), "router": router, "action": "cleanup", "state": "pending",
        "createdAt": hub.now_str(), "updatedAt": hub.now_str(),
        "message": "等待路由器清理 Agent 备份和临时日志（AI 助手下发）",
        "result": {},
    }
    data = hub.load_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": []})
    commands = data.get("commands", []) if isinstance(data, dict) else []
    commands.append(command)
    hub.save_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": commands[-100:]})
    hub.notify_agent_commands_changed()
    return {"ok": True, "commandId": command["id"], "router": router,
            "message": "Agent 清理指令已发送，路由器将在领取后清理备份与非必要日志"}


def _agent_cleanup_status(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    router = hub.resolve_agent_router(hub.clean_saved_value(args.get("router")) or hub.primary_router_name()) or "router"
    command_id = hub.clean_saved_value(args.get("commandId"))
    lookup_by_id = getattr(hub, "agent_command_by_id", None)
    lookup_latest = getattr(hub, "latest_agent_command", None)
    if command_id and callable(lookup_by_id):
        command = lookup_by_id(command_id, router, "cleanup")
    elif callable(lookup_latest):
        command = lookup_latest(router, "cleanup")
    else:
        command = None
    if not isinstance(command, dict) or not command:
        return {"ok": False, "state": "missing", "message": "还没有发送过 Agent 清理指令"}
    result = command.get("result") if isinstance(command.get("result"), dict) else {}
    cleaned = result.get("cleanedItems") if isinstance(result.get("cleanedItems"), list) else []
    reclaimed = hub.clean_saved_value(result.get("reclaimedText")) or hub.to_int(result.get("reclaimedBytes"), 0)
    errors = result.get("errors") if isinstance(result.get("errors"), list) else []
    return {
        "ok": True,
        "state": str(command.get("state") or "pending"),
        "message": str(command.get("message") or ""),
        "cleanedItems": [str(item) for item in cleaned][:20],
        "reclaimed": str(reclaimed),
        "errors": [str(item) for item in errors][:10],
        "updatedAt": str(command.get("updatedAt") or ""),
    }


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
    wan = str(args["wan"]).upper()
    try:
        result = _router_core(executor).set_upnp(enabled, wan)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_UPNP_WRITE_FAILED") from error
    return {"ok": True, "upnp": _router_data(result),
            "message": f"已{'启用' if enabled else '停用'}路由器 UPnP（{wan}）"}


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
    return {"ok": True, "rule": rule, "portMappings": _router_data(result),
            "message": (f"已创建路由器原生端口映射：{rule['proto'].upper()} {rule['interface']}:{rule['extPort']}"
                        f" → {rule['intIp']}:{rule['intPort']}")}


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
    return {"ok": True, "deleted": True, "name": rule_name, "portMappings": _router_data(result),
            "message": f"已删除路由器原生端口映射：{rule_name}"}


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
    name = str(target.get("ruleName") or target.get("name") or uuid)
    return {"ok": True, "uuid": uuid, "enabled": enabled, "firewall": _router_data(result),
            "message": f"已{'启用' if enabled else '停用'}防火墙规则：{name}"}


FIREWALL_DIRECTION_ZH = {"forward": "转发", "inbound": "入站", "outbound": "出站"}
_FIREWALL_TEXT_FIELDS = ("ruleName", "srcIP", "destIP", "srcPort", "destPort",
                         "ipv6SuffixSrc", "ipv6SuffixDest")
_FIREWALL_ENUM_FIELDS = (("direction", "forward"), ("ipVersion", "ipv4"),
                         ("proto", "tcp"), ("target", "ACCEPT"))
_FIREWALL_MERGE_FIELDS = _FIREWALL_TEXT_FIELDS + tuple(field for field, _ in _FIREWALL_ENUM_FIELDS) + ("inIface", "outIface")
_FIREWALL_CREATE_DEFAULTS = {"direction": "forward", "ipVersion": "ipv4",
                             "proto": "tcp", "target": "ACCEPT", "inIface": "wan", "outIface": "lan"}


def _firewall_rule_payload(args: Dict[str, Any], base: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Merge assistant arguments into a Router Core firewall rule payload.

    Mirrors the APP editor: unset fields take the editor defaults on create,
    and switching direction clears the interface that direction ignores.
    """
    rule = dict(base or {})
    for key in _FIREWALL_TEXT_FIELDS:
        if key in args and args.get(key) is not None:
            rule[key] = str(args[key]).strip()
    for key, default in _FIREWALL_ENUM_FIELDS:
        if args.get(key) not in (None, ""):
            rule[key] = str(args[key]).strip()
        elif base is None:
            rule[key] = default
    for key in ("inIface", "outIface"):
        if args.get(key) not in (None, ""):
            rule[key] = str(args[key]).strip()
        elif base is None:
            rule[key] = _FIREWALL_CREATE_DEFAULTS[key]
    direction = str(rule.get("direction") or "forward").lower()
    if direction == "outbound" and args.get("inIface") in (None, ""):
        rule["inIface"] = ""
    elif direction == "inbound" and args.get("outIface") in (None, ""):
        rule["outIface"] = ""
    if str(rule.get("proto") or "tcp").lower() not in {"tcp", "udp"}:
        # APP clears hidden port inputs when switching to ICMP/any.
        rule["srcPort"] = ""
        rule["destPort"] = ""
    if base is None:
        rule["enable"] = "0" if args.get("enabled") is False else "1"
    elif args.get("enabled") is not None:
        rule["enable"] = "0" if not args["enabled"] else "1"
    return rule


def _firewall_rule_summary(rule: Dict[str, Any]) -> str:
    direction = FIREWALL_DIRECTION_ZH.get(str(rule.get("direction") or "forward").lower(),
                                         str(rule.get("direction") or "forward"))
    version = "IPv6" if str(rule.get("ipVersion") or "ipv4").lower() == "ipv6" else "IPv4"
    proto = str(rule.get("proto") or "tcp").upper()
    action = "允许" if str(rule.get("target") or "ACCEPT").upper() == "ACCEPT" else "丢弃"
    ports = str(rule.get("destPort") or "任意端口")
    src = f"源 {rule['srcIP']} " if rule.get("srcIP") else ""
    dest = f"目的 {rule['destIP']} " if rule.get("destIP") else ""
    return f"{direction} · {version} · {proto} · {src}{dest}目的端口 {ports} · {action}"


def _firewall_rule_uuid(target: Dict[str, Any]) -> str:
    uuid_value = str(target.get("uuid") or target.get("id") or "").strip()
    if not uuid_value:
        raise ToolError("防火墙规则缺少 UUID", "RULE_UUID_MISSING", 409)
    return uuid_value


def _router_firewall_rule_create(executor, args, client_context) -> Dict[str, Any]:
    rule = _firewall_rule_payload(dict(args))
    try:
        result = _router_core(executor).add_firewall_rule(rule)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_FIREWALL_CREATE_FAILED") from error
    return {"ok": True, "rule": rule, "firewall": _router_data(result),
            "message": (f"已创建防火墙规则：{rule.get('ruleName')}（{_firewall_rule_summary(rule)}）")}


def _router_firewall_rule_update(executor, args, client_context) -> Dict[str, Any]:
    target = _resolve_rule(_firewall_rules(executor), args["rule"], "防火墙")
    uuid_value = _firewall_rule_uuid(target)
    # Router Core update follows the APP's full-editor submission contract.
    # Keep the whitelist, but include legal empty fields instead of silently
    # changing a clear operation into a partial update.
    base = {key: str(target.get(key) or "") for key in _FIREWALL_TEXT_FIELDS}
    for key, default in _FIREWALL_ENUM_FIELDS:
        base[key] = str(target.get(key) or default)
    for key in ("inIface", "outIface"):
        base[key] = str(target.get(key) if target.get(key) is not None else _FIREWALL_CREATE_DEFAULTS[key])
    fallback_name = target.get("ruleName") or target.get("name")
    if fallback_name:
        base["ruleName"] = str(fallback_name)
    existing_enable = target.get("enable", target.get("enabled"))
    rule = _firewall_rule_payload(dict(args), base=base)
    if "enable" not in rule and existing_enable is not None:
        rule["enable"] = "0" if str(existing_enable).lower() in ("0", "false") else "1"
    rule.pop("uuid", None)
    try:
        result = _router_core(executor).update_firewall_rule(uuid_value, rule)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_FIREWALL_UPDATE_FAILED") from error
    name = str(rule.get("ruleName") or target.get("ruleName") or target.get("name") or uuid_value)
    return {"ok": True, "uuid": uuid_value, "rule": rule, "firewall": _router_data(result),
            "message": f"已修改防火墙规则：{name}"}


def _router_firewall_rule_remove(executor, args, client_context) -> Dict[str, Any]:
    target = _resolve_rule(_firewall_rules(executor), args["rule"], "防火墙")
    uuid_value = _firewall_rule_uuid(target)
    name = str(target.get("ruleName") or target.get("name") or uuid_value)
    try:
        result = _router_core(executor).delete_firewall_rule(uuid_value)
    except Exception as error:
        raise _router_core_error(error, "ROUTER_FIREWALL_DELETE_FAILED") from error
    return {"ok": True, "deleted": True, "uuid": uuid_value, "name": name, "firewall": _router_data(result),
            "message": f"已删除防火墙规则：{name}"}


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


def _wait_task_snapshot(manager: Any, kind: str, timeout_seconds: float = 40.0) -> Dict[str, Any] | None:
    """Poll a router task to its terminal state inside the request window."""
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    last: Dict[str, Any] | None = None
    while True:
        try:
            snapshot = manager.snapshot(kind)
        except Exception:
            snapshot = None
        if isinstance(snapshot, dict):
            last = snapshot
            if str(snapshot.get("state") or "") not in {"", "idle", "queued", "running"}:
                return last
        if time.monotonic() >= deadline:
            return last
        time.sleep(1.5)


def _beta_releases(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    next_data = result.get("new") if isinstance(result.get("new"), dict) else {}
    raw = next_data.get("firmwareList")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = None
    items: List[Any] = []
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = [
            {**value, "version": str(key)} if isinstance(value, dict) else {"version": str(key)}
            for key, value in raw.items()
        ]
    releases: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, str):
            releases.append({"version": item.strip(), "notes": [], "size": 0, "downloadUrl": ""})
            continue
        if not isinstance(item, dict):
            continue
        version = str(item.get("version") or item.get("versionCode") or "").strip()
        if not version:
            continue
        notes_value = item.get("releaseNotes") or item.get("release_notes") or item.get("notes")
        if isinstance(notes_value, list):
            notes = [str(note).strip() for note in notes_value if str(note).strip()]
        elif isinstance(notes_value, str) and notes_value.strip():
            notes = [line.strip() for line in notes_value.splitlines() if line.strip()]
        else:
            notes = []
        try:
            size = int(item.get("size") or item.get("sizeBytes") or 0)
        except (TypeError, ValueError):
            size = 0
        releases.append({
            "version": version,
            "notes": notes,
            "size": size,
            "downloadUrl": str(item.get("downloadUrl") or "").strip(),
        })
    return releases


def _firmware_size_text(size: int) -> str:
    if size <= 0:
        return ""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return ""


def firmware_check_content(task: Dict[str, Any]) -> str:
    """Format a beta-check task snapshot into readable Chinese (never JSON)."""
    state = str(task.get("state") or "")
    result = task.get("result") if isinstance(task.get("result"), dict) else {}
    if state in {"", "idle", "queued", "running"}:
        return "路由器 Beta 固件检测进行中。完成后回复「固件检测结果」，我会把版本与更新内容整理给你。"
    if state == "timed_out":
        return "路由器 Beta 固件检测超时：路由器长时间未返回版本信息，可稍后重试。"
    if state == "failed":
        return "路由器 Beta 固件检测失败：" + str(task.get("message") or "未知错误")
    current = str(result.get("cur") or "").strip() or "未知"
    releases = _beta_releases(result)
    next_data = result.get("new") if isinstance(result.get("new"), dict) else {}
    message = str(next_data.get("msg") or task.get("message") or "").strip()
    lines = ["路由器 Beta 固件检测结果：", f"• 当前版本：{current}"]
    if not releases:
        lines.append("• 检测结果：已是最新版本" + (f"（{message}）" if message else ""))
    else:
        lines.append(f"• 发现 {len(releases)} 个可更新版本：")
        for index, release in enumerate(releases, start=1):
            head = f"{index}. {release['version']}"
            size_text = _firmware_size_text(int(release.get("size") or 0))
            if size_text:
                head += f"（{size_text}）"
            lines.append(head)
            for note in release.get("notes") or []:
                lines.append(f"   更新内容：{note}")
            download = str(release.get("downloadUrl") or "")
            if download:
                lines.append(f"   下载地址：{download}")
    if message and releases:
        lines.append(f"• 路由器备注：{message}")
    lines.append("固件升级会重启路由器并短暂断网。升级请到 APP「路由设置 → Beta 在线升级」页面按提示手动进行，我目前只能检测、不能替你执行升级。")
    return "\n".join(lines)


def _router_firmware_status(executor, args, client_context) -> Dict[str, Any]:
    manager = _require_service(executor, "ROUTER_TASK_MANAGER")
    try:
        snapshot = manager.snapshot("beta")
    except Exception as error:
        raise _router_task_error(error, "ROUTER_FIRMWARE_STATUS_FAILED") from error
    task = snapshot if isinstance(snapshot, dict) else {}
    has_snapshot = bool(task.get("result")) or str(task.get("state") or "") not in {"", "idle"}
    return {
        "ok": True,
        "kind": "beta",
        "message": ("还没有检测过路由器 Beta 固件版本；说「检测固件更新」可以现在查一次"
                    if not has_snapshot else "这是最近一次 Beta 固件检测结果。"),
        "content": firmware_check_content(task),
        "task": task,
    }


def _router_firmware_check(executor, args, client_context) -> Dict[str, Any]:
    manager = _require_service(executor, "ROUTER_TASK_MANAGER")
    try:
        task = manager.start_beta()
    except Exception as error:
        raise _router_task_error(error, "ROUTER_FIRMWARE_CHECK_FAILED") from error
    snapshot = _wait_task_snapshot(manager, "beta", 40.0) or task
    state = str((snapshot or {}).get("state") or "")
    return {
        "ok": True,
        "kind": "beta",
        "message": ("路由器 Beta 固件检测已启动，通常十几秒内完成；完成后回复「固件检测结果」查看明细"
                    if state in {"", "idle", "queued", "running"} else "路由器 Beta 固件检测完成。"),
        "content": firmware_check_content(snapshot or {}),
        "task": snapshot,
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
    hub_info = status.get("hub") if isinstance(status.get("hub"), dict) else {}
    vpn_addresses = status.get("vpnStunAddresses") if isinstance(status.get("vpnStunAddresses"), list) else []
    summary = {
        "router": router,
        "agent": presence,
        "hub": {
            "name": hub_info.get("name"),
            "version": hub_info.get("version"),
            "advertiseUrl": hub_info.get("advertiseUrl"),
            "updatedAt": hub_info.get("updatedAt"),
        },
        "exitIpv4": router.get("exitIpv4"),
        "exitIpv6": router.get("exitIpv6") or status.get("router", {}).get("exitIpv6") if isinstance(status.get("router"), dict) else router.get("exitIpv6"),
        "vpnAddressCount": len(vpn_addresses),
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
    return {"ok": True, "rule": _rule_view(rule, PORTMAP_VIEW_FIELDS),
            "message": (f"已创建端口映射：{rule['name']}"
                        f"（{rule['listenPort']} → {rule.get('targetIpv4')}:{rule.get('targetPort')}）")}


def _portmap_remove(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    rows = hub._load_portmap_rules()
    target = _resolve_rule(rows, args["rule"], "端口映射")
    rule_id = target.get("id")
    hub._save_portmap_rules([row for row in rows if row.get("id") != rule_id])
    hub._queue_portmap_command("delete", {"id": rule_id}, reactivate=True)
    hub.add_event({"type": "portmap_deleted", "title": f"端口映射已删除（AI）：{target.get('name')}",
                   "name": target.get("name"), "oldValue": str(target.get("listenPort"))})
    return {"ok": True, "deleted": True, "id": rule_id, "name": target.get("name"),
            "message": f"已删除端口映射：{target.get('name')}"}


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
    return {"ok": True, "rule": _rule_view(rule, PORTMAP_VIEW_FIELDS), "action": "start" if enabled else "stop",
            "message": f"已{'启用' if enabled else '停用'}端口映射：{target.get('name')}"}


def _tcp_peak_content(task: Dict[str, Any], side: str) -> str:
    if not task:
        return f"{'本机 APP' if side == 'app' else 'Relay'} 还没有 TCP 峰值连接数测试记录。"
    lines = [
        f"【{'本机 APP' if side == 'app' else 'Relay'} TCP 峰值连接数】",
        f"• 状态：{task.get('status') or task.get('state') or '未知'}",
    ]
    for family, label in (("ipv4", "IPv4"), ("ipv6", "IPv6")):
        metric = task.get(family) if isinstance(task.get(family), dict) else {}
        lines.append(
            f"• {label}：当前 {int(metric.get('current') or 0)}，峰值 {int(metric.get('peak') or 0)}，"
            f"成功 {int(metric.get('success') or 0)}，失败 {int(metric.get('failure') or 0)}，"
            f"CPS {int(metric.get('cps') or 0)}，耗时 {int(metric.get('elapsedMs') or 0) / 1000:.1f} 秒"
        )
    reason = str(task.get("finishReason") or "").strip()
    if reason:
        lines.append(f"• 结束原因：{reason}")
    if side == "relay":
        lines.append(
            f"• 资源：Conntrack 峰值 {int(task.get('conntrackPeak') or 0)}，"
            f"CPU 峰值 {float(task.get('cpuPeak') or 0):.1f}%，"
            f"最低可用内存 {int(task.get('memoryMinAvailableMb') or 0)} MB"
        )
    released = task.get("resourcesReleased")
    if isinstance(released, bool):
        lines.append(f"• 资源释放：{'已完成' if released else '尚未确认'}（{task.get('releaseStatus') or '无说明'}）")
    return "\n".join(lines)


def _tcp_peak_status(executor, args, client_context) -> Dict[str, Any]:
    side = str(args.get("side") or "relay")
    if side == "app":
        task = executor._client_context(client_context).get("tcpPeak") or {}
    else:
        task = _require_service(executor, "TCP_SESSION_SERVICE").snapshot()
    return {
        "ok": True,
        "side": side,
        "task": task,
        "content": _tcp_peak_content(task, side),
        "message": _tcp_peak_content(task, side),
    }


def _tcp_peak_start(executor, args, client_context) -> Dict[str, Any]:
    if args.get("side") != "relay":
        raise ToolError("本机测试必须由 APP 执行", "CLIENT_EXECUTION_REQUIRED", 409)
    service = _require_service(executor, "TCP_SESSION_SERVICE")
    try:
        task = service.start({key: value for key, value in args.items() if key != "side"})
    except ValueError as error:
        raise ToolError(str(error), "INVALID_ARGUMENTS", 400) from error
    except RuntimeError as error:
        raise ToolError(str(error), "TCP_TEST_CONFLICT", 409) from error
    return {"ok": True, "task": task, "message": "Relay TCP 峰值连接数测试任务已提交"}


def _tcp_peak_stop(executor, args, client_context) -> Dict[str, Any]:
    if args.get("side") != "relay":
        raise ToolError("本机测试必须由 APP 执行", "CLIENT_EXECUTION_REQUIRED", 409)
    service = _require_service(executor, "TCP_SESSION_SERVICE")
    try:
        task = service.stop(str(args.get("taskId") or ""))
    except RuntimeError as error:
        raise ToolError(str(error), "TCP_TEST_CONFLICT", 409) from error
    return {"ok": True, "task": task, "message": "已通知 Relay 停止测试并释放连接"}


def _assistant_confirmations_list(executor, args, client_context) -> Dict[str, Any]:
    store = getattr(executor.hub, "ASSISTANT_AI_STORE", None)
    if store is None:
        raise ToolError("确认单存储未就绪", "SERVICE_UNAVAILABLE", 503)
    try:
        limit = int(args.get("limit") or 10)
    except (TypeError, ValueError):
        limit = 10
    items: List[Dict[str, Any]] = []
    for row in store.list_recent_confirmations(limit=limit):
        spec = catalog.tool_spec(str(row.get("tool_id") or ""))
        status = str(row.get("status") or "")
        if row.get("expired"):
            state = "已过期未执行"
        elif status == "pending":
            state = "等待确认"
        elif status == "executing":
            state = "执行中"
        elif status == "completed":
            state = "已确认执行成功"
        elif status == "failed":
            state = "已确认但执行失败"
        else:
            state = status or "未知"
        item: Dict[str, Any] = {
            "id": str(row.get("id") or "")[:8],
            "tool": spec["name"] if spec else str(row.get("tool_id") or ""),
            "state": state,
            "createdAt": str(row.get("created_at") or ""),
            "expiresAt": str(row.get("expires_at") or ""),
        }
        raw_result = row.get("result_json")
        if raw_result:
            try:
                parsed = json.loads(raw_result)
                message = parsed.get("message") if isinstance(parsed, dict) else ""
                if message:
                    item["result"] = str(message)[:160]
            except ValueError:
                pass
        items.append(item)
    return {"ok": True, "confirmations": items,
            "message": (f"最近 {len(items)} 条确认单" if items else "没有任何确认单记录")}


def _app_navigate(executor, args, client_context) -> Dict[str, Any]:
    return {"clientAction": {"type": "navigate", "route": args["route"]}}


def _app_refresh(executor, args, client_context) -> Dict[str, Any]:
    return {"clientAction": {"type": "refresh", "scope": "full"}}


HANDLERS: Dict[str, Any] = {
    "assistant.confirmations.list": _assistant_confirmations_list,
    "relay.stun.rule.add": _stun_add,
    "relay.stun.rule.remove": _stun_remove,
    "relay.agent.upgrade": _agent_upgrade,
    "agent.cleanup": _agent_cleanup,
    "agent.cleanup.status": _agent_cleanup_status,
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
    "router.firewall.rule.create": _router_firewall_rule_create,
    "router.firewall.rule.update": _router_firewall_rule_update,
    "router.firewall.rule.remove": _router_firewall_rule_remove,
    "router.firewall.list": _router_firewall_list,
    "router.nat.diagnostic": _router_nat_diagnostic,
    "router.diagnostic": _router_diagnostic,
    "router.firmware.status": _router_firmware_status,
    "router.firmware.check": _router_firmware_check,
    "network.self_check": _network_self_check,
    "router.portmap.create": _portmap_create,
    "router.portmap.remove": _portmap_remove,
    "router.portmap.toggle": _portmap_toggle,
    "tcp.peak.status": _tcp_peak_status,
    "tcp.peak.start": _tcp_peak_start,
    "tcp.peak.stop": _tcp_peak_stop,
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


def _preview_agent_cleanup(executor, args, client_context) -> Dict[str, Any]:
    hub = executor.hub
    router = hub.resolve_agent_router(hub.clean_saved_value(args.get("router")) or hub.primary_router_name()) or "router"
    return {
        "toolId": "agent.cleanup",
        "executor": "hub",
        "title": "确认一键清理 Agent",
        "summary": f"清理 {router} 上 Agent 的全部备份和非必要临时日志（不影响配置与映射规则）",
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


def _preview_tcp_peak_start(executor, args, client_context) -> Dict[str, Any]:
    service = _require_service(executor, "TCP_SESSION_SERVICE")
    try:
        config = service._config({key: value for key, value in args.items() if key != "side"})
    except ValueError as error:
        raise ToolError(str(error), "INVALID_ARGUMENTS", 400) from error
    side = str(args["side"])
    canonical = {"side": side, **config}
    side_label = "本机 APP" if side == "app" else "Relay"
    family_label = {"ipv4": "IPv4", "ipv6": "IPv6", "both": "IPv4/IPv6 分别"}[config["family"]]
    return {
        "toolId": "tcp.peak.start",
        "executor": "app" if side == "app" else "hub",
        "title": f"确认启动{side_label} TCP 峰值连接数测试",
        "summary": (
            f"由{side_label}测试 {config['host']}:{config['port']}，{family_label}，"
            f"量程上限 {config['targetConnections']}，目标 CPS {config['cps']}"
        ),
        "arguments": canonical,
        "expiresInSeconds": 300,
    }


def _preview_tcp_peak_stop(executor, args, client_context) -> Dict[str, Any]:
    side = str(args["side"])
    if side == "app":
        task = executor._client_context(client_context).get("tcpPeak") or {}
    else:
        task = _require_service(executor, "TCP_SESSION_SERVICE").snapshot()
    task_id = str(task.get("taskId") or task.get("id") or "").strip()
    requested_id = str(args.get("taskId") or "").strip()
    if not task_id or str(task.get("state") or "") not in {
        "queued", "accepted", "running", "stop_requested", "releasing",
    }:
        raise ToolError("当前没有正在运行的 TCP 峰值连接数测试", "TCP_TEST_NOT_ACTIVE", 409)
    if requested_id and requested_id != task_id:
        raise ToolError("测试任务已经变化，请刷新后重新确认", "TCP_TEST_CONFLICT", 409)
    side_label = "本机 APP" if side == "app" else "Relay"
    return {
        "toolId": "tcp.peak.stop",
        "executor": "app" if side == "app" else "hub",
        "title": f"确认停止{side_label}测试",
        "summary": f"停止{side_label} TCP 峰值连接数测试，并释放全部测试连接（任务 {task_id}）",
        "arguments": {"side": side, "taskId": task_id},
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


def _preview_firewall_rule_create(executor, args, client_context) -> Dict[str, Any]:
    rule = _firewall_rule_payload(dict(args))
    return {
        "toolId": "router.firewall.rule.create",
        "executor": "hub",
        "title": "确认新建防火墙规则",
        "summary": f"新建防火墙规则：{rule.get('ruleName')}（{_firewall_rule_summary(rule)}）",
        "arguments": dict(args),
        "expiresInSeconds": 300,
    }


def _preview_firewall_rule_update(executor, args, client_context) -> Dict[str, Any]:
    target = _resolve_rule(_firewall_rules(executor), args["rule"], "防火墙")
    uuid_value = _firewall_rule_uuid(target)
    changed = {key: args[key] for key in _FIREWALL_MERGE_FIELDS if key in args and key != "rule"}
    if args.get("enabled") is not None:
        changed["enabled"] = args["enabled"]
    pinned = {"rule": uuid_value}
    pinned.update({key: value for key, value in args.items() if key != "rule"})
    name = str(target.get("ruleName") or target.get("name") or uuid_value)
    change_text = "、".join(f"{key}={value}" for key, value in changed.items()) or "无字段变更"
    return {
        "toolId": "router.firewall.rule.update",
        "executor": "hub",
        "title": "确认修改防火墙规则",
        "summary": f"修改防火墙规则：{name}（{change_text}）",
        "arguments": pinned,
        "expiresInSeconds": 300,
    }


def _preview_firewall_rule_remove(executor, args, client_context) -> Dict[str, Any]:
    target = _resolve_rule(_firewall_rules(executor), args["rule"], "防火墙")
    uuid_value = _firewall_rule_uuid(target)
    name = str(target.get("ruleName") or target.get("name") or uuid_value)
    return {
        "toolId": "router.firewall.rule.remove",
        "executor": "hub",
        "title": "确认删除防火墙规则",
        "summary": f"删除防火墙规则：{name}（{uuid_value}）",
        "arguments": {"rule": uuid_value},
        "expiresInSeconds": 300,
    }


PREVIEWS: Dict[str, Any] = {
    "relay.stun.rule.add": _preview_stun_add,
    "relay.stun.rule.remove": _preview_stun_remove,
    "relay.agent.upgrade": _preview_agent_upgrade,
    "agent.cleanup": _preview_agent_cleanup,
    "router.portmap.create": _preview_portmap_create,
    "router.portmap.remove": _preview_portmap_remove,
    "router.portmap.toggle": _preview_portmap_toggle,
    "tcp.peak.start": _preview_tcp_peak_start,
    "tcp.peak.stop": _preview_tcp_peak_stop,
    "router.upnp.set": _preview_router_upnp_set,
    "router.native_portmap.create": _preview_native_portmap_create,
    "router.native_portmap.remove": _preview_native_portmap_remove,
    "router.firewall.toggle": _preview_firewall_toggle,
    "router.firewall.rule.create": _preview_firewall_rule_create,
    "router.firewall.rule.update": _preview_firewall_rule_update,
    "router.firewall.rule.remove": _preview_firewall_rule_remove,
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
