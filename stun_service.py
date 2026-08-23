"""Small STUN control-plane for LabProbe Relay.

TCP follows Lucky's native-forwarding path: Hub creates one stable router
port-map (channel port -> selected LAN service) and the Agent uses that same
channel port only for STUN keepalive/address discovery.  A changing STUN
public endpoint never changes the router port-map.  UDP remains a relay proxy
because Lucky does not support disabling its built-in UDP forwarder.

All router writes use the Hub's eWeb controller; this module never calls
router iptables directly.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from flask import Blueprint, jsonify, request

import router_rpc


SERVICE_TEMPLATES = {
    "HTTPS": (443, {"TCP"}, "TCP"),
    "HTTP": (80, {"TCP"}, "TCP"),
    "SSH": (22, {"TCP"}, "TCP"),
    "RDP": (3389, {"TCP"}, "TCP"),
    "Telnet": (23, {"TCP"}, "TCP"),
    "OpenVPN": (1194, {"TCP", "UDP"}, "UDP"),
    "DNS": (53, {"TCP", "UDP"}, "UDP"),
    "WireGuard": (51820, {"UDP"}, "UDP"),
    "Custom": (None, {"TCP", "UDP"}, "TCP"),
}

# Cloudflare publishes its free STUN endpoint for UDP only. A TCP rule must
# use a server that explicitly accepts STUN Binding requests over TCP.
DEFAULT_STUN_UDP_SERVER = "stun.cloudflare.com:3478"
DEFAULT_STUN_TCP_SERVER = "stunserver2025.stunprotocol.org:3478"
LEGACY_TCP_STUN_SERVER = DEFAULT_STUN_UDP_SERVER


def _text(value: Any) -> str:
    return str(value or "").strip()


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _now() -> int:
    return int(time.time())


def _now_text() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _stun_server(protocol: str) -> str:
    protocol = _text(protocol).upper()
    configured = _text(os.environ.get(f"STUN_{protocol}_SERVER"))
    if configured:
        return configured
    return DEFAULT_STUN_TCP_SERVER if protocol == "TCP" else DEFAULT_STUN_UDP_SERVER


def _rule_fingerprint(row: Dict[str, Any]) -> str:
    data = {str(key): value for key, value in row.items() if str(key) not in {"stats", "uuid"}}
    return hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class StunService:
    def __init__(self, hub: Any, client: Any):
        self.hub = hub
        self.client = client
        self.controller = router_rpc.RouterController(client)
        self.lock = threading.RLock()
        self.rules_path = Path(hub.DATA_DIR) / "stun_rules.json"
        self.commands_path = Path(hub.DATA_DIR) / "stun_commands.json"
        self.status_path = Path(hub.DATA_DIR) / "stun_router_status.json"
        self.history_path = Path(hub.DATA_DIR) / "stun_address_history.json"
        self.firewall_path = Path(hub.DATA_DIR) / "stun_firewall.json"
        self.native_mapping_path = Path(hub.DATA_DIR) / "stun_native_portmap.json"
        self._migrate_legacy_tcp_server()

    def _document(self) -> Dict[str, Any]:
        raw = self.hub.load_json(self.rules_path, {"revision": 0, "rules": []})
        if not isinstance(raw, dict):
            raw = {}
        return {
            "revision": _int(raw.get("revision")),
            "updatedAt": _text(raw.get("updatedAt")),
            "rules": [dict(row) for row in raw.get("rules", []) if isinstance(row, dict)],
        }

    def _save_rules(self, rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        previous = self._document()
        document = {
            "revision": previous["revision"] + 1,
            "updatedAt": _now_text(),
            "rules": [dict(row) for row in rows],
        }
        self.hub.save_json(self.rules_path, document)
        return document

    def _migrate_legacy_tcp_server(self) -> None:
        """Repair saved STUN rules and queue the corrected rule for Agent."""
        document = self._document()
        migrated = []
        changed = False
        for raw in document["rules"]:
            rule = dict(raw)
            if _text(rule.get("kind")).lower() == "stun":
                protocol = _text(rule.get("transportProtocol")).upper() or "TCP"
                forward_mode = "router_native" if protocol == "TCP" else "relay_proxy"
                if _text(rule.get("forwardMode")) != forward_mode:
                    rule["forwardMode"] = forward_mode
                    rule["updatedAt"] = _now_text()
                    changed = True
                if protocol == "TCP" and _text(rule.get("stunServer")) == LEGACY_TCP_STUN_SERVER:
                    rule["stunServer"] = _stun_server("TCP")
                    rule["updatedAt"] = _now_text()
                    changed = True
            migrated.append(rule)
        if not changed:
            return
        self._save_rules(migrated)
        for rule in migrated:
            if rule.get("enabled") and _text(rule.get("kind")).lower() == "stun":
                self.queue("upsert", {"rule": rule})

    def _router_name(self) -> str:
        value = getattr(self.hub, "_portmap_router_name", None)
        if callable(value):
            return _text(value()) or "router"
        return _text(os.environ.get("PORTMAP_ROUTER_NAME")) or "router"

    def _allocated_port(self, protocol: str, excluding: str = "") -> int:
        used = {
            _int(row.get("listenPort"))
            for row in self._document()["rules"]
            if _text(row.get("id")) != excluding and _text(row.get("transportProtocol")).upper() == protocol
        }
        loader = getattr(self.hub, "_load_portmap_rules", None)
        if callable(loader):
            for row in loader():
                if _text(row.get("transportProtocol")).upper() == protocol:
                    used.add(_int(row.get("listenPort")))
        for port in range(20000, 20021):
            if port not in used:
                return port
        raise ValueError("中继端口已用完，请先停止一个映射或穿透规则")

    def clean_rule(self, payload: Dict[str, Any], old: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        old = dict(old or {})
        service = _text(payload.get("serviceType") or old.get("serviceType") or "Custom")
        service = next((name for name in SERVICE_TEMPLATES if name.lower() == service.lower()), "Custom")
        suggested_port, protocols, default_protocol = SERVICE_TEMPLATES[service]
        protocol = _text(payload.get("transportProtocol") or old.get("transportProtocol") or default_protocol).upper()
        if protocol not in protocols:
            raise ValueError(f"{service} 不支持 {protocol} 穿透")
        target_ip = _text(payload.get("targetIpv4") or old.get("targetIpv4"))
        try:
            address = ipaddress.ip_address(target_ip)
        except ValueError as error:
            raise ValueError("请输入有效的内网 IPv4 地址") from error
        if address.version != 4 or not (address.is_private or address.is_loopback or address.is_link_local):
            raise ValueError("目标地址必须是内网 IPv4 地址")
        target_port = _int(payload.get("targetPort"), _int(old.get("targetPort"), suggested_port or 0))
        if not 1 <= target_port <= 65535:
            raise ValueError("目标端口必须在 1–65535")
        rule_id = _text(payload.get("id") or old.get("id")) or f"stun-{uuid.uuid4().hex[:12]}"
        if not all(char.isalnum() or char in "-_" for char in rule_id):
            raise ValueError("规则 ID 无效")
        listen = _int(old.get("listenPort")) if old else 0
        if not listen:
            listen = self._allocated_port(protocol, rule_id)
        name = _text(payload.get("name") or old.get("name")) or f"{service} · {target_ip}:{target_port}"
        if len(name) > 64:
            raise ValueError("名称不能超过 64 个字符")
        return {
            "id": rule_id,
            "kind": "stun",
            "name": name,
            "enabled": bool(payload.get("enabled", old.get("enabled", True))),
            "mode": "stun",
            "listenPort": listen,
            "targetMode": "ipv4",
            "targetIpv4": target_ip,
            "targetPort": target_port,
            "serviceType": service,
            "transportProtocol": protocol,
            # Lucky's documented high-performance mode is available for TCP:
            # the router owns forwarding while the STUN client only keeps the
            # public NAT mapping alive.  UDP needs LabRelay's proxy socket.
            "forwardMode": "router_native" if protocol == "TCP" else "relay_proxy",
            "stunServer": _stun_server(protocol),
            "maxConnections": max(1, min(256, _int(payload.get("maxConnections"), _int(old.get("maxConnections"), 32)) or 32)),
            "idleTimeoutSec": max(30, min(3600, _int(payload.get("idleTimeoutSec"), _int(old.get("idleTimeoutSec"), 300)) or 300)),
            "createdAt": _text(old.get("createdAt")) or _now_text(),
            "updatedAt": _now_text(),
        }

    def _commands(self) -> List[Dict[str, Any]]:
        raw = self.hub.load_json(self.commands_path, {"commands": []})
        return [dict(row) for row in raw.get("commands", []) if isinstance(row, dict)] if isinstance(raw, dict) else []

    def _save_commands(self, commands: Iterable[Dict[str, Any]]) -> None:
        self.hub.save_json(self.commands_path, {"commands": [dict(row) for row in commands]})

    def queue(self, action: str, payload: Dict[str, Any], router: str = "") -> None:
        router = router or self._router_name()
        rule_id = _text(payload.get("id") or (payload.get("rule") or {}).get("id"))
        with self.lock:
            commands = self._commands()
            commands = [row for row in commands if not (row.get("router") == router and row.get("action") == action and _text((row.get("payload") or {}).get("id") or ((row.get("payload") or {}).get("rule") or {}).get("id")) == rule_id and row.get("status") in {"pending", "delivered"})]
            commands.append({"id": f"stun-cmd-{uuid.uuid4().hex[:12]}", "router": router, "action": action, "payload": payload, "status": "pending", "createdAt": _now_text(), "attempts": 0})
            self._save_commands(commands)

    def _status_record(self) -> Dict[str, Any]:
        raw = self.hub.load_json(self.status_path, {})
        return raw if isinstance(raw, dict) else {}

    def _runtime(self) -> Dict[str, Dict[str, Any]]:
        rows = self._status_record().get("status", {}).get("rules", [])
        output: Dict[str, Dict[str, Any]] = {}
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            rule = row.get("rule") if isinstance(row.get("rule"), dict) else {}
            runtime = row.get("runtime") if isinstance(row.get("runtime"), dict) else {}
            rule_id = _text(rule.get("id") or runtime.get("id"))
            if rule_id:
                output[rule_id] = dict(runtime)
        return output

    def _history(self) -> Dict[str, List[Dict[str, Any]]]:
        raw = self.hub.load_json(self.history_path, {})
        return {str(key): list(value) for key, value in raw.items() if isinstance(value, list)} if isinstance(raw, dict) else {}

    def _remember_endpoint(self, rule_id: str, runtime: Dict[str, Any]) -> None:
        endpoint = _text(runtime.get("publicEndpoint"))
        if not endpoint:
            return
        history = self._history()
        rows = [row for row in history.get(rule_id, []) if isinstance(row, dict)]
        if not rows or _text(rows[0].get("endpoint")) != endpoint:
            rows.insert(0, {"endpoint": endpoint, "updatedAt": _int(runtime.get("mappingUpdatedAt")) or _now(), "protocol": _text(runtime.get("transportProtocol"))})
        history[rule_id] = rows[:3]
        self.hub.save_json(self.history_path, history)

    def _firewall_bindings(self) -> Dict[str, Dict[str, Any]]:
        raw = self.hub.load_json(self.firewall_path, {})
        rows = raw.get("rules", {}) if isinstance(raw, dict) else {}
        return {str(key): dict(value) for key, value in rows.items() if isinstance(value, dict)} if isinstance(rows, dict) else {}

    def _save_firewall_bindings(self, rows: Dict[str, Dict[str, Any]]) -> None:
        self.hub.save_json(self.firewall_path, {"updatedAt": _now_text(), "rules": rows})

    def _native_mapping_bindings(self) -> Dict[str, Dict[str, Any]]:
        raw = self.hub.load_json(self.native_mapping_path, {})
        rows = raw.get("rules", {}) if isinstance(raw, dict) else {}
        return {str(key): dict(value) for key, value in rows.items() if isinstance(value, dict)} if isinstance(rows, dict) else {}

    def _save_native_mapping_bindings(self, rows: Dict[str, Dict[str, Any]]) -> None:
        self.hub.save_json(self.native_mapping_path, {"updatedAt": _now_text(), "rules": rows})

    @staticmethod
    def _native_mapping_rows(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        rows = snapshot.get("portMapping") or snapshot.get("list") or []
        return [dict(row) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []

    @staticmethod
    def _find_native_mapping(snapshot: Dict[str, Any], rule_name: str) -> Optional[Dict[str, Any]]:
        return next((row for row in StunService._native_mapping_rows(snapshot) if _text(row.get("ruleName")) == rule_name), None)

    @staticmethod
    def _is_native_forward(rule: Dict[str, Any]) -> bool:
        return _text(rule.get("forwardMode")) == "router_native"

    def _expected_native_mapping(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ruleName": f"LabProbe STUN {rule['id']}",
            "src": "wan",
            "srcIp": "",
            "srcPort": str(rule["listenPort"]),
            "destIp": _text(rule["targetIpv4"]),
            "destPort": str(rule["targetPort"]),
            "proto": "tcp",
        }

    @staticmethod
    def _native_mapping_matches(row: Dict[str, Any], expected: Dict[str, Any]) -> bool:
        return all(_text(row.get(key)) == _text(value) for key, value in expected.items())

    def ensure_native_mapping(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Create/update the one fixed TCP map owned by this STUN rule.

        The saved fingerprint prevents us from overwriting a router rule the
        user changed outside LabProbe.  It also means public STUN IP/port
        updates can never trigger router configuration churn.
        """
        if not self._is_native_forward(rule):
            return {"state": "not_required"}
        expected = self._expected_native_mapping(rule)
        bindings = self._native_mapping_bindings()
        binding = bindings.get(rule["id"], {})
        current = self.client.native_port_mapping(True)
        existing = self._find_native_mapping(current, expected["ruleName"])
        if existing:
            current_fingerprint = _rule_fingerprint(existing)
            if binding.get("fingerprint") and binding["fingerprint"] != current_fingerprint:
                result = {"state": "manual_change", "message": "已检测到路由器端口映射被手动修改"}
                bindings[rule["id"]] = {**binding, **result}
                self._save_native_mapping_bindings(bindings)
                return result
            if not self._native_mapping_matches(existing, expected):
                verified = self.controller.write_and_verify(
                    "native-portmap",
                    lambda: self.client.rpc("devConfig.update", "port_mapping", {"old": existing, "new": expected}),
                    lambda: self.client.native_port_mapping(True),
                )
                existing = self._find_native_mapping(verified.get("data", {}), expected["ruleName"])
                if not existing or not self._native_mapping_matches(existing, expected):
                    result = {"state": "verify_failed", "message": "路由器端口映射更新后未能确认"}
                    bindings[rule["id"]] = {**binding, **result}
                    self._save_native_mapping_bindings(bindings)
                    return result
            result = {"state": "ready", "ruleName": expected["ruleName"], "fingerprint": _rule_fingerprint(existing)}
            bindings[rule["id"]] = result
            self._save_native_mapping_bindings(bindings)
            return result
        verified = self.controller.write_and_verify(
            "native-portmap",
            lambda: self.client.rpc("devConfig.add", "port_mapping", {"list": [expected]}),
            lambda: self.client.native_port_mapping(True),
        )
        created = self._find_native_mapping(verified.get("data", {}), expected["ruleName"])
        if not created or not self._native_mapping_matches(created, expected):
            result = {"state": "verify_failed", "message": "路由器端口映射创建后未能确认"}
            bindings[rule["id"]] = {**binding, **result}
            self._save_native_mapping_bindings(bindings)
            return result
        result = {"state": "ready", "ruleName": expected["ruleName"], "fingerprint": _rule_fingerprint(created)}
        bindings[rule["id"]] = result
        self._save_native_mapping_bindings(bindings)
        return result

    def remove_native_mapping(self, rule_id: str) -> None:
        bindings = self._native_mapping_bindings()
        binding = bindings.get(rule_id)
        if not binding:
            return
        current = self.client.native_port_mapping(True)
        row = self._find_native_mapping(current, _text(binding.get("ruleName")))
        if row and binding.get("fingerprint") != _rule_fingerprint(row):
            raise ValueError("路由器端口映射已被手动修改；为避免误删，未停止穿透")
        if row:
            self.controller.write_and_verify(
                "native-portmap",
                lambda: self.client.rpc("devConfig.del", "port_mapping", {"ruleName": [_text(row.get("ruleName"))]}),
                lambda: self.client.native_port_mapping(True),
            )
        bindings.pop(rule_id, None)
        self._save_native_mapping_bindings(bindings)

    @staticmethod
    def _find_firewall(firewall: Dict[str, Any], firewall_uuid: str) -> Optional[Dict[str, Any]]:
        rows = firewall.get("list", []) if isinstance(firewall, dict) else []
        return next((dict(row) for row in rows if isinstance(row, dict) and _text(row.get("uuid")) == firewall_uuid), None)

    def _expected_firewall(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ruleName": f"LabProbe STUN {rule['id']}", "direction": "inbound", "ipVersion": "ipv4",
            "proto": _text(rule["transportProtocol"]).lower(), "srcIP": "", "destIP": "", "srcPort": "",
            "destPort": str(rule["listenPort"]), "target": "ACCEPT", "enable": "1",
            "ipv6SuffixSrc": "", "ipv6SuffixDest": "", "inIface": "wan", "outIface": "",
        }

    def ensure_firewall(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        expected = self._expected_firewall(rule)
        bindings = self._firewall_bindings()
        binding = bindings.get(rule["id"], {})
        current = self.client.firewall(True)
        existing = self._find_firewall(current, _text(binding.get("uuid")))
        if existing:
            if binding.get("fingerprint") and binding["fingerprint"] != _rule_fingerprint(existing):
                return {"state": "manual_change", "message": "已检测到防火墙规则被手动修改"}
            if any(_text(existing.get(key)) != _text(value) for key, value in expected.items()):
                return {"state": "verify_failed", "message": "防火墙规则回读与穿透规则不一致"}
            bindings[rule["id"]] = {"uuid": _text(existing.get("uuid")), "fingerprint": _rule_fingerprint(existing)}
            self._save_firewall_bindings(bindings)
            return {"state": "ready", "uuid": _text(existing.get("uuid")), "fingerprint": _rule_fingerprint(existing)}
        if _int(current.get("maxLen"), 20) and len(current.get("list", [])) >= _int(current.get("maxLen"), 20):
            return {"state": "full", "message": "路由器防火墙规则已满"}
        written = self.controller.write_and_verify(
            "firewall",
            lambda: self.client.rpc("devConfig.add", "ip_firewall", {"list": [expected]}),
            lambda: self.client.firewall(True),
        )
        verified = written.get("data") if isinstance(written, dict) else {}
        created = next((dict(row) for row in verified.get("list", []) if isinstance(row, dict) and _text(row.get("ruleName")) == expected["ruleName"] and _text(row.get("destPort")) == expected["destPort"] and _text(row.get("proto")).lower() == expected["proto"]), None)
        if not created or not _text(created.get("uuid")):
            return {"state": "verify_failed", "message": "防火墙规则创建后未能确认"}
        bindings[rule["id"]] = {"uuid": _text(created.get("uuid")), "fingerprint": _rule_fingerprint(created)}
        self._save_firewall_bindings(bindings)
        return {"state": "ready", "uuid": _text(created.get("uuid")), "fingerprint": _rule_fingerprint(created)}

    def remove_firewall(self, rule_id: str) -> None:
        bindings = self._firewall_bindings()
        binding = bindings.get(rule_id)
        if not binding:
            return
        current = self.client.firewall(True)
        row = self._find_firewall(current, _text(binding.get("uuid")))
        if row and binding.get("fingerprint") == _rule_fingerprint(row):
            self.controller.write_and_verify("firewall", lambda: self.client.rpc("devConfig.del", "ip_firewall", {"uuid": [_text(row.get("uuid"))]}), lambda: self.client.firewall(True))
        bindings.pop(rule_id, None)
        self._save_firewall_bindings(bindings)

    def rows(self) -> List[Dict[str, Any]]:
        runtime = self._runtime()
        firewall_bindings = self._firewall_bindings()
        native_bindings = self._native_mapping_bindings()
        result = []
        for rule in self._document()["rules"]:
            item = dict(rule)
            current = runtime.get(rule["id"], {})
            native_state = _text(native_bindings.get(rule["id"], {}).get("state")) or ("ready" if native_bindings.get(rule["id"], {}).get("fingerprint") else "pending")
            firewall_state = "not_required" if self._is_native_forward(rule) else (_text(firewall_bindings.get(rule["id"], {}).get("state")) or ("ready" if firewall_bindings.get(rule["id"], {}).get("uuid") else "pending"))
            actual = _text(current.get("state"))
            if self._is_native_forward(rule) and actual == "mapped" and native_state != "ready":
                actual = "router_mapping_error" if native_state not in {"pending", ""} else "router_mapping"
            elif not self._is_native_forward(rule) and actual == "mapped" and firewall_state != "ready":
                actual = "firewall_error" if firewall_state not in {"pending", ""} else "mapping"
            item.update({"runtime": current, "actualState": actual, "firewallState": firewall_state, "nativeMappingState": native_state})
            result.append(item)
        return result


def create_stun_blueprint(hub: Any, service: StunService) -> Blueprint:
    bp = Blueprint("stun_service", __name__, url_prefix="/api")

    def app_auth():
        return None if hub.check_app_token() else (jsonify({"ok": False, "error": "unauthorized"}), 401)

    @bp.route("/stun", methods=["GET", "POST"])
    def rules():
        if request.method == "GET":
            if not hub.check_read_token():
                return jsonify({"ok": False, "error": "unauthorized"}), 401
            doc = service._document()
            status = service._status_record()
            return jsonify({"ok": True, "rules": service.rows(), "revision": doc["revision"], "rulesUpdatedAt": doc["updatedAt"], "portRange": {"min": 20000, "max": 20020}, "agentOnline": _now() - _int(status.get("receivedEpoch"), 0) <= 35, "agentLastSeenAt": _text(status.get("receivedAt"))})
        if (denied := app_auth()) is not None:
            return denied
        try:
            rule = service.clean_rule(request.get_json(silent=True) or {})
            if rule["enabled"] and service._is_native_forward(rule):
                mapping = service.ensure_native_mapping(rule)
                if mapping.get("state") != "ready":
                    raise ValueError(_text(mapping.get("message")) or "路由器端口映射未就绪")
            doc = service._document()
            service._save_rules([*doc["rules"], rule])
            service.queue("upsert", {"rule": rule})
            return jsonify({"ok": True, "rule": rule}), 201
        except Exception as error:
            return jsonify({"ok": False, "error": str(error)}), 400

    @bp.route("/stun/<rule_id>", methods=["PUT", "DELETE"])
    def rule_item(rule_id: str):
        if (denied := app_auth()) is not None:
            return denied
        doc = service._document()
        old = next((row for row in doc["rules"] if _text(row.get("id")) == rule_id), None)
        if not old:
            return jsonify({"ok": False, "error": "rule not found"}), 404
        if request.method == "DELETE":
            cleanup_error = ""
            try:
                service.remove_native_mapping(rule_id)
                service.remove_firewall(rule_id)
            except Exception as error:
                return jsonify({"ok": False, "error": str(error)}), 409
            service._save_rules([row for row in doc["rules"] if _text(row.get("id")) != rule_id])
            service.queue("delete", {"id": rule_id})
            return jsonify({"ok": True, "id": rule_id, "deleted": True, "cleanupError": cleanup_error})
        try:
            payload = request.get_json(silent=True) or {}
            payload["id"] = rule_id
            rule = service.clean_rule(payload, old)
            if service._is_native_forward(rule):
                if rule["enabled"]:
                    mapping = service.ensure_native_mapping(rule)
                    if mapping.get("state") != "ready":
                        raise ValueError(_text(mapping.get("message")) or "路由器端口映射未就绪")
                else:
                    service.remove_native_mapping(rule_id)
                # A previous relay-proxy version may have installed the old
                # automatic eWeb firewall entry.  TCP native forwarding does
                # not need it, so remove only our fingerprinted entry.
                service.remove_firewall(rule_id)
            elif service._is_native_forward(old):
                service.remove_native_mapping(rule_id)
            service._save_rules([rule if _text(row.get("id")) == rule_id else row for row in doc["rules"]])
            service.queue("upsert", {"rule": rule})
            return jsonify({"ok": True, "rule": rule})
        except Exception as error:
            return jsonify({"ok": False, "error": str(error)}), 400

    @bp.post("/stun/<rule_id>/<action>")
    def action(rule_id: str, action: str):
        if (denied := app_auth()) is not None:
            return denied
        if action not in {"start", "stop"}:
            return jsonify({"ok": False, "error": "invalid action"}), 400
        doc = service._document()
        rule = next((dict(row) for row in doc["rules"] if _text(row.get("id")) == rule_id), None)
        if not rule:
            return jsonify({"ok": False, "error": "rule not found"}), 404
        if action == "start" and service._is_native_forward(rule):
            try:
                mapping = service.ensure_native_mapping(rule)
                if mapping.get("state") != "ready":
                    raise ValueError(_text(mapping.get("message")) or "路由器端口映射未就绪")
            except Exception as error:
                return jsonify({"ok": False, "error": str(error)}), 409
        if action == "stop" and service._is_native_forward(rule):
            try:
                service.remove_native_mapping(rule_id)
            except Exception as error:
                return jsonify({"ok": False, "error": str(error)}), 409
        rule["enabled"] = action == "start"
        rule["updatedAt"] = _now_text()
        service._save_rules([rule if _text(row.get("id")) == rule_id else row for row in doc["rules"]])
        service.queue("upsert" if action == "start" else "stop", {"rule": rule} if action == "start" else {"id": rule_id})
        if action == "stop" and not service._is_native_forward(rule):
            try:
                service.remove_firewall(rule_id)
            except Exception:
                pass
        return jsonify({"ok": True, "rule": rule, "action": action})

    @bp.get("/stun/<rule_id>/addresses")
    def addresses(rule_id: str):
        if not hub.check_read_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return jsonify({"ok": True, "id": rule_id, "addresses": service._history().get(rule_id, [])[:3]})

    @bp.get("/router/stun/commands")
    def agent_commands():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad hook token"}), 401
        router = _text(request.args.get("router")) or service._router_name()
        limit = max(1, min(50, _int(request.args.get("limit"), 20)))
        now = _now()
        selected = []
        commands = service._commands()
        changed = False
        for command in commands:
            if command.get("router") != router:
                continue
            retry = command.get("status") == "delivered" and now - _int(command.get("deliveredEpoch")) >= 15 and _int(command.get("attempts")) < 5
            if command.get("status") == "pending" or retry:
                command.update({"status": "delivered", "deliveredAt": _now_text(), "deliveredEpoch": now, "attempts": _int(command.get("attempts")) + 1})
                selected.append({key: command.get(key) for key in ["id", "action", "payload", "createdAt"]})
                changed = True
                if len(selected) >= limit:
                    break
        if changed:
            service._save_commands(commands)
        return jsonify({"ok": True, "commands": selected})

    @bp.post("/router/stun/ack")
    def agent_ack():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad hook token"}), 401
        acks = (request.get_json(silent=True) or {}).get("acks", [])
        values = {_text(row.get("id")): row for row in acks if isinstance(row, dict)} if isinstance(acks, list) else {}
        commands = service._commands()
        changed = 0
        for command in commands:
            ack = values.get(_text(command.get("id")))
            if ack:
                command.update({"status": "done" if bool(ack.get("ok")) else "failed", "result": ack.get("result"), "finishedAt": _now_text()})
                changed += 1
        if changed:
            service._save_commands(commands)
        return jsonify({"ok": True, "acknowledged": changed})

    @bp.post("/router/stun/status")
    def agent_status():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad hook token"}), 401
        payload = request.get_json(silent=True) or {}
        record = {"router": _text(request.args.get("router")) or service._router_name(), "receivedAt": _now_text(), "receivedEpoch": _now(), "status": payload}
        service.hub.save_json(service.status_path, record)
        runtime = service._runtime()
        firewall_bindings = service._firewall_bindings()
        rules = service._document()["rules"]
        desired = {rule["id"]: rule for rule in rules}
        local_rules = {}
        for row in payload.get("rules", []) if isinstance(payload.get("rules"), list) else []:
            if isinstance(row, dict) and isinstance(row.get("rule"), dict):
                local = row["rule"]
                if _text(local.get("id")):
                    local_rules[_text(local.get("id"))] = local
        compare = ["enabled", "kind", "listenPort", "targetIpv4", "targetPort", "serviceType", "transportProtocol", "forwardMode", "stunServer", "maxConnections", "idleTimeoutSec"]
        for rule_id, rule in desired.items():
            local = local_rules.get(rule_id)
            if local is None or any(local.get(key) != rule.get(key) for key in compare):
                service.queue("upsert", {"rule": rule}, record["router"])
        for rule_id in set(local_rules) - set(desired):
            service.queue("delete", {"id": rule_id}, record["router"])
        for rule in rules:
            current = runtime.get(rule["id"], {})
            service._remember_endpoint(rule["id"], current)
            if rule.get("enabled") and service._is_native_forward(rule):
                try:
                    service.ensure_native_mapping(rule)
                except Exception as error:
                    native = service._native_mapping_bindings()
                    native[rule["id"]] = {**native.get(rule["id"], {}), "state": "error", "message": str(error)}
                    service._save_native_mapping_bindings(native)
                # Clean up the obsolete firewall entry created by an earlier
                # build, but never touch a manually edited rule.
                try:
                    service.remove_firewall(rule["id"])
                except Exception:
                    pass
            elif rule.get("enabled") and _text(current.get("state")) == "mapped":
                try:
                    result = service.ensure_firewall(rule)
                except Exception as error:
                    result = {"state": "error", "message": str(error)}
                firewall_bindings[rule["id"]] = {**firewall_bindings.get(rule["id"], {}), **result}
        service._save_firewall_bindings(firewall_bindings)
        return jsonify({"ok": True, "receivedAt": record["receivedAt"]})

    return bp


def install_stun_service(hub: Any, client: Any) -> StunService:
    existing = getattr(hub, "STUN_SERVICE", None)
    if existing is not None:
        return existing
    service = StunService(hub, client)
    hub.STUN_SERVICE = service
    hub.app.register_blueprint(create_stun_blueprint(hub, service))
    return service
