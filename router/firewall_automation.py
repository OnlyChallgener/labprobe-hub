"""Safe address-follow automation for existing Ruijie Web firewall rules.

The router remains the only firewall authority.  A binding merely adopts an
existing rule UUID and allows Hub to update one explicitly selected destination
address field through ``devConfig.update/ip_firewall``.  Every other raw router
field is copied back unchanged and the write is force-read for verification.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from flask import Blueprint, jsonify, request

import router_rpc


class FirewallAutomationError(ValueError):
    def __init__(self, message: str, code: str = "INVALID_AUTOMATION", http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def _text(value: Any) -> str:
    return str(value or "").strip()


def _enabled(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return _text(value).lower() in {"1", "true", "yes", "on", "enabled"}


def _rows(data: Any) -> List[Dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    value = data.get("list")
    return [dict(row) for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _find_rule(data: Any, firewall_uuid: str) -> Optional[Dict[str, Any]]:
    return next((row for row in _rows(data) if _text(row.get("uuid")) == firewall_uuid), None)


def _ip(value: Any, family: str) -> str:
    raw = _text(value).split("/", 1)[0].split("%", 1)[0]
    if not raw:
        return ""
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return ""
    expected = 4 if family == "ipv4" else 6
    if address.version != expected or address.is_unspecified or address.is_multicast or address.is_loopback:
        return ""
    if address.version == 6 and address.is_link_local:
        return ""
    return str(address)


def _suffix(address: str) -> str:
    parsed = ipaddress.IPv6Address(address)
    host = int(parsed) & ((1 << 64) - 1)
    if host == 0:
        return ""
    return str(ipaddress.IPv6Address(host))


def _field_value(field: str, value: Any, family: str) -> str:
    if field == "destIP":
        return _ip(value, family)
    if field != "ipv6SuffixDest" or family != "ipv6":
        return ""
    raw = _text(value)
    if not raw:
        return ""
    try:
        parsed = ipaddress.IPv6Address(raw if ":" in raw else f"::{raw}")
    except ValueError:
        return ""
    host = int(parsed) & ((1 << 64) - 1)
    return str(ipaddress.IPv6Address(host)) if host else ""


def _target_from_endpoint(value: Any) -> str:
    raw = _text(value)
    if raw.startswith("[") and "]" in raw:
        return raw[1:raw.index("]")]
    if raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        return host if port.isdigit() else raw
    # A bare IPv6 has multiple colons.  An unbracketed IPv6 endpoint may have a
    # decimal port after the final colon, but accepting it would be ambiguous;
    # Relay's 6-to-6 runtime uses the bracketed form.
    return raw


class FirewallAutomationService:
    VERSION = 1
    TARGETS = {"router", "device", "mapping"}
    FAMILIES = {"ipv4", "ipv6"}
    FIELDS = {"destIP", "ipv6SuffixDest"}

    def __init__(self, hub: Any, client: Any):
        self.hub = hub
        self.client = client
        self.controller = router_rpc.RouterController(client)
        self.logger = hub.LOGGER
        self.path = Path(hub.DATA_DIR) / "firewall_automation.json"
        self.config_lock = threading.RLock()
        self.reconcile_lock = threading.Lock()

    def _document(self) -> Dict[str, Any]:
        with self.config_lock:
            raw = self.hub.load_json(self.path, {})
            if not isinstance(raw, dict):
                raw = {}
            bindings = raw.get("bindings")
            if not isinstance(bindings, list):
                bindings = []
            return {
                "version": self.VERSION,
                "updatedAt": _text(raw.get("updatedAt")),
                "bindings": [dict(row) for row in bindings if isinstance(row, dict) and _text(row.get("firewallUuid"))],
            }

    def _save(self, bindings: Iterable[Dict[str, Any]]) -> None:
        rows = sorted((dict(row) for row in bindings), key=lambda row: _text(row.get("firewallUuid")))
        with self.config_lock:
            self.hub.save_json(
                self.path,
                {"version": self.VERSION, "updatedAt": self.hub.now_str(), "bindings": rows[:100]},
            )

    def bindings(self) -> List[Dict[str, Any]]:
        return self._document()["bindings"]

    def _binding(self, firewall_uuid: str) -> Optional[Dict[str, Any]]:
        return next((row for row in self.bindings() if _text(row.get("firewallUuid")) == firewall_uuid), None)

    def _normalize_binding(self, firewall_uuid: str, body: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
        target_type = _text(body.get("targetType")).lower()
        if target_type not in self.TARGETS:
            raise FirewallAutomationError("请选择路由器、终端设备或映射规则作为跟随目标")

        family = _text(body.get("addressFamily") or rule.get("ipVersion")).lower()
        if family not in self.FAMILIES:
            raise FirewallAutomationError("双栈规则不能绑定单一地址，请分别使用 IPv4 和 IPv6 规则")

        field = _text(body.get("matchField"))
        if not field:
            field = "ipv6SuffixDest" if _text(rule.get("ipv6SuffixDest")) else "destIP"
        if field not in self.FIELDS or (family == "ipv4" and field != "destIP"):
            raise FirewallAutomationError("目标地址匹配方式与 IP 版本不兼容")

        rule_family = _text(rule.get("ipVersion")).lower()
        if rule_family != family:
            raise FirewallAutomationError("自动跟随的 IP 版本必须与原防火墙规则一致")
        if not _field_value(field, rule.get(field), family):
            label = "目的 IPv6 后缀" if field == "ipv6SuffixDest" else "目的 IP"
            raise FirewallAutomationError(f"请先在原防火墙规则中填写有效的{label}，自动跟随不会改变匹配模式")

        target_mac = self.hub.norm_mac(body.get("targetMac")) if target_type == "device" else ""
        mapping_id = _text(body.get("mappingId")) if target_type == "mapping" else ""
        if target_type == "device" and not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", target_mac):
            raise FirewallAutomationError("请选择需要跟随的终端设备")
        if target_type == "mapping" and not mapping_id:
            raise FirewallAutomationError("请选择需要跟随的映射规则")

        return {
            "firewallUuid": firewall_uuid,
            "enabled": _enabled(body.get("enabled"), True),
            "targetType": target_type,
            "targetMac": target_mac,
            "mappingId": mapping_id,
            "addressFamily": family,
            "matchField": field,
        }

    def upsert(self, firewall_uuid: str, body: Dict[str, Any]) -> Dict[str, Any]:
        firewall_uuid = _text(firewall_uuid)
        if not firewall_uuid:
            raise FirewallAutomationError("防火墙规则 UUID 不能为空")
        firewall = self.client.firewall(True)
        rule = _find_rule(firewall, firewall_uuid)
        if rule is None:
            raise FirewallAutomationError("原防火墙规则不存在，未创建任何新规则", "RULE_NOT_FOUND", 404)
        binding = self._normalize_binding(firewall_uuid, body, rule)
        rows = [row for row in self.bindings() if _text(row.get("firewallUuid")) != firewall_uuid]
        rows.append(binding)
        self._save(rows)
        self.reconcile(firewall, firewall_uuid, blocking=True)
        return self.describe(firewall_uuid, self.client.firewall(True))

    def delete(self, firewall_uuid: str) -> bool:
        before = self.bindings()
        after = [row for row in before if _text(row.get("firewallUuid")) != firewall_uuid]
        if len(after) != len(before):
            self._save(after)
            return True
        return False

    def _router_address(self, family: str) -> Tuple[str, str]:
        state = self.hub.load_json(self.hub.STATE_FILE, {})
        router = state.get("router") if isinstance(state, dict) and isinstance(state.get("router"), dict) else {}
        if family == "ipv6":
            candidates = [router.get("wanIpv6")]
            for row in router.get("wanIpv6List", []) if isinstance(router.get("wanIpv6List"), list) else []:
                if isinstance(row, dict) and row.get("primary"):
                    candidates.insert(0, row.get("ip"))
            for candidate in candidates:
                value = _ip(candidate, family)
                if value:
                    return value, _text(router.get("name")) or "路由器"
            return "", _text(router.get("name")) or "路由器"

        with self.hub.ROUTER_DASHBOARD_LOCK:
            root = self.hub.ROUTER_DASHBOARD_CACHE
            details = root.get("details") if isinstance(root, dict) and isinstance(root.get("details"), dict) else {}
            wan = details.get("wan") if isinstance(details.get("wan"), dict) else {}
            value = _ip(wan.get("ipv4"), family)
            name = _text(root.get("router")) if isinstance(root, dict) else ""
        return value, name or _text(router.get("name")) or "路由器"

    def _online_device(self, target_mac: str) -> Optional[Dict[str, Any]]:
        document = self.hub.load_json(self.hub.DEVICES_FILE, {})
        rows = document.get("online") if isinstance(document, dict) else []
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and self.hub.norm_mac(row.get("mac")) == target_mac:
                return dict(row)
        return None

    def _device_address(self, binding: Dict[str, Any]) -> Tuple[str, str]:
        target_mac = _text(binding.get("targetMac"))
        family = _text(binding.get("addressFamily"))
        row = self._online_device(target_mac)
        archive = self.hub.load_device_archive()
        stored = archive.get(target_mac) if isinstance(archive, dict) and isinstance(archive.get(target_mac), dict) else {}
        name = _text((row or {}).get("name") or (row or {}).get("hostName") or stored.get("name") or stored.get("hostName")) or target_mac
        if row is None:
            return "", name
        if family == "ipv4":
            return _ip(row.get("ip"), family), name

        state = self.hub.load_json(self.hub.STATE_FILE, {})
        router = state.get("router") if isinstance(state, dict) and isinstance(state.get("router"), dict) else {}
        prefixes = self.hub.normalize_ipv6_prefixes(router.get("lanIpv6Prefixes") or [])
        records = self.hub.normalize_ipv6_records(row.get("ipv6Records") or stored.get("ipv6Records") or [], prefixes)
        safe_records = [
            record for record in records
            if not record.get("historical")
            and _text(record.get("state")).upper() != "FAILED"
            and (not prefixes or record.get("currentPrefix"))
        ]
        value = self.hub.pick_primary_ipv6(safe_records) if safe_records else ""
        if not value:
            candidates = [row.get("ipv6"), row.get("ipv6Address"), row.get("globalIpv6")]
            if not prefixes:
                value = next((_ip(candidate, family) for candidate in candidates if _ip(candidate, family)), "")
        return _ip(value, family), name

    def _mapping_address(self, binding: Dict[str, Any]) -> Tuple[str, str]:
        mapping_id = _text(binding.get("mappingId"))
        document, readable = self.hub._load_portmap_rules_document()
        rule = next((row for row in document.get("rules", []) if _text(row.get("id")) == mapping_id), None) if readable else None
        name = _text((rule or {}).get("name")) or mapping_id
        status = self.hub.load_json(self.hub.PORTMAP_ROUTER_STATUS_FILE, {})
        runtime = self.hub._portmap_runtime_map(status).get(mapping_id, {})
        if _text(runtime.get("state")).lower() not in {"running", "active"}:
            return "", name
        candidate = _target_from_endpoint(runtime.get("resolvedTarget"))
        return _ip(candidate, _text(binding.get("addressFamily"))), name

    def resolve(self, binding: Dict[str, Any]) -> Tuple[str, str]:
        target_type = _text(binding.get("targetType"))
        family = _text(binding.get("addressFamily"))
        if target_type == "router":
            address, name = self._router_address(family)
        elif target_type == "device":
            address, name = self._device_address(binding)
        elif target_type == "mapping":
            address, name = self._mapping_address(binding)
        else:
            return "", ""
        if address and _text(binding.get("matchField")) == "ipv6SuffixDest":
            address = _suffix(address)
        return address, name

    def _rule_compatible(self, rule: Optional[Dict[str, Any]], binding: Dict[str, Any]) -> bool:
        if rule is None:
            return False
        family = _text(binding.get("addressFamily"))
        field = _text(binding.get("matchField"))
        return (
            _text(rule.get("ipVersion")).lower() == family
            and field in self.FIELDS
            and not (family == "ipv4" and field != "destIP")
            and bool(_field_value(field, rule.get(field), family))
        )

    def _state(self, binding: Dict[str, Any], firewall: Any) -> Dict[str, Any]:
        rule = _find_rule(firewall, _text(binding.get("firewallUuid")))
        desired, target_name = self.resolve(binding)
        current = _field_value(
            _text(binding.get("matchField")),
            (rule or {}).get(_text(binding.get("matchField"))),
            _text(binding.get("addressFamily")),
        )
        if not _enabled(binding.get("enabled"), True):
            status = "disabled"
            message = "自动跟随已暂停"
        elif rule is None:
            status = "missing_rule"
            message = "原规则已不存在，不会自动新建"
        elif not self._rule_compatible(rule, binding):
            status = "unsupported"
            message = "原规则的 IP 版本或匹配方式已改变，未执行自动更新"
        elif not desired:
            status = "waiting_target"
            message = "尚未确认唯一有效地址，保持原规则不变"
        elif current == desired:
            status = "synced"
            message = "目的地址已同步"
        else:
            status = "pending"
            message = "检测到地址变化，等待安全同步"
        return {
            **binding,
            "targetName": target_name,
            "ruleName": _text((rule or {}).get("ruleName")),
            "direction": _text((rule or {}).get("direction")),
            "currentAddress": current,
            "desiredAddress": desired,
            "status": status,
            "statusMessage": message,
        }

    def describe(self, firewall_uuid: str = "", firewall: Any = None) -> Any:
        if firewall is None:
            snapshot = getattr(self.hub, "ROUTER_CONFIG_SYNC", None)
            frame = snapshot.snapshot("firewall") if snapshot is not None else {}
            firewall = frame.get("data") if isinstance(frame, dict) else None
            if not isinstance(firewall, dict):
                firewall = self.client.firewall(True)
        states = [self._state(binding, firewall) for binding in self.bindings()]
        if firewall_uuid:
            return next((row for row in states if _text(row.get("firewallUuid")) == firewall_uuid), {})
        return {"bindings": states, "total": len(states)}

    def _verify(self, data: Any, binding: Dict[str, Any], desired: str) -> None:
        rule = _find_rule(data, _text(binding.get("firewallUuid")))
        actual = _field_value(
            _text(binding.get("matchField")),
            (rule or {}).get(_text(binding.get("matchField"))),
            _text(binding.get("addressFamily")),
        )
        if actual != desired:
            raise FirewallAutomationError("路由器回读地址与期望值不一致", "VERIFY_FAILED", 502)

    def reconcile(self, firewall: Any = None, firewall_uuid: str = "", blocking: bool = False) -> Dict[str, Any]:
        acquired = self.reconcile_lock.acquire(blocking=blocking)
        if not acquired:
            return {"ok": True, "changed": False, "busy": True}
        try:
            current = firewall if isinstance(firewall, dict) else self.client.firewall(True)
            bindings = self.bindings()
            if firewall_uuid:
                bindings = [row for row in bindings if _text(row.get("firewallUuid")) == firewall_uuid]
            for binding in bindings:
                if not _enabled(binding.get("enabled"), True):
                    continue
                rule = _find_rule(current, _text(binding.get("firewallUuid")))
                if not self._rule_compatible(rule, binding):
                    continue
                field = _text(binding.get("matchField"))
                family = _text(binding.get("addressFamily"))
                desired, _target_name = self.resolve(binding)
                actual = _field_value(field, rule.get(field), family)
                if not desired or not actual or actual == desired:
                    continue

                # Preserve the complete raw Web rule.  Only synthetic runtime stats
                # are removed; ports, direction, action, interfaces and order remain
                # byte-for-byte as returned by the router.
                payload = dict(rule)
                payload.pop("stats", None)
                payload[field] = desired
                result = self.controller.write_and_verify(
                    "firewall",
                    lambda payload=payload: self.client.rpc("devConfig.update", "ip_firewall", {"list": [payload]}),
                    lambda: self.client.firewall(True),
                )
                verified = result.get("data") if isinstance(result, dict) else None
                self._verify(verified, binding, desired)
                self.logger.info(
                    "firewall address follow updated uuid=%s field=%s from=%s to=%s",
                    binding.get("firewallUuid"),
                    field,
                    actual,
                    desired,
                )
                # One write per cycle limits router pressure and keeps each change
                # independently verified.  Remaining bindings are handled next cycle.
                return {
                    "ok": True,
                    "changed": True,
                    "firewallUuid": binding.get("firewallUuid"),
                    "field": field,
                    "oldAddress": actual,
                    "newAddress": desired,
                    "verifiedAt": int(time.time()),
                }
            return {"ok": True, "changed": False}
        finally:
            self.reconcile_lock.release()


def create_firewall_automation_blueprint(
    check_app_token: Callable[[], bool],
    logger: Any,
    service: FirewallAutomationService,
) -> Blueprint:
    bp = Blueprint("router_firewall_automation", __name__, url_prefix="/api/router/firewall/automation")

    @bp.before_request
    def _authorize():
        if not check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return None

    @bp.errorhandler(Exception)
    def _handle(error: Exception):
        logger.warning(
            "router firewall automation api error path=%s type=%s message=%s",
            request.path,
            type(error).__name__,
            error,
        )
        if isinstance(error, FirewallAutomationError):
            return jsonify({"ok": False, "error": error.code, "message": str(error)}), error.http_status
        if isinstance(error, router_rpc.RouterRpcError):
            return jsonify({"ok": False, "error": error.code, "message": str(error)}), error.http_status
        return jsonify({"ok": False, "error": "INTERNAL_ERROR", "message": "防火墙自动跟随操作失败"}), 500

    @bp.get("")
    def get_bindings():
        return jsonify({"ok": True, "data": service.describe()})

    @bp.put("/<firewall_uuid>")
    def put_binding(firewall_uuid: str):
        return jsonify({"ok": True, "data": service.upsert(firewall_uuid, request.get_json(silent=True) or {})})

    @bp.delete("/<firewall_uuid>")
    def delete_binding(firewall_uuid: str):
        removed = service.delete(firewall_uuid)
        return jsonify({"ok": True, "removed": removed, "message": "已停止自动跟随，原防火墙规则保持不变"})

    @bp.post("/<firewall_uuid>/sync")
    def sync_binding(firewall_uuid: str):
        if service._binding(firewall_uuid) is None:
            raise FirewallAutomationError("该规则尚未开启自动跟随", "BINDING_NOT_FOUND", 404)
        result = service.reconcile(firewall_uuid=firewall_uuid, blocking=True)
        return jsonify({"ok": True, "data": service.describe(firewall_uuid), "result": result})

    return bp


def install_firewall_automation(hub: Any, client: Any) -> FirewallAutomationService:
    existing = getattr(hub, "FIREWALL_AUTOMATION", None)
    if existing is not None:
        return existing
    service = FirewallAutomationService(hub, client)
    hub.FIREWALL_AUTOMATION = service
    hub.app.register_blueprint(create_firewall_automation_blueprint(hub.check_app_token, hub.LOGGER, service))
    return service
