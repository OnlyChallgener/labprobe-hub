"""Safe mapping-only automation for existing Ruijie Web firewall rules.

The router remains the only firewall authority.  A binding merely adopts an
existing rule UUID for a Relay IPv6 mapping or router-native port mapping and
allows Hub to update one explicitly selected destination address field through
``devConfig.update/ip_firewall``.  Every other raw router field is copied back
unchanged and the write is force-read for verification.  Out-of-band/manual
changes suspend automation instead of being overwritten.
"""
from __future__ import annotations

import ipaddress
import hashlib
import json
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


def _rule_fingerprint(rule: Dict[str, Any], controlled_field: str) -> str:
    """Fingerprint every user-controlled field except the one automation owns."""
    clean = {
        str(key): value
        for key, value in rule.items()
        if str(key) not in {"stats", controlled_field}
    }
    wire = json.dumps(clean, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(wire.encode("utf-8")).hexdigest()


def _port_contains(value: Any, target: Any) -> bool:
    try:
        port = int(str(target or "").strip())
    except (TypeError, ValueError):
        return False
    if not 1 <= port <= 65535:
        return False
    for item in (_text(value).replace("-", ":").split(",") if _text(value) else []):
        part = item.strip()
        if part.isdigit() and int(part) == port:
            return True
        if ":" in part:
            left, right = part.split(":", 1)
            if left.strip().isdigit() and right.strip().isdigit() and int(left) <= port <= int(right):
                return True
    return False


def _protocol_matches(rule_protocol: Any, mapping_protocol: Any) -> bool:
    rule = _text(rule_protocol).lower()
    mapping = _text(mapping_protocol).lower().replace("/", "+")
    if mapping in {"tcp+udp", "udp+tcp", "both"}:
        return rule in {"tcp", "udp"}
    return rule == mapping and rule in {"tcp", "udp"}


class FirewallAutomationService:
    VERSION = 2
    TARGETS = {"mapping"}
    MAPPING_KINDS = {"relay", "native"}
    FAMILIES = {"ipv4", "ipv6"}
    FIELDS = {"destIP", "ipv6SuffixDest"}
    STABLE_OBSERVATIONS = 2

    def __init__(self, hub: Any, client: Any):
        self.hub = hub
        self.client = client
        self.controller = router_rpc.RouterController(client)
        self.logger = hub.LOGGER
        self.path = Path(hub.DATA_DIR) / "firewall_automation.json"
        self.config_lock = threading.RLock()
        self.reconcile_lock = threading.Lock()
        self.candidate_lock = threading.RLock()
        self.candidates: Dict[str, Dict[str, Any]] = {}

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
            raise FirewallAutomationError("自动化仅支持路由器 IPv6 映射和端口映射")

        mapping_kind = _text(body.get("mappingKind") or "relay").lower()
        if mapping_kind not in self.MAPPING_KINDS:
            raise FirewallAutomationError("映射类型无效")
        mapping_id = _text(body.get("mappingId"))
        if not mapping_id:
            raise FirewallAutomationError("请选择需要关联的映射规则")

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

        if _text(rule.get("target")).upper() != "ACCEPT":
            raise FirewallAutomationError("丢弃规则不参与映射自动化")
        if _text(rule.get("direction")).lower() != "forward":
            raise FirewallAutomationError("映射只能关联 WAN 到 LAN 的转发规则")
        if _text(rule.get("inIface")).lower() != "wan" or _text(rule.get("outIface")).lower() != "lan":
            raise FirewallAutomationError("映射防火墙规则必须使用 WAN 入接口和 LAN 出接口")

        provisional = {
            "mappingKind": mapping_kind,
            "mappingId": mapping_id,
            "addressFamily": family,
        }
        mapping = self._mapping_spec(provisional, fresh=True)
        if mapping is None:
            raise FirewallAutomationError("关联的映射规则不存在或暂不可读取", "MAPPING_NOT_FOUND", 404)
        if _text(mapping.get("addressFamily")) != family:
            raise FirewallAutomationError("防火墙规则与映射的 IP 版本不一致")
        if not _protocol_matches(rule.get("proto"), mapping.get("protocol")):
            raise FirewallAutomationError("防火墙规则与映射的协议不一致")
        if not _port_contains(rule.get("destPort"), mapping.get("targetPort")):
            raise FirewallAutomationError("目的端口未覆盖映射的目标端口")

        current = _field_value(field, rule.get(field), family)

        return {
            "firewallUuid": firewall_uuid,
            "enabled": _enabled(body.get("enabled"), True),
            "targetType": "mapping",
            "mappingKind": mapping_kind,
            "mappingId": mapping_id,
            "addressFamily": family,
            "matchField": field,
            "ownership": _text(body.get("ownership") or "adopted"),
            "lastAppliedValue": current,
            "ruleFingerprint": _rule_fingerprint(rule, field),
            "suspended": False,
            "suspendedReason": "",
            "lastAppliedAt": int(time.time()),
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
            with self.candidate_lock:
                self.candidates.pop(firewall_uuid, None)
            return True
        return False

    def _relay_mapping_spec(self, binding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        mapping_id = _text(binding.get("mappingId"))
        document, readable = self.hub._load_portmap_rules_document()
        rule = next((row for row in document.get("rules", []) if _text(row.get("id")) == mapping_id), None) if readable else None
        if not isinstance(rule, dict):
            return None
        mode = _text(rule.get("mode")).lower()
        family = "ipv4" if mode == "6to4" else "ipv6"
        status = self.hub.load_json(self.hub.PORTMAP_ROUTER_STATUS_FILE, {})
        runtime = self.hub._portmap_runtime_map(status).get(mapping_id, {})
        candidate = ""
        if _text(runtime.get("state")).lower() in {"running", "active"}:
            candidate = _target_from_endpoint(runtime.get("resolvedTarget"))
        if not candidate and family == "ipv4":
            candidate = rule.get("targetIpv4")
        if not candidate and _text(rule.get("targetMode")) == "ipv6_full":
            candidate = rule.get("targetIpv6")
        if not candidate:
            candidate = rule.get("targetIpv6Snapshot")
        return {
            "mappingKind": "relay",
            "mappingId": mapping_id,
            "name": _text(rule.get("name")) or mapping_id,
            "addressFamily": family,
            "address": _ip(candidate, family),
            "protocol": _text(rule.get("transportProtocol") or "TCP").lower(),
            "targetPort": rule.get("targetPort"),
        }

    @staticmethod
    def _native_rows(data: Any) -> List[Dict[str, Any]]:
        if not isinstance(data, dict):
            return []
        rows = data.get("portMapping") or data.get("list") or []
        return [dict(row) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []

    def _native_mapping_spec(self, binding: Dict[str, Any], fresh: bool = False) -> Optional[Dict[str, Any]]:
        mapping_id = _text(binding.get("mappingId"))
        data: Any = None
        snapshot = getattr(self.hub, "ROUTER_CONFIG_SYNC", None)
        frame = snapshot.snapshot("portMappings") if snapshot is not None else {}
        if isinstance(frame, dict):
            data = frame.get("data")
        if fresh and not self._native_rows(data):
            data = self.client.native_port_mapping(True)
        rule = next((row for row in self._native_rows(data) if _text(row.get("ruleName")) == mapping_id), None)
        if not isinstance(rule, dict):
            return None
        return {
            "mappingKind": "native",
            "mappingId": mapping_id,
            "name": _text(rule.get("ruleName")) or mapping_id,
            "addressFamily": "ipv4",
            "address": _ip(rule.get("destIp"), "ipv4"),
            "protocol": _text(rule.get("proto") or "tcp").lower(),
            "targetPort": rule.get("destPort"),
        }

    def _mapping_spec(self, binding: Dict[str, Any], fresh: bool = False) -> Optional[Dict[str, Any]]:
        kind = _text(binding.get("mappingKind") or "relay").lower()
        if kind == "relay":
            return self._relay_mapping_spec(binding)
        if kind == "native":
            return self._native_mapping_spec(binding, fresh=fresh)
        return None

    def resolve(self, binding: Dict[str, Any]) -> Tuple[str, str]:
        target_type = _text(binding.get("targetType"))
        family = _text(binding.get("addressFamily"))
        if target_type != "mapping":
            return "", ""
        mapping = self._mapping_spec(binding)
        if mapping is None:
            return "", _text(binding.get("mappingId"))
        address = _ip(mapping.get("address"), family)
        name = _text(mapping.get("name"))
        if address and _text(binding.get("matchField")) == "ipv6SuffixDest":
            address = _suffix(address)
        return address, name

    def _rule_compatible(self, rule: Optional[Dict[str, Any]], binding: Dict[str, Any]) -> bool:
        if rule is None:
            return False
        if _text(binding.get("targetType")) != "mapping":
            return False
        family = _text(binding.get("addressFamily"))
        field = _text(binding.get("matchField"))
        mapping = self._mapping_spec(binding)
        return bool(mapping) and (
            _text(rule.get("ipVersion")).lower() == family
            and field in self.FIELDS
            and not (family == "ipv4" and field != "destIP")
            and bool(_field_value(field, rule.get(field), family))
            and _text(rule.get("target")).upper() == "ACCEPT"
            and _text(rule.get("direction")).lower() == "forward"
            and _text(rule.get("inIface")).lower() == "wan"
            and _text(rule.get("outIface")).lower() == "lan"
            and _text(mapping.get("addressFamily")) == family
            and _protocol_matches(rule.get("proto"), mapping.get("protocol"))
            and _port_contains(rule.get("destPort"), mapping.get("targetPort"))
        )

    def _state(self, binding: Dict[str, Any], firewall: Any) -> Dict[str, Any]:
        rule = _find_rule(firewall, _text(binding.get("firewallUuid")))
        desired, target_name = self.resolve(binding)
        current = _field_value(
            _text(binding.get("matchField")),
            (rule or {}).get(_text(binding.get("matchField"))),
            _text(binding.get("addressFamily")),
        )
        fingerprint = _rule_fingerprint(rule, _text(binding.get("matchField"))) if rule else ""
        last_applied = _field_value(
            _text(binding.get("matchField")),
            binding.get("lastAppliedValue"),
            _text(binding.get("addressFamily")),
        )
        legacy_scope = _text(binding.get("targetType")) != "mapping"
        manual_drift = bool(
            rule
            and not legacy_scope
            and (
                not _text(binding.get("ruleFingerprint"))
                or not last_applied
                or fingerprint != _text(binding.get("ruleFingerprint"))
                or current != last_applied
            )
        )
        if legacy_scope:
            status = "out_of_scope"
            message = "该旧绑定不属于路由器映射，已停止自动操作"
        elif not _enabled(binding.get("enabled"), True):
            status = "disabled"
            message = "自动跟随已暂停"
        elif _enabled(binding.get("suspended"), False) or manual_drift:
            status = "manual_override"
            message = "检测到人工修改，自动跟随已暂停，不会覆盖当前规则"
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

    def _replace_binding(self, replacement: Dict[str, Any]) -> None:
        firewall_uuid = _text(replacement.get("firewallUuid"))
        rows = [row for row in self.bindings() if _text(row.get("firewallUuid")) != firewall_uuid]
        rows.append(dict(replacement))
        self._save(rows)

    def _suspend(self, binding: Dict[str, Any], reason: str) -> None:
        if _enabled(binding.get("suspended"), False) and _text(binding.get("suspendedReason")) == reason:
            return
        replacement = {
            **binding,
            "suspended": True,
            "suspendedReason": reason,
            "suspendedAt": int(time.time()),
        }
        self._replace_binding(replacement)
        with self.candidate_lock:
            self.candidates.pop(_text(binding.get("firewallUuid")), None)

    def _candidate_confirmed(self, firewall_uuid: str, desired: str) -> bool:
        now = time.monotonic()
        with self.candidate_lock:
            previous = self.candidates.get(firewall_uuid)
            if not isinstance(previous, dict) or _text(previous.get("value")) != desired:
                self.candidates[firewall_uuid] = {"value": desired, "count": 1, "firstSeen": now}
                return False
            previous["count"] = min(self.STABLE_OBSERVATIONS, int(previous.get("count") or 0) + 1)
            return int(previous["count"]) >= self.STABLE_OBSERVATIONS

    def _clear_candidate(self, firewall_uuid: str) -> None:
        with self.candidate_lock:
            self.candidates.pop(firewall_uuid, None)

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
                uuid = _text(binding.get("firewallUuid"))
                if _text(binding.get("targetType")) != "mapping":
                    continue
                if not _enabled(binding.get("enabled"), True) or _enabled(binding.get("suspended"), False):
                    continue
                rule = _find_rule(current, uuid)
                if rule is None:
                    continue
                field = _text(binding.get("matchField"))
                family = _text(binding.get("addressFamily"))
                actual = _field_value(field, rule.get(field), family)
                last_applied = _field_value(field, binding.get("lastAppliedValue"), family)
                fingerprint = _rule_fingerprint(rule, field)
                if (
                    not last_applied
                    or not _text(binding.get("ruleFingerprint"))
                    or actual != last_applied
                    or fingerprint != _text(binding.get("ruleFingerprint"))
                ):
                    self._suspend(binding, "manual_change" if last_applied else "confirmation_required")
                    self.logger.info("firewall automation paused after external change uuid=%s", uuid)
                    return {"ok": True, "changed": False, "suspended": True, "firewallUuid": uuid}
                if not self._rule_compatible(rule, binding):
                    continue
                desired, _target_name = self.resolve(binding)
                if not desired or not actual or actual == desired:
                    if actual == desired:
                        self._clear_candidate(uuid)
                    continue
                if not self._candidate_confirmed(uuid, desired):
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
                updated_rule = _find_rule(verified, uuid)
                replacement = {
                    **binding,
                    "lastAppliedValue": desired,
                    "ruleFingerprint": _rule_fingerprint(updated_rule or payload, field),
                    "lastAppliedAt": int(time.time()),
                    "suspended": False,
                    "suspendedReason": "",
                }
                self._replace_binding(replacement)
                self._clear_candidate(uuid)
                self.logger.info(
                    "firewall address follow updated uuid=%s field=%s from=%s to=%s",
                    uuid,
                    field,
                    actual,
                    desired,
                )
                # One write per cycle limits router pressure and keeps each change
                # independently verified.  Remaining bindings are handled next cycle.
                return {
                    "ok": True,
                    "changed": True,
                    "firewallUuid": uuid,
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
