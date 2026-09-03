"""Persistent, ownership-safe firewall lifecycle for LabRelay PortMap listeners.

PortMap terminates inbound IPv6 traffic on the router itself.  The router Web
firewall therefore needs one INPUT/inbound allow rule per listener, but never a
WAN-to-LAN forwarding rule or a synthetic zone.  This module stays entirely on
the user mutation path and does not participate in Router/Devices realtime.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Dict, Optional

import router_rpc


OWNER = "labprobe-portmap"


def _text(value: Any) -> str:
    return str(value or "").strip()


def _fingerprint(row: Dict[str, Any]) -> str:
    ignored = {"uuid", "stats", "hitCount", "bytes", "packets"}
    body = {key: value for key, value in row.items() if key not in ignored}
    encoded = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class PortMapFirewallService:
    def __init__(self, hub: Any, client: Any):
        self.hub = hub
        self.client = client
        self.controller = router_rpc.RouterController(client)
        self.path = Path(hub.DATA_DIR) / "portmap_firewall.json"
        self.lock = threading.RLock()

    def _document(self) -> Dict[str, Dict[str, Any]]:
        raw = self.hub.load_json(self.path, {})
        rows = raw.get("rules", {}) if isinstance(raw, dict) else {}
        return {
            str(key): dict(value)
            for key, value in rows.items()
            if isinstance(value, dict) and _text(value.get("owner")) == OWNER
        } if isinstance(rows, dict) else {}

    def _save(self, rows: Dict[str, Dict[str, Any]]) -> None:
        self.hub.save_json(self.path, {"owner": OWNER, "rules": rows})

    @staticmethod
    def expected(rule: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ruleName": f"LabProbe PortMap {_text(rule.get('id'))}",
            "direction": "inbound",
            "ipVersion": "ipv6",
            "proto": _text(rule.get("transportProtocol")).lower() or "tcp",
            "srcIP": "",
            "destIP": "",
            "srcPort": "",
            "destPort": str(int(rule.get("listenPort") or 0)),
            "target": "ACCEPT",
            "enable": "1",
            "ipv6SuffixSrc": "",
            "ipv6SuffixDest": "",
            "inIface": "wan",
            "outIface": "",
        }

    @staticmethod
    def _rows(snapshot: Any) -> list[Dict[str, Any]]:
        values = snapshot.get("list", []) if isinstance(snapshot, dict) else []
        return [dict(row) for row in values if isinstance(row, dict)] if isinstance(values, list) else []

    @classmethod
    def _find_uuid(cls, snapshot: Any, uuid: str) -> Optional[Dict[str, Any]]:
        return next((row for row in cls._rows(snapshot) if _text(row.get("uuid")) == uuid), None)

    @classmethod
    def _find_name(cls, snapshot: Any, name: str) -> Optional[Dict[str, Any]]:
        return next((row for row in cls._rows(snapshot) if _text(row.get("ruleName")) == name), None)

    @staticmethod
    def _matches(row: Dict[str, Any], expected: Dict[str, Any]) -> bool:
        return all(_text(row.get(key)) == _text(value) for key, value in expected.items())

    def cached(self, rule_id: str) -> Dict[str, Any]:
        binding = self._document().get(rule_id, {})
        return {
            "state": _text(binding.get("state")) or ("ready" if binding.get("uuid") else "missing"),
            "message": _text(binding.get("message")),
            "owner": _text(binding.get("owner")),
        }

    def ensure(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        rule_id = _text(rule.get("id"))
        if not rule_id:
            raise ValueError("端口映射规则 ID 不能为空")
        expected = self.expected(rule)
        with self.lock:
            bindings = self._document()
            binding = bindings.get(rule_id, {})
            current = self.client.firewall(True)
            existing = self._find_uuid(current, _text(binding.get("uuid")))
            if existing is None:
                same_name = self._find_name(current, expected["ruleName"])
                if same_name is not None:
                    result = {
                        "owner": OWNER,
                        "state": "manual_change",
                        "message": "检测到同名但不属于 LabProbe 的防火墙规则，未接管",
                    }
                    bindings[rule_id] = result
                    self._save(bindings)
                    return result
            if existing is not None:
                current_fingerprint = _fingerprint(existing)
                if _text(binding.get("fingerprint")) != current_fingerprint:
                    result = {**binding, "owner": OWNER, "state": "manual_change", "message": "防火墙规则已被手动修改，未覆盖"}
                    bindings[rule_id] = result
                    self._save(bindings)
                    return result
                if not self._matches(existing, expected):
                    written = self.controller.write_and_verify(
                        "firewall",
                        lambda: self.client.rpc("devConfig.update", "ip_firewall", {"list": [{**expected, "uuid": _text(existing.get("uuid"))}]}),
                        lambda: self.client.firewall(True),
                    )
                    verified = written.get("data") if isinstance(written, dict) else {}
                    existing = self._find_uuid(verified, _text(existing.get("uuid")))
                    if existing is None or not self._matches(existing, expected):
                        result = {**binding, "owner": OWNER, "state": "verify_failed", "message": "端口映射入站规则更新后未能确认"}
                        bindings[rule_id] = result
                        self._save(bindings)
                        return result
                result = {
                    "owner": OWNER,
                    "state": "ready",
                    "uuid": _text(existing.get("uuid")),
                    "fingerprint": _fingerprint(existing),
                }
                bindings[rule_id] = result
                self._save(bindings)
                return result

            if int(current.get("maxLen") or 20) and len(self._rows(current)) >= int(current.get("maxLen") or 20):
                result = {"owner": OWNER, "state": "full", "message": "路由器防火墙规则已满"}
                bindings[rule_id] = result
                self._save(bindings)
                return result
            written = self.controller.write_and_verify(
                "firewall",
                lambda: self.client.rpc("devConfig.add", "ip_firewall", {"list": [expected]}),
                lambda: self.client.firewall(True),
            )
            verified = written.get("data") if isinstance(written, dict) else {}
            created = self._find_name(verified, expected["ruleName"])
            if created is None or not _text(created.get("uuid")) or not self._matches(created, expected):
                result = {"owner": OWNER, "state": "verify_failed", "message": "端口映射入站规则创建后未能确认"}
                bindings[rule_id] = result
                self._save(bindings)
                return result
            result = {
                "owner": OWNER,
                "state": "ready",
                "uuid": _text(created.get("uuid")),
                "fingerprint": _fingerprint(created),
            }
            bindings[rule_id] = result
            self._save(bindings)
            return result

    def remove(self, rule_id: str) -> None:
        with self.lock:
            bindings = self._document()
            binding = bindings.get(rule_id)
            if not binding:
                return
            current = self.client.firewall(True)
            row = self._find_uuid(current, _text(binding.get("uuid")))
            if row is not None and _text(binding.get("fingerprint")) != _fingerprint(row):
                raise ValueError("端口映射防火墙规则已被手动修改；为避免误删，未移除")
            if row is not None:
                written = self.controller.write_and_verify(
                    "firewall",
                    lambda: self.client.rpc("devConfig.del", "ip_firewall", {"uuid": [_text(row.get("uuid"))]}),
                    lambda: self.client.firewall(True),
                )
                verified = written.get("data") if isinstance(written, dict) else {}
                if self._find_uuid(verified, _text(row.get("uuid"))) is not None:
                    raise RuntimeError("端口映射入站规则删除后未能确认")
            bindings.pop(rule_id, None)
            self._save(bindings)

    def snapshot(self, rule_id: str) -> Dict[str, Any]:
        with self.lock:
            bindings = copy.deepcopy(self._document())
            binding = bindings.get(rule_id, {})
            current = self.client.firewall(True) if binding.get("uuid") else {"list": []}
            return {"bindings": bindings, "row": copy.deepcopy(self._find_uuid(current, _text(binding.get("uuid"))))}

    def restore(self, rule_id: str, snapshot: Dict[str, Any]) -> None:
        with self.lock:
            before = copy.deepcopy(snapshot.get("bindings", {}))
            old_binding = before.get(rule_id, {})
            old_row = copy.deepcopy(snapshot.get("row")) if isinstance(snapshot.get("row"), dict) else None
            current = self.client.firewall(True)
            current_binding = self._document().get(rule_id, {})
            existing = self._find_uuid(current, _text(current_binding.get("uuid")))
            if old_row is None and existing is not None and _text(current_binding.get("fingerprint")) == _fingerprint(existing):
                self.controller.write_and_verify(
                    "firewall",
                    lambda: self.client.rpc("devConfig.del", "ip_firewall", {"uuid": [_text(existing.get("uuid"))]}),
                    lambda: self.client.firewall(True),
                )
            elif old_row is not None:
                old_uuid = _text(old_row.get("uuid"))
                existing_old = self._find_uuid(current, old_uuid)
                restored = existing_old
                if existing_old is None:
                    written = self.controller.write_and_verify(
                        "firewall",
                        lambda: self.client.rpc("devConfig.add", "ip_firewall", {"list": [{key: value for key, value in old_row.items() if key not in {"uuid", "stats"}}]}),
                        lambda: self.client.firewall(True),
                    )
                    verified = written.get("data") if isinstance(written, dict) else {}
                    restored = self._find_name(verified, _text(old_row.get("ruleName")))
                elif _fingerprint(existing_old) != _fingerprint(old_row):
                    written = self.controller.write_and_verify(
                        "firewall",
                        lambda: self.client.rpc("devConfig.update", "ip_firewall", {"list": [old_row]}),
                        lambda: self.client.firewall(True),
                    )
                    verified = written.get("data") if isinstance(written, dict) else {}
                    restored = self._find_uuid(verified, old_uuid)
                if restored is None:
                    raise RuntimeError("原有端口映射入站规则恢复后未能确认")
                before[rule_id] = {
                    **old_binding,
                    "owner": OWNER,
                    "state": "ready",
                    "uuid": _text(restored.get("uuid")),
                    "fingerprint": _fingerprint(restored),
                }
            self._save(before)


def install_portmap_firewall(hub: Any, client: Any) -> PortMapFirewallService:
    existing = getattr(hub, "PORTMAP_FIREWALL_SERVICE", None)
    if existing is not None:
        return existing
    service = PortMapFirewallService(hub, client)
    hub.PORTMAP_FIREWALL_SERVICE = service
    return service
