"""STUN middle-port policy without changing Router Core or realtime paths.

PortMap/IPv6 keeps its own Hub range. STUN may use a user-selected local
middle port (1024-65535); when the APP sends 0 Hub assigns a stable automatic
port from 30000-32767. Legacy STUN rules still using 20000-20020 are migrated
once at Hub startup so they no longer collide with ordinary PortMap rules.
"""
from __future__ import annotations

import secrets
import time
import types
from typing import Any, Dict, Iterable

STUN_USER_PORT_MIN = 1024
STUN_USER_PORT_MAX = 65535
STUN_AUTO_PORT_MIN = 30000
STUN_AUTO_PORT_MAX = 32767
STUN_LEGACY_PORT_MIN = 20000
STUN_LEGACY_PORT_MAX = 20020


def install_stun_port_config_patch(hub: Any) -> None:
    stun = getattr(hub, "STUN_SERVICE", None)
    if stun is None or getattr(stun, "_labprobe_user_stun_port_v2", False):
        return

    # Suppress the older migration block in labrelay_sync_patch. This patch is
    # now the single owner of STUN middle-port allocation/migration semantics.
    stun._labprobe_port_pool_v2 = True

    original_used_ports = stun._used_ports
    original_clean_rule = stun.clean_rule
    original_ensure_firewall = stun.ensure_firewall

    def available_port(
        protocol: str,
        excluding: str = "",
        extra_used: Iterable[int] = (),
    ) -> int:
        used = set(original_used_ports(protocol, excluding)) | {int(port) for port in extra_used if int(port) > 0}
        span = STUN_AUTO_PORT_MAX - STUN_AUTO_PORT_MIN + 1
        start = secrets.randbelow(span)
        for offset in range(span):
            port = STUN_AUTO_PORT_MIN + ((start + offset) % span)
            if port not in used:
                return port
        raise ValueError("STUN 自动端口池已用完，请手动指定中间端口")

    def allocated_port(self: Any, protocol: str, excluding: str = "") -> int:
        return available_port(protocol, excluding)

    # Install the allocator first because the original cleaner dynamically
    # calls self._allocated_port for new rules or protocol conflicts.
    stun._allocated_port = types.MethodType(allocated_port, stun)

    def clean_rule(self: Any, payload: Dict[str, Any], old: Dict[str, Any] | None = None) -> Dict[str, Any]:
        incoming = dict(payload or {})
        cleaned = original_clean_rule(incoming, old)
        has_port = "listenPort" in incoming
        requested_raw = incoming.get("listenPort") if has_port else None
        try:
            requested = int(requested_raw or 0)
        except (TypeError, ValueError):
            requested = 0

        protocol = str(cleaned.get("transportProtocol") or "TCP").strip().upper()
        rule_id = str(cleaned.get("id") or "").strip()
        used = set(original_used_ports(protocol, rule_id))

        if has_port and requested > 0:
            if not STUN_USER_PORT_MIN <= requested <= STUN_USER_PORT_MAX:
                raise ValueError(f"中间端口必须在 {STUN_USER_PORT_MIN}-{STUN_USER_PORT_MAX}")
            if requested in used:
                raise ValueError(f"中间端口 {requested} 已被其他 {protocol} 规则占用")
            cleaned["listenPort"] = requested
        elif has_port:
            # Explicit 0/blank means automatic mode. Keep a current automatic
            # port if it is still valid; otherwise allocate from 30000-32767.
            current = int(cleaned.get("listenPort") or 0)
            if not (STUN_AUTO_PORT_MIN <= current <= STUN_AUTO_PORT_MAX and current not in used):
                cleaned["listenPort"] = self._allocated_port(protocol, rule_id)
        return cleaned

    stun.clean_rule = types.MethodType(clean_rule, stun)

    # Router-self STUN is Relay-proxy mode. If the user edits its middle port,
    # update only the fingerprint-owned firewall rule instead of failing the
    # normal verification step. Manually changed rules remain protected.
    def ensure_firewall(self: Any, rule: Dict[str, Any]) -> Dict[str, Any]:
        if str(rule.get("firewallMode") or "").strip().lower() == "wireguard_lan_forward":
            return original_ensure_firewall(rule)
        try:
            from stun_service import _rule_fingerprint

            expected = self._expected_firewall(rule)
            bindings = self._firewall_bindings()
            binding = bindings.get(rule["id"], {})
            firewall_uuid = str(binding.get("uuid") or "").strip()
            if firewall_uuid and binding.get("fingerprint"):
                current = self.client.firewall(True)
                existing = self._find_firewall(current, firewall_uuid)
                if (
                    existing is not None
                    and binding.get("fingerprint") == _rule_fingerprint(existing)
                    and not self._firewall_matches(existing, expected)
                ):
                    written = self.controller.write_and_verify(
                        "firewall",
                        lambda: self.client.rpc(
                            "devConfig.update",
                            "ip_firewall",
                            {"old": existing, "new": expected},
                        ),
                        lambda: self.client.firewall(True),
                    )
                    verified = written.get("data") if isinstance(written, dict) else {}
                    rows = verified.get("list", []) if isinstance(verified, dict) else []
                    updated = next(
                        (
                            dict(row)
                            for row in rows
                            if isinstance(row, dict) and self._firewall_matches(row, expected)
                        ),
                        None,
                    )
                    if updated is None or not str(updated.get("uuid") or "").strip():
                        return {"state": "verify_failed", "message": "本机入站规则更新后未能确认"}
                    result = {
                        "owner": "labprobe-stun",
                        "state": "ready",
                        "uuid": str(updated.get("uuid") or "").strip(),
                        "fingerprint": _rule_fingerprint(updated),
                    }
                    bindings[rule["id"]] = result
                    self._save_firewall_bindings(bindings)
                    return result
        except Exception as error:
            hub.LOGGER.warning("STUN owned firewall middle-port update deferred: %s", error)
        return original_ensure_firewall(rule)

    stun.ensure_firewall = types.MethodType(ensure_firewall, stun)

    # One-time desired-state migration. Do not perform router writes here: the
    # existing STUN reconciliation/status path updates native mappings/firewall.
    # Enabled rules are queued for normal Agent reconciliation immediately.
    document = stun._document()
    rows = [dict(row) for row in document.get("rules", []) if isinstance(row, dict)]
    migrated = []
    reserved: dict[str, set[int]] = {}
    changed = False
    for raw in rows:
        rule = dict(raw)
        if str(rule.get("kind") or "").strip().lower() != "stun":
            migrated.append(rule)
            continue
        protocol = str(rule.get("transportProtocol") or "TCP").strip().upper()
        occupied = reserved.setdefault(protocol, set())
        old_port = int(rule.get("listenPort") or 0)
        needs_migration = (
            STUN_LEGACY_PORT_MIN <= old_port <= STUN_LEGACY_PORT_MAX
            or old_port <= 0
            or old_port in occupied
        )
        if needs_migration:
            rule_id = str(rule.get("id") or "").strip()
            rule["listenPort"] = available_port(protocol, rule_id, occupied)
            rule["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            changed = True
        occupied.add(int(rule.get("listenPort") or 0))
        migrated.append(rule)

    if changed:
        saved = stun._save_rules(migrated)
        for rule in migrated:
            if str(rule.get("kind") or "").strip().lower() == "stun" and bool(rule.get("enabled")):
                stun.queue("upsert", {"rule": rule}, revision=saved["revision"])
        hub.LOGGER.info(
            "Migrated legacy STUN middle ports %s-%s to automatic pool %s-%s",
            STUN_LEGACY_PORT_MIN,
            STUN_LEGACY_PORT_MAX,
            STUN_AUTO_PORT_MIN,
            STUN_AUTO_PORT_MAX,
        )

    stun._labprobe_user_stun_port_v1 = True
    stun._labprobe_user_stun_port_v2 = True
    hub.LOGGER.info(
        "STUN middle-port policy enabled user=%s-%s auto=%s-%s",
        STUN_USER_PORT_MIN,
        STUN_USER_PORT_MAX,
        STUN_AUTO_PORT_MIN,
        STUN_AUTO_PORT_MAX,
    )
