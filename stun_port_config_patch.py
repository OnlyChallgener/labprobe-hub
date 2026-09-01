"""STUN middle-port policy without changing Router Core or realtime paths.

PortMap/IPv6 keeps its own Hub range. STUN may use a user-selected local
middle port (1024-65535); when omitted, Hub chooses a stable random port from
30000-32767. The upstream NAT still owns the public/external port.
"""
from __future__ import annotations

import secrets
import types
from typing import Any, Dict

STUN_USER_PORT_MIN = 1024
STUN_USER_PORT_MAX = 65535
STUN_AUTO_PORT_MIN = 30000
STUN_AUTO_PORT_MAX = 32767


def install_stun_port_config_patch(hub: Any) -> None:
    stun = getattr(hub, "STUN_SERVICE", None)
    if stun is None or getattr(stun, "_labprobe_user_stun_port_v1", False):
        return

    # Suppress the older temporary STUN pool migration in labrelay_sync_patch.
    # Existing rules keep their current middle port until the user changes it.
    stun._labprobe_port_pool_v2 = True

    original_used_ports = stun._used_ports
    original_clean_rule = stun.clean_rule
    original_ensure_firewall = stun.ensure_firewall

    def allocated_port(self: Any, protocol: str, excluding: str = "") -> int:
        used = set(original_used_ports(protocol, excluding))
        span = STUN_AUTO_PORT_MAX - STUN_AUTO_PORT_MIN + 1
        start = secrets.randbelow(span)
        for offset in range(span):
            port = STUN_AUTO_PORT_MIN + ((start + offset) % span)
            if port not in used:
                return port
        raise ValueError("STUN 自动端口池已用完，请手动指定中间端口")

    # Install the allocator first because the original cleaner dynamically
    # calls self._allocated_port for new rules.
    stun._allocated_port = types.MethodType(allocated_port, stun)

    def clean_rule(self: Any, payload: Dict[str, Any], old: Dict[str, Any] | None = None) -> Dict[str, Any]:
        incoming = dict(payload or {})
        cleaned = original_clean_rule(incoming, old)
        requested_raw = incoming.get("listenPort") if "listenPort" in incoming else None
        try:
            requested = int(requested_raw or 0)
        except (TypeError, ValueError):
            requested = 0

        # 0/blank means automatic assignment for a new rule and "keep current"
        # for an existing rule. A positive value is an explicit middle port.
        if requested > 0:
            if not STUN_USER_PORT_MIN <= requested <= STUN_USER_PORT_MAX:
                raise ValueError(f"中间端口必须在 {STUN_USER_PORT_MIN}-{STUN_USER_PORT_MAX}")
            protocol = str(cleaned.get("transportProtocol") or "TCP").strip().upper()
            rule_id = str(cleaned.get("id") or "").strip()
            if requested in set(original_used_ports(protocol, rule_id)):
                raise ValueError(f"中间端口 {requested} 已被其他 {protocol} 规则占用")
            cleaned["listenPort"] = requested
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
    stun._labprobe_user_stun_port_v1 = True
    hub.LOGGER.info(
        "STUN middle-port policy enabled user=%s-%s auto=%s-%s",
        STUN_USER_PORT_MIN,
        STUN_USER_PORT_MAX,
        STUN_AUTO_PORT_MIN,
        STUN_AUTO_PORT_MAX,
    )
