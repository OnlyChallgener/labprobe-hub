"""Bridge broadband credentials without restoring Relay dashboard traffic.

Hub direct RPC is authoritative for router telemetry and terminal data. This
patch first reads the temporary PPPoE credentials through the existing Hub
router session. If a firmware does not expose a complete username/password pair
over eWeb, the lightweight Agent command endpoint wakes the router-local Relay
fallback without uploading dashboard snapshots.

The Agent endpoint supports long polling. In steady state the router keeps one
small request open for up to five minutes instead of sending frequent request
headers, while credential refreshes wake it immediately.

Credentials remain memory-only and are never logged, persisted, backed up or
published over MQTT.
"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any, Dict, Iterable, Tuple

from flask import jsonify, request

import router_compat


_USERNAME_KEYS = {
    "username", "user", "account", "pppoeuser", "pppoeusername",
    "pppoeaccount", "broadbandaccount", "broadbanduser",
}
_PASSWORD_KEYS = {
    "password", "passwd", "pwd", "pppoepassword", "pppoepasswd",
    "broadbandpassword",
}
_MAC_KEYS = {"mac", "macaddr", "macaddress", "hwaddr", "lanmac"}
_AGENT_COMMAND_CONDITION = threading.Condition()


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _clean_value(value: Any, *, secret: bool = False) -> str:
    if isinstance(value, (dict, list, tuple, set)) or value is None:
        return ""
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "undefined", "--"}:
        return ""
    if secret:
        compact = re.sub(r"\s+", "", text)
        if compact and all(ch in "*xX•·." for ch in compact):
            return ""
    return text


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _decode_payload(value: Any) -> Any:
    current = value
    for _ in range(6):
        if isinstance(current, str):
            text = current.strip()
            if text.startswith(("{", "[")):
                try:
                    current = json.loads(text)
                    continue
                except Exception:
                    return current
        if isinstance(current, dict) and "data" in current:
            keys = {_normalized_key(key) for key in current}
            if keys.issubset({"data", "code", "id", "error", "rcode", "message", "msg"}):
                current = current.get("data")
                continue
        break
    return current


def _walk(value: Any) -> Iterable[Tuple[str, Any, Dict[str, Any]]]:
    value = _decode_payload(value)
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child, value
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _candidate_score(row: Dict[str, Any]) -> int:
    marker = " ".join(
        _clean_value(row.get(key)).lower()
        for key in ("name", "ifname", "interface", "type", "role", "proto", "protocol", "mode")
    )
    score = 0
    if "pppoe" in marker:
        score += 8
    if "wan" in marker:
        score += 5
    normalized = {_normalized_key(key) for key in row}
    if normalized & _USERNAME_KEYS:
        score += 3
    if normalized & _PASSWORD_KEYS:
        score += 3
    return score


def _extract_router_credentials(value: Any) -> Dict[str, str]:
    """Extract the highest-scoring same-object WAN/PPPoE credential pair."""
    root = _decode_payload(value)
    rows: list[Dict[str, Any]] = []

    def collect(node: Any) -> None:
        node = _decode_payload(node)
        if isinstance(node, dict):
            rows.append(node)
            for child in node.values():
                collect(child)
        elif isinstance(node, list):
            for child in node:
                collect(child)

    collect(root)
    rows.sort(key=_candidate_score, reverse=True)

    username = ""
    password = ""
    lan_mac = ""
    pair_selected = False
    for row in rows:
        local_user = ""
        local_password = ""
        for key, child in row.items():
            normalized = _normalized_key(key)
            if not local_user and normalized in _USERNAME_KEYS:
                local_user = _clean_value(child)
            if not local_password and normalized in _PASSWORD_KEYS:
                local_password = _clean_value(child, secret=True)
            if not lan_mac and normalized in _MAC_KEYS:
                candidate = _clean_value(child).lower().replace("-", ":")
                if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", candidate):
                    lan_mac = candidate
        # Rows are score-sorted; retain the first complete pair but continue
        # scanning so a LAN MAC in a separate object is not lost.
        if local_user and local_password and not pair_selected:
            username, password = local_user, local_password
            pair_selected = True
        elif not pair_selected:
            if local_user and not username:
                username = local_user
            if local_password and not password:
                password = local_password

    if not username or not password:
        for key, child, _parent in _walk(root):
            normalized = _normalized_key(key)
            if not username and normalized in _USERNAME_KEYS:
                username = _clean_value(child)
            elif not password and normalized in _PASSWORD_KEYS:
                password = _clean_value(child, secret=True)
            if username and password:
                break

    return {"username": username, "password": password, "lanMac": lan_mac}


def _read_direct_credentials(client: Any) -> Dict[str, str]:
    merged = {"username": "", "password": "", "lanMac": ""}
    loaders = (
        lambda: client.rpc("devConfig.get", "network", no_parse=True),
        lambda: client.rpc("devConfig.get", "network"),
        lambda: (client.dashboard(force=True) or {}).get("network", {}),
    )
    last_error: Exception | None = None
    for loader in loaders:
        try:
            found = _extract_router_credentials(loader())
            for key in merged:
                if not merged[key] and found.get(key):
                    merged[key] = found[key]
            if merged["username"] and merged["password"]:
                return merged
        except Exception as exc:  # keep trying alternative router wire forms
            last_error = exc
    if not any(merged.values()) and last_error is not None:
        raise last_error
    return merged


def _relay_dashboard_ack(self: Any):
    """Compatibility response for already-installed Relay 0.2.9 agents."""
    if not self.hub.check_hook_token():
        return jsonify({"ok": False, "error": "bad agent token"}), 401

    with self.hub.ROUTER_DASHBOARD_LOCK:
        dashboard_nonce = self.hub.ROUTER_DASHBOARD_REFRESH_NONCE
    with self.hub.ROUTER_CREDENTIALS_LOCK:
        credentials_nonce = self.hub.ROUTER_CREDENTIALS_REFRESH_NONCE

    return jsonify({
        "ok": True,
        "ignored": True,
        "source": "router_rpc",
        "message": "dashboard telemetry is supplied directly by Hub",
        "refreshNonce": dashboard_nonce,
        "credentialsRefreshNonce": credentials_nonce,
        "time": self.hub.now_str(),
    })


def _direct_credentials_refresh_view(self: Any):
    if not self.hub.check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    with self.hub.ROUTER_CREDENTIALS_LOCK:
        self.hub.ROUTER_CREDENTIALS_REFRESH_NONCE += 1
        nonce = self.hub.ROUTER_CREDENTIALS_REFRESH_NONCE
        previous = dict(self.hub.ROUTER_CREDENTIALS_CACHE)

    try:
        found = _read_direct_credentials(self.client)
    except Exception as exc:
        # Never include router payloads or secret-bearing exception bodies in logs.
        self.logger.warning("router credential direct refresh failed type=%s", type(exc).__name__)
        found = {"username": "", "password": "", "lanMac": ""}

    found_username = str(found.get("username") or "")
    found_password = str(found.get("password") or "")
    direct_complete = bool(found_username and found_password)

    # Do not mark a partial eWeb response complete. Leaving the new nonce
    # outstanding makes the router-local Relay fallback fetch both fields.
    if direct_complete:
        safe = {
            "router": str(previous.get("router") or self.hub.primary_router_name() or "router"),
            "lanMac": str(found.get("lanMac") or previous.get("lanMac") or ""),
            "username": found_username,
            "password": found_password,
            "refreshCompletedNonce": nonce,
            "receivedAt": self.hub.now_str(),
            "receivedEpoch": time.time(),
            "source": "hub_router_rpc",
        }
        with self.hub.ROUTER_CREDENTIALS_LOCK:
            self.hub.ROUTER_CREDENTIALS_CACHE.clear()
            self.hub.ROUTER_CREDENTIALS_CACHE.update(safe)

    # Wake the single long-polling Relay immediately. For a direct-complete
    # result it advances its nonce without re-reading the router; otherwise it
    # performs the local fallback and pushes the complete pair.
    with _AGENT_COMMAND_CONDITION:
        _AGENT_COMMAND_CONDITION.notify_all()

    return jsonify({
        "ok": True,
        "refreshNonce": nonce,
        "refreshCompletedNonce": nonce if direct_complete else 0,
        "credentialsAvailable": direct_complete,
        "relayFallbackPending": not direct_complete,
        "message": "credentials refreshed from router" if direct_complete else "waiting for router-local credential fallback",
        "time": self.hub.now_str(),
    })


def _agent_command_snapshot(self: Any, router: str) -> tuple[list[Dict[str, Any]], int, int]:
    data = self.hub.load_json(self.hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": []})
    commands = data.get("commands", []) if isinstance(data, dict) else []
    pending = [
        row for row in commands
        if isinstance(row, dict) and row.get("router") == router and row.get("state") == "pending"
    ][:5]
    with self.hub.ROUTER_CREDENTIALS_LOCK:
        requested = self.hub.ROUTER_CREDENTIALS_REFRESH_NONCE
        completed = _safe_int(self.hub.ROUTER_CREDENTIALS_CACHE.get("refreshCompletedNonce"), 0)
    return pending, requested, completed


def _agent_commands_view(self: Any):
    """Return commands with a low-traffic, credential-aware long poll."""
    if not self.hub.check_hook_token():
        return jsonify({"ok": False, "error": "bad agent token"}), 401
    router = self.hub.clean_saved_value(request.args.get("router")) or self.hub.primary_router_name()
    since_credentials = max(0, _safe_int(request.args.get("credentialsSince"), 0))
    wait_seconds = min(300, max(0, _safe_int(request.args.get("wait"), 0)))

    with _AGENT_COMMAND_CONDITION:
        pending, requested, completed = _agent_command_snapshot(self, router)
        if wait_seconds and not pending and requested <= since_credentials:
            _AGENT_COMMAND_CONDITION.wait(timeout=wait_seconds)
            pending, requested, completed = _agent_command_snapshot(self, router)

    return jsonify({
        "ok": True,
        "commands": pending,
        "credentialsRefreshNonce": requested,
        "credentialsCompletedNonce": completed,
        "time": self.hub.now_str(),
    })


def install_router_relay_credentials_patch() -> None:
    cls = router_compat.RouterRpcCompatibilitySync
    if getattr(cls, "_labprobe_relay_credentials_patch", False):
        return

    original_start = cls.start

    def start_with_scoped_routes(self: Any) -> Any:
        result = original_start(self)
        if "api_router_credentials_refresh" in self.hub.app.view_functions:
            self.hub.app.view_functions["api_router_credentials_refresh"] = self.direct_credentials_refresh_view
        if "api_router_agent_commands" in self.hub.app.view_functions:
            self.hub.app.view_functions["api_router_agent_commands"] = self.agent_commands_view
        return result

    cls.ignored_relay_dashboard_push = _relay_dashboard_ack
    cls.direct_credentials_refresh_view = _direct_credentials_refresh_view
    cls.agent_commands_view = _agent_commands_view
    cls.start = start_with_scoped_routes
    cls._labprobe_relay_credentials_patch = True
