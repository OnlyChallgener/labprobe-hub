"""Bridge broadband credentials without restoring Relay dashboard traffic.

Hub direct RPC is authoritative for router telemetry and terminal data. This
patch first reads the temporary PPPoE credentials through the existing Hub
router session. If a firmware does not expose a complete username/password pair
over eWeb, the lightweight Agent command endpoint wakes the router-local Relay
fallback without uploading dashboard snapshots.

The Agent endpoint supports long polling. In steady state the router keeps one
small request open instead of sending frequent request headers, while credential
refreshes wake it immediately.

Credentials remain memory-only and are never logged, persisted, backed up or
published over MQTT.
"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any, Dict, Iterable, Mapping, Tuple

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


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = _clean_value(value).lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return None


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


def _row_wan_id(row: Mapping[str, Any]) -> str:
    for key in ("wanId", "wan_id", "wan", "ifname", "interface", "name", "id"):
        value = _normalized_key(row.get(key))
        if re.fullmatch(r"wan[0-9]*", value):
            return value
    return ""


def _credential_row(row: Mapping[str, Any], wan_id: str) -> Dict[str, Any] | None:
    """Read one credential object; never borrow a missing field from another."""
    username = ""
    password = ""
    password_present = False
    password_indicated = False
    configured: bool | None = None
    for key, child in row.items():
        normalized = _normalized_key(key)
        if not username and normalized in _USERNAME_KEYS:
            username = _clean_value(child)
        if normalized in _PASSWORD_KEYS:
            password_present = True
            password_indicated = password_indicated or bool(_clean_value(child))
            if not password:
                password = _clean_value(child, secret=True)
        if normalized in {"passwordconfigured", "pppoepasswordconfigured", "credentialset"}:
            configured = _flag(child)
    if password or password_indicated:
        configured = True
    elif password_present and configured is None:
        # A present but empty password is explicitly not configured. An absent
        # password key remains unknown instead of becoming false.
        configured = False
    if not username and not password and configured is None:
        return None
    return {
        "wanId": wan_id,
        "username": username,
        "password": password,
        "passwordConfigured": configured,
    }


def _select_credential_rows(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    selected: Dict[str, Dict[str, Any]] = {}
    scores: Dict[str, Tuple[int, int, int, int]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        wan_id = _row_wan_id(row)
        if wan_id and set(row).issubset({"wanId", "username", "password", "passwordConfigured"}):
            # Re-projecting an already canonical row must not reinterpret its
            # empty placeholder password as an explicitly empty firmware field.
            password = _clean_value(row.get("password"), secret=True)
            clean = {
                "wanId": wan_id,
                "username": _clean_value(row.get("username")),
                "password": password,
                "passwordConfigured": True if password else _flag(row.get("passwordConfigured")),
            }
        else:
            clean = _credential_row(row, wan_id)
        if not wan_id or clean is None:
            continue
        score = (
            1 if clean["username"] and clean["password"] else 0,
            1 if clean["username"] else 0,
            1 if clean["password"] else 0,
            _candidate_score(dict(row)),
        )
        if wan_id not in selected or score > scores[wan_id]:
            selected[wan_id] = clean
            scores[wan_id] = score
    return [selected[key] for key in ("wan", "wan1") if key in selected] + [
        selected[key] for key in selected if key not in {"wan", "wan1"}
    ]


def _default_credential_projection(wans: List[Dict[str, Any]]) -> Dict[str, Any]:
    default = next((row for row in wans if row.get("wanId") == "wan"), {})
    return {
        "username": str(default.get("username") or ""),
        "password": str(default.get("password") or ""),
        "passwordConfigured": default.get("passwordConfigured"),
    }


def _credentials_result(wans: List[Dict[str, Any]], lan_mac: str = "") -> Dict[str, Any]:
    rows = _select_credential_rows(wans)
    return {**_default_credential_projection(rows), "lanMac": lan_mac, "wans": rows}


def _credential_rows_from_payload(payload: Any) -> List[Dict[str, Any]]:
    """Accept WAN-aware pushes, or the legacy top-level default-WAN pair."""
    root = _decode_payload(payload)
    if not isinstance(root, Mapping):
        return []
    raw_wans = root.get("wans")
    if isinstance(raw_wans, list):
        return _select_credential_rows(raw_wans)
    if isinstance(raw_wans, Mapping):
        rows = []
        for wan_id, row in raw_wans.items():
            if isinstance(row, Mapping):
                rows.append({**dict(row), "wanId": str(wan_id)})
        return _select_credential_rows(rows)
    if any(_normalized_key(key) in (_USERNAME_KEYS | _PASSWORD_KEYS | {"passwordconfigured"}) for key in root):
        row = dict(root)
        row.setdefault("wanId", "wan")
        return _select_credential_rows([row])
    return []


def _extract_router_credentials(value: Any) -> Dict[str, Any]:
    """Extract independent, explicitly WAN-scoped credential objects."""
    root = _decode_payload(value)
    rows: List[Dict[str, Any]] = []
    stack: List[Tuple[Any, str]] = [(root, "")]
    while stack:
        node, inherited_id = stack.pop(0)
        if isinstance(node, list):
            stack.extend((item, inherited_id) for item in node)
            continue
        if not isinstance(node, Mapping):
            continue
        wan_id = _row_wan_id(node) or inherited_id
        if wan_id:
            row = _credential_row(node, wan_id)
            if row is not None:
                rows.append(row)
        for key, child in node.items():
            normalized_key = _normalized_key(key)
            child_id = normalized_key if re.fullmatch(r"wan[0-9]*", normalized_key) else ""
            stack.append((child, child_id or wan_id))

    # Legacy firmware may return a bare PPPoE object with no WAN wrapper.
    if not rows and isinstance(root, Mapping):
        marker = " ".join(_clean_value(root.get(key)).lower() for key in ("proto", "protocol", "type"))
        if "pppoe" in marker:
            row = _credential_row(root, "wan")
            if row is not None:
                rows.append(row)

    lan_mac = ""
    for key, child, _parent in _walk(root):
        normalized = _normalized_key(key)
        if normalized in _MAC_KEYS:
            candidate = _clean_value(child).lower().replace("-", ":")
            if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", candidate):
                lan_mac = candidate
                break
    return _credentials_result(rows, lan_mac)


def _coerce_found_credentials(found: Mapping[str, Any]) -> Dict[str, Any]:
    raw_wans = found.get("wans")
    if isinstance(raw_wans, list):
        rows = _select_credential_rows(raw_wans)
    elif found.get("username") or found.get("password") or found.get("passwordConfigured") is not None:
        rows = _select_credential_rows([{
            "wanId": "wan",
            "username": found.get("username", ""),
            "password": found.get("password", ""),
            "passwordConfigured": found.get("passwordConfigured"),
        }])
    else:
        rows = []
    return _credentials_result(rows, _clean_value(found.get("lanMac")))


def _read_direct_credentials(client: Any) -> Dict[str, Any]:
    merged_wans: Dict[str, Dict[str, Any]] = {}
    lan_mac = ""
    loaders = (
        lambda: client.rpc("devConfig.get", "network", no_parse=True),
        lambda: client.rpc("devConfig.get", "network"),
        lambda: (client.dashboard(force=True) or {}).get("network", {}),
    )
    last_error: Exception | None = None
    for loader in loaders:
        try:
            found = _coerce_found_credentials(_extract_router_credentials(loader()))
            if found.get("lanMac") and not lan_mac:
                lan_mac = found["lanMac"]
            for row in found.get("wans", []):
                wan_id = row["wanId"]
                current = merged_wans.get(wan_id)
                # Replace the whole row; username/password are never merged
                # across router responses or WAN objects.
                merged_wans[wan_id] = _select_credential_rows([current, row])[0] if current else dict(row)
            projection = _default_credential_projection(list(merged_wans.values()))
            if projection["username"] and projection["password"] and all(
                row.get("username") and row.get("password") for row in merged_wans.values()
            ):
                return _credentials_result(list(merged_wans.values()), lan_mac)
        except Exception as exc:  # keep trying alternative router wire forms
            last_error = exc
    if not merged_wans and not lan_mac and last_error is not None:
        raise last_error
    return _credentials_result(list(merged_wans.values()), lan_mac)


def _relay_dashboard_ack(self: Any):
    """Compatibility response for already-installed Relay 0.2.9 agents."""
    if not self.hub.check_hook_token():
        return jsonify({"ok": False, "error": "bad agent token"}), 401

    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        ddns_store = getattr(self.hub, "LAB_DDNS", None)
        if ddns_store is not None:
            ddns_store.accept_address(payload.get("ddnsAddress"))
        # WireGuard remains a Relay-owned extension. Preserve that status while
        # continuing to ignore Relay router telemetry/dashboard fields.
        wireguard = payload.get("wireguard")
        if isinstance(wireguard, dict) and hasattr(self.hub, "ROUTER_DASHBOARD_LOCK"):
            with self.hub.ROUTER_DASHBOARD_LOCK:
                self.hub.ROUTER_DASHBOARD_CACHE["wireguard"] = dict(wireguard)
            if hasattr(self.hub, "_persist_router_dashboard_if_due"):
                self.hub._persist_router_dashboard_if_due(force=False)
        # EG 线（BE50 那类）固件的 eWeb RPC 只回零值，agent 的本地 procfs 遥测是
        # App 实时契约的唯一真源。dashboard 缓存仍以 Hub RPC 为准（上面照旧忽略），
        # 但把这份 telemetry 单独喂给实时引擎；引擎自带 eWeb 新鲜让路守卫，
        # 所以 BE72 这类有 eWeb 采样的机器不会被这条降级。
        telemetry = payload.get("telemetry")
        if isinstance(telemetry, dict):
            engine = getattr(self.hub, "ROUTER_REALTIME", None)
            if engine is not None and hasattr(engine, "accept_agent_telemetry"):
                epoch = _safe_int(payload.get("telemetryEpoch"), 0) or int(time.time())
                try:
                    engine.accept_agent_telemetry(telemetry, epoch * 1000)
                except Exception as exc:
                    self.hub.LOGGER.warning("agent dashboard telemetry feed failed: %s", exc)

    dashboard_nonce = 0
    if hasattr(self.hub, "ROUTER_DASHBOARD_LOCK"):
        with self.hub.ROUTER_DASHBOARD_LOCK:
            completed = _safe_int(payload.get("refreshNonce"), 0) if isinstance(payload, dict) else 0
            if completed > _safe_int(self.hub.ROUTER_DASHBOARD_CACHE.get("refreshCompletedNonce"), 0):
                self.hub.ROUTER_DASHBOARD_CACHE["refreshCompletedNonce"] = completed
                self.hub.ROUTER_DASHBOARD_CACHE["refreshCompletedAt"] = self.hub.now_str()
            dashboard_nonce = self.hub.ROUTER_DASHBOARD_REFRESH_NONCE
    credentials_nonce = 0
    if hasattr(self.hub, "ROUTER_CREDENTIALS_LOCK"):
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


def _no_store(response: Any):
    response.headers["Cache-Control"] = "no-store"
    return response


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

    found = _coerce_found_credentials(found)
    wans = found.get("wans", [])
    projection = _default_credential_projection(wans)
    found_username = projection["username"]
    found_password = projection["password"]
    direct_complete = bool(
        wans
        and found_username
        and found_password
        and all(row.get("username") and row.get("password") for row in wans)
    )

    # Do not mark a partial eWeb response complete. Leaving the new nonce
    # outstanding makes the router-local Relay fallback fetch both fields.
    if direct_complete:
        safe = {
            "router": str(previous.get("router") or self.hub.primary_router_name() or "router"),
            "lanMac": str(found.get("lanMac") or previous.get("lanMac") or ""),
            "username": found_username,
            "password": found_password,
            "passwordConfigured": projection["passwordConfigured"],
            "wans": [dict(row) for row in wans],
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

    return _no_store(jsonify({
        "ok": True,
        "refreshNonce": nonce,
        "refreshCompletedNonce": nonce if direct_complete else 0,
        "credentialsAvailable": direct_complete,
        "relayFallbackPending": not direct_complete,
        "message": "credentials refreshed from router" if direct_complete else "waiting for router-local credential fallback",
        "time": self.hub.now_str(),
    }))


def _relay_credentials_push_view(self: Any):
    """Accept only a complete, unmasked router-local credential pair."""
    if not self.hub.check_hook_token():
        return jsonify({"ok": False, "error": "bad agent token"}), 401
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "invalid payload"}), 400

    wans = _credential_rows_from_payload(payload)
    projection = _default_credential_projection(wans)
    completed = _safe_int(payload.get("refreshNonce"), 0)
    if not wans or not projection["username"] or not projection["password"] or completed <= 0 or not all(
        row.get("username") and row.get("password") for row in wans
    ):
        # Never overwrite a prior valid memory snapshot with an empty/masked
        # router response, and never acknowledge the nonce so Relay retries.
        with self.hub.ROUTER_CREDENTIALS_LOCK:
            requested = self.hub.ROUTER_CREDENTIALS_REFRESH_NONCE
        response = jsonify({
            "ok": False,
            "error": "incomplete_credentials",
            "message": "router did not expose complete broadband credentials for every WAN",
            "refreshNonce": requested,
        })
        response.status_code = 422
        return _no_store(response), 422

    safe = {
        "router": _clean_value(payload.get("router")) or self.hub.primary_router_name() or "router",
        "lanMac": _clean_value(payload.get("lanMac")),
        "username": projection["username"],
        "password": projection["password"],
        "passwordConfigured": projection["passwordConfigured"],
        "wans": [dict(row) for row in wans],
        "refreshCompletedNonce": completed,
        "receivedAt": self.hub.now_str(),
        "receivedEpoch": time.time(),
        "source": "router_local_agent",
    }
    with self.hub.ROUTER_CREDENTIALS_LOCK:
        self.hub.ROUTER_CREDENTIALS_CACHE.clear()
        self.hub.ROUTER_CREDENTIALS_CACHE.update(safe)
        requested = self.hub.ROUTER_CREDENTIALS_REFRESH_NONCE
    return _no_store(jsonify({"ok": True, "time": self.hub.now_str(), "refreshNonce": requested}))


def _matches_router(hub: Any, cmd_router: str, target_router: str) -> bool:
    clean = getattr(hub, "clean_saved_value", lambda v: str(v or "").strip())
    cmd_r = clean(cmd_router)
    target_r = clean(target_router)
    if not cmd_r or cmd_r in ("router", "default"):
        return True
    if not target_r or target_r in ("router", "default"):
        return True
    primary_fn = getattr(hub, "primary_router_name", None)
    primary = primary_fn() if callable(primary_fn) else ""
    return (
        cmd_r.lower() == target_r.lower()
        or (primary and cmd_r.lower() == primary.lower())
        or (primary and target_r.lower() == primary.lower())
    )


def _agent_command_snapshot(self: Any, router: str) -> tuple[list[Dict[str, Any]], int, int]:
    data = self.hub.load_json(self.hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": []})
    commands = data.get("commands", []) if isinstance(data, dict) else []
    changed = False
    now_epoch = time.time()
    for row in commands:
        if not isinstance(row, dict) or not _matches_router(self.hub, row.get("router", ""), router) or row.get("state") != "pending":
            continue
        updated_epoch = self.hub.time_to_epoch(row.get("updatedAt") or row.get("createdAt") or 0)
        if updated_epoch > 0 and now_epoch - updated_epoch > 900:
            row.update({
                "state": "failed",
                "updatedAt": self.hub.now_str(),
                "message": "指令等待领取超时，请重新发起",
            })
            changed = True
    if changed:
        self.hub.save_json(self.hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": commands[-100:]})
    pending = [
        row for row in commands
        if isinstance(row, dict) and _matches_router(self.hub, row.get("router", ""), router) and row.get("state") == "pending"
    ][-20:]
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
        self.hub._AGENT_COMMAND_CONDITION = _AGENT_COMMAND_CONDITION
        if "api_router_credentials_refresh" in self.hub.app.view_functions:
            self.hub.app.view_functions["api_router_credentials_refresh"] = self.direct_credentials_refresh_view
        if "api_router_credentials_push" in self.hub.app.view_functions:
            self.hub.app.view_functions["api_router_credentials_push"] = self.relay_credentials_push_view
        if "api_router_agent_commands" in self.hub.app.view_functions:
            self.hub.app.view_functions["api_router_agent_commands"] = self.agent_commands_view
        return result

    cls.ignored_relay_dashboard_push = _relay_dashboard_ack
    cls.direct_credentials_refresh_view = _direct_credentials_refresh_view
    cls.relay_credentials_push_view = _relay_credentials_push_view
    cls.agent_commands_view = _agent_commands_view
    cls.start = start_with_scoped_routes
    cls._labprobe_relay_credentials_patch = True
