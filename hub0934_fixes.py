"""Hub 0.9.34 canonical device and port-map runtime corrections.

This patch is intentionally small and installed after the existing Hub/Relay patches.
It keeps one current record per MAC for every device view, protects a valid port-map
``startedAt`` from sparse status samples, normalizes permanent-rule fields before
reconciliation, prunes redundant queued upserts, and narrows the router-credential
read endpoint to APP_TOKEN only.
"""
from __future__ import annotations

from typing import Any, Dict, List
from flask import jsonify, request


PORTMAP_COMPARE_KEYS = (
    "enabled",
    "mode",
    "listenPort",
    "targetMode",
    "targetIpv4",
    "targetIpv6",
    "targetIpv6Suffix",
    "targetMac",
    "targetPort",
    "transportProtocol",
    "expiresAt",
    "leaseSeconds",
    "maxConnections",
    "idleTimeoutSec",
)
PORTMAP_INTEGER_KEYS = {
    "listenPort",
    "targetPort",
    "leaseSeconds",
    "maxConnections",
    "idleTimeoutSec",
}


def _clean(hub: Any, value: Any) -> str:
    return hub.clean_saved_value(value)


def _overlay_non_empty(hub: Any, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Overlay newer values while refusing blank fields to erase useful history."""
    out = dict(base or {})
    for key, value in (overlay or {}).items():
        if _clean(hub, value) or isinstance(value, bool) or value == 0:
            out[key] = value
        elif key not in out:
            out[key] = value
    return out


def _device_map(hub: Any, rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {
        hub.norm_mac(row.get("mac")): dict(row)
        for row in (rows or [])
        if isinstance(row, dict) and hub.norm_mac(row.get("mac"))
    }


def canonical_watched_devices(hub: Any, online_devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build watched cards from one canonical record per MAC.

    Authority order is previous watched < durable archive < current online snapshot.
    Watched configuration may override only the display name; it never overwrites
    traffic, IPv6, signal, last-seen, or offline timestamps.
    """
    configured = hub.cfg_get("watched_devices", []) or []
    state = hub.load_json(hub.DEVICES_FILE, {})
    previous = state.get("watched", []) if isinstance(state, dict) else []
    previous_by_mac = _device_map(hub, previous if isinstance(previous, list) else [])
    archive = hub.load_device_archive()
    online_by_mac = _device_map(hub, online_devices)
    result: List[Dict[str, Any]] = []

    for config in configured if isinstance(configured, list) else []:
        if not isinstance(config, dict):
            continue
        mac = hub.norm_mac(config.get("mac"))
        if not mac:
            continue
        row = _overlay_non_empty(hub, previous_by_mac.get(mac, {}), archive.get(mac, {}))
        online = online_by_mac.get(mac)
        if online is not None:
            row = _overlay_non_empty(hub, row, online)
            row["online"] = True
            row["offlineAt"] = None
            row["lastSeenAt"] = _clean(hub, online.get("lastSeenAt")) or hub.now_str()
            if not _clean(hub, row.get("onlineSince")):
                row["onlineSince"] = hub.now_str()
        else:
            row["online"] = False
            last_ip = _clean(hub, row.get("lastIp") or row.get("ip"))
            row["lastIp"] = last_ip
            row["ip"] = None
            row["offlineAt"] = _clean(hub, row.get("offlineAt") or row.get("archivedAt"))
            row["lastSeenAt"] = _clean(hub, row.get("lastSeenAt")) or row["offlineAt"]
        row["mac"] = mac
        alias = _clean(hub, config.get("name"))
        if alias:
            row["name"] = alias
        result.append(hub.hydrate_device_with_archive(row, archive))
    return result


def _normalize_portmap_payload(hub: Any, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize sparse Relay state without manufacturing a new runtime start."""
    if not isinstance(payload, dict):
        return payload
    desired = {
        _clean(hub, row.get("id")): row
        for row in hub._load_portmap_rules()
        if isinstance(row, dict) and _clean(hub, row.get("id"))
    }
    previous_document = hub.load_json(hub.PORTMAP_ROUTER_STATUS_FILE, {})
    previous_runtime = hub._portmap_runtime_map(previous_document if isinstance(previous_document, dict) else {})
    rows = payload.get("rules")
    if not isinstance(rows, list):
        return payload

    for item in rows:
        if not isinstance(item, dict):
            continue
        local_rule = item.get("rule") if isinstance(item.get("rule"), dict) else {}
        runtime = item.get("runtime") if isinstance(item.get("runtime"), dict) else {}
        rule_id = _clean(hub, local_rule.get("id") or runtime.get("id"))
        expected = desired.get(rule_id, {})

        # leaseSeconds is Hub scheduling metadata. Older Relay versions omit it;
        # absence must compare equal to the canonical zero used by permanent rules.
        if "leaseSeconds" not in local_rule:
            local_rule["leaseSeconds"] = max(0, hub.to_int(expected.get("leaseSeconds"), 0))
        item["rule"] = local_rule

        old_runtime = previous_runtime.get(rule_id, {})
        state = _clean(hub, runtime.get("state"))
        if state == "running" and hub._portmap_epoch(runtime.get("startedAt")) is None:
            stable_started = hub._portmap_epoch(old_runtime.get("startedAt"))
            if stable_started is not None:
                runtime["startedAt"] = stable_started
        item["runtime"] = runtime
    return payload


def _portmap_value(hub: Any, row: Dict[str, Any], key: str) -> Any:
    value = row.get(key)
    if key == "enabled":
        return bool(value)
    if key in PORTMAP_INTEGER_KEYS:
        return max(0, hub.to_int(value, 0))
    if key == "expiresAt":
        return hub._portmap_epoch(value)
    if key == "transportProtocol":
        return _clean(hub, value or "TCP").upper()
    return _clean(hub, value)


def _portmap_rules_equal(hub: Any, expected: Dict[str, Any], local: Dict[str, Any]) -> bool:
    if not isinstance(expected, dict) or not isinstance(local, dict):
        return False
    return all(_portmap_value(hub, expected, key) == _portmap_value(hub, local, key) for key in PORTMAP_COMPARE_KEYS)


def _prune_redundant_portmap_commands(hub: Any) -> int:
    """Close old duplicate upserts before an already-running Relay receives them.

    This protects the first startup after the fix as well: a command queued by an
    older Hub revision is marked complete when the persisted Relay status already
    proves the same rule is running with an equivalent normalized configuration.
    """
    desired = {
        _clean(hub, row.get("id")): row
        for row in hub._load_portmap_rules()
        if isinstance(row, dict) and _clean(hub, row.get("id"))
    }
    status_document = hub.load_json(hub.PORTMAP_ROUTER_STATUS_FILE, {})
    status_payload = status_document.get("status") if isinstance(status_document, dict) and isinstance(status_document.get("status"), dict) else status_document
    if not isinstance(status_payload, dict):
        return 0
    _normalize_portmap_payload(hub, status_payload)

    local_rules: Dict[str, Dict[str, Any]] = {}
    local_runtime: Dict[str, Dict[str, Any]] = {}
    for item in status_payload.get("rules", []) if isinstance(status_payload.get("rules"), list) else []:
        if not isinstance(item, dict):
            continue
        rule = item.get("rule") if isinstance(item.get("rule"), dict) else {}
        runtime = item.get("runtime") if isinstance(item.get("runtime"), dict) else {}
        rule_id = _clean(hub, rule.get("id") or runtime.get("id"))
        if rule_id:
            local_rules[rule_id] = rule
            local_runtime[rule_id] = runtime

    document = hub.load_json(hub.PORTMAP_COMMANDS_FILE, {"commands": []})
    commands = document.get("commands", []) if isinstance(document, dict) else []
    if not isinstance(commands, list):
        return 0
    changed = 0
    for command in commands:
        if not isinstance(command, dict) or command.get("status") not in {"pending", "delivered"} or command.get("action") != "upsert":
            continue
        payload = command.get("payload") if isinstance(command.get("payload"), dict) else {}
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        rule_id = _clean(hub, rule.get("id"))
        runtime = local_runtime.get(rule_id, {})
        if (
            rule_id
            and bool(desired.get(rule_id, {}).get("enabled"))
            and _clean(hub, runtime.get("state")) == "running"
            and hub._portmap_epoch(runtime.get("startedAt")) is not None
            and _portmap_rules_equal(hub, desired.get(rule_id, {}), local_rules.get(rule_id, {}))
        ):
            command.update({
                "status": "done",
                "result": {"ok": True, "unchanged": True, "message": "already synchronized"},
                "finishedAt": hub.now_str(),
                "finishedEpoch": hub.to_int(getattr(hub, "time", None).time() if getattr(hub, "time", None) else 0, 0),
            })
            changed += 1
    if changed:
        hub.save_json(hub.PORTMAP_COMMANDS_FILE, {"commands": commands})
    return changed


def install_hub0934_fixes(hub: Any) -> None:
    if getattr(hub, "HUB0934_FIXES_INSTALLED", False):
        return

    original_build_sync_snapshot = hub.build_sync_snapshot

    def build_sync_snapshot() -> Dict[str, Any]:
        root = original_build_sync_snapshot()
        devices = root.get("devices") if isinstance(root.get("devices"), dict) else {}
        online = devices.get("online") if isinstance(devices.get("online"), list) else []
        archive = hub.load_device_archive()
        watched = canonical_watched_devices(hub, online)
        offline = hub.archived_offline_devices(online, archive)
        devices.update({"online": online, "offline": offline, "watched": watched})
        root["devices"] = devices
        return root

    hub.build_sync_snapshot = build_sync_snapshot

    def build_watched_devices(
        online: List[Dict[str, Any]],
        *,
        emit_events: bool = True,
    ) -> List[Dict[str, Any]]:
        # ``canonical_watched_devices`` is projection-only and never emits
        # transition events. Keep the current Hub helper signature so the
        # Router Core durable writer can explicitly disable legacy emission.
        del emit_events
        return canonical_watched_devices(hub, online)

    hub.build_watched_devices = build_watched_devices

    def api_devices() -> Any:
        if not hub.check_read_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        state = hub.load_json(hub.DEVICES_FILE, {"online": [], "watched": [], "updatedAt": None})
        archive = hub.load_device_archive()
        online = [hub.hydrate_device_with_archive(row, archive) for row in (state.get("online", []) or [])]
        view = request.args.get("view", "watched")
        if view == "online":
            items = online
        elif view == "offline":
            items = hub.archived_offline_devices(online, archive)
        else:
            items = canonical_watched_devices(hub, online)
        return jsonify({
            "ok": True,
            "updatedAt": state.get("updatedAt"),
            "devices": items,
            "onlineDeviceCount": state.get("onlineDeviceCount", len(online)),
            "ipv6Hydrated": True,
            "ipv6NeighborCount": sum(1 for value in archive.values() if hub.normalize_ipv6_list(value.get("ipv6List") or [])),
        })

    hub.app.view_functions["api_devices"] = api_devices

    original_portmap_status = hub.app.view_functions.get("api_router_portmap_status")
    if original_portmap_status is not None:
        def api_router_portmap_status(*args: Any, **kwargs: Any) -> Any:
            payload = request.get_json(silent=True)
            if isinstance(payload, dict):
                _normalize_portmap_payload(hub, payload)
            return original_portmap_status(*args, **kwargs)
        hub.app.view_functions["api_router_portmap_status"] = api_router_portmap_status

    original_credentials = hub.app.view_functions.get("api_router_credentials")
    if original_credentials is not None:
        def api_router_credentials(*args: Any, **kwargs: Any) -> Any:
            if not hub.check_app_token():
                return jsonify({"ok": False, "error": "unauthorized"}), 401
            return original_credentials(*args, **kwargs)
        hub.app.view_functions["api_router_credentials"] = api_router_credentials

    # Repair stale watched copies immediately. This is idempotent and writes only
    # when the resulting canonical list differs from the current document.
    state = hub.load_json(hub.DEVICES_FILE, {"online": [], "watched": [], "updatedAt": None})
    if isinstance(state, dict):
        online = state.get("online", []) if isinstance(state.get("online"), list) else []
        repaired = canonical_watched_devices(hub, online)
        if repaired != (state.get("watched") if isinstance(state.get("watched"), list) else []):
            state["watched"] = repaired
            state["updatedAt"] = hub.now_str()
            hub.save_json(hub.DEVICES_FILE, state)

    pruned = _prune_redundant_portmap_commands(hub)
    hub.HUB0934_FIXES_INSTALLED = True
    hub.LOGGER.info(
        "Hub canonical devices, stable port-map time and credential scope enabled; pruned=%s",
        pruned,
    )
