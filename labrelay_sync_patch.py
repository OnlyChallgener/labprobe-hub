"""Authoritative LabRelay presence and runtime state for Hub 0.9.33.

Hub is the only state authority between the APP and LabRelay.  Desired rules,
daemon runtime, and Agent presence are intentionally separate documents.  Every
receipt is ordered by a Hub-generated monotonic revision, never client clocks or
HTTP completion order.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List

from flask import jsonify, request


def install_labrelay_sync_patch(hub: Any) -> None:
    if getattr(hub, "LABRELAY_SYNC_PATCHED", False):
        return

    lock = threading.RLock()
    original_portmaps = hub.app.view_functions.get("api_portmaps")
    if original_portmaps is None:
        raise RuntimeError("api_portmaps endpoint is required")

    def clean(value: Any) -> str:
        return hub.clean_saved_value(value)

    def number(value: Any) -> int:
        return max(0, hub.to_int(value, 0))

    def router_name(value: Any = "") -> str:
        return hub._canonical_portmap_router(value)

    def statuses() -> Dict[str, Any]:
        value = hub.load_json(hub.AGENT_STATUS_FILE, {})
        return value if isinstance(value, dict) else {}

    def runtime_document() -> Dict[str, Any]:
        value = hub.load_json(hub.PORTMAP_ROUTER_STATUS_FILE, {})
        return value if isinstance(value, dict) else {}

    def presence(router: str = "") -> Dict[str, Any]:
        router = router_name(router)
        heartbeat: Dict[str, Any] = {}
        for candidate_router, candidate in statuses().items():
            if (
                isinstance(candidate, dict)
                and router_name(candidate_router) == router
                and number(candidate.get("lastSeenEpoch")) >= number(heartbeat.get("lastSeenEpoch"))
            ):
                heartbeat = candidate
        runtime = runtime_document()
        same_router = router_name(runtime.get("router")) == router
        heartbeat_seen = number(heartbeat.get("lastSeenEpoch"))
        runtime_seen = number(runtime.get("receivedEpoch")) if same_router else 0
        seen = max(heartbeat_seen, runtime_seen)
        now = int(time.time())
        age = max(0, now - seen) if seen else 0
        online_grace = 12
        stale_grace = 30
        state = "online" if seen and age <= online_grace else ("stale" if seen and age <= stale_grace else "offline")
        return {
            "router": router,
            "agentOnline": state == "online",
            "agentState": state,
            "agentLastSeenAt": clean(heartbeat.get("lastSeenAt") or runtime.get("receivedAt")),
            "agentLastSeenEpoch": seen,
            "agentAgeSeconds": age,
            "agentVersion": clean(heartbeat.get("version")),
            "agentArchitecture": clean(heartbeat.get("architecture")),
            "agentRevision": max(number(heartbeat.get("revision")), number(runtime.get("presenceRevision")) if same_router else 0),
            "serverTime": now,
        }

    def reconcile(payload: Dict[str, Any], router: str) -> None:
        document, rules_loaded = hub._load_portmap_rules_document()
        if not rules_loaded:
            hub.LOGGER.warning(
                "Port-map rules document unavailable; skip router reconciliation for %s",
                router,
            )
            return
        desired = {
            clean(row.get("id")): row
            for row in document.get("rules", [])
            if isinstance(row, dict) and clean(row.get("id"))
        }
        local: Dict[str, Dict[str, Any]] = {}
        for row in payload.get("rules", []) if isinstance(payload.get("rules"), list) else []:
            if not isinstance(row, dict):
                continue
            local_rule = row.get("rule") if isinstance(row.get("rule"), dict) else {}
            runtime = row.get("runtime") if isinstance(row.get("runtime"), dict) else {}
            rule_id = clean(local_rule.get("id") or runtime.get("id"))
            if rule_id:
                local[rule_id] = local_rule
        compare = ("enabled", "mode", "listenPort", "targetMode", "targetIpv4", "targetIpv6", "targetIpv6Suffix", "targetMac", "targetPort", "transportProtocol", "expiresAt", "leaseSeconds", "maxConnections", "idleTimeoutSec")

        def compare_value(row: Dict[str, Any], key: str) -> Any:
            # Rules persisted before UDP support have no transportProtocol and
            # remain TCP rules.  Normalize only this legacy field so a TCP
            # Relay report is not needlessly requeued.
            if key == "transportProtocol":
                return clean(row.get(key) or "TCP").upper()
            return row.get(key)

        for rule_id, rule in desired.items():
            if rule_id not in local or any(compare_value(local[rule_id], key) != compare_value(rule, key) for key in compare):
                hub._queue_portmap_command("upsert", {"rule": rule}, router)
        for rule_id in set(local) - set(desired):
            hub._queue_portmap_command("delete", {"id": rule_id}, router)

    def decorated_rules(rules: List[Dict[str, Any]], router: str) -> tuple[List[Dict[str, Any]], int]:
        document = runtime_document()
        same_router = router_name(document.get("router")) == router
        runtime = hub._portmap_runtime_map(document) if same_router else {}
        runtime_revision = number(document.get("runtimeRevision")) if same_router else 0
        agent = presence(router)
        command_states = hub._portmap_command_sync_states(router)
        now = int(time.time())
        result: List[Dict[str, Any]] = []
        for source in rules:
            row = dict(source)
            desired = "running" if bool(row.get("enabled")) else "stopped"
            local = dict(runtime.get(clean(row.get("id")), {}))
            state = clean(local.get("state"))
            error = clean(local.get("lastError"))
            expired = hub._portmap_epoch(row.get("expiresAt"))
            if expired is not None and expired <= now and desired == "running":
                actual, sync = "expired", "synced"
                local["state"] = "expired"
            elif state == "running":
                # Listener/runtime state is authoritative for synchronization.
                # A connection-level error (for example, a peer reset) is useful
                # diagnostic history but must not make an active rule look as if
                # the Agent is still applying its configuration.
                actual, sync = "running", "synced"
            elif state in {"starting", "waiting_target", "draining"}:
                actual, sync = state, "syncing"
            elif state == "error" and error:
                actual, sync = "error", "error"
            elif desired == "stopped":
                actual = state or "stopped"
                sync = "syncing" if actual in {"running", "starting", "draining"} else "synced"
            elif agent["agentOnline"] or agent["agentState"] == "stale":
                # A single slow ctl query is neutral while the Agent is alive.
                actual, sync = "waiting_agent", "syncing"
            else:
                actual, sync = "waiting_agent", "agent_offline"
            command_sync = command_states.get(clean(row.get("id")))
            desired_satisfied = (
                (desired == "running" and state == "running")
                or (desired == "stopped" and state not in {"running", "starting", "draining"})
            )
            if command_sync == "error" and not desired_satisfied:
                actual, sync = "error", "error"
                local.setdefault("lastError", "command delivery failed")
            row.update({
                "desiredState": desired,
                "actualState": actual,
                "syncState": sync,
                "runtime": local,
                "revision": max(number(row.get("revision")), runtime_revision),
            })
            result.append(row)
        return result, runtime_revision

    def api_portmaps() -> Any:
        if request.method != "GET":
            return original_portmaps()
        if not hub.check_read_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        with lock:
            document, rules_loaded = hub._load_portmap_rules_document()
            rules = document.get("rules", [])
            rows = [row for row in rules if isinstance(row, dict)]
            router = router_name(request.args.get("router"))
            rows, runtime_revision = decorated_rules(rows, router)
            rules_revision = number(document.get("revision")) if isinstance(document, dict) else 0
            agent = presence(router)
            return jsonify({
                "ok": True,
                "router": router,
                "rules": rows,
                "rulesLoaded": rules_loaded,
                "rulesRevision": rules_revision,
                "runtimeRevision": runtime_revision,
                "revision": max(rules_revision, runtime_revision, number(agent.get("agentRevision"))),
                "rulesUpdatedAt": clean(document.get("updatedAt")) if isinstance(document, dict) else "",
                "serverTime": int(time.time()),
                "portRange": {"min": 20000, "max": 20020},
                **agent,
            })

    def api_agent_status() -> Any:
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad agent token"}), 401
        payload = request.get_json(silent=True) or {}
        router = router_name(payload.get("router"))
        now = int(time.time())
        with lock:
            data = statuses()
            old = data.get(router, {}) if isinstance(data.get(router), dict) else {}
            revision = max(number(old.get("revision")) + 1, now)
            data[router] = {
                "router": router,
                "version": clean(payload.get("version")) or clean(old.get("version")) or "unknown",
                "architecture": clean(payload.get("architecture")) or clean(old.get("architecture")),
                "updateState": clean(payload.get("updateState")) or "idle",
                "message": clean(payload.get("message")),
                "lastSeenAt": hub.now_str(),
                "lastSeenEpoch": now,
                "revision": revision,
            }
            hub.save_json(hub.AGENT_STATUS_FILE, data)
            commands = hub.load_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": []})
            rows = commands.get("commands", []) if isinstance(commands, dict) else []
            changed = False
            for command in rows:
                if isinstance(command, dict) and router_name(command.get("router")) == router and command.get("action") == "update" and command.get("state") == "accepted" and hub.version_parts(data[router]["version"]) >= hub.version_parts(command.get("targetVersion")):
                    command.update({"state": "completed", "message": f"updated to {data[router]['version']}", "updatedAt": hub.now_str()})
                    changed = True
            if changed:
                hub.save_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": rows})
        snapshot = presence(router)
        websocket = getattr(hub, "HUB_REALTIME_WEBSOCKET", None)
        if websocket is not None:
            try:
                websocket._publish("agent", snapshot)
            except Exception:
                hub.LOGGER.debug("Agent realtime publish deferred", exc_info=True)
        return jsonify({"ok": True, "router": router, "revision": revision, "serverTime": now})

    def api_portmap_status() -> Any:
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad hook token"}), 401
        payload = request.get_json(silent=True) or {}
        router = router_name(request.args.get("router") or payload.get("router"))
        now = int(time.time())
        with lock:
            old = runtime_document()
            revision = max(number(old.get("runtimeRevision")) + 1, now)
            record = {"router": router, "receivedAt": hub.now_str(), "receivedEpoch": now, "runtimeRevision": revision, "presenceRevision": revision, "status": payload}
            hub.save_json(hub.PORTMAP_ROUTER_STATUS_FILE, record)
            hub._append_portmap_history(record)
            reconcile(payload, router)
        snapshot = presence(router)
        websocket = getattr(hub, "HUB_REALTIME_WEBSOCKET", None)
        if websocket is not None:
            try:
                websocket._publish("agent", snapshot)
            except Exception:
                hub.LOGGER.debug("Agent realtime publish deferred", exc_info=True)
        return jsonify({"ok": True, "router": router, "runtimeRevision": revision, "serverTime": now})

    hub.app.view_functions["api_portmaps"] = api_portmaps
    hub.app.view_functions["api_router_agent_status"] = api_agent_status
    hub.app.view_functions["api_router_portmap_status"] = api_portmap_status
    hub.agent_presence_snapshot = presence
    hub.LABRELAY_SYNC_PATCHED = True
    hub.LOGGER.info("LabRelay authoritative presence/runtime revisions enabled")
