"""Truthful Agent presence derived from Agent heartbeat and port-map runtime reports."""
from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any, Dict

from flask import jsonify, request

ONLINE_SECONDS = max(30, int(os.environ.get("AGENT_ONLINE_GRACE_SEC", "90")))
STALE_SECONDS = max(ONLINE_SECONDS + 30, int(os.environ.get("AGENT_STALE_GRACE_SEC", "180")))


def _epoch(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        return float(text)
    except ValueError:
        pass
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(text, pattern).timestamp()
        except ValueError:
            continue
    return 0.0


def _presence(hub: Any, router: str = "") -> Dict[str, Any]:
    router_status = hub.load_json(hub.PORTMAP_ROUTER_STATUS_FILE, {})
    if not isinstance(router_status, dict):
        router_status = {}
    target = hub.clean_saved_value(router or router_status.get("router") or hub.primary_router_name()) or "router"
    statuses = hub.load_json(hub.AGENT_STATUS_FILE, {})
    if not isinstance(statuses, dict):
        statuses = {}
    heartbeat = statuses.get(target) if isinstance(statuses.get(target), dict) else {}
    if not heartbeat:
        primary = hub.clean_saved_value(hub.primary_router_name()) if hasattr(hub, "primary_router_name") else "router"
        for candidate in (primary, "router", router_status.get("router")):
            candidate = hub.clean_saved_value(candidate)
            if candidate and isinstance(statuses.get(candidate), dict):
                heartbeat = statuses.get(candidate)
                break
    runtime_epoch = _epoch(router_status.get("receivedEpoch"))
    heartbeat_epoch = _epoch(heartbeat.get("lastSeenEpoch") or heartbeat.get("lastSeenAt"))
    seen_epoch = max(runtime_epoch, heartbeat_epoch)
    age = max(0, int(time.time() - seen_epoch)) if seen_epoch > 0 else 0
    state = "online" if seen_epoch > 0 and age <= ONLINE_SECONDS else (
        "stale" if seen_epoch > 0 and age <= STALE_SECONDS else "offline"
    )
    seen_text = hub.clean_saved_value(heartbeat.get("lastSeenAt") or router_status.get("receivedAt"))
    return {
        "router": target,
        "agentOnline": state == "online",
        "agentState": state,
        "agentStateText": "Agent 在线" if state == "online" else ("Agent 状态稍旧" if state == "stale" else "Agent 未连接"),
        "agentLastSeenAt": seen_text,
        "agentLastSeenEpoch": int(seen_epoch),
        "agentAgeSeconds": age,
        "agentVersion": hub.clean_saved_value(heartbeat.get("version")),
        "agentArchitecture": hub.clean_saved_value(heartbeat.get("architecture")),
    }


def install_agent_presence_patch(hub: Any) -> None:
    if getattr(hub, "_labprobe_agent_presence_patch", False):
        return

    original_portmaps = hub.app.view_functions.get("api_portmaps")
    if original_portmaps is not None:
        def portmaps_with_presence(*args: Any, **kwargs: Any):
            result = original_portmaps(*args, **kwargs)
            if request.method != "GET":
                return result
            response = result[0] if isinstance(result, tuple) else result
            if not getattr(response, "is_json", False):
                return result
            root = response.get_json(silent=True)
            if not isinstance(root, dict):
                return result
            root.update(_presence(hub, root.get("router", "")))
            response.set_data(jsonify(root).get_data())
            response.content_type = "application/json"
            return result
        hub.app.view_functions["api_portmaps"] = portmaps_with_presence

    original_status = hub.app.view_functions.get("api_router_agent_status")
    if original_status is not None:
        def status_with_presence(*args: Any, **kwargs: Any):
            payload = request.get_json(silent=True) or {}
            result = original_status(*args, **kwargs)
            response = result[0] if isinstance(result, tuple) else result
            if getattr(response, "status_code", 200) < 400:
                snapshot = _presence(hub, hub.clean_saved_value(payload.get("router")))
                ws = getattr(hub, "HUB_REALTIME_WEBSOCKET", None)
                publish = getattr(ws, "_publish", None)
                if callable(publish):
                    try:
                        publish("agent", snapshot)
                    except Exception:
                        hub.LOGGER.debug("Agent presence WSS publish deferred", exc_info=True)
            return result
        hub.app.view_functions["api_router_agent_status"] = status_with_presence

    hub.agent_presence_snapshot = lambda router="": _presence(hub, router)
    hub._labprobe_agent_presence_patch = True
