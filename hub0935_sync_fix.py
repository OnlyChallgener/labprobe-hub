"""Hub 0.9.35 device synchronization and router WebSocket corrections.

The router eWeb ``/ws`` stream is not a Webhook.  It already pushes ``fast``
frames continuously and closes the connection when Hub sends the unsupported
application message ``{"action":"keepalive"}``.  The replacement receiver is
therefore passive and relies on the existing fast-frame stall watchdog.

Device persistence also has one writer.  LabRelay's ``/hook/ruijie/devices`` is
the normal durable authority.  Hub's five-second router poll remains a live WSS
view only and cannot overwrite the durable archive.  The one-minute snapshot
endpoint is retained as a fallback only when the Relay hook has genuinely gone
stale.
"""
from __future__ import annotations

import json
import ssl
import threading
import time
from types import MethodType
from typing import Any, Dict, List, Optional

import websocket
from flask import jsonify, request

import router_fast_watchdog_patch
import router_ws_patch


HOOK_FALLBACK_GRACE_SECONDS = 35


def _run_router_connection_without_app_keepalive(
    self: Any,
    ws_url: str,
    origin: str,
    cookie: str,
    verify_tls: bool,
    hostname: str,
) -> None:
    """Receive native router frames without sending an unsupported JSON action."""
    sslopt = None
    if ws_url.startswith("wss://") and not verify_tls:
        sslopt = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}
    ws = websocket.create_connection(
        ws_url,
        timeout=6,
        origin=origin,
        cookie=cookie or None,
        sslopt=sslopt or {},
        http_no_proxy=[hostname] if hostname else None,
        enable_multithread=True,
    )
    ws.settimeout(router_fast_watchdog_patch.FAST_SOCKET_POLL_SECONDS)
    connected_at = time.time()
    self._set_connected(True, ws_url)
    try:
        while not self._stop.is_set():
            try:
                raw = ws.recv()
            except websocket.WebSocketTimeoutException:
                if router_fast_watchdog_patch._fast_stream_stalled(
                    self,
                    connected_at,
                    time.time(),
                ):
                    self._set_connected(
                        False,
                        ws_url,
                        "router fast stream stalled; reconnecting",
                    )
                    return
                continue
            if raw is None or raw == "":
                raise RuntimeError("router websocket closed")
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            try:
                message = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if isinstance(message, dict):
                self._dispatch_message(message)
    finally:
        try:
            ws.close()
        except Exception:
            pass


def install_router_ws_passive_fix() -> None:
    """Install after the fast-watchdog patch and before its monitor is created."""
    monitor_class = router_ws_patch.RouterWebSocketMonitor
    if getattr(monitor_class, "_labprobe_passive_fast_stream_fix", False):
        return
    monitor_class._run_connection = _run_router_connection_without_app_keepalive
    monitor_class._labprobe_passive_fast_stream_fix = True


def _patch_live_history_to_memory_only(hub: Any) -> None:
    history = getattr(hub, "DURABLE_DEVICE_HISTORY", None)
    if history is None or getattr(history, "_live_poll_memory_only", False):
        return
    original_ingest = history.ingest

    def ingest(
        self: Any,
        payload: Any,
        *,
        prepared_online: Optional[List[Dict[str, Any]]] = None,
        prepared_total: Optional[int] = None,
    ) -> Dict[str, Any]:
        # ``prepared_online`` is supplied only by RouterDeviceLiveSync.  That
        # five-second lane may publish a live WSS frame but must never rewrite
        # DEVICES_FILE, the archive, transition events, rollups or revisions.
        if prepared_online is not None:
            rows = [row for row in prepared_online if isinstance(row, dict)]
            return {
                "accepted": True,
                "liveOnly": True,
                "persisted": False,
                "onlineDeviceCount": len(rows),
                "total": max(len(rows), int(prepared_total or 0)),
                "updatedAt": hub.now_str(),
            }
        return original_ingest(payload)

    history.ingest = MethodType(ingest, history)
    history._live_poll_memory_only = True


def install_hub0935_device_sync_fix(hub: Any) -> None:
    """Make the Relay hook authoritative and expose independent channel health."""
    if getattr(hub, "HUB0935_DEVICE_SYNC_FIXED", False):
        return
    history = getattr(hub, "DURABLE_DEVICE_HISTORY", None)
    if history is None:
        raise RuntimeError("DurableDeviceHistory must be installed first")

    _patch_live_history_to_memory_only(hub)
    state_lock = threading.RLock()
    source_state: Dict[str, Any] = {
        "lastHookEpoch": 0,
        "lastHookAt": "",
        "lastFallbackEpoch": 0,
        "lastFallbackAt": "",
    }

    def mark_source(kind: str) -> None:
        now = int(time.time())
        with state_lock:
            if kind == "hook":
                source_state["lastHookEpoch"] = now
                source_state["lastHookAt"] = hub.now_str()
            else:
                source_state["lastFallbackEpoch"] = now
                source_state["lastFallbackAt"] = hub.now_str()

    def relay_device_hook() -> Any:
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad hook token"}), 401
        payload = request.get_json(silent=True)
        if payload is None:
            raw = request.get_data(as_text=True)
            try:
                payload = json.loads(raw)
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "invalid device payload"}), 400
        try:
            result = history.ingest(payload)
            if result.get("accepted"):
                mark_source("hook")
            return jsonify({
                "ok": True,
                **result,
                "authority": "labrelay_hook",
                "time": hub.now_str(),
            })
        except Exception as exc:
            history.logger.warning("Relay device hook rejected: %s", exc)
            return jsonify({"ok": False, "error": str(exc), "time": hub.now_str()}), 400

    def fallback_snapshot() -> Any:
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad agent token"}), 401
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify({"ok": False, "error": "empty snapshot"}), 400
        now = int(time.time())
        with state_lock:
            hook_age = now - int(source_state.get("lastHookEpoch") or 0)
            hook_recent = bool(source_state.get("lastHookEpoch")) and hook_age <= HOOK_FALLBACK_GRACE_SECONDS
        if hook_recent:
            return jsonify({
                "ok": True,
                "accepted": False,
                "duplicateSource": True,
                "authority": "labrelay_hook",
                "hookAgeSeconds": max(0, hook_age),
                "time": hub.now_str(),
            })
        try:
            result = history.ingest(payload)
            if result.get("accepted"):
                mark_source("fallback")
            return jsonify({
                "ok": True,
                **result,
                "authority": "labrelay_snapshot_fallback",
                "time": hub.now_str(),
            })
        except Exception as exc:
            history.logger.warning("fallback device snapshot rejected: %s", exc)
            return jsonify({"ok": False, "error": str(exc), "time": hub.now_str()}), 400

    def sync_status() -> Any:
        if not hub.check_read_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        health = hub.load_json(history.health_path, {})
        now = int(time.time())
        with state_lock:
            source = dict(source_state)
        hook_epoch = int(source.get("lastHookEpoch") or 0)
        hook_age = max(0, now - hook_epoch) if hook_epoch else 0
        return jsonify({
            "ok": True,
            **(health if isinstance(health, dict) else {}),
            **source,
            "authority": "labrelay_hook",
            "hookHealthy": bool(hook_epoch and hook_age <= HOOK_FALLBACK_GRACE_SECONDS),
            "hookAgeSeconds": hook_age,
            "fallbackAfterSeconds": HOOK_FALLBACK_GRACE_SECONDS,
            "liveRouterPollPersistence": False,
            "routerWebSocketIndependent": True,
        })

    hub.app.view_functions["hook_ruijie_devices"] = relay_device_hook
    hub.app.view_functions["api_router_devices_snapshot"] = fallback_snapshot
    hub.app.view_functions["api_router_devices_snapshot_status"] = sync_status
    hub.DEVICE_SYNC_SOURCE_STATE = source_state
    hub.HUB0935_DEVICE_SYNC_FIXED = True
    hub.LOGGER.info(
        "Hub 0.9.35 device authority enabled: Relay hook durable, router live poll memory-only"
    )
