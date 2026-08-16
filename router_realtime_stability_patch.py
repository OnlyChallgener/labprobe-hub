"""Realtime dashboard stability fixes for Hub 0.9.15.

Fast telemetry comes from the router's native /ws connection.  It must not wait
behind terminal-list/configuration RPCs and it must not trigger a fresh HTTP
login every second while WebSocket authentication is still being established.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict

from flask import jsonify

import router_compat
import router_ws_patch


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    text = str(value or "").strip()
    return "" if text.lower() in {"none", "null", "--"} else text


def _ws_fresh_from_status(status: Any, max_age: float = 8.0) -> bool:
    row = _dict(status)
    last_message_at = float(row.get("lastFastAt") or row.get("lastMessageAt") or 0.0)
    return bool(row.get("connected")) and last_message_at > 0 and time.time() - last_message_at <= max_age


def _client_ws_snapshot(client: Any) -> tuple[bool, Dict[str, Any]]:
    monitor = getattr(client, "router_ws_monitor", None)
    snapshot = monitor.snapshot() if monitor is not None else {}
    has_payload = any(isinstance(snapshot.get(key), dict) and snapshot.get(key) for key in ("fast", "slow", "static"))
    return bool(has_payload and _ws_fresh_from_status(snapshot.get("wsStatus"))), snapshot


def dashboard_has_data(payload: Any, require_fresh: bool = False) -> bool:
    root = _dict(payload)
    if not root:
        return False
    if require_fresh:
        last_message_at = float(root.get("wsLastMessageAt") or 0.0)
        if last_message_at <= 0 or time.time() - last_message_at > 12.0:
            return False

    telemetry = _dict(root.get("telemetry"))
    wan_telemetry = _dict(telemetry.get("wan"))
    connections = _dict(telemetry.get("connections"))
    numeric_values = [
        telemetry.get("temperatureC"), telemetry.get("cpuPercent"), telemetry.get("memoryPercent"),
        telemetry.get("uptimeSeconds"), wan_telemetry.get("uploadBps"), wan_telemetry.get("downloadBps"),
        connections.get("ipv4"), connections.get("ipv6"),
    ]
    if any(float(value or 0) != 0 for value in numeric_values if isinstance(value, (int, float))):
        return True

    details = _dict(root.get("details"))
    identity = _dict(details.get("identity"))
    wan = _dict(details.get("wan"))
    ap = _dict(details.get("ap"))
    meaningful = [
        root.get("router"), identity.get("hostname"), identity.get("model"), identity.get("serialNumber"),
        wan.get("ipv4"), wan.get("gateway"), ap.get("hostName"), ap.get("model"), ap.get("networkName"),
    ]
    return any(
        bool(text) and text not in {"router", "路由器"}
        for text in (_text(value) for value in meaningful)
    ) or bool(details.get("ports"))


def merge_dashboard(previous: Any, latest: Any) -> Dict[str, Any]:
    base = _clone(previous) if isinstance(previous, dict) else {}
    incoming = _dict(latest)

    def merge(target: Dict[str, Any], source: Dict[str, Any]) -> None:
        for key, value in source.items():
            if isinstance(value, dict):
                if not value and isinstance(target.get(key), dict) and target.get(key):
                    continue
                child = _clone(target.get(key)) if isinstance(target.get(key), dict) else {}
                merge(child, value)
                target[key] = child
            elif value is None:
                if key not in target:
                    target[key] = None
            elif isinstance(value, str) and not value.strip() and _text(target.get(key)):
                continue
            elif isinstance(value, list) and not value and isinstance(target.get(key), list) and target.get(key):
                continue
            else:
                target[key] = _clone(value)

    merge(base, incoming)
    return base


def _static_bootstrap_timeout_seconds() -> float:
    try:
        return max(1.0, float(os.environ.get("ROUTER_STATIC_BOOTSTRAP_WAIT_SEC", "20")))
    except (TypeError, ValueError):
        return 20.0


def _stable_normalize(original):
    def wrapped(self: Any, raw: Dict[str, Any]) -> Dict[str, Any]:
        with self.hub.ROUTER_DASHBOARD_LOCK:
            previous = _clone(self.hub.ROUTER_DASHBOARD_CACHE) if self.hub.ROUTER_DASHBOARD_CACHE else {}
        normalized = original(self, raw)

        ws_status = _dict(raw.get("wsStatus"))
        has_payload = isinstance(raw.get("fast"), dict) and bool(raw.get("fast"))
        fresh = bool(has_payload and _ws_fresh_from_status(ws_status))
        last_message_at = float(ws_status.get("lastFastAt") or ws_status.get("lastMessageAt") or 0.0)

        if previous and not fresh:
            if isinstance(previous.get("telemetry"), dict):
                normalized["telemetry"] = _clone(previous["telemetry"])
            if isinstance(previous.get("details"), dict):
                normalized["details"] = merge_dashboard({"details": previous["details"]}, {"details": normalized.get("details")})["details"]
            normalized["router"] = normalized.get("router") or previous.get("router") or "路由器"

        normalized["online"] = fresh
        normalized["telemetryStale"] = not fresh
        normalized["wsDataAvailable"] = fresh
        normalized["wsLastMessageAt"] = last_message_at
        normalized["source"] = "router_ws" if fresh else "router_cache"
        return normalized

    return wrapped


def _stable_sync_dashboard(self: Any, force: bool = False) -> Dict[str, Any]:
    raw = self.client.dashboard(force=force)
    normalized = self._normalize_dashboard(raw if isinstance(raw, dict) else {})
    with self.hub.ROUTER_DASHBOARD_LOCK:
        previous = _clone(self.hub.ROUTER_DASHBOARD_CACHE) if self.hub.ROUTER_DASHBOARD_CACHE else {}
        candidate = merge_dashboard(previous, normalized)
        if dashboard_has_data(previous) and not dashboard_has_data(candidate):
            candidate = previous
        refresh_nonce = self.hub.ROUTER_DASHBOARD_REFRESH_NONCE
        candidate["refreshNonce"] = refresh_nonce
        candidate["refreshCompletedNonce"] = refresh_nonce
        candidate["refreshCompletedAt"] = self.hub.now_str()
        self.hub.ROUTER_DASHBOARD_CACHE.clear()
        self.hub.ROUTER_DASHBOARD_CACHE.update(candidate)
        public = self.hub._router_dashboard_public()
    self.hub._persist_router_dashboard_if_due(force=False)
    self.hub.MQTT_PUBLISHER.publish_dashboard(public)
    return public


def _static_bootstrap_once(self: Any) -> None:
    if not self.configured():
        return
    monitor = getattr(self.client, "router_ws_monitor", None)
    if monitor is not None:
        monitor.wait_authenticated(_static_bootstrap_timeout_seconds())
    try:
        self.sync_dashboard(force=True)
    except Exception as exc:
        self.logger.debug("router initial static dashboard refresh deferred: %s", exc)


def _start_workers(self: Any) -> None:
    if not self.primary or self._thread is not None:
        return
    self._thread = threading.Thread(target=_static_bootstrap_once, args=(self,), name="router-static-bootstrap", daemon=True)
    self._thread.start()
    self.logger.info("router static bootstrap worker started; /ws fast handles realtime independently")


def _sync_once_dashboard_first(self: Any, force: bool = True) -> Dict[str, Any]:
    dashboard = self.sync_dashboard(force=force)
    devices: Dict[str, Any] = {}
    try:
        with self._refresh_lock:
            devices = self.sync_devices(force=force)
    except Exception as exc:
        self.logger.debug("router terminal refresh deferred after dashboard update: %s", exc)
    return {"dashboard": dashboard, "devices": devices}


def _non_blocking_refresh_view(self: Any):
    if not self.hub.check_app_token():
        return jsonify({"ok": False, "error": "unauthorized", "message": "APP Token 无效"}), 401
    with self.hub.ROUTER_DASHBOARD_LOCK:
        self.hub.ROUTER_DASHBOARD_REFRESH_NONCE += 1
        nonce = self.hub.ROUTER_DASHBOARD_REFRESH_NONCE
        if self.hub.ROUTER_DASHBOARD_CACHE:
            self.hub.ROUTER_DASHBOARD_CACHE["refreshNonce"] = nonce
            self.hub.ROUTER_DASHBOARD_CACHE["refreshCompletedNonce"] = nonce
            self.hub.ROUTER_DASHBOARD_CACHE["refreshCompletedAt"] = self.hub.now_str()
        dashboard = self.hub._router_dashboard_public()

    def worker() -> None:
        try:
            self.sync_dashboard(force=True)
        except Exception as exc:
            self.logger.warning("router manual dashboard refresh failed: %s", exc)
        try:
            with self._refresh_lock:
                self.sync_devices(force=True)
        except Exception as exc:
            self.logger.debug("router manual terminal refresh deferred: %s", exc)

    threading.Thread(target=worker, name=f"router-manual-refresh-{nonce}", daemon=True).start()
    return jsonify({
        "ok": True,
        "refreshNonce": nonce,
        "refreshCompletedNonce": nonce,
        "message": "刷新请求已提交，页面保留现有数据并自动更新",
        "dashboard": dashboard,
        "time": self.hub.now_str(),
    })


def install_router_realtime_stability_patch() -> None:
    original_config_poll = router_ws_patch._config_poll_seconds

    def stable_config_poll() -> float:
        try:
            value = float(os.environ.get("ROUTER_CONFIG_POLL_SEC", "120"))
        except (TypeError, ValueError):
            value = 120.0
        return max(60.0, value, original_config_poll())

    router_ws_patch._config_poll_seconds = stable_config_poll

    cls = router_compat.RouterRpcCompatibilitySync
    if getattr(cls, "_labprobe_realtime_stability_patch", False):
        return
    cls.start = _start_workers
    cls.sync_dashboard = _stable_sync_dashboard
    cls.sync_once = _sync_once_dashboard_first
    cls.refresh_view = _non_blocking_refresh_view
    cls._normalize_dashboard = _stable_normalize(cls._normalize_dashboard)
    cls._labprobe_realtime_stability_patch = True


def install_router_status_localization(hub: Any, sync: Any) -> None:
    endpoint = next((name for name in hub.app.view_functions if name.endswith(".get_status")), "")
    if not endpoint:
        return

    def status_view():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized", "message": "APP Token 无效"}), 401
        state = sync.client.status(probe=False)
        configured = bool(state.get("configured"))
        session_connected = bool(state.get("connected"))
        realtime_service = getattr(hub, "ROUTER_LITE_REALTIME", None)
        realtime_payload = realtime_service.router_payload() if realtime_service is not None else {}
        realtime_epoch_ms = int(_dict(realtime_payload).get("sampleEpochMs") or 0)
        realtime_fresh = bool(realtime_epoch_ms and not _dict(realtime_payload).get("stale"))
        with hub.ROUTER_DASHBOARD_LOCK:
            data_available = realtime_fresh or dashboard_has_data(hub.ROUTER_DASHBOARD_CACHE, require_fresh=True)

        error_code = str(state.get("lastErrorCode") or "")
        if realtime_fresh:
            status = "ready"
            message = "路由器已连接，实时数据正常"
            error_code = ""
        elif session_connected:
            status = "syncing"
            message = "路由器会话已登录，正在等待实时数据"
            error_code = "HUB_NO_ROUTER_DATA"
        elif not configured:
            status = "unconfigured"
            message = "尚未配置路由器管理地址和密码"
            error_code = "HUB_ROUTER_NOT_CONFIGURED"
        elif error_code:
            status = "router_login_failed"
            message = "路由器连接异常，请检查管理密码或网络"
        else:
            status = "recovering"
            message = "正在恢复路由器连接，已保留上次数据" if dashboard_has_data(hub.ROUTER_DASHBOARD_CACHE) else "正在恢复路由器连接"
            error_code = ""

        return jsonify({
            "ok": True,
            "state": status,
            "connected": data_available,
            "sessionConnected": session_connected,
            "dataAvailable": data_available,
            "message": message,
            "errorCode": error_code,
            "lastSuccessAt": int(state.get("lastSuccessAt") or 0),
        })

    hub.app.view_functions[endpoint] = status_view
