"""Realtime dashboard stability fixes for Hub 0.9.15.

The router WebSocket already delivers fast telemetry, so dashboard publication must
not wait behind the much slower terminal-list RPC.  This patch separates those
workers, preserves the last complete dashboard during transient empty responses,
and makes manual refresh non-blocking.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict

from flask import jsonify

import router_compat


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    text = str(value or "").strip()
    return "" if text.lower() in {"none", "null", "--"} else text


def dashboard_has_data(payload: Any) -> bool:
    """Return True only when the dashboard contains actual router information."""
    root = _dict(payload)
    if not root:
        return False
    if bool(root.get("online")):
        return True

    telemetry = _dict(root.get("telemetry"))
    wan_telemetry = _dict(telemetry.get("wan"))
    connections = _dict(telemetry.get("connections"))
    numeric_values = [
        telemetry.get("temperatureC"),
        telemetry.get("cpuPercent"),
        telemetry.get("memoryPercent"),
        telemetry.get("uptimeSeconds"),
        wan_telemetry.get("uploadBps"),
        wan_telemetry.get("downloadBps"),
        connections.get("ipv4"),
        connections.get("ipv6"),
    ]
    if any(float(value or 0) != 0 for value in numeric_values if isinstance(value, (int, float))):
        return True

    details = _dict(root.get("details"))
    identity = _dict(details.get("identity"))
    wan = _dict(details.get("wan"))
    ap = _dict(details.get("ap"))
    meaningful = [
        root.get("router"),
        identity.get("hostname"),
        identity.get("model"),
        identity.get("serialNumber"),
        wan.get("ipv4"),
        wan.get("gateway"),
        ap.get("hostName"),
        ap.get("model"),
        ap.get("networkName"),
    ]
    return any(_text(value) not in {"router"} for value in meaningful) or bool(details.get("ports"))


def merge_dashboard(previous: Any, latest: Any) -> Dict[str, Any]:
    """Deep-merge a partial live snapshot without erasing valid cached fields."""
    base = _clone(previous) if isinstance(previous, dict) else {}
    incoming = _dict(latest)

    def merge(target: Dict[str, Any], source: Dict[str, Any]) -> None:
        for key, value in source.items():
            if isinstance(value, dict):
                if not value and isinstance(target.get(key), dict) and target.get(key):
                    continue
                child = target.get(key) if isinstance(target.get(key), dict) else {}
                child = _clone(child)
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


def _dashboard_interval_seconds() -> float:
    try:
        return max(0.5, float(os.environ.get("ROUTER_DASHBOARD_FAST_SEC", "1")))
    except (TypeError, ValueError):
        return 1.0


def _device_interval_seconds() -> float:
    try:
        return max(3.0, float(os.environ.get("ROUTER_DEVICE_POLL_SEC", "5")))
    except (TypeError, ValueError):
        return 5.0


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


def _dashboard_loop(self: Any) -> None:
    interval = _dashboard_interval_seconds()
    last_error = ""
    while not self._stop.is_set():
        if self.configured():
            try:
                self.sync_dashboard(force=False)
                last_error = ""
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                if message != last_error:
                    self.logger.warning("router realtime dashboard refresh failed: %s", message)
                    last_error = message
        self._stop.wait(interval)


def _device_loop(self: Any) -> None:
    interval = _device_interval_seconds()
    last_error = ""
    while not self._stop.is_set():
        if self.configured():
            try:
                self.sync_devices(force=True)
                last_error = ""
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                if message != last_error:
                    self.logger.warning("router terminal refresh failed: %s", message)
                    last_error = message
        self._stop.wait(interval)


def _start_workers(self: Any) -> None:
    if not self.primary or self._thread is not None:
        return
    dashboard_thread = threading.Thread(target=lambda: _dashboard_loop(self), name="router-dashboard-realtime", daemon=True)
    device_thread = threading.Thread(target=lambda: _device_loop(self), name="router-device-sync", daemon=True)
    self._thread = dashboard_thread
    self._device_thread = device_thread
    dashboard_thread.start()
    device_thread.start()
    self.logger.info(
        "router realtime workers started dashboard=%ss devices=%ss",
        _dashboard_interval_seconds(),
        _device_interval_seconds(),
    )


def _sync_once_dashboard_first(self: Any, force: bool = True) -> Dict[str, Any]:
    with self._refresh_lock:
        dashboard = self.sync_dashboard(force=False)
        try:
            devices = self.sync_devices(force=force)
        except Exception as exc:
            self.logger.debug("router terminal refresh deferred after dashboard update: %s", exc)
            devices = {}
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
            self.sync_dashboard(force=False)
        except Exception as exc:
            self.logger.warning("router manual dashboard refresh failed: %s", exc)
        try:
            self.sync_devices(force=True)
        except Exception as exc:
            self.logger.debug("router manual terminal refresh deferred: %s", exc)

    threading.Thread(target=worker, name=f"router-manual-refresh-{nonce}", daemon=True).start()
    return jsonify({
        "ok": True,
        "refreshNonce": nonce,
        "refreshCompletedNonce": nonce,
        "message": "刷新请求已提交，页面将保留现有数据并自动更新",
        "dashboard": dashboard,
        "time": self.hub.now_str(),
    })


def install_router_realtime_stability_patch() -> None:
    cls = router_compat.RouterRpcCompatibilitySync
    if getattr(cls, "_labprobe_realtime_stability_patch", False):
        return
    cls.start = _start_workers
    cls.sync_dashboard = _stable_sync_dashboard
    cls.sync_once = _sync_once_dashboard_first
    cls.refresh_view = _non_blocking_refresh_view
    cls._labprobe_realtime_stability_patch = True


def install_router_status_localization(hub: Any, sync: Any) -> None:
    """Replace the APP-facing status endpoint with consistent Chinese state text."""
    endpoint = next((name for name in hub.app.view_functions if name.endswith(".get_status")), "")
    if not endpoint:
        return

    def status_view():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized", "message": "APP Token 无效"}), 401
        state = sync.client.status(probe=False)
        configured = bool(state.get("configured"))
        connected = bool(state.get("connected"))
        with hub.ROUTER_DASHBOARD_LOCK:
            data_available = dashboard_has_data(hub.ROUTER_DASHBOARD_CACHE)

        error_code = str(state.get("lastErrorCode") or "")
        error_message = str(state.get("lastError") or "")
        if connected and data_available:
            status = "ready"
            message = "Hub 已连接路由器，实时数据正常"
            error_code = ""
        elif connected:
            status = "syncing"
            message = "路由器已连接，正在同步实时数据"
            error_code = ""
        elif not configured:
            status = "unconfigured"
            message = "尚未配置路由器管理地址和密码"
            error_code = "HUB_ROUTER_NOT_CONFIGURED"
        elif error_code:
            status = "router_login_failed"
            message = f"路由器连接异常：{error_message}" if error_message else "Hub 无法登录路由器"
        elif data_available:
            status = "recovering"
            message = "路由器连接正在恢复，已保留上次数据"
            error_code = ""
        else:
            status = "recovering"
            message = "正在恢复路由器连接"
            error_code = ""

        return jsonify({
            "ok": True,
            "state": status,
            "connected": connected,
            "dataAvailable": data_available,
            "message": message,
            "errorCode": error_code,
            "lastSuccessAt": int(state.get("lastSuccessAt") or 0),
        })

    hub.app.view_functions[endpoint] = status_view
