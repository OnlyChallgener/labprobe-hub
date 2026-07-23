"""Small, non-blocking realtime APIs for the Android foreground UI.

The router metrics are read from the existing WSS-backed in-memory dashboard.
Device rates are sampled from the router's native device API only while an APP
is actively requesting them. The HTTP routes always return the last sample
immediately; router RPC work happens on a background thread.

This deliberately keeps high-frequency numbers separate from full dashboard,
device archive, MQTT revision and SQLite/file synchronization paths.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List

from flask import jsonify


def _integer(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(float(str(value).strip())))
    except (TypeError, ValueError):
        return default


def _clean_mac(hub: Any, value: Any) -> str:
    try:
        return hub.norm_mac(value)
    except Exception:
        return str(value or "").strip().lower().replace("-", ":")


def _device_rows(hub: Any, raw: Any) -> List[Dict[str, Any]]:
    items = raw.get("items", []) if isinstance(raw, dict) else raw if isinstance(raw, list) else []
    rows: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        mac = _clean_mac(hub, item.get("mac"))
        if not mac:
            continue
        rows.append({
            "mac": mac,
            "uploadBps": _integer(
                item.get("realtimeUploadBytes",
                    item.get("realtimeUpBytes",
                        item.get("realtimeUpload",
                            item.get("flowUp", 0))))
            ),
            "downloadBps": _integer(
                item.get("realtimeDownloadBytes",
                    item.get("realtimeDownBytes",
                        item.get("realtimeDownload",
                            item.get("flowDown", 0))))
            ),
            "connectionCount": _integer(
                item.get("connectionCount", item.get("flow_cnt", item.get("flowCnt", 0)))
            ),
        })
    rows.sort(key=lambda row: row["mac"])
    return rows


class RouterLiteRealtimeService:
    def __init__(self, hub: Any, router_sync: Any):
        self.hub = hub
        self.sync = router_sync
        self.logger = hub.LOGGER
        self._cache_lock = threading.RLock()
        self._rpc_lock = threading.RLock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._last_demand = 0.0
        self._devices: List[Dict[str, Any]] = []
        self._device_epoch = 0.0
        self._device_error = ""
        self._thread = threading.Thread(
            target=self._loop,
            name="router-lite-realtime",
            daemon=True,
        )
        self._wrap_full_device_sync()

    def _wrap_full_device_sync(self) -> None:
        """Share one RPC lock and reuse normal device-sync results as samples."""
        original = self.sync.sync_devices
        if getattr(original, "_labprobe_lite_wrapped", False):
            return

        def wrapped(force: bool = True):
            with self._rpc_lock:
                document = original(force=force)
            online = document.get("online", []) if isinstance(document, dict) else []
            self._store_devices(_device_rows(self.hub, online), source="full_sync")
            return document

        wrapped._labprobe_lite_wrapped = True  # type: ignore[attr-defined]
        self.sync.sync_devices = wrapped

    def start(self) -> None:
        self._thread.start()
        self.logger.info("router lightweight realtime APIs enabled")

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def mark_device_demand(self) -> None:
        self._last_demand = time.monotonic()
        self._wake.set()

    def _store_devices(self, rows: List[Dict[str, Any]], source: str) -> None:
        now = time.time()
        with self._cache_lock:
            self._devices = rows
            self._device_epoch = now
            self._device_error = ""
            self._device_source = source

    def _refresh_devices(self) -> None:
        if not self.sync.configured():
            return
        try:
            with self._rpc_lock:
                raw = self.sync.client.devices(force=True)
            self._store_devices(_device_rows(self.hub, raw), source="router_api")
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            with self._cache_lock:
                changed = message != self._device_error
                self._device_error = message
            if changed:
                self.logger.warning("device realtime sample failed: %s", message)

    def _loop(self) -> None:
        while not self._stop.is_set():
            active = time.monotonic() - self._last_demand <= 4.0
            if active:
                started = time.monotonic()
                self._refresh_devices()
                elapsed = time.monotonic() - started
                self._wake.wait(max(0.15, 1.0 - elapsed))
            else:
                self._wake.wait(5.0)
            self._wake.clear()

    def router_payload(self) -> Dict[str, Any]:
        with self.hub.ROUTER_DASHBOARD_LOCK:
            dashboard = json.loads(json.dumps(self.hub.ROUTER_DASHBOARD_CACHE, ensure_ascii=False)) \
                if self.hub.ROUTER_DASHBOARD_CACHE else {}
        telemetry = dashboard.get("telemetry") if isinstance(dashboard.get("telemetry"), dict) else {}
        wan = telemetry.get("wan") if isinstance(telemetry.get("wan"), dict) else {}
        connections = telemetry.get("connections") if isinstance(telemetry.get("connections"), dict) else {}
        source_epoch = float(dashboard.get("telemetryEpoch") or dashboard.get("receivedEpoch") or 0.0)
        now = time.time()
        return {
            "ok": True,
            "sampleEpochMs": int(source_epoch * 1000) if source_epoch else 0,
            "serverEpochMs": int(now * 1000),
            "stale": not source_epoch or now - source_epoch > 3.0,
            "uploadBps": _integer(wan.get("uploadBps")),
            "downloadBps": _integer(wan.get("downloadBps")),
            "totalUploadBytes": _integer(wan.get("totalUploadBytes")),
            "totalDownloadBytes": _integer(wan.get("totalDownloadBytes")),
            "cpuPercent": float(telemetry.get("cpuPercent") or 0.0),
            "memoryPercent": float(telemetry.get("memoryPercent") or 0.0),
            "temperatureC": float(telemetry.get("temperatureC") or 0.0),
            "uptimeSeconds": _integer(telemetry.get("uptimeSeconds")),
            "onlineDeviceCount": _integer(telemetry.get("onlineDeviceCount")),
            "ipv4Connections": _integer(connections.get("ipv4")),
            "ipv6Connections": _integer(connections.get("ipv6")),
            "ipv4HalfConnections": _integer(connections.get("ipv4Half")),
            "ipv6HalfConnections": _integer(connections.get("ipv6Half")),
            "cps": _integer(connections.get("cps")),
        }

    def devices_payload(self) -> Dict[str, Any]:
        self.mark_device_demand()
        with self._cache_lock:
            rows = json.loads(json.dumps(self._devices, ensure_ascii=False))
            epoch = self._device_epoch
            error = self._device_error
            source = getattr(self, "_device_source", "")
        now = time.time()
        return {
            "ok": True,
            "sampleEpochMs": int(epoch * 1000) if epoch else 0,
            "serverEpochMs": int(now * 1000),
            "stale": not epoch or now - epoch > 3.0,
            "source": source,
            "devices": rows,
            "error": error if not rows else "",
        }


def install_router_lite_realtime_patch(hub: Any, router_sync: Any) -> RouterLiteRealtimeService:
    existing = getattr(hub, "ROUTER_LITE_REALTIME", None)
    if existing is not None:
        return existing

    service = RouterLiteRealtimeService(hub, router_sync)

    @hub.app.get("/api/router/realtime")
    def api_router_realtime():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return jsonify(service.router_payload())

    @hub.app.get("/api/devices/realtime")
    def api_devices_realtime():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return jsonify(service.devices_payload())

    @hub.app.get("/api/realtime")
    def api_lite_realtime():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return jsonify({
            "ok": True,
            "router": service.router_payload(),
            "deviceRuntime": service.devices_payload(),
        })

    service.start()
    hub.ROUTER_LITE_REALTIME = service
    return service
