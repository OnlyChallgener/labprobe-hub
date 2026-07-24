"""Compact realtime cache for APP numeric refreshes.

Route realtime comes from Hub's authenticated eWeb ``/ws type=fast`` receiver.
Terminal realtime remains the router-local LabRelay lane. HTTP reads only this
memory cache for initial page load, manual refresh and reconnect calibration;
it never starts eWeb/CMD collection.

When the WSS APP lease expires, Relay terminal pushes are acknowledged as
inactive and are not written into the device cache. The route ``fast`` receiver
keeps the last valid frame and reconnects in the background.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List

from flask import jsonify, request


DEMAND_TTL_SECONDS = 45.0
ROUTER_STALE_MS = 3_000
DEVICES_STALE_MS = 4_000
_ROUTER_FIELDS = {
    "uploadBps",
    "downloadBps",
    "totalUploadBytes",
    "totalDownloadBytes",
    "cpuPercent",
    "memoryPercent",
    "temperatureC",
    "uptimeSeconds",
    "onlineDeviceCount",
    "ipv4Connections",
    "ipv6Connections",
    "ipv4HalfConnections",
    "ipv6HalfConnections",
    "cps",
}


def _integer(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(float(str(value).strip())))
    except (TypeError, ValueError):
        return default


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip().rstrip("%"))
    except (TypeError, ValueError):
        return default


def _clean_source(value: Any) -> str:
    text = str(value or "").strip()
    return text[:48] if text else "relay_local_dev_sta"


class RouterLiteRealtimeService:
    def __init__(self, hub: Any, router_sync: Any = None):
        self.hub = hub
        self.sync = router_sync
        self.logger = hub.LOGGER
        self._lock = threading.RLock()
        self._demand = threading.Condition(threading.RLock())
        self._stopped = False
        self._demand_sequence = 0
        self._client_demand_until: Dict[str, float] = {}

        self._router_sample: Dict[str, Any] = {}
        self._router_epoch_ms = 0
        self._router_sequence = 0
        self._router_source = ""
        self._router_agent_version = ""

        self._devices: List[Dict[str, Any]] = []
        self._devices_epoch_ms = 0
        self._devices_sequence = 0
        self._devices_source = ""
        self._devices_agent_version = ""

    def start(self) -> None:
        monitor = getattr(getattr(self.sync, "client", None), "router_ws_monitor", None)
        if monitor is not None and hasattr(monitor, "set_fast_handler"):
            monitor.set_fast_handler(self.accept_router_fast)
            self.logger.info("router eweb /ws fast realtime bridge enabled; relay handles devices only")
        else:
            self.logger.info("router realtime cache enabled; waiting for eweb /ws monitor")

    def stop(self) -> None:
        with self._demand:
            self._stopped = True
            self._demand.notify_all()

    def set_wss_demand(self, client_id: str, active: bool) -> None:
        client_id = str(client_id or "").strip()[:96]
        if not client_id:
            return
        now = time.time()
        with self._demand:
            was_active = any(until > now for until in self._client_demand_until.values())
            if active:
                self._client_demand_until[client_id] = now + DEMAND_TTL_SECONDS
            else:
                self._client_demand_until.pop(client_id, None)
            self._client_demand_until = {
                key: until for key, until in self._client_demand_until.items() if until > now
            }
            is_active = bool(self._client_demand_until)
            if is_active != was_active:
                self._demand_sequence += 1
                self._demand.notify_all()

    def mark_router_demand(self) -> None:
        return None

    def mark_device_demand(self) -> None:
        self.set_wss_demand("legacy-devices", True)

    def _demand_payload_locked(self) -> Dict[str, Any]:
        now = time.time()
        self._client_demand_until = {
            key: until for key, until in self._client_demand_until.items() if until > now
        }
        active = bool(self._client_demand_until)
        return {
            "ok": True,
            "sequence": self._demand_sequence,
            "routerActive": False,
            "devicesActive": active,
            "demandClientCount": len(self._client_demand_until),
            "serverEpochMs": int(now * 1000),
        }

    def demand_payload(self, since: int = 0, wait_seconds: int = 0) -> Dict[str, Any]:
        wait_seconds = max(0, min(55, int(wait_seconds)))
        with self._demand:
            def ready() -> bool:
                payload = self._demand_payload_locked()
                return (
                    self._stopped
                    or payload["sequence"] > since
                    or payload["routerActive"]
                    or payload["devicesActive"]
                )

            if wait_seconds and not ready():
                self._demand.wait_for(ready, timeout=wait_seconds)
            return self._demand_payload_locked()

    def _sample_epoch_ms(self, value: Any) -> int:
        now_ms = int(time.time() * 1000)
        sample_ms = _integer(value, now_ms)
        if sample_ms <= 0 or sample_ms > now_ms + 10_000:
            return now_ms
        return sample_ms

    def _router_fields(self, value: Any) -> Dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        output: Dict[str, Any] = {}
        for key in _ROUTER_FIELDS:
            if key not in value:
                continue
            if key in {"cpuPercent", "memoryPercent", "temperatureC"}:
                output[key] = _number(value.get(key))
            else:
                output[key] = _integer(value.get(key))
        return output

    def accept_router_fast(self, sample: Any, sample_epoch_ms: int = 0) -> None:
        router = self._router_fields(sample)
        if not router:
            return
        epoch_ms = self._sample_epoch_ms(sample_epoch_ms)
        router_event: Dict[str, Any] = {}
        with self._lock:
            merged_router = dict(self._router_sample)
            merged_router.update(router)
            changed = merged_router != self._router_sample or epoch_ms != self._router_epoch_ms
            self._router_sample = merged_router
            self._router_epoch_ms = epoch_ms
            self._router_source = "router_eweb_ws_fast"
            self._router_agent_version = ""
            if changed:
                self._router_sequence += 1
                router_event = {
                    "ok": True,
                    "sampleEpochMs": epoch_ms,
                    "sequence": self._router_sequence,
                    "source": self._router_source,
                    **merged_router,
                }
        publisher = getattr(self.hub, "MQTT_PUBLISHER", None)
        if router_event and publisher is not None:
            publisher.publish_router_realtime(router_event)

    def _device_rows(self, value: Any) -> List[Dict[str, Any]]:
        if not isinstance(value, list):
            return []
        rows: List[Dict[str, Any]] = []
        for item in value:
            if not isinstance(item, dict):
                continue
            try:
                mac = self.hub.norm_mac(item.get("mac"))
            except Exception:
                mac = str(item.get("mac") or "").strip().lower().replace("-", ":")
            if not mac:
                continue
            rows.append({
                "mac": mac,
                "uploadBps": _integer(item.get("uploadBps")),
                "downloadBps": _integer(item.get("downloadBps")),
                "connectionCount": _integer(item.get("connectionCount")),
            })
        rows.sort(key=lambda row: row["mac"])
        return rows

    def accept_push(self, payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("invalid realtime payload")

        # Snapshot the APP-owned lease before touching sample memory. A Relay push
        # never renews demand and cannot keep high-frequency collection alive.
        with self._demand:
            demand = self._demand_payload_locked()
        devices_active = bool(demand["devicesActive"])

        sample_epoch_ms = self._sample_epoch_ms(payload.get("sampleEpochMs"))
        source = _clean_source(payload.get("source"))
        agent_version = str(payload.get("agentVersion") or "").strip()[:32]
        devices_supplied = devices_active and isinstance(payload.get("devices"), list)
        devices = self._device_rows(payload.get("devices")) if devices_supplied else []

        devices_event: Dict[str, Any] = {}
        with self._lock:
            if devices_supplied:
                previous = {row["mac"]: row for row in self._devices}
                changed_rows = [
                    row for row in devices
                    if previous.get(row["mac"]) != row
                ]
                changed = devices != self._devices or sample_epoch_ms != self._devices_epoch_ms
                self._devices = devices
                self._devices_epoch_ms = sample_epoch_ms
                self._devices_source = source
                self._devices_agent_version = agent_version
                if changed:
                    self._devices_sequence += 1
                devices_event = {
                    "ok": True,
                    "sampleEpochMs": sample_epoch_ms,
                    "sequence": self._devices_sequence,
                    "source": source,
                    "delta": True,
                    "onlineDeviceCount": len(devices),
                    "devices": changed_rows,
                }

        publisher = getattr(self.hub, "MQTT_PUBLISHER", None)
        if devices_event and publisher is not None:
            publisher.publish_devices_realtime(devices_event)

        demand["acceptedRouter"] = False
        demand["acceptedDevices"] = devices_supplied
        return demand

    def router_payload(self) -> Dict[str, Any]:
        with self._lock:
            sample = dict(self._router_sample)
            epoch_ms = self._router_epoch_ms
            sequence = self._router_sequence
            source = self._router_source
            agent_version = self._router_agent_version
        now_ms = int(time.time() * 1000)
        age_ms = max(0, now_ms - epoch_ms) if epoch_ms else 0
        return {
            "ok": True,
            "sampleEpochMs": epoch_ms,
            "serverEpochMs": now_ms,
            "sampleAgeMs": age_ms,
            "sequence": sequence,
            "source": source or "waiting_router_eweb_ws_fast",
            "agentVersion": agent_version,
            "stale": not epoch_ms or age_ms > ROUTER_STALE_MS,
            **sample,
            "error": "" if sample else "等待路由器本地实时采样",
        }

    def devices_payload(self) -> Dict[str, Any]:
        with self._lock:
            devices = [dict(row) for row in self._devices]
            epoch_ms = self._devices_epoch_ms
            sequence = self._devices_sequence
            source = self._devices_source
            agent_version = self._devices_agent_version
        now_ms = int(time.time() * 1000)
        age_ms = max(0, now_ms - epoch_ms) if epoch_ms else 0
        return {
            "ok": True,
            "sampleEpochMs": epoch_ms,
            "serverEpochMs": now_ms,
            "sampleAgeMs": age_ms,
            "sequence": sequence,
            "source": source or "waiting_relay_local",
            "agentVersion": agent_version,
            "stale": not epoch_ms or age_ms > DEVICES_STALE_MS,
            "delta": False,
            "onlineDeviceCount": len(devices),
            "devices": devices,
            "error": "" if epoch_ms else "等待路由器本地终端采样",
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

    @hub.app.get("/api/router/realtime/agent/demand")
    def api_router_realtime_agent_demand():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad agent token"}), 401
        since = _integer(request.args.get("since"), 0)
        wait_seconds = min(55, _integer(request.args.get("wait"), 0))
        return jsonify(service.demand_payload(since=since, wait_seconds=wait_seconds))

    @hub.app.post("/api/router/realtime/agent/push")
    def api_router_realtime_agent_push():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad agent token"}), 401
        try:
            result = service.accept_push(request.get_json(silent=True) or {})
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify(result)

    service.start()
    publisher = getattr(hub, "MQTT_PUBLISHER", None)
    if publisher is not None:
        publisher.set_realtime_demand_handler(service.set_wss_demand)
    hub.ROUTER_LITE_REALTIME = service
    return service
