"""Demand-driven realtime bridge backed by router-local LabRelay collection.

APP requests only read memory. The first foreground request wakes LabRelay by a
long-poll condition; while demand remains active, Relay executes the same local
``dev_sta`` commands that were previously fast over SSH and pushes only compact
numeric samples. Hub never performs high-frequency eWeb/CMD calls here, and the
normal full device/configuration sync remains completely independent.

The APP request itself is the lease. Once the lease expires, Relay push requests
are acknowledged with inactive demand but their samples are not written into the
Hub cache. The last valid frame remains available for UI continuity without any
continued cache churn or high-frequency collection.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List

from flask import jsonify, request


DEMAND_TTL_SECONDS = 5.0
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
        self._router_demand_until = 0.0
        self._devices_demand_until = 0.0

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
        self.logger.info("router relay-local realtime bridge enabled")

    def stop(self) -> None:
        with self._demand:
            self._stopped = True
            self._demand.notify_all()

    def _mark_demand(self, kind: str) -> None:
        now = time.time()
        with self._demand:
            attribute = "_router_demand_until" if kind == "router" else "_devices_demand_until"
            previous = float(getattr(self, attribute))
            was_active = previous > now
            setattr(self, attribute, max(previous, now + DEMAND_TTL_SECONDS))
            if not was_active:
                self._demand_sequence += 1
                self._demand.notify_all()

    def mark_router_demand(self) -> None:
        self._mark_demand("router")

    def mark_device_demand(self) -> None:
        self._mark_demand("devices")

    def _demand_payload_locked(self) -> Dict[str, Any]:
        now = time.time()
        return {
            "ok": True,
            "sequence": self._demand_sequence,
            "routerActive": self._router_demand_until > now,
            "devicesActive": self._devices_demand_until > now,
            "routerUntilEpochMs": int(self._router_demand_until * 1000),
            "devicesUntilEpochMs": int(self._devices_demand_until * 1000),
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
        router_active = bool(demand["routerActive"])
        devices_active = bool(demand["devicesActive"])

        sample_epoch_ms = self._sample_epoch_ms(payload.get("sampleEpochMs"))
        source = _clean_source(payload.get("source"))
        agent_version = str(payload.get("agentVersion") or "").strip()[:32]
        router = self._router_fields(payload.get("routerSample")) if router_active else {}
        devices_supplied = devices_active and isinstance(payload.get("devices"), list)
        devices = self._device_rows(payload.get("devices")) if devices_supplied else []

        if router and "onlineDeviceCount" not in router and devices_supplied:
            router["onlineDeviceCount"] = len(devices)

        with self._lock:
            if router:
                changed = router != self._router_sample or sample_epoch_ms != self._router_epoch_ms
                self._router_sample = router
                self._router_epoch_ms = sample_epoch_ms
                self._router_source = source
                self._router_agent_version = agent_version
                if changed:
                    self._router_sequence += 1
            if devices_supplied:
                changed = devices != self._devices or sample_epoch_ms != self._devices_epoch_ms
                self._devices = devices
                self._devices_epoch_ms = sample_epoch_ms
                self._devices_source = source
                self._devices_agent_version = agent_version
                if changed:
                    self._devices_sequence += 1

        demand["acceptedRouter"] = bool(router)
        demand["acceptedDevices"] = devices_supplied
        return demand

    def router_payload(self) -> Dict[str, Any]:
        self.mark_router_demand()
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
            "source": source or "waiting_relay_local",
            "agentVersion": agent_version,
            "stale": not epoch_ms or age_ms > ROUTER_STALE_MS,
            **sample,
            "error": "" if sample else "等待路由器本地实时采样",
        }

    def devices_payload(self) -> Dict[str, Any]:
        self.mark_device_demand()
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
    hub.ROUTER_LITE_REALTIME = service
    return service
