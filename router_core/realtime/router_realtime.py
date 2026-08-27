"""Router Core Realtime Aggregation Engine.

Hub Realtime Architecture & Responsibilities:
1. Ingest official Reyee /ws (eWeb fast-telemetry stream)
2. Ingest Relay realtime terminal samples
3. Normalize & maintain latest memory snapshots/deltas
4. Fan-out 8 standard App WSS frames:
   - ready, router, devices, devices_snapshot, task, config, agent, keepalive
5. Manage freshness/staleness without adding HTTP polling loops

Server vs Client Keepalive & Watchdog Parameters:
- HUB SERVER:
  - SERVER_KEEPALIVE_INTERVAL_SECONDS = 3.0 (idle keepalive frame heartbeat)
  - SERVER_CLIENT_QUEUE_SIZE = 8 (per-client ring buffer)
- ANDROID CLIENT BASELINE (for reference & compatibility tracking):
  - OkHttp pingInterval = 10s
  - watchdog check interval = 1s
  - server frame timeout = 45s
"""

import json
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set


ROUTER_STALE_MS = 3_000
DEVICES_STALE_MS = 4_000
_ROUTER_INTEGER_FIELDS = {
    "uploadBps",
    "downloadBps",
    "totalUploadBytes",
    "totalDownloadBytes",
    "uptimeSeconds",
    "onlineDeviceCount",
    "ipv4Connections",
    "ipv6Connections",
    "ipv4HalfConnections",
    "ipv6HalfConnections",
    "cps",
}
_ROUTER_NUMBER_FIELDS = {
    "cpuPercent",
    "memoryPercent",
    "temperatureC",
    "temperature2gC",
    "temperature5gC",
    "storagePercent",
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


def _sample_epoch_ms(value: Any = 0) -> int:
    now_ms = int(time.time() * 1000)
    sample_ms = _integer(value, now_ms)
    if sample_ms <= 0 or sample_ms > now_ms + 10_000:
        return now_ms
    return sample_ms


class RealtimeFrame:
    """Helper to build specification-compliant WSS frames."""

    @staticmethod
    def ready(client_id: str, server_time: int) -> Dict[str, Any]:
        return {
            "type": "ready",
            "data": {
                "clientId": client_id,
                "serverTime": server_time,
                "version": "1.0.0",
            },
        }

    @staticmethod
    def router(
        state: str,
        connected: bool,
        cpu: float = 0.0,
        memory: float = 0.0,
        upload_speed: int = 0,
        download_speed: int = 0,
        wan_ip: str = "",
        message: str = "",
        sample_epoch_ms: int = 0,
    ) -> Dict[str, Any]:
        epoch_ms = _sample_epoch_ms(sample_epoch_ms)
        return {
            "type": "router",
            "data": {
                "state": state,
                "connected": connected,
                "cpuPercent": round(cpu, 1),
                "memoryPercent": round(memory, 1),
                "uploadBps": _integer(upload_speed),
                "downloadBps": _integer(download_speed),
                "wanIp": wan_ip,
                "message": message,
                "sampleEpochMs": epoch_ms,
                "sampleAgeMs": max(0, int(time.time() * 1000) - epoch_ms),
                "stale": False,
            },
        }

    @staticmethod
    def devices(
        devices_list: List[Dict[str, Any]],
        sample_epoch_ms: int = 0,
        delta: bool = False,
    ) -> Dict[str, Any]:
        epoch_ms = _sample_epoch_ms(sample_epoch_ms)
        return {
            "type": "devices",
            "data": {
                "devices": devices_list,
                "onlineDeviceCount": len(devices_list),
                "delta": bool(delta),
                "sampleEpochMs": epoch_ms,
                "sampleAgeMs": max(0, int(time.time() * 1000) - epoch_ms),
            },
        }

    @staticmethod
    def devices_snapshot(devices_list: List[Dict[str, Any]], sample_epoch_ms: int = 0) -> Dict[str, Any]:
        epoch_ms = _sample_epoch_ms(sample_epoch_ms)
        return {
            "type": "devices_snapshot",
            "data": {
                "devices": devices_list,
                "onlineDeviceCount": len(devices_list),
                "fullSnapshot": True,
                "sampleEpochMs": epoch_ms,
                "sampleAgeMs": max(0, int(time.time() * 1000) - epoch_ms),
            },
        }

    @staticmethod
    def task(kind: str, state: str, progress: int = 0, message: str = "") -> Dict[str, Any]:
        return {
            "type": "task",
            "data": {
                "kind": kind,
                "state": state,
                "progress": progress,
                "message": message,
                "timestamp": int(time.time() * 1000),
            },
        }

    @staticmethod
    def config(resource: str, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "config",
            "data": {
                "resource": resource,
                "action": action,
                "data": payload,
                "timestamp": int(time.time() * 1000),
            },
        }

    @staticmethod
    def agent(status: str, version: str = "", ip: str = "") -> Dict[str, Any]:
        return {
            "type": "agent",
            "data": {
                "status": status,
                "version": version,
                "ip": ip,
                "timestamp": int(time.time() * 1000),
            },
        }

    @staticmethod
    def keepalive() -> Dict[str, Any]:
        return {
            "type": "keepalive",
            "data": {
                "timestamp": int(time.time() * 1000),
            },
        }


class RouterRealtimeEngine:
    """Hub Realtime Broadcaster managing client subscriptions, fan-out, and memory snapshots."""

    # Hub Server-Side Constants
    SERVER_KEEPALIVE_INTERVAL_SECONDS = 3.0
    SERVER_CLIENT_QUEUE_SIZE = 8

    # Reference Android Client Watchdog Parameters
    CLIENT_WATCHDOG_PING_INTERVAL_SECONDS = 10
    CLIENT_WATCHDOG_CHECK_INTERVAL_SECONDS = 1
    CLIENT_SERVER_FRAME_TIMEOUT_SECONDS = 45

    def __init__(self):
        self._subscribers: Set[Callable[[str], None]] = set()
        self._lock = threading.RLock()
        self._latest_router_frame: Optional[Dict[str, Any]] = None
        self._latest_devices_frame: Optional[Dict[str, Any]] = None
        self._router_sequence = 0
        self._last_heartbeat_at = time.time()

    def subscribe(self, callback: Callable[[str], None]) -> None:
        """Subscribes an authenticated client callback to broadcast frames."""
        with self._lock:
            self._subscribers.add(callback)

    def unsubscribe(self, callback: Callable[[str], None]) -> None:
        """Removes a client callback."""
        with self._lock:
            self._subscribers.discard(callback)

    def broadcast(self, frame_dict: Dict[str, Any]) -> None:
        """Broadcasts a normalized frame to all active App subscribers."""
        frame_type = frame_dict.get("type")
        raw_json = json.dumps(frame_dict, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            if frame_type == "router":
                self._latest_router_frame = frame_dict
            elif frame_type == "devices_snapshot" or (
                frame_type == "devices"
                and not bool((frame_dict.get("data") or {}).get("delta", False))
            ):
                self._latest_devices_frame = frame_dict
            subscribers = list(self._subscribers)

        for sub in subscribers:
            try:
                sub(raw_json)
            except Exception:
                pass

    def accept_router_fast(self, sample: Any, sample_epoch_ms: int = 0) -> None:
        """Normalize one Reyee ``fast`` sample and publish the App router contract."""
        self._accept_router_sample(sample, sample_epoch_ms, "router_eweb_ws_fast")

    def accept_router_slow(self, sample: Any, sample_epoch_ms: int = 0) -> None:
        """Merge slow eWeb fields such as storage without delaying APP refresh."""
        self._accept_router_sample(sample, sample_epoch_ms, "router_eweb_ws_slow")

    def _accept_router_sample(self, sample: Any, sample_epoch_ms: int, source: str) -> None:
        if not isinstance(sample, dict):
            return
        normalized: Dict[str, Any] = {}
        for key in _ROUTER_INTEGER_FIELDS:
            if key in sample:
                normalized[key] = _integer(sample.get(key))
        for key in _ROUTER_NUMBER_FIELDS:
            if key in sample:
                normalized[key] = _number(sample.get(key))
        if not normalized:
            return

        epoch_ms = _sample_epoch_ms(sample_epoch_ms)
        with self._lock:
            previous = dict((self._latest_router_frame or {}).get("data") or {})
            merged = {
                key: value
                for key, value in previous.items()
                if key in _ROUTER_INTEGER_FIELDS or key in _ROUTER_NUMBER_FIELDS
            }
            merged.update(normalized)
            self._router_sequence += 1
            sequence = self._router_sequence

        payload = {
            "ok": True,
            "state": "connected",
            "connected": True,
            "sampleEpochMs": epoch_ms,
            "sampleAgeMs": max(0, int(time.time() * 1000) - epoch_ms),
            "sequence": sequence,
            "source": source,
            "stale": False,
            **merged,
            "error": "",
        }
        self.broadcast({"type": "router", "data": payload})

    def accept_devices_realtime(
        self,
        payload: Any,
        snapshot: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Publish a Relay terminal delta while retaining its full memory snapshot."""
        if not isinstance(payload, dict) or _integer(payload.get("sampleEpochMs")) <= 0:
            return
        if isinstance(snapshot, dict) and _integer(snapshot.get("sampleEpochMs")) > 0:
            with self._lock:
                self._latest_devices_frame = {"type": "devices", "data": dict(snapshot)}
        self.broadcast({"type": "devices", "data": dict(payload)})

    def accept_devices_snapshot(self, payload: Any) -> None:
        """Publish the authoritative Router Driver ``user_list`` snapshot."""
        if not isinstance(payload, dict) or _integer(payload.get("sampleEpochMs")) <= 0:
            return
        frame = {"type": "devices_snapshot", "data": dict(payload)}
        self.broadcast(frame)

    def emit_keepalive(self) -> None:
        """Emits a lightweight heartbeat keepalive frame."""
        self._last_heartbeat_at = time.time()
        self.broadcast(RealtimeFrame.keepalive())

    def seed_from_dashboard(self, dashboard: Dict[str, Any]) -> None:
        """Seed realtime frame from cached dashboard or RPC snapshot so cold clients receive data immediately."""
        if not isinstance(dashboard, dict):
            return
        hardware = dashboard.get("hardware") if isinstance(dashboard.get("hardware"), dict) else {}
        traffic = dashboard.get("traffic") if isinstance(dashboard.get("traffic"), dict) else {}
        network = dashboard.get("network") if isinstance(dashboard.get("network"), dict) else {}
        
        cpu = _number(hardware.get("cpuUsage") or dashboard.get("cpuPercent") or dashboard.get("cpu"))
        mem = _number(hardware.get("memoryUsage") or dashboard.get("memoryPercent") or dashboard.get("memory"))
        up = _integer(traffic.get("uploadBps") or dashboard.get("uploadBps") or dashboard.get("uploadSpeed"))
        down = _integer(traffic.get("downloadBps") or dashboard.get("downloadBps") or dashboard.get("downloadSpeed"))
        wan = str(network.get("wanIp") or dashboard.get("wanIp") or "")

        sample = {
            "cpuPercent": cpu,
            "memoryPercent": mem,
            "uploadBps": up,
            "downloadBps": down,
            "wanIp": wan,
        }
        self._accept_router_sample(sample, int(time.time() * 1000), "router_dashboard_seed")

    def get_router_calibration_snapshot(self) -> Dict[str, Any]:
        """Calibration snapshot for HTTP /api/router/realtime cold start."""
        with self._lock:
            latest = dict((self._latest_router_frame or {}).get("data") or {})
        if latest:
            now_ms = int(time.time() * 1000)
            epoch_ms = _integer(latest.get("sampleEpochMs"))
            age_ms = max(0, now_ms - epoch_ms) if epoch_ms else 0
            latest["serverEpochMs"] = now_ms
            latest["sampleAgeMs"] = age_ms
            latest["stale"] = not epoch_ms or age_ms > ROUTER_STALE_MS
            return latest
        return {
            "ok": True,
            "state": "checking",
            "connected": False,
            "cpuPercent": 0.0,
            "memoryPercent": 0.0,
            "uploadBps": 0,
            "downloadBps": 0,
            "wanIp": "",
            "message": "正在准备数据",
            "sampleEpochMs": 0,
            "serverEpochMs": int(time.time() * 1000),
            "sampleAgeMs": 0,
            "stale": True,
            "error": "等待路由器本地实时采样",
        }

    def router_payload(self) -> Dict[str, Any]:
        return self.get_router_calibration_snapshot()

    def get_devices_calibration_snapshot(self) -> List[Dict[str, Any]]:
        """Calibration snapshot for HTTP /api/devices/realtime cold start."""
        with self._lock:
            latest = dict((self._latest_devices_frame or {}).get("data") or {})
        if latest:
            return list(latest.get("devices") or [])
        return []

    def devices_payload(self) -> Dict[str, Any]:
        with self._lock:
            latest = dict((self._latest_devices_frame or {}).get("data") or {})
        now_ms = int(time.time() * 1000)
        if not latest:
            return {
                "ok": True,
                "devices": [],
                "onlineDeviceCount": 0,
                "delta": False,
                "sampleEpochMs": 0,
                "serverEpochMs": now_ms,
                "sampleAgeMs": 0,
                "stale": True,
                "error": "等待路由器本地终端采样",
            }
        epoch_ms = _integer(latest.get("sampleEpochMs"))
        age_ms = max(0, now_ms - epoch_ms) if epoch_ms else 0
        latest["serverEpochMs"] = now_ms
        latest["sampleAgeMs"] = age_ms
        latest["stale"] = not epoch_ms or age_ms > DEVICES_STALE_MS
        latest["delta"] = False
        return latest
