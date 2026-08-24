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
    ) -> Dict[str, Any]:
        return {
            "type": "router",
            "data": {
                "state": state,
                "connected": connected,
                "cpu": round(cpu, 1),
                "memory": round(memory, 1),
                "uploadSpeed": int(upload_speed),
                "downloadSpeed": int(download_speed),
                "wanIp": wan_ip,
                "message": message,
                "timestamp": int(time.time() * 1000),
            },
        }

    @staticmethod
    def devices(devices_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "type": "devices",
            "data": {
                "devices": devices_list,
                "count": len(devices_list),
                "timestamp": int(time.time() * 1000),
            },
        }

    @staticmethod
    def devices_snapshot(devices_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "type": "devices_snapshot",
            "data": {
                "devices": devices_list,
                "count": len(devices_list),
                "timestamp": int(time.time() * 1000),
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
        self._lock = threading.Lock()
        self._latest_router_frame: Optional[Dict[str, Any]] = None
        self._latest_devices_frame: Optional[Dict[str, Any]] = None
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
        if frame_type == "router":
            self._latest_router_frame = frame_dict
        elif frame_type in ("devices", "devices_snapshot"):
            self._latest_devices_frame = frame_dict

        raw_json = json.dumps(frame_dict, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            subscribers = list(self._subscribers)

        for sub in subscribers:
            try:
                sub(raw_json)
            except Exception:
                pass

    def emit_keepalive(self) -> None:
        """Emits a lightweight heartbeat keepalive frame."""
        self._last_heartbeat_at = time.time()
        self.broadcast(RealtimeFrame.keepalive())

    def get_router_calibration_snapshot(self) -> Dict[str, Any]:
        """Calibration snapshot for HTTP /api/router/realtime cold start."""
        if self._latest_router_frame:
            return self._latest_router_frame.get("data", {})
        return {
            "state": "checking",
            "connected": False,
            "cpu": 0.0,
            "memory": 0.0,
            "uploadSpeed": 0,
            "downloadSpeed": 0,
            "wanIp": "",
            "message": "正在准备数据",
            "timestamp": int(time.time() * 1000),
        }

    def get_devices_calibration_snapshot(self) -> List[Dict[str, Any]]:
        """Calibration snapshot for HTTP /api/devices/realtime cold start."""
        if self._latest_devices_frame:
            return self._latest_devices_frame.get("data", {}).get("devices", [])
        return []
