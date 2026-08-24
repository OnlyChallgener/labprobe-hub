"""Router Core Realtime Aggregation Engine.

Manages 8 standard WSS frame types:
- ready, router, devices, devices_snapshot, task, config, agent, keepalive.
Guarantees exact App watchdog constants:
- OkHttp pingInterval = 10s
- watchdog check interval = 1s
- serverFrameTimeout = 45s
HTTP endpoints (/api/router/realtime, /api/devices/realtime) are calibration-only.
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
    """Realtime Broadcaster managing WSS client subscriptions and frames."""

    WATCHDOG_PING_INTERVAL_SECONDS = 10
    WATCHDOG_CHECK_INTERVAL_SECONDS = 1
    SERVER_FRAME_TIMEOUT_SECONDS = 45

    def __init__(self):
        self._subscribers: Set[Callable[[str], None]] = set()
        self._lock = threading.Lock()
        self._latest_router_frame: Optional[Dict[str, Any]] = None
        self._latest_devices_frame: Optional[Dict[str, Any]] = None

    def subscribe(self, callback: Callable[[str], None]) -> None:
        """Subscribes a WebSocket client queue/channel to broadcast frames."""
        with self._lock:
            self._subscribers.add(callback)

    def unsubscribe(self, callback: Callable[[str], None]) -> None:
        """Removes a WebSocket client callback."""
        with self._lock:
            self._subscribers.discard(callback)

    def broadcast(self, frame_dict: Dict[str, Any]) -> None:
        """Broadcasts a JSON frame to all active subscribers."""
        frame_type = frame_dict.get("type")
        if frame_type == "router":
            self._latest_router_frame = frame_dict
        elif frame_type in ("devices", "devices_snapshot"):
            self._latest_devices_frame = frame_dict

        raw_json = json.dumps(frame_dict, separators=(",", ":"))
        with self._lock:
            subscribers = list(self._subscribers)

        for sub in subscribers:
            try:
                sub(raw_json)
            except Exception:
                pass

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
