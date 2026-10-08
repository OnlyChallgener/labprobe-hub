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

from router_capabilities import is_be50_firmware


ROUTER_STALE_MS = 3_000
BE50_AGENT_STALE_MS = 10_000
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

    # Agent 的 dashboard 推送是 EG 线（BE50 那类）唯一的实时源：那台机器的 eWeb 端口表
    # 和 WS 采样接口跟 BE72 不是一套，hub 连上去只会永远 ``等待路由器本地实时采样``。
    # 但 BE72 上 eWeb 更快也更全，不能被 2 秒一次的 agent 推送盖过去，所以只在 eWeb
    # 超过这个秒数没出样时才让 agent 顶上。
    AGENT_TELEMETRY_TAKEOVER_SECONDS = 20

    @staticmethod
    def flatten_agent_telemetry(telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """把 agent 的嵌套 telemetry 摊平成 App 实时契约的字段名。

        值为 None 的字段直接丢掉：``storagePercent: null`` 是「没读到」，
        摊成 0.0 就会在 App 上显示成 0%，那是把未知伪装成测到过的数。
        """
        connections = telemetry.get("connections") if isinstance(telemetry.get("connections"), dict) else {}
        wan = telemetry.get("wan") if isinstance(telemetry.get("wan"), dict) else {}
        sample: Dict[str, Any] = {}
        flat = (
            ("cpuPercent", telemetry, "cpuPercent"),
            ("memoryPercent", telemetry, "memoryPercent"),
            ("temperatureC", telemetry, "temperatureC"),
            ("temperature2gC", telemetry, "temperature2gC"),
            ("temperature5gC", telemetry, "temperature5gC"),
            ("storagePercent", telemetry, "storagePercent"),
            ("uptimeSeconds", telemetry, "uptimeSeconds"),
            ("onlineDeviceCount", telemetry, "onlineDeviceCount"),
            ("ipv4Connections", connections, "ipv4"),
            ("ipv6Connections", connections, "ipv6"),
            ("ipv4HalfConnections", connections, "ipv4Half"),
            ("ipv6HalfConnections", connections, "ipv6Half"),
            ("cps", connections, "cps"),
            ("downloadBps", wan, "downloadBps"),
            ("uploadBps", wan, "uploadBps"),
            ("totalDownloadBytes", wan, "totalDownloadBytes"),
            ("totalUploadBytes", wan, "totalUploadBytes"),
        )
        for target, source, key in flat:
            value = source.get(key) if key in source else None
            if value is not None:
                sample[target] = value
        return sample

    def accept_agent_telemetry(self, telemetry: Any, sample_epoch_ms: int = 0) -> None:
        """Feed the App realtime contract from an agent dashboard push.

        Skipped while the eWeb WebSocket path is still producing samples, so this
        never downgrades a Reyee box that already has the faster source.
        """
        if not isinstance(telemetry, dict):
            return
        with self._lock:
            data = dict((self._latest_router_frame or {}).get("data") or {})
        source = str(data.get("source") or "")
        epoch_ms = _integer(data.get("sampleEpochMs"), 0)
        if source.startswith("router_eweb_ws") and epoch_ms and \
                int(time.time() * 1000) - epoch_ms < int(self.AGENT_TELEMETRY_TAKEOVER_SECONDS * 1000):
            return
        sample = self.flatten_agent_telemetry(telemetry)
        if not sample:
            return
        self._accept_router_sample(sample, sample_epoch_ms, "agent_dashboard_push")

    def accept_router_slow(self, sample: Any, sample_epoch_ms: int = 0) -> None:
        """Merge slow eWeb fields such as storage without delaying APP refresh."""
        if isinstance(sample, dict):
            sample = {
                k: v for k, v in sample.items()
                if k not in {"uploadBps", "downloadBps", "ipv4Connections", "ipv6Connections", "cps"}
            }
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
            stale_ms = (
                BE50_AGENT_STALE_MS
                if is_be50_firmware() and latest.get("source") == "agent_dashboard_push"
                else ROUTER_STALE_MS
            )
            latest["stale"] = not epoch_ms or age_ms > stale_ms
            return latest
        return {
            "ok": True,
            "state": "checking",
            "connected": False,
            # 没有真帧时不给 cpuPercent/memoryPercent/速率键：0.0 会被 App 渲染成「0%」，
            # 把「没测到」伪装成「测到 0」。缺键时 App 侧按 -- 显示。
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
