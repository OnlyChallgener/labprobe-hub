"""Verified low-latency runtime channels for the Android foreground UI.

Design rules:
- Router counters read the native /ws ``fast`` frame directly.  They never wait
  for the full dashboard normalizer or device/configuration RPCs.
- If the router does not emit a fresh ``fast`` frame for 2.5 seconds, a separate
  short-timeout HTTP lane requests ``devSta.get/ws_sysinfo {get: fast}``.
- Device rates use another independent HTTP lane requesting
  ``devSta.get/user_list {dataType: timely}``.
- Neither runtime lane calls, wraps, locks or delays the normal full device sync.
- APP-facing requests only return memory snapshots and are therefore immediate.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import jsonify

from router_rpc import GLOBAL_ROUTER_SESSION_CACHE, _deep_strip_runtime_fields, _wire_json


ROUTER_WS_FRESH_SECONDS = 2.5
ROUTER_RUNTIME_INTERVAL_SECONDS = 1.0
DEVICE_RUNTIME_INTERVAL_SECONDS = 1.5
RUNTIME_DEMAND_SECONDS = 5.0


def _integer(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(float(str(value).strip().rstrip("%"))))
    except (TypeError, ValueError):
        return default


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip().rstrip("%"))
    except (TypeError, ValueError):
        return default


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _decode(value: Any) -> Any:
    current = value
    for _ in range(5):
        if isinstance(current, str):
            text = current.strip()
            if text.startswith(("{", "[")):
                try:
                    current = json.loads(text)
                    continue
                except Exception:
                    return current
        if isinstance(current, dict) and "data" in current:
            keys = set(current)
            if keys.issubset({"data", "code", "id", "error", "rcode", "message", "msg"}):
                current = current.get("data")
                continue
        break
    return current


def _walk(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _first(value: Any, *keys: str, default: Any = 0) -> Any:
    wanted = {key.lower() for key in keys}
    for key, child in _walk(value):
        if key.lower() in wanted and child not in (None, "", [], {}):
            return child
    return default


def _dict(value: Any, *keys: str) -> Dict[str, Any]:
    if isinstance(value, dict):
        for key in keys:
            child = value.get(key)
            if isinstance(child, dict):
                return child
    wanted = {key.lower() for key in keys}
    for key, child in _walk(value):
        if key.lower() in wanted and isinstance(child, dict):
            return child
    return {}


def _clean_mac(hub: Any, value: Any) -> str:
    try:
        return hub.norm_mac(value)
    except Exception:
        return str(value or "").strip().lower().replace("-", ":")


def _device_rows(hub: Any, raw: Any) -> List[Dict[str, Any]]:
    root = _decode(raw)
    items = root.get("items", root.get("list", [])) if isinstance(root, dict) else root if isinstance(root, list) else []
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


def _router_metrics_from_fast(fast_value: Any, online_devices: int = 0) -> Dict[str, Any]:
    fast = _decode(fast_value)
    if not isinstance(fast, dict):
        return {}
    wan_stat = _dict(fast, "wan_stat", "wanStat")
    aggregate = _dict(wan_stat, "wans") or _dict(wan_stat, "wan") or wan_stat
    if not isinstance(aggregate, dict):
        aggregate = {}
    return {
        "uploadBps": _integer(aggregate.get("up")),
        "downloadBps": _integer(aggregate.get("down")),
        "totalUploadBytes": _integer(aggregate.get("total_up")),
        "totalDownloadBytes": _integer(aggregate.get("total_down")),
        "cpuPercent": _number(_first(fast, "cpu_usage", "cpuUsage", "cpuutil")),
        "memoryPercent": _number(_first(fast, "memutil", "memoryPercent", "memory_usage")),
        "temperatureC": _number(_first(fast, "temp", "temperature", "temperatureC")),
        "uptimeSeconds": _integer(_first(fast, "runtime", "uptime", "uptimeSeconds")),
        "onlineDeviceCount": max(0, int(online_devices)),
        "ipv4Connections": _integer(aggregate.get("ipv4_connection_count")),
        "ipv6Connections": _integer(aggregate.get("ipv6_connection_count")),
        "ipv4HalfConnections": _integer(aggregate.get("ipv4_half_connection_count")),
        "ipv6HalfConnections": _integer(aggregate.get("ipv6_half_connection_count")),
        "cps": _integer(aggregate.get("cps")),
    }


class _RealtimeRpcLane:
    """Independent short-timeout eWeb CMD connection.

    It shares only the already-authenticated SID/cookie snapshot.  It does not
    share requests.Session, connection pools or locks with normal Hub syncing.
    """

    def __init__(self, client: Any, name: str):
        self.client = client
        self.name = name
        self.http = requests.Session()
        try:
            self.http.headers.update(dict(client.http.headers))
        except Exception:
            pass
        self._lock = threading.Lock()

    def close(self) -> None:
        self.http.close()

    def rpc(self, module: str, data: Optional[Dict[str, Any]] = None) -> Any:
        with self._lock:
            cfg = self.client.config
            session = self.client.session
            if not getattr(session, "sid", "") or not getattr(session, "valid_locally", False):
                session = self.client.login()
            sid = str(getattr(session, "sid", "") or "").strip()
            if not sid:
                raise RuntimeError("router session has no sid")

            config_key = self.client._session_cache_key(cfg)
            GLOBAL_ROUTER_SESSION_CACHE.restore(config_key, self.http)
            params: Dict[str, Any] = {
                "module": module,
                "noParse": True,
                "async": None,
                "remoteIp": False,
                "device": "pc",
            }
            if data is not None:
                params["data"] = _deep_strip_runtime_fields(data)
            payload = {"method": "devSta.get", "params": params}
            url = str(cfg.get("address") or "").rstrip("/") + f"/cgi-bin/luci/api/cmd?auth={sid}"
            started = time.monotonic()
            response = self.http.post(
                url,
                data=_wire_json(payload).encode("utf-8"),
                headers=self.client._headers_for(payload, session),
                timeout=(1.2, 2.8),
                verify=bool(cfg.get("verifyTls", False)),
                allow_redirects=False,
            )
            duration_ms = int((time.monotonic() - started) * 1000)
            if response.status_code in {401, 403}:
                raise RuntimeError(f"runtime {self.name} auth rejected")
            if response.status_code >= 400:
                raise RuntimeError(f"runtime {self.name} HTTP {response.status_code}")
            try:
                root = response.json()
            except ValueError as exc:
                raise RuntimeError(f"runtime {self.name} returned invalid JSON") from exc
            if isinstance(root, dict) and root.get("error"):
                raise RuntimeError(f"runtime {self.name} rejected")
            if isinstance(root, dict):
                try:
                    code = int(root.get("code") or 0)
                except (TypeError, ValueError):
                    code = -1
                if code != 0:
                    raise RuntimeError(f"runtime {self.name} code {code}")
                value = root.get("data") if "data" in root else root
            else:
                value = root
            return _decode(value), duration_ms


class RouterLiteRealtimeService:
    def __init__(self, hub: Any, router_sync: Any, router_lane: Any = None, device_lane: Any = None):
        self.hub = hub
        self.sync = router_sync
        self.client = router_sync.client
        self.logger = hub.LOGGER
        self._cache_lock = threading.RLock()
        self._stop = threading.Event()
        self._router_wake = threading.Event()
        self._device_wake = threading.Event()
        self._last_router_demand = 0.0
        self._last_device_demand = 0.0
        self._router_lane = router_lane or _RealtimeRpcLane(self.client, "router-fast")
        self._device_lane = device_lane or _RealtimeRpcLane(self.client, "device-timely")
        self._router_sample: Dict[str, Any] = {}
        self._router_epoch = 0.0
        self._router_source = ""
        self._router_sequence = 0
        self._router_duration_ms = 0
        self._router_error = ""
        self._devices: List[Dict[str, Any]] = []
        self._device_epoch = 0.0
        self._device_source = ""
        self._device_sequence = 0
        self._device_duration_ms = 0
        self._device_error = ""
        self._router_thread = threading.Thread(target=self._router_loop, name="router-runtime-fast", daemon=True)
        self._device_thread = threading.Thread(target=self._device_loop, name="router-runtime-devices", daemon=True)
        self._preload_device_cache()

    def _preload_device_cache(self) -> None:
        try:
            document = self.hub.load_json(self.hub.DEVICES_FILE, {})
            rows = _device_rows(self.hub, document.get("online", []) if isinstance(document, dict) else [])
            if rows:
                self._store_devices(rows, "full_sync_cache", 0)
        except Exception:
            pass

    def start(self) -> None:
        self._router_thread.start()
        self._device_thread.start()
        self.logger.info("router verified realtime channels enabled")

    def stop(self) -> None:
        self._stop.set()
        self._router_wake.set()
        self._device_wake.set()
        for lane in (self._router_lane, self._device_lane):
            close = getattr(lane, "close", None)
            if callable(close):
                close()

    def mark_router_demand(self) -> None:
        self._last_router_demand = time.monotonic()
        self._router_wake.set()

    def mark_device_demand(self) -> None:
        self._last_device_demand = time.monotonic()
        self._device_wake.set()

    def _online_device_count(self) -> int:
        with self.hub.ROUTER_DASHBOARD_LOCK:
            dashboard = self.hub.ROUTER_DASHBOARD_CACHE or {}
            telemetry = dashboard.get("telemetry") if isinstance(dashboard.get("telemetry"), dict) else {}
            return _integer(telemetry.get("onlineDeviceCount"))

    def _ws_fast_snapshot(self) -> Tuple[Dict[str, Any], float]:
        monitor = getattr(self.client, "router_ws_monitor", None)
        if monitor is None:
            return {}, 0.0
        lock = getattr(monitor, "_lock", None)
        if lock is None:
            return {}, 0.0
        with lock:
            messages = getattr(monitor, "_messages", {})
            message_at = getattr(monitor, "_message_at", {})
            fast = _clone(messages.get("fast")) if isinstance(messages.get("fast"), dict) else {}
            epoch = float(message_at.get("fast") or 0.0)
        return fast, epoch

    def _store_router(self, metrics: Dict[str, Any], epoch: float, source: str, duration_ms: int) -> None:
        if not metrics:
            return
        with self._cache_lock:
            changed = metrics != self._router_sample or epoch != self._router_epoch or source != self._router_source
            self._router_sample = metrics
            self._router_epoch = epoch or time.time()
            self._router_source = source
            self._router_duration_ms = duration_ms
            self._router_error = ""
            if changed:
                self._router_sequence += 1

    def _promote_ws_fast(self) -> bool:
        fast, epoch = self._ws_fast_snapshot()
        if not fast or epoch <= 0:
            return False
        metrics = _router_metrics_from_fast(fast, self._online_device_count())
        self._store_router(metrics, epoch, "router_ws_fast", 0)
        return time.time() - epoch <= ROUTER_WS_FRESH_SECONDS

    def _refresh_router_rpc(self) -> None:
        try:
            raw, duration_ms = self._router_lane.rpc("ws_sysinfo", {"get": "fast"})
            metrics = _router_metrics_from_fast(raw, self._online_device_count())
            self._store_router(metrics, time.time(), "router_rpc_fast", duration_ms)
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            with self._cache_lock:
                changed = message != self._router_error
                self._router_error = message
            if changed:
                self.logger.warning("router fast runtime sample failed: %s", message)

    def _router_loop(self) -> None:
        while not self._stop.is_set():
            active = time.monotonic() - self._last_router_demand <= RUNTIME_DEMAND_SECONDS
            if not active:
                self._router_wake.wait(2.0)
                self._router_wake.clear()
                continue
            started = time.monotonic()
            ws_fresh = self._promote_ws_fast()
            if not ws_fresh:
                self._refresh_router_rpc()
            elapsed = time.monotonic() - started
            self._router_wake.wait(max(0.1, ROUTER_RUNTIME_INTERVAL_SECONDS - elapsed))
            self._router_wake.clear()

    def _store_devices(self, rows: List[Dict[str, Any]], source: str, duration_ms: int) -> None:
        now = time.time()
        with self._cache_lock:
            changed = rows != self._devices or source != self._device_source
            self._devices = rows
            self._device_epoch = now
            self._device_source = source
            self._device_duration_ms = duration_ms
            self._device_error = ""
            if changed:
                self._device_sequence += 1

    def _refresh_devices_rpc(self) -> None:
        try:
            raw, duration_ms = self._device_lane.rpc(
                "user_list",
                {"devType": "all", "dataType": "timely"},
            )
            self._store_devices(_device_rows(self.hub, raw), "router_rpc_timely", duration_ms)
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            with self._cache_lock:
                changed = message != self._device_error
                self._device_error = message
            if changed:
                self.logger.warning("device timely runtime sample failed: %s", message)

    def _device_loop(self) -> None:
        while not self._stop.is_set():
            active = time.monotonic() - self._last_device_demand <= RUNTIME_DEMAND_SECONDS
            if not active:
                self._device_wake.wait(2.0)
                self._device_wake.clear()
                continue
            started = time.monotonic()
            self._refresh_devices_rpc()
            elapsed = time.monotonic() - started
            self._device_wake.wait(max(0.1, DEVICE_RUNTIME_INTERVAL_SECONDS - elapsed))
            self._device_wake.clear()

    def router_payload(self) -> Dict[str, Any]:
        self.mark_router_demand()
        self._promote_ws_fast()
        with self._cache_lock:
            sample = dict(self._router_sample)
            epoch = self._router_epoch
            source = self._router_source
            sequence = self._router_sequence
            duration_ms = self._router_duration_ms
            error = self._router_error
        now = time.time()
        age_ms = int(max(0.0, now - epoch) * 1000) if epoch else 0
        return {
            "ok": True,
            "sampleEpochMs": int(epoch * 1000) if epoch else 0,
            "serverEpochMs": int(now * 1000),
            "sampleAgeMs": age_ms,
            "sequence": sequence,
            "source": source,
            "requestDurationMs": duration_ms,
            "stale": not epoch or age_ms > 3_000,
            **sample,
            "error": error if not sample else "",
        }

    def devices_payload(self) -> Dict[str, Any]:
        self.mark_device_demand()
        with self._cache_lock:
            rows = _clone(self._devices)
            epoch = self._device_epoch
            source = self._device_source
            sequence = self._device_sequence
            duration_ms = self._device_duration_ms
            error = self._device_error
        now = time.time()
        age_ms = int(max(0.0, now - epoch) * 1000) if epoch else 0
        return {
            "ok": True,
            "sampleEpochMs": int(epoch * 1000) if epoch else 0,
            "serverEpochMs": int(now * 1000),
            "sampleAgeMs": age_ms,
            "sequence": sequence,
            "source": source,
            "requestDurationMs": duration_ms,
            "stale": not epoch or age_ms > 4_000,
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
