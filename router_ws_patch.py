"""Native Reyee /ws telemetry for LabProbe Hub.

The eWeb dashboard keeps one WebSocket open at ``/ws``. It pushes ``static``,
``slow`` and ``fast`` snapshots and returns ``recent_wan`` / ``daily_wan`` after
small action messages. Configuration and control remain on the signed HTTP CMD
API; this module supplies the live status path and keeps CMD dashboard polling
as a low-frequency configuration fallback.
"""
from __future__ import annotations

import json
import os
import ssl
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import websocket

import router_compat
import router_rpc_v010


WS_MESSAGE_TYPES = {"static", "slow", "fast", "recent_wan", "daily_wan", "ping"}


def _deep_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "on", "up", "connected", "online", "yes"}


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any, *keys: str) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in keys:
            rows = value.get(key)
            if isinstance(rows, list):
                return rows
    return []


def _first_text(row: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(row.get(key) or "").strip()
        if value and value.lower() not in {"none", "null"}:
            return value
    return ""


def _config_poll_seconds() -> float:
    try:
        return max(10.0, float(os.environ.get("ROUTER_CONFIG_POLL_SEC", "30")))
    except (TypeError, ValueError):
        return 30.0


class RouterWebSocketMonitor:
    def __init__(self, client: Any, logger: Any):
        self.client = client
        self.logger = logger
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._messages: Dict[str, Dict[str, Any]] = {}
        self._message_at: Dict[str, float] = {}
        self._connected = False
        self._url = ""
        self._last_error = ""
        self._connected_at = 0.0
        self._last_message_at = 0.0

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="router-eweb-ws", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _connection_info(self) -> tuple[str, str, str, bool, str]:
        cfg = self.client.config
        address = str(cfg.get("address") or "").strip().rstrip("/")
        if not address:
            return "", "", "", False, ""
        parsed = urlsplit(address if "://" in address else f"http://{address}")
        secure = parsed.scheme.lower() == "https"
        scheme = "wss" if secure else "ws"
        ws_url = f"{scheme}://{parsed.netloc}/ws"
        origin = f"{'https' if secure else 'http'}://{parsed.netloc}"
        session = self.client.session
        cookie = ""
        if getattr(session, "serial_number", "") and getattr(session, "sid", ""):
            cookie = f"{session.serial_number}={session.sid}"
        return ws_url, origin, cookie, bool(cfg.get("verifyTls", False)), parsed.hostname or ""

    def _set_connected(self, connected: bool, url: str = "", error: str = "") -> None:
        with self._lock:
            changed = connected != self._connected
            self._connected = connected
            if url:
                self._url = url
            if connected:
                self._connected_at = time.time()
                self._last_error = ""
            elif error:
                self._last_error = error
        if changed:
            if connected:
                self.logger.info("router eweb websocket connected url=%s", url)
            elif error:
                self.logger.warning("router eweb websocket disconnected: %s", error)

    def _store(self, message: Dict[str, Any]) -> None:
        message_type = str(message.get("type") or "").strip()
        if not message_type:
            return
        now = time.time()
        with self._lock:
            self._messages[message_type] = message
            self._message_at[message_type] = now
            self._last_message_at = now

    @staticmethod
    def _send(ws: websocket.WebSocket, action: str) -> None:
        ws.send(json.dumps({"action": action}, separators=(",", ":")))

    def _run_connection(self, ws_url: str, origin: str, cookie: str, verify_tls: bool, hostname: str) -> None:
        sslopt = None
        if ws_url.startswith("wss://") and not verify_tls:
            sslopt = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}
        ws = websocket.create_connection(
            ws_url,
            timeout=6,
            origin=origin,
            cookie=cookie or None,
            sslopt=sslopt or {},
            http_no_proxy=[hostname] if hostname else None,
            enable_multithread=True,
        )
        ws.settimeout(1.0)
        self._set_connected(True, ws_url)
        try:
            self._send(ws, "get_recent_wan")
            self._send(ws, "get_daily_wan")
            self._send(ws, "ping")
            last_keepalive = time.monotonic()
            last_history = time.monotonic()
            while not self._stop.is_set():
                now = time.monotonic()
                if now - last_keepalive >= 10.0:
                    self._send(ws, "keepalive")
                    last_keepalive = now
                if now - last_history >= 300.0:
                    self._send(ws, "get_recent_wan")
                    self._send(ws, "get_daily_wan")
                    last_history = now
                try:
                    raw = ws.recv()
                except websocket.WebSocketTimeoutException:
                    continue
                if raw is None:
                    raise RuntimeError("router websocket closed")
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                try:
                    message = json.loads(raw)
                except (TypeError, ValueError):
                    continue
                if isinstance(message, dict):
                    self._store(message)
        finally:
            try:
                ws.close()
            except Exception:
                pass

    def _loop(self) -> None:
        retry = 1.0
        last_logged_error = ""
        while not self._stop.is_set():
            ws_url, origin, cookie, verify_tls, hostname = self._connection_info()
            if not ws_url:
                self._stop.wait(2.0)
                continue
            try:
                self._run_connection(ws_url, origin, cookie, verify_tls, hostname)
                retry = 1.0
                last_logged_error = ""
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                self._set_connected(False, ws_url, message if message != last_logged_error else "")
                last_logged_error = message
                self._stop.wait(retry)
                retry = min(30.0, retry * 2.0)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            data = {key: _deep_copy(value) for key, value in self._messages.items() if key in WS_MESSAGE_TYPES}
            data["wsStatus"] = {
                "connected": self._connected,
                "url": self._url,
                "connectedAt": self._connected_at,
                "lastMessageAt": self._last_message_at,
                "lastError": self._last_error,
                "messageTypes": sorted(self._messages),
            }
            return data


_ORIGINAL_CLIENT_INIT = router_rpc_v010.StableRuijieRouterClient.__init__
_ORIGINAL_DASHBOARD = router_rpc_v010.StableRuijieRouterClient.dashboard
_ORIGINAL_NORMALIZE = router_compat.RouterRpcCompatibilitySync._normalize_dashboard


def _client_init(self: Any, *args: Any, **kwargs: Any) -> None:
    _ORIGINAL_CLIENT_INIT(self, *args, **kwargs)
    self._router_rpc_dashboard_lock = threading.RLock()
    self._router_rpc_dashboard_snapshot: Dict[str, Any] = {}
    self._router_rpc_dashboard_at = 0.0
    monitor = RouterWebSocketMonitor(self, self.logger)
    self.router_ws_monitor = monitor
    monitor.start()


def _load_rpc_dashboard_baseline(self: Any, ws_live: bool, force: bool) -> Dict[str, Any]:
    now = time.monotonic()
    with self._router_rpc_dashboard_lock:
        cached = _deep_copy(self._router_rpc_dashboard_snapshot) if self._router_rpc_dashboard_snapshot else {}
        age = now - float(self._router_rpc_dashboard_at or 0.0)
    due = not cached or not ws_live or age >= _config_poll_seconds()
    if not due:
        return cached
    try:
        current = _ORIGINAL_DASHBOARD(self, force)
    except Exception:
        if cached and ws_live:
            self.logger.debug("router CMD dashboard refresh failed; keeping cached configuration", exc_info=True)
            return cached
        raise
    output = dict(current) if isinstance(current, dict) else {}
    with self._router_rpc_dashboard_lock:
        self._router_rpc_dashboard_snapshot = _deep_copy(output)
        self._router_rpc_dashboard_at = now
    return output


def _dashboard(self: Any, force: bool = False) -> Dict[str, Any]:
    monitor = getattr(self, "router_ws_monitor", None)
    snapshot = monitor.snapshot() if monitor is not None else {}
    ws_status = _dict(snapshot.get("wsStatus"))
    ws_live = bool(ws_status.get("connected")) and bool(snapshot.get("fast") or snapshot.get("slow"))
    output = _load_rpc_dashboard_baseline(self, ws_live=ws_live, force=force)
    for key in ("static", "slow", "fast", "recent_wan", "daily_wan"):
        if isinstance(snapshot.get(key), dict):
            output[key] = snapshot[key]
    slow = _dict(snapshot.get("slow"))
    if isinstance(slow.get("port_status"), dict):
        output["portStatus"] = slow["port_status"]
    if isinstance(slow.get("wireless"), dict):
        output["wirelessRealtime"] = slow["wireless"]
    output["wsStatus"] = ws_status
    return output


def _normalized_ports(value: Any) -> list:
    rows = _list(value, "List", "list", "ports", "portList")
    normalized = []
    for index, item in enumerate(rows):
        if not isinstance(item, dict):
            continue
        row = dict(item)
        speed = _first_text(row, "speed", "rate", "link_speed", "linkSpeed")
        state = _first_text(row, "status", "link", "link_status", "linkStatus", "connected")
        connected = _truthy(state) or (speed not in {"", "0", "--"} and state.lower() not in {"off", "down", "disconnected"})
        row["status"] = "on" if connected else "off"
        row.setdefault("panel_name", _first_text(row, "panelName", "name") or f"端口{index + 1}")
        normalized.append(row)
    return normalized


def _merge_wireless(config: Any, realtime: Any) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    if isinstance(config, dict):
        merged.update(_deep_copy(config))
    if isinstance(realtime, dict):
        for key, value in realtime.items():
            if key in {"ssidList", "ssid_list"} and not value:
                continue
            merged[key] = _deep_copy(value)
    if "ssidList" not in merged and isinstance(merged.get("ssid_list"), list):
        merged["ssidList"] = merged["ssid_list"]
    if "radioList" not in merged and isinstance(merged.get("radio_list"), list):
        merged["radioList"] = merged["radio_list"]
    return merged


def _first_ssid(wireless: Dict[str, Any]) -> str:
    rows = _list(wireless, "ssidList", "ssid_list", "wlans", "list")
    fallback = ""
    for item in rows:
        if not isinstance(item, dict):
            continue
        name = _first_text(item, "ssidName", "ssid", "networkName")
        if not name:
            continue
        fallback = fallback or name
        enabled_value = item.get("enabled", item.get("enable", "true"))
        if str(enabled_value).strip().lower() not in {"0", "false", "off", "disabled"}:
            return name
    return fallback


def _normalize_dashboard(self: Any, raw: Dict[str, Any]) -> Dict[str, Any]:
    normalized = _ORIGINAL_NORMALIZE(self, raw)
    details = normalized.setdefault("details", {})
    telemetry = normalized.setdefault("telemetry", {})
    static = _dict(raw.get("static"))
    slow = _dict(raw.get("slow"))
    realtime_wireless = _dict(raw.get("wirelessRealtime")) or _dict(slow.get("wireless"))
    config_wireless = _dict(raw.get("wireless"))
    wireless = _merge_wireless(config_wireless, realtime_wireless)
    details["wireless"] = wireless
    details["wirelessConfig"] = config_wireless

    identity = details.setdefault("identity", {})
    ap = details.setdefault("ap", {})
    model = _first_text(static, "model", "product_name")
    serial = _first_text(static, "serial_number", "serialNumber", "sn")
    software = _first_text(static, "sw_version", "software", "firmware")
    hardware = _first_text(static, "hw_version", "hardware")
    hostname = _first_text(slow, "hostname")
    if model:
        identity["model"] = model
        ap["model"] = model
    if serial:
        identity["serialNumber"] = serial
        ap["serialNumber"] = serial
    if hostname:
        identity["hostname"] = hostname
        ap["hostName"] = hostname
        normalized["router"] = hostname
    if software:
        ap["software"] = software
    if hardware:
        ap["hardware"] = hardware

    ssid = _first_ssid(wireless)
    if ssid:
        ap["networkName"] = ssid

    radios = [row for row in _list(wireless, "radioList", "radio_list") if isinstance(row, dict)]
    bands, channels, utilization = [], [], []
    for row in radios:
        band = _first_text(row, "band", "name", "radio")
        channel = _first_text(row, "channel", "channelText")
        use = _first_text(
            row,
            "channel_utilization",
            "channelUtilization",
            "channel_usage",
            "channelUsage",
            "channel_util",
            "chutil",
            "utilization",
        )
        if band:
            bands.append(band)
        if channel:
            channels.append(channel)
        if use:
            utilization.append(use)
    if bands:
        ap["bands"] = list(dict.fromkeys(bands))
    if channels:
        ap["channels"] = channels[:2]
    if utilization:
        ap["channelUtilization"] = utilization[:2]
    if radios:
        ap["status"] = "ON" if any(_truthy(row.get("enabled", row.get("radio_switch", True))) for row in radios) else "OFF"

    ports = _normalized_ports(slow.get("port_status") or raw.get("portStatus"))
    if ports:
        details["ports"] = ports

    wan = details.setdefault("wan", {})
    wan_ip = _first_text(slow, "wan_ip", "wanIp")
    if wan_ip:
        wan["ipv4"] = wan_ip
    if "diskutil" in slow:
        try:
            telemetry["storagePercent"] = float(str(slow.get("diskutil")).strip().rstrip("%"))
        except (TypeError, ValueError):
            pass

    normalized["online"] = bool(slow.get("connected")) or _truthy(slow.get("status")) or bool(ws_status := _dict(raw.get("wsStatus"))).get("connected", False)
    normalized["telemetryStale"] = False if raw.get("fast") else normalized.get("telemetryStale", True)
    normalized["detailsStale"] = False if raw.get("slow") or raw.get("static") else normalized.get("detailsStale", True)
    normalized["source"] = "router_ws+rpc" if raw.get("fast") or raw.get("slow") else normalized.get("source", "router_rpc")
    details["recentWan"] = raw.get("recent_wan") or {}
    details["dailyWan"] = raw.get("daily_wan") or {}
    details["wsStatus"] = raw.get("wsStatus") or {}
    return normalized


def install_router_ws_patch() -> None:
    client_class = router_rpc_v010.StableRuijieRouterClient
    if not getattr(client_class, "_labprobe_ws_patch", False):
        client_class.__init__ = _client_init
        client_class.dashboard = _dashboard
        client_class._labprobe_ws_patch = True
    compat_class = router_compat.RouterRpcCompatibilitySync
    if not getattr(compat_class, "_labprobe_ws_patch", False):
        compat_class._normalize_dashboard = _normalize_dashboard
        compat_class._labprobe_ws_patch = True
