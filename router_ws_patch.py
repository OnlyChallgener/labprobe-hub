"""Native Reyee /ws telemetry for LabProbe Hub.

The eWeb dashboard keeps one WebSocket open at ``/ws``. The router proactively
pushes ``type=fast`` about once per second after authentication; that frame is
the primary route realtime channel and must stay independent from HTTP config,
Dashboard normalization, terminal queries and history traffic.
"""
from __future__ import annotations

import json
import os
import queue
import ssl
import threading
import time
from typing import Any, Callable, Dict, Optional
from urllib.parse import quote, urlsplit

import websocket

import router_compat
import router_rpc_v010


WS_MESSAGE_TYPES = {"static", "slow", "fast", "recent_wan", "daily_wan", "ping"}
_MISSING = object()

_FAST_WAN_INT_FIELDS = {
    "uploadBps": ("up", "uploadBps", "upload_bps", "uploadSpeed", "upSpeed", "txSpeed"),
    "downloadBps": ("down", "downloadBps", "download_bps", "downloadSpeed", "downSpeed", "rxSpeed"),
    "totalUploadBytes": ("total_up", "totalUploadBytes", "totalUpload", "txBytes"),
    "totalDownloadBytes": ("total_down", "totalDownloadBytes", "totalDownload", "rxBytes"),
    "ipv4Connections": ("ipv4_connection_count", "ipv4Connections", "ipv4Conn", "v4Conn"),
    "ipv6Connections": ("ipv6_connection_count", "ipv6Connections", "ipv6Conn", "v6Conn"),
    "ipv4HalfConnections": ("ipv4_half_connection_count", "ipv4HalfConnections"),
    "ipv6HalfConnections": ("ipv6_half_connection_count", "ipv6HalfConnections"),
    "cps": ("cps", "connectionsPerSecond"),
}

_FAST_ROOT_INT_FIELDS = {
    "uptimeSeconds": ("runtime", "uptime", "uptimeSeconds"),
    "onlineDeviceCount": ("onlineDeviceCount", "online_device_count", "online_sta_count", "sta_num", "user_count"),
    "maxConnections": ("conntrack_max", "maxConnections"),
}

_FAST_ROOT_NUMBER_FIELDS = {
    "cpuPercent": ("cpu_usage", "cpuUsage", "cpuutil", "cpuPercent"),
    "memoryPercent": ("memutil", "memoryPercent", "memory_usage"),
    "temperatureC": ("temp", "temperature", "temperatureC"),
}


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


def _number(value: Any) -> Any:
    if value is _MISSING:
        return _MISSING
    try:
        return float(str(value).strip().rstrip("%"))
    except (TypeError, ValueError):
        return _MISSING


def _integer(value: Any) -> Any:
    number = _number(value)
    if number is _MISSING:
        return _MISSING
    return max(0, int(number))


def _lookup_recursive(value: Any, keys: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        for key in keys:
            if key in value and value.get(key) is not None:
                return value.get(key)
        for child in value.values():
            found = _lookup_recursive(child, keys)
            if found is not _MISSING:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _lookup_recursive(child, keys)
            if found is not _MISSING:
                return found
    return _MISSING


def _lookup_dict_recursive(value: Any, keys: tuple[str, ...]) -> Dict[str, Any]:
    found = _lookup_recursive(value, keys)
    return found if isinstance(found, dict) else {}


def _message_type(message: Dict[str, Any]) -> str:
    return str(message.get("type") or message.get("msgType") or "").strip().lower()


def _message_payload(message: Dict[str, Any]) -> Any:
    data = message.get("data")
    return data if isinstance(data, (dict, list)) else message


def _aggregate_wan(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        if any(key in value for keys in _FAST_WAN_INT_FIELDS.values() for key in keys):
            return value
        child_rows = [child for child in value.values() if isinstance(child, dict)]
        if child_rows:
            return _sum_wan_rows(child_rows)
        return value
    if isinstance(value, list):
        return _sum_wan_rows([child for child in value if isinstance(child, dict)])
    return {}


def _sum_wan_rows(rows: list[Dict[str, Any]]) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    for target, keys in _FAST_WAN_INT_FIELDS.items():
        total = 0
        found_any = False
        for row in rows:
            value = _lookup_recursive(row, keys)
            number = _integer(value)
            if number is _MISSING:
                continue
            total += number
            found_any = True
        if found_any:
            output[target] = total
    return output


def normalize_fast_message(message: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the compact numeric APP realtime payload from one eWeb fast frame."""
    if not isinstance(message, dict):
        return {}
    root = _message_payload(message)
    wan_stat = _lookup_dict_recursive(root, ("wan_stat", "wanStat", "wanStatus"))
    aggregate = _aggregate_wan(
        wan_stat.get("wans")
        if isinstance(wan_stat.get("wans"), (dict, list))
        else wan_stat.get("wan")
        if isinstance(wan_stat.get("wan"), (dict, list))
        else wan_stat
    )

    sample: Dict[str, Any] = {}
    for target, keys in _FAST_WAN_INT_FIELDS.items():
        value = aggregate.get(target) if target in aggregate else _lookup_recursive(aggregate, keys)
        if value is _MISSING:
            value = _lookup_recursive(root, keys)
        number = _integer(value)
        if number is not _MISSING:
            sample[target] = number

    for target, keys in _FAST_ROOT_INT_FIELDS.items():
        number = _integer(_lookup_recursive(root, keys))
        if number is not _MISSING:
            sample[target] = number
    for target, keys in _FAST_ROOT_NUMBER_FIELDS.items():
        number = _number(_lookup_recursive(root, keys))
        if number is not _MISSING:
            sample[target] = number
    return sample


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
        self._fast_handler_lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._low_thread: Optional[threading.Thread] = None
        self._low_frequency_messages: queue.Queue = queue.Queue(maxsize=32)
        self._fast_handler: Optional[Callable[[Dict[str, Any], int], None]] = None
        self._messages: Dict[str, Dict[str, Any]] = {}
        self._message_at: Dict[str, float] = {}
        self._fast_sample: Dict[str, Any] = {}
        self._fast_epoch_ms = 0
        self._connected = False
        self._url = ""
        self._last_error = ""
        self._connected_at = 0.0
        self._last_message_at = 0.0
        self._last_fast_at = 0.0
        self._authenticated_once = False
        self._authenticated_at = 0.0
        self._authenticated = threading.Event()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._low_thread = threading.Thread(target=self._low_frequency_loop, name="router-eweb-ws-low", daemon=True)
        self._thread = threading.Thread(target=self._loop, name="router-eweb-ws", daemon=True)
        self._low_thread.start()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def set_fast_handler(self, handler: Callable[[Dict[str, Any], int], None]) -> None:
        with self._fast_handler_lock:
            self._fast_handler = handler
        with self._lock:
            sample = dict(self._fast_sample)
            epoch_ms = self._fast_epoch_ms
        if sample and epoch_ms:
            try:
                handler(dict(sample), epoch_ms)
            except Exception:
                self.logger.debug("router fast handler rejected replayed frame", exc_info=True)

    def wait_authenticated(self, timeout: float = 0.0) -> bool:
        return self._authenticated.wait(timeout=max(0.0, float(timeout or 0.0)))

    def _ensure_authenticated(self, force: bool = False) -> bool:
        session = self.client.session
        sid = str(getattr(session, "sid", "") or "").strip()
        if force or not self._authenticated_once or not sid:
            session = self.client.login(force=force)
            sid = str(getattr(session, "sid", "") or "").strip()
        if not sid:
            return False
        with self._lock:
            self._authenticated_once = True
            self._authenticated_at = time.time()
        self._authenticated.set()
        return True

    @staticmethod
    def _cookie_header(client: Any, sid: str) -> str:
        cookies: Dict[str, str] = {}
        try:
            cookies.update({cookie.name: cookie.value for cookie in client.http.cookies})
        except Exception:
            pass
        serial = str(getattr(client.session, "serial_number", "") or "").strip()
        if serial and sid:
            cookies[serial] = sid
        return "; ".join(f"{key}={value}" for key, value in cookies.items() if key and value)

    def _connection_info(self) -> tuple[str, str, str, bool, str]:
        cfg = self.client.config
        address = str(cfg.get("address") or "").strip().rstrip("/")
        if not address:
            return "", "", "", False, ""
        parsed = urlsplit(address if "://" in address else f"http://{address}")
        secure = parsed.scheme.lower() == "https"
        scheme = "wss" if secure else "ws"
        session = self.client.session
        sid = str(getattr(session, "sid", "") or "").strip()
        if not sid:
            return "", "", "", False, ""
        ws_url = f"{scheme}://{parsed.netloc}/ws?auth={quote(sid, safe='')}"
        origin = f"{'https' if secure else 'http'}://{parsed.netloc}"
        cookie = self._cookie_header(self.client, sid)
        return ws_url, origin, cookie, bool(cfg.get("verifyTls", False)), parsed.hostname or ""

    @staticmethod
    def _safe_url(value: str) -> str:
        return value.split("?", 1)[0] + "?auth=***" if "?" in value else value

    def _set_connected(self, connected: bool, url: str = "", error: str = "") -> None:
        safe_url = self._safe_url(url)
        with self._lock:
            changed = connected != self._connected
            self._connected = connected
            if safe_url:
                self._url = safe_url
            if connected:
                self._connected_at = time.time()
                self._last_error = ""
            elif error:
                self._last_error = error
        if changed:
            if connected:
                self.logger.info("router eweb websocket connected url=%s", safe_url)
            elif error:
                self.logger.warning("router eweb websocket disconnected: %s", error)

    def _store_low_frequency(self, message: Dict[str, Any]) -> None:
        message_type = _message_type(message)
        if not message_type:
            return
        now = time.time()
        with self._lock:
            self._messages[message_type] = message
            self._message_at[message_type] = now
            self._last_message_at = now

    def _store_fast(self, message: Dict[str, Any], sample: Dict[str, Any], epoch_ms: int) -> None:
        now = time.time()
        with self._lock:
            self._messages["fast"] = message
            self._message_at["fast"] = now
            self._last_message_at = now
            self._last_fast_at = now
            if sample:
                merged = dict(self._fast_sample)
                merged.update(sample)
                self._fast_sample = merged
                self._fast_epoch_ms = epoch_ms

    def _dispatch_message(self, message: Dict[str, Any]) -> None:
        message_type = _message_type(message)
        if not message_type:
            return
        if self._is_auth_invalid(message):
            raise RouterWebSocketAuthExpired("router websocket authentication rejected")
        if message_type == "fast":
            epoch_ms = int(time.time() * 1000)
            sample = normalize_fast_message(message)
            self._store_fast(message, sample, epoch_ms)
            if sample:
                with self._fast_handler_lock:
                    handler = self._fast_handler
                if handler is not None:
                    try:
                        handler(dict(sample), epoch_ms)
                    except Exception:
                        self.logger.debug("router fast handler failed; keeping websocket receiver alive", exc_info=True)
            return
        try:
            self._low_frequency_messages.put_nowait(message)
        except queue.Full:
            try:
                self._low_frequency_messages.get_nowait()
            except queue.Empty:
                pass
            try:
                self._low_frequency_messages.put_nowait(message)
            except queue.Full:
                pass

    def _low_frequency_loop(self) -> None:
        while not self._stop.is_set():
            try:
                message = self._low_frequency_messages.get(timeout=0.5)
            except queue.Empty:
                continue
            self._store_low_frequency(message)

    @staticmethod
    def _send(ws: websocket.WebSocket, action: str) -> None:
        ws.send(json.dumps({"action": action}, separators=(",", ":")))

    @staticmethod
    def _is_auth_invalid(message: Dict[str, Any]) -> bool:
        status = str(
            message.get("status")
            or message.get("code")
            or message.get("rcode")
            or message.get("errCode")
            or ""
        ).strip()
        if status in {"401", "403"}:
            return True
        text = json.dumps(message, ensure_ascii=False).lower()
        return (
            ("auth" in text or "login" in text or "session" in text or "sid" in text)
            and any(token in text for token in ("invalid", "expired", "unauthorized", "forbidden"))
        )

    @staticmethod
    def _bad_status_code(exc: Exception) -> int:
        for name in ("status_code", "status"):
            try:
                value = int(getattr(exc, name))
                if value:
                    return value
            except (TypeError, ValueError):
                pass
        return 0

    def _keepalive_loop(self, ws: websocket.WebSocket, stop: threading.Event) -> None:
        while not self._stop.wait(10.0) and not stop.is_set():
            try:
                self._send(ws, "keepalive")
            except Exception:
                stop.set()
                try:
                    ws.close()
                except Exception:
                    pass
                return

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
        keepalive_stop = threading.Event()
        keepalive_thread = threading.Thread(
            target=self._keepalive_loop,
            args=(ws, keepalive_stop),
            name="router-eweb-ws-keepalive",
            daemon=True,
        )
        keepalive_thread.start()
        try:
            while not self._stop.is_set():
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
                    self._dispatch_message(message)
        finally:
            keepalive_stop.set()
            try:
                ws.close()
            except Exception:
                pass

    def _loop(self) -> None:
        retry = 1.0
        last_logged_error = ""
        force_login = False
        while not self._stop.is_set():
            try:
                if not self._ensure_authenticated(force=force_login):
                    self._stop.wait(2.0)
                    continue
                force_login = False
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                self._set_connected(False, "", message if message != last_logged_error else "")
                last_logged_error = message
                self._stop.wait(retry)
                retry = min(30.0, retry * 2.0)
                continue
            ws_url, origin, cookie, verify_tls, hostname = self._connection_info()
            if not ws_url:
                self._stop.wait(2.0)
                continue
            try:
                self._run_connection(ws_url, origin, cookie, verify_tls, hostname)
                retry = 1.0
                last_logged_error = ""
            except RouterWebSocketAuthExpired as exc:
                message = f"{type(exc).__name__}: {exc}"
                self._set_connected(False, ws_url, message if message != last_logged_error else "")
                last_logged_error = message
                force_login = True
                self._stop.wait(1.0)
                retry = 1.0
            except websocket.WebSocketBadStatusException as exc:
                message = f"{type(exc).__name__}: {exc}"
                status_code = self._bad_status_code(exc)
                force_login = status_code in {401, 403}
                self._set_connected(False, ws_url, message if message != last_logged_error else "")
                last_logged_error = message
                self._stop.wait(1.0 if force_login else retry)
                retry = 1.0 if force_login else min(30.0, retry * 2.0)
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
                "lastFastAt": self._last_fast_at,
                "lastError": self._last_error,
                "messageTypes": sorted(self._messages),
                "authenticatedAt": self._authenticated_at,
            }
            return data


class RouterWebSocketAuthExpired(RuntimeError):
    pass


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
    del ws_live
    due = force or not cached or age >= _config_poll_seconds()
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

    ws_connected = bool(_dict(raw.get("wsStatus")).get("connected", False))
    normalized["online"] = bool(slow.get("connected")) or _truthy(slow.get("status")) or ws_connected
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
