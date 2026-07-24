"""Hardening for the router native ``/ws type=fast`` realtime lane.

The router socket can remain TCP-connected while its one-second ``fast`` stream
has silently stopped. The original outer reconnect loop could also back off to
30 seconds after ordinary transport failures. This patch detects a silent fast
stall and caps every reconnect delay at three seconds, without using HTTP
Dashboard, terminal, configuration or Agent realtime fallbacks.
"""
from __future__ import annotations

import json
import ssl
import threading
import time
from typing import Any

import websocket

import router_lite_realtime_patch
import router_ws_patch

FAST_START_GRACE_SECONDS = 5.0
FAST_STALL_SECONDS = 4.5
FAST_SOCKET_POLL_SECONDS = 1.0
MAX_ROUTER_RETRY_SECONDS = 3.0
DEVICE_DEMAND_TTL_SECONDS = 15.0
ROUTER_STALE_MS = 7_000
DEVICES_STALE_MS = 7_000


def _fast_stream_stalled(monitor: Any, connected_at: float, now: float) -> bool:
    with monitor._lock:
        last_fast_at = float(getattr(monitor, "_last_fast_at", 0.0) or 0.0)
    if last_fast_at >= connected_at:
        return now - last_fast_at >= FAST_STALL_SECONDS
    return now - connected_at >= FAST_START_GRACE_SECONDS


def _run_connection_with_fast_watchdog(
    self: Any,
    ws_url: str,
    origin: str,
    cookie: str,
    verify_tls: bool,
    hostname: str,
) -> None:
    """Receive router frames and reopen the socket when ``fast`` goes silent."""
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
    ws.settimeout(FAST_SOCKET_POLL_SECONDS)
    connected_at = time.time()
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
                if _fast_stream_stalled(self, connected_at, time.time()):
                    self._set_connected(False, ws_url, "router fast stream stalled; reconnecting")
                    return
                continue
            if raw is None or raw == "":
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


def _router_ws_loop_fast_recovery(self: Any) -> None:
    """Original authentication semantics with a strict 1/2/3 second retry cap."""
    retry = 1.0
    last_logged_error = ""
    force_login = False
    while not self._stop.is_set():
        try:
            if not self._ensure_authenticated(force=force_login):
                self._stop.wait(1.0)
                continue
            force_login = False
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            self._set_connected(False, "", message if message != last_logged_error else "")
            last_logged_error = message
            self._stop.wait(retry)
            retry = min(MAX_ROUTER_RETRY_SECONDS, retry + 1.0)
            continue

        ws_url, origin, cookie, verify_tls, hostname = self._connection_info()
        if not ws_url:
            self._stop.wait(1.0)
            continue
        try:
            self._run_connection(ws_url, origin, cookie, verify_tls, hostname)
            retry = 1.0
            last_logged_error = ""
        except router_ws_patch.RouterWebSocketAuthExpired as exc:
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
            retry = 1.0 if force_login else min(MAX_ROUTER_RETRY_SECONDS, retry + 1.0)
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            self._set_connected(False, ws_url, message if message != last_logged_error else "")
            last_logged_error = message
            self._stop.wait(retry)
            retry = min(MAX_ROUTER_RETRY_SECONDS, retry + 1.0)


def install_router_fast_watchdog_patch() -> None:
    """Install once before the router client instance is created."""
    router_lite_realtime_patch.DEMAND_TTL_SECONDS = DEVICE_DEMAND_TTL_SECONDS
    router_lite_realtime_patch.ROUTER_STALE_MS = ROUTER_STALE_MS
    router_lite_realtime_patch.DEVICES_STALE_MS = DEVICES_STALE_MS

    monitor_class = router_ws_patch.RouterWebSocketMonitor
    if getattr(monitor_class, "_labprobe_fast_watchdog_patch", False):
        return
    monitor_class._run_connection = _run_connection_with_fast_watchdog
    monitor_class._loop = _router_ws_loop_fast_recovery
    monitor_class._labprobe_fast_watchdog_patch = True
