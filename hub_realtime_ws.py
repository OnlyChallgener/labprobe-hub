"""Authenticated Hub-native WebSocket fan-out for compact realtime deltas.

This is intentionally separate from the router's eWeb socket.  Router eWeb
``fast`` frames and LabRelay device samples are first stored in Hub memory by
``RouterLiteRealtimeService``; this module only fans out the resulting compact
increments to foreground APP clients authenticated with the existing APP_TOKEN.
"""

from __future__ import annotations

import json
import queue
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict

from flask import jsonify, request
from flask_sock import Sock


CLIENT_QUEUE_SIZE = 4
KEEPALIVE_SECONDS = 3.0


@dataclass
class _RealtimeClient:
    client_id: str
    frames: queue.Queue[str] = field(default_factory=lambda: queue.Queue(maxsize=CLIENT_QUEUE_SIZE))


class HubRealtimeWebSocketService:
    """Fan out only small router/device realtime messages to APP clients."""

    def __init__(self, hub: Any, realtime_service: Any):
        self.hub = hub
        self.realtime_service = realtime_service
        self.logger = hub.LOGGER
        self._clients_lock = threading.RLock()
        self._clients: Dict[str, _RealtimeClient] = {}
        # Register through Flask-Sock's blueprint path before binding it to
        # the application.  This also works when this is the first dynamic
        # route installed on a minimal Flask app.
        self._sock = Sock()
        self._sock.route("/api/realtime/ws")(self._connect)
        self._sock.init_app(hub.app)

        @hub.app.before_request
        def _reject_unauthorized_realtime_ws():
            # Reject before the protocol upgrade so an invalid APP_TOKEN is
            # reported to the client as an HTTP authentication failure rather
            # than a briefly-open WebSocket that immediately closes.
            if request.path == "/api/realtime/ws" and not hub.check_app_token():
                return jsonify({"ok": False, "error": "unauthorized"}), 401
            return None

    @staticmethod
    def _frame(kind: str, payload: Dict[str, Any] | None = None) -> str:
        value: Dict[str, Any] = {"type": kind}
        if payload is not None:
            value["data"] = payload
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _enqueue(client: _RealtimeClient, frame: str) -> None:
        try:
            client.frames.put_nowait(frame)
            return
        except queue.Full:
            pass
        try:
            client.frames.get_nowait()
        except queue.Empty:
            pass
        try:
            client.frames.put_nowait(frame)
        except queue.Full:
            # A concurrent fan-out replaced the dropped frame.  Keeping the
            # latest queued values is preferable to blocking fast reception.
            return

    def _publish(self, kind: str, payload: Dict[str, Any]) -> None:
        if not isinstance(payload, dict) or not payload:
            return
        # The payload is already a compact in-memory event.  Never read a
        # dashboard, terminal list, SQLite document or router HTTP API here.
        frame = self._frame(kind, dict(payload))
        with self._clients_lock:
            clients = tuple(self._clients.values())
        for client in clients:
            self._enqueue(client, frame)

    def publish_router_realtime(self, payload: Dict[str, Any]) -> None:
        self._publish("router", payload)

    def publish_devices_realtime(self, payload: Dict[str, Any]) -> None:
        self._publish("devices", payload)

    def client_count(self) -> int:
        with self._clients_lock:
            return len(self._clients)

    def _register(self) -> _RealtimeClient:
        client = _RealtimeClient(client_id=f"app-ws-{secrets.token_hex(8)}")
        with self._clients_lock:
            self._clients[client.client_id] = client
        self.realtime_service.set_wss_demand(client.client_id, True)
        return client

    def _unregister(self, client: _RealtimeClient) -> None:
        with self._clients_lock:
            self._clients.pop(client.client_id, None)
        self.realtime_service.set_wss_demand(client.client_id, False)

    def _connect(self, ws: Any) -> None:
        # Flask-Sock exposes the normal Flask request context during the
        # handshake, so the same Bearer APP_TOKEN guard covers HTTP and WSS.
        if not self.hub.check_app_token():
            ws.close(1008, "unauthorized")
            return

        client = self._register()
        try:
            ws.send(self._frame("ready", {"serverEpochMs": int(time.time() * 1000)}))
            while True:
                try:
                    frame = client.frames.get(timeout=KEEPALIVE_SECONDS)
                except queue.Empty:
                    frame = self._frame("keepalive", {"serverEpochMs": int(time.time() * 1000)})
                ws.send(frame)
        except Exception:
            # A normal APP background/close path is expected.  Do not log a
            # noisy warning or let one client affect another sender.
            return
        finally:
            self._unregister(client)


def install_hub_realtime_ws(hub: Any, realtime_service: Any) -> HubRealtimeWebSocketService:
    existing = getattr(hub, "HUB_REALTIME_WEBSOCKET", None)
    if existing is not None:
        return existing
    service = HubRealtimeWebSocketService(hub, realtime_service)
    realtime_service.set_app_realtime_publisher(service)
    hub.HUB_REALTIME_WEBSOCKET = service
    return service
