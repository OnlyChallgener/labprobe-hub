"""Authenticated Hub-native WebSocket fan-out for compact realtime deltas.

Router eWeb ``type=fast`` frames and LabRelay terminal samples are already
stored in Hub memory.  This module keeps one authenticated foreground WSS
connection per APP, immediately sends the latest memory snapshots, then fans
out compact deltas.  It never reads a router HTTP API, full Dashboard, terminal
list, SQLite document or revision stream.
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
PROTOCOL_NAME = "labprobe-realtime-v2"


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
        self._sock = Sock()
        self._sock.route("/api/realtime/ws")(self._connect)
        self._sock.init_app(hub.app)

        @hub.app.before_request
        def _reject_unauthorized_realtime_ws():
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
            return

    def _publish(self, kind: str, payload: Dict[str, Any]) -> None:
        if not isinstance(payload, dict) or not payload:
            return
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
        self._renew_client_lease(client)
        return client

    def _renew_client_lease(self, client: _RealtimeClient) -> None:
        # A live APP WSS connection is the terminal realtime demand lease.  The
        # router fast lane is independent and never waits for Agent demand.
        self.realtime_service.set_wss_demand(client.client_id, True)

    def _unregister(self, client: _RealtimeClient) -> None:
        with self._clients_lock:
            self._clients.pop(client.client_id, None)
        self.realtime_service.set_wss_demand(client.client_id, False)

    def _send(self, ws: Any, client: _RealtimeClient, frame: str) -> None:
        ws.send(frame)
        self._renew_client_lease(client)

    def _send_initial_snapshots(self, ws: Any, client: _RealtimeClient) -> None:
        router = self.realtime_service.router_payload()
        if int(router.get("sampleEpochMs") or 0) > 0:
            self._send(ws, client, self._frame("router", router))
        devices = self.realtime_service.devices_payload()
        if int(devices.get("sampleEpochMs") or 0) > 0:
            self._send(ws, client, self._frame("devices", devices))

    def _connect(self, ws: Any) -> None:
        if not self.hub.check_app_token():
            ws.close(1008, "unauthorized")
            return

        client = self._register()
        try:
            self._send(
                ws,
                client,
                self._frame(
                    "ready",
                    {
                        "protocol": PROTOCOL_NAME,
                        "clientId": client.client_id,
                        "serverEpochMs": int(time.time() * 1000),
                        "keepaliveSeconds": KEEPALIVE_SECONDS,
                    },
                ),
            )
            # Initial values come only from Hub memory, so the APP never waits
            # for Agent, HTTP login, Dashboard or a fresh router command.
            self._send_initial_snapshots(ws, client)
            sequence = 0
            while True:
                try:
                    frame = client.frames.get(timeout=KEEPALIVE_SECONDS)
                except queue.Empty:
                    sequence += 1
                    frame = self._frame(
                        "keepalive",
                        {
                            "sequence": sequence,
                            "serverEpochMs": int(time.time() * 1000),
                        },
                    )
                self._send(ws, client, frame)
        except Exception:
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
