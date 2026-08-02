import json
import threading
import time
from types import SimpleNamespace

from hub0935_sync_fix import (
    _patch_live_history_to_memory_only,
    _run_router_connection_without_app_keepalive,
)


class FakeSocket:
    def __init__(self):
        self.closed = False
        self.timeout = None
        self.frames = [json.dumps({"type": "fast", "data": {"up": 1}})]

    def settimeout(self, value):
        self.timeout = value

    def recv(self):
        return self.frames.pop(0)

    def close(self):
        self.closed = True


class FakeMonitor:
    def __init__(self):
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._last_fast_at = 0.0
        self.connected = []
        self.messages = []

    def _set_connected(self, connected, url="", error=""):
        self.connected.append((connected, url, error))

    def _dispatch_message(self, message):
        self.messages.append(message)
        self._last_fast_at = time.time()
        self._stop.set()


def test_router_native_ws_is_passive_and_sends_no_application_keepalive(monkeypatch):
    socket = FakeSocket()
    monkeypatch.setattr(
        "hub0935_sync_fix.websocket.create_connection",
        lambda *args, **kwargs: socket,
    )
    monitor = FakeMonitor()

    _run_router_connection_without_app_keepalive(
        monitor,
        "ws://192.168.5.1/ws?auth=test",
        "http://192.168.5.1",
        "sid=test",
        False,
        "192.168.5.1",
    )

    assert monitor.connected[0][0] is True
    assert monitor.messages == [{"type": "fast", "data": {"up": 1}}]
    assert socket.closed is True
    # FakeSocket deliberately has no send()/ping() method.  Reaching this line
    # proves the receiver did not emit the old {"action":"keepalive"} frame.


class FakeHistory:
    def __init__(self):
        self.calls = []

    def ingest(self, payload, **kwargs):
        self.calls.append((payload, kwargs))
        return {"accepted": True, "persisted": True}


class FakeHub(SimpleNamespace):
    def now_str(self):
        return "2026-08-02 21:00:00"


def test_live_router_poll_cannot_persist_or_overwrite_relay_history():
    history = FakeHistory()
    hub = FakeHub(DURABLE_DEVICE_HISTORY=history)
    _patch_live_history_to_memory_only(hub)

    live = history.ingest(
        {"list": []},
        prepared_online=[{"mac": "aa:bb:cc:dd:ee:ff"}],
        prepared_total=1,
    )
    assert live["accepted"] is True
    assert live["liveOnly"] is True
    assert live["persisted"] is False
    assert history.calls == []

    durable = history.ingest({"list": [{"mac": "aa:bb:cc:dd:ee:ff"}]})
    assert durable["persisted"] is True
    assert len(history.calls) == 1
