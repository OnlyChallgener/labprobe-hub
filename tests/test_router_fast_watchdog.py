import time
from types import SimpleNamespace

import websocket

import router_build024_fix
import router_compat
import router_fast_watchdog_patch as patch
import router_lite_realtime_patch
import router_ws_patch


def test_install_sets_short_realtime_thresholds_and_patches_monitor():
    patch.install_router_fast_watchdog_patch()
    assert router_lite_realtime_patch.DEMAND_TTL_SECONDS == patch.DEVICE_DEMAND_TTL_SECONDS
    assert router_lite_realtime_patch.ROUTER_STALE_MS == patch.ROUTER_STALE_MS
    assert router_lite_realtime_patch.DEVICES_STALE_MS == patch.DEVICES_STALE_MS
    assert patch.MAX_ROUTER_RETRY_SECONDS == 2.0
    assert router_ws_patch.RouterWebSocketMonitor._run_connection is patch._run_connection_with_fast_watchdog
    assert router_ws_patch.RouterWebSocketMonitor._loop is patch._router_ws_loop_fast_recovery


def test_build024_restores_radio_temperature_storage_and_detail_worker():
    old_fields = set(router_lite_realtime_patch._ROUTER_FIELDS)
    old_fast_fields = dict(router_ws_patch._FAST_ROOT_NUMBER_FIELDS)
    old_router_fields = router_lite_realtime_patch.RouterLiteRealtimeService._router_fields
    old_start = router_compat.RouterRpcCompatibilitySync.start
    try:
        router_build024_fix.install_router_build024_fix()
        assert "temperature2gC" in router_lite_realtime_patch._ROUTER_FIELDS
        assert "temperature5gC" in router_lite_realtime_patch._ROUTER_FIELDS
        assert "storagePercent" in router_lite_realtime_patch._ROUTER_FIELDS
        assert router_ws_patch._FAST_ROOT_NUMBER_FIELDS["temperature2gC"][0] == "temp_2g"
        assert router_ws_patch._FAST_ROOT_NUMBER_FIELDS["temperature5gC"][0] == "temp_5g"
        assert router_build024_fix.DETAIL_REFRESH_SECONDS == 60.0
        service = object.__new__(router_lite_realtime_patch.RouterLiteRealtimeService)
        mapped = service._router_fields({
            "temperature2gC": 47.5,
            "temperature5gC": "50.25",
            "storagePercent": "34.23%",
        })
        assert mapped == {
            "temperature2gC": 47.5,
            "temperature5gC": 50.25,
            "storagePercent": 34.23,
        }
    finally:
        router_lite_realtime_patch._ROUTER_FIELDS.clear()
        router_lite_realtime_patch._ROUTER_FIELDS.update(old_fields)
        router_ws_patch._FAST_ROOT_NUMBER_FIELDS.clear()
        router_ws_patch._FAST_ROOT_NUMBER_FIELDS.update(old_fast_fields)
        router_lite_realtime_patch.RouterLiteRealtimeService._router_fields = old_router_fields
        router_compat.RouterRpcCompatibilitySync.start = old_start


def test_fast_stall_detection_uses_current_connection_only():
    now = time.time()
    monitor = SimpleNamespace(
        _lock=__import__("threading").RLock(),
        _last_fast_at=now - 100,
    )
    assert patch._fast_stream_stalled(monitor, now - 1, now) is False
    monitor._last_fast_at = now - patch.FAST_STALL_SECONDS - 0.1
    assert patch._fast_stream_stalled(monitor, now - 10, now) is True


def test_run_connection_returns_quickly_when_fast_stream_is_silent(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.closed = False

        def settimeout(self, _value):
            return None

        def recv(self):
            raise websocket.WebSocketTimeoutException("timeout")

        def send(self, _value):
            return None

        def close(self):
            self.closed = True

    fake_socket = FakeSocket()
    monkeypatch.setattr(patch.websocket, "create_connection", lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr(patch, "FAST_START_GRACE_SECONDS", 0.01)
    monkeypatch.setattr(patch, "FAST_SOCKET_POLL_SECONDS", 0.001)

    class Monitor:
        def __init__(self):
            import threading

            self._lock = threading.RLock()
            self._stop = threading.Event()
            self._last_fast_at = 0.0
            self.disconnected_reason = ""

        def _set_connected(self, connected, _url="", error=""):
            if not connected:
                self.disconnected_reason = error

        def _keepalive_loop(self, _ws, stop):
            stop.wait(0.2)

        def _dispatch_message(self, _message):
            raise AssertionError("no frame should be dispatched")

    monitor = Monitor()
    started = time.monotonic()
    patch._run_connection_with_fast_watchdog(
        monitor,
        "ws://router/ws?auth=x",
        "http://router",
        "sid=x",
        False,
        "router",
    )
    assert time.monotonic() - started < 0.3
    assert fake_socket.closed is True
    assert "fast stream stalled" in monitor.disconnected_reason
