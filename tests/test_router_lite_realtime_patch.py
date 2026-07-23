import threading
import time
from types import SimpleNamespace

from flask import Flask

from router_lite_realtime_patch import (
    RouterLiteRealtimeService,
    _device_rows,
    _router_metrics_from_fast,
)


def fast_payload(up=1000, down=2000, ipv4=5, ipv6=6):
    return {
        "type": "fast",
        "cpu_usage": 12,
        "memutil": 34,
        "temp": 48,
        "runtime": 3600,
        "wan_stat": {
            "wans": {
                "up": up,
                "down": down,
                "total_up": 3000,
                "total_down": 4000,
                "ipv4_connection_count": ipv4,
                "ipv6_connection_count": ipv6,
                "ipv4_half_connection_count": 1,
                "ipv6_half_connection_count": 2,
                "cps": 3,
            }
        },
    }


class FakeLane:
    def __init__(self, result):
        self.result = result
        self.calls = []
        self.closed = False

    def rpc(self, module, data=None):
        self.calls.append((module, data, time.monotonic()))
        value = self.result() if callable(self.result) else self.result
        return value, 0

    def close(self):
        self.closed = True


class BlockingLane(FakeLane):
    def __init__(self, result):
        super().__init__(result)
        self.entered = threading.Event()
        self.release = threading.Event()

    def rpc(self, module, data=None):
        self.calls.append((module, data, time.monotonic()))
        self.entered.set()
        assert self.release.wait(timeout=3), "blocking lane was not released"
        value = self.result() if callable(self.result) else self.result
        return value, 800


def test_device_rows_extract_only_runtime_fields():
    hub = SimpleNamespace(norm_mac=lambda value: str(value).lower())
    rows = _device_rows(hub, {
        "list": [{
            "mac": "AA:BB:CC:DD:EE:FF",
            "flowUp": "1234",
            "flowDown": 5678,
            "flow_cnt": "9",
            "name": "large static field must not be returned",
        }]
    })
    assert rows == [{
        "mac": "aa:bb:cc:dd:ee:ff",
        "uploadBps": 1234,
        "downloadBps": 5678,
        "connectionCount": 9,
    }]


def test_router_metrics_parse_native_fast_frame():
    result = _router_metrics_from_fast(fast_payload(up=111, down=222, ipv4=7, ipv6=8), 4)
    assert result["uploadBps"] == 111
    assert result["downloadBps"] == 222
    assert result["ipv4Connections"] == 7
    assert result["ipv6Connections"] == 8
    assert result["onlineDeviceCount"] == 4


def _fixture(ws_epoch=None, ws_fast=None, router_lane=None, device_lane=None):
    app = Flask(__name__)
    monitor = SimpleNamespace(
        _lock=threading.RLock(),
        _messages={"fast": ws_fast or fast_payload()},
        _message_at={"fast": ws_epoch if ws_epoch is not None else time.time()},
    )
    client = SimpleNamespace(router_ws_monitor=monitor)

    class Sync:
        def __init__(self):
            self.client = client
            self.full_sync_calls = 0

        def configured(self):
            return True

        def sync_devices(self, force=True):
            self.full_sync_calls += 1
            raise AssertionError("realtime service must never call full device sync")

    hub = SimpleNamespace(
        app=app,
        LOGGER=SimpleNamespace(info=lambda *_args: None, warning=lambda *_args: None),
        check_app_token=lambda: True,
        ROUTER_DASHBOARD_LOCK=threading.RLock(),
        ROUTER_DASHBOARD_CACHE={"telemetry": {"onlineDeviceCount": 1}},
        norm_mac=lambda value: str(value).lower(),
        DEVICES_FILE="devices.json",
        load_json=lambda _path, default: default,
    )
    sync = Sync()
    return hub, sync, monitor, router_lane or FakeLane(fast_payload()), device_lane or FakeLane({"list": []})


def wait_until(predicate, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    return predicate()


def test_router_payload_reads_ws_fast_directly_not_dashboard_cache():
    hub, sync, monitor, router_lane, device_lane = _fixture(ws_fast=fast_payload(up=4321, down=8765))
    service = RouterLiteRealtimeService(hub, sync, router_lane, device_lane)
    payload = service.router_payload()
    assert payload["uploadBps"] == 4321
    assert payload["downloadBps"] == 8765
    assert payload["source"] == "router_ws_fast"
    assert payload["sampleAgeMs"] < 500
    assert router_lane.calls == []

    with monitor._lock:
        monitor._messages["fast"] = fast_payload(up=9999, down=1111)
        monitor._message_at["fast"] = time.time()
    updated = service.router_payload()
    assert updated["uploadBps"] == 9999
    assert updated["sequence"] > payload["sequence"]


def test_stale_ws_uses_independent_fast_rpc_lane():
    router_lane = FakeLane(fast_payload(up=7000, down=8000))
    hub, sync, _monitor, _, device_lane = _fixture(
        ws_epoch=time.time() - 20,
        router_lane=router_lane,
    )
    service = RouterLiteRealtimeService(hub, sync, router_lane, device_lane)
    service.start()
    try:
        service.router_payload()

        def ready():
            value = service.router_payload()
            return value if value.get("source") == "router_rpc_fast" else None

        payload = wait_until(ready)
        assert payload
        assert payload["uploadBps"] == 7000
        assert router_lane.calls[0][0] == "ws_sysinfo"
        assert router_lane.calls[0][1] == {"get": "fast"}
    finally:
        service.stop()


def test_device_timely_lane_never_calls_or_locks_full_sync():
    device_lane = FakeLane({
        "list": [{"mac": "AA", "flowUp": 11, "flowDown": 22, "flow_cnt": 3}]
    })
    hub, sync, _monitor, router_lane, _ = _fixture(device_lane=device_lane)
    service = RouterLiteRealtimeService(hub, sync, router_lane, device_lane)
    service.start()
    try:
        service.devices_payload()

        def ready():
            value = service.devices_payload()
            return value if value.get("devices") else None

        latest = wait_until(ready)
        assert latest
        assert latest["devices"][0]["downloadBps"] == 22
        assert latest["source"] == "router_rpc_timely"
        assert device_lane.calls[0][0] == "user_list"
        assert device_lane.calls[0][1] == {"devType": "all", "dataType": "timely"}
        assert sync.full_sync_calls == 0
    finally:
        service.stop()


def test_blocked_device_lane_cannot_block_router_lane():
    router_lane = FakeLane(fast_payload(up=9090, down=8080))
    device_lane = BlockingLane({"list": []})
    hub, sync, _monitor, _, _ = _fixture(
        ws_epoch=time.time() - 20,
        router_lane=router_lane,
        device_lane=device_lane,
    )
    service = RouterLiteRealtimeService(hub, sync, router_lane, device_lane)
    service.start()
    try:
        service.devices_payload()
        assert device_lane.entered.wait(timeout=1.0)
        service.router_payload()

        def ready():
            value = service.router_payload()
            return value if value.get("source") == "router_rpc_fast" else None

        payload = wait_until(ready, timeout=1.0)
        assert payload
        assert payload["uploadBps"] == 9090
        assert sync.full_sync_calls == 0
    finally:
        device_lane.release.set()
        service.stop()


def test_payload_methods_return_memory_immediately():
    hub, sync, _monitor, router_lane, device_lane = _fixture()
    service = RouterLiteRealtimeService(hub, sync, router_lane, device_lane)
    started = time.monotonic()
    router = service.router_payload()
    devices = service.devices_payload()
    elapsed = time.monotonic() - started
    assert router["ok"] is True
    assert devices["ok"] is True
    assert elapsed < 0.2
