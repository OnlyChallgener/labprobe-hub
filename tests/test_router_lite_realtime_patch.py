import inspect
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace

from flask import Flask

from router_lite_realtime_patch import RouterLiteRealtimeService, install_router_lite_realtime_patch
from router_ws_patch import RouterWebSocketMonitor, normalize_fast_message


def _fixture():
    app = Flask(__name__)
    publisher = SimpleNamespace(
        router=[],
        devices=[],
        publish_router_realtime=lambda payload: publisher.router.append(payload),
        publish_devices_realtime=lambda payload: publisher.devices.append(payload),
    )
    hub = SimpleNamespace(
        app=app,
        LOGGER=SimpleNamespace(info=lambda *_args: None, warning=lambda *_args: None),
        realtime_publisher=publisher,
        check_app_token=lambda: True,
        check_hook_token=lambda: True,
        norm_mac=lambda value: str(value or "").strip().lower().replace("-", ":"),
    )
    service = RouterLiteRealtimeService(hub)
    service.set_app_realtime_publisher(publisher)
    return hub, service


def _activate_both(service):
    service.set_wss_demand("app-test", True)


def test_router_http_reads_memory_without_starting_realtime_demand():
    _hub, service = _fixture()
    started = time.monotonic()
    payload = service.router_payload()
    elapsed = time.monotonic() - started

    assert elapsed < 0.05
    assert payload["ok"] is True
    assert payload["stale"] is True
    assert payload["source"] == "waiting_router_eweb_ws_fast"
    demand = service.demand_payload()
    assert demand["routerActive"] is False
    assert demand["devicesActive"] is False


def test_device_request_wakes_idle_agent_long_poll():
    _hub, service = _fixture()
    entered = threading.Event()
    result = {}

    def wait_for_demand():
        entered.set()
        result.update(service.demand_payload(since=0, wait_seconds=2))

    thread = threading.Thread(target=wait_for_demand)
    thread.start()
    assert entered.wait(timeout=0.5)
    time.sleep(0.05)
    service.set_wss_demand("app-test", True)
    thread.join(timeout=0.8)

    assert not thread.is_alive()
    assert result["devicesActive"] is True
    assert result["sequence"] >= 1


def test_app_demand_lease_expires_and_relay_push_is_not_cached():
    _hub, service = _fixture()
    _activate_both(service)
    first_ms = int(time.time() * 1000)
    accepted = service.accept_push({
        "sampleEpochMs": first_ms,
        "routerSample": {"uploadBps": 1},
        "devices": [{"mac": "aa", "uploadBps": 2, "downloadBps": 3, "connectionCount": 4}],
    })
    assert accepted["acceptedRouter"] is False
    assert accepted["acceptedDevices"] is True

    service.set_wss_demand("app-test", False)

    expired = service.accept_push({
        "sampleEpochMs": first_ms + 1000,
        "routerSample": {"uploadBps": 999},
        "devices": [{"mac": "aa", "uploadBps": 888, "downloadBps": 777, "connectionCount": 6}],
    })
    assert expired["routerActive"] is False
    assert expired["devicesActive"] is False
    assert expired["acceptedRouter"] is False
    assert expired["acceptedDevices"] is False

    # Inspect memory directly so the assertion itself does not renew APP demand.
    with service._lock:
        assert service._router_sample == {}
        assert service._router_epoch_ms == 0
        assert service._devices[0]["uploadBps"] == 2
        assert service._devices_epoch_ms == first_ms


def test_ws_fast_updates_router_memory_sample_and_pushes_native_wss():
    hub, service = _fixture()
    now_ms = int(time.time() * 1000)
    service.accept_router_fast({
        "uploadBps": "1234",
        "downloadBps": 5678,
        "ipv4Connections": "9",
        "ipv6Connections": 10,
        "cpuPercent": "11.5",
    }, now_ms)

    router = service.router_payload()
    assert router["uploadBps"] == 1234
    assert router["downloadBps"] == 5678
    assert router["ipv4Connections"] == 9
    assert router["source"] == "router_eweb_ws_fast"
    assert router["sampleAgeMs"] < 500
    assert router["stale"] is False
    assert hub.realtime_publisher.router[-1]["uploadBps"] == 1234


def test_relay_push_updates_only_device_memory_samples():
    hub, service = _fixture()
    _activate_both(service)
    now_ms = int(time.time() * 1000)
    response = service.accept_push({
        "source": "relay_local_dev_sta",
        "agentVersion": "0.2.11",
        "sampleEpochMs": now_ms,
        "routerSample": {
            "uploadBps": "1234",
            "downloadBps": 5678,
            "ipv4Connections": "9",
            "ipv6Connections": 10,
            "cpuPercent": "11.5",
        },
        "devices": [{
            "mac": "AA-BB-CC-DD-EE-FF",
            "uploadBps": "101",
            "downloadBps": 202,
            "connectionCount": "3",
            "name": "must not be stored",
        }],
    })

    assert response["ok"] is True
    assert response["acceptedRouter"] is False
    assert response["acceptedDevices"] is True
    router = service.router_payload()
    devices = service.devices_payload()
    assert "uploadBps" not in router
    assert router["source"] == "waiting_router_eweb_ws_fast"
    assert devices["devices"] == [{
        "mac": "aa:bb:cc:dd:ee:ff",
        "uploadBps": 101,
        "downloadBps": 202,
        "connectionCount": 3,
    }]
    assert devices["stale"] is False
    assert hub.realtime_publisher.router == []
    assert hub.realtime_publisher.devices[-1]["devices"][0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert hub.realtime_publisher.devices[-1]["delta"] is True


def test_router_and_device_samples_can_update_independently():
    _hub, service = _fixture()
    _activate_both(service)
    first_ms = int(time.time() * 1000)
    service.accept_router_fast({
        "uploadBps": 1,
        "downloadBps": 2,
    }, first_ms)
    service.accept_push({
        "sampleEpochMs": first_ms,
        "devices": [{"mac": "aa", "uploadBps": 3, "downloadBps": 4, "connectionCount": 5}],
    })
    service.accept_router_fast({
        "uploadBps": 9,
        "downloadBps": 8,
    }, first_ms + 10)

    assert service.router_payload()["uploadBps"] == 9
    assert service.devices_payload()["devices"][0]["uploadBps"] == 3


def test_device_wss_payload_contains_only_changed_rows():
    hub, service = _fixture()
    _activate_both(service)
    first_ms = int(time.time() * 1000)
    service.accept_push({
        "sampleEpochMs": first_ms,
        "devices": [
            {"mac": "aa", "uploadBps": 1, "downloadBps": 2, "connectionCount": 3},
            {"mac": "bb", "uploadBps": 4, "downloadBps": 5, "connectionCount": 6},
        ],
    })
    service.accept_push({
        "sampleEpochMs": first_ms + 2000,
        "devices": [
            {"mac": "aa", "uploadBps": 1, "downloadBps": 2, "connectionCount": 3},
            {"mac": "bb", "uploadBps": 40, "downloadBps": 5, "connectionCount": 6},
        ],
    })

    event = hub.realtime_publisher.devices[-1]
    assert event["sampleEpochMs"] == first_ms + 2000
    assert event["devices"] == [{
        "mac": "bb",
        "uploadBps": 40,
        "downloadBps": 5,
        "connectionCount": 6,
    }]


def test_expired_samples_are_reported_stale_without_blocking():
    _hub, service = _fixture()
    _activate_both(service)
    old_ms = int((time.time() - 10) * 1000)
    service.accept_router_fast({
        "uploadBps": 1,
    }, old_ms)
    service.accept_push({
        "sampleEpochMs": old_ms,
        "devices": [],
    })

    assert service.router_payload()["stale"] is True
    assert service.devices_payload()["stale"] is True


def test_install_registers_app_and_agent_routes():
    hub, _service = _fixture()
    installed = install_router_lite_realtime_patch(hub, SimpleNamespace())
    rules = {rule.rule for rule in hub.app.url_map.iter_rules()}

    assert "/api/router/realtime" in rules
    assert "/api/devices/realtime" in rules
    assert "/api/router/realtime/agent/demand" in rules
    assert "/api/router/realtime/agent/push" in rules
    installed.stop()


def test_service_contains_no_high_frequency_eweb_or_full_sync_path():
    source = inspect.getsource(__import__("router_lite_realtime_patch"))
    assert "requests.Session" not in source
    assert "ws_sysinfo" not in source
    assert "user_list" not in source
    assert "sync_devices" not in source
    assert "_rpc_lock" not in source
    assert "relay_local_dev_sta" in source
    assert "router_eweb_ws_fast" in source
    assert "MQTT_PUBLISHER" not in source
    assert 'demand["acceptedRouter"]' in source
    assert 'demand["acceptedDevices"]' in source


def test_ws_fast_normalizer_extracts_realtime_numbers_without_history():
    sample = normalize_fast_message({
        "type": "fast",
        "data": {
            "cpu_usage": 12,
            "memutil": "34.5%",
            "temp": 48,
            "runtime": 3600,
            "wan_stat": {"wans": {
                "up": "111",
                "down": 222,
                "total_up": 333,
                "total_down": 444,
                "ipv4_connection_count": 7,
                "ipv6_connection_count": 8,
                "ipv4_half_connection_count": 1,
                "ipv6_half_connection_count": 2,
                "cps": 3,
            }},
        },
    })

    assert sample["uploadBps"] == 111
    assert sample["downloadBps"] == 222
    assert sample["ipv4Connections"] == 7
    assert sample["ipv6Connections"] == 8
    assert sample["cpuPercent"] == 12.0
    assert sample["memoryPercent"] == 34.5
    assert sample["temperatureC"] == 48.0
    assert sample["uptimeSeconds"] == 3600


def test_ws_fast_dispatch_does_not_touch_http_dashboard_or_device_sync():
    calls = []

    class ForbiddenClient:
        def login(self, *_args, **_kwargs):
            raise AssertionError("login must not be called from fast dispatch")

        def dashboard(self, *_args, **_kwargs):
            raise AssertionError("dashboard must not be called from fast dispatch")

        def devices(self, *_args, **_kwargs):
            raise AssertionError("devices must not be called from fast dispatch")

    logger = SimpleNamespace(
        info=lambda *_args: None,
        warning=lambda *_args: None,
        debug=lambda *_args, **_kwargs: None,
    )
    monitor = RouterWebSocketMonitor(ForbiddenClient(), logger)
    monitor.set_fast_handler(lambda sample, epoch_ms: calls.append((sample, epoch_ms)))
    monitor._dispatch_message({
        "type": "fast",
        "data": {"wan_stat": {"wans": {"up": 5, "down": 6}}, "cpu_usage": 7},
    })

    assert len(calls) == 1
    assert calls[0][0]["uploadBps"] == 5
    assert calls[0][0]["downloadBps"] == 6
    assert calls[0][0]["cpuPercent"] == 7.0


def test_relay_runtime_uses_only_independent_two_second_device_lane():
    runtime = (Path(__file__).parents[1] / "labrelay" / "src" / "runtime.rs").read_text(encoding="utf-8")
    assert "DEVICES_SAMPLE_INTERVAL: Duration = Duration::from_secs(2)" in runtime
    assert "async fn devices_lane(" in runtime
    assert "MissedTickBehavior::Skip" in runtime
    assert "COMMAND_TIMEOUT: Duration = Duration::from_millis(1_400)" in runtime
    assert "tokio::join!(\n        demand_lane" in runtime
    assert "ROUTER_SAMPLE_INTERVAL" not in runtime
    assert "async fn router_lane(" not in runtime
    assert "ws_sysinfo" not in runtime
    assert "routerSample" not in runtime
    assert "let (mut router_sample, device_sample) = tokio::join!" not in runtime


def test_http_realtime_routes_bypass_global_data_and_router_rpc_locks():
    hub_source = (Path(__file__).parents[1] / "hub.py").read_text(encoding="utf-8")
    assert 'request.path.startswith("/api/router/realtime")' in hub_source
    assert 'request.path.startswith("/api/devices/realtime")' in hub_source
    assert 'or request.path == "/api/realtime"' in hub_source
    assert 'request.path.startswith("/api/realtime/ws")' in hub_source


def test_hub_native_wss_fans_out_only_compact_realtime_events():
    import pytest

    pytest.importorskip("flask_sock")
    from hub_realtime_ws import install_hub_realtime_ws

    hub, service = _fixture()
    websocket = install_hub_realtime_ws(hub, service)
    rules = {rule.rule for rule in hub.app.url_map.iter_rules()}
    assert "/api/realtime/ws" in rules

    client = websocket._register()
    try:
        websocket.publish_router_realtime({"sequence": 1, "uploadBps": 2})
        frame = json.loads(client.frames.get(timeout=0.2))
        assert frame == {"type": "router", "data": {"sequence": 1, "uploadBps": 2}}
        assert "devices" not in frame["data"]
    finally:
        websocket._unregister(client)
        service.stop()


def test_hub_native_wss_route_streams_fast_sample_to_authenticated_client():
    import pytest

    pytest.importorskip("flask_sock")
    websocket_client = pytest.importorskip("websocket")
    from werkzeug.serving import make_server
    from hub_realtime_ws import install_hub_realtime_ws

    hub, service = _fixture()
    install_hub_realtime_ws(hub, service)
    server = make_server("127.0.0.1", 0, hub.app, threaded=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    client = None
    try:
        client = websocket_client.create_connection(
            f"ws://127.0.0.1:{server.server_port}/api/realtime/ws",
            timeout=2,
            http_proxy_host=None,
            http_proxy_port=None,
        )
        assert json.loads(client.recv())["type"] == "ready"
        service.accept_router_fast({"uploadBps": 123, "downloadBps": 456}, int(time.time() * 1000))
        frame = json.loads(client.recv())
        assert frame["type"] == "router"
        assert frame["data"]["uploadBps"] == 123
        assert frame["data"]["downloadBps"] == 456
    finally:
        if client is not None:
            client.close()
        server.shutdown()
        worker.join(timeout=2)
        service.stop()
