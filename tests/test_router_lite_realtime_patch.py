import inspect
import threading
import time
from types import SimpleNamespace

from flask import Flask

from router_lite_realtime_patch import RouterLiteRealtimeService, install_router_lite_realtime_patch


def _fixture():
    app = Flask(__name__)
    hub = SimpleNamespace(
        app=app,
        LOGGER=SimpleNamespace(info=lambda *_args: None, warning=lambda *_args: None),
        check_app_token=lambda: True,
        check_hook_token=lambda: True,
        norm_mac=lambda value: str(value or "").strip().lower().replace("-", ":"),
    )
    return hub, RouterLiteRealtimeService(hub)


def test_router_request_marks_demand_and_returns_immediately():
    _hub, service = _fixture()
    started = time.monotonic()
    payload = service.router_payload()
    elapsed = time.monotonic() - started

    assert elapsed < 0.05
    assert payload["ok"] is True
    assert payload["stale"] is True
    assert payload["source"] == "waiting_relay_local"
    demand = service.demand_payload()
    assert demand["routerActive"] is True
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
    service.mark_device_demand()
    thread.join(timeout=0.8)

    assert not thread.is_alive()
    assert result["devicesActive"] is True
    assert result["sequence"] >= 1


def test_relay_push_updates_router_and_device_memory_samples():
    _hub, service = _fixture()
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
    router = service.router_payload()
    devices = service.devices_payload()
    assert router["uploadBps"] == 1234
    assert router["downloadBps"] == 5678
    assert router["ipv4Connections"] == 9
    assert router["source"] == "relay_local_dev_sta"
    assert router["agentVersion"] == "0.2.11"
    assert router["sampleAgeMs"] < 500
    assert router["stale"] is False
    assert devices["devices"] == [{
        "mac": "aa:bb:cc:dd:ee:ff",
        "uploadBps": 101,
        "downloadBps": 202,
        "connectionCount": 3,
    }]
    assert devices["stale"] is False


def test_router_and_device_samples_can_update_independently():
    _hub, service = _fixture()
    first_ms = int(time.time() * 1000)
    service.accept_push({
        "sampleEpochMs": first_ms,
        "routerSample": {"uploadBps": 1, "downloadBps": 2},
        "devices": [{"mac": "aa", "uploadBps": 3, "downloadBps": 4, "connectionCount": 5}],
    })
    service.accept_push({
        "sampleEpochMs": first_ms + 10,
        "routerSample": {"uploadBps": 9, "downloadBps": 8},
    })

    assert service.router_payload()["uploadBps"] == 9
    assert service.devices_payload()["devices"][0]["uploadBps"] == 3


def test_expired_samples_are_reported_stale_without_blocking():
    _hub, service = _fixture()
    old_ms = int((time.time() - 10) * 1000)
    service.accept_push({
        "sampleEpochMs": old_ms,
        "routerSample": {"uploadBps": 1},
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
