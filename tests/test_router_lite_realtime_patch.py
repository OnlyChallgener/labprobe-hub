import threading
import time
from types import SimpleNamespace

from flask import Flask

from router_lite_realtime_patch import RouterLiteRealtimeService, _device_rows, install_router_lite_realtime_patch


def test_device_rows_extract_only_runtime_fields():
    hub = SimpleNamespace(norm_mac=lambda value: str(value).lower())
    rows = _device_rows(hub, {
        "items": [
            {
                "mac": "AA:BB:CC:DD:EE:FF",
                "flowUp": "1234",
                "flowDown": 5678,
                "flow_cnt": "9",
                "name": "large static field must not be returned",
            }
        ]
    })
    assert rows == [{
        "mac": "aa:bb:cc:dd:ee:ff",
        "uploadBps": 1234,
        "downloadBps": 5678,
        "connectionCount": 9,
    }]


def _fixture():
    app = Flask(__name__)
    hub = SimpleNamespace(
        app=app,
        LOGGER=SimpleNamespace(info=lambda *_args: None, warning=lambda *_args: None),
        check_app_token=lambda: True,
        ROUTER_DASHBOARD_LOCK=threading.RLock(),
        ROUTER_DASHBOARD_CACHE={
            "telemetryEpoch": time.time(),
            "telemetry": {
                "cpuPercent": 12,
                "memoryPercent": 34,
                "temperatureC": 48,
                "uptimeSeconds": 3600,
                "onlineDeviceCount": 1,
                "wan": {
                    "uploadBps": 1000,
                    "downloadBps": 2000,
                    "totalUploadBytes": 3000,
                    "totalDownloadBytes": 4000,
                },
                "connections": {"ipv4": 5, "ipv6": 6, "ipv4Half": 1, "ipv6Half": 2, "cps": 3},
            },
        },
        norm_mac=lambda value: str(value).lower(),
    )

    class Client:
        def devices(self, force=True):
            return {"items": [{"mac": "AA", "flowUp": 11, "flowDown": 22, "flow_cnt": 3}]}

    class Sync:
        client = Client()

        def configured(self):
            return True

        def sync_devices(self, force=True):
            return {"online": [{"mac": "AA", "realtimeUpload": 11, "realtimeDownload": 22, "connectionCount": 3}]}

    return hub, Sync()


def test_router_payload_is_small_and_wss_cache_backed():
    hub, sync = _fixture()
    service = RouterLiteRealtimeService(hub, sync)
    payload = service.router_payload()
    assert payload["uploadBps"] == 1000
    assert payload["downloadBps"] == 2000
    assert payload["ipv4Connections"] == 5
    assert payload["ipv6Connections"] == 6
    assert "details" not in payload


def test_routes_return_immediately_and_background_sample_devices():
    hub, sync = _fixture()
    service = install_router_lite_realtime_patch(hub, sync)
    try:
        client = hub.app.test_client()
        router = client.get("/api/router/realtime").get_json()
        assert router["uploadBps"] == 1000

        first = client.get("/api/devices/realtime").get_json()
        assert first["ok"] is True
        deadline = time.time() + 2
        latest = first
        while time.time() < deadline and not latest["devices"]:
            time.sleep(0.05)
            latest = client.get("/api/devices/realtime").get_json()
        assert latest["devices"][0]["downloadBps"] == 22

        combined = client.get("/api/realtime").get_json()
        assert combined["router"]["cpuPercent"] == 12
        assert combined["deviceRuntime"]["devices"][0]["connectionCount"] == 3
    finally:
        service.stop()
