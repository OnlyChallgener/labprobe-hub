import json
import time
from types import SimpleNamespace

from flask import Flask

from hub_realtime_ws import HubRealtimeWebSocketService, PROTOCOL_NAME
from router_core.realtime.router_realtime import RouterRealtimeEngine
from router_lite_realtime_patch import RouterLiteRealtimeService


def _fixture():
    hub = SimpleNamespace(
        app=Flask(__name__),
        LOGGER=SimpleNamespace(
            info=lambda *_args, **_kwargs: None,
            warning=lambda *_args, **_kwargs: None,
            debug=lambda *_args, **_kwargs: None,
        ),
        check_app_token=lambda: True,
        norm_mac=lambda value: str(value or "").strip().lower().replace("-", ":"),
    )
    engine = RouterRealtimeEngine()
    service = RouterLiteRealtimeService(hub, router_realtime=engine)
    websocket = HubRealtimeWebSocketService(hub, engine, service)
    return engine, service, websocket


def test_new_app_socket_wakes_agent_even_when_old_lease_is_still_active():
    _engine, service, websocket = _fixture()
    service.set_wss_demand("old-app", True)
    before = service.demand_payload()["sequence"]

    client = websocket._register()
    try:
        demand = service.demand_payload()
        assert demand["devicesActive"] is False
        assert demand["sequence"] == before + 1
        assert demand["demandClientCount"] == 2
    finally:
        websocket._unregister(client)
        service.set_wss_demand("old-app", False)
        service.stop()


def test_protocol_generation_is_unchanged_for_existing_app():
    assert PROTOCOL_NAME == "labprobe-realtime-v3"


def test_router_core_frame_is_fanned_out_to_registered_app_socket():
    engine, service, websocket = _fixture()
    client = websocket._register()
    try:
        epoch_ms = int(time.time() * 1000)
        engine.accept_router_fast(
            {"uploadBps": 101, "downloadBps": 202, "cpuPercent": 9.5},
            epoch_ms,
        )
        frame = json.loads(client.frames.get_nowait())
        assert frame["type"] == "router"
        assert frame["data"]["uploadBps"] == 101
        assert frame["data"]["downloadBps"] == 202
        assert frame["data"]["sampleEpochMs"] == epoch_ms
    finally:
        websocket._unregister(client)
        service.stop()


def test_device_wire_frames_drop_repeated_history_but_keep_app_fields():
    runtime = {
        "type": "devices",
        "data": {
            "sampleEpochMs": 123,
            "sampleAgeMs": 1,
            "onlineDeviceCount": 1,
            "delta": False,
            "devices": [{
                "mac": "aa:bb:cc:dd:ee:ff",
                "uploadBps": 10,
                "downloadBps": 20,
                "connectionCount": 3,
                "ipv6Records": [{"address": "2001:db8::1"}] * 100,
            }],
        },
    }
    raw = json.dumps(runtime, separators=(",", ":"))
    compact = json.loads(HubRealtimeWebSocketService._wire_frame(raw))
    assert compact["data"]["devices"] == [{
        "mac": "aa:bb:cc:dd:ee:ff",
        "uploadBps": 10,
        "downloadBps": 20,
        "connectionCount": 3,
    }]
    assert len(json.dumps(compact)) < len(raw) // 4

    snapshot = {
        "type": "devices_snapshot",
        "data": {
            "fullSnapshot": True,
            "accepted": True,
            "sampleEpochMs": 123,
            "devices": [{
                "mac": "aa:bb:cc:dd:ee:ff",
                "name": "phone",
                "ipv6List": ["2001:db8::1"],
                "ipv6Records": [{"address": "2001:db8::1"}] * 100,
                "raw": {"vendorMetadata": "x" * 1000},
            }],
        },
    }
    compact = json.loads(HubRealtimeWebSocketService._wire_frame(json.dumps(snapshot, separators=(",", ":"))))
    assert compact["data"]["devices"] == [{
        "mac": "aa:bb:cc:dd:ee:ff",
        "name": "phone",
        "ipv6List": ["2001:db8::1"],
    }]
    assert "ipv6Records" in snapshot["data"]["devices"][0]


def test_repeated_device_snapshots_send_small_runtime_frames_between_full_updates():
    _engine, service, websocket = _fixture()
    client = websocket._register()
    try:
        def frame(epoch):
            return json.dumps({
                "type": "devices_snapshot",
                "data": {
                    "accepted": True,
                    "fullSnapshot": True,
                    "sampleEpochMs": epoch,
                    "onlineDeviceCount": 1,
                    "devices": [{
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "name": "phone",
                        "uploadBps": epoch,
                        "ipv6Records": [{"address": "2001:db8::1"}] * 100,
                    }],
                },
            }, separators=(",", ":"))

        websocket._fan_out(frame(100))
        first = [json.loads(client.frames.get_nowait()) for _ in range(2)]
        assert [item["type"] for item in first] == ["devices", "devices_snapshot"]
        websocket._fan_out(frame(200))
        second = json.loads(client.frames.get_nowait())
        assert second["type"] == "devices"
        assert second["data"]["sampleEpochMs"] == 200
        assert second["data"]["devices"][0]["uploadBps"] == 200
        assert client.frames.empty()
    finally:
        websocket._unregister(client)
        service.stop()
