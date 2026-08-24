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
