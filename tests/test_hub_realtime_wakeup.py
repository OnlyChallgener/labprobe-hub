from types import SimpleNamespace

from flask import Flask

from hub_realtime_ws import HubRealtimeWebSocketService, PROTOCOL_NAME
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
    service = RouterLiteRealtimeService(hub)
    websocket = HubRealtimeWebSocketService(hub, service)
    return service, websocket


def test_new_app_socket_wakes_agent_even_when_old_lease_is_still_active():
    service, websocket = _fixture()
    service.set_wss_demand("old-app", True)
    before = service.demand_payload()["sequence"]

    client = websocket._register()
    try:
        demand = service.demand_payload()
        assert demand["devicesActive"] is True
        assert demand["sequence"] == before + 1
        assert demand["demandClientCount"] == 2
    finally:
        websocket._unregister(client)
        service.set_wss_demand("old-app", False)
        service.stop()


def test_protocol_marks_immediate_terminal_sampler_wakeup_generation():
    assert PROTOCOL_NAME == "labprobe-realtime-v3"
