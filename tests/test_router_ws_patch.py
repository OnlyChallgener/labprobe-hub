import json
from pathlib import Path
from types import SimpleNamespace

import websocket
import router_ws_patch

from router_ws_patch import (
    RouterWebSocketMonitor,
    _config_poll_seconds,
    _first_ssid,
    _merge_wireless,
    _normalized_ports,
)


def test_empty_realtime_ssid_list_does_not_erase_configured_ssids():
    configured = {
        "ssidList": [
            {"ssidName": "Lot-BE72Pro", "enabled": "true"},
            {"ssidName": "@Ruijie-s8067", "enabled": "true"},
        ],
        "radioList": [{"band": "2.4G", "channel": "1"}],
    }
    realtime = {
        "ssidList": [],
        "radioList": [{"band": "2.4G", "channel": "auto", "channel_usage": "42"}],
    }

    merged = _merge_wireless(configured, realtime)

    assert [row["ssidName"] for row in merged["ssidList"]] == ["Lot-BE72Pro", "@Ruijie-s8067"]
    assert merged["radioList"][0]["channel_usage"] == "42"
    assert _first_ssid(merged) == "Lot-BE72Pro"


def test_uppercase_port_list_is_normalized_for_app():
    ports = _normalized_ports(
        {
            "count": "2",
            "List": [
                {"panel_name": "WAN", "speed": "2500", "status": "connected"},
                {"panel_name": "LAN5/GAME", "speed": "10", "status": "down"},
            ],
        }
    )

    assert ports[0]["status"] == "on"
    assert ports[0]["panel_name"] == "WAN"
    assert ports[1]["status"] == "off"
    assert ports[1]["panel_name"] == "LAN5/GAME"


def test_config_poll_interval_has_safe_floor(monkeypatch):
    monkeypatch.setenv("ROUTER_CONFIG_POLL_SEC", "3")
    assert _config_poll_seconds() == 10.0
    monkeypatch.setenv("ROUTER_CONFIG_POLL_SEC", "45")
    assert _config_poll_seconds() == 45.0


def test_ws_bad_status_relogin_is_limited_to_proven_auth_failures():
    assert RouterWebSocketMonitor._bad_status_requires_login(
        websocket.WebSocketBadStatusException("unauthorized", 401)
    ) is True
    assert RouterWebSocketMonitor._bad_status_requires_login(
        websocket.WebSocketBadStatusException(
            "redirect",
            302,
            resp_headers={"Location": "/cgi-bin/luci/"},
        )
    ) is True
    assert RouterWebSocketMonitor._bad_status_requires_login(
        websocket.WebSocketBadStatusException(
            "maintenance",
            302,
            resp_headers={"Location": "/maintenance"},
        )
    ) is False
    assert RouterWebSocketMonitor._bad_status_requires_login(
        websocket.WebSocketBadStatusException("gateway", 502)
    ) is False


def test_production_ws_receiver_remains_passive():
    # Other patch unit tests intentionally monkey-patch the class globally, so
    # inspect the production module source rather than the mutated test process.
    source = Path(router_ws_patch.__file__).read_text(encoding="utf-8")
    assert "target=self._keepalive_loop" not in source
    assert 'WS_SUBPROTOCOL = "sysinfo-stream"' in source
    assert "subprotocols=[WS_SUBPROTOCOL]" in source


def test_production_ws_requests_firmware_sysinfo_subprotocol(monkeypatch):
    connection_options = {}

    class FakeSocket:
        def settimeout(self, _value):
            return None

        def recv(self):
            return json.dumps({"type": "fast", "data": {"up": 1, "down": 2}})

        def close(self):
            return None

    def connect(*_args, **kwargs):
        connection_options.update(kwargs)
        return FakeSocket()

    monkeypatch.setattr(router_ws_patch.websocket, "create_connection", connect)
    monitor = RouterWebSocketMonitor(
        SimpleNamespace(),
        SimpleNamespace(info=lambda *_args, **_kwargs: None, debug=lambda *_args, **_kwargs: None),
    )
    monitor.set_fast_handler(lambda *_args: monitor._stop.set())

    monitor._run_connection(
        "ws://192.168.5.1/ws?auth=test",
        "http://192.168.5.1",
        "sid=test",
        False,
        "192.168.5.1",
    )

    assert connection_options["subprotocols"] == ["sysinfo-stream"]
