from types import SimpleNamespace
from unittest.mock import Mock

from router_ws_patch import RouterWebSocketMonitor, _config_poll_seconds, _first_ssid, _merge_wireless, _normalized_ports


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


def test_be50_monitor_never_starts_threads_or_attempts_login(monkeypatch):
    monkeypatch.setenv("PRIMARY_ROUTER_NAME", "BE50")
    monkeypatch.delenv("ROUTER_FIRMWARE_FAMILY", raising=False)
    client = SimpleNamespace(config={}, login=Mock())
    monitor = RouterWebSocketMonitor(client, Mock())

    monitor.start()
    monitor._loop()

    assert monitor._thread is None
    assert monitor._low_thread is None
    client.login.assert_not_called()


def test_be5100_config_alias_disables_monitor_without_env_identity(monkeypatch):
    monkeypatch.delenv("PRIMARY_ROUTER_NAME", raising=False)
    monkeypatch.delenv("ROUTER_FIRMWARE_FAMILY", raising=False)
    monitor = RouterWebSocketMonitor(SimpleNamespace(config={"name": "BE5100"}), Mock())

    monitor.start()

    assert monitor._thread is None


def test_be72_monitor_still_authenticates_and_connects(monkeypatch):
    monkeypatch.setenv("PRIMARY_ROUTER_NAME", "BE72")
    monkeypatch.delenv("ROUTER_FIRMWARE_FAMILY", raising=False)
    monitor = RouterWebSocketMonitor(SimpleNamespace(config={}), Mock())
    authenticate = Mock(return_value=True)
    connect = Mock(side_effect=lambda *args: monitor.stop())
    monkeypatch.setattr(monitor, "_ensure_authenticated", authenticate)
    monkeypatch.setattr(monitor, "_connection_info", lambda: ("ws://router/ws", "http://router", "", False, "router"))
    monkeypatch.setattr(monitor, "_run_connection", connect)

    monitor._loop()

    authenticate.assert_called_once_with(force=False)
    connect.assert_called_once()
