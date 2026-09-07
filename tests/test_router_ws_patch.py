from router_ws_patch import _config_poll_seconds, _first_ssid, _merge_wireless, _normalized_ports


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


def test_normalize_fast_message_does_not_extract_port_rates_as_wan_speed():
    from router_ws_patch import normalize_fast_message

    sample = normalize_fast_message({
        "type": "fast",
        "data": {
            "ports": [
                {"panel_name": "WAN", "txSpeed": 950000000, "rxSpeed": 475000000, "txBytes": 12345},
            ],
            "cpu_usage": 15,
        }
    })
    assert "uploadBps" not in sample
    assert "downloadBps" not in sample
    assert "totalUploadBytes" not in sample
    assert sample["cpuPercent"] == 15.0

