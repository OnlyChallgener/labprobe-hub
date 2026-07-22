from router_ws_patch import _first_ssid, _merge_wireless, _normalized_ports


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
