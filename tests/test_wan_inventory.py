from router_core.wan import build_wan_inventory


PORT_STATUS = {
    "List": [
        {"portId": "5", "name": "WAN", "panel_name": "WAN", "status": "on", "speed": "2500"},
        {"portId": "6", "name": "LAN", "panel_name": "LAN2/WAN1", "status": "on", "speed": "2500"},
    ]
}


def test_single_wan_keeps_supported_but_unconfigured_wan1():
    raw = {
        "network": {"wan": [{"proto": "pppoe", "ifname": "eth2.1", "ipv6": "1"}], "wanNum": "1"},
        "ipinfo": {
            "wan": {"ip": "36.157.252.37", "gateway": "36.157.252.1", "dnsList": "223.5.5.5"},
            "wan_v6": {"ip": "2409:8a50:2e04::1", "gateway6": "2409:8a50:2e04::2"},
        },
        "networkConnect": {"wan": {"status": "online", "default": True, "uptime": 3600}},
        "portStatus": PORT_STATUS,
        "updatedAt": 1795259700,
    }
    result = build_wan_inventory(raw)
    assert result["configuredCount"] == 1
    assert result["onlineCount"] == 1
    assert [wan["wanId"] for wan in result["wans"]] == ["wan", "wan1"]
    wan, wan1 = result["wans"]
    assert wan["configured"] and wan["online"] and wan["defaultEgress"]
    assert wan["ipv4"] == "36.157.252.37"
    assert wan["ipv6"] == "2409:8a50:2e04::1"
    assert wan["linkSpeedMbps"] == 2500
    assert wan["uptimeSeconds"] == 3600
    assert wan1["supported"] and not wan1["configured"] and not wan1["online"]
    assert wan1["capabilities"]["speedtest"] is False


def test_dual_wan_preserves_identity_addresses_and_default_route():
    raw = {
        "network": {
            "wan": [
                {"name": "wan", "proto": "pppoe", "ifname": "eth2.1", "ipv6": "1"},
                {"name": "wan1", "proto": "dhcp", "ifname": "eth1.4094", "ipv6": "1"},
            ],
            "wanNum": "2",
        },
        "ipinfo": {
            "wan": {"ip": "36.157.252.37"},
            "wan1": {"ip": "198.51.100.20"},
            "wan1_v6": {"ip": "2001:db8:1::20"},
        },
        "networkConnect": {
            "list": [
                {"ifname": "wan", "status": "online", "default": False, "mode": "weight", "role": "balance"},
                {"ifname": "wan1", "status": "online", "default": True, "mode": "weight", "role": "balance"},
            ]
        },
        "portStatus": {
            "List": [
                {"portId": "5", "name": "WAN", "panel_name": "WAN", "speed": "2500"},
                {"portId": "6", "name": "WAN1", "panel_name": "LAN2/WAN1", "speed": "1000"},
            ]
        },
    }
    result = build_wan_inventory(raw)
    assert result["configuredCount"] == 2
    assert result["onlineCount"] == 2
    assert result["multiWanMode"] == "weight"
    wan, wan1 = result["wans"]
    assert not wan["defaultEgress"]
    assert wan1["defaultEgress"]
    assert wan1["ipv4"] == "198.51.100.20"
    assert wan1["ipv6"] == "2001:db8:1::20"
    assert wan1["physicalPortId"] == 6
    assert wan1["linkSpeedMbps"] == 1000
    assert all(wan1["capabilities"].values())


def test_missing_optional_sources_do_not_fabricate_online_state():
    result = build_wan_inventory({"network": {"wan": [{"proto": "none"}]}})
    wan = result["wans"][0]
    assert wan["configured"]
    assert not wan["enabled"]
    assert not wan["online"]
    assert wan["ipv4"] == "" and wan["ipv6"] == ""
    assert wan["linkSpeedMbps"] == 0


def test_empty_dashboard_returns_empty_inventory():
    result = build_wan_inventory({})
    assert result["wans"] == []
    assert result["supported"] is False
    assert result["configuredCount"] == 0
