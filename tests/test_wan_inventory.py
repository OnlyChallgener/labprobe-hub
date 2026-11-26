from router_core.contracts import WanInfo
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
        },
        "ipinfo6": {"wan_v6": {"ip": "2409:8a50:2e04::1", "gateway6": "2409:8a50:2e04::2"}},
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
    assert wan["families"] == ["ipv4", "ipv6"]
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


def test_anonymous_reyee_config_array_binds_to_explicit_connection_slots():
    raw = {
        "network": {
            "wan": [
                {"proto": "pppoe", "mtu": "1460", "service": "CMCC"},
                {"proto": "dhcp", "mtu": "1500", "metric": "5"},
            ],
            "wanNum": "2",
        },
        "networkConnect": {
            "list": [
                {"ifname": "wan", "connnected": "true"},
                {"ifname": "wan1", "connnected": "false"},
            ]
        },
        "ipinfo": {"wan": {"ip": "10.87.133.112", "gateway": "10.87.128.1"}},
        "ipinfo6": {"wan_v6": {"ip6": "2001:db8::10/64", "gateway6": "2001:db8::1"}},
        "flowAudit": {
            "wan": {"up": 100, "down": 200, "total_up": 1000, "total_down": 2000},
            "wan1": {"up": 0, "down": 0, "total_up": 0, "total_down": 0},
        },
    }
    result = build_wan_inventory(raw)
    assert result["configuredCount"] == 2
    assert result["onlineCount"] == 1
    wan, wan1 = result["wans"]
    assert wan["configured"] and wan["online"] and wan["proto"] == "pppoe"
    assert wan["uploadBps"] == 100 and wan["downloadBps"] == 200
    assert wan["ipv6"] == "2001:db8::10"
    assert wan1["configured"] and not wan1["online"] and wan1["proto"] == "dhcp"
    assert wan1["ipv4"] == "" and wan1["gateway"] == ""
    assert wan1["uploadBps"] == 0 and wan1["totalUploadBytes"] == 0


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


def test_optional_wan_numerics_serialize_as_null_not_zero():
    row = WanInfo(wanId="wan").to_dict()
    for key in (
        "mtu", "vlanId", "uploadBps", "downloadBps", "totalUploadBytes",
        "totalDownloadBytes", "dailyUploadBytes", "dailyDownloadBytes", "trafficObservedAt",
    ):
        assert row[key] is None
    assert row["pppoePasswordConfigured"] is None
    assert row["trafficComplete"] is None


def test_dual_dhcp_joins_runtime_rows_by_exact_logical_id():
    raw = {
        "network": {
            "wan": [
                {"name": "wan", "proto": "dhcp", "ifname": "eth2.101", "netmask": "255.255.255.0", "mtu": 1500, "vlanid": 101, "macaddr": "00:11:22:33:44:55", "serviceName": "Primary"},
                {"name": "wan1", "proto": "dhcp", "ifname": "eth1.102", "netmask": "255.255.255.0", "mtu": 1492, "vlanid": 102, "macaddr": "00:11:22:33:44:66", "serviceName": "Secondary"},
            ]
        },
        "ipinfo": [
            {"ifname": "wan1", "ip": "198.51.100.2", "gateway": "198.51.100.1"},
            {"ifname": "wan", "ip": "192.0.2.2", "gateway": "192.0.2.1"},
        ],
        "networkConnect": [
            {"ifname": "wan1", "status": "online", "uptime": 20},
            {"ifname": "wan", "status": "online", "uptime": 10},
        ],
        "portStatus": {"List": [
            {"name": "WAN1", "panel_name": "LAN2/WAN1", "ipaddr": "203.0.113.99", "speed": 1000},
            {"name": "WAN", "panel_name": "WAN", "ipaddr": "203.0.113.98", "speed": 2500},
        ]},
    }
    wan, wan1 = build_wan_inventory(raw)["wans"]
    assert (wan["ipv4"], wan1["ipv4"]) == ("192.0.2.2", "198.51.100.2")
    assert (wan["uptimeSeconds"], wan1["uptimeSeconds"]) == (10, 20)
    assert (wan["ifname"], wan1["ifname"]) == ("eth2.101", "eth1.102")
    assert (wan["mtu"], wan1["mtu"]) == (1500, 1492)
    assert (wan["vlanId"], wan1["vlanId"]) == (101, 102)
    assert (wan["mac"], wan1["mac"]) == ("00:11:22:33:44:55", "00:11:22:33:44:66")
    assert (wan["remark"], wan1["remark"]) == ("Primary", "Secondary")
    assert "203.0.113.99" not in (wan["ipv4"], wan1["ipv4"])


def test_dual_pppoe_rcgame_credentials_and_verified_operator_are_wan_scoped():
    raw = {
        "network": {"wan": [
            {"name": "wan", "proto": "pppoe", "ifname": "pppoe-wan"},
            {"name": "wan1", "proto": "pppoe", "ifname": "pppoe-wan1"},
        ]},
        "ipinfo": {"wan": {"ip": "192.0.2.10"}, "wan1": {"ip": "198.51.100.10"}},
        "networkConnect": {
            "wan": {"status": "online", "operator": "Unverified", "uptime": 100},
            "wan1": {"status": "online", "operator": "Verified Carrier", "operatorVerified": True, "uptime": 200},
        },
        "rcgame": {"flows": [
            {"wanId": "wan1", "username": "user-wan1", "password": "secret-wan1"},
            {"wanId": "wan", "username": "user-wan", "passwordConfigured": True},
        ]},
    }
    wan, wan1 = build_wan_inventory(raw)["wans"]
    assert (wan["pppoeUsername"], wan1["pppoeUsername"]) == ("user-wan", "user-wan1")
    assert wan["pppoePasswordConfigured"] is True
    assert wan1["pppoePasswordConfigured"] is True
    assert wan["operator"] == ""
    assert wan1["operator"] == "Verified Carrier"
    assert "secret-wan" not in str(wan) and "secret-wan1" not in str(wan1)


def test_masked_rcgame_password_proves_configured_without_exposing_it():
    wan = build_wan_inventory({
        "network": {"wan": {"proto": "pppoe"}},
        "rcgame": {"flows": [{"wanId": "wan", "username": "masked-user", "password": "******"}]},
    })["wans"][0]
    assert wan["pppoeUsername"] == "masked-user"
    assert wan["pppoePasswordConfigured"] is True
    assert "******" not in str(wan)


def test_ambiguous_dual_network_config_does_not_guess_positions():
    result = build_wan_inventory({
        "network": {"wan": [{"proto": "pppoe", "ifname": "eth0"}, {"proto": "dhcp", "ifname": "eth1"}]},
        "ipinfo": {"wan": {"ip": "192.0.2.1"}, "wan1": {"ip": "198.51.100.1"}},
    })
    wan, wan1 = result["wans"]
    assert not wan["configured"] and not wan1["configured"]
    assert wan["proto"] == "" and wan1["proto"] == ""
    assert wan["ifname"] == "" and wan1["ifname"] == ""
    assert not wan["defaultEgress"] and not wan1["defaultEgress"]


def test_bridge_and_offline_wan1_do_not_borrow_port_addresses():
    result = build_wan_inventory({
        "network": {"wan": [
            {"name": "wan", "proto": "bridge"},
            {"name": "wan1", "proto": "dhcp"},
        ]},
        "networkConnect": {"wan1": {"status": "offline"}},
        "portStatus": {"List": [
            {"name": "WAN", "panel_name": "WAN", "ipaddr": "203.0.113.1"},
            {"name": "WAN1", "panel_name": "WAN1", "ipaddr": "203.0.113.2"},
        ]},
    })
    wan, wan1 = result["wans"]
    assert wan["ipv4"] == "" and wan["ipv6"] == "" and not wan["online"]
    assert wan1["ipv4"] == "" and not wan1["online"]
    assert wan1["uptimeSeconds"] == 0


def test_aggregate_wans_are_not_copied_to_an_individual_wan():
    wan = build_wan_inventory({
        "network": {"wan": {"proto": "dhcp"}},
        "fast": {"wan_stat": {"wans": {"up": 100, "down": 200, "total_up": 300, "total_down": 400}}},
    })["wans"][0]
    assert wan["uploadBps"] is None
    assert wan["downloadBps"] is None
    assert wan["totalUploadBytes"] is None
    assert wan["trafficSource"] == ""
    assert wan["trafficComplete"] is None


def test_canonical_traffic_sources_map_rates_and_counters_per_wan():
    row = {"wanId": "wan", "up": 100, "down": 200, "total_up": 300, "total_down": 400, "daily_up": 5, "daily_down": 6}
    sources = [
        ({"flowAudit": {"wans": [row], "observedAt": 1000}}, "flowAudit"),
        ({"fast": {"wan_stat": {"wans": {"wan": row}}, "timestamp": 1001}}, "fast_wan_stat"),
        ({"telemetry": {"wans": [row], "observedAt": 1002}}, "telemetry"),
    ]
    for raw, source in sources:
        wan = build_wan_inventory({**raw, "network": {"wan": {"proto": "dhcp"}}})["wans"][0]
        assert wan["uploadBps"] == 100 and wan["downloadBps"] == 200
        assert wan["totalUploadBytes"] == 300 and wan["totalDownloadBytes"] == 400
        assert wan["dailyUploadBytes"] == 5 and wan["dailyDownloadBytes"] == 6
        assert wan["trafficSource"] == source
        assert wan["trafficObservedAt"] in {1000, 1001, 1002}
        assert wan["trafficComplete"] is True


def test_missing_wan1_traffic_is_not_filled_from_wan_or_aggregate():
    wan, wan1 = build_wan_inventory({
        "network": {"wan": [{"name": "wan", "proto": "dhcp"}, {"name": "wan1", "proto": "dhcp"}]},
        "fast": {"wan_stat": {
            "up": 999, "down": 999, "total_up": 999, "total_down": 999,
            "wans": {"wan": {"up": 10, "down": 20}},
        }},
    })["wans"]
    assert wan["uploadBps"] == 10
    assert wan1["uploadBps"] is None and wan1["downloadBps"] is None
    assert wan1["trafficSource"] == ""


def test_driver_wan_inventory_reuses_low_frequency_snapshot_and_honors_force(monkeypatch):
    from router_core.cache.router_cache import RouterCache
    from router_core.driver.reyee import ReyeeEWebDriver

    cache = RouterCache()
    driver = ReyeeEWebDriver(cache=cache)
    calls = []

    def dashboard(force=False):
        calls.append(force)
        return {"network": {"wan": [{"proto": "dhcp"}], "wanNum": "1"}}

    monkeypatch.setattr(driver, "get_dashboard", dashboard)
    first = driver.get_wans()
    assert driver.get_wans() == first
    assert calls == [False]
    assert cache._store["wans"].ttl == 120.0
    driver.get_wans(force=True)
    assert calls == [False, True]
