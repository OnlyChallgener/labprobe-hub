import threading
from types import SimpleNamespace

from router_compat import RouterRpcCompatibilitySync
from router_core.wan_telemetry import normalize_wan_telemetry


def _dashboard(wan_value, **extra):
    sync = RouterRpcCompatibilitySync.__new__(RouterRpcCompatibilitySync)
    sync._device_total = 0
    sync.hub = SimpleNamespace(
        LOGGER=None,
        ROUTER_DASHBOARD_LOCK=threading.RLock(),
        ROUTER_DASHBOARD_CACHE={},
        now_str=lambda: "2026-11-25 00:00:00",
    )
    raw = {
        "fast": {"wan_stat": {"wans": wan_value}},
        "ipinfo": {"wan": {"ipv4": "192.0.2.2"}},
    }
    raw.update(extra)
    return sync._normalize_dashboard(raw)


def test_map_telemetry_projects_canonical_aggregate_fields():
    value = {
        "wan": {"tx_rate": 1200, "rx_rate": 3400, "total_up": 10, "total_down": 20},
        "wan1": {"tx_rate": 300, "rx_rate": 700, "total_up": 2, "total_down": 4},
    }
    normalized = normalize_wan_telemetry(value)
    assert normalized["aggregate"]["uploadBps"] == 1500
    assert normalized["aggregate"]["downloadBps"] == 4100
    dashboard = _dashboard(value)
    assert dashboard["telemetry"]["wan"] == {
        "uploadBps": 1500,
        "downloadBps": 4100,
        "totalUploadBytes": 12,
        "totalDownloadBytes": 24,
        "dailyUploadBytes": 0,
        "dailyDownloadBytes": 0,
    }


def test_list_telemetry_preserves_zero_and_connection_counts():
    value = [
        {"intf": "wan", "tx_rate": 0, "rx_rate": 0, "ipv4_connection_count": 3},
        {"intf": "wan1", "tx_rate": 0, "rx_rate": 0, "ipv4_connection_count": 2},
    ]
    dashboard = _dashboard(value)
    assert dashboard["telemetry"]["wan"]["uploadBps"] == 0
    assert dashboard["telemetry"]["wan"]["downloadBps"] == 0
    assert dashboard["telemetry"]["connections"]["ipv4"] == 5


def test_missing_metric_does_not_undercount_other_wan():
    value = {
        "wan": {"tx_rate": 100, "rx_rate": 200},
        "wan1": {"rx_rate": 300},
    }
    normalized = normalize_wan_telemetry(value)
    assert "uploadBps" not in normalized["aggregate"]
    assert normalized["aggregate"]["downloadBps"] == 500
    assert normalized["complete"] is False


def test_dashboard_publishes_top_level_and_telemetry_wans_with_exact_singular_wan():
    value = {
        "wan": {"tx_rate": 100, "rx_rate": 200, "total_up": 1, "total_down": 2, "daily_up": 3, "daily_down": 4},
        "wan1": {"tx_rate": 300, "rx_rate": 400},
    }
    dashboard = _dashboard(
        value,
        network={"wan": [
            {"name": "wan", "proto": "dhcp", "ifname": "eth2.1"},
            {"name": "wan1", "proto": "pppoe", "ifname": "eth1.2"},
        ]},
        ipinfo={"list": [
            {"ifname": "wan1", "ip": "198.51.100.1"},
            {"ifname": "wan", "ip": "192.0.2.1"},
        ]},
    )
    assert [row["wanId"] for row in dashboard["wans"]] == ["wan", "wan1"]
    assert dashboard["wans"][0]["ipv4"] == "192.0.2.1"
    assert dashboard["wans"][1]["ipv4"] == "198.51.100.1"
    assert dashboard["details"]["wan"]["ipv4"] == "192.0.2.1"
    assert dashboard["details"]["lan"]["uplink"] == "eth2.1"
    assert [row["wanId"] for row in dashboard["telemetry"]["wans"]] == ["wan", "wan1"]
    assert dashboard["telemetry"]["wans"][0]["trafficSource"] == "fast_wan_stat"
    assert dashboard["telemetry"]["wans"][1]["uploadBps"] == 300
    assert dashboard["telemetry"]["wans"][1]["totalUploadBytes"] is None
    assert dashboard["telemetry"]["wans"][1]["trafficComplete"] is False


def test_dashboard_scrubs_nested_password_keys_but_keeps_configured_flags():
    dashboard = _dashboard(
        {},
        network={"wan": {
            "proto": "pppoe",
            "username": "wan-user",
            "password": "network-secret",
            "nested": [{"pppoe_passwd": "nested-secret", "wpaPassphrase": "wifi-secret"}],
        }},
        rcgame={"flows": [{"wanId": "wan", "username": "flow-user", "password": "rcgame-secret"}]},
    )
    encoded = str(dashboard["details"]["network"]) + str(dashboard["details"]["rcgame"])
    assert "network-secret" not in encoded
    assert "nested-secret" not in encoded
    assert "wifi-secret" not in encoded
    assert "rcgame-secret" not in encoded
    assert dashboard["details"]["network"]["wan"]["username"] == "wan-user"
    assert dashboard["wans"][0]["pppoeUsername"] == "flow-user"
    assert dashboard["wans"][0]["pppoePasswordConfigured"] is True


def test_singular_wan_does_not_fall_back_to_first_wan1_runtime_row():
    dashboard = _dashboard(
        {},
        network={"wan": [{"name": "wan", "proto": "dhcp"}, {"name": "wan1", "proto": "dhcp"}]},
        ipinfo={"list": [{"ifname": "wan1", "ip": "198.51.100.1"}]},
    )
    assert dashboard["wans"][0]["ipv4"] == ""
    assert dashboard["wans"][1]["ipv4"] == "198.51.100.1"
    assert dashboard["details"]["wan"]["ipv4"] == ""
