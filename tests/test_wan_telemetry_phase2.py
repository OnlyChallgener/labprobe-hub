import threading
from types import SimpleNamespace

from router_compat import RouterRpcCompatibilitySync
from router_core.wan_telemetry import normalize_wan_telemetry


def _dashboard(wan_value):
    sync = RouterRpcCompatibilitySync.__new__(RouterRpcCompatibilitySync)
    sync._device_total = 0
    sync.hub = SimpleNamespace(
        LOGGER=None,
        ROUTER_DASHBOARD_LOCK=threading.RLock(),
        ROUTER_DASHBOARD_CACHE={},
        now_str=lambda: "2026-11-25 00:00:00",
    )
    return sync._normalize_dashboard({
        "fast": {"wan_stat": {"wans": wan_value}},
        "ipinfo": {"wan": {"ipv4": "192.0.2.2"}},
    })


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
