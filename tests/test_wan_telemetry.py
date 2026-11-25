from router_core.wan_telemetry import normalize_wan_telemetry


def test_aggregate_shape_keeps_zero_values():
    result = normalize_wan_telemetry({"up": 0, "down": 0, "total_up": 0})
    assert result["shape"] == "aggregate"
    assert result["complete"] is True
    assert result["aggregate"]["uploadBps"] == 0
    assert result["aggregate"]["downloadBps"] == 0
    assert result["aggregate"]["totalUploadBytes"] == 0


def test_wan_keyed_map_sums_each_interface_without_losing_identity():
    result = normalize_wan_telemetry({
        "wan": {"up": 100, "down": 200, "total_up": 10},
        "wan1": {"up": 300, "down": 400, "total_up": 20},
    })
    assert result["shape"] == "map"
    assert [row["wanId"] for row in result["wans"]] == ["wan", "wan1"]
    assert result["aggregate"]["uploadBps"] == 400
    assert result["aggregate"]["downloadBps"] == 600
    assert result["aggregate"]["totalUploadBytes"] == 30


def test_list_shape_preserves_firmware_order_and_aliases():
    result = normalize_wan_telemetry([
        {"intf": "wan1", "tx_rate": 30, "rx_rate": 40},
        {"intf": "wan", "uploadBps": 10, "downloadBps": 20},
    ])
    assert [row["wanId"] for row in result["wans"]] == ["wan1", "wan"]
    assert result["aggregate"]["uploadBps"] == 40
    assert result["aggregate"]["downloadBps"] == 60


def test_missing_line_value_does_not_undercount_aggregate():
    result = normalize_wan_telemetry({
        "wan": {"up": 100, "down": 200},
        "wan1": {"down": 300},
    })
    assert result["complete"] is False
    assert "uploadBps" not in result["aggregate"]
    assert result["aggregate"]["downloadBps"] == 500


def test_mixed_units_are_not_aggregated_as_realtime_rates():
    result = normalize_wan_telemetry({
        "wan": {"up": 100, "down": 200, "unit": "bit/s"},
        "wan1": {"up": 30, "down": 40, "unit": "B/s"},
    })
    assert result["unitMismatch"] is True
    assert "uploadBps" not in result["aggregate"]
    assert "downloadBps" not in result["aggregate"]


def test_empty_or_unknown_shape_is_not_fabricated():
    assert normalize_wan_telemetry({})["aggregate"] == {}
    assert normalize_wan_telemetry({"wan": {}})["complete"] is False
