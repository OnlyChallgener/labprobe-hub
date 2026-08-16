from router_realtime_stability_patch import dashboard_has_data, merge_dashboard


def test_merge_dashboard_keeps_static_fields_during_fast_update():
    previous = {
        "router": "BE72 Pro",
        "online": True,
        "details": {
            "identity": {"hostname": "BE72 Pro", "model": "BE72"},
            "wan": {"ipv4": "192.0.2.10"},
        },
        "telemetry": {"cpuPercent": 18, "memoryPercent": 46},
    }
    latest = {
        "online": True,
        "details": {"identity": {}, "wan": {}},
        "telemetry": {"cpuPercent": 24, "memoryPercent": 0},
    }

    merged = merge_dashboard(previous, latest)

    assert merged["details"]["identity"]["hostname"] == "BE72 Pro"
    assert merged["details"]["wan"]["ipv4"] == "192.0.2.10"
    assert merged["telemetry"]["cpuPercent"] == 24
    assert merged["telemetry"]["memoryPercent"] == 0
    assert dashboard_has_data(merged) is True


def test_empty_snapshot_is_not_usable():
    assert dashboard_has_data({}) is False
    assert dashboard_has_data({"router": "router", "online": False, "telemetry": {}}) is False
