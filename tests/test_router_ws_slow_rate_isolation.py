from router_ws_patch import normalize_fast_message, normalize_slow_message


def test_slow_frame_never_emits_wan_rates_from_history_counters():
    slow_frame = {
        "type": "slow",
        "data": {
            "wan_ip": "100.64.12.34",
            "status": "connected",
            "diskutil": 0.18,
            "runtime": 365420,
            "user_list": {"online_count": 28},
            "recent_wan": {
                "history": [
                    {"time": 1700000000, "up": 1500000000, "down": 3200000000}
                ]
            },
            "daily_wan": {
                "total_download": 45000000000,
                "total_upload": 8900000000,
            },
        },
    }
    sample = normalize_slow_message(slow_frame)
    assert "uploadBps" not in sample
    assert "downloadBps" not in sample
    assert sample.get("uptimeSeconds") == 365420
    assert sample.get("storagePercent") == 18.0


def test_fast_frame_extracts_tx_rx_rate_bps():
    fast_frame = {
        "type": "fast",
        "data": {
            "cpuutil": 14.0,
            "memutil": 0.44,
            "runtime": 365420,
            "wan_stat": {
                "rx_bytes": 1284950284,
                "tx_bytes": 482910482,
                "rx_rate_bps": 1248900,
                "tx_rate_bps": 345000,
            },
        },
    }
    sample = normalize_fast_message(fast_frame)
    assert sample.get("uploadBps") == 345000
    assert sample.get("downloadBps") == 1248900
    assert sample.get("totalUploadBytes") == 482910482
    assert sample.get("totalDownloadBytes") == 1284950284


def test_be72pro_real_fast_frame_wan_rates_are_bits_per_second():
    """2026-11-24 BE72Pro 实测 fast 帧（dev_sta get -m ws_sysinfo）。

    wan_stat.wan 只有 up/down，没有 tx_rate_bps；这两项是 bit/s，
    HUB 的 eWeb WS 通道必须原样输出，不能与 Relay 通道产生 8 倍差。
    """
    fast_frame = {
        "type": "fast",
        "data": {
            "cpuutil": 14.0,
            "memutil": 0.44,
            "runtime": 365420,
            "wan_stat": {
                "wan": {
                    "up": "24372",
                    "down": "19361",
                    "total_up": "3672912896",
                    "total_down": "13989216196",
                }
            },
        },
    }
    sample = normalize_fast_message(fast_frame)
    assert sample.get("uploadBps") == 24372
    assert sample.get("downloadBps") == 19361
    assert sample.get("totalUploadBytes") == 3672912896
    assert sample.get("totalDownloadBytes") == 13989216196
