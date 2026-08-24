"""Tests for RouterCache SWR engine and RouterRealtime aggregation engine."""

import time
import pytest
from router_core.cache.router_cache import RouterCache, CacheEntry
from router_core.realtime.router_realtime import RouterRealtimeEngine, RealtimeFrame


def test_router_cache_lifecycle_and_invalidation():
    cache = RouterCache(default_ttl=10.0, max_entries=10)

    # Set and get
    cache.set("status", {"state": "connected"})
    assert cache.get("status") == {"state": "connected"}

    # Invalidation by prefix
    cache.set("firewall:1", {"name": "rule1"})
    cache.set("firewall:2", {"name": "rule2"})
    cache.set("other", {"val": 123})

    cache.invalidate("firewall")
    assert cache.get("firewall:1") is None
    assert cache.get("firewall:2") is None
    assert cache.get("other") == {"val": 123}

    # Clear all
    cache.invalidate()
    assert cache.get("other") is None


def test_router_cache_single_flight_collapsing():
    cache = RouterCache(default_ttl=5.0)
    fetch_count = 0

    def slow_fetch():
        nonlocal fetch_count
        fetch_count += 1
        time.sleep(0.05)
        return {"data": "fetched"}

    # Concurrent callers
    import threading

    results = []

    def caller():
        res = cache.get_or_fetch("heavy_key", slow_fetch, ttl=5.0)
        results.append(res)

    threads = [threading.Thread(target=caller) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All 10 callers should get identical data
    assert len(results) == 10
    for r in results:
        assert r == {"data": "fetched"}

    # Single flight collapsed the 10 requests into 1 execution
    assert fetch_count == 1


def test_router_realtime_engine_frames_and_snapshots():
    engine = RouterRealtimeEngine()

    received_frames = []

    def mock_subscriber(raw_json: str):
        received_frames.append(raw_json)

    engine.subscribe(mock_subscriber)

    # 1. Router frame
    r_frame = RealtimeFrame.router(
        state="connected",
        connected=True,
        cpu=15.4,
        memory=42.1,
        upload_speed=1024,
        download_speed=2048,
        wan_ip="1.2.3.4",
        message="OK",
    )
    assert r_frame["type"] == "router"
    engine.broadcast(r_frame)

    # Verify snapshot
    snapshot = engine.get_router_calibration_snapshot()
    assert snapshot["connected"] is True
    assert snapshot["cpu"] == 15.4
    assert snapshot["wanIp"] == "1.2.3.4"

    # 2. Devices frame
    d_frame = RealtimeFrame.devices([{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.110.100"}])
    assert d_frame["type"] == "devices"
    engine.broadcast(d_frame)

    dev_snapshot = engine.get_devices_calibration_snapshot()
    assert len(dev_snapshot) == 1
    assert dev_snapshot[0]["mac"] == "AA:BB:CC:DD:EE:FF"

    # 3. Task, Config, Agent, Keepalive frames
    t_frame = RealtimeFrame.task(kind="diagnostic", state="running", progress=50)
    assert t_frame["type"] == "task"
    engine.broadcast(t_frame)

    c_frame = RealtimeFrame.config(resource="firewall", action="update", payload={"rules": []})
    assert c_frame["type"] == "config"
    engine.broadcast(c_frame)

    a_frame = RealtimeFrame.agent(status="running", version="0.10.12", ip="127.0.0.1")
    assert a_frame["type"] == "agent"
    engine.broadcast(a_frame)

    k_frame = RealtimeFrame.keepalive()
    assert k_frame["type"] == "keepalive"
    engine.broadcast(k_frame)

    assert len(received_frames) == 6

    # Verify parameters
    assert engine.SERVER_KEEPALIVE_INTERVAL_SECONDS == 3.0
    assert engine.SERVER_CLIENT_QUEUE_SIZE == 8
    assert engine.CLIENT_WATCHDOG_PING_INTERVAL_SECONDS == 10
    assert engine.CLIENT_WATCHDOG_CHECK_INTERVAL_SECONDS == 1
    assert engine.CLIENT_SERVER_FRAME_TIMEOUT_SECONDS == 45
