"""Unit Tests for router_core/cache and router_core/realtime.

Validates:
1. RouterCache SWR lifecycle and Single-Flight collapsing.
2. RouterRealtimeEngine frame formatting for all 8 standard types.
3. Exact Watchdog parameters (10s ping, 1s check, 45s frame timeout).
4. HTTP calibration snapshots.
"""

import json
import threading
import time
import pytest

from router_core.cache.router_cache import RouterCache
from router_core.realtime.router_realtime import RealtimeFrame, RouterRealtimeEngine


def test_router_cache_swr_and_single_flight():
    cache = RouterCache(default_ttl=0.1)

    # 1. Basic set and get
    cache.set("k1", "v1", ttl=0.05)
    assert cache.get("k1") == "v1"
    assert cache.peek("k1") == "v1"

    # Wait for expiration
    time.sleep(0.06)
    assert cache.get("k1") is None
    # Stale peek still returns v1
    assert cache.peek("k1") == "v1"

    # 2. Invalidate prefix
    cache.set("p_1", "a")
    cache.set("p_2", "b")
    cache.set("other", "c")
    cache.invalidate("p_")
    assert cache.get("p_1") is None
    assert cache.get("p_2") is None
    assert cache.get("other") == "c"

    # 3. Single-Flight collapsing
    fetch_count = 0

    def slow_fetcher():
        nonlocal fetch_count
        fetch_count += 1
        time.sleep(0.05)
        return "expensive_result"

    results = []
    threads = []
    barrier = threading.Barrier(20)

    def worker():
        barrier.wait()
        val = cache.get_or_fetch("heavy_key", slow_fetcher, ttl=1.0)
        results.append(val)

    for _ in range(20):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(results) == 20
    assert all(r == "expensive_result" for r in results)
    # Exactly ONE fetch executed!
    assert fetch_count == 1


def test_realtime_frame_specifications():
    # 1. ready frame
    f_ready = RealtimeFrame.ready("cid_123", 1700000000000)
    assert f_ready["type"] == "ready"
    assert f_ready["data"]["clientId"] == "cid_123"

    # 2. router frame
    f_router = RealtimeFrame.router(
        state="connected",
        connected=True,
        cpu=12.55,
        memory=40.2,
        upload_speed=1024,
        download_speed=2048,
        wan_ip="1.2.3.4",
        message="OK",
    )
    assert f_router["type"] == "router"
    assert f_router["data"]["cpu"] == 12.6
    assert f_router["data"]["downloadSpeed"] == 2048

    # 3. devices & devices_snapshot frame
    dev_list = [{"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.110.100"}]
    f_devs = RealtimeFrame.devices(dev_list)
    assert f_devs["type"] == "devices"
    assert f_devs["data"]["count"] == 1

    f_snap = RealtimeFrame.devices_snapshot(dev_list)
    assert f_snap["type"] == "devices_snapshot"

    # 4. task frame
    f_task = RealtimeFrame.task(kind="nat_diagnostic", state="running", progress=50)
    assert f_task["type"] == "task"
    assert f_task["data"]["progress"] == 50

    # 5. config frame
    f_cfg = RealtimeFrame.config(resource="portMappings", action="add", payload={"rule": "web"})
    assert f_cfg["type"] == "config"
    assert f_cfg["data"]["resource"] == "portMappings"

    # 6. agent frame
    f_agent = RealtimeFrame.agent(status="online", version="0.2.28", ip="192.168.110.1")
    assert f_agent["type"] == "agent"
    assert f_agent["data"]["status"] == "online"

    # 7. keepalive frame
    f_ka = RealtimeFrame.keepalive()
    assert f_ka["type"] == "keepalive"
    assert "timestamp" in f_ka["data"]


def test_realtime_engine_watchdog_and_broadcasting():
    engine = RouterRealtimeEngine()

    assert engine.WATCHDOG_PING_INTERVAL_SECONDS == 10
    assert engine.WATCHDOG_CHECK_INTERVAL_SECONDS == 1
    assert engine.SERVER_FRAME_TIMEOUT_SECONDS == 45

    received_frames = []

    def on_frame(raw_json: str):
        received_frames.append(json.loads(raw_json))

    engine.subscribe(on_frame)

    # Broadcast router frame
    r_frame = RealtimeFrame.router(state="connected", connected=True, cpu=5.0)
    engine.broadcast(r_frame)

    assert len(received_frames) == 1
    assert received_frames[0]["type"] == "router"

    # Calibration snapshot matches latest broadcast
    calib = engine.get_router_calibration_snapshot()
    assert calib["connected"] is True
    assert calib["cpu"] == 5.0

    # Unsubscribe
    engine.unsubscribe(on_frame)
    engine.broadcast(RealtimeFrame.keepalive())
    assert len(received_frames) == 1
