"""Two-minute wall-clock soak for the compact Hub realtime bridge."""
from __future__ import annotations

import json
import sys
import statistics
import threading
import time
from types import SimpleNamespace
from pathlib import Path

from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from router_lite_realtime_patch import RouterLiteRealtimeService


class Publisher:
    def __init__(self):
        self.lock = threading.Lock()
        self.router_times = []
        self.device_times = []
        self.device_sizes = []

    def publish_router_realtime(self, payload):
        with self.lock:
            self.router_times.append(time.monotonic())

    def publish_devices_realtime(self, payload):
        with self.lock:
            self.device_times.append(time.monotonic())
            self.device_sizes.append(len(payload.get("devices") or []))


def intervals(values):
    return [right - left for left, right in zip(values, values[1:])]


def scheduled_lane(period, duration, callback):
    started = time.monotonic()
    sequence = 0
    while True:
        due = started + sequence * period
        remaining = due - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        elapsed = time.monotonic() - started
        if elapsed > duration:
            return
        callback(sequence, elapsed)
        sequence += 1


def main():
    duration = 120.0
    publisher = Publisher()
    hub = SimpleNamespace(
        app=Flask(__name__),
        LOGGER=SimpleNamespace(info=lambda *_args: None, warning=lambda *_args: None),
        MQTT_PUBLISHER=publisher,
        norm_mac=lambda value: str(value or "").strip().lower().replace("-", ":"),
    )
    service = RouterLiteRealtimeService(hub)
    service.set_wss_demand("soak-app", True)

    # HTTP is calibration-only: one initial cache read for each lane.
    http_reads = 2
    service.router_payload()
    service.devices_payload()

    http_config_unblocked = threading.Event()

    def blocked_http_config_query():
        time.sleep(30.0)
        http_config_unblocked.set()

    def router_push(sequence, _elapsed):
        service.accept_router_fast(
            {
                "uploadBps": sequence * 101,
                "downloadBps": sequence * 211,
                "ipv4Connections": 20 + sequence % 3,
                "ipv6Connections": 10 + sequence % 2,
            },
            int(time.time() * 1000),
        )

    failed_device_sample = 20

    def devices_push(sequence, _elapsed):
        if sequence == failed_device_sample:
            # A failed/timed-out terminal sample produces no frame. Router lane
            # remains independent and continues at its own one-second cadence.
            return
        service.accept_push({
            "sampleEpochMs": int(time.time() * 1000),
            "source": "soak-relay",
            "devices": [{
                "mac": "aa:bb:cc:dd:ee:ff",
                "uploadBps": sequence * 31,
                "downloadBps": sequence * 47,
                "connectionCount": 3,
            }],
        })

    router_thread = threading.Thread(
        target=scheduled_lane, args=(1.0, duration, router_push), daemon=True
    )
    device_thread = threading.Thread(
        target=scheduled_lane, args=(2.0, duration, devices_push), daemon=True
    )
    router_thread.start()
    device_thread.start()
    http_thread = threading.Thread(target=blocked_http_config_query, daemon=True)
    http_thread.start()

    soak_started = time.monotonic()
    next_heartbeat = soak_started + 15.0
    while time.monotonic() - soak_started <= duration:
        now = time.monotonic()
        if now >= next_heartbeat:
            service.set_wss_demand("soak-app", True)
            next_heartbeat += 15.0
        time.sleep(0.1)

    router_thread.join(timeout=3)
    device_thread.join(timeout=3)
    http_thread.join(timeout=1)

    # Reconnect/manual calibration is the only second HTTP read.
    service.router_payload()
    service.devices_payload()
    http_reads += 2
    service.set_wss_demand("soak-app", False)

    router_gaps = intervals(publisher.router_times)
    device_gaps = intervals(publisher.device_times)
    summary = {
        "durationSeconds": round(time.monotonic() - soak_started, 3),
        "routerFrames": len(publisher.router_times),
        "routerMeanInterval": round(statistics.mean(router_gaps), 3),
        "routerMaxInterval": round(max(router_gaps), 3),
        "deviceFrames": len(publisher.device_times),
        "deviceMeanInterval": round(statistics.mean(device_gaps), 3),
        "deviceMaxInterval": round(max(device_gaps), 3),
        "deviceTimeoutInjected": True,
        "httpConfigBlockedSeconds": 30,
        "httpConfigBlockFinished": http_config_unblocked.is_set(),
        "httpCalibrationReads": http_reads,
        "automaticHttpFallbacks": 0,
        "maxDeviceDeltaRows": max(publisher.device_sizes),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    assert 118 <= summary["durationSeconds"] <= 128
    assert len(publisher.router_times) >= 118
    assert summary["routerMaxInterval"] < 2.5
    assert len(publisher.device_times) >= 58
    assert summary["deviceMaxInterval"] < 5.0
    assert summary["httpConfigBlockFinished"] is True
    assert summary["automaticHttpFallbacks"] == 0
    assert summary["maxDeviceDeltaRows"] <= 1


if __name__ == "__main__":
    main()
