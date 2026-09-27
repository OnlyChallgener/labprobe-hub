"""让 agent 的 dashboard 推送也能喂 App 的实时帧。

动机是实测出来的：BE50（EG 线固件 3.0B11P380）上 hub 的 eWeb WS 采样通道压根不存在，
`/api/router/realtime` 永远回 `connected:false / sampleEpochMs:0 / 等待路由器本地实时采样`，
App 就一直「等待首帧」。而 agent 每 2 秒推的 telemetry 里其实有这些数（BE50 上值多为 0，
但键是齐的；设备数 7 是对的）。

BE72 上 eWeb 那条更快也更全，所以 agent 这条必须让路 —— 下面第 3、4 条钉的就是这个。
"""

import json
import time

from router_core.realtime.router_realtime import RouterRealtimeEngine


# 2026-09-27 从 58444 那台 hub 的 /api/router/dashboard 里抄下来的真实形状。
BE50_TELEMETRY = {
    "cpuPercent": 0.0,
    "memoryPercent": 0.0,
    "storagePercent": None,
    "temperatureC": 0.0,
    "temperature2gC": 0.0,
    "temperature5gC": 0.0,
    "uptimeSeconds": 0,
    "onlineDeviceCount": 7,
    "connections": {"cps": 0, "flowCount": 0, "ipv4": 0, "ipv4Half": 0, "ipv4Local": 0,
                    "ipv6": 0, "ipv6Half": 0, "ipv6Local": 0, "max": 0},
    "wan": {"dailyDownloadBytes": 0, "dailyUploadBytes": 0, "downloadBps": 0,
            "totalDownloadBytes": 0, "totalUploadBytes": 0, "uploadBps": 0},
}


def _collect(engine):
    frames = []
    engine.subscribe(lambda raw: frames.append(json.loads(raw)))
    return frames


def test_flatten_maps_nested_agent_fields():
    sample = RouterRealtimeEngine.flatten_agent_telemetry({
        "cpuPercent": 6.02, "memoryPercent": 37.85, "storagePercent": 23.0,
        "uptimeSeconds": 1302851, "temperatureC": 72.0, "onlineDeviceCount": 7,
        "connections": {"ipv4": 128, "ipv6": 2, "ipv4Half": 20, "ipv6Half": 0, "cps": 3},
        "wan": {"downloadBps": 1074743, "uploadBps": 12000,
                "totalDownloadBytes": 999, "totalUploadBytes": 888},
    })
    assert sample["cpuPercent"] == 6.02
    assert sample["ipv4Connections"] == 128
    assert sample["ipv6Connections"] == 2
    assert sample["cps"] == 3
    assert sample["downloadBps"] == 1074743
    assert sample["uptimeSeconds"] == 1302851


def test_flatten_drops_unknown_instead_of_inventing_zero():
    # storagePercent: null 在 App 上是「--」；摊成 0.0 就成了「测到 0%」，是假数。
    sample = RouterRealtimeEngine.flatten_agent_telemetry(BE50_TELEMETRY)
    assert "storagePercent" not in sample
    assert sample["onlineDeviceCount"] == 7
    assert sample["ipv4Connections"] == 0


def test_agent_telemetry_produces_the_first_router_frame_when_eweb_is_absent():
    engine = RouterRealtimeEngine()
    frames = _collect(engine)
    engine.accept_agent_telemetry(BE50_TELEMETRY, int(time.time() * 1000))
    router = [f for f in frames if f.get("type") == "router"]
    assert len(router) == 1
    data = router[0]["data"]
    assert data["connected"] is True
    assert data["ok"] is True
    assert data["stale"] is False
    assert data["source"] == "agent_dashboard_push"
    assert data["onlineDeviceCount"] == 7
    assert data["sampleEpochMs"] > 0


def test_agent_telemetry_yields_to_a_fresh_eweb_sample():
    engine = RouterRealtimeEngine()
    engine.accept_router_fast({"cpuPercent": 5.0, "downloadBps": 100}, int(time.time() * 1000))
    frames = _collect(engine)
    engine.accept_agent_telemetry({"cpuPercent": 99.0, "onlineDeviceCount": 7}, int(time.time() * 1000))
    assert [f for f in frames if f.get("type") == "router"] == []


def test_agent_telemetry_takes_over_once_eweb_goes_quiet():
    engine = RouterRealtimeEngine()
    stale_ms = int(time.time() * 1000) - (engine.AGENT_TELEMETRY_TAKEOVER_SECONDS * 1000 + 5000)
    engine.accept_router_fast({"cpuPercent": 5.0}, stale_ms)
    frames = _collect(engine)
    engine.accept_agent_telemetry({"cpuPercent": 12.5, "onlineDeviceCount": 7}, int(time.time() * 1000))
    router = [f for f in frames if f.get("type") == "router"]
    assert len(router) == 1
    assert router[0]["data"]["source"] == "agent_dashboard_push"
    assert router[0]["data"]["cpuPercent"] == 12.5


def test_agent_telemetry_ignores_payloads_without_any_contract_field():
    engine = RouterRealtimeEngine()
    frames = _collect(engine)
    engine.accept_agent_telemetry({"wireguard": {"peers": 2}}, int(time.time() * 1000))
    engine.accept_agent_telemetry(None)
    assert frames == []
