"""Regression and verification tests for minimal Router Core production recovery.

Covers:
1. SN missing but SID valid allows login (no fake serial='router')
2. Invalid Router config save does not wipe out previous valid config
3. When no real fast frame exists, NEVER emit fake router frame
4. First real fast frame immediately emitted into Hub WSS
5. Relay devices realtime demand/push works normally (devicesActive=True, acceptedDevices=True)
6. Relay devices realtime cannot change Core online member list
7. router/BE72 alias heartbeat works
8. router/BE72 alias command works
9. Hub restart preserves Router config
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
import requests
from flask import Flask

from router_core.driver.reyee_session import ReyeeSessionManager, _normalize_endpoint_url
from router_rpc import EncryptedRouterConfigStore
from router_core.realtime.router_realtime import RouterRealtimeEngine, RealtimeFrame
from router_lite_realtime_patch import RouterLiteRealtimeService
from agent_presence_patch import _presence, install_agent_presence_patch
from labrelay_sync_patch import install_labrelay_sync_patch
import hub_entry


# 1. SN missing but SID valid allows login
def test_sn_missing_but_sid_valid_allows_login(monkeypatch):
    class FakeResponse:
        status_code = 200
        text = '<html><input name="encry_key" value="testkey1234567890"/></html>'

        def json(self):
            return {
                "code": 0,
                "data": {
                    "sid": "session-valid-abc123",
                    "token": "token-valid-abc123",
                    "sessiontime": 3600,
                },
            }

    class FakeSession(requests.Session):
        def get(self, url, **kwargs):
            return FakeResponse()

        def post(self, url, **kwargs):
            return FakeResponse()

    mgr = ReyeeSessionManager(
        address="http://192.168.110.1",
        password="secretpassword",
        session_factory=FakeSession,
    )
    session = mgr.get_session()

    assert session.sid == "session-valid-abc123"
    assert session.token == "token-valid-abc123"
    assert session.serial_number == ""  # Does NOT fake serial="router"
    assert "sysauth=session-valid-abc123" in session.cookie_header
    assert "router=" not in session.cookie_header


# 2. Invalid Router config save does not wipe out previous valid config
def test_invalid_router_config_save_preserves_previous_valid_config(tmp_path, monkeypatch):
    store = EncryptedRouterConfigStore(tmp_path)
    store.save("http://192.168.110.1", "old-valid-pass", 3600, False, username="admin", name="BE72")

    session_mgr = ReyeeSessionManager(
        address="http://192.168.110.1",
        password="old-valid-pass",
    )

    monkeypatch.setattr(hub_entry, "router_config_store", store)
    monkeypatch.setattr(hub_entry, "router_session_mgr", session_mgr)

    # Candidate login failure
    def fake_perform_login(self):
        raise ValueError("Invalid candidate router password")

    monkeypatch.setattr(ReyeeSessionManager, "_perform_login", fake_perform_login)

    # Attempt to save invalid config
    with pytest.raises(ValueError, match="Invalid candidate router password"):
        hub_entry._save_router_config({
            "address": "http://192.168.110.1",
            "password": "wrong-new-pass",
            "test": True,
        })

    # The store MUST still contain the previous valid config
    current = store.load()
    assert current["address"] == "http://192.168.110.1"
    assert current["password"] == "old-valid-pass"
    assert session_mgr.address == "http://192.168.110.1"
    assert session_mgr.password == "old-valid-pass"


# 3. When no real fast frame exists, NEVER emit fake router frame
def test_no_real_fast_never_emits_fake_router_frame():
    engine = RouterRealtimeEngine()
    snapshot = engine.get_router_calibration_snapshot()

    assert snapshot["sampleEpochMs"] == 0
    assert snapshot["stale"] is True
    assert snapshot["connected"] is False
    assert snapshot["cpuPercent"] == 0.0
    assert snapshot["message"] == "等待路由器本地实时采样"


# 4. First real fast frame immediately emitted into Hub WSS
def test_first_real_fast_frame_immediately_enters_hub_wss():
    engine = RouterRealtimeEngine()
    received_frames = []

    engine.subscribe(lambda raw: received_frames.append(json.loads(raw)))

    # Real fast frame arrives from BE72 sysinfo-stream
    engine.accept_router_fast({"cpuPercent": 18.5, "uploadBps": 1024, "downloadBps": 8192}, sample_epoch_ms=1700000000000)

    assert len(received_frames) == 1
    frame = received_frames[0]
    assert frame["type"] == "router"
    assert frame["data"]["cpuPercent"] == 18.5
    assert frame["data"]["uploadBps"] == 1024
    assert frame["data"]["downloadBps"] == 8192
    assert frame["data"]["sampleEpochMs"] == 1700000000000
    assert frame["data"]["stale"] is False
    assert frame["data"]["source"] == "router_eweb_ws_fast"


# 5. Relay devices realtime demand/push works normally
def test_relay_devices_realtime_demand_and_push():
    fake_hub = SimpleNamespace(
        LOGGER=SimpleNamespace(info=lambda *args: None, debug=lambda *args: None),
        norm_mac=lambda mac: str(mac or "").strip().lower().replace("-", ":"),
    )
    engine = RouterRealtimeEngine()
    service = RouterLiteRealtimeService(fake_hub, router_sync=None, router_realtime=engine)

    # Initial state: no WSS clients -> devicesActive is False
    demand = service.demand_payload()
    assert demand["devicesActive"] is False
    assert demand["routerActive"] is False

    # App WSS client connects -> demand activated
    service.set_wss_demand("app-client-1", True)
    demand = service.demand_payload()
    assert demand["devicesActive"] is True
    assert demand["routerActive"] is False

    # Mock Core devices snapshot in engine
    engine.accept_devices_snapshot({
        "sampleEpochMs": 1700000000000,
        "devices": [
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.110.10", "name": "Phone"},
        ],
    })

    # Relay pushes 2-second rate sample
    push_result = service.accept_push({
        "sampleEpochMs": 1700000002000,
        "devices": [
            {"mac": "AA:BB:CC:DD:EE:01", "uploadBps": 4096, "downloadBps": 16384, "connectionCount": 12},
        ],
    })

    assert push_result["acceptedDevices"] is True
    assert push_result["acceptedRouter"] is False  # Never accepts router total rate fallback from Relay

    # Check updated device rates in engine
    latest = engine.devices_payload()
    assert latest["sampleEpochMs"] == 1700000002000
    assert len(latest["devices"]) == 1
    assert latest["devices"][0]["mac"] == "aa:bb:cc:dd:ee:01"
    assert latest["devices"][0]["uploadBps"] == 4096
    assert latest["devices"][0]["downloadBps"] == 16384
    assert latest["devices"][0]["connectionCount"] == 12


# 6. Relay devices realtime cannot change Core online member list
def test_relay_devices_realtime_cannot_change_core_online_member_list():
    fake_hub = SimpleNamespace(
        LOGGER=SimpleNamespace(info=lambda *args: None, debug=lambda *args: None),
        norm_mac=lambda mac: str(mac or "").strip().lower().replace("-", ":"),
    )
    engine = RouterRealtimeEngine()
    service = RouterLiteRealtimeService(fake_hub, router_sync=None, router_realtime=engine)
    service.set_wss_demand("app-client-1", True)

    # Core user_list has 1 device
    engine.accept_devices_snapshot({
        "sampleEpochMs": 1700000000000,
        "devices": [
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.110.10", "name": "Authorized Device"},
        ],
    })

    # Relay pushes rates including an alien MAC not in Core user_list
    service.accept_push({
        "sampleEpochMs": 1700000002000,
        "devices": [
            {"mac": "AA:BB:CC:DD:EE:01", "uploadBps": 1000, "downloadBps": 2000},
            {"mac": "99:88:77:66:55:44", "uploadBps": 9999, "downloadBps": 9999},
        ],
    })

    # Core device count MUST remain 1; alien MAC is rejected from membership
    latest = engine.devices_payload()
    assert len(latest["devices"]) == 1
    assert latest["devices"][0]["mac"] == "aa:bb:cc:dd:ee:01"


# 7. router/BE72 alias heartbeat works
def test_router_be72_alias_heartbeat_normal():
    now_epoch = int(time.time())
    agent_store = {
        "router": {
            "version": "0.2.28",
            "architecture": "aarch64",
            "lastSeenAt": "2026-08-27 12:00:00",
            "lastSeenEpoch": now_epoch,
        }
    }
    fake_hub = SimpleNamespace(
        AGENT_STATUS_FILE="agent_status.json",
        PORTMAP_ROUTER_STATUS_FILE="portmap_status.json",
        primary_router_name=lambda: "BE72",
        clean_saved_value=lambda v: str(v or "").strip(),
        load_json=lambda path, default=None: agent_store if "agent" in path else default,
    )

    presence = _presence(fake_hub, "")
    assert presence["agentOnline"] is True
    assert presence["agentState"] == "online"
    assert presence["agentVersion"] == "0.2.28"
    assert presence["agentArchitecture"] == "aarch64"


# 8. router/BE72 alias command works
def test_router_be72_alias_command_normal():
    app = Flask(__name__)
    app.add_url_rule("/api/portmaps", endpoint="api_portmaps", view_func=lambda: ("original", 200))
    commands_store = {
        "commands": [
            {
                "id": "cmd-be72-1",
                "router": "BE72",
                "action": "upsert",
                "payload": {"rule": {"id": "rule-1"}},
                "status": "pending",
            }
        ]
    }
    fake_hub = SimpleNamespace(
        app=app,
        LOGGER=SimpleNamespace(info=lambda *args: None, debug=lambda *args: None),
        AGENT_STATUS_FILE="agent_status.json",
        PORTMAP_ROUTER_STATUS_FILE="portmap_status.json",
        PORTMAP_COMMANDS_FILE="portmap_commands.json",
        primary_router_name=lambda: "BE72",
        clean_saved_value=lambda v: str(v or "").strip(),
        to_int=lambda v, d=0: int(v) if v else d,
        check_hook_token=lambda: True,
        now_str=lambda: "2026-08-27 12:00:00",
        load_json=lambda path, default=None: commands_store if "commands" in path else default,
        save_json=lambda path, value: None,
        _append_portmap_history=lambda record: None,
        _queue_portmap_command=lambda action, payload, router: None,
        _load_portmap_rules=lambda: [],
    )
    install_labrelay_sync_patch(fake_hub)

    # Agent polls with ?router=router
    with fake_hub.app.test_request_context("/api/router/portmaps/commands?router=router", method="GET"):
        response = fake_hub.app.view_functions["api_router_portmap_commands"]()

    assert response.status_code == 200
    data = response.get_json()
    assert len(data["commands"]) == 1
    assert data["commands"][0]["id"] == "cmd-be72-1"


# 9. Hub restart preserves Router config
def test_hub_restart_preserves_router_config(tmp_path):
    store1 = EncryptedRouterConfigStore(tmp_path)
    store1.save("http://192.168.110.1:8080/cgi-bin/luci", "p@ssword123", 7200, True, username="admin", name="MyBE72")

    # Simulate restart by loading in a new instance
    store2 = EncryptedRouterConfigStore(tmp_path)
    loaded = store2.load()

    assert loaded["address"] == "http://192.168.110.1:8080/cgi-bin/luci"
    assert loaded["password"] == "p@ssword123"
    assert loaded["username"] == "admin"
    assert loaded["sessionSeconds"] == 7200
    assert loaded["verifyTls"] is True
    assert loaded["name"] == "MyBE72"
