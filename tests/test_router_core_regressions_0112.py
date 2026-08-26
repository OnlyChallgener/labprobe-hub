import json
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import followup_stability_patch
import hub
import hub_entry
import router_relay_credentials_patch
from router_core.driver.reyee import ReyeeEWebDriver
from router_core.driver.reyee_rpc import ReyeeRpcClient
from router_core.realtime.router_realtime import RouterRealtimeEngine
from router_rpc import EncryptedRouterConfigStore
from router_ws_patch import RouterWebSocketMonitor, normalize_fast_message


def _rpc_mock() -> MagicMock:
    rpc = MagicMock(spec=ReyeeRpcClient)
    rpc.session_manager = MagicMock()
    rpc.session_manager.address = "http://192.168.5.1"
    rpc.session_manager.password = "secret"
    rpc.session_manager.is_valid.return_value = True
    return rpc


def test_native_ddns_accepts_be72_json_string_and_redacts_password():
    rpc = _rpc_mock()
    # Case 1: Router returns json array string in data field directly
    rpc.rpc.return_value = json.dumps([
        {"service": "first", "domain": "one.example", "password": "one-secret"},
        {"service": "second", "domain": "two.example", "password": "two-secret"},
    ])
    driver = ReyeeEWebDriver(rpc_client=rpc)

    result = driver.get_ddns(force=True)

    assert [row["service"] for row in result["list"]] == ["first", "second"]
    assert [row["service"] for row in result["services"]] == ["first", "second"]
    assert all(row["password"] == "" for row in result["list"])
    assert all(row["passwordConfigured"] is True for row in result["list"])

    # Case 2: Router returns nested list dict
    rpc.rpc.return_value = {
        "list": [
            {"service": "third", "domain": "three.example", "password": "three-secret"},
        ]
    }
    result2 = driver.get_ddns(force=True)
    assert [row["service"] for row in result2["list"]] == ["third"]
    assert [row["service"] for row in result2["services"]] == ["third"]


def test_be72_fast_frame_keeps_both_radio_temperatures_in_core_wss():
    engine = RouterRealtimeEngine()
    frames = []
    engine.subscribe(frames.append)
    monitor = RouterWebSocketMonitor(
        SimpleNamespace(),
        SimpleNamespace(debug=lambda *_args, **_kwargs: None),
    )
    monitor.set_fast_handler(engine.accept_router_fast)

    monitor._dispatch_message({
        "type": "fast",
        "data": {"temp": 52, "temp_2g": 47.5, "temp_5g": 50.25},
    })

    payload = json.loads(frames[-1])["data"]
    assert payload["temperatureC"] == 52.0
    assert payload["temperature2gC"] == 47.5
    assert payload["temperature5gC"] == 50.25


def test_be72_fractional_percentages_and_slow_frame_reach_core_wss():
    engine = RouterRealtimeEngine()
    frames = []
    engine.subscribe(frames.append)
    monitor = RouterWebSocketMonitor(
        SimpleNamespace(),
        SimpleNamespace(debug=lambda *_args, **_kwargs: None),
    )
    monitor.set_slow_handler(engine.accept_router_slow)

    assert normalize_fast_message({"type": "slow", "data": {"memutil": 0.34, "diskutil": 0.11}})["storagePercent"] == 11.0
    monitor._dispatch_message({
        "type": "slow",
        "data": {"runtime": 90000, "memutil": 0.34, "diskutil": 0.11},
    })

    payload = json.loads(frames[-1])["data"]
    assert payload["uptimeSeconds"] == 90000
    assert payload["memoryPercent"] == 34.0
    assert payload["storagePercent"] == 11.0
    assert payload["source"] == "router_eweb_ws_slow"


def test_core_dashboard_merges_authenticated_websocket_snapshot():
    rpc = _rpc_mock()
    rpc.rpc.return_value = {}
    rpc.batch.return_value = [{}, {}, {}, {}]
    driver = ReyeeEWebDriver(rpc_client=rpc)
    driver.router_ws_monitor = SimpleNamespace(snapshot=lambda: {
        "fast": {"type": "fast", "data": {"temp_2g": 41, "temp_5g": 45}},
        "slow": {"type": "slow", "data": {"hostname": "BE72"}},
        "wsStatus": {"connected": True},
    })

    result = driver.get_dashboard(force=True)

    assert result["fast"]["data"]["temp_2g"] == 41
    assert result["slow"]["data"]["hostname"] == "BE72"
    assert result["wsStatus"]["connected"] is True


def test_production_credentials_and_agent_command_views_are_installed():
    sync = hub.ROUTER_RPC_COMPAT_SYNC
    assert hub.app.view_functions["api_router_credentials_refresh"].__self__ is sync
    assert hub.app.view_functions["api_router_agent_commands"].__self__ is sync


def test_agent_snapshot_expires_stale_command_without_starving_cleanup():
    rows = [
        {
            "id": "stale",
            "router": "router",
            "action": "update",
            "state": "pending",
            "createdAt": "2020-01-01 00:00:00",
        },
        {
            "id": "cleanup",
            "router": "router",
            "action": "cleanup",
            "state": "pending",
            "createdAt": hub.now_str(),
        },
    ]
    saved = []
    fake_hub = SimpleNamespace(
        AGENT_UPDATE_COMMANDS_FILE="commands.json",
        load_json=lambda *_args, **_kwargs: {"commands": rows},
        save_json=lambda _path, value: saved.append(value),
        time_to_epoch=hub.time_to_epoch,
        now_str=hub.now_str,
        ROUTER_CREDENTIALS_LOCK=threading.RLock(),
        ROUTER_CREDENTIALS_REFRESH_NONCE=0,
        ROUTER_CREDENTIALS_CACHE={},
    )

    pending, _requested, _completed = router_relay_credentials_patch._agent_command_snapshot(
        SimpleNamespace(hub=fake_hub), "router"
    )

    assert rows[0]["state"] == "failed"
    assert [row["id"] for row in pending] == ["cleanup"]
    assert saved


def test_manifest_refresh_queues_the_resolved_github_fallback_urls(monkeypatch):
    rows = [{"id": "cmd", "state": "preparing"}]
    saved = []
    fake_hub = SimpleNamespace(
        AGENT_UPDATE_COMMANDS_FILE="commands.json",
        UPDATE_REPOSITORY_ROOT="https://unreachable.invalid",
        AGENT_MANIFEST_URL="https://unreachable.invalid/manifest.json",
        AGENT_INSTALLER_URL="https://unreachable.invalid/install.sh",
        LOGGER=SimpleNamespace(warning=lambda *_args, **_kwargs: None),
        load_json=lambda *_args, **_kwargs: {"commands": rows},
        save_json=lambda _path, value: saved.append(value),
        now_str=hub.now_str,
        clean_saved_value=hub.clean_saved_value,
        agent_release_manifest=lambda force=False: {
            "version": "0.2.28",
            "_repositoryRoot": "https://github.com/OnlyChallgener/LabRelay/releases/download/v0.2.28",
            "_manifestUrl": "https://github.com/manifest.json",
            "_installerUrl": "https://github.com/install.sh",
        },
    )

    class ImmediateThread:
        def __init__(self, target, **_kwargs):
            self.target = target

        def start(self):
            self.target()

    monkeypatch.setattr(followup_stability_patch.threading, "Thread", ImmediateThread)
    followup_stability_patch._start_manifest_refresh(fake_hub, "cmd", force=True)

    assert rows[0]["state"] == "pending"
    assert rows[0]["manifestUrl"] == "https://github.com/manifest.json"
    assert rows[0]["installerUrl"] == "https://github.com/install.sh"
    assert saved


def test_app_managed_router_config_overrides_compose_after_save(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "config-key")
    monkeypatch.setenv("ROUTER_EWEB_URL", "http://192.168.5.1")
    monkeypatch.setenv("ROUTER_EWEB_PASSWORD", "compose-password")
    store = EncryptedRouterConfigStore(tmp_path)

    store.save(
        "http://192.168.8.1",
        "app-password",
        4200,
        username="operator",
        name="BE72 Upstairs",
    )
    loaded = store.load()

    assert loaded["managed"] is True
    assert loaded["address"] == "http://192.168.8.1"
    assert loaded["password"] == "app-password"
    assert loaded["username"] == "operator"
    assert loaded["name"] == "BE72 Upstairs"


def test_router_config_routes_are_owned_by_core():
    adapter = hub.app.url_map.bind("localhost")
    assert adapter.match("/api/router/config", method="GET")[0] == "router_core_api.get_connection_config"
    assert adapter.match("/api/router/config", method="PUT")[0] == "router_core_api.save_connection_config"


def test_public_router_config_uses_effective_runtime_values_when_store_is_empty(monkeypatch):
    monkeypatch.setattr(hub_entry.router_config_store, "load", lambda: {})
    monkeypatch.setattr(hub_entry.router_driver, "get_status", lambda: {
        "connected": True,
        "state": "ready",
        "message": "ok",
    })
    monkeypatch.setattr(hub_entry.router_session_mgr, "address", "http://192.168.5.1")
    monkeypatch.setattr(hub_entry.router_session_mgr, "username", "admin")
    monkeypatch.setattr(hub_entry.router_session_mgr, "password", "runtime-secret")
    monkeypatch.setattr(hub_entry.router_session_mgr, "session_seconds", 3600)
    monkeypatch.setattr(hub_entry.router_session_mgr, "verify_tls", False)

    config = hub_entry._public_router_config()

    assert config["address"] == "http://192.168.5.1"
    assert config["username"] == "admin"
    assert config["passwordConfigured"] is True
    assert config["connected"] is True


def test_router_config_save_with_blank_password_preserves_effective_secret(monkeypatch):
    saved_passwords = []
    reconfigured = []

    monkeypatch.setattr(hub_entry.router_config_store, "load", lambda: {})

    def save(address, password, session_seconds, verify_tls, *, username, name):
        saved_passwords.append(password)
        return {
            "address": address,
            "password": password,
            "sessionSeconds": session_seconds,
            "verifyTls": verify_tls,
            "username": username,
            "name": name,
            "managed": True,
        }

    monkeypatch.setattr(hub_entry.router_config_store, "save", save)
    monkeypatch.setattr(hub_entry.router_session_mgr, "address", "http://192.168.5.1")
    monkeypatch.setattr(hub_entry.router_session_mgr, "username", "admin")
    monkeypatch.setattr(hub_entry.router_session_mgr, "password", "runtime-secret")
    monkeypatch.setattr(hub_entry.router_session_mgr, "session_seconds", 3600)
    monkeypatch.setattr(hub_entry.router_session_mgr, "reconfigure", lambda **kwargs: reconfigured.append(kwargs))
    monkeypatch.setattr(hub_entry.router_cache, "clear", lambda: None)
    monkeypatch.setattr(hub_entry.router_driver, "get_status", lambda: {"connected": True, "state": "ready"})

    result = hub_entry._save_router_config({
        "name": "BE72",
        "address": "http://192.168.5.1",
        "username": "admin",
        "password": "",
        "test": False,
    })

    assert saved_passwords == ["runtime-secret"]
    assert reconfigured[0]["password"] == "runtime-secret"
    assert result["address"] == "http://192.168.5.1"
    assert result["passwordConfigured"] is True
