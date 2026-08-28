"""End-to-end test verifying that Router Core v1 is actively serving production Hub."""

import pytest
import hub
import hub_entry


@pytest.fixture(autouse=True)
def setup_tokens(monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-token")
    monkeypatch.setenv("LABPROBE_TOKEN", "test-token")
    monkeypatch.setattr(hub, "get_app_token", lambda: "test-token")
    monkeypatch.setattr(hub, "get_hook_token", lambda: "test-token")
    monkeypatch.setattr(hub, "cfg_get", lambda k, default=None: "test-token" if "token" in k else default)


@pytest.fixture
def test_client():
    hub.app.config["TESTING"] = True
    return hub.app.test_client()


def test_production_router_core_blueprint_registered(test_client):
    blueprints = hub.app.blueprints
    assert "router_core_api" in blueprints
    assert hasattr(hub, "ROUTER_SERVICE")
    assert hasattr(hub, "ROUTER_DRIVER")
    assert hasattr(hub, "ROUTER_CACHE")
    assert hasattr(hub, "ROUTER_REALTIME")
    assert hub.HUB_REALTIME_WEBSOCKET.realtime_service is hub.ROUTER_REALTIME
    assert hub.HUB_REALTIME_WEBSOCKET.demand_service is hub.ROUTER_LITE_REALTIME


def test_router_settings_accept_existing_compose_environment(monkeypatch, tmp_path):
    monkeypatch.setattr(hub, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(hub, "cfg_get", lambda _key, default=None: default)
    monkeypatch.delenv("ROUTER_HOST", raising=False)
    monkeypatch.delenv("ROUTER_PASSWORD", raising=False)
    monkeypatch.setenv("ROUTER_EWEB_URL", "http://192.168.8.1")
    monkeypatch.setenv("ROUTER_EWEB_PASSWORD", "existing-secret")
    monkeypatch.setenv("ROUTER_SESSION_TIME", "4200")
    monkeypatch.setenv("ROUTER_VERIFY_TLS", "true")

    settings = hub_entry._resolve_router_settings()

    assert settings == {
        "host": "http://192.168.8.1",
        "password": "existing-secret",
        "username": "admin",
        "session_seconds": 4200,
        "verify_tls": True,
    }


def test_production_router_capabilities_and_status(test_client):
    headers = {"Authorization": "Bearer test-token"}

    # Capabilities
    res = test_client.get("/api/router/capabilities", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert "features" in data
    assert "configured" in data

    # Status
    res = test_client.get("/api/router/status", headers=headers)
    assert res.status_code == 200
    status_data = res.get_json()
    assert "state" in status_data
    assert "connected" in status_data


def test_production_router_realtime_and_tasks(test_client):
    headers = {"Authorization": "Bearer test-token"}

    # Realtime calibration
    res = test_client.get("/api/router/realtime", headers=headers)
    assert res.status_code == 200
    rt_data = res.get_json()
    assert "state" in rt_data
    assert "connected" in rt_data

    # Task query
    res = test_client.get("/api/router/tasks/diagnostic", headers=headers)
    assert res.status_code == 200
    task_data = res.get_json()
    assert task_data["ok"] is True
    assert "data" in task_data


def test_production_router_ipv6_and_firewall_unconfigured_contract(test_client):
    headers = {"Authorization": "Bearer test-token"}

    # IPv6 Status (unconfigured returns 503 with standardized error dictionary)
    res = test_client.get("/api/router/ipv6/status", headers=headers)
    assert res.status_code in (200, 502, 503)
    if res.status_code in (502, 503):
        body = res.get_json()
        assert body["ok"] is False

    # Firewall
    res = test_client.get("/api/router/firewall", headers=headers)
    assert res.status_code in (200, 502, 503)
    if res.status_code in (502, 503):
        body = res.get_json()
        assert body["ok"] is False
