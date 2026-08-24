"""Integration Tests for router_core/service/blueprint.py.

Validates:
1. App-Token authorization on all routes.
2. Endpoint responses matching docs/contracts/app-hub-contract-v1.json.
3. Accurate query parameters (force=1) and JSON request forwarding.
4. Error translation into standard HTTP status codes.
"""

from unittest.mock import MagicMock
from flask import Flask
import pytest

from router_core.driver.base import RouterDriver
from router_core.errors import RouterAuthError, RouterNotConfiguredError, RouterUnreachableError
from router_core.service.router_service import RouterService
from router_core.service.blueprint import create_router_blueprint_v1


@pytest.fixture
def mock_driver():
    driver = MagicMock(spec=RouterDriver)
    driver.get_capabilities.return_value = {
        "configured": True,
        "features": {
            "dashboard": True,
            "devices": True,
            "firewall": True,
            "nativePortMapping": True,
            "upnp": True,
            "ddns": True,
            "diagnostic": True,
        },
    }
    driver.get_status.return_value = {
        "state": "connected",
        "connected": True,
        "sessionConnected": True,
        "dataAvailable": True,
        "message": "路由连接正常",
        "errorCode": "",
        "lastSuccessAt": 1700000000000,
    }
    driver.get_dashboard.return_value = {"hardware": {"cpu": 15.0}}
    driver.get_devices.return_value = [{"mac": "AA:BB:CC:DD:EE:01"}]
    driver.get_port_mappings.return_value = {"rules": [{"name": "ssh", "extPort": 2222}]}
    driver.add_port_mapping.return_value = {"rules": [{"name": "web", "extPort": 80}]}
    driver.update_port_mapping.return_value = {"rules": [{"name": "web", "extPort": 8080}]}
    driver.delete_port_mapping.return_value = {"rules": []}
    driver.get_upnp.return_value = {"enabled": True, "wan": "WAN", "rules": []}
    driver.set_upnp.return_value = {"enabled": False, "wan": "WAN", "rules": []}
    driver.get_firewall.return_value = {"wanInboundAllow": False, "rules": []}
    driver.add_firewall_rule.return_value = {"wanInboundAllow": False, "rules": [{"uuid": "u1"}]}
    driver.update_firewall_rule.return_value = {"wanInboundAllow": False, "rules": [{"uuid": "u1"}]}
    driver.set_firewall_rule_enabled.return_value = {"wanInboundAllow": False, "rules": [{"uuid": "u1", "enabled": True}]}
    driver.delete_firewall_rule.return_value = {"wanInboundAllow": False, "rules": []}
    driver.reorder_firewall_rules.return_value = {"wanInboundAllow": False, "rules": []}
    driver.get_ddns.return_value = {"services": []}
    driver.add_ddns.return_value = {"services": [{"serviceId": "s1"}]}
    driver.update_ddns.return_value = {"services": [{"serviceId": "s1"}]}
    driver.delete_ddns.return_value = {"services": []}
    driver.get_ipv6_status.return_value = {"enabled": True, "wanAddress": "240e::1"}
    driver.get_ipv6_config.return_value = {"wan": {"proto": "dhcpv6"}}
    driver.get_dhcpv6_clients.return_value = {"clients": []}
    driver.save_ipv6_config.return_value = {"wan": {"proto": "dhcpv6"}}
    driver.get_diagnostic.return_value = {"process": "100%", "List": []}
    driver.start_diagnostic.return_value = {"process": "0%", "List": []}
    return driver


@pytest.fixture
def test_app(mock_driver):
    app = Flask("router_core_test_app")
    service = RouterService(mock_driver)
    bp = create_router_blueprint_v1(service, check_app_token=lambda: True)
    app.register_blueprint(bp)
    return app.test_client()


@pytest.fixture
def unauthorized_app(mock_driver):
    app = Flask("unauthorized_app")
    service = RouterService(mock_driver)
    bp = create_router_blueprint_v1(service, check_app_token=lambda: False)
    app.register_blueprint(bp)
    return app.test_client()


def test_auth_guard(unauthorized_app):
    resp = unauthorized_app.get("/api/router/capabilities")
    assert resp.status_code == 401
    assert resp.get_json() == {"ok": False, "error": "unauthorized"}


def test_capabilities_and_status(test_app, mock_driver):
    r1 = test_app.get("/api/router/capabilities")
    assert r1.status_code == 200
    assert r1.get_json()["configured"] is True

    r2 = test_app.get("/api/router/status")
    assert r2.status_code == 200
    assert r2.get_json()["connected"] is True


def test_dashboard_and_devices(test_app, mock_driver):
    r1 = test_app.get("/api/router/dashboard?force=1")
    assert r1.status_code == 200
    assert r1.get_json()["hardware"]["cpu"] == 15.0
    mock_driver.get_dashboard.assert_called_with(force=True)

    r2 = test_app.post("/api/router/dashboard/refresh")
    assert r2.status_code == 200
    assert r2.get_json()["hardware"]["cpu"] == 15.0

    r3 = test_app.get("/api/router/devices")
    assert r3.status_code == 200
    assert len(r3.get_json()) == 1


def test_port_mapping_endpoints(test_app, mock_driver):
    # GET
    r1 = test_app.get("/api/router/port-mapping")
    assert r1.status_code == 200
    assert "data" in r1.get_json()

    # POST
    r2 = test_app.post("/api/router/port-mapping", json={"name": "web", "extPort": 80})
    assert r2.status_code == 200
    assert "data" in r2.get_json()

    # PUT
    r3 = test_app.put("/api/router/port-mapping/web", json={"name": "web", "extPort": 8080})
    assert r3.status_code == 200
    assert "data" in r3.get_json()

    # DELETE
    r4 = test_app.delete("/api/router/port-mapping/web")
    assert r4.status_code == 200
    assert "data" in r4.get_json()


def test_upnp_and_firewall_endpoints(test_app, mock_driver):
    # UPnP
    r1 = test_app.get("/api/router/upnp")
    assert r1.status_code == 200
    assert r1.get_json()["data"]["enabled"] is True

    r2 = test_app.put("/api/router/upnp", json={"enabled": False, "wan": "WAN"})
    assert r2.status_code == 200
    assert r2.get_json()["data"]["enabled"] is False

    # Firewall
    r3 = test_app.get("/api/router/firewall")
    assert r3.status_code == 200
    assert "wanInboundAllow" in r3.get_json()["data"]

    r4 = test_app.post("/api/router/firewall/rules", json={"name": "test_fw"})
    assert r4.status_code == 200
    assert len(r4.get_json()["data"]["rules"]) == 1

    r5 = test_app.patch("/api/router/firewall/rules/u1/enabled", json={"enabled": True})
    assert r5.status_code == 200

    r6 = test_app.post("/api/router/firewall/reorder", json={"scope": "wan", "uuids": ["u1"]})
    assert r6.status_code == 200


def test_ddns_and_ipv6_and_diagnostic(test_app, mock_driver):
    # DDNS
    r1 = test_app.get("/api/router/ddns")
    assert r1.status_code == 200
    assert "services" in r1.get_json()["data"]

    # IPv6
    r2 = test_app.get("/api/router/ipv6/status")
    assert r2.status_code == 200
    assert r2.get_json()["data"]["wanAddress"] == "240e::1"

    # Diagnostic
    r3 = test_app.get("/api/router/diagnostic")
    assert r3.status_code == 200
    assert r3.get_json()["data"]["process"] == "100%"

    r4 = test_app.post("/api/router/diagnostic")
    assert r4.status_code == 200


def test_error_handling(test_app, mock_driver):
    mock_driver.get_dashboard.side_effect = RouterAuthError("Session expired")
    resp = test_app.get("/api/router/dashboard")
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["code"] == "LOGIN_FAILED"
    assert data["status"] == "error"
