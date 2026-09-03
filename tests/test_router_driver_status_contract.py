"""Tests for ReyeeEWebDriver and status localization patch contract.

Validates the three primary states:
1. unconfigured: Host or password missing
2. configured but not logged in: Host and password present, session not yet active (state=syncing, configured=True)
3. logged in: Host and password present, session active (state=ready, connected=True, configured=True)
"""

from unittest.mock import MagicMock
import pytest
from flask import Flask, jsonify

from router_core.driver.reyee import ReyeeEWebDriver
from router_core.driver.reyee_rpc import ReyeeRpcClient
from router_core.driver.reyee_session import ReyeeSession, ReyeeSessionManager
from router_realtime_stability_patch import install_router_status_localization


def test_driver_status_unconfigured_when_password_missing():
    mock_mgr = MagicMock(spec=ReyeeSessionManager)
    mock_mgr.address = "https://192.168.110.1"
    mock_mgr.password = ""
    mock_mgr.is_valid.return_value = False

    mock_rpc = MagicMock(spec=ReyeeRpcClient)
    mock_rpc.session_manager = mock_mgr

    driver = ReyeeEWebDriver(rpc_client=mock_rpc)
    status = driver.get_status()
    caps = driver.get_capabilities()

    assert status["configured"] is False
    assert status["state"] == "unconfigured"
    assert status["connected"] is False
    assert status["errorCode"] == "ROUTER_NOT_CONFIGURED"
    assert caps["configured"] is False


def test_driver_status_configured_not_logged_in():
    mock_mgr = MagicMock(spec=ReyeeSessionManager)
    mock_mgr.address = "https://192.168.110.1"
    mock_mgr.password = "my_router_pass"
    mock_mgr.is_valid.return_value = False

    mock_rpc = MagicMock(spec=ReyeeRpcClient)
    mock_rpc.session_manager = mock_mgr

    driver = ReyeeEWebDriver(rpc_client=mock_rpc)
    status = driver.get_status()
    caps = driver.get_capabilities()

    assert status["configured"] is True
    assert status["state"] == "syncing"
    assert status["connected"] is False
    assert status["message"] == "正在准备路由控制数据"
    assert status["errorCode"] == ""
    assert caps["configured"] is True


def test_driver_status_logged_in():
    mock_mgr = MagicMock(spec=ReyeeSessionManager)
    mock_mgr.address = "https://192.168.110.1"
    mock_mgr.password = "my_router_pass"
    mock_mgr.is_valid.return_value = True

    mock_rpc = MagicMock(spec=ReyeeRpcClient)
    mock_rpc.session_manager = mock_mgr

    driver = ReyeeEWebDriver(rpc_client=mock_rpc)
    status = driver.get_status()
    caps = driver.get_capabilities()

    assert status["configured"] is True
    assert status["state"] in ("connected", "ready")
    assert status["connected"] is True
    assert status["sessionConnected"] is True
    assert status["dataAvailable"] is True
    assert status["message"] == "路由连接正常"
    assert status["errorCode"] == ""
    assert caps["configured"] is True


def test_patch_status_view_integration():
    """Validates that status_view() does not misclassify configured states."""
    app = Flask(__name__)
    hub = MagicMock()
    hub.app = app
    hub.check_app_token.return_value = True
    hub.ROUTER_DASHBOARD_LOCK = MagicMock()
    hub.ROUTER_DASHBOARD_CACHE = {}

    mock_mgr = MagicMock(spec=ReyeeSessionManager)
    mock_mgr.address = "https://192.168.110.1"
    mock_mgr.password = "valid_password"
    mock_mgr.is_valid.return_value = False

    mock_rpc = MagicMock(spec=ReyeeRpcClient)
    mock_rpc.session_manager = mock_mgr

    driver = ReyeeEWebDriver(rpc_client=mock_rpc)
    sync = MagicMock()
    sync.client = driver

    @app.route("/api/router/status", endpoint="router_core_v1.get_status")
    def get_status():
        return jsonify(driver.get_status())

    install_router_status_localization(hub, sync)

    with app.test_request_context("/api/router/status"):
        resp = app.view_functions["router_core_v1.get_status"]()
        json_data = resp.get_json()

        # Must NOT be unconfigured because password is configured!
        assert json_data["state"] != "unconfigured"
        assert json_data["errorCode"] != "HUB_ROUTER_NOT_CONFIGURED"
        assert json_data["state"] in ("syncing", "recovering")
