import time
from types import SimpleNamespace

import pytest
from flask import Blueprint, Flask, jsonify

import router_native_features_patch as native_patch
import router_rpc_v099 as v099
from router_native_features_patch import (
    _nat_error_message,
    _nat_result_is_stale,
    _nat_result_timestamp,
    _nat_result_with_request,
    _nat_terminal,
    normalize_nat_request,
)
from router_rpc import RouterRpcError


def test_nat_request_defaults_match_reliable_server():
    assert normalize_nat_request({}) == {
        "host": "stun.voip.aebc.com",
        "port": 3478,
        "interface": "wan",
        "mode": "classic",
    }


def test_nat_request_accepts_rfc5780_and_wan1():
    assert normalize_nat_request({
        "host": "stun.voip.aebc.com",
        "port": "5478",
        "interface": "WAN1",
        "mode": "5780",
    }) == {
        "host": "stun.voip.aebc.com",
        "port": 5478,
        "interface": "wan1",
        "mode": "5780",
    }


def test_nat_result_keeps_requested_parameters_for_app_history():
    result = _nat_result_with_request(
        {"status": "completed", "nat_type": "port-restricted cone"},
        {"host": "stun.example.com", "port": 5478, "interface": "wan1", "mode": "5780"},
    )

    assert result["requested_port"] == 5478
    assert result["requested_host"] == "stun.example.com"
    assert result["requested_interface"] == "wan1"
    assert result["requested_mode"] == "5780"
    assert result["nat_type"] == "port-restricted cone"
    assert result["status"] == "failed"
    assert result["wanId"] == "wan1"
    assert result["errorCode"] == "wan_mismatch"


def test_nat_result_rejects_firmware_output_from_another_wan():
    result = _nat_result_with_request(
        {"status": "completed", "nat_type": "Full Cone", "detected_interface": "wan"},
        {"interface": "wan1"},
    )
    assert result["status"] == "failed"
    assert result["requested_interface"] == "wan1"
    assert result["detected_interface"] == "wan"
    assert result["wanId"] == "wan"
    assert result["errorCode"] == "wan_mismatch"


def test_nat_result_correlates_request_and_firmware_metadata():
    result = _nat_result_with_request(
        {
            "status": "completed",
            "nat_type": "Full Cone",
            "timestamp": "2000",
            "log": "[2026-11-25 10:00:00] Interface: WAN1\n[2026-11-25 10:00:00] Source IP: 192.0.2.10\n",
        },
        {"host": "stun.example.com", "port": 3478, "interface": "wan1", "mode": "classic"},
        request_id="request-1",
        task_id="nat-1",
        request_started_at=2000,
    )

    assert result["request_id"] == result["requestId"] == "request-1"
    assert result["task_id"] == result["taskId"] == "nat-1"
    assert result["request_started_at"] == result["requestStartedAt"] == 2000
    assert result["result_timestamp"] == result["resultTimestamp"] == 2000
    assert result["requested_interface"] == "wan1"
    assert result["detected_interface"] == "wan1"
    assert result["source_ip"] == result["sourceIpv4"] == "192.0.2.10"


def test_nat_timestamped_results_before_request_or_previous_result_are_stale():
    assert _nat_result_timestamp({"timestamp": "1700000000000"}) == 1_700_000_000
    assert _nat_result_is_stale({"timestamp": 1999}, 2000)
    assert _nat_result_is_stale({"timestamp": 2001}, 2000, 2002)
    assert not _nat_result_is_stale({"timestamp": 2000}, 2000)
    assert not _nat_result_is_stale({"status": "completed"}, 2000)


def test_nat_terminal_accepts_completed_failed_and_nat_type_results():
    assert _nat_terminal({"status": "completed"})
    assert _nat_terminal({"status": "timeout"})
    assert _nat_terminal({"nat_type": "symmetric"})
    assert not _nat_terminal({"status": "running"})


def test_nat_transport_errors_are_localized():
    assert _nat_error_message(RuntimeError("read timed out")) == "路由器 NAT 检测请求暂时无响应"
    assert _nat_error_message(RuntimeError("DNS resolution failed")) == "STUN 服务器域名解析失败"


@pytest.mark.parametrize(
    "payload",
    [
        {"host": "bad host"},
        {"port": 0},
        {"port": 70000},
        {"interface": "lan"},
        {"mode": "unknown"},
    ],
)
def test_nat_request_rejects_invalid_values(payload):
    with pytest.raises(RouterRpcError):
        normalize_nat_request(payload)


def test_native_nat_endpoint_rejects_concurrent_request_and_stale_result(monkeypatch):
    threads = []
    now = int(time.time())

    class DeferredThread:
        def __init__(self, *, target, args=(), name=None, daemon=None):
            self.target = target
            self.args = args
            threads.append(self)

        def start(self):
            return None

    class FakeClient:
        def __init__(self):
            self.get_calls = 0

        def rpc(self, method, module, data=None):
            assert module == "nat_detector"
            if method == "devSta.set":
                return {"status": "completed", "nat_type": "Stale NAT", "timestamp": now - 10}
            assert method == "devSta.get"
            self.get_calls += 1
            return {
                "status": "completed",
                "nat_type": "Current NAT",
                "detected_interface": "wan1",
                "timestamp": now,
                "log": f"[2026-11-25 10:00:00] Interface: WAN1\nSource IP: 192.0.2.30\n",
            }

    client = FakeClient()
    logger = SimpleNamespace(debug=lambda *args, **kwargs: None, warning=lambda *args, **kwargs: None)

    def fake_factory(check_app_token, factory_logger, config_dir):
        bp = Blueprint("native_nat_test", __name__)
        v099.ReliableRuijieRouterClient()

        @bp.errorhandler(RouterRpcError)
        def handle_error(error):
            return jsonify({"ok": False, "error": error.code, "message": str(error)}), error.http_status

        return bp

    monkeypatch.setattr(native_patch.threading, "Thread", DeferredThread)
    monkeypatch.setattr(native_patch, "NAT_POLL_SECONDS", 0)
    monkeypatch.setattr(v099, "ReliableRuijieRouterClient", lambda *args, **kwargs: client)
    monkeypatch.setattr(v099, "create_router_blueprint_v099", fake_factory)
    monkeypatch.setattr(v099, "_labprobe_native_features_patch", False, raising=False)
    native_patch.install_router_native_features_patch()
    app = Flask(__name__)
    app.register_blueprint(v099.create_router_blueprint_v099(lambda: True, logger, None))
    test_client = app.test_client()

    first = test_client.post("/nat-diagnostic", json={"interface": "wan1"})
    second = test_client.post("/nat-diagnostic", json={"interface": "wan"})

    assert first.status_code == 202
    first_data = first.get_json()
    assert first_data["taskId"]
    assert first_data["requestId"]
    assert first_data["requestedInterface"] == "wan1"
    assert second.status_code == 409
    assert second.get_json()["error"] == "NAT_DIAGNOSTIC_BUSY"
    assert first_data["taskId"] not in str(second.get_json())
    assert len(threads) == 1

    threads[0].target(*threads[0].args)
    result = test_client.get("/nat-diagnostic").get_json()["data"]

    assert result["status"] == "completed"
    assert result["nat_type"] == "Current NAT"
    assert result["taskId"] == first_data["taskId"]
    assert result["requestId"] == first_data["requestId"]
    assert result["requested_interface"] == "wan1"
    assert result["detected_interface"] == "wan1"
    assert result["source_ip"] == "192.0.2.30"
    assert client.get_calls == 1
