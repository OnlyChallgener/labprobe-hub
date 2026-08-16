import pytest

from router_native_features_patch import (
    _nat_error_message,
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
