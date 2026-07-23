import pytest

from router_native_features_patch import _nat_result_with_request, normalize_nat_request
from router_rpc import RouterRpcError


def test_nat_request_defaults_match_reyee_capture():
    assert normalize_nat_request({}) == {
        "host": "stun.hot-chilli.net",
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


def test_nat_result_keeps_requested_port_for_app_history():
    result = _nat_result_with_request(
        {"status": "completed", "nat_type": "port-restricted cone"},
        {"host": "stun.example.com", "port": 5478, "interface": "wan", "mode": "5780"},
    )

    assert result["requested_port"] == 5478
    assert result["requested_host"] == "stun.example.com"
    assert result["requested_mode"] == "5780"
    assert result["nat_type"] == "port-restricted cone"


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
