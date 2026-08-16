from router_be72_sid_wire_patch import _eweb_byte_length, _headers_for_api
from router_rpc import RouterSession, _wire_json


def _session() -> RouterSession:
    return RouterSession(
        sid="452f51eb9e5d0f7a930250310a53db2b",
        auth_token="unused-token",
        serial_number="G1TD8RX039025",
    )


def test_cmd_headers_match_browser_capture():
    payload = {
        "method": "devSta.get",
        "params": {
            "module": "develop_mode",
            "noParse": False,
            "async": None,
            "remoteIp": False,
            "device": "pc",
        },
    }
    wire = _wire_json(payload)

    assert _eweb_byte_length(wire) == 118
    headers = _headers_for_api("cmd", wire, _session())

    assert headers["Content-Accept"] == "81463bc2f8d88672754c14a1ffeb3329"
    assert headers["Contents-Accept"] == "7e755ba156d2381e9b6f9b24d2a3dafd"
    assert headers["Cookie"] == "G1TD8RX039025=452f51eb9e5d0f7a930250310a53db2b"
    assert headers["Content-Type"] == "application/json;charset=UTF-8"


def test_plain_overview_does_not_get_cmd_signatures():
    wire = _wire_json({"method": "getDeviceInfo", "params": None})
    headers = _headers_for_api("overview", wire, _session())

    assert "Content-Accept" not in headers
    assert "Contents-Accept" not in headers
    assert headers["Cookie"].startswith("G1TD8RX039025=")
