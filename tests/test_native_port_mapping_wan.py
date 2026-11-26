from types import SimpleNamespace

import pytest

from router_core.driver.reyee import ReyeeEWebDriver
from router_core.errors import RouterValidationError


class FakeRpc:
    def __init__(self):
        self.rows = [
            {"ruleName": "all", "src": "", "srcPort": "80", "destPort": "8080"},
            {"ruleName": "wan1", "src": "wan1", "srcPort": "81", "destPort": "8081"},
        ]
        self.calls = []

    def rpc(self, method, module="", data=None, **kwargs):
        self.calls.append((method, module, data))
        if method == "devConfig.get":
            return {"portMapping": [dict(row) for row in self.rows]}
        if method == "devConfig.add":
            self.rows.extend(dict(row) for row in data["list"])
            return {"rcode": "0"}
        if method == "devConfig.update":
            old, new = data["old"], data["new"]
            self.rows = [new if row.get("ruleName") == old.get("ruleName") else row for row in self.rows]
            return {"rcode": "0"}
        return {"rcode": "0"}


def driver(rpc):
    cache = SimpleNamespace(get_or_fetch=lambda key, loader, ttl=0, force=False: loader(), invalidate=lambda *a, **k: None)
    return ReyeeEWebDriver(rpc_client=rpc, cache=cache)


def test_port_mapping_reads_expose_wan_identity_without_changing_src():
    result = driver(FakeRpc()).get_port_mappings(force=True)
    assert [row["wanId"] for row in result["portMapping"]] == ["all", "wan1"]
    assert [row["src"] for row in result["portMapping"]] == ["", "wan1"]


def test_port_mapping_add_maps_wan_id_to_firmware_src():
    rpc = FakeRpc()
    driver(rpc).add_port_mapping({
        "ruleName": "new", "wanId": "all", "srcPort": "82", "destPort": "8082",
        "destIp": "192.168.5.2", "proto": "tcp",
    })
    payload = next(data for method, module, data in rpc.calls if method == "devConfig.add")["list"][0]
    assert payload["src"] == ""
    assert "wanId" not in payload
    assert rpc.rows[-1]["src"] == ""


def test_port_mapping_rejects_unknown_wan_before_write():
    rpc = FakeRpc()
    with pytest.raises(RouterValidationError) as raised:
        driver(rpc).add_port_mapping({"ruleName": "bad", "wanId": "wan2"})
    assert raised.value.code == "PORT_MAPPING_WAN_UNSUPPORTED"
    assert not rpc.calls


def test_port_mapping_update_keeps_global_name_and_old_new_contract():
    rpc = FakeRpc()
    driver(rpc).update_port_mapping("wan1", {
        "ruleName": "wan1", "wanId": "wan", "srcPort": "83", "destPort": "8083",
        "destIp": "192.168.5.3", "proto": "tcp",
    })
    method, module, data = next(call for call in rpc.calls if call[0] == "devConfig.update")
    assert (method, module) == ("devConfig.update", "port_mapping")
    assert data["old"]["ruleName"] == "wan1"
    assert "wanId" not in data["old"]
    assert data["new"]["src"] == "wan"
    assert "wanId" not in data["new"]
