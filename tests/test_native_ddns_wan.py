from types import SimpleNamespace

import pytest

from router_core.driver.reyee import ReyeeEWebDriver
from router_core.errors import RouterValidationError


class FakeRpc:
    def __init__(self, modern=True):
        self.modern = modern
        self.entries = [
            {"id": "a", "provider": "aliyun.com", "domain": "a.example.com", "interface": "wan", "record_type": "A", "enabled": True},
            {"id": "aaaa", "provider": "aliyun.com", "domain": "aaaa.example.com", "interface": "wan1", "record_type": "AAAA", "enabled": True},
        ]
        self.legacy = [
            {"service": "a", "service_name": "aliyun.com", "domain": "a.example.com", "interface": "wan", "use_ipv6": "0", "enabled": "1"},
            {"service": "aaaa", "service_name": "aliyun.com", "domain": "aaaa.example.com", "interface": "wan1", "use_ipv6": "1", "enabled": "1"},
        ]
        self.calls = []

    def rpc(self, method, module="", data=None, **kwargs):
        self.calls.append((method, module, data))
        if method == "devSta.get" and module == "ddns_view":
            return {"entries": [dict(row) for row in self.entries], "settings": {}} if self.modern else {"rcode": "03510001"}
        if method == "devSta.get" and module == "ddnsCfg":
            return {"list": [dict(row) for row in self.legacy]}
        if method == "devSta.set" and module == "ddns":
            self.entries = [dict(row) for row in data["entries"]]
            for index, row in enumerate(self.entries):
                row.setdefault("id", f"generated-{index}")
            return {"rcode": "0"}
        if method == "devSta.add" and module == "ddnsCfg":
            row = dict(data)
            row.setdefault("service", f"generated-{len(self.legacy)}")
            self.legacy.append(row)
            return {"rcode": "0"}
        if method == "devSta.update" and module == "ddnsCfg":
            target = data["data"][0]
            self.legacy = [target if row.get("service") == target.get("service") else row for row in self.legacy]
            return {"rcode": "0"}
        return {"rcode": "0"}


def driver(rpc):
    cache = SimpleNamespace(get_or_fetch=lambda key, loader, ttl=0, force=False: loader(), invalidate=lambda *a, **k: None)
    return ReyeeEWebDriver(rpc_client=rpc, cache=cache)


def test_ddns_reads_expose_wan_id_for_both_protocols():
    for modern in (True, False):
        rows = driver(FakeRpc(modern)).get_ddns(force=True)["list"]
        assert [row["wanId"] for row in rows] == ["wan", "wan1"]
        assert [row["interface"] for row in rows] == ["wan", "wan1"]


def test_modern_ddns_add_maps_wan_id_to_interface():
    rpc = FakeRpc(True)
    driver(rpc).add_ddns({
        "provider": "aliyun.com", "domain": "new.example.com", "record_type": "A",
        "wanId": "wan1", "username": "ak",
    }, "secret")
    payload = next(data for method, module, data in rpc.calls if method == "devSta.set")["entries"][-1]
    assert payload["interface"] == "wan1"
    assert "wanId" not in payload


def test_legacy_ddns_add_maps_wan_id_to_interface():
    rpc = FakeRpc(False)
    driver(rpc).add_ddns({
        "service_name": "aliyun.com", "domain": "new.example.com", "use_ipv6": "1",
        "wanId": "wan1", "username": "ak",
    }, "secret")
    payload = next(data for method, module, data in rpc.calls if method == "devSta.add")
    assert payload["interface"] == "wan1"
    assert "wanId" not in payload


def test_ddns_rejects_unknown_wan_before_write():
    rpc = FakeRpc(True)
    with pytest.raises(RouterValidationError) as raised:
        driver(rpc).add_ddns({"provider": "aliyun.com", "domain": "bad.example.com", "wanId": "wan2"}, "secret")
    assert raised.value.code == "DDNS_WAN_UNSUPPORTED"
    assert not rpc.calls
