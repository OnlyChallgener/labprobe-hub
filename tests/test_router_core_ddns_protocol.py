"""Router Core 原生 DDNS 新旧固件协议回归。

BE72Pro 2026-11-24 实测：dev_sta get -m ddns_view 返回 3 条 entries，
而 dev_sta get -m ddnsCfg 为空 —— 这正是 APP 显示 0 条的根因。
"""

import json
from types import SimpleNamespace

from router_core.driver.reyee import ReyeeEWebDriver


BE72_ENTRIES = [
    {"provider": "aliyun.com", "domain": "rj.lab86.shinya.icu", "zone": "shinya.icu",
     "interface": "wan", "record_type": "A", "username": "LTAI5t8cJde2sDPDC7NjRvei",
     "enabled": True, "id": "uX0abxr32S", "rcode": "0", "credential_set": True},
    {"provider": "aliyun.com", "domain": "op.lab86.shinya.icu", "zone": "shinya.icu",
     "interface": "wan", "record_type": "AAAA", "username": "LTAI5t8cJde2sDPDC7NjRvei",
     "enabled": True, "id": "fzSi9uAlyR", "rcode": "0", "credential_set": True},
    {"provider": "aliyun.com", "domain": "t.lab86.shinya.icu", "zone": "shinya.icu",
     "interface": "wan", "record_type": "TXT", "username": "LTAI5t8cJde2sDPDC7NjRvei",
     "txt_template": "{{ip}}:{{port}}", "txt_family": "ipv4", "external_port": 6500,
     "enabled": True, "id": "ddns_6affba6f_4", "rcode": "0", "credential_set": True},
]


class FakeRpc:
    def __init__(self, view):
        self.view = view
        self.calls = []
        self.entries = [dict(e) for e in BE72_ENTRIES] if view else []

    def rpc(self, method, module="", data=None, **kwargs):
        self.calls.append((method, module, data))
        if method == "devSta.get" and module == "ddns_view":
            if not self.view:
                return {"rcode": "03510001", "rmsg": "module unavailable"}
            return {"entries": [dict(e) for e in self.entries], "settings": {"interval": 300}}
        if method == "devSta.get" and module == "ddns":
            return {"entries": [dict(e) for e in self.entries]}
        if method == "devSta.get" and module == "ddnsCfg":
            return {"list": []} if self.view else {"list": [dict(e) for e in self.entries]}
        if method == "devSta.set" and module == "ddns":
            self.entries = [dict(e) for e in (data or {}).get("entries", [])]
            return {"rcode": "0"}
        return {"rcode": "0"}


def driver(rpc):
    def get_or_fetch(key, loader, ttl=0, force=False):
        return loader()
    cache = SimpleNamespace(get_or_fetch=get_or_fetch, invalidate=lambda *a, **k: None)
    return ReyeeEWebDriver(rpc_client=rpc, cache=cache)


def test_be72pro_ddns_view_returns_all_three_records():
    rpc = FakeRpc(view=True)
    result = driver(rpc).get_ddns(force=True)
    rows = result["list"]
    assert len(rows) == 3
    assert result["nativeProtocol"] == "ddns_view"
    assert [r["id"] for r in rows] == [e["id"] for e in BE72_ENTRIES]
    assert [r["record_type"] for r in rows] == ["A", "AAAA", "TXT"]
    assert all(r["enabled"] is True for r in rows)
    assert all(r["provider"] == "aliyun.com" for r in rows)
    assert all(r["password"] == "" for r in rows)
    assert rows[0]["passwordConfigured"] is True
    assert result["settings"]["interval"] == 300
    # 查询全程不能再去读老 ddnsCfg。
    assert not any(m == "devSta.get" and mod == "ddnsCfg" for m, mod, _ in rpc.calls)


def test_legacy_firmware_still_uses_ddnscfg():
    rpc = FakeRpc(view=False)
    result = driver(rpc).get_ddns(force=True)
    assert result["nativeProtocol"] == "ddnsCfg"
    assert any(m == "devSta.get" and mod == "ddnsCfg" for m, mod, _ in rpc.calls)


def test_ddns_view_write_uses_devsta_set_not_legacy_add():
    rpc = FakeRpc(view=True)
    d = driver(rpc)
    d.add_ddns({"provider": "dnspod.cn", "domain": "new.example.com", "record_type": "A"}, "secret")
    assert any(m == "devSta.set" and mod == "ddns" for m, mod, _ in rpc.calls)
    assert not any(m == "devSta.add" and mod == "ddnsCfg" for m, mod, _ in rpc.calls)
    rows = d.get_ddns(force=True)["list"]
    assert len(rows) == 4
    added = next(r for r in rows if r["domain"] == "new.example.com")
    assert added["provider"] == "dnspod.cn"
    assert added["passwordConfigured"] is True
    assert added["password"] == ""
