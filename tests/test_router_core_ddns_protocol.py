"""Router Core 原生 DDNS 新旧固件协议回归。

BE72Pro 2026-11-24 实测：dev_sta get -m ddns_view 返回 3 条 entries，
而 dev_sta get -m ddnsCfg 为空 —— 这正是 APP 显示 0 条的根因。
"""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from router_core.driver.reyee import ReyeeEWebDriver
from router_core.errors import RouterRpcExecutionError, RouterUnreachableError, RouterValidationError
from router_rpc import RouterController, RouterRpcError, RuijieRouterClient, TinyTtlCache


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

_DEFAULT_VIEW_RESPONSE = object()


class FakeRpc:
    def __init__(self, view):
        self.view = view
        self.calls = []
        self.entries = [dict(e) for e in BE72_ENTRIES] if view else []
        self.settings = {"interval": 300}
        self.lock = threading.RLock()
        self.next_id = 1
        self.fail_view = False
        self.malformed_view = False
        self.missing_settings = False
        self.view_response = _DEFAULT_VIEW_RESPONSE

    def rpc(self, method, module="", data=None, **kwargs):
        with self.lock:
            self.calls.append((method, module, data))
            if method == "devSta.get" and module == "ddns_view":
                if self.view_response is not _DEFAULT_VIEW_RESPONSE:
                    return self.view_response
                if self.fail_view:
                    raise RouterUnreachableError("temporary network failure")
                if self.malformed_view:
                    return {"entries": {}}
                if not self.view:
                    return {"rcode": "03510001", "rmsg": "module unavailable"}
                response = {"entries": [dict(e) for e in self.entries]}
                if not self.missing_settings:
                    response["settings"] = dict(self.settings)
                return response
            if method == "devSta.get" and module == "ddns":
                return {"entries": [dict(e) for e in self.entries]}
            if method == "devSta.get" and module == "ddnsCfg":
                return {"list": []} if self.view else {"list": [dict(e) for e in self.entries]}
            if method == "devSta.set" and module == "ddns":
                entries = [dict(e) for e in (data or {}).get("entries", [])]
                for entry in entries:
                    if not entry.get("id"):
                        entry["id"] = f"generated-{self.next_id}"
                        self.next_id += 1
                self.entries = entries
                self.settings = dict((data or {}).get("settings") or self.settings)
                return {"rcode": "0"}
            return {"rcode": "0"}


class FakeLegacyClient:
    def __init__(self, rpc):
        self.rpc_client = rpc
        self.write_lock = threading.RLock()
        self.cache = TinyTtlCache()

    def rpc(self, method, module="", data=None, **kwargs):
        return self.rpc_client.rpc(method, module, data, **kwargs)

    def cached(self, key, ttl, loader, force=False):
        if not force:
            cached = self.cache.get(key, ttl)
            if cached is not None:
                return cached
        return self.cache.put(key, loader())

    def ddns(self, force=False):
        return RuijieRouterClient.ddns(self, force)


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


def test_force_refresh_reprobes_protocol_after_firmware_change():
    rpc = FakeRpc(view=True)
    d = driver(rpc)
    d._ddns_protocol_value = d._DDNS_PROTOCOL_CFG
    result = d.get_ddns(force=True)
    assert result["nativeProtocol"] == "ddns_view"
    assert len(result["list"]) == 3
    assert any(module == "ddns_view" for _, module, _ in rpc.calls)


def test_legacy_firmware_still_uses_ddnscfg():
    rpc = FakeRpc(view=False)
    result = driver(rpc).get_ddns(force=True)
    assert result["nativeProtocol"] == "ddnsCfg"
    assert any(m == "devSta.get" and mod == "ddnsCfg" for m, mod, _ in rpc.calls)


@pytest.mark.parametrize("response", [{}, []])
def test_legacy_empty_view_response_falls_back_to_ddnscfg(response):
    rpc = FakeRpc(view=False)
    rpc.view_response = response
    result = driver(rpc).get_ddns(force=True)
    assert result["nativeProtocol"] == "ddnsCfg"
    assert any(module == "ddnsCfg" for _, module, _ in rpc.calls)


def test_unexpected_view_error_never_falls_back_to_legacy_write():
    rpc = FakeRpc(view=True)
    rpc.view_response = {"rcode": "9999", "rmsg": "internal error"}
    with pytest.raises(RouterRpcExecutionError) as raised:
        driver(rpc).add_ddns({"provider": "aliyun.com", "domain": "new.example.com"}, "secret")
    assert raised.value.code == "DDNS_INVALID_RESPONSE"
    assert not any(module == "ddnsCfg" for _, module, _ in rpc.calls)
    assert not any(method == "devSta.set" for method, _, _ in rpc.calls)


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


def test_ddns_view_update_matches_only_id_and_preserves_other_data():
    rpc = FakeRpc(view=True)
    rpc.entries[0]["password"] = "original-secret"
    d = driver(rpc)
    target_id = rpc.entries[0]["id"]
    d.update_ddns(target_id, {"domain": "updated.example.com"}, None)
    writes = [data for method, module, data in rpc.calls if method == "devSta.set" and module == "ddns"]
    assert len(writes) == 1
    entries = writes[0]["entries"]
    assert entries[0]["id"] == target_id
    assert entries[0]["domain"] == "updated.example.com"
    assert entries[0]["password"] == "original-secret"
    assert entries[1:] == BE72_ENTRIES[1:]
    assert writes[0]["settings"] == {"interval": 300}


def test_ddns_view_delete_matches_only_id():
    rpc = FakeRpc(view=True)
    d = driver(rpc)
    target_id = rpc.entries[1]["id"]
    d.delete_ddns(target_id)
    assert [row["id"] for row in rpc.entries] == [BE72_ENTRIES[0]["id"], BE72_ENTRIES[2]["id"]]


@pytest.mark.parametrize("action", ["update", "delete"])
def test_ddns_view_missing_target_never_adds_or_writes(action):
    rpc = FakeRpc(view=True)
    d = driver(rpc)
    with pytest.raises(RouterValidationError) as raised:
        if action == "update":
            d.update_ddns("missing", {"domain": "must-not-be-added.example.com"}, "secret")
        else:
            d.delete_ddns("missing")
    assert raised.value.code == "DDNS_RECORD_NOT_FOUND"
    assert not any(method == "devSta.set" for method, _, _ in rpc.calls)
    assert rpc.entries == BE72_ENTRIES


def test_ddns_view_rejects_duplicate_ids_before_write():
    rpc = FakeRpc(view=True)
    rpc.entries[1]["id"] = rpc.entries[0]["id"]
    with pytest.raises(RouterRpcExecutionError) as raised:
        driver(rpc).add_ddns({"provider": "aliyun.com", "domain": "new.example.com"}, "secret")
    assert raised.value.code == "DDNS_INVALID_RESPONSE"
    assert not any(method == "devSta.set" for method, _, _ in rpc.calls)


def test_ddns_view_malformed_entries_never_fall_back_to_legacy_write():
    rpc = FakeRpc(view=True)
    rpc.malformed_view = True
    with pytest.raises(RouterRpcExecutionError) as raised:
        driver(rpc).add_ddns({"provider": "aliyun.com", "domain": "new.example.com"}, "secret")
    assert raised.value.code == "DDNS_INVALID_RESPONSE"
    assert not any(module == "ddnsCfg" for _, module, _ in rpc.calls)
    assert not any(method == "devSta.set" for method, _, _ in rpc.calls)


def test_ddns_view_network_failure_does_not_cache_legacy_protocol():
    rpc = FakeRpc(view=True)
    rpc.fail_view = True
    d = driver(rpc)
    with pytest.raises(RouterUnreachableError):
        d.add_ddns({"provider": "aliyun.com", "domain": "new.example.com"}, "secret")
    assert getattr(d, "_ddns_protocol_value", "") != "ddnsCfg"
    assert not any(module == "ddnsCfg" for _, module, _ in rpc.calls)
    assert not any(method == "devSta.set" for method, _, _ in rpc.calls)


def test_ddns_view_concurrent_adds_serialize_whole_read_modify_write():
    rpc = FakeRpc(view=True)
    d = driver(rpc)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(d.add_ddns, {"provider": "aliyun.com", "domain": f"new-{i}.example.com"}, "secret")
            for i in range(2)
        ]
        for future in futures:
            future.result(timeout=5)
    assert len(rpc.entries) == len(BE72_ENTRIES) + 2
    assert {row["domain"] for row in rpc.entries}.issuperset({"new-0.example.com", "new-1.example.com"})
    assert rpc.settings == {"interval": 300}


def test_router_rpc_ddns_update_preserves_settings_and_secret():
    rpc = FakeRpc(view=True)
    rpc.entries[0]["password"] = "original-secret"
    controller = RouterController(FakeLegacyClient(rpc))
    target_id = rpc.entries[0]["id"]
    controller.mutate_ddns("update", {"domain": "updated.example.com"}, "", target_id)
    write = next(data for method, module, data in rpc.calls if method == "devSta.set" and module == "ddns")
    assert write["settings"] == {"interval": 300}
    assert write["entries"][0]["password"] == "original-secret"
    assert write["entries"][1:] == BE72_ENTRIES[1:]


def test_router_rpc_ddns_missing_target_returns_error_without_write():
    rpc = FakeRpc(view=True)
    controller = RouterController(FakeLegacyClient(rpc))
    with pytest.raises(RouterRpcError) as raised:
        controller.mutate_ddns("delete", {}, "", "missing")
    assert raised.value.code == "DDNS_RECORD_NOT_FOUND"
    assert raised.value.http_status == 404
    assert not any(method == "devSta.set" for method, _, _ in rpc.calls)


def test_ddns_view_missing_settings_never_writes():
    rpc = FakeRpc(view=True)
    rpc.missing_settings = True
    with pytest.raises(RouterRpcExecutionError) as raised:
        driver(rpc).add_ddns({"provider": "aliyun.com", "domain": "new.example.com"}, "secret")
    assert raised.value.code == "DDNS_INVALID_RESPONSE"
    assert not any(method == "devSta.set" for method, _, _ in rpc.calls)


def test_router_rpc_ddns_missing_settings_never_writes():
    rpc = FakeRpc(view=True)
    rpc.missing_settings = True
    controller = RouterController(FakeLegacyClient(rpc))
    with pytest.raises(RouterRpcError) as raised:
        controller.mutate_ddns("add", {"provider": "aliyun.com", "domain": "new.example.com"}, "secret")
    assert raised.value.code == "DDNS_INVALID_RESPONSE"
    assert not any(method == "devSta.set" for method, _, _ in rpc.calls)


def test_router_rpc_ddns_response_reuses_single_verified_read():
    rpc = FakeRpc(view=True)
    controller = RouterController(FakeLegacyClient(rpc))
    response = controller.mutate_ddns_response("add", {"provider": "aliyun.com", "domain": "new.example.com"}, "secret")
    assert response["ok"] is True
    assert response["data"] is response["writeResult"]
    view_reads = sum(1 for method, module, _ in rpc.calls if method == "devSta.get" and module == "ddns_view")
    assert view_reads == 2


def test_router_rpc_ddns_malformed_view_never_writes_legacy():
    rpc = FakeRpc(view=True)
    rpc.malformed_view = True
    controller = RouterController(FakeLegacyClient(rpc))
    with pytest.raises(RouterRpcError) as raised:
        controller.mutate_ddns("add", {"provider": "aliyun.com", "domain": "new.example.com"}, "secret")
    assert raised.value.code == "DDNS_INVALID_RESPONSE"
    assert not any(module == "ddnsCfg" for _, module, _ in rpc.calls)
    assert not any(method == "devSta.set" for method, _, _ in rpc.calls)