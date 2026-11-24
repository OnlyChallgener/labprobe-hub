import threading
import time

import router_rpc
import router_slow_cache_patch as slow_cache
from router_compat import RouterRpcCompatibilitySync, _device_rate_bps, _device_rate_bytes


class _Logger:
    def debug(self, *args, **kwargs):
        pass


class _Client:
    def __init__(self):
        self.cache = router_rpc.TinyTtlCache()
        self.logger = _Logger()
        self.scope = "router-a"

    def _session_cache_key(self):
        return self.scope


def _cached(client, key, loader, force=False):
    slow_cache.install_router_slow_cache_patch()
    return router_rpc.RuijieRouterClient.cached(client, key, 1, loader, force)


def _age(cache, key, seconds):
    with cache._lock:
        saved_at, value = cache._data[key]
        cache._data[key] = (saved_at - seconds, value)


def test_slow_cache_returns_stale_immediately_and_refreshes_once():
    client = _Client()
    client.cache.put("ddns", {"value": "old"})
    _age(client.cache, "ddns", 120)
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def loader():
        calls.append(1)
        entered.set()
        release.wait(1)
        return {"value": "new"}

    started = time.monotonic()
    first = _cached(client, "ddns", loader)
    second = _cached(client, "ddns", loader)
    assert time.monotonic() - started < 0.2
    assert first == {"value": "old"}
    assert second == {"value": "old"}
    assert entered.wait(1)
    assert len(calls) == 1

    release.set()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        row = client.cache.get("ddns", 60)
        if row == {"value": "new"}:
            break
        time.sleep(0.01)
    assert client.cache.get("ddns", 60) == {"value": "new"}


def test_failed_background_refresh_keeps_last_successful_value():
    client = _Client()
    client.cache.put("firewall", {"rules": [1]})
    _age(client.cache, "firewall", 120)
    attempted = threading.Event()

    def loader():
        attempted.set()
        raise RuntimeError("temporary router failure")

    assert _cached(client, "firewall", loader) == {"rules": [1]}
    assert attempted.wait(1)
    time.sleep(0.03)
    with client.cache._lock:
        assert client.cache._data["firewall"][1] == {"rules": [1]}


class _DeviceClient(_Client):
    def __init__(self, rows=None):
        super().__init__()
        self.rows = rows if rows is not None else [
            {"mac": "AA:BB:CC:DD:EE:01", "flowUp": 2680, "flowDown": 12000, "flow_cnt": 3}
        ]

    def rpc(self, method, module, data=None, **kwargs):
        return {"list": [dict(row) for row in self.rows]}

    def cached(self, key, ttl, loader, force=False):
        return router_rpc.RuijieRouterClient.cached(self, key, ttl, loader, force)


def test_router_rpc_device_rates_keep_bps_and_convert_bytes_once():
    client = _DeviceClient()

    payload = router_rpc.RuijieRouterClient.devices(client, force=True)
    row = payload["items"][0]

    assert row["uploadBps"] == 2680
    assert row["downloadBps"] == 12000
    assert row["realtimeUpBytes"] == 335
    assert row["realtimeDownBytes"] == 1500


def test_router_compat_byte_rate_fallback_converts_raw_bits_once():
    assert _device_rate_bytes({"flowUp": 2680}, "realtimeUpBytes", "uploadBps", "flowUp") == 335
    assert _device_rate_bytes({"flowDown": 12000}, "realtimeDownBytes", "downloadBps", "flowDown") == 1500
    assert _device_rate_bytes({"flowUp": 2680, "realtimeUpBytes": 335}, "realtimeUpBytes", "uploadBps", "flowUp") == 335
    assert _device_rate_bps({"uploadBps": 2680, "realtimeUpBytes": 999}, "realtimeUpBytes", "uploadBps", "flowUp") == 2680
    assert _device_rate_bytes({}, "realtimeUpBytes", "uploadBps", "flowUp") is None


def test_router_rpc_device_rates_omit_unknown_fields():
    client = _DeviceClient([{"mac": "AA:BB:CC:DD:EE:01"}])

    row = router_rpc.RuijieRouterClient.devices(client, force=True)["items"][0]

    assert "uploadBps" not in row
    assert "downloadBps" not in row
    assert "realtimeUpBytes" not in row
    assert "realtimeDownBytes" not in row
    assert "connectionCount" not in row


def test_router_compat_snapshot_marks_byte_contract_and_prefers_bps():
    state = {}

    class Client:
        def devices(self, force=False):
            return {"items": [{
                "mac": "AA:BB:CC:DD:EE:01",
                "uploadBps": 2680,
                "downloadBps": 12000,
                "realtimeUpBytes": 999,
                "realtimeDownBytes": 999,
            }]}

    hub = type("Hub", (), {})()
    hub.LOGGER = _Logger()
    hub.DATA_LOCK = threading.RLock()
    hub.DEVICES_FILE = "devices.json"
    hub.STATE_FILE = "state.json"
    hub.norm_mac = lambda value: str(value or "").strip().lower()
    hub.parse_ruijie_devices = lambda payload: ([dict(row) for row in payload["list"]], len(payload["list"]))
    hub.load_device_archive = lambda: {}
    hub.hydrate_device_with_archive = lambda device, archive: dict(device)
    hub.archive_device_snapshot = lambda device: None
    hub.attach_hub_local_ipv6_to_nas_devices = lambda rows: rows
    hub.build_watched_devices = lambda rows: rows
    hub.now_str = lambda: "2026-11-24 12:00:00"
    hub.save_json = lambda path, value: state.__setitem__(path, value)
    hub.load_json = lambda path, default: dict(state.get(path, default))
    sync = RouterRpcCompatibilitySync(hub, Client())

    document = sync.sync_devices(force=True)
    row = document["online"][0]

    assert row["uploadBps"] == 2680
    assert row["realtimeUpload"] == 335
    assert row["realtimeRateUnit"] == "bytes/s"
    assert document["realtimeRateContractVersion"] == 2


def test_force_refresh_is_synchronous_and_router_scope_change_clears_old_values():
    client = _Client()
    client.cache.put("upnp", {"enabled": False})
    assert _cached(client, "upnp", lambda: {"enabled": True}, force=True) == {"enabled": True}
    assert client.cache.get("upnp", 60) == {"enabled": True}

    client.scope = "router-b"
    assert _cached(client, "ddns", lambda: {"router": "b"}) == {"router": "b"}
    assert client.cache.get("upnp", 60) is None
