import threading
import time

import router_rpc
import router_slow_cache_patch as slow_cache


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


def test_force_refresh_is_synchronous_and_router_scope_change_clears_old_values():
    client = _Client()
    client.cache.put("upnp", {"enabled": False})
    assert _cached(client, "upnp", lambda: {"enabled": True}, force=True) == {"enabled": True}
    assert client.cache.get("upnp", 60) == {"enabled": True}

    client.scope = "router-b"
    assert _cached(client, "ddns", lambda: {"router": "b"}) == {"router": "b"}
    assert client.cache.get("upnp", 60) is None
