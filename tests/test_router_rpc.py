import base64
from pathlib import Path

from router_rpc import EncryptedRouterConfigStore, TinyTtlCache, gibberish_aes_encrypt


def test_gibberish_aes_envelope():
    raw = base64.b64decode(gibberish_aes_encrypt("secret"))
    assert raw.startswith(b"Salted__")
    assert len(raw) > 24


def test_router_config_password_is_encrypted(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    store = EncryptedRouterConfigStore(tmp_path)
    saved = store.save("192.168.5.1", "router-password", 3600)
    assert saved["address"] == "http://192.168.5.1"
    assert saved["password"] == "router-password"
    text = (tmp_path / "router_eweb.json").read_text("utf-8")
    assert "router-password" not in text


def test_session_range_is_clamped(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    store = EncryptedRouterConfigStore(tmp_path)
    assert store.save("192.168.5.1", "pw", 20)["sessionSeconds"] == 600
    assert store.save("192.168.5.1", None, 99999)["sessionSeconds"] == 7200


def test_ttl_cache_clear_prefix():
    cache = TinyTtlCache()
    cache.put("firewall", {"ok": True})
    cache.put("upnp", {"ok": True})
    cache.clear("fire")
    assert cache.get("firewall", 60) is None
    assert cache.get("upnp", 60) == {"ok": True}
