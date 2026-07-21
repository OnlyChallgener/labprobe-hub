import base64
import time
from pathlib import Path

import requests
from flask import Flask, request

from router_rpc import EncryptedRouterConfigStore, RouterSession, TinyTtlCache, gibberish_aes_encrypt
from router_rpc_v010 import StableRuijieRouterClient, create_router_blueprint_v010


class _Logger:
    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


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


def test_local_session_timeout_keeps_fresh_sid(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    client = StableRuijieRouterClient(EncryptedRouterConfigStore(tmp_path), _Logger())
    client.session = RouterSession(sid="sid-123", obtained_at=time.time(), session_seconds=3600)

    client._set_session_time(7200)

    assert client.session.sid == "sid-123"
    assert client.session.session_seconds == 7200
    assert client.session.valid_locally


def test_reyee_browser_session_cookies_are_sent_to_rpc(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    client = StableRuijieRouterClient(EncryptedRouterConfigStore(tmp_path), _Logger())
    session = RouterSession(
        sid="cdb9f2a4c034f59d01b6990c977a59f1",
        serial_number="G1TD8RX039025",
        obtained_at=time.time(),
        session_seconds=3600,
    )

    client._install_browser_session_cookies(session)
    prepared = client.http.prepare_request(
        requests.Request(
            "POST",
            "http://192.168.5.1/cgi-bin/luci//api/cmd?auth=cdb9f2a4c034f59d01b6990c977a59f1",
        )
    )
    cookie = prepared.headers.get("Cookie", "")

    assert "SN=G1TD8RX039025" in cookie
    assert "G1TD8RX039025=cdb9f2a4c034f59d01b6990c977a59f1" in cookie


def test_session_refreshes_before_five_minutes_remain():
    session = RouterSession(sid="sid-123", obtained_at=time.time() - 3200, session_seconds=3600)
    assert session.valid_locally

    session.obtained_at = time.time() - 3301
    assert not session.valid_locally


def test_hub_router_status_hides_eweb_credentials_and_session(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    app = Flask(__name__)
    app.register_blueprint(
        create_router_blueprint_v010(
            check_app_token=lambda: request.headers.get("Authorization") == "Bearer test-app-token",
            logger=_Logger(),
            config_dir=tmp_path,
        )
    )

    response = app.test_client().get("/api/router/status", headers={"Authorization": "Bearer test-app-token"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["state"] == "no_router_data"
    assert payload["errorCode"] == "HUB_NO_ROUTER_DATA"
    assert "password" not in payload
    assert "address" not in payload
    assert "sessionActive" not in payload
    assert "sessionRemainingSeconds" not in payload