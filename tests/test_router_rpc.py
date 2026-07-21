import base64
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests
from flask import Flask, request

from router_rpc import (
    GLOBAL_ROUTER_SESSION_CACHE,
    EncryptedRouterConfigStore,
    RouterAuthExpired,
    RouterSession,
    TinyTtlCache,
    gibberish_aes_encrypt,
)
from router_rpc_v010 import StableRuijieRouterClient, create_router_blueprint_v010


def _eweb_login_html() -> str:
    wrapped_key = gibberish_aes_encrypt("dynamic-page-key", "eweb")
    return f"var k = GibberishAES.dec('{wrapped_key}', 'eweb')"


class _Logger:
    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


def test_gibberish_aes_envelope():
    raw = base64.b64decode(gibberish_aes_encrypt("secret", "page-key"))
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
    client.session = RouterSession(sid="sid-123", eweb_token="token-123", obtained_at=time.time(), session_seconds=3600)

    client._set_session_time(7200)

    assert client.session.sid == "sid-123"
    assert client.session.session_seconds == 7200
    assert client.session.valid_locally


def test_reyee_browser_session_cookies_are_sent_to_rpc(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    client = StableRuijieRouterClient(EncryptedRouterConfigStore(tmp_path), _Logger())
    session = RouterSession(
        sid="cdb9f2a4c034f59d01b6990c977a59f1",
        eweb_token="token-value",
        serial_number="G1TD8RX039025",
        obtained_at=time.time(),
        session_seconds=3600,
    )

    client._install_browser_session_cookies(session)
    prepared = client.http.prepare_request(
        requests.Request(
            "POST",
            "http://192.168.5.1/cgi-bin/luci/;stok=token-value/api/cmd",
        )
    )
    cookie = prepared.headers.get("Cookie", "")

    assert "SN=G1TD8RX039025" in cookie
    assert "G1TD8RX039025=cdb9f2a4c034f59d01b6990c977a59f1" in cookie


def test_global_session_and_cookies_are_reused_across_clients(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    store = EncryptedRouterConfigStore(tmp_path)
    store.save("192.168.5.1", "router-password", 3600)
    GLOBAL_ROUTER_SESSION_CACHE.clear()
    try:
        first = StableRuijieRouterClient(store, _Logger())
        first.http.cookies.set("router-cookie", "cookie-value", path="/cgi-bin/luci")
        first.session = RouterSession(
            sid="sid-shared",
            eweb_token="token-shared",
            serial_number="G1TD8RX039025",
            obtained_at=time.time(),
            session_seconds=3600,
        )

        second = StableRuijieRouterClient(store, _Logger())
        monkeypatch.setattr(second.http, "post", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected login")))
        restored = second.login()

        assert first.login_lock is second.login_lock
        assert restored.sid == "sid-shared"
        assert restored.eweb_token == "token-shared"
        cookies = {cookie.name: cookie.value for cookie in second.http.cookies}
        assert cookies["router-cookie"] == "cookie-value"
        assert cookies["SN"] == "G1TD8RX039025"
        assert cookies["G1TD8RX039025"] == "sid-shared"
    finally:
        GLOBAL_ROUTER_SESSION_CACHE.clear()


def test_concurrent_callers_perform_one_real_login(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    store = EncryptedRouterConfigStore(tmp_path)
    store.save("192.168.5.1", "router-password", 3600)
    GLOBAL_ROUTER_SESSION_CACHE.clear()
    login_count = 0
    count_lock = threading.Lock()

    class CountingLogger(_Logger):
        def __init__(self):
            self.login_messages = []

        def info(self, message, *args, **kwargs):
            if message.startswith("router eweb login ok"):
                self.login_messages.append(message)

    logger = CountingLogger()
    clients = [StableRuijieRouterClient(store, logger) for _ in range(2)]

    def response(payload, url):
        result = requests.Response()
        result.status_code = 200
        result.url = url
        result.headers["Content-Type"] = "application/json"
        result._content = json.dumps(payload).encode("utf-8")
        return result

    def fake_post(url, *args, **kwargs):
        nonlocal login_count
        with count_lock:
            login_count += 1
        return response({
            "code": 0,
            "data": {
                "sid": "sid-once",
                "token": "token-once",
                "sn": "G1TD8RX039025",
                "sessiontime": 3600,
            }
        }, url)

    def fake_get(url, *args, **kwargs):
        result = response({}, url)
        result._content = _eweb_login_html().encode("utf-8")
        return result

    for client in clients:
        monkeypatch.setattr(client.http, "post", fake_post)
        monkeypatch.setattr(client.http, "get", fake_get)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            sessions = list(executor.map(lambda client: client.login(), clients))
        assert login_count == 1
        assert len(logger.login_messages) == 1
        assert sessions[0] is sessions[1]
        assert sessions[0].sid == "sid-once"
    finally:
        GLOBAL_ROUTER_SESSION_CACHE.clear()


def test_login_once_then_reuses_eweb_token_for_repeated_devsta_get(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    store = EncryptedRouterConfigStore(tmp_path)
    store.save("192.168.5.1", "router-password", 3600)
    GLOBAL_ROUTER_SESSION_CACHE.clear()
    login_urls = []
    entry_urls = []
    cmd_urls = []

    class CountingLogger(_Logger):
        def __init__(self):
            self.login_messages = []

        def info(self, message, *args, **kwargs):
            if message.startswith("router eweb login ok"):
                self.login_messages.append(message % args)

    logger = CountingLogger()
    client = StableRuijieRouterClient(store, logger)

    def response(payload, url):
        result = requests.Response()
        result.status_code = 200
        result.url = url
        result.headers["Content-Type"] = "application/json"
        result._content = json.dumps(payload).encode("utf-8")
        return result

    def fake_post(url, *args, **kwargs):
        if url == "http://192.168.5.1/cgi-bin/luci/api/auth":
            login_urls.append(url)
            return response({
                "code": 0,
                "data": {
                    "sid": "sid-once",
                    "sn": "G1TD8RX039025",
                    "token": "token-once",
                    "sessiontime": 3600,
                }
            }, url)
        cmd_urls.append(url)
        return response({"data": {"list": []}}, url)

    def fake_get(url, *args, **kwargs):
        entry_urls.append(url)
        result = response({}, url)
        result._content = _eweb_login_html().encode("utf-8")
        return result

    monkeypatch.setattr(client.http, "post", fake_post)
    monkeypatch.setattr(client.http, "get", fake_get)
    try:
        for _ in range(3):
            client.rpc("devSta.get", "user_list", {"devType": "all"}, no_parse=True)
        assert login_urls == ["http://192.168.5.1/cgi-bin/luci/api/auth"]
        assert len(entry_urls) == 1
        assert entry_urls[0].startswith("http://192.168.5.1/cgi-bin/luci/?stamp=")
        assert cmd_urls == ["http://192.168.5.1/cgi-bin/luci/;stok=token-once/api/cmd"] * 3
        assert client.session.eweb_token == "token-once"
        assert len(logger.login_messages) == 1
        assert "token=True" in logger.login_messages[0]
    finally:
        GLOBAL_ROUTER_SESSION_CACHE.clear()

def test_cmd_403_relogs_once_and_saves_new_dynamic_eweb_token(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    store = EncryptedRouterConfigStore(tmp_path)
    store.save("192.168.5.1", "router-password", 3600)
    GLOBAL_ROUTER_SESSION_CACHE.clear()
    client = StableRuijieRouterClient(store, _Logger())
    client.session = RouterSession(
        sid="sid-cookie",
        eweb_token="token-old",
        serial_number="G1TD8RX039025",
        obtained_at=time.time(),
        session_seconds=3600,
    )
    client._install_browser_session_cookies(client.session)
    client._save_session_cookies()
    post_urls = []
    entry_urls = []

    def rpc_response(status, url, payload=None):
        result = requests.Response()
        result.status_code = status
        result.url = url
        result.headers["Content-Type"] = "application/json"
        result._content = json.dumps(payload or {"data": {}}).encode("utf-8")
        return result

    def fake_post(url, *args, **kwargs):
        post_urls.append(url)
        if url.endswith("/cgi-bin/luci/api/auth"):
            return rpc_response(200, url, {
                "code": 0,
                "data": {
                    "sid": "sid-new",
                    "token": "token-new",
                    "sn": "G1TD8RX039025",
                    "sessiontime": 3600,
                }
            })
        return rpc_response(403 if ";stok=token-old/" in url else 200, url)

    def fake_get(url, *args, **kwargs):
        entry_urls.append(url)
        result = rpc_response(200, url)
        result._content = _eweb_login_html().encode("utf-8")
        return result

    monkeypatch.setattr(client.http, "post", fake_post)
    monkeypatch.setattr(client.http, "get", fake_get)
    try:
        client.rpc("devSta.get", "user_list", {"devType": "all"}, no_parse=True)
        assert post_urls == [
            "http://192.168.5.1/cgi-bin/luci/;stok=token-old/api/cmd",
            "http://192.168.5.1/cgi-bin/luci/api/auth",
            "http://192.168.5.1/cgi-bin/luci/;stok=token-new/api/cmd",
        ]
        assert len(entry_urls) == 1
        assert entry_urls[0].startswith("http://192.168.5.1/cgi-bin/luci/?stamp=")
        assert client.session.eweb_token == "token-new"
        assert client.session.sid == "sid-new"
    finally:
        GLOBAL_ROUTER_SESSION_CACHE.clear()

def test_eweb_apis_use_login_token_path(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    store = EncryptedRouterConfigStore(tmp_path)
    store.save("192.168.5.1", "router-password", 3600)
    GLOBAL_ROUTER_SESSION_CACHE.clear()
    client = StableRuijieRouterClient(store, _Logger())
    client.session = RouterSession(
        sid="sid-cookie",
        eweb_token="token-value",
        serial_number="G1TD8RX039025",
        obtained_at=time.time(),
        session_seconds=3600,
    )
    client._install_browser_session_cookies(client.session)
    client._save_session_cookies()
    requested_urls = []

    def fake_post(url, *args, **kwargs):
        requested_urls.append(url)
        response = requests.Response()
        response.status_code = 200
        response.url = url
        response._content = b'{"data": {}}'
        return response

    monkeypatch.setattr(client.http, "post", fake_post)
    try:
        client.rpc("acConfig.get", "network_group", no_parse=True)
        client._post_api("common", {"method": "getSessiontime"})
        client._post_api("system", {"method": "get"})
        assert requested_urls == [
            "http://192.168.5.1/cgi-bin/luci/;stok=token-value/api/cmd",
            "http://192.168.5.1/cgi-bin/luci/;stok=token-value/api/common",
            "http://192.168.5.1/cgi-bin/luci/;stok=token-value/api/system",
        ]
    finally:
        GLOBAL_ROUTER_SESSION_CACHE.clear()


def test_repeated_403_backoff_suppresses_new_login(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    store = EncryptedRouterConfigStore(tmp_path)
    store.save("192.168.5.1", "router-password", 3600)
    client = StableRuijieRouterClient(store, _Logger())
    config_key = client._session_cache_key()
    GLOBAL_ROUTER_SESSION_CACHE.clear()
    GLOBAL_ROUTER_SESSION_CACHE.block_login(config_key, 60)
    monkeypatch.setattr(client.http, "post", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected login")))
    try:
        try:
            client.login()
        except RouterAuthExpired as exc:
            assert "retry paused" in str(exc)
        else:
            raise AssertionError("login backoff was not enforced")
    finally:
        GLOBAL_ROUTER_SESSION_CACHE.clear()


def test_session_refreshes_before_five_minutes_remain():
    session = RouterSession(eweb_token="token-123", obtained_at=time.time() - 3200, session_seconds=3600)
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