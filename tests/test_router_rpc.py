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


def test_dynamic_login_key_is_extracted_from_eweb_html():
    key = "bfe55be6c57a416b2c8b27c535871a76"
    html = f'<script>GibberishAES.enc(passwordEl.value, "{key}")</script>'
    assert StableRuijieRouterClient._extract_login_key(html) == key


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
    client.session = RouterSession(
        sid="sid-123",
        auth_token="token-123",
        obtained_at=time.time(),
        session_seconds=3600,
    )

    client._set_session_time(7200)

    assert client.session.sid == "sid-123"
    assert client.session.session_seconds == 7200
    assert client.session.valid_locally


def test_reyee_sid_and_login_cookies_are_sent_to_rpc(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    client = StableRuijieRouterClient(EncryptedRouterConfigStore(tmp_path), _Logger())
    client.http.cookies.set("SN", "G1TD8RX039025", path="/")
    client.http.cookies.set(
        "G1TD8RX039025",
        "cdb9f2a4c034f59d01b6990c977a59f1",
        path="/",
    )
    prepared = client.http.prepare_request(
        requests.Request(
            "POST",
            "http://192.168.5.1/cgi-bin/luci/api/cmd?auth=cdb9f2a4c034f59d01b6990c977a59f1",
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
        first.http.cookies.set("SN", "G1TD8RX039025", path="/")
        first.http.cookies.set("G1TD8RX039025", "sid-shared", path="/")
        first.session = RouterSession(
            sid="sid-shared",
            auth_token="token-shared",
            serial_number="G1TD8RX039025",
            obtained_at=time.time(),
            session_seconds=3600,
        )

        second = StableRuijieRouterClient(store, _Logger())
        monkeypatch.setattr(
            second.http,
            "post",
            lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected login")),
        )
        monkeypatch.setattr(
            second.http,
            "get",
            lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected login page fetch")),
        )
        restored = second.login()

        assert first.login_lock is second.login_lock
        assert restored.sid == "sid-shared"
        assert restored.auth_token == "token-shared"
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
        return response(
            {
                "code": 0,
                "data": {
                    "sid": "sid-once",
                    "token": "token-once",
                    "sn": "G1TD8RX039025",
                    "sessiontime": 3600,
                },
            },
            url,
        )

    def fake_get(url, *args, **kwargs):
        result = requests.Response()
        result.status_code = 200
        result.url = url
        result._content = (
            b'<script>GibberishAES.enc(passwordEl.value, '
            b'"bfe55be6c57a416b2c8b27c535871a76")</script>'
        )
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


def test_eweb_apis_use_sid_query_and_cached_cookie(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "test-app-token")
    store = EncryptedRouterConfigStore(tmp_path)
    store.save("192.168.5.1", "router-password", 3600)
    GLOBAL_ROUTER_SESSION_CACHE.clear()
    client = StableRuijieRouterClient(store, _Logger())
    client.http.cookies.set("SN", "G1TD8RX039025", path="/")
    client.http.cookies.set("G1TD8RX039025", "sid-cookie", path="/")
    client.session = RouterSession(
        sid="sid-cookie",
        auth_token="token-must-not-be-used-as-auth",
        serial_number="G1TD8RX039025",
        obtained_at=time.time(),
        session_seconds=3600,
    )
    requested_urls = []
    requested_cookies = []

    def fake_post(url, *args, **kwargs):
        requested_urls.append(url)
        prepared = client.http.prepare_request(requests.Request("POST", url))
        requested_cookies.append(prepared.headers.get("Cookie", ""))
        response = requests.Response()
        response.status_code = 200
        response.url = url
        response._content = b'{"code": 0, "data": {}}'
        return response

    monkeypatch.setattr(client.http, "post", fake_post)
    try:
        client.rpc("acConfig.get", "network_group", no_parse=True)
        client._post_api("common", {"method": "getSessiontime"})
        client._post_api("system", {"method": "get"})
        assert requested_urls == [
            "http://192.168.5.1/cgi-bin/luci/api/cmd?auth=sid-cookie",
            "http://192.168.5.1/cgi-bin/luci/api/common?auth=sid-cookie",
            "http://192.168.5.1/cgi-bin/luci/api/system?auth=sid-cookie",
        ]
        assert all("G1TD8RX039025=sid-cookie" in cookie for cookie in requested_cookies)
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
    monkeypatch.setattr(
        client.http,
        "post",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected login")),
    )
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
    session = RouterSession(
        sid="sid-123",
        auth_token="token-123",
        obtained_at=time.time() - 3200,
        session_seconds=3600,
    )
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

    response = app.test_client().get(
        "/api/router/status",
        headers={"Authorization": "Bearer test-app-token"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["state"] == "no_router_data"
    assert payload["errorCode"] == "HUB_NO_ROUTER_DATA"
    assert "password" not in payload
    assert "address" not in payload
    assert "sessionActive" not in payload
    assert "sessionRemainingSeconds" not in payload
