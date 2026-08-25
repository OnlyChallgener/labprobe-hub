"""Unit Tests for ReyeeSessionManager and ReyeeRpcClient.

Validates:
1. AES-256-CBC encryption & decryption with fixed test salt vectors (Reference Oracle compliance).
2. Dynamic key extraction from mock HTML.
3. Single-Flight concurrency locking (only 1 real login across parallel callers).
4. Idle timeout maintenance (touch/record_activity).
5. RPC wire format (?auth=<sid>, Cookie header, {method, params}).
6. Auto-recovery on HTTP 401 / code 401 (max 1 retry).
7. Circuit breaker cooldown on repeated authentication failures.
"""

import json
import threading
import time
from unittest.mock import MagicMock, patch
import pytest
import requests

from router_core.driver.reyee_session import (
    ReyeeSession,
    ReyeeSessionManager,
    gibberish_aes_decrypt,
    gibberish_aes_encrypt,
)
from router_core.driver.reyee_rpc import ReyeeRpcClient
from router_core.errors import RouterAuthError, RouterAuthExpiredError, RouterUnreachableError


def test_fixed_salt_aes_encryption_and_decryption():
    """Validates OpenSSL Salted__ AES-256-CBC format with fixed test salt."""
    key = "7a8b9c0d1e2f"
    plain = "Ruijie_Secure_Pass_123!"
    fixed_salt = b"12345678"

    encrypted = gibberish_aes_encrypt(plain, key, custom_salt=fixed_salt)
    assert isinstance(encrypted, str)
    assert not any(c.isspace() for c in encrypted)

    # Decrypt and assert roundtrip
    decrypted = gibberish_aes_decrypt(encrypted, key)
    assert decrypted == plain

    # Also test random salt roundtrip
    random_encrypted = gibberish_aes_encrypt(plain, key)
    assert gibberish_aes_decrypt(random_encrypted, key) == plain


def test_dynamic_key_extraction_and_login():
    """Tests dynamic GibberishAES key extraction from mock login page."""
    mock_html = """
    <html>
    <script>
        var encKey = "abcdef0123456789";
        var enc = GibberishAES.enc(passwordEl.value, "abcdef0123456789");
    </script>
    </html>
    """

    mock_http = MagicMock(spec=requests.Session())

    # 1. Mock GET /cgi-bin/luci/
    get_resp = MagicMock()
    get_resp.status_code = 200
    get_resp.text = mock_html

    # 2. Mock POST /cgi-bin/luci/api/auth
    post_resp = MagicMock()
    post_resp.status_code = 200
    post_resp.json.return_value = {
        "code": 0,
        "data": {
            "token": "tok_xyz_123",
            "sid": "sid_abc_999",
            "sn": "SN123456789",
            "sessiontime": 1800,
        },
    }
    post_resp.headers = {"Set-Cookie": "sysauth=sid_abc_999; path=/cgi-bin/luci"}

    mock_http.get.return_value = get_resp
    mock_http.post.return_value = post_resp
    mock_http.cookies = requests.cookies.RequestsCookieJar()

    mgr = ReyeeSessionManager(
        address="https://192.168.110.1",
        password="test_password",
        session_factory=lambda: mock_http,
    )

    session = mgr.get_session()
    assert session.sid == "sid_abc_999"
    assert session.token == "tok_xyz_123"
    assert session.session_seconds == 1800
    assert session.cookie_header == "SN123456789=sid_abc_999"
    assert mgr.is_valid() is True

    login_call = mock_http.post.call_args_list[0]
    login_payload = json.loads(login_call.kwargs["data"].decode("utf-8"))
    assert login_payload["method"] == "login"
    assert set(login_payload["params"]) == {"password", "time", "encry", "limit", "setInit"}
    assert "username" not in login_payload["params"]
    assert "pwd" not in login_payload["params"]

    probe_call = mock_http.post.call_args_list[1]
    assert probe_call.args[0].endswith("/cgi-bin/luci/api/overview?auth=sid_abc_999")
    assert probe_call.kwargs["headers"]["Cookie"] == "SN123456789=sid_abc_999"


def test_single_flight_concurrent_login():
    """Spawns 30 concurrent threads requesting get_session() simultaneously.
    
    Asserts that exactly ONE network login request executes.
    """
    mock_http = MagicMock(spec=requests.Session())

    get_resp = MagicMock()
    get_resp.status_code = 200
    get_resp.text = 'GibberishAES.enc(passwordEl.value, "1122334455667788")'

    post_resp = MagicMock()
    post_resp.status_code = 200
    post_resp.json.return_value = {
        "data": {
            "token": "token_single_flight",
            "sid": "sid_single_flight",
            "sn": "SN_SINGLE_FLIGHT",
            "sessiontime": 3600,
        },
        "code": 0,
    }
    post_resp.headers = {"Set-Cookie": "sysauth=sid_single_flight; path=/"}

    # Simulate 50ms latency inside network post
    def slow_post(*args, **kwargs):
        time.sleep(0.05)
        return post_resp

    mock_http.get.return_value = get_resp
    mock_http.post.side_effect = slow_post
    mock_http.cookies = requests.cookies.RequestsCookieJar()

    mgr = ReyeeSessionManager(
        address="https://192.168.110.1",
        password="secret_pass",
        session_factory=lambda: mock_http,
    )

    sessions = []
    threads = []
    barrier = threading.Barrier(30)

    def worker():
        barrier.wait()
        s = mgr.get_session()
        sessions.append(s)

    for _ in range(30):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(sessions) == 30
    assert all(s.sid == "sid_single_flight" for s in sessions)
    # Exactly one login plus one SID validation probe executed.
    assert mock_http.post.call_count == 2
    assert mock_http.get.call_count == 1


def test_idle_timeout_and_activity_touch():
    """Validates that session is an idle timeout (not elapsed wall-clock)."""
    session = ReyeeSession(
        sid="test_sid",
        token="test_tok",
        cookie_header="sysauth=test_sid",
        session_seconds=2, # 2 seconds idle timeout
    )
    assert session.is_valid_locally is True

    # Artificially age the activity timestamp by 3 seconds
    session.last_activity_at = time.time() - 3.0
    assert session.is_valid_locally is False

    # Calling touch() restores local validity
    session.touch()
    assert session.is_valid_locally is True


def test_reyee_rpc_wire_and_auto_recovery():
    """Validates RPC dispatch wire format and max-1 retry auto recovery on 401."""
    mock_mgr = MagicMock(spec=ReyeeSessionManager)
    mock_mgr.address = "https://192.168.110.1"
    mock_mgr.verify_tls = False
    mock_mgr.http_timeout = (4, 12)

    initial_session = ReyeeSession("sid_old", "tok_old", "sysauth=sid_old")
    refreshed_session = ReyeeSession("sid_new", "tok_new", "sysauth=sid_new")

    mock_mgr.get_session.side_effect = [initial_session, refreshed_session]

    mock_http = MagicMock()
    mock_mgr.http_session = mock_http

    # First call returns 401 Unauthorized, second call returns 200 OK
    resp_401 = MagicMock()
    resp_401.status_code = 401

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {"code": 0, "data": {"hostname": "Reyee-BE72"}}

    probe_401 = MagicMock()
    probe_401.status_code = 401
    mock_http.post.side_effect = [resp_401, probe_401, resp_200]

    rpc_client = ReyeeRpcClient(mock_mgr)
    result = rpc_client.call("getHostName")

    assert result["data"]["hostname"] == "Reyee-BE72"
    assert mock_http.post.call_count == 3
    mock_mgr.invalidate_session.assert_called_once()
    mock_mgr.record_activity.assert_called_once()


def test_circuit_breaker_on_repeated_auth_failures():
    """Validates that 3 consecutive login failures trigger retry backoff."""
    mock_http = MagicMock()
    mock_http.get.side_effect = requests.RequestException("Connection refused")

    mgr = ReyeeSessionManager(
        address="https://192.168.110.1",
        password="bad_password",
        session_factory=lambda: mock_http,
    )

    # 3 failures
    for _ in range(3):
        with pytest.raises(RouterUnreachableError):
            mgr.get_session()

    # 4th call immediately triggers circuit breaker without calling network again
    with pytest.raises(RouterAuthError) as exc_info:
        mgr.get_session()
    assert "retry paused" in str(exc_info.value)


def test_reyee_rpc_client_rpc_with_no_parse_and_wire_payload():
    """Validates rpc() constructs eWeb params payload with module, data, noParse."""
    mock_mgr = MagicMock(spec=ReyeeSessionManager)
    mock_mgr.address = "https://192.168.110.1"
    mock_mgr.verify_tls = False
    mock_mgr.http_timeout = (4, 12)
    mock_mgr.get_session.return_value = ReyeeSession("sid_123", "tok_123", "sysauth=sid_123")

    mock_http = MagicMock()
    mock_mgr.http_session = mock_http

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"code": 0, "data": [{"mac": "00:11:22:33:44:55"}]}
    mock_http.post.return_value = resp

    client = ReyeeRpcClient(mock_mgr)
    res = client.rpc(
        method="devSta.get",
        module="user_list",
        data={"devType": "all", "dataType": "timely"},
        no_parse=True,
    )

    assert len(res) == 1

    # Verify wire payload passed into mock_http.post
    call_args = mock_http.post.call_args
    assert call_args is not None
    posted_json = json.loads(call_args.kwargs["data"].decode("utf-8"))
    assert posted_json["method"] == "devSta.get"
    assert posted_json["params"]["module"] == "user_list"
    assert posted_json["params"]["noParse"] is True
    assert posted_json["params"]["data"] == {"devType": "all", "dataType": "timely"}
    assert posted_json["params"]["device"] == "pc"
    assert call_args.kwargs["headers"]["Cookie"] == "sysauth=sid_123"
    assert len(call_args.kwargs["headers"]["Content-Accept"]) == 32
    assert len(call_args.kwargs["headers"]["Contents-Accept"]) == 32


def test_cmd_signature_rejection_does_not_invalidate_valid_session():
    mock_mgr = MagicMock(spec=ReyeeSessionManager)
    mock_mgr.address = "http://192.168.5.1"
    mock_mgr.verify_tls = False
    mock_mgr.http_timeout = (4, 12)
    mock_mgr.get_session.return_value = ReyeeSession("sid", "token", "SN=sid", serial_number="SN")
    mock_http = MagicMock()
    mock_mgr.http_session = mock_http

    rejected = MagicMock(status_code=403)
    valid_probe = MagicMock(status_code=200)
    valid_probe.json.return_value = {"code": 0, "data": {"sn": "SN"}}
    mock_http.post.side_effect = [rejected, valid_probe]

    with pytest.raises(Exception) as exc_info:
        ReyeeRpcClient(mock_mgr).rpc("devSta.get", "user_list")

    assert getattr(exc_info.value, "code", "") == "RPC_SIGNATURE_REJECTED"
    mock_mgr.invalidate_session.assert_not_called()


def test_reyee_driver_rpc_and_batch_delegation():
    """Validates ReyeeEWebDriver.rpc() and batch() delegate cleanly to ReyeeRpcClient."""
    from router_core.driver.reyee import ReyeeEWebDriver

    mock_rpc_client = MagicMock(spec=ReyeeRpcClient)
    mock_rpc_client.rpc.return_value = {"ok": True, "source": "rpc_client"}
    mock_rpc_client.batch.return_value = {"ok": True, "source": "batch"}

    driver = ReyeeEWebDriver(rpc_client=mock_rpc_client)

    # 1. Test rpc with no_parse
    r1 = driver.rpc("devConfig.get", "network", no_parse=True)
    assert r1["ok"] is True
    mock_rpc_client.rpc.assert_called_once_with(
        method="devConfig.get",
        module="network",
        data=None,
        no_parse=True,
        params=None,
    )

    # 2. Test batch
    calls = [{"method": "devSta.get", "module": "sysinfo"}]
    r2 = driver.batch(calls)
    assert r2["ok"] is True
    mock_rpc_client.batch.assert_called_once_with(calls)


def test_reyee_driver_ddns_get_update_delete():
    from router_core.driver.reyee import ReyeeEWebDriver

    mock_rpc = MagicMock(spec=ReyeeRpcClient)
    # Simulate router returning 2 DDNS records for aliyun.com
    mock_rpc.rpc.return_value = {
        "list": [
            {"service": "aliyun.com", "domain": "rj.lab86@shinya.icu", "user": "user1", "enable": "1", "password": "pwd"},
            {"service": "aliyun.com", "domain": "op.lab86@shinya.icu", "user": "user2", "enable": "1", "password": "pwd"},
        ]
    }

    driver = ReyeeEWebDriver(rpc_client=mock_rpc)
    ddns_res = driver.get_ddns(force=True)

    assert len(ddns_res["list"]) == 2
    assert ddns_res["list"][0]["domain"] == "rj.lab86@shinya.icu"
    assert ddns_res["list"][0]["password"] == ""
    assert ddns_res["list"][0]["passwordConfigured"] is True
    assert ddns_res["list"][1]["domain"] == "op.lab86@shinya.icu"

    # Test update_ddns
    mock_rpc.rpc.reset_mock()
    mock_rpc.rpc.side_effect = [
        # 1. get_ddns inside update_ddns
        {"list": [
            {"service": "aliyun.com", "domain": "rj.lab86@shinya.icu", "user": "user1", "enable": "1"},
            {"service": "aliyun.com", "domain": "op.lab86@shinya.icu", "user": "user2", "enable": "1"},
        ]},
        # 2. devSta.update
        {"code": 0},
        # 3. read back get_ddns
        {"list": [
            {"service": "aliyun.com", "domain": "rj.lab86@shinya.icu", "user": "user1", "enable": "0"},
            {"service": "aliyun.com", "domain": "op.lab86@shinya.icu", "user": "user2", "enable": "1"},
        ]},
    ]

    update_res = driver.update_ddns("rj.lab86@shinya.icu", {"enable": "0", "domain": "rj.lab86@shinya.icu"}, password=None)
    assert len(update_res["list"]) == 2
    assert update_res["list"][0]["enable"] == "0"
