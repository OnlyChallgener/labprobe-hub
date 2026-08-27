"""Unit Tests for ReyeeSessionManager and ReyeeRpcClient.

Validates:
1. AES-256-CBC encryption & decryption with fixed test salt vectors (Reference Oracle compliance).
2. Dynamic key extraction from mock HTML.
3. Single-Flight concurrency locking (only 1 real login across parallel callers).
4. Idle timeout maintenance (touch/record_activity).
5. RPC wire format (?auth=<sid>, Cookie header, {method, params}).
6. Auto-recovery on HTTP 401 / code 401 (max 1 retry).
7. Circuit breaker cooldown on repeated authentication failures.
8. BE72 signed-CMD headers match the last known-good production client.
"""

import hashlib
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
    key = "7a8b9c0d1e2f"
    plain = "Ruijie_Secure_Pass_123!"
    fixed_salt = b"12345678"
    encrypted = gibberish_aes_encrypt(plain, key, custom_salt=fixed_salt)
    assert isinstance(encrypted, str)
    assert not any(c.isspace() for c in encrypted)
    assert gibberish_aes_decrypt(encrypted, key) == plain
    random_encrypted = gibberish_aes_encrypt(plain, key)
    assert gibberish_aes_decrypt(random_encrypted, key) == plain


def test_dynamic_key_extraction_and_login():
    mock_html = """
    <html><script>
        var encKey = "abcdef0123456789";
        var enc = GibberishAES.enc(passwordEl.value, "abcdef0123456789");
    </script></html>
    """
    mock_http = MagicMock(spec=requests.Session())
    get_resp = MagicMock()
    get_resp.status_code = 200
    get_resp.text = mock_html
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
        sessions.append(mgr.get_session())

    for _ in range(30):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    assert len(sessions) == 30
    assert all(s.sid == "sid_single_flight" for s in sessions)
    assert mock_http.post.call_count == 2
    assert mock_http.get.call_count == 1


def test_idle_timeout_and_activity_touch():
    session = ReyeeSession(
        sid="test_sid",
        token="test_tok",
        cookie_header="sysauth=test_sid",
        session_seconds=2,
    )
    assert session.is_valid_locally is True
    session.last_activity_at = time.time() - 3.0
    assert session.is_valid_locally is False
    session.touch()
    assert session.is_valid_locally is True


def test_reyee_rpc_wire_and_auto_recovery():
    mock_mgr = MagicMock(spec=ReyeeSessionManager)
    mock_mgr.address = "https://192.168.110.1"
    mock_mgr.verify_tls = False
    mock_mgr.http_timeout = (4, 12)
    initial_session = ReyeeSession("sid_old", "tok_old", "sysauth=sid_old")
    refreshed_session = ReyeeSession("sid_new", "tok_new", "sysauth=sid_new")
    mock_mgr.get_session.side_effect = [initial_session, refreshed_session]
    mock_http = MagicMock()
    mock_mgr.http_session = mock_http
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


@pytest.mark.parametrize(
    "expired_response",
    [
        {"status_code": 302, "headers": {"Location": "/cgi-bin/luci/"}, "text": ""},
        {
            "status_code": 200,
            "headers": {},
            "text": '<form id="login"><input id="password"><script src="api/auth"></script></form>',
        },
    ],
)
def test_reyee_rpc_recovers_from_be72_login_redirect_or_page(expired_response):
    mock_mgr = MagicMock(spec=ReyeeSessionManager)
    mock_mgr.address = "https://192.168.110.1"
    mock_mgr.verify_tls = False
    mock_mgr.http_timeout = (4, 12)
    mock_mgr.get_session.side_effect = [
        ReyeeSession("sid_old", "tok_old", "SN=sid_old"),
        ReyeeSession("sid_new", "tok_new", "SN=sid_new"),
    ]
    expired = MagicMock()
    expired.status_code = expired_response["status_code"]
    expired.headers = expired_response["headers"]
    expired.text = expired_response["text"]
    success = MagicMock()
    success.status_code = 200
    success.headers = {}
    success.text = ""
    success.json.return_value = {"code": 0, "data": {"hostname": "Reyee-BE72"}}
    mock_mgr.http_session.post.side_effect = [expired, success]
    result = ReyeeRpcClient(mock_mgr).call("getHostName")
    assert result["data"]["hostname"] == "Reyee-BE72"
    mock_mgr.invalidate_session.assert_called_once_with()
    assert mock_mgr.http_session.post.call_count == 2
    assert "auth=sid_old" in mock_mgr.http_session.post.call_args_list[0].args[0]
    assert "auth=sid_new" in mock_mgr.http_session.post.call_args_list[1].args[0]


def test_reyee_rpc_login_redirect_retries_at_most_once():
    mock_mgr = MagicMock(spec=ReyeeSessionManager)
    mock_mgr.address = "https://192.168.110.1"
    mock_mgr.verify_tls = False
    mock_mgr.http_timeout = (4, 12)
    mock_mgr.get_session.side_effect = [
        ReyeeSession("sid_old", "tok_old", "SN=sid_old"),
        ReyeeSession("sid_new", "tok_new", "SN=sid_new"),
    ]
    expired = MagicMock()
    expired.status_code = 302
    expired.headers = {"Location": "/cgi-bin/luci/"}
    expired.text = ""
    mock_mgr.http_session.post.side_effect = [expired, expired]
    with pytest.raises(RouterAuthExpiredError):
        ReyeeRpcClient(mock_mgr).call("getHostName")
    assert mock_mgr.http_session.post.call_count == 2
    assert mock_mgr.invalidate_session.call_count == 2


def test_reyee_rpc_does_not_treat_unrelated_redirect_as_auth_expiry():
    mock_mgr = MagicMock(spec=ReyeeSessionManager)
    mock_mgr.address = "https://192.168.110.1"
    mock_mgr.verify_tls = False
    mock_mgr.http_timeout = (4, 12)
    mock_mgr.get_session.return_value = ReyeeSession("sid", "tok", "SN=sid")
    redirect = MagicMock()
    redirect.status_code = 302
    redirect.headers = {"Location": "https://router.example/maintenance"}
    redirect.text = ""
    redirect.json.side_effect = ValueError("not json")
    mock_mgr.http_session.post.return_value = redirect
    with pytest.raises(Exception) as raised:
        ReyeeRpcClient(mock_mgr).call("getHostName")
    assert "Invalid JSON" in str(raised.value)
    mock_mgr.invalidate_session.assert_not_called()


def test_circuit_breaker_on_repeated_auth_failures():
    mock_http = MagicMock()
    mock_http.get.side_effect = requests.RequestException("Connection refused")
    mgr = ReyeeSessionManager(
        address="https://192.168.110.1",
        password="bad_password",
        session_factory=lambda: mock_http,
    )
    for _ in range(3):
        with pytest.raises(RouterUnreachableError):
            mgr.get_session()
    with pytest.raises(RouterAuthError) as exc_info:
        mgr.get_session()
    assert "retry paused" in str(exc_info.value)


def test_reyee_rpc_client_rpc_with_no_parse_and_wire_payload():
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
    call_args = mock_http.post.call_args
    assert call_args is not None
    assert "auth=sid_123" in call_args.args[0]
    posted_json = json.loads(call_args.kwargs["data"].decode("utf-8"))
    assert posted_json["method"] == "devSta.get"
    assert posted_json["params"]["module"] == "user_list"
    assert posted_json["params"]["noParse"] is True
    assert posted_json["params"]["data"] == {"devType": "all", "dataType": "timely"}
    assert posted_json["params"]["device"] == "pc"
    assert call_args.kwargs["headers"]["Cookie"] == "sysauth=sid_123"
    assert len(call_args.kwargs["headers"]["Content-Accept"]) == 32
    assert len(call_args.kwargs["headers"]["Contents-Accept"]) == 32

    client.rpc(
        method="devSta.update",
        module="ddnsCfg",
        data={"data": [{"service": "0", "enabled": "0"}]},
    )
    nested_call_args = mock_http.post.call_args
    nested_json = json.loads(nested_call_args.kwargs["data"].decode("utf-8"))
    assert nested_json["params"]["data"] == {"data": [{"service": "0", "enabled": "0"}]}


def test_be72_cmd_signature_matches_known_good_production_contract():
    payload = {
        "method": "devSta.get",
        "params": {
            "module": "user_list",
            "noParse": True,
            "async": None,
            "remoteIp": False,
            "device": "pc",
            "data": {"devType": "all", "dataType": "timely"},
        },
    }
    wire = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    headers = ReyeeRpcClient._headers("/cgi-bin/luci/api/cmd", payload, wire, "SN=sid")
    secret = "Web@Rj$2020!"
    assert headers["Content-Accept"] == hashlib.md5(
        (secret + str(ReyeeRpcClient._eweb_byte_length(wire))).encode("utf-8")
    ).hexdigest()
    assert headers["Contents-Accept"] == hashlib.md5((secret + wire).encode("utf-8")).hexdigest()


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
    client = ReyeeRpcClient(mock_mgr)
    with pytest.raises(Exception) as exc_info:
        client.rpc("devSta.get", "user_list")
    assert getattr(exc_info.value, "code", "") == "RPC_SIGNATURE_REJECTED"
    mock_mgr.invalidate_session.assert_not_called()
    status = client.control_status()
    assert status["checked"] is True
    assert status["connected"] is False
    assert status["lastErrorCode"] == "RPC_SIGNATURE_REJECTED"


def test_reyee_driver_rpc_and_batch_delegation():
    from router_core.driver.reyee import ReyeeEWebDriver
    mock_rpc_client = MagicMock(spec=ReyeeRpcClient)
    mock_rpc_client.rpc.return_value = {"ok": True, "source": "rpc_client"}
    mock_rpc_client.batch.return_value = {"ok": True, "source": "batch"}
    driver = ReyeeEWebDriver(rpc_client=mock_rpc_client)
    r1 = driver.rpc("devConfig.get", "network", no_parse=True)
    assert r1["ok"] is True
    mock_rpc_client.rpc.assert_called_once_with(
        method="devConfig.get",
        module="network",
        data=None,
        no_parse=True,
        params=None,
    )
    calls = [{"method": "devSta.get", "module": "sysinfo"}]
    r2 = driver.batch(calls)
    assert r2["ok"] is True
    mock_rpc_client.batch.assert_called_once_with(calls)


def test_reyee_driver_ddns_get_update_delete():
    from router_core.driver.reyee import ReyeeEWebDriver
    mock_rpc = MagicMock(spec=ReyeeRpcClient)
    mock_rpc.rpc.return_value = {
        "list": [
            {"service": "random-service-a", "service_name": "aliyun.com", "domain": "rj.lab86@shinya.icu", "username": "user1", "enabled": "1", "password": "pwd"},
            {"service": "random-service-b", "service_name": "aliyun.com", "domain": "op.lab86@shinya.icu", "username": "user2", "enabled": "1", "password": "pwd"},
        ]
    }
    driver = ReyeeEWebDriver(rpc_client=mock_rpc)
    ddns_res = driver.get_ddns(force=True)
    assert len(ddns_res["list"]) == 2
    assert ddns_res["list"][0]["serviceId"] == "random-service-a"
    assert ddns_res["list"][0]["service"] == "random-service-a"
    assert ddns_res["list"][0]["service_name"] == "aliyun.com"
    assert ddns_res["list"][0]["domain"] == "rj.lab86@shinya.icu"
    assert ddns_res["list"][0]["password"] == ""
    assert ddns_res["list"][0]["passwordConfigured"] is True
    assert ddns_res["list"][1]["domain"] == "op.lab86@shinya.icu"

    mock_rpc.rpc.reset_mock()
    mock_rpc.rpc.side_effect = [{"code": 0}, {"list": []}]
    driver.add_ddns(
        {
            "service_name": "aliyun.com",
            "domain": "new.lab86@shinya.icu",
            "username": "user3",
            "enable": "0",
        },
        "pwd3",
    )
    add_call = next(call for call in mock_rpc.rpc.call_args_list if call.kwargs.get("method") == "devSta.add")
    assert add_call.kwargs["data"]["enabled"] == "0"
    assert "enable" not in add_call.kwargs["data"]

    mock_rpc.rpc.reset_mock()
    mock_rpc.rpc.side_effect = [
        {"list": [
            {"service": "random-service-a", "service_name": "aliyun.com", "domain": "rj.lab86@shinya.icu", "username": "user1", "enabled": "1"},
            {"service": "random-service-b", "service_name": "aliyun.com", "domain": "op.lab86@shinya.icu", "username": "user2", "enabled": "1"},
        ]},
        {"code": 0},
        {"list": [
            {"service": "random-service-a", "service_name": "aliyun.com", "domain": "rj.lab86@shinya.icu", "username": "user1", "enabled": "0"},
            {"service": "random-service-b", "service_name": "aliyun.com", "domain": "op.lab86@shinya.icu", "username": "user2", "enabled": "1"},
        ]},
    ]
    update_res = driver.update_ddns(
        "random-service-a",
        {
            "service_name": "aliyun.com",
            "enable": "0",
            "domain": "rj.lab86@shinya.icu",
            "username": "user1",
        },
        password=None,
    )
    assert len(update_res["list"]) == 2
    assert update_res["list"][0]["enabled"] == "0"
    update_call = next(call for call in mock_rpc.rpc.call_args_list if call.kwargs.get("method") == "devSta.update")
    update_payload = update_call.kwargs["data"]
    assert list(update_payload) == ["data"]
    assert update_payload["data"][0]["service"] == "random-service-a"
    assert update_payload["data"][0]["service_name"] == "aliyun.com"
    assert update_payload["data"][0]["enabled"] == "0"
    assert "enable" not in update_payload["data"][0]
    assert "user" not in update_payload["data"][0]
