import threading
from types import SimpleNamespace

from flask import Flask

import router_relay_credentials_patch as credentials_patch
from router_relay_credentials_patch import (
    _direct_credentials_refresh_view,
    _extract_router_credentials,
    _relay_dashboard_ack,
)


def test_relay_dashboard_ack_contains_credential_refresh_nonce():
    app = Flask(__name__)
    hub = SimpleNamespace(
        check_hook_token=lambda: True,
        ROUTER_DASHBOARD_LOCK=threading.RLock(),
        ROUTER_DASHBOARD_REFRESH_NONCE=17,
        ROUTER_CREDENTIALS_LOCK=threading.RLock(),
        ROUTER_CREDENTIALS_REFRESH_NONCE=1784730000123,
        now_str=lambda: "2026-07-23 10:00:00",
    )

    with app.app_context():
        response = _relay_dashboard_ack(SimpleNamespace(hub=hub))
        payload = response.get_json()

    assert payload["ok"] is True
    assert payload["ignored"] is True
    assert payload["refreshNonce"] == 17
    assert payload["credentialsRefreshNonce"] == 1784730000123


def test_extract_router_credentials_prefers_pppoe_wan_pair():
    payload = {
        "lan": {"macaddr": "10-5F-02-05-80-67", "username": "not-wan"},
        "interfaces": [
            {"ifname": "guest", "username": "guest-user", "password": "guest-pass"},
            {
                "ifname": "wan",
                "proto": "pppoe",
                "pppoe_username": "broadband-user",
                "pppoe_password": "broadband-pass",
            },
        ],
    }

    result = _extract_router_credentials(payload)

    assert result["username"] == "broadband-user"
    assert result["password"] == "broadband-pass"
    assert result["lanMac"] == "10:5f:02:05:80:67"


def test_extract_router_credentials_supports_wrapped_no_parse_json():
    payload = {
        "rcode": "00000000",
        "data": '{"wan":{"type":"PPPoE","account":"user-2","passwd":"p@ss-2"}}',
    }

    result = _extract_router_credentials(payload)

    assert result["username"] == "user-2"
    assert result["password"] == "p@ss-2"


def test_extract_router_credentials_rejects_masked_password():
    payload = {"wan": {"proto": "pppoe", "username": "user-3", "password": "******"}}

    result = _extract_router_credentials(payload)

    assert result["username"] == "user-3"
    assert result["password"] == ""


def _refresh_fixture():
    hub = SimpleNamespace(
        check_app_token=lambda: True,
        ROUTER_CREDENTIALS_LOCK=threading.RLock(),
        ROUTER_CREDENTIALS_REFRESH_NONCE=100,
        ROUTER_CREDENTIALS_CACHE={},
        primary_router_name=lambda: "router",
        now_str=lambda: "2026-07-23 10:00:00",
    )
    return SimpleNamespace(
        hub=hub,
        client=object(),
        logger=SimpleNamespace(warning=lambda *_args, **_kwargs: None),
    )


def test_partial_direct_credentials_wait_for_router_local_fallback(monkeypatch):
    app = Flask(__name__)
    sync = _refresh_fixture()
    monkeypatch.setattr(
        credentials_patch,
        "_read_direct_credentials",
        lambda _client: {"username": "only-user", "password": "", "lanMac": ""},
    )

    with app.app_context():
        payload = _direct_credentials_refresh_view(sync).get_json()

    assert payload["refreshNonce"] == 101
    assert payload["refreshCompletedNonce"] == 0
    assert payload["credentialsAvailable"] is False
    assert payload["relayFallbackPending"] is True
    assert sync.hub.ROUTER_CREDENTIALS_CACHE == {}


def test_complete_direct_credentials_are_memory_only_and_completed(monkeypatch):
    app = Flask(__name__)
    sync = _refresh_fixture()
    monkeypatch.setattr(
        credentials_patch,
        "_read_direct_credentials",
        lambda _client: {
            "username": "broadband-user",
            "password": "broadband-pass",
            "lanMac": "10:5f:02:05:80:67",
        },
    )

    with app.app_context():
        payload = _direct_credentials_refresh_view(sync).get_json()

    assert payload["refreshCompletedNonce"] == 101
    assert payload["credentialsAvailable"] is True
    assert payload["relayFallbackPending"] is False
    assert sync.hub.ROUTER_CREDENTIALS_CACHE["username"] == "broadband-user"
    assert sync.hub.ROUTER_CREDENTIALS_CACHE["password"] == "broadband-pass"
    assert sync.hub.ROUTER_CREDENTIALS_CACHE["refreshCompletedNonce"] == 101
