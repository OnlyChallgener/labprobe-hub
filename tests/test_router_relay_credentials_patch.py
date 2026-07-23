import threading
import time
from types import SimpleNamespace

from flask import Flask

import router_relay_credentials_patch as credentials_patch
from router_relay_credentials_patch import (
    _AGENT_COMMAND_CONDITION,
    _agent_commands_view,
    _direct_credentials_refresh_view,
    _extract_router_credentials,
    _relay_credentials_push_view,
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
        check_hook_token=lambda: True,
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


def test_incomplete_relay_push_does_not_overwrite_valid_memory_cache():
    app = Flask(__name__)
    sync = _refresh_fixture()
    sync.hub.ROUTER_CREDENTIALS_REFRESH_NONCE = 101
    sync.hub.ROUTER_CREDENTIALS_CACHE.update({
        "username": "old-user",
        "password": "old-pass",
        "refreshCompletedNonce": 100,
    })

    with app.test_request_context(
        "/api/router/dashboard/credentials/push",
        method="POST",
        json={"router": "router", "username": "new-user", "password": "******", "refreshNonce": 101},
    ):
        response, status = _relay_credentials_push_view(sync)
        payload = response.get_json()

    assert status == 422
    assert payload["error"] == "incomplete_credentials"
    assert sync.hub.ROUTER_CREDENTIALS_CACHE["username"] == "old-user"
    assert sync.hub.ROUTER_CREDENTIALS_CACHE["password"] == "old-pass"
    assert sync.hub.ROUTER_CREDENTIALS_CACHE["refreshCompletedNonce"] == 100


def test_complete_relay_push_updates_memory_cache_and_nonce():
    app = Flask(__name__)
    sync = _refresh_fixture()
    sync.hub.ROUTER_CREDENTIALS_REFRESH_NONCE = 101

    with app.test_request_context(
        "/api/router/dashboard/credentials/push",
        method="POST",
        json={
            "router": "router",
            "lanMac": "10:5f:02:05:80:67",
            "username": "local-user",
            "password": "local-pass",
            "refreshNonce": 101,
        },
    ):
        payload = _relay_credentials_push_view(sync).get_json()

    assert payload["ok"] is True
    assert payload["refreshNonce"] == 101
    assert sync.hub.ROUTER_CREDENTIALS_CACHE["username"] == "local-user"
    assert sync.hub.ROUTER_CREDENTIALS_CACHE["password"] == "local-pass"
    assert sync.hub.ROUTER_CREDENTIALS_CACHE["refreshCompletedNonce"] == 101
    assert sync.hub.ROUTER_CREDENTIALS_CACHE["source"] == "router_local_agent"


def _command_fixture(requested=100, completed=100):
    hub = SimpleNamespace(
        check_hook_token=lambda: True,
        clean_saved_value=lambda value: str(value or "").strip(),
        primary_router_name=lambda: "router",
        AGENT_UPDATE_COMMANDS_FILE="commands.json",
        load_json=lambda _path, default: default,
        ROUTER_CREDENTIALS_LOCK=threading.RLock(),
        ROUTER_CREDENTIALS_REFRESH_NONCE=requested,
        ROUTER_CREDENTIALS_CACHE={"refreshCompletedNonce": completed},
        now_str=lambda: "2026-07-23 10:00:00",
    )
    return SimpleNamespace(hub=hub)


def test_agent_command_response_reports_requested_and_completed_nonce():
    app = Flask(__name__)
    sync = _command_fixture(requested=101, completed=101)

    with app.test_request_context(
        "/api/router/agent/commands?router=router&credentialsSince=100&wait=0"
    ):
        payload = _agent_commands_view(sync).get_json()

    assert payload["commands"] == []
    assert payload["credentialsRefreshNonce"] == 101
    assert payload["credentialsCompletedNonce"] == 101


def test_agent_long_poll_wakes_immediately_on_credential_refresh(monkeypatch):
    app = Flask(__name__)
    sync = _command_fixture(requested=100, completed=100)
    result = {}
    entered_snapshot = threading.Event()
    original_snapshot = credentials_patch._agent_command_snapshot

    def observed_snapshot(owner, router):
        value = original_snapshot(owner, router)
        entered_snapshot.set()
        return value

    monkeypatch.setattr(credentials_patch, "_agent_command_snapshot", observed_snapshot)

    def wait_for_command():
        started = time.monotonic()
        with app.test_request_context(
            "/api/router/agent/commands?router=router&credentialsSince=100&wait=2"
        ):
            result["payload"] = _agent_commands_view(sync).get_json()
        result["elapsed"] = time.monotonic() - started

    thread = threading.Thread(target=wait_for_command)
    thread.start()
    assert entered_snapshot.wait(timeout=1.0)
    with sync.hub.ROUTER_CREDENTIALS_LOCK:
        sync.hub.ROUTER_CREDENTIALS_REFRESH_NONCE = 101
    with _AGENT_COMMAND_CONDITION:
        _AGENT_COMMAND_CONDITION.notify_all()
    thread.join(timeout=1.5)

    assert not thread.is_alive()
    assert result["elapsed"] < 1.0
    assert result["payload"]["credentialsRefreshNonce"] == 101
    assert result["payload"]["credentialsCompletedNonce"] == 100
