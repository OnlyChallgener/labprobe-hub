import threading
from types import SimpleNamespace

from flask import Flask

from router_relay_credentials_patch import _relay_dashboard_ack


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
