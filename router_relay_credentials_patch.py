"""Keep the existing Relay 0.2.9 broadband-credential trigger working.

Direct Hub RPC owns dashboard telemetry now, so Relay dashboard payloads are
ignored.  The response must still return the credential refresh nonce; Relay
uses that nonce to run ``dev_config get -m network '{}'`` and push the temporary
username/password result back to Hub.
"""
from __future__ import annotations

from typing import Any

from flask import jsonify

import router_compat


def _relay_dashboard_ack(self: Any):
    if not self.hub.check_hook_token():
        return jsonify({"ok": False, "error": "bad agent token"}), 401

    with self.hub.ROUTER_DASHBOARD_LOCK:
        dashboard_nonce = self.hub.ROUTER_DASHBOARD_REFRESH_NONCE
    with self.hub.ROUTER_CREDENTIALS_LOCK:
        credentials_nonce = self.hub.ROUTER_CREDENTIALS_REFRESH_NONCE

    return jsonify({
        "ok": True,
        "ignored": True,
        "source": "router_rpc",
        "message": "dashboard telemetry is supplied directly by Hub; Relay credential refresh remains active",
        "refreshNonce": dashboard_nonce,
        "credentialsRefreshNonce": credentials_nonce,
        "time": self.hub.now_str(),
    })


def install_router_relay_credentials_patch() -> None:
    cls = router_compat.RouterRpcCompatibilitySync
    if getattr(cls, "_labprobe_relay_credentials_patch", False):
        return
    cls.ignored_relay_dashboard_push = _relay_dashboard_ack
    cls._labprobe_relay_credentials_patch = True
