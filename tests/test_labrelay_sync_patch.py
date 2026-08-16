from types import SimpleNamespace

from flask import Flask

from labrelay_sync_patch import install_labrelay_sync_patch


class _Logger:
    def info(self, *args, **kwargs):
        pass


class _Hub(SimpleNamespace):
    def clean_saved_value(self, value):
        return str(value or "").strip()

    def to_int(self, value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def primary_router_name(self):
        return "router"

    def check_hook_token(self):
        return True

    def now_str(self):
        return "2026-08-11 12:00:00"


def _rule(transport_protocol):
    rule = {
        "id": "udp-rule",
        "enabled": True,
        "mode": "6to4",
        "listenPort": 20000,
        "targetMode": "ipv4",
        "targetIpv4": "192.168.5.46",
        "targetIpv6": "",
        "targetIpv6Suffix": "",
        "targetMac": "",
        "targetPort": 53,
        "expiresAt": None,
        "leaseSeconds": 0,
        "maxConnections": 32,
        "idleTimeoutSec": 300,
    }
    if transport_protocol is not None:
        rule["transportProtocol"] = transport_protocol
    return rule


def _installed_hub(desired):
    app = Flask(__name__)
    app.add_url_rule("/api/portmaps", endpoint="api_portmaps", view_func=lambda: ("original", 200))
    queued = []
    saved = {}
    hub = _Hub(
        app=app,
        LOGGER=_Logger(),
        AGENT_STATUS_FILE="agent_status.json",
        PORTMAP_ROUTER_STATUS_FILE="portmap_status.json",
        _load_portmap_rules=lambda: [desired],
        load_json=lambda path, default=None: default,
        save_json=lambda path, value: saved.update({path: value}),
        _append_portmap_history=lambda record: None,
        _queue_portmap_command=lambda action, payload, router: queued.append((action, payload, router)),
    )
    install_labrelay_sync_patch(hub)
    return hub, queued


def _status_payload(rule):
    return {"router": "router", "rules": [{"rule": rule, "runtime": {"id": rule["id"]}}]}


def test_production_reconcile_requeues_udp_when_relay_reports_tcp():
    hub, queued = _installed_hub(_rule("UDP"))

    with hub.app.test_request_context(
        "/api/router/portmaps/status", method="POST", json=_status_payload(_rule("TCP"))
    ):
        response = hub.app.view_functions["api_router_portmap_status"]()

    assert response.status_code == 200
    assert queued == [("upsert", {"rule": _rule("UDP")}, "router")]


def test_production_reconcile_treats_missing_legacy_transport_as_tcp():
    hub, queued = _installed_hub(_rule(None))

    with hub.app.test_request_context(
        "/api/router/portmaps/status", method="POST", json=_status_payload(_rule("TCP"))
    ):
        response = hub.app.view_functions["api_router_portmap_status"]()

    assert response.status_code == 200
    assert queued == []
