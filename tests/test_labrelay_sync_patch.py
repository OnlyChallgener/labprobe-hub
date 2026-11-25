from types import SimpleNamespace

from flask import Flask

from labrelay_sync_patch import install_labrelay_sync_patch


class _Logger:
    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
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

    def _canonical_portmap_router(self, value=""):
        primary = self.primary_router_name()
        candidate = self.clean_saved_value(value) or primary or "router"
        return primary if candidate.lower() in {"router", primary.lower()} else candidate

    def check_hook_token(self):
        return True

    def check_read_token(self):
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


def _installed_hub(desired, *, rules_loaded=True):
    app = Flask(__name__)
    app.add_url_rule("/api/portmaps", endpoint="api_portmaps", view_func=lambda: ("original", 200))
    queued = []
    saved = {}
    hub = _Hub(
        app=app,
        LOGGER=_Logger(),
        AGENT_STATUS_FILE="agent_status.json",
        AGENT_UPDATE_COMMANDS_FILE="agent_update_commands.json",
        PORTMAP_RULES_FILE="portmap_rules.json",
        PORTMAP_ROUTER_STATUS_FILE="portmap_status.json",
        _load_portmap_rules_document=lambda: (
            {"version": 1, "revision": 1, "updatedAt": "", "rules": [desired]},
            rules_loaded,
        ),
        _portmap_epoch=lambda value: value,
        _portmap_runtime_map=lambda document: {},
        _portmap_command_sync_states=lambda router: {},
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


def test_agent_status_preserves_bounded_multi_wan_capabilities():
    hub, _queued = _installed_hub(_rule("TCP"))
    saved = {}
    hub.save_json = lambda path, value: saved.update({path: value})
    with hub.app.test_request_context(
        "/api/router/agent/status",
        method="POST",
        json={
            "router": "router",
            "version": "0.2.80",
            "protocolVersion": 2,
            "capabilities": ["relay.multiWan", "relay.wanTelemetry", "bad value", "relay.multiWan"],
            "wanIds": ["WAN", "wan1", "WAN"],
        },
    ):
        response = hub.app.view_functions["api_router_agent_status"]()

    assert response.status_code == 200
    heartbeat = saved[hub.AGENT_STATUS_FILE]["router"]
    assert heartbeat["protocolVersion"] == 2
    assert heartbeat["capabilities"] == ["relay.multiWan", "relay.wanTelemetry"]
    assert heartbeat["wanIds"] == ["wan", "wan1"]

    hub.load_json = lambda path, default=None: saved.get(path, default)
    with hub.app.test_request_context("/api/portmaps", method="GET"):
        body = hub.app.view_functions["api_portmaps"]().get_json()
    assert body["agentProtocolVersion"] == 2
    assert body["agentCapabilities"] == ["relay.multiWan", "relay.wanTelemetry"]
    assert body["agentWanIds"] == ["wan", "wan1"]


def test_old_agent_without_capabilities_remains_single_wan():
    hub, _queued = _installed_hub(_rule("TCP"))
    saved = {}
    hub.save_json = lambda path, value: saved.update({path: value})
    with hub.app.test_request_context("/api/router/agent/status", method="POST", json={
        "router": "router", "version": "0.2.79",
    }):
        hub.app.view_functions["api_router_agent_status"]()
    hub.load_json = lambda path, default=None: saved.get(path, default)
    with hub.app.test_request_context("/api/portmaps", method="GET"):
        body = hub.app.view_functions["api_portmaps"]().get_json()
    assert body["agentProtocolVersion"] == 0
    assert body["agentCapabilities"] == []
    assert body["agentWanIds"] == []


def test_explicit_empty_capabilities_clear_old_values_and_version_change_does_not_inherit_them():
    hub, _queued = _installed_hub(_rule("TCP"))
    saved = {}
    hub.save_json = lambda path, value: saved.update({path: value})

    def post(body):
        with hub.app.test_request_context("/api/router/agent/status", method="POST", json=body):
            hub.app.view_functions["api_router_agent_status"]()
        hub.load_json = lambda path, default=None: saved.get(path, default)

    post({"router": "router", "version": "0.2.80", "protocolVersion": 2,
          "capabilities": ["relay.multiWan"], "wanIds": ["wan", "wan1"]})
    post({"router": "router", "version": "0.2.80", "protocolVersion": 2,
          "capabilities": [], "wanIds": []})
    assert saved[hub.AGENT_STATUS_FILE]["router"]["capabilities"] == []
    assert saved[hub.AGENT_STATUS_FILE]["router"]["wanIds"] == []

    post({"router": "router", "version": "0.2.81", "protocolVersion": 2,
          "capabilities": ["relay.multiWan"], "wanIds": ["wan1"]})
    post({"router": "router", "version": "0.2.82"})
    heartbeat = saved[hub.AGENT_STATUS_FILE]["router"]
    assert heartbeat["protocolVersion"] == 0
    assert heartbeat["capabilities"] == []
    assert heartbeat["wanIds"] == []


def test_unavailable_rules_document_never_reconciles_runtime_as_empty():
    hub, queued = _installed_hub(_rule("TCP"), rules_loaded=False)
    local = _rule("TCP")
    local["id"] = "router-only-rule"

    with hub.app.test_request_context(
        "/api/router/portmaps/status", method="POST", json=_status_payload(local)
    ):
        response = hub.app.view_functions["api_router_portmap_status"]()

    assert response.status_code == 200
    assert queued == []


def test_get_reports_unavailable_rules_document_truthfully():
    hub, _queued = _installed_hub(_rule("TCP"), rules_loaded=False)

    with hub.app.test_request_context("/api/portmaps", method="GET"):
        response = hub.app.view_functions["api_portmaps"]()

    assert response.get_json()["rulesLoaded"] is False


def test_exhausted_command_is_reported_as_error_instead_of_syncing_forever():
    desired = _rule("TCP")
    hub, _queued = _installed_hub(desired)
    hub._portmap_command_sync_states = lambda router: {desired["id"]: "error"}
    documents = {
        hub.PORTMAP_RULES_FILE: {
            "version": 1,
            "revision": 1,
            "updatedAt": "2026-09-01 12:00:00",
            "rules": [desired],
        },
        hub.PORTMAP_ROUTER_STATUS_FILE: {},
        hub.AGENT_STATUS_FILE: {
            "router": {"lastSeenAt": "2026-09-01 12:00:00", "lastSeenEpoch": 1_788_200_000}
        },
    }
    hub.load_json = lambda path, default=None: documents.get(path, default)

    with hub.app.test_request_context("/api/portmaps", method="GET"):
        response = hub.app.view_functions["api_portmaps"]()

    rule = response.get_json()["rules"][0]
    assert rule["actualState"] == "error"
    assert rule["syncState"] == "error"
    assert rule["runtime"]["lastError"] == "command delivery failed"


def test_running_rule_with_connection_error_remains_synced():
    desired = _rule("TCP")
    hub, _queued = _installed_hub(desired)
    runtime = {
        "id": desired["id"],
        "state": "running",
        "lastError": "Connection reset by peer (os error 104)",
        "startedAt": 1_787_900_000,
    }
    runtime_document = {
        "router": "router",
        "receivedAt": "2026-08-28 17:45:39",
        "receivedEpoch": 1_787_910_339,
        "runtimeRevision": 1_787_910_339,
        "status": {"rules": [{"rule": desired, "runtime": runtime}]},
    }
    documents = {
        hub.PORTMAP_RULES_FILE: {
            "revision": 36,
            "updatedAt": "2026-08-28 17:04:00",
            "rules": [desired],
        },
        hub.PORTMAP_ROUTER_STATUS_FILE: runtime_document,
        hub.AGENT_STATUS_FILE: {},
    }
    hub.load_json = lambda path, default=None: documents.get(path, default)
    hub._portmap_runtime_map = lambda document: {
        desired["id"]: document["status"]["rules"][0]["runtime"]
    }

    with hub.app.test_request_context("/api/portmaps", method="GET"):
        response = hub.app.view_functions["api_portmaps"]()

    body = response.get_json()
    rule = body["rules"][0]
    assert rule["actualState"] == "running"
    assert rule["syncState"] == "synced"
    assert rule["runtime"]["lastError"] == "Connection reset by peer (os error 104)"
