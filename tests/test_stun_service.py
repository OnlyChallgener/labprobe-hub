from pathlib import Path
from types import SimpleNamespace
import copy
import threading
import time

from flask import Flask

from stun_service import DEFAULT_STUN_TCP_SERVER, StunService, create_stun_blueprint


class _Cache:
    def clear(self, _prefix):
        pass


class _Client:
    def __init__(self):
        self.write_lock = threading.RLock()
        self.cache = _Cache()
        self.rules = []
        self.native_rules = []
        self.firewall_reads = 0
        self.native_reads = 0
        self.rpc_calls = []

    def firewall(self, _force=False):
        self.firewall_reads += 1
        return {"list": [dict(row) for row in self.rules], "maxLen": 20}

    def native_port_mapping(self, _force=False):
        self.native_reads += 1
        return {"portMapping": [dict(row) for row in self.native_rules]}

    def rpc(self, operation, module, payload):
        self.rpc_calls.append((operation, module, copy.deepcopy(payload)))
        if module == "ip_firewall":
            if operation == "devConfig.add":
                for row in payload["list"]:
                    self.rules.append({**row, "uuid": f"fw-{len(self.rules) + 1}"})
            elif operation == "devConfig.del":
                self.rules = [row for row in self.rules if row["uuid"] not in payload["uuid"]]
        elif module == "port_mapping":
            if operation == "devConfig.add":
                self.native_rules.extend(dict(row) for row in payload["list"])
            elif operation == "devConfig.update":
                old, new = payload["old"], payload["new"]
                self.native_rules = [dict(new) if row.get("ruleName") == old.get("ruleName") else row for row in self.native_rules]
            elif operation == "devConfig.del":
                self.native_rules = [row for row in self.native_rules if row.get("ruleName") not in payload["ruleName"]]
        else:
            raise AssertionError(module)
        return {"ok": True}


def _hub(tmp_path):
    saved = {}

    def load(path, default=None):
        return saved.get(Path(path), default)

    def save(path, value):
        saved[Path(path)] = value

    return SimpleNamespace(
        DATA_DIR=tmp_path,
        app=Flask(__name__),
        load_json=load,
        save_json=save,
        _load_portmap_rules=lambda: [{"listenPort": 20000, "transportProtocol": "TCP"}],
        check_app_token=lambda: True,
        check_read_token=lambda: True,
        check_hook_token=lambda: True,
    )


def _running_rule(tmp_path, payload=None):
    hub = _hub(tmp_path)
    client = _Client()
    service = StunService(hub, client)
    rule = service.clean_rule(payload or {
        "serviceType": "HTTPS",
        "targetIpv4": "192.168.5.46",
        "targetPort": 443,
        "name": "家庭 HTTPS",
    })
    assert service.ensure_native_mapping(rule)["state"] == "ready"
    service._save_rules([rule])
    service._save_commands([])
    hub.app.register_blueprint(create_stun_blueprint(hub, service))
    return hub, client, service, rule, hub.app.test_client()


def test_service_templates_choose_protocol_and_skip_portmap_reservation(tmp_path):
    service = StunService(_hub(tmp_path), _Client())
    https = service.clean_rule({"serviceType": "HTTPS", "targetIpv4": "192.168.5.46", "targetPort": 443})
    wireguard = service.clean_rule({"serviceType": "WireGuard", "targetIpv4": "192.168.5.47", "targetPort": 51820})

    assert https["transportProtocol"] == "TCP"
    assert https["listenPort"] == 20001
    assert wireguard["transportProtocol"] == "UDP"
    assert wireguard["listenPort"] == 20000
    assert https["stunServer"] == DEFAULT_STUN_TCP_SERVER


def test_legacy_tcp_rule_is_migrated_to_a_tcp_stun_server_and_queued(tmp_path):
    hub = _hub(tmp_path)
    legacy = {
        "id": "stun-tcp",
        "kind": "stun",
        "name": "HTTPS · 192.168.5.46:443",
        "enabled": True,
        "targetIpv4": "192.168.5.46",
        "targetPort": 443,
        "transportProtocol": "TCP",
        "stunServer": "stun.cloudflare.com:3478",
    }
    hub.save_json(tmp_path / "stun_rules.json", {"revision": 1, "rules": [legacy]})

    service = StunService(hub, _Client())

    assert service._document()["rules"][0]["stunServer"] == DEFAULT_STUN_TCP_SERVER
    assert service._commands()[0]["action"] == "upsert"
    assert service._commands()[0]["payload"]["rule"]["stunServer"] == DEFAULT_STUN_TCP_SERVER


def test_address_history_retains_only_latest_three_unique_endpoints(tmp_path):
    service = StunService(_hub(tmp_path), _Client())
    for port in (20001, 20002, 20003, 20004):
        service._remember_endpoint("stun-1", {"publicEndpoint": f"203.0.113.9:{port}", "mappingUpdatedAt": port})

    rows = service._history()["stun-1"]
    assert [row["endpoint"] for row in rows] == ["203.0.113.9:20004", "203.0.113.9:20003", "203.0.113.9:20002"]


def test_dynamic_public_endpoint_never_changes_the_relay_to_lan_forward_target(tmp_path):
    hub = _hub(tmp_path)
    service = StunService(hub, _Client())
    rule = service.clean_rule({"serviceType": "HTTPS", "targetIpv4": "192.168.5.46", "targetPort": 443})
    service._save_rules([rule])

    for endpoint in ("203.0.113.9:20001", "203.0.113.9:28764"):
        hub.save_json(service.status_path, {
            "receivedEpoch": 1,
            "status": {"rules": [{"rule": rule, "runtime": {"id": rule["id"], "state": "mapped", "publicEndpoint": endpoint}}]},
        })
        current = service.rows()[0]
        assert current["targetIpv4"] == "192.168.5.46"
        assert current["targetPort"] == 443
        assert current["runtime"]["publicEndpoint"] == endpoint


def test_stale_mapping_is_not_reported_ready_and_addresses_are_layered(tmp_path):
    hub, _, service, rule, _ = _running_rule(tmp_path)
    now = int(time.time())
    hub.save_json(service.status_path, {
        "status": {"rules": [{
            "rule": rule,
            "runtime": {
                "id": rule["id"],
                "state": "mapped",
                "publicEndpoint": "203.0.113.9:28764",
                "publicIp": "203.0.113.9",
                "publicPort": 28764,
                "mappingUpdatedAt": now - 91,
            },
        }]},
    })

    stale = service.rows()[0]
    assert stale["actualState"] == "mapping"
    assert stale["runtime"]["mappingFresh"] is False
    assert stale["addresses"]["target"]["endpoint"] == "192.168.5.46:443"
    assert stale["addresses"]["channel"]["endpoint"] == f"0.0.0.0:{rule['listenPort']}"
    assert stale["addresses"]["public"] == {
        "host": "203.0.113.9",
        "port": 28764,
        "endpoint": "203.0.113.9:28764",
        "updatedAt": now - 91,
        "fresh": False,
        "reachabilityState": "unknown",
    }

    hub.save_json(service.status_path, {
        "status": {"rules": [{
            "rule": rule,
            "runtime": {
                "id": rule["id"],
                "state": "mapped",
                "publicEndpoint": "203.0.113.9:28764",
                "publicIp": "203.0.113.9",
                "publicPort": 28764,
                "mappingUpdatedAt": now,
            },
        }]},
    })
    fresh = service.rows()[0]
    assert fresh["actualState"] == "mapped"
    assert fresh["runtime"]["mappingFresh"] is True


def test_tcp_stun_uses_one_router_native_map_while_public_endpoint_changes(tmp_path):
    client = _Client()
    service = StunService(_hub(tmp_path), client)
    rule = service.clean_rule({"serviceType": "HTTPS", "targetIpv4": "192.168.5.46", "targetPort": 443})

    assert rule["forwardMode"] == "router_native"
    assert service.ensure_native_mapping(rule)["state"] == "ready"
    created = dict(client.native_rules[0])
    assert created == {
        "ruleName": f"LabProbe STUN {rule['id']}",
        "src": "wan", "srcIp": "", "srcPort": str(rule["listenPort"]),
        "destIp": "192.168.5.46", "destPort": "443", "proto": "tcp",
    }

    for endpoint in ("203.0.113.9:20001", "203.0.113.9:28764"):
        service._remember_endpoint(rule["id"], {"publicEndpoint": endpoint})
        assert service.ensure_native_mapping(rule)["state"] == "ready"
        assert client.native_rules == [created]


def test_tcp_native_map_updates_only_when_the_selected_target_changes(tmp_path):
    client = _Client()
    service = StunService(_hub(tmp_path), client)
    old = service.clean_rule({"serviceType": "HTTPS", "targetIpv4": "192.168.5.46", "targetPort": 443})
    assert service.ensure_native_mapping(old)["state"] == "ready"
    updated = service.clean_rule({"targetIpv4": "192.168.5.47", "targetPort": 8443}, old)

    assert service.ensure_native_mapping(updated)["state"] == "ready"
    assert client.native_rules[0]["srcPort"] == str(old["listenPort"])
    assert client.native_rules[0]["destIp"] == "192.168.5.47"
    assert client.native_rules[0]["destPort"] == "8443"


def test_custom_target_port_is_preserved_until_service_is_explicitly_changed(tmp_path):
    service = StunService(_hub(tmp_path), _Client())

    http = service.clean_rule({"serviceType": "HTTP", "targetIpv4": "192.168.5.46", "targetPort": 9999})
    https = service.clean_rule({"serviceType": "HTTPS", "targetIpv4": "192.168.5.46", "targetPort": 9443})

    assert http["targetPort"] == 9999
    assert https["targetPort"] == 9443


def test_edit_preserves_enabled_false_and_can_clear_a_custom_name(tmp_path):
    service = StunService(_hub(tmp_path), _Client())
    old = service.clean_rule({
        "serviceType": "HTTP",
        "targetIpv4": "192.168.5.46",
        "targetPort": 9999,
        "name": "家庭 NAS",
        "enabled": True,
    })

    updated = service.clean_rule({"enabled": "false", "name": ""}, old)

    assert updated["enabled"] is False
    assert updated["name"] == "HTTP · 192.168.5.46:9999"


def test_protocol_change_reallocates_a_listen_port_that_conflicts_in_new_protocol(tmp_path):
    service = StunService(_hub(tmp_path), _Client())
    old = service.clean_rule({"serviceType": "HTTPS", "targetIpv4": "192.168.5.46", "targetPort": 9443})
    udp = {
        **service.clean_rule({"serviceType": "WireGuard", "targetIpv4": "192.168.5.47", "targetPort": 51820}),
        "listenPort": old["listenPort"],
    }
    service._save_rules([old, udp])

    updated = service.clean_rule({"serviceType": "OpenVPN", "transportProtocol": "UDP"}, old)

    assert updated["transportProtocol"] == "UDP"
    assert updated["listenPort"] != old["listenPort"]


def test_running_rule_name_only_save_does_not_touch_router_or_queue_reapply(tmp_path):
    _, router, service, rule, app = _running_rule(tmp_path)
    rule["stunServer"] = "stun.internal.example:3478"
    service._save_rules([rule])
    reads_before = (router.native_reads, router.firewall_reads)
    writes_before = list(router.rpc_calls)

    response = app.put(f"/api/stun/{rule['id']}", json={"name": "新的备注"})

    assert response.status_code == 200
    assert service._document()["rules"][0]["name"] == "新的备注"
    assert service._document()["rules"][0]["stunServer"] == "stun.internal.example:3478"
    assert (router.native_reads, router.firewall_reads) == reads_before
    assert router.rpc_calls == writes_before
    assert service._commands() == []


def test_target_port_change_updates_mapping_and_queues_exactly_one_upsert(tmp_path):
    _, router, service, rule, app = _running_rule(tmp_path)

    response = app.put(f"/api/stun/{rule['id']}", json={"targetPort": 8443})

    assert response.status_code == 200
    assert router.native_rules[0]["destPort"] == "8443"
    commands = service._commands()
    assert len(commands) == 1
    assert commands[0]["action"] == "upsert"
    assert commands[0]["payload"]["rule"]["targetPort"] == 8443


def test_target_ipv4_change_updates_mapping_and_queues_exactly_one_upsert(tmp_path):
    _, router, service, rule, app = _running_rule(tmp_path)

    response = app.put(f"/api/stun/{rule['id']}", json={"targetIpv4": "192.168.5.47"})

    assert response.status_code == 200
    assert router.native_rules[0]["destIp"] == "192.168.5.47"
    commands = service._commands()
    assert len(commands) == 1
    assert commands[0]["payload"]["rule"]["targetIpv4"] == "192.168.5.47"


def test_protocol_change_uses_controlled_reapply_and_one_command(tmp_path):
    _, router, service, rule, app = _running_rule(tmp_path, {
        "serviceType": "OpenVPN",
        "transportProtocol": "TCP",
        "targetIpv4": "192.168.5.46",
        "targetPort": 1194,
    })

    response = app.put(
        f"/api/stun/{rule['id']}",
        json={"serviceType": "OpenVPN", "transportProtocol": "UDP"},
    )

    assert response.status_code == 200
    assert router.native_rules[0]["proto"] == "udp"
    commands = service._commands()
    assert len(commands) == 1
    assert commands[0]["payload"]["rule"]["transportProtocol"] == "UDP"


def test_mapping_update_failure_restores_mapping_desired_and_commands(tmp_path):
    _, router, service, rule, app = _running_rule(tmp_path)
    desired_before = copy.deepcopy(service._document())
    commands_before = copy.deepcopy(service._commands())
    mapping_before = copy.deepcopy(router.native_rules)
    original_rpc = router.rpc
    fail_once = {"value": True}

    def fail_after_native_update(operation, module, payload):
        if operation == "devConfig.update" and module == "port_mapping" and fail_once["value"]:
            fail_once["value"] = False
            original_rpc(operation, module, payload)
            raise RuntimeError("router update interrupted")
        return original_rpc(operation, module, payload)

    router.rpc = fail_after_native_update
    response = app.put(f"/api/stun/{rule['id']}", json={"targetPort": 8443})

    assert response.status_code == 400
    assert "router update interrupted" in response.get_json()["error"]
    assert service._document() == desired_before
    assert service._commands() == commands_before
    assert router.native_rules == mapping_before


def test_desired_save_failure_restores_native_mapping(tmp_path):
    hub, router, service, rule, app = _running_rule(tmp_path)
    desired_before = copy.deepcopy(service._document())
    mapping_before = copy.deepcopy(router.native_rules)
    original_save = hub.save_json
    fail_once = {"value": True}

    def fail_new_desired(path, value):
        if Path(path) == service.rules_path and fail_once["value"] and value.get("revision") == desired_before["revision"] + 1:
            fail_once["value"] = False
            original_save(path, value)
            raise OSError("desired store unavailable")
        original_save(path, value)

    hub.save_json = fail_new_desired
    response = app.put(f"/api/stun/{rule['id']}", json={"targetPort": 8443})

    assert response.status_code == 400
    assert "desired store unavailable" in response.get_json()["error"]
    assert service._document() == desired_before
    assert service._commands() == []
    assert router.native_rules == mapping_before


def test_command_save_failure_restores_desired_and_native_mapping(tmp_path):
    hub, router, service, rule, app = _running_rule(tmp_path)
    desired_before = copy.deepcopy(hub.load_json(service.rules_path, {}))
    desired_before["transactionMarker"] = "preserve-exactly"
    hub.save_json(service.rules_path, copy.deepcopy(desired_before))
    commands_before = {"commands": [], "transactionMarker": "preserve-exactly"}
    hub.save_json(service.commands_path, copy.deepcopy(commands_before))
    mapping_before = copy.deepcopy(router.native_rules)
    original_save = hub.save_json
    fail_once = {"value": True}

    def fail_new_command(path, value):
        if Path(path) == service.commands_path and fail_once["value"]:
            fail_once["value"] = False
            original_save(path, value)
            raise OSError("command store unavailable")
        original_save(path, value)

    hub.save_json = fail_new_command
    response = app.put(f"/api/stun/{rule['id']}", json={"targetIpv4": "192.168.5.47"})

    assert response.status_code == 400
    assert "command store unavailable" in response.get_json()["error"]
    assert hub.load_json(service.rules_path, {}) == desired_before
    assert service._command_document() == commands_before
    assert router.native_rules == mapping_before


def test_create_command_failure_rolls_back_desired_and_native_mapping(tmp_path):
    hub = _hub(tmp_path)
    router = _Client()
    service = StunService(hub, router)
    service._save_rules([])
    service._save_commands([])
    hub.app.register_blueprint(create_stun_blueprint(hub, service))
    app = hub.app.test_client()
    desired_before = copy.deepcopy(service._document())
    commands_before = copy.deepcopy(service._command_document())
    original_save = hub.save_json
    fail_once = {"value": True}

    def fail_new_command(path, value):
        original_save(path, value)
        if Path(path) == service.commands_path and fail_once["value"]:
            fail_once["value"] = False
            raise OSError("command store unavailable")

    hub.save_json = fail_new_command
    response = app.post("/api/stun", json={
        "serviceType": "HTTPS",
        "targetIpv4": "192.168.5.46",
        "targetPort": 443,
        "name": "家庭 HTTPS",
    })

    assert response.status_code == 400
    assert service._document() == desired_before
    assert service._command_document() == commands_before
    assert router.native_rules == []


def test_stop_save_failure_restores_enabled_rule_and_native_mapping(tmp_path):
    hub, router, service, rule, app = _running_rule(tmp_path)
    desired_before = copy.deepcopy(service._document())
    mapping_before = copy.deepcopy(router.native_rules)
    original_save = hub.save_json
    fail_once = {"value": True}

    def fail_new_desired(path, value):
        original_save(path, value)
        if Path(path) == service.rules_path and fail_once["value"] and value.get("revision") == desired_before["revision"] + 1:
            fail_once["value"] = False
            raise OSError("desired store unavailable")

    hub.save_json = fail_new_desired
    response = app.post(f"/api/stun/{rule['id']}/stop")

    assert response.status_code == 409
    assert service._document() == desired_before
    assert router.native_rules == mapping_before


def test_delete_command_failure_restores_rule_mapping_and_history(tmp_path):
    hub, router, service, rule, app = _running_rule(tmp_path)
    service._remember_endpoint(rule["id"], {"publicEndpoint": "203.0.113.9:20001"})
    desired_before = copy.deepcopy(service._document())
    commands_before = copy.deepcopy(service._command_document())
    history_before = copy.deepcopy(service._history())
    mapping_before = copy.deepcopy(router.native_rules)
    original_save = hub.save_json
    fail_once = {"value": True}

    def fail_new_command(path, value):
        original_save(path, value)
        if Path(path) == service.commands_path and fail_once["value"]:
            fail_once["value"] = False
            raise OSError("command store unavailable")

    hub.save_json = fail_new_command
    response = app.delete(f"/api/stun/{rule['id']}")

    assert response.status_code == 409
    assert service._document() == desired_before
    assert service._command_document() == commands_before
    assert service._history() == history_before
    assert router.native_rules == mapping_before


def test_old_failed_ack_cannot_override_new_revision_sync_state(tmp_path):
    _, _, service, rule, app = _running_rule(tmp_path)
    first = app.put(f"/api/stun/{rule['id']}", json={"targetPort": 8443})
    assert first.status_code == 200
    delivered = app.get("/api/router/stun/commands?router=router").get_json()["commands"]
    old_command = delivered[0]

    second = app.put(f"/api/stun/{rule['id']}", json={"targetIpv4": "192.168.5.47"})
    assert second.status_code == 200
    current_revision = service._document()["revision"]
    assert current_revision > old_command["revision"]

    ack = app.post(
        "/api/router/stun/ack?router=router",
        json={"acks": [{"id": old_command["id"], "ok": False, "result": {"error": "old apply failed"}}]},
    )
    assert ack.status_code == 200
    assert service._document()["rules"][0]["targetIpv4"] == "192.168.5.47"
    assert service.rows()[0]["syncError"] == ""
    commands = service._commands()
    assert len(commands) == 1
    assert commands[0]["revision"] == current_revision


def test_runtime_rule_mismatch_cannot_report_ready_but_keeps_endpoint_history(tmp_path):
    hub, _, service, rule, _ = _running_rule(tmp_path)
    stale_rule = {**rule, "targetPort": 9443}
    hub.save_json(service.status_path, {
        "status": {"rules": [{
            "rule": stale_rule,
            "runtime": {
                "id": rule["id"],
                "state": "mapped",
                "publicEndpoint": "203.0.113.9:20001",
            },
        }]},
    })

    current = service.rows()[0]
    assert current["actualState"] == "mapping"
    assert current["runtime"]["publicEndpoint"] == "203.0.113.9:20001"


def test_status_reconciliation_reuses_same_command_id_for_same_revision(tmp_path):
    _, _, service, rule, app = _running_rule(tmp_path)
    payload = {"rules": []}

    assert app.post("/api/router/stun/status?router=router", json=payload).status_code == 200
    first = service._commands()
    assert len(first) == 1
    same_revision = service.queue(
        "stop",
        {"id": rule["id"]},
        revision=service._document()["revision"],
    )
    assert same_revision["id"] == first[0]["id"]
    assert app.post("/api/router/stun/status?router=router", json=payload).status_code == 200
    second = service._commands()

    assert len(second) == 1
    assert second[0]["id"] == first[0]["id"]
    assert second[0]["revision"] == service._document()["revision"]


def test_rows_expose_agent_and_native_mapping_errors_and_stop_disabled_runtime(tmp_path):
    service = StunService(_hub(tmp_path), _Client())
    rule = service.clean_rule({"serviceType": "HTTPS", "targetIpv4": "192.168.5.46", "targetPort": 9443})
    service._save_rules([rule])
    service.hub.save_json(service.status_path, {
        "status": {"rules": [{"rule": rule, "runtime": {"id": rule["id"], "state": "mapped", "publicEndpoint": "203.0.113.9:20001"}}]},
    })
    service._save_native_mapping_bindings({rule["id"]: {"state": "error", "message": "路由器拒绝写入"}})
    service._save_commands([{
        "id": "stun-cmd-failed",
        "action": "upsert",
        "payload": {"rule": {"id": rule["id"]}},
        "status": "failed",
        "result": {"error": "Agent 端口冲突"},
    }])

    current = service.rows()[0]
    assert current["actualState"] == "router_mapping_error"
    assert current["nativeMappingMessage"] == "路由器拒绝写入"
    assert current["syncError"] == "Agent 端口冲突"

    stopped = {**rule, "enabled": False}
    service._save_rules([stopped])
    assert service.rows()[0]["actualState"] == "stopped"


def test_command_log_keeps_active_commands_and_only_latest_terminal_records(tmp_path):
    service = StunService(_hub(tmp_path), _Client())
    terminal = [
        {"id": f"done-{index}", "status": "done", "payload": {"id": f"rule-{index}"}}
        for index in range(130)
    ]
    pending = {"id": "pending", "status": "pending", "payload": {"id": "rule-pending"}}

    compacted = service._compact_commands([*terminal, pending])

    assert len(compacted) == 101
    assert compacted[0]["id"] == "done-30"
    assert compacted[-1]["id"] == "pending"


def test_delete_removes_address_history_and_deleted_rule_history_is_not_readable(tmp_path):
    hub = _hub(tmp_path)
    service = StunService(hub, _Client())
    rule = service.clean_rule({"serviceType": "HTTPS", "targetIpv4": "192.168.5.46", "targetPort": 9443})
    service._save_rules([rule])
    service._remember_endpoint(rule["id"], {"publicEndpoint": "203.0.113.9:20001"})
    hub.app.register_blueprint(create_stun_blueprint(hub, service))
    client = hub.app.test_client()

    assert client.delete(f"/api/stun/{rule['id']}").status_code == 200
    assert rule["id"] not in service._history()
    assert client.get(f"/api/stun/{rule['id']}/addresses").status_code == 404


def test_udp_stun_uses_the_same_router_native_map_model(tmp_path):
    client = _Client()
    service = StunService(_hub(tmp_path), client)
    rule = service.clean_rule({"serviceType": "WireGuard", "targetIpv4": "192.168.5.47", "targetPort": 51820})

    assert rule["forwardMode"] == "router_native"
    assert service.ensure_native_mapping(rule)["state"] == "ready"
    assert client.native_rules[0]["proto"] == "udp"
    assert client.native_rules[0]["destIp"] == "192.168.5.47"
    assert client.native_rules[0]["destPort"] == "51820"


def test_legacy_relay_firewall_binding_refuses_to_overwrite_manual_changes(tmp_path):
    client = _Client()
    service = StunService(_hub(tmp_path), client)
    rule = service.clean_rule({"serviceType": "WireGuard", "targetIpv4": "192.168.5.46", "targetPort": 51820})

    rule["forwardMode"] = "relay_proxy"
    assert service.ensure_firewall(rule)["state"] == "ready"
    assert client.rules[0]["direction"] == "inbound"
    assert client.rules[0]["destPort"] == str(rule["listenPort"])
    client.rules[0]["destPort"] = "9443"
    assert service.ensure_firewall(rule)["state"] == "manual_change"


def test_wireguard_lan_firewall_uses_tunnel_source_and_lan_egress(tmp_path):
    client = _Client()
    service = StunService(_hub(tmp_path), client)
    rule = {
        "id": "wireguard-lan-labwg0",
        "firewallMode": "wireguard_lan_forward",
        "tunnelNetwork": "10.77.0.0/24",
        "transportProtocol": "ALL",
        "listenPort": 51820,
    }

    assert service.ensure_firewall(rule)["state"] == "ready"
    assert client.rules[0] == {
        "ruleName": "LabProbe WireGuard wireguard-lan-labwg0",
        "direction": "forward",
        "ipVersion": "ipv4",
        "proto": "all",
        "srcIP": "10.77.0.0/24",
        "destIP": "",
        "srcPort": "",
        "destPort": "",
        "target": "ACCEPT",
        "enable": "1",
        "ipv6SuffixSrc": "",
        "ipv6SuffixDest": "",
        "inIface": "",
        "outIface": "lan",
        "uuid": "fw-1",
    }

    client.rules[0]["outIface"] = "wan"
    assert service.ensure_firewall(rule)["state"] == "manual_change"
    service.remove_firewall(rule["id"])
    assert client.rules[0]["uuid"] == "fw-1"


def test_wireguard_lan_does_not_adopt_same_name_unowned_rule(tmp_path):
    client = _Client()
    client.rules.append({
        "ruleName": "LabProbe WireGuard wireguard-lan-labwg0",
        "uuid": "manual-1",
        "direction": "forward",
    })
    service = StunService(_hub(tmp_path), client)
    rule = {
        "id": "wireguard-lan-labwg0",
        "firewallMode": "wireguard_lan_forward",
        "tunnelNetwork": "10.77.0.0/24",
        "transportProtocol": "ALL",
        "listenPort": 51820,
    }

    result = service.ensure_firewall(rule)
    assert result["state"] == "manual_change"
    assert [row["uuid"] for row in client.rules] == ["manual-1"]


def test_relay_stun_startup_does_not_block_the_agent_control_loop():
    source = (Path(__file__).parents[1] / "labrelay" / "src" / "main.rs").read_text(encoding="utf-8")

    assert "confirm_stun_startup(&shared, Duration::from_secs(30))" not in source
    assert "Duration::from_secs(if is_stun_upsert { 70 } else { 8 })" not in source
    assert 'let startup_state = if rule.kind == "stun" { "mapping" } else { "running" };' in source
    assert "pending_transaction.take().is_some()" in source
    assert "STUN UDP 响应超时，正在重试" in source
    assert "STUN 绑定响应事务不匹配" in source
