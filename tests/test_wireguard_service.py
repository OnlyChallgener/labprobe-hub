import base64
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest
from flask import Flask

import wireguard_service as wireguard_module
from wireguard_service import WireGuardService, install_wireguard_service


PUBLIC_KEY = base64.b64encode(bytes(range(32))).decode()


class _StunLifecycleStub:
    def __init__(self):
        self.ensure_calls = []
        self.remove_calls = []

    def ensure_firewall(self, rule):
        self.ensure_calls.append(dict(rule))
        return {"state": "ready", "uuid": f"uuid-{rule['id']}"}

    def remove_firewall(self, rule_id):
        self.remove_calls.append(rule_id)


def _hub(tmp_path):
    saved = {}
    stun_lifecycle = _StunLifecycleStub()

    saved[Path(tmp_path) / "stun_rules.json"] = {
        "revision": 1,
        "rules": [{
            "id": "stun-wireguard",
            "kind": "stun",
            "enabled": True,
            "transportProtocol": "UDP",
            "forwardMode": "router_native",
            "targetIpv4": "192.168.5.1",
            "targetPort": 51820,
        }],
    }

    def load(path, default=None):
        return saved.get(Path(path), default)

    def save(path, value):
        saved[Path(path)] = value

    return SimpleNamespace(
        DATA_DIR=tmp_path,
        app=Flask(__name__),
        load_json=load,
        save_json=save,
        check_app_token=lambda: True,
        check_read_token=lambda: True,
        check_hook_token=lambda: True,
        _portmap_router_name=lambda: "Router",
        STUN_SERVICE=stun_lifecycle,
        _stun_lifecycle=stun_lifecycle,
        _saved=saved,
    )


def _server():
    return {
        "expectedRevision": 0,
        "interfaceName": "labwg0",
        "address": "10.77.0.1/24",
        "listenPort": 51820,
        "enabled": True,
        "peers": [{
            "id": "phone",
            "name": "Phone",
            "publicKey": PUBLIC_KEY,
            "allowedIps": ["10.77.0.2/32"],
            "persistentKeepaliveSeconds": 25,
        }],
        "endpointProfiles": [
            {
                "id": "ddns-primary",
                "endpointSource": "ddns",
                "hostname": "wg.example.test",
                "port": 51820,
            },
            {
                "id": "stun-fallback",
                "endpointSource": "stun",
                "stunRuleId": "stun-wireguard",
                "port": 24567,
            },
        ],
    }


def test_hub_rejects_private_and_preshared_keys(tmp_path):
    service = WireGuardService(_hub(tmp_path))
    payload = _server()
    payload["privateKey"] = "must-never-reach-hub"
    with pytest.raises(ValueError, match="私钥"):
        service.put(payload, 0)

    payload = _server()
    payload["peers"][0]["presharedKey"] = "must-never-reach-hub"
    with pytest.raises(ValueError, match="私钥"):
        service.put(payload, 0)


def test_ddns_and_stun_have_independent_endpoint_revisions(tmp_path):
    hub = _hub(tmp_path)
    service = WireGuardService(hub)
    saved = service.put(_server(), 0)
    assert saved["revision"] == 1
    assert saved["endpointRevision"] == 0
    assert saved["server"]["endpointProfiles"][0]["bindingMode"] == "fixed-port"
    assert saved["server"]["endpointProfiles"][1]["bindingMode"] == "router-native"
    assert saved["server"]["endpointProfiles"][1]["forwardMode"] == "router_native"
    assert saved["server"]["endpointProfiles"][1]["localTargetPort"] == 51820
    assert hub._stun_lifecycle.ensure_calls[0]["id"] == "wireguard-ddns-ddns-primary"
    assert hub._stun_lifecycle.ensure_calls[0]["listenPort"] == 51820
    lan_calls = [row for row in hub._stun_lifecycle.ensure_calls if row["id"] == "wireguard-lan-labwg0"]
    assert lan_calls == [{
        "id": "wireguard-lan-labwg0",
        "kind": "wireguard-lan-forward",
        "firewallMode": "wireguard_lan_forward",
        "enabled": True,
        "tunnelNetwork": "10.77.0.0/24",
        "transportProtocol": "ALL",
        "listenPort": 51820,
    }]

    ddns = service.update_endpoint(
        "ddns-primary", "ddns", "ddns:ddns-primary", "wg.example.test", 0
    )
    stun = service.update_endpoint(
        "stun-fallback", "stun", "stun:stun-wireguard", "203.0.113.8:24567", 0
    )
    current = service.document()
    assert current["revision"] == 1
    assert current["endpointRevision"] == 2
    assert ddns["endpointRevision"] == 1
    assert stun["endpointRevision"] == 1
    assert ddns["resolvedEndpoint"] == "wg.example.test:51820"
    assert stun["resolvedEndpoint"] == "203.0.113.8:24567"
    endpoint_commands = [row for row in service.commands() if row["action"] == "endpoint"]
    assert [row["revisionScope"] for row in endpoint_commands] == [
        "endpoint:ddns-primary",
        "endpoint:stun-fallback",
    ]


def test_endpoint_updater_cannot_write_a_profile_owned_by_other_source(tmp_path):
    service = WireGuardService(_hub(tmp_path))
    service.put(_server(), 0)
    with pytest.raises(ValueError, match="does not own"):
        service.update_endpoint(
            "ddns-primary", "stun", "stun:stun-wireguard", "203.0.113.8:24567", 0
        )
    with pytest.raises(ValueError, match="owner does not match"):
        service.update_endpoint(
            "ddns-primary", "ddns", "ddns:some-other-profile", "wg.example.test", 0
        )
    with pytest.raises(ValueError, match="expectedEndpointRevision is required"):
        service.update_endpoint(
            "ddns-primary", "ddns", "ddns:ddns-primary", "wg.example.test", None
        )


@pytest.mark.parametrize(
    "change, message",
    [
        ({"enabled": False}, "必须已启用"),
        ({"transportProtocol": "TCP"}, "必须关联 UDP"),
        ({"targetPort": 443}, "目标端口"),
        ({"forwardMode": "relay"}, "路由器原生"),
    ],
)
def test_stun_profile_requires_enabled_udp_router_native_mapping(tmp_path, change, message):
    hub = _hub(tmp_path)
    rule_path = Path(tmp_path) / "stun_rules.json"
    hub._saved[rule_path]["rules"][0].update(change)
    service = WireGuardService(hub)
    with pytest.raises(ValueError, match=message):
        service.put(_server(), 0)


def test_stun_profile_requires_existing_rule(tmp_path):
    hub = _hub(tmp_path)
    hub._saved[Path(tmp_path) / "stun_rules.json"]["rules"] = []
    service = WireGuardService(hub)
    with pytest.raises(ValueError, match="关联规则不存在"):
        service.put(_server(), 0)


def test_ddns_firewall_is_removed_when_profile_deleted_or_server_deleted(tmp_path):
    hub = _hub(tmp_path)
    service = WireGuardService(hub)
    service.put(_server(), 0)
    changed = _server()
    changed["endpointProfiles"] = [changed["endpointProfiles"][1]]
    service.put(changed, 1)
    assert "wireguard-ddns-ddns-primary" in hub._stun_lifecycle.remove_calls

    service.delete(2)
    assert hub._stun_lifecycle.remove_calls.count("wireguard-ddns-ddns-primary") == 1

    hub2 = _hub(tmp_path / "delete")
    service2 = WireGuardService(hub2)
    service2.put(_server(), 0)
    service2.delete(1)
    assert "wireguard-ddns-ddns-primary" in hub2._stun_lifecycle.remove_calls
    assert "wireguard-lan-labwg0" in hub2._stun_lifecycle.remove_calls


def test_lan_forward_status_warns_when_router_ip_forward_is_not_readable(tmp_path):
    hub = _hub(tmp_path)
    service = WireGuardService(hub)
    service.put(_server(), 0)

    status = service.lan_forward_status(service.document()["server"])
    assert status["firewall"]["sourceNetwork"] == "10.77.0.0/24"
    assert status["firewall"]["direction"] == "forward"
    assert status["firewall"]["outIface"] == "lan"
    assert status["ipForward"]["state"] == "unknown"
    assert "未提供可读" in status["ipForward"]["warning"]


def test_manual_endpoint_is_immutable_to_automatic_updaters(tmp_path):
    service = WireGuardService(_hub(tmp_path))
    payload = _server()
    payload["endpointProfiles"].append({
        "id": "manual-office",
        "endpointSource": "manual",
        "resolvedEndpoint": "198.51.100.20:51820",
        "port": 51820,
    })
    saved = service.put(payload, 0)
    manual = saved["server"]["endpointProfiles"][2]
    assert manual["owner"] == ""
    assert manual["resolvedEndpoint"] == "198.51.100.20:51820"
    with pytest.raises(ValueError, match="manual endpoint profile"):
        service.update_endpoint(
            "manual-office", "ddns", "ddns:manual-office", "other.example.test", 0
        )
    assert service.document()["server"]["endpointProfiles"][2] == manual


def test_expected_revision_and_delete_tombstone_prevent_resurrection(tmp_path):
    service = WireGuardService(_hub(tmp_path))
    service.put(_server(), 0)
    with pytest.raises(RuntimeError, match="revision conflict"):
        service.put(_server(), 0)
    deleted = service.delete(1)
    assert deleted["revision"] == 2
    assert deleted["server"] is None
    assert deleted["tombstone"]["revision"] == 2
    command = service.commands()[-1]
    assert command["action"] == "delete"
    assert command["revision"] == 2
    assert command["payload"]["tombstone"] is True


def test_agent_status_rejects_any_secret_material(tmp_path):
    hub = _hub(tmp_path)
    install_wireguard_service(hub)
    client = hub.app.test_client()
    response = client.post(
        "/api/router/wireguard/status?router=Router",
        json={"revision": 1, "privateKey": "never-store-this"},
    )
    assert response.status_code == 400
    assert not (tmp_path / "wireguard_agent_status.json") in hub._saved


def test_put_succeeds_and_queues_apply_command_when_firewall_fails(tmp_path):
    hub = _hub(tmp_path)
    class _FailingStunLifecycle:
        def ensure_firewall(self, rule):
            raise RuntimeError("防火墙规则创建失败")
        def remove_firewall(self, rule_id):
            raise RuntimeError("防火墙规则删除失败")

    hub.STUN_SERVICE = _FailingStunLifecycle()
    hub._stun_lifecycle = hub.STUN_SERVICE
    service = WireGuardService(hub)

    saved = service.put(_server(), 0)
    assert saved["revision"] == 1
    assert saved["server"]["interfaceName"] == "labwg0"
    assert service.document()["server"]["interfaceName"] == "labwg0"

    commands = service.commands()
    assert len(commands) == 1
    assert commands[0]["action"] == "apply"
    assert commands[0]["revision"] == 1
    assert commands[0]["payload"]["server"]["interfaceName"] == "labwg0"


def test_delete_succeeds_and_queues_delete_command_when_firewall_removal_fails(tmp_path):
    hub = _hub(tmp_path)
    class _FailingStunLifecycle:
        def ensure_firewall(self, rule):
            return {"state": "ready"}
        def remove_firewall(self, rule_id):
            raise RuntimeError("防火墙规则删除失败")

    hub.STUN_SERVICE = _FailingStunLifecycle()
    hub._stun_lifecycle = hub.STUN_SERVICE
    service = WireGuardService(hub)
    service.put(_server(), 0)

    deleted = service.delete(1)
    assert deleted["revision"] == 2
    assert deleted["server"] is None
    assert deleted["tombstone"]["interfaceName"] == "labwg0"

    commands = service.commands()
    assert commands[-1]["action"] == "delete"
    assert commands[-1]["revision"] == 2
    assert commands[-1]["payload"]["tombstone"] is True


def test_blueprint_put_returns_200_when_firewall_fails(tmp_path):
    hub = _hub(tmp_path)
    class _FailingStunLifecycle:
        def ensure_firewall(self, rule):
            raise RuntimeError("防火墙规则创建失败")
        def remove_firewall(self, rule_id):
            raise RuntimeError("防火墙规则删除失败")

    hub.STUN_SERVICE = _FailingStunLifecycle()
    hub._stun_lifecycle = hub.STUN_SERVICE
    install_wireguard_service(hub)
    client = hub.app.test_client()

    response = client.put(
        "/api/wireguard/server",
        json=_server(),
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["ok"] is True
    assert body["revision"] == 1
    assert body["server"]["interfaceName"] == "labwg0"
    assert "lanForwarding" in body


def test_wireguard_provisioning_succeeds_without_stun_service_or_firewall_lifecycle(tmp_path):
    hub = _hub(tmp_path)
    hub.STUN_SERVICE = None
    hub._stun_lifecycle = None
    service = WireGuardService(hub)

    saved = service.put(_server(), 0)
    assert saved["revision"] == 1
    assert saved["server"]["interfaceName"] == "labwg0"
    assert len(service.commands()) == 1
    assert service.commands()[0]["action"] == "apply"

    deleted = service.delete(1)
    assert deleted["revision"] == 2
    assert deleted["server"] is None
    assert service.commands()[-1]["action"] == "delete"


def test_listen_port_customization_and_ddns_endpoint_sync(tmp_path):
    hub = _hub(tmp_path)
    service = WireGuardService(hub)
    server_data = _server()
    server_data["listenPort"] = 40000
    server_data["endpointProfiles"] = [
        p for p in server_data["endpointProfiles"] if p["endpointSource"] == "ddns"
    ]

    saved = service.put(server_data, 0)
    assert saved["server"]["listenPort"] == 40000

    ddns_profile = next(
        p for p in saved["server"]["endpointProfiles"] if p["endpointSource"] == "ddns"
    )
    assert ddns_profile["port"] == 40000

    # Verify apply command payload contains 40000
    command = service.commands()[0]
    assert command["payload"]["server"]["listenPort"] == 40000

    # Updating DDNS endpoint formats with the customized listenPort 40000
    updated_ddns = service.update_endpoint(
        "ddns-primary", "ddns", "ddns:ddns-primary", "wg.example.test", 0
    )
    assert updated_ddns["resolvedEndpoint"] == "wg.example.test:40000"
    assert updated_ddns["endpointRevision"] == 1


def test_listen_port_customization_updates_stun_target_port(tmp_path):
    hub = _hub(tmp_path)
    service = WireGuardService(hub)
    service.put(_server(), 0)

    save_order = []
    original_save = hub.save_json

    def tracking_save(path, value):
        save_order.append(Path(path).name)
        original_save(path, value)

    hub.save_json = tracking_save

    # Now update listenPort to 40000
    server_data = _server()
    server_data["listenPort"] = 40000
    saved = service.put(server_data, 1)
    assert saved["server"]["listenPort"] == 40000

    # Verify stun_rules.json rule stun-wireguard was updated with targetPort = 40000
    stun_rules_path = Path(tmp_path) / "stun_rules.json"
    updated_stun_rules = hub.load_json(stun_rules_path, {})
    rule = updated_stun_rules["rules"][0]
    assert rule["targetPort"] == 40000
    assert save_order.index("wireguard_server.json") < save_order.index("wireguard_commands.json")
    assert save_order.index("wireguard_commands.json") < save_order.index("stun_rules.json")


def test_failed_validation_does_not_mutate_stun_target_port(tmp_path):
    hub = _hub(tmp_path)
    service = WireGuardService(hub)
    service.put(_server(), 0)

    invalid = _server()
    invalid["listenPort"] = 40000
    invalid["mtu"] = 1200

    with pytest.raises(ValueError, match="MTU"):
        service.put(invalid, 1)

    stun_document = hub.load_json(Path(tmp_path) / "stun_rules.json", {})
    assert stun_document["rules"][0]["targetPort"] == 51820
    assert service.document()["revision"] == 1
    assert len(service.commands()) == 1


def test_command_save_failure_restores_previous_desired_document(tmp_path):
    hub = _hub(tmp_path)
    service = WireGuardService(hub)
    service.put(_server(), 0)
    original_save = hub.save_json

    def failing_command_save(path, value):
        if Path(path) == service.commands_path:
            raise OSError("command store unavailable")
        original_save(path, value)

    hub.save_json = failing_command_save

    changed = _server()
    changed["listenPort"] = 40000
    with pytest.raises(OSError, match="command store unavailable"):
        service.put(changed, 1)

    restored = service.document()
    assert restored["revision"] == 1
    assert restored["server"]["listenPort"] == 51820
    assert len(service.commands()) == 1
    stun_document = hub.load_json(Path(tmp_path) / "stun_rules.json", {})
    assert stun_document["rules"][0]["targetPort"] == 51820


def test_agent_status_cannot_queue_rolled_back_revision_during_command_save_failure(tmp_path):
    hub = _hub(tmp_path)
    service = install_wireguard_service(hub)
    service.put(_server(), 0)
    original_save = hub.save_json
    command_save_entered = threading.Event()
    allow_command_failure = threading.Event()
    failure_pending = {"value": True}
    put_errors = []

    def fail_once_after_status_can_arrive(path, value):
        if Path(path) == service.commands_path and failure_pending["value"]:
            failure_pending["value"] = False
            command_save_entered.set()
            assert allow_command_failure.wait(timeout=2)
            raise OSError("command store unavailable")
        original_save(path, value)

    hub.save_json = fail_once_after_status_can_arrive
    changed = _server()
    changed["listenPort"] = 40000

    def save_changed_server():
        try:
            service.put(changed, 1)
        except Exception as error:
            put_errors.append(error)

    put_thread = threading.Thread(target=save_changed_server)
    put_thread.start()
    assert command_save_entered.wait(timeout=2)

    status_started = threading.Event()
    status_response = []

    def report_old_applied_revision():
        status_started.set()
        with hub.app.test_client() as client:
            status_response.append(client.post("/api/router/wireguard/status?router=Router", json={"revision": 1}))

    status_thread = threading.Thread(target=report_old_applied_revision)
    status_thread.start()
    assert status_started.wait(timeout=2)
    allow_command_failure.set()
    put_thread.join(timeout=2)
    status_thread.join(timeout=2)

    assert not put_thread.is_alive()
    assert not status_thread.is_alive()
    assert len(put_errors) == 1
    assert isinstance(put_errors[0], OSError)
    assert status_response[0].status_code == 200
    assert service.document()["revision"] == 1
    assert all(command["revision"] != 2 for command in service.commands())
    assert all(command["status"] != "pending" or command["revision"] == 1 for command in service.commands())


def test_stun_target_port_save_failure_rolls_back_wireguard_command_and_desired(tmp_path):
    hub = _hub(tmp_path)
    service = install_wireguard_service(hub)
    service.put(_server(), 0)
    commands_before = service.commands()
    original_save = hub.save_json

    def failing_stun_save(path, value):
        if Path(path) == Path(tmp_path) / "stun_rules.json":
            raise OSError("STUN document unavailable")
        original_save(path, value)

    hub.save_json = failing_stun_save
    changed = _server()
    changed["expectedRevision"] = 1
    changed["listenPort"] = 40000

    client = hub.app.test_client()
    response = client.put("/api/wireguard/server", json=changed)
    assert response.status_code == 409
    assert response.get_json()["ok"] is False
    assert "STUN targetPort 同步失败" in response.get_json()["error"]

    restored = service.document()
    assert restored["revision"] == 1
    assert restored["server"]["listenPort"] == 51820
    assert service.commands() == commands_before
    assert all(command["revision"] != 2 for command in service.commands())
    stun_document = hub.load_json(Path(tmp_path) / "stun_rules.json", {})
    assert stun_document["rules"][0]["targetPort"] == 51820
    delivered = client.get("/api/router/wireguard/commands?router=Router").get_json()["commands"]
    assert all(command["revision"] != 2 for command in delivered)


def test_failed_apply_command_reuses_one_id_with_bounded_backoff(tmp_path, monkeypatch):
    clock = {"now": 1_000}
    monkeypatch.setattr(wireguard_module, "_now", lambda: clock["now"])

    hub = _hub(tmp_path)
    service = install_wireguard_service(hub)
    client = hub.app.test_client()
    service.put(_server(), 0)
    command_id = service.commands()[0]["id"]
    delays = [15, 30, 60, 120, 120]

    for attempt, delay in enumerate(delays, start=1):
        delivered = client.get("/api/router/wireguard/commands?router=Router").get_json()["commands"]
        assert [row["id"] for row in delivered] == [command_id]

        ack = client.post(
            "/api/router/wireguard/ack?router=Router",
            json={"acks": [{"id": command_id, "ok": False, "result": {"ok": False, "error": "apply failed"}}]},
        )
        assert ack.status_code == 200

        failed = service.commands()
        assert len(failed) == 1
        assert failed[0]["status"] == "failed"
        assert failed[0]["attempts"] == attempt
        assert failed[0]["retryAfterEpoch"] == clock["now"] + delay

        client.post("/api/router/wireguard/status?router=Router", json={"revision": 0})
        assert len(service.commands()) == 1
        assert service.commands()[0]["status"] == "failed"

        if attempt < len(delays):
            clock["now"] = failed[0]["retryAfterEpoch"] - 1
            client.post("/api/router/wireguard/status?router=Router", json={"revision": 0})
            assert service.commands()[0]["status"] == "failed"

            clock["now"] += 1
            client.post("/api/router/wireguard/status?router=Router", json={"revision": 0})
            assert len(service.commands()) == 1
            assert service.commands()[0]["status"] == "pending"
            client.post("/api/router/wireguard/status?router=Router", json={"revision": 0})
            assert len(service.commands()) == 1
            assert service.commands()[0]["id"] == command_id

    clock["now"] += 10_000
    client.post("/api/router/wireguard/status?router=Router", json={"revision": 0})
    terminal = service.commands()
    assert len(terminal) == 1
    assert terminal[0]["id"] == command_id
    assert terminal[0]["status"] == "failed"
    assert terminal[0]["attempts"] == 5


def test_successful_apply_command_flow_remains_terminal(tmp_path):
    hub = _hub(tmp_path)
    service = install_wireguard_service(hub)
    client = hub.app.test_client()
    service.put(_server(), 0)

    delivered = client.get("/api/router/wireguard/commands?router=Router").get_json()["commands"]
    command_id = delivered[0]["id"]
    response = client.post(
        "/api/router/wireguard/ack?router=Router",
        json={"acks": [{"id": command_id, "ok": True, "result": {"ok": True, "revision": 1}}]},
    )
    assert response.status_code == 200

    client.post("/api/router/wireguard/status?router=Router", json={"revision": 1})
    assert client.get("/api/router/wireguard/commands?router=Router").get_json()["commands"] == []
    rows = service.commands()
    assert len(rows) == 1
    assert rows[0]["status"] == "done"
    assert "retryAfterEpoch" not in rows[0]


def test_old_config_without_listen_port_defaults_to_51820(tmp_path):
    hub = _hub(tmp_path)
    service = WireGuardService(hub)
    server_data = _server()
    del server_data["listenPort"]

    saved = service.put(server_data, 0)
    assert saved["server"]["listenPort"] == 51820


def test_invalid_listen_port_rejected(tmp_path):
    hub = _hub(tmp_path)
    service = WireGuardService(hub)
    server_data = _server()
    server_data["listenPort"] = 70000

    with pytest.raises(ValueError, match="WireGuard UDP 监听端口无效"):
        service.put(server_data, 0)


def test_blueprint_post_method_supported_as_alias(tmp_path):
    hub = _hub(tmp_path)
    service = install_wireguard_service(hub)
    client = hub.app.test_client()

    response = client.post(
        "/api/wireguard/server",
        json={"listenPort": 51826, "mtu": 1400, "enabled": True},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["server"]["listenPort"] == 51826
    assert data["server"]["mtu"] == 1400
    assert data["server"]["enabled"] is True


def test_server_toggle_enabled_state(tmp_path):
    hub = _hub(tmp_path)
    service = WireGuardService(hub)
    saved = service.put(_server(), 0)
    assert saved["server"]["enabled"] is True

    # Disable the server
    disabled = service.put({"enabled": False}, 1)
    assert disabled["server"]["enabled"] is False
    assert disabled["server"]["listenPort"] == 51820

    # Verify apply command was queued with enabled: False
    commands = service.commands()
    assert len(commands) == 1
    latest_cmd = commands[0]
    assert latest_cmd["action"] == "apply"
    assert latest_cmd["payload"]["server"]["enabled"] is False





