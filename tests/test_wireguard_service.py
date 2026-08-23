import base64
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask

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
