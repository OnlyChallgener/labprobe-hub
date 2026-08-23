from pathlib import Path
from types import SimpleNamespace
import threading

from flask import Flask

from stun_service import DEFAULT_STUN_TCP_SERVER, StunService


class _Cache:
    def clear(self, _prefix):
        pass


class _Client:
    def __init__(self):
        self.write_lock = threading.RLock()
        self.cache = _Cache()
        self.rules = []
        self.native_rules = []

    def firewall(self, _force=False):
        return {"list": [dict(row) for row in self.rules], "maxLen": 20}

    def native_port_mapping(self, _force=False):
        return {"portMapping": [dict(row) for row in self.native_rules]}

    def rpc(self, operation, module, payload):
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
    )


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
