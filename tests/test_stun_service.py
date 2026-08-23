from pathlib import Path
from types import SimpleNamespace
import threading

from flask import Flask

from stun_service import StunService


class _Cache:
    def clear(self, _prefix):
        pass


class _Client:
    def __init__(self):
        self.write_lock = threading.RLock()
        self.cache = _Cache()
        self.rules = []

    def firewall(self, _force=False):
        return {"list": [dict(row) for row in self.rules], "maxLen": 20}

    def rpc(self, operation, module, payload):
        assert module == "ip_firewall"
        if operation == "devConfig.add":
            for row in payload["list"]:
                self.rules.append({**row, "uuid": f"fw-{len(self.rules) + 1}"})
        elif operation == "devConfig.del":
            self.rules = [row for row in self.rules if row["uuid"] not in payload["uuid"]]
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


def test_address_history_retains_only_latest_three_unique_endpoints(tmp_path):
    service = StunService(_hub(tmp_path), _Client())
    for port in (20001, 20002, 20003, 20004):
        service._remember_endpoint("stun-1", {"publicEndpoint": f"203.0.113.9:{port}", "mappingUpdatedAt": port})

    rows = service._history()["stun-1"]
    assert [row["endpoint"] for row in rows] == ["203.0.113.9:20004", "203.0.113.9:20003", "203.0.113.9:20002"]


def test_firewall_is_created_through_router_controller_and_manual_change_pauses_it(tmp_path):
    client = _Client()
    service = StunService(_hub(tmp_path), client)
    rule = service.clean_rule({"serviceType": "HTTPS", "targetIpv4": "192.168.5.46", "targetPort": 443})

    assert service.ensure_firewall(rule)["state"] == "ready"
    assert client.rules[0]["direction"] == "inbound"
    assert client.rules[0]["destPort"] == str(rule["listenPort"])
    client.rules[0]["destPort"] = "9443"
    assert service.ensure_firewall(rule)["state"] == "manual_change"
