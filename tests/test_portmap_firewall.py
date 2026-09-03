import copy
import threading
from pathlib import Path
from types import SimpleNamespace

import hub
from portmap_firewall import OWNER, PortMapFirewallService


class _Client:
    def __init__(self):
        self.rows = []
        self.next_id = 1
        self.write_lock = threading.RLock()
        self.cache = SimpleNamespace(clear=lambda *_args, **_kwargs: None)

    def firewall(self, _force=False):
        return {"list": copy.deepcopy(self.rows), "maxLen": 20}

    def rpc(self, method, module, payload):
        assert module == "ip_firewall"
        if method == "devConfig.add":
            for source in payload["list"]:
                row = copy.deepcopy(source)
                row["uuid"] = f"fw-{self.next_id}"
                self.next_id += 1
                self.rows.append(row)
        elif method == "devConfig.update":
            for source in payload["list"]:
                index = next(i for i, row in enumerate(self.rows) if row["uuid"] == source["uuid"])
                self.rows[index] = copy.deepcopy(source)
        elif method == "devConfig.del":
            uuids = set(payload["uuid"])
            self.rows = [row for row in self.rows if row.get("uuid") not in uuids]
        return {"ok": True}


class _Hub:
    def __init__(self, tmp_path, client):
        self.DATA_DIR = tmp_path
        self.saved = {}

    def load_json(self, path, default):
        return copy.deepcopy(self.saved.get(Path(path), default))

    def save_json(self, path, value):
        self.saved[Path(path)] = copy.deepcopy(value)


def _rule(**changes):
    return {
        "id": "nas-https",
        "enabled": True,
        "listenPort": 20001,
        "transportProtocol": "TCP",
        **changes,
    }


def test_portmap_firewall_is_owned_persistent_ipv6_input_only(tmp_path):
    client = _Client()
    service = PortMapFirewallService(_Hub(tmp_path, client), client)

    result = service.ensure(_rule())

    assert result["state"] == "ready"
    assert service.cached("nas-https")["owner"] == OWNER
    assert client.rows == [{
        "ruleName": "LabProbe PortMap nas-https",
        "direction": "inbound",
        "ipVersion": "ipv6",
        "proto": "tcp",
        "srcIP": "",
        "destIP": "",
        "srcPort": "",
        "destPort": "20001",
        "target": "ACCEPT",
        "enable": "1",
        "ipv6SuffixSrc": "",
        "ipv6SuffixDest": "",
        "inIface": "wan",
        "outIface": "",
        "uuid": "fw-1",
    }]
    assert "forward" not in client.rows[0]["direction"]

    service.remove("nas-https")
    assert client.rows == []
    assert service.cached("nas-https")["state"] == "missing"


def test_portmap_firewall_never_adopts_or_deletes_unknown_same_name(tmp_path):
    client = _Client()
    manual = PortMapFirewallService.expected(_rule())
    manual["uuid"] = "manual-1"
    client.rows.append(manual)
    service = PortMapFirewallService(_Hub(tmp_path, client), client)

    result = service.ensure(_rule())

    assert result["state"] == "manual_change"
    service.remove("nas-https")
    assert client.rows == [manual]


def test_portmap_firewall_snapshot_restores_deleted_owned_rule(tmp_path):
    client = _Client()
    service = PortMapFirewallService(_Hub(tmp_path, client), client)
    service.ensure(_rule())
    snapshot = service.snapshot("nas-https")

    service.remove("nas-https")
    service.restore("nas-https", snapshot)

    assert len(client.rows) == 1
    assert client.rows[0]["destPort"] == "20001"
    assert service.cached("nas-https")["state"] == "ready"


def test_router_self_is_a_distinct_canonical_portmap_target():
    ipv4 = hub._clean_portmap_rule({
        "id": "router-ssh",
        "name": "路由器 SSH",
        "enabled": True,
        "mode": "6to4",
        "listenPort": 20001,
        "targetType": "router_self",
        "targetPort": 22,
        "transportProtocol": "TCP",
    })
    assert ipv4["targetType"] == "router_self"
    assert ipv4["targetMode"] == "ipv4"
    assert ipv4["targetIpv4"] == "127.0.0.1"

    ipv6 = hub._clean_portmap_rule({**ipv4, "mode": "6to6"}, ipv4)
    assert ipv6["targetType"] == "router_self"
    assert ipv6["targetMode"] == "ipv6_full"
    assert ipv6["targetIpv6"] == "::1"


def test_relay_source_keeps_router_self_out_of_lan_route_validation():
    source = (Path(__file__).parents[1] / "labrelay" / "src" / "main.rs").read_text(encoding="utf-8")
    assert 'if rule.target_type == "router_self"' in source
    assert "IpAddr::V4(Ipv4Addr::LOCALHOST)" in source
    assert "IpAddr::V6(Ipv6Addr::LOCALHOST)" in source
