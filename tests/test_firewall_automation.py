import copy
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from router.firewall_automation import FirewallAutomationService


class _Cache:
    def clear(self, _prefix):
        return None


class _Client:
    def __init__(self, rules):
        self.rules = copy.deepcopy(rules)
        self.calls = []
        self.write_lock = threading.RLock()
        self.cache = _Cache()

    def firewall(self, _force=False):
        return {"list": copy.deepcopy(self.rules), "maxRules": 20}

    def rpc(self, method, module, data):
        self.calls.append((method, module, copy.deepcopy(data)))
        assert method == "devConfig.update"
        assert module == "ip_firewall"
        payload = copy.deepcopy(data["list"][0])
        index = next(i for i, row in enumerate(self.rules) if row["uuid"] == payload["uuid"])
        self.rules[index] = payload
        return {"ok": True}


def _load_json(path, default):
    value = Path(path)
    return json.loads(value.read_text(encoding="utf-8")) if value.exists() else copy.deepcopy(default)


def _save_json(path, data):
    value = Path(path)
    value.parent.mkdir(parents=True, exist_ok=True)
    value.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def _hub(tmp_path, devices):
    state_path = tmp_path / "state.json"
    devices_path = tmp_path / "devices.json"
    portmap_path = tmp_path / "portmaps.json"
    portmap_status_path = tmp_path / "portmap_status.json"
    _save_json(state_path, {"router": {"name": "Router"}})
    _save_json(devices_path, {"online": devices})
    return SimpleNamespace(
        DATA_DIR=tmp_path,
        STATE_FILE=state_path,
        DEVICES_FILE=devices_path,
        PORTMAP_ROUTER_STATUS_FILE=portmap_status_path,
        ROUTER_DASHBOARD_LOCK=threading.RLock(),
        ROUTER_DASHBOARD_CACHE={},
        LOGGER=logging.getLogger("firewall-automation-test"),
        load_json=_load_json,
        save_json=_save_json,
        now_str=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        norm_mac=lambda value: str(value or "").lower().replace("-", ":").strip(),
        load_device_archive=lambda: {},
        normalize_ipv6_prefixes=lambda value: value if isinstance(value, list) else [],
        normalize_ipv6_records=lambda value, _prefixes: value if isinstance(value, list) else [],
        pick_primary_ipv6=lambda records: records[0].get("ip", "") if records else "",
        _load_portmap_rules_document=lambda: ({"rules": []}, True),
        _portmap_runtime_map=lambda _value: {},
    )


def _rule(uuid, address):
    return {
        "uuid": uuid,
        "ruleName": f"rule-{uuid}",
        "direction": "forward",
        "ipVersion": "ipv4",
        "proto": "tcp",
        "srcIP": "",
        "destIP": address,
        "srcPort": "",
        "destPort": "80,443,1000:2000",
        "target": "ACCEPT",
        "enable": "1",
        "inIface": "wan",
        "outIface": "lan",
        "order": 7,
        "unknownVendorField": {"must": "stay"},
        "stats": {"packets": 9, "bytes": 1024},
    }


def test_adopts_existing_uuid_and_only_changes_selected_address(tmp_path):
    original = _rule("uuid-1", "192.168.5.10")
    client = _Client([original])
    service = FirewallAutomationService(
        _hub(tmp_path, [{"name": "NAS", "mac": "00:11:22:33:44:55", "ip": "192.168.5.46"}]),
        client,
    )

    result = service.upsert(
        "uuid-1",
        {
            "enabled": True,
            "targetType": "device",
            "targetMac": "00:11:22:33:44:55",
            "addressFamily": "ipv4",
            "matchField": "destIP",
        },
    )

    assert result["status"] == "synced"
    assert len(client.calls) == 1
    method, module, data = client.calls[0]
    assert (method, module) == ("devConfig.update", "ip_firewall")
    written = data["list"][0]
    assert written["uuid"] == original["uuid"]
    assert written["destIP"] == "192.168.5.46"
    assert written["destPort"] == original["destPort"]
    assert written["direction"] == original["direction"]
    assert written["proto"] == original["proto"]
    assert written["target"] == original["target"]
    assert written["enable"] == original["enable"]
    assert written["inIface"] == original["inIface"]
    assert written["outIface"] == original["outIface"]
    assert written["order"] == original["order"]
    assert written["unknownVendorField"] == original["unknownVendorField"]
    assert "stats" not in written
    assert all(call[0] != "devConfig.add" for call in client.calls)


def test_missing_adopted_rule_is_never_recreated(tmp_path):
    client = _Client([])
    service = FirewallAutomationService(
        _hub(tmp_path, [{"name": "NAS", "mac": "00:11:22:33:44:55", "ip": "192.168.5.46"}]),
        client,
    )
    service._save([
        {
            "firewallUuid": "deleted-uuid",
            "enabled": True,
            "targetType": "device",
            "targetMac": "00:11:22:33:44:55",
            "mappingId": "",
            "addressFamily": "ipv4",
            "matchField": "destIP",
        }
    ])

    result = service.reconcile(client.firewall(True), blocking=True)

    assert result["changed"] is False
    assert client.calls == []
    assert service.describe("deleted-uuid", client.firewall(True))["status"] == "missing_rule"


def test_ipv6_suffix_follow_keeps_ports_and_full_rule_shape(tmp_path):
    original = _rule("uuid-v6", "")
    original.update({"ipVersion": "ipv6", "ipv6SuffixDest": "::a9e5:169d:a7c8:9bfe"})
    client = _Client([original])
    service = FirewallAutomationService(
        _hub(
            tmp_path,
            [{
                "name": "NAS",
                "mac": "00:11:22:33:44:55",
                "ip": "192.168.5.46",
                "ipv6Records": [{"ip": "2409:8a50:2e40:b150:b8b8:e809:e2a4:fa38", "state": "REACHABLE"}],
            }],
        ),
        client,
    )

    service.upsert(
        "uuid-v6",
        {
            "targetType": "device",
            "targetMac": "00:11:22:33:44:55",
            "addressFamily": "ipv6",
            "matchField": "ipv6SuffixDest",
        },
    )

    written = client.calls[0][2]["list"][0]
    assert written["ipv6SuffixDest"] == "::b8b8:e809:e2a4:fa38"
    assert written["destIP"] == ""
    assert written["destPort"] == "80,443,1000:2000"
    assert written["unknownVendorField"] == {"must": "stay"}


def test_reconcile_limits_each_cycle_to_one_verified_write(tmp_path):
    client = _Client([_rule("uuid-1", "192.168.5.10"), _rule("uuid-2", "192.168.5.11")])
    service = FirewallAutomationService(
        _hub(
            tmp_path,
            [
                {"name": "NAS", "mac": "00:11:22:33:44:55", "ip": "192.168.5.46"},
                {"name": "PC", "mac": "00:11:22:33:44:66", "ip": "192.168.5.201"},
            ],
        ),
        client,
    )
    service._save([
        {"firewallUuid": "uuid-1", "enabled": True, "targetType": "device", "targetMac": "00:11:22:33:44:55", "mappingId": "", "addressFamily": "ipv4", "matchField": "destIP"},
        {"firewallUuid": "uuid-2", "enabled": True, "targetType": "device", "targetMac": "00:11:22:33:44:66", "mappingId": "", "addressFamily": "ipv4", "matchField": "destIP"},
    ])

    first = service.reconcile(client.firewall(True), blocking=True)

    assert first["changed"] is True
    assert len(client.calls) == 1
    assert sorted(row["destIP"] for row in client.rules) == ["192.168.5.11", "192.168.5.46"]

    second = service.reconcile(client.firewall(True), blocking=True)
    assert second["changed"] is True
    assert len(client.calls) == 2
    assert sorted(row["destIP"] for row in client.rules) == ["192.168.5.201", "192.168.5.46"]
