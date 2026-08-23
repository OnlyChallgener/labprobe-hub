import copy
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from router.firewall_automation import FirewallAutomationError, FirewallAutomationService


class _Cache:
    def clear(self, _prefix):
        return None


class _Snapshots:
    def __init__(self, native):
        self.native = copy.deepcopy(native)

    def snapshot(self, resource):
        return {"data": copy.deepcopy(self.native)} if resource == "portMappings" else {}


class _Client:
    def __init__(self, rules, native=None):
        self.rules = copy.deepcopy(rules)
        self.native = copy.deepcopy(native or {"portMapping": []})
        self.calls = []
        self.write_lock = threading.RLock()
        self.cache = _Cache()

    def firewall(self, _force=False):
        return {"list": copy.deepcopy(self.rules), "maxRules": 20}

    def native_port_mapping(self, _force=False):
        return copy.deepcopy(self.native)

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


def _relay_mapping(mapping_id="mapping-1", address="192.168.5.46", mode="6to4", port=9443):
    return {
        "id": mapping_id,
        "name": "NAS 映射",
        "enabled": True,
        "mode": mode,
        "targetMode": "ipv4" if mode == "6to4" else "ipv6_suffix",
        "targetIpv4": address if mode == "6to4" else "",
        "targetIpv6": "",
        "targetIpv6Snapshot": address if mode != "6to4" else "",
        "transportProtocol": "TCP",
        "targetPort": port,
    }


def _hub(tmp_path, mappings=None, native=None):
    state_path = tmp_path / "state.json"
    devices_path = tmp_path / "devices.json"
    portmap_status_path = tmp_path / "portmap_status.json"
    _save_json(state_path, {"router": {"name": "Router"}})
    _save_json(devices_path, {"online": []})
    relay_rows = copy.deepcopy(mappings or [])
    native_data = copy.deepcopy(native or {"portMapping": []})
    return SimpleNamespace(
        DATA_DIR=tmp_path,
        STATE_FILE=state_path,
        DEVICES_FILE=devices_path,
        PORTMAP_ROUTER_STATUS_FILE=portmap_status_path,
        ROUTER_CONFIG_SYNC=_Snapshots(native_data),
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
        _load_portmap_rules_document=lambda: ({"rules": copy.deepcopy(relay_rows)}, True),
        _portmap_runtime_map=lambda _value: {},
    )


def _rule(uuid, address, *, family="ipv4", port="80,443,1000:2000"):
    rule = {
        "uuid": uuid,
        "ruleName": f"rule-{uuid}",
        "direction": "forward",
        "ipVersion": family,
        "proto": "tcp",
        "srcIP": "",
        "destIP": address if family == "ipv4" else "",
        "srcPort": "",
        "destPort": port,
        "target": "ACCEPT",
        "enable": "1",
        "inIface": "wan",
        "outIface": "lan",
        "order": 7,
        "unknownVendorField": {"must": "stay"},
        "stats": {"packets": 9, "bytes": 1024},
    }
    if family == "ipv6":
        rule["ipv6SuffixDest"] = address
    return rule


def _binding(uuid="uuid-1", *, kind="relay", mapping_id="mapping-1", family="ipv4", field="destIP"):
    return {
        "enabled": True,
        "targetType": "mapping",
        "mappingKind": kind,
        "mappingId": mapping_id,
        "addressFamily": family,
        "matchField": field,
    }


def test_mapping_binding_requires_two_observations_and_preserves_raw_rule(tmp_path):
    original = _rule("uuid-1", "192.168.5.10", port="80,443,9443,1000:2000")
    client = _Client([original])
    service = FirewallAutomationService(_hub(tmp_path, [_relay_mapping()]), client)

    first = service.upsert("uuid-1", _binding())
    assert first["status"] == "pending"
    assert client.calls == []
    result = service.reconcile(client.firewall(True), blocking=True)

    assert result["changed"] is True
    written = client.calls[0][2]["list"][0]
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


def test_manual_address_change_pauses_instead_of_overwriting(tmp_path):
    client = _Client([_rule("uuid-1", "192.168.5.10", port="9443")])
    service = FirewallAutomationService(_hub(tmp_path, [_relay_mapping()]), client)
    service.upsert("uuid-1", _binding())
    client.rules[0]["destIP"] = "192.168.5.99"

    result = service.reconcile(client.firewall(True), blocking=True)

    assert result["suspended"] is True
    assert client.calls == []
    state = service.describe("uuid-1", client.firewall(True))
    assert state["status"] == "manual_override"
    assert state["currentAddress"] == "192.168.5.99"


def test_manual_port_change_is_never_reverted(tmp_path):
    client = _Client([_rule("uuid-1", "192.168.5.10", port="9443")])
    service = FirewallAutomationService(_hub(tmp_path, [_relay_mapping()]), client)
    service.upsert("uuid-1", _binding())
    client.rules[0]["destPort"] = "9443,10443"

    result = service.reconcile(client.firewall(True), blocking=True)

    assert result["suspended"] is True
    assert client.calls == []
    assert client.rules[0]["destPort"] == "9443,10443"


def test_native_mapping_uses_existing_router_config_snapshot(tmp_path):
    native = {"portMapping": [{"ruleName": "Lucky", "destIp": "192.168.5.46", "destPort": "1661", "srcPort": "58822", "proto": "tcp"}]}
    client = _Client([_rule("uuid-native", "192.168.5.20", port="1661,9443")], native=native)
    service = FirewallAutomationService(_hub(tmp_path, native=native), client)

    service.upsert("uuid-native", _binding("uuid-native", kind="native", mapping_id="Lucky"))
    service.reconcile(client.firewall(True), blocking=True)

    assert client.rules[0]["destIP"] == "192.168.5.46"


def test_ipv6_suffix_mapping_preserves_multi_port_shape(tmp_path):
    target = "2409:8a50:2e40:b150:b8b8:e809:e2a4:fa38"
    original = _rule("uuid-v6", "::a9e5:169d:a7c8:9bfe", family="ipv6", port="2772,1661,9443")
    client = _Client([original])
    service = FirewallAutomationService(_hub(tmp_path, [_relay_mapping(address=target, mode="6to6")]), client)

    service.upsert("uuid-v6", _binding("uuid-v6", family="ipv6", field="ipv6SuffixDest"))
    service.reconcile(client.firewall(True), blocking=True)

    written = client.calls[0][2]["list"][0]
    assert written["ipv6SuffixDest"] == "::b8b8:e809:e2a4:fa38"
    assert written["destPort"] == "2772,1661,9443"
    assert written["unknownVendorField"] == {"must": "stay"}


def test_drop_and_non_mapping_targets_are_rejected_or_ignored(tmp_path):
    dropped = _rule("drop", "192.168.5.10", port="9443")
    dropped["target"] = "DROP"
    client = _Client([dropped])
    service = FirewallAutomationService(_hub(tmp_path, [_relay_mapping()]), client)

    with pytest.raises(FirewallAutomationError):
        service.upsert("drop", _binding("drop"))

    service._save([{"firewallUuid": "drop", "enabled": True, "targetType": "device", "targetMac": "00:11:22:33:44:55", "addressFamily": "ipv4", "matchField": "destIP"}])
    assert service.reconcile(client.firewall(True), blocking=True)["changed"] is False
    assert service.describe("drop", client.firewall(True))["status"] == "out_of_scope"
    assert client.calls == []
