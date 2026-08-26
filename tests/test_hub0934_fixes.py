import inspect
from types import SimpleNamespace

from hub0934_fixes import (
    _normalize_portmap_payload,
    _prune_redundant_portmap_commands,
    canonical_watched_devices,
    install_hub0934_fixes,
)


class FakeTime:
    @staticmethod
    def time():
        return 1722600000


class FakeHub(SimpleNamespace):
    DEVICES_FILE = "devices.json"
    PORTMAP_ROUTER_STATUS_FILE = "portmap_status.json"
    PORTMAP_COMMANDS_FILE = "portmap_commands.json"
    time = FakeTime()

    def clean_saved_value(self, value):
        if value is None:
            return ""
        text = str(value).strip()
        return "" if text.lower() in {"none", "null"} else text

    def norm_mac(self, value):
        return str(value or "").replace("-", ":").lower()

    def now_str(self):
        return "2026-08-02 18:00:00"

    def hydrate_device_with_archive(self, row, archive):
        return dict(row)

    def to_int(self, value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _portmap_epoch(self, value):
        value = self.to_int(value, 0)
        return value if value > 0 else None


def test_watched_uses_latest_archive_instead_of_stale_watched_copy():
    hub = FakeHub()
    hub.cfg_get = lambda key, default=None: [
        {"mac": "24:1A:E6:BB:16:D9", "name": "华为Mate60"}
    ] if key == "watched_devices" else default
    hub.load_json = lambda path, default=None: {
        "watched": [{
            "mac": "24:1a:e6:bb:16:d9",
            "todayUpload": 9,
            "todayDownload": 85,
            "offlineAt": "2026-08-02 08:25:27",
            "lastSeenAt": "2026-08-02 08:25:27",
        }]
    }
    hub.load_device_archive = lambda: {
        "24:1a:e6:bb:16:d9": {
            "mac": "24:1a:e6:bb:16:d9",
            "todayUpload": 25,
            "todayDownload": 250,
            "offlineAt": "2026-08-02 15:29:39",
            "lastSeenAt": "2026-08-02 15:29:39",
            "lastIp": "192.168.5.23",
        }
    }

    row = canonical_watched_devices(hub, [])[0]
    assert row["name"] == "华为Mate60"
    assert row["todayUpload"] == 25
    assert row["todayDownload"] == 250
    assert row["offlineAt"] == "2026-08-02 15:29:39"
    assert row["lastSeenAt"] == "2026-08-02 15:29:39"


def test_current_online_snapshot_has_highest_device_authority():
    hub = FakeHub()
    hub.cfg_get = lambda key, default=None: [{"mac": "aa:bb:cc:dd:ee:ff"}] if key == "watched_devices" else default
    hub.load_json = lambda path, default=None: {"watched": [{"mac": "aa:bb:cc:dd:ee:ff", "rssi": "-89"}]}
    hub.load_device_archive = lambda: {"aa:bb:cc:dd:ee:ff": {"mac": "aa:bb:cc:dd:ee:ff", "rssi": "-70"}}

    row = canonical_watched_devices(hub, [{
        "mac": "aa:bb:cc:dd:ee:ff",
        "online": True,
        "rssi": "-45",
        "lastSeenAt": "2026-08-02 18:00:00",
    }])[0]
    assert row["online"] is True
    assert row["rssi"] == "-45"
    assert row["offlineAt"] is None


def test_installed_watched_projection_keeps_router_core_keyword_contract():
    source = inspect.getsource(install_hub0934_fixes)
    assert "emit_events: bool = True" in source
    assert "del emit_events" in source


def test_permanent_rule_missing_lease_does_not_trigger_false_mismatch():
    hub = FakeHub()
    hub._load_portmap_rules = lambda: [{"id": "rule-1", "leaseSeconds": 0, "expiresAt": None}]
    hub.load_json = lambda path, default=None: {"status": {"rules": []}}
    hub._portmap_runtime_map = lambda document: {"rule-1": {"startedAt": 1722500000}}
    payload = {
        "rules": [{
            "rule": {"id": "rule-1", "enabled": True, "expiresAt": None},
            "runtime": {"id": "rule-1", "state": "running"},
        }]
    }

    _normalize_portmap_payload(hub, payload)
    row = payload["rules"][0]
    assert row["rule"]["leaseSeconds"] == 0
    assert row["runtime"]["startedAt"] == 1722500000


def test_existing_started_at_is_never_replaced():
    hub = FakeHub()
    hub._load_portmap_rules = lambda: [{"id": "rule-1", "leaseSeconds": 0}]
    hub.load_json = lambda path, default=None: {}
    hub._portmap_runtime_map = lambda document: {"rule-1": {"startedAt": 1000}}
    payload = {
        "rules": [{
            "rule": {"id": "rule-1"},
            "runtime": {"id": "rule-1", "state": "running", "startedAt": 2000},
        }]
    }

    _normalize_portmap_payload(hub, payload)
    assert payload["rules"][0]["runtime"]["startedAt"] == 2000


def test_redundant_permanent_upsert_is_closed_before_relay_receives_it():
    hub = FakeHub()
    desired = {
        "id": "rule-1",
        "enabled": True,
        "mode": "6to4",
        "listenPort": 20000,
        "targetMode": "ipv4",
        "targetIpv4": "192.168.5.2",
        "targetIpv6": "",
        "targetIpv6Suffix": "",
        "targetMac": "",
        "targetPort": 58443,
        "expiresAt": None,
        "leaseSeconds": 0,
        "maxConnections": 32,
        "idleTimeoutSec": 300,
    }
    runtime_document = {
        "status": {
            "rules": [{
                "rule": {key: value for key, value in desired.items() if key != "leaseSeconds"},
                "runtime": {"id": "rule-1", "state": "running", "startedAt": 1722500000},
            }]
        }
    }
    command_document = {
        "commands": [{
            "id": "cmd-1",
            "status": "pending",
            "action": "upsert",
            "payload": {"rule": dict(desired)},
        }]
    }
    saved = {}
    hub._load_portmap_rules = lambda: [dict(desired)]
    hub._portmap_runtime_map = lambda document: {"rule-1": {"startedAt": 1722500000}}

    def load_json(path, default=None):
        if path == hub.PORTMAP_ROUTER_STATUS_FILE:
            return runtime_document
        if path == hub.PORTMAP_COMMANDS_FILE:
            return command_document
        return default

    hub.load_json = load_json
    hub.save_json = lambda path, value: saved.update({path: value})

    assert _prune_redundant_portmap_commands(hub) == 1
    command = saved[hub.PORTMAP_COMMANDS_FILE]["commands"][0]
    assert command["status"] == "done"
    assert command["result"]["unchanged"] is True
    assert command["finishedEpoch"] == 1722600000
