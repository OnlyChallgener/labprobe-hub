from pathlib import Path

import stun_port_config_patch as patch


def test_stun_middle_port_patch_is_installed_in_runtime_order():
    text = Path("hub_entry.py").read_text(encoding="utf-8")
    assert "from stun_port_config_patch import install_stun_port_config_patch" in text
    service = text.index("install_stun_service(hub, router_driver)")
    port_patch = text.index("install_stun_port_config_patch(hub)")
    legacy_sync = text.index("install_labrelay_sync_patch(hub)")
    assert service < port_patch < legacy_sync


def test_stun_middle_port_policy_matches_app_contract():
    assert patch.STUN_USER_PORT_MIN == 1024
    assert patch.STUN_USER_PORT_MAX == 65535
    assert patch.STUN_AUTO_PORT_MIN == 30000
    assert patch.STUN_AUTO_PORT_MAX == 32767


class _Logger:
    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


class _FakeStun:
    def __init__(self, rules):
        self.rules = [dict(row) for row in rules]
        self.queued = []

    def _document(self):
        return {"revision": 4, "rules": [dict(row) for row in self.rules]}

    def _save_rules(self, rows):
        self.rules = [dict(row) for row in rows]
        return {"revision": 5, "rules": self.rules}

    def queue(self, action, payload, revision=0):
        self.queued.append((action, payload, revision))

    def _used_ports(self, protocol, excluding=""):
        return {
            int(row.get("listenPort") or 0)
            for row in self.rules
            if row.get("id") != excluding and str(row.get("transportProtocol") or "TCP").upper() == protocol.upper()
        }

    def clean_rule(self, payload, old=None):
        old = dict(old or {})
        result = dict(old)
        result.update(payload or {})
        result.setdefault("id", "stun-new")
        result.setdefault("kind", "stun")
        result.setdefault("transportProtocol", "TCP")
        if not int(result.get("listenPort") or 0):
            result["listenPort"] = self._allocated_port(result["transportProtocol"], result["id"])
        return result

    def ensure_firewall(self, rule):
        return {"state": "ready"}


class _Hub:
    def __init__(self, rules):
        self.STUN_SERVICE = _FakeStun(rules)
        self.LOGGER = _Logger()


def _rule(rule_id, port, enabled=True):
    return {
        "id": rule_id,
        "kind": "stun",
        "listenPort": port,
        "transportProtocol": "TCP",
        "enabled": enabled,
    }


def test_legacy_stun_middle_port_is_migrated_out_of_20000_pool():
    hub = _Hub([_rule("legacy", 20004)])
    patch.install_stun_port_config_patch(hub)
    port = hub.STUN_SERVICE.rules[0]["listenPort"]
    assert patch.STUN_AUTO_PORT_MIN <= port <= patch.STUN_AUTO_PORT_MAX
    assert hub.STUN_SERVICE.queued[0][0] == "upsert"


def test_explicit_manual_stun_middle_port_survives_cleaning():
    hub = _Hub([_rule("manual", 30100, enabled=False)])
    patch.install_stun_port_config_patch(hub)
    old = hub.STUN_SERVICE.rules[0]
    cleaned = hub.STUN_SERVICE.clean_rule({"id": "manual", "listenPort": 3499}, old)
    assert cleaned["listenPort"] == 3499


def test_explicit_zero_switches_existing_manual_port_back_to_auto_pool():
    hub = _Hub([_rule("manual", 3499, enabled=False)])
    patch.install_stun_port_config_patch(hub)
    old = hub.STUN_SERVICE.rules[0]
    cleaned = hub.STUN_SERVICE.clean_rule({"id": "manual", "listenPort": 0}, old)
    assert patch.STUN_AUTO_PORT_MIN <= cleaned["listenPort"] <= patch.STUN_AUTO_PORT_MAX
