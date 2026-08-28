import json
import threading
from types import SimpleNamespace

import pytest

from assistant.domains import HANDLERS, NAVIGATE_ROUTES, PREVIEWS, register_builtin
from assistant.extend import drain_pending, register_domain
from assistant.tools import ToolError, ToolExecutor


class FakeStunService:
    def __init__(self):
        self.lock = threading.RLock()
        self._rules = []
        self.queued = []
        self.hub = SimpleNamespace(save_json=lambda path, doc: None)
        self.history_path = "stun-history.json"

    def clean_rule(self, payload, old=None):
        return {
            "id": payload.get("id") or "stun-1",
            "name": payload.get("name") or f"{payload.get('targetIpv4')}:{payload.get('targetPort', 5001)}",
            "enabled": payload.get("enabled", True),
            "listenPort": 20000 + len(self._rules),
            "targetIpv4": payload.get("targetIpv4"),
            "targetPort": payload.get("targetPort", 5001),
            "transportProtocol": payload.get("transportProtocol", "UDP"),
        }

    def _is_native_forward(self, rule):
        return False

    def _document(self):
        return {"revision": 1, "updatedAt": "t", "rules": [dict(row) for row in self._rules]}

    def _save_rules(self, rows):
        self._rules = [dict(row) for row in rows]
        return {"revision": 2, "updatedAt": "t2"}

    def queue(self, action, payload, router="", revision=0):
        self.queued.append((action, payload, revision))

    def remove_native_mapping(self, rule_id):
        pass

    def remove_firewall(self, rule_id):
        pass

    def _history(self):
        return {}


def make_hub():
    saved_rules = []
    commands = []
    events = []

    hub = SimpleNamespace(
        STUN_SERVICE=FakeStunService(),
        STATE_FILE="state.json",
        load_json=lambda path, default: {"commands": list(commands)} if path == "commands.json" else {"router": {"mode": "push", "onlineDeviceCount": 7}, "updatedAt": "2026-08-28 12:00:00"},
        save_json=lambda path, doc: commands.clear() or commands.extend(doc["commands"]),
        resolve_agent_router=lambda value: value or "BE72Pro",
        clean_saved_value=lambda value: str(value or "").strip(),
        primary_router_name=lambda: "BE72Pro",
        agent_release_manifest=lambda force: {"versionName": "0.2.30", "_repositoryRoot": "/repo"},
        UPDATE_REPOSITORY_ROOT="/repo",
        AGENT_MANIFEST_URL="/agent/latest.json",
        AGENT_INSTALLER_URL="/agent/install.sh",
        AGENT_UPDATE_COMMANDS_FILE="commands.json",
        now_str=lambda: "2026-08-28 12:00:00",
        notify_agent_commands_changed=lambda: None,
        _clean_portmap_rule=lambda payload, existing=None: {
            "id": payload.get("id") or "pm-1", "name": payload.get("name"),
            "listenPort": payload.get("listenPort"), "targetIpv4": payload.get("targetIpv4"),
            "targetPort": payload.get("targetPort"), "enabled": True,
        },
        _load_portmap_rules=lambda: list(saved_rules),
        _portmap_check_conflict=lambda rows, rule: None,
        _save_portmap_rules=lambda rows: saved_rules.clear() or saved_rules.extend(rows),
        _queue_portmap_command=lambda action, payload: commands.append((action, payload)),
        add_event=lambda event: events.append(event),
        _portmap_epoch=lambda value: None,
        to_int=lambda value, default=0: value if isinstance(value, int) else default,
    )
    hub.saved_rules = saved_rules
    hub.commands = commands
    hub.events = events
    return hub


def make_executor():
    hub = make_hub()
    executor = ToolExecutor(hub)
    register_builtin(executor)
    return hub, executor


def test_builtin_domains_are_catalogued_and_bound():
    hub, executor = make_executor()
    for tool_id in HANDLERS:
        assert executor._handlers.get(tool_id) is not None
    for tool_id in PREVIEWS:
        assert executor._previews.get(tool_id) is not None
    assert set(NAVIGATE_ROUTES) <= {"home", "devices", "router", "tools", "ai_chat", "favorites", "settings", "stun", "wireguard", "roaming"}


def test_write_tool_requires_confirmation():
    _, executor = make_executor()
    with pytest.raises(ToolError) as excinfo:
        executor.execute("router.portmap.create", {
            "name": "NAS", "listenPort": 20001, "targetIpv4": "192.168.5.30", "targetPort": 5001,
        })
    assert excinfo.value.code == "CONFIRMATION_REQUIRED"


def test_portmap_create_confirmed_goes_through_command_queue():
    hub, executor = make_executor()
    preview = executor.preview("router.portmap.create", {
        "name": "NAS", "listenPort": 20001, "targetIpv4": "192.168.5.30", "targetPort": 5001,
    })
    assert "NAS" in preview["summary"]
    result = executor.execute("router.portmap.create", {
        "name": "NAS", "listenPort": 20001, "targetIpv4": "192.168.5.30", "targetPort": 5001,
    }, allow_write=True)
    assert result["ok"] is True
    assert hub.commands and hub.commands[0][0] == "upsert"
    assert any(event["type"] == "portmap_created" for event in hub.events)


def test_portmap_remove_resolves_rule_by_name():
    hub, executor = make_executor()
    executor.execute("router.portmap.create", {
        "name": "NAS", "listenPort": 20001, "targetIpv4": "192.168.5.30", "targetPort": 5001,
    }, allow_write=True)
    result = executor.execute("router.portmap.remove", {"rule": "NAS"}, allow_write=True)
    assert result["deleted"] is True
    assert hub.saved_rules == []
    assert hub.commands[-1][0] == "delete"


def test_portmap_toggle_reuses_lease_rules():
    hub, executor = make_executor()
    executor.execute("router.portmap.create", {
        "name": "NAS", "listenPort": 20001, "targetIpv4": "192.168.5.30", "targetPort": 5001,
    }, allow_write=True)
    result = executor.execute("router.portmap.toggle", {"rule": "NAS", "enabled": False}, allow_write=True)
    assert result["action"] == "stop"
    assert hub.saved_rules[0]["enabled"] is False
    assert hub.commands[-1][0] == "stop"


def test_stun_add_and_remove_round_trip():
    hub, executor = make_executor()
    result = executor.execute("relay.stun.rule.add", {
        "targetIpv4": "192.168.5.30", "targetPort": 5001, "transportProtocol": "UDP",
    }, allow_write=True)
    assert result["rule"]["listenPort"] is not None
    assert hub.STUN_SERVICE.queued[-1][0] == "upsert"
    removed = executor.execute("relay.stun.rule.remove", {"rule": "192.168.5.30"}, allow_write=True)
    assert removed["deleted"] is True
    assert hub.STUN_SERVICE.queued[-1][0] == "delete"


def test_agent_upgrade_queues_update_command():
    hub, executor = make_executor()
    result = executor.execute("relay.agent.upgrade", {}, allow_write=True)
    assert result["targetVersion"] == "0.2.30"
    assert hub.commands and hub.commands[0]["action"] == "update"


def test_router_status_reads_state_document():
    _, executor = make_executor()
    result = executor.execute("router.status", {})
    assert result["router"]["onlineDeviceCount"] == 7


def test_app_tools_return_client_action():
    _, executor = make_executor()
    navigate = executor.execute("app.navigate", {"route": "router"})
    assert navigate["clientAction"] == {"type": "navigate", "route": "router"}
    refresh = executor.execute("app.refresh", {})
    assert refresh["clientAction"] == {"type": "refresh", "scope": "full"}


def test_extend_registration_before_executor_is_drained_later():
    from assistant import catalog

    hub = make_hub()  # no ASSISTANT_TOOL_EXECUTOR attribute yet
    specs = [{
        "id": "demo.future", "version": "1", "name": "未来能力", "description": "x",
        "examples": [], "risk": "read", "confirmation": "none", "scope": "demo.read",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    }]
    handlers = {"demo.future": lambda executor, args, ctx: {"future": True}}
    register_domain(hub, specs, handlers)

    executor = ToolExecutor(hub)
    assert drain_pending(executor) == 1
    assert executor.execute("demo.future", {}) == {"future": True}
    catalog._TOOLS[:] = [tool for tool in catalog._TOOLS if tool["id"] != "demo.future"]
