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


class FakeRouterService:
    def __init__(self):
        self.calls = []
        self.upnp = {"enabled": True, "wan": "WAN1", "rules": [{"name": "dynamic", "extPort": 5000}]}
        self.portmaps = [{
            "name": "NAS-HTTPS", "interface": "WAN1", "proto": "tcp",
            "extPort": 8443, "intIp": "192.168.5.30", "intPort": 443, "enabled": True,
        }]
        self.firewall = {"rules": [{"uuid": "fw-sun", "name": "Sun", "enabled": True}]}

    def get_capabilities(self):
        return {"configured": True, "features": {"upnp": True, "firewall": True, "nativePortMapping": True}}

    def get_status(self):
        return {"state": "ready", "connected": True, "dataAvailable": True}

    def get_upnp(self, force=False):
        return {"data": dict(self.upnp)}

    def set_upnp(self, enabled, wan):
        self.calls.append(("upnp", enabled, wan))
        self.upnp.update({"enabled": enabled, "wan": wan})
        return {"data": dict(self.upnp)}

    def get_port_mappings(self, force=False):
        return {"data": {"rules": [dict(row) for row in self.portmaps]}}

    def add_port_mapping(self, rule):
        self.calls.append(("portmap_add", dict(rule)))
        self.portmaps.append(dict(rule))
        return self.get_port_mappings()

    def delete_port_mapping(self, name):
        self.calls.append(("portmap_delete", name))
        self.portmaps = [row for row in self.portmaps if row.get("name") != name]
        return self.get_port_mappings()

    def get_ddns(self, force=False):
        return {"data": {"services": [{
            "serviceId": "ddns-1", "provider": "cloudflare", "domain": "home.example.com",
            "username": "visible-name", "password": "must-not-leak", "enabled": True,
        }]}}

    def get_ipv6_status(self):
        return {"data": {"enabled": True, "wanAddress": "2409::1"}}

    def get_ipv6_config(self):
        return {"data": {"wan": {"proto": "dhcpv6"}, "lan": {"proto": "slaac"}}}

    def get_dhcpv6_clients(self):
        return {"data": {"clients": [{"hostname": "NAS", "ipv6": "2409::30"}]}}

    def get_firewall(self, force=False):
        return {"data": {"rules": [dict(row) for row in self.firewall["rules"]]}}

    def set_firewall_rule_enabled(self, uuid, enabled):
        self.calls.append(("firewall_toggle", uuid, enabled))
        for row in self.firewall["rules"]:
            if row["uuid"] == uuid:
                row["enabled"] = enabled
        return {"data": {"rules": [dict(row) for row in self.firewall["rules"]]}}

    def add_firewall_rule(self, rule):
        self.calls.append(("firewall_add", dict(rule)))
        row = dict(rule)
        row["uuid"] = str(row.get("uuid") or f"fw-new-{len(self.firewall['rules'])}")
        self.firewall["rules"].append(row)
        return {"data": {"rules": [dict(row) for row in self.firewall["rules"]]}}

    def update_firewall_rule(self, uuid, rule):
        self.calls.append(("firewall_update", uuid, dict(rule)))
        for row in self.firewall["rules"]:
            if row["uuid"] == uuid:
                row.update(rule)
        return {"data": {"rules": [dict(row) for row in self.firewall["rules"]]}}

    def delete_firewall_rule(self, uuid):
        self.calls.append(("firewall_delete", uuid))
        self.firewall["rules"] = [row for row in self.firewall["rules"] if row["uuid"] != uuid]
        return {"data": {"rules": [dict(row) for row in self.firewall["rules"]]}}


def make_hub():
    saved_rules = []
    commands = []
    events = []

    task_calls = []
    task_manager = SimpleNamespace(
        start_nat=lambda payload: task_calls.append(("nat", dict(payload))) or {
            "kind": "nat", "taskId": "nat-1", "state": "succeeded",
            "stage": "finished", "result": {"nat_type": "Port Restricted Cone NAT"},
        },
        start_diagnostic=lambda: task_calls.append(("diagnostic", {})) or {
            "kind": "diagnostic", "taskId": "diagnostic-1", "state": "succeeded",
            "stage": "finished", "result": {"process": "100%", "List": []},
        },
    )
    hub = SimpleNamespace(
        STUN_SERVICE=FakeStunService(),
        ROUTER_SERVICE=FakeRouterService(),
        ROUTER_TASK_MANAGER=task_manager,
        STATE_FILE="state.json",
        status_document=lambda: {"hub": {"status": "ok"}},
        agent_presence_snapshot=lambda: {"online": True, "router": "BE72"},
        _load_portmap_rules_document=lambda: ({"rules": [{"id": "pm-1"}]}, True),
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
        _queue_portmap_command=lambda action, payload, **kwargs: commands.append((action, payload)),
        add_event=lambda event: events.append(event),
        _portmap_epoch=lambda value: None,
        to_int=lambda value, default=0: value if isinstance(value, int) else default,
    )
    hub.saved_rules = saved_rules
    hub.commands = commands
    hub.events = events
    hub.task_calls = task_calls
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
    assert set(NAVIGATE_ROUTES) <= {"home", "devices", "router", "tools", "ai_chat", "favorites",
                                    "settings", "stun", "wireguard", "ipv6", "portmap", "ddns", "nat", "wol"}


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
    assert result["router"]["connected"] is True


def test_router_core_read_capabilities_cover_manual_router_settings_without_navigation():
    _, executor = make_executor()

    capabilities = executor.execute("router.capabilities", {})
    upnp = executor.execute("router.upnp.get", {})
    native = executor.execute("router.native_portmap.list", {})
    firewall = executor.execute("router.firewall.list", {})
    ddns = executor.execute("router.ddns.list", {})
    ipv6 = executor.execute("router.ipv6.inspect", {})

    assert capabilities["capabilities"]["features"]["nativePortMapping"] is True
    assert upnp["upnp"]["wan"] == "WAN1"
    assert native["rules"][0]["name"] == "NAS-HTTPS"
    assert firewall["rules"][0]["uuid"] == "fw-sun"
    assert ddns["services"][0]["domain"] == "home.example.com"
    assert "password" not in ddns["services"][0]
    assert ipv6["status"]["wanAddress"] == "2409::1"
    assert ipv6["config"]["lan"]["proto"] == "slaac"
    assert ipv6["clients"][0]["hostname"] == "NAS"
    for result in (capabilities, upnp, native, firewall, ddns, ipv6):
        assert "clientAction" not in result


@pytest.mark.parametrize(
    ("tool_id", "arguments"),
    [
        ("router.upnp.set", {"enabled": False, "wan": "WAN1"}),
        ("router.native_portmap.create", {
            "name": "NAS-HTTP", "interface": "WAN1", "proto": "tcp",
            "extPort": 8080, "intIp": "192.168.5.30", "intPort": 80,
        }),
        ("router.native_portmap.remove", {"rule": "NAS-HTTPS"}),
        ("router.firewall.toggle", {"rule": "Sun", "enabled": False}),
    ],
)
def test_router_core_writes_always_require_confirmation(tool_id, arguments):
    _, executor = make_executor()
    with pytest.raises(ToolError) as excinfo:
        executor.execute(tool_id, arguments)
    assert excinfo.value.code == "CONFIRMATION_REQUIRED"


def test_upnp_preview_normalizes_wan_and_confirmed_write_reuses_router_service():
    hub, executor = make_executor()
    preview = executor.preview("router.upnp.set", {"enabled": False, "wan": "wan1"})

    assert preview["arguments"] == {"enabled": False, "wan": "WAN1"}
    result = executor.execute("router.upnp.set", preview["arguments"], allow_write=True)

    assert hub.ROUTER_SERVICE.calls[-1] == ("upnp", False, "WAN1")
    assert result["upnp"]["enabled"] is False


def test_native_portmap_create_preview_and_confirmed_write_use_router_service():
    hub, executor = make_executor()
    args = {
        "name": "NAS-HTTP", "interface": "wan1", "proto": "TCP",
        "extPort": 8080, "intIp": "192.168.5.30", "intPort": 80,
    }
    preview = executor.preview("router.native_portmap.create", args)
    assert preview["arguments"]["interface"] == "WAN1"
    assert preview["arguments"]["proto"] == "tcp"

    result = executor.execute("router.native_portmap.create", preview["arguments"], allow_write=True)

    assert hub.ROUTER_SERVICE.calls[-1][0] == "portmap_add"
    assert result["rule"]["name"] == "NAS-HTTP"


def test_native_portmap_remove_preview_pins_exact_rule_name():
    hub, executor = make_executor()
    preview = executor.preview("router.native_portmap.remove", {"rule": "NAS-HTTPS"})
    assert preview["arguments"] == {"rule": "NAS-HTTPS"}

    result = executor.execute("router.native_portmap.remove", preview["arguments"], allow_write=True)

    assert hub.ROUTER_SERVICE.calls[-1] == ("portmap_delete", "NAS-HTTPS")
    assert result["deleted"] is True


def test_firewall_toggle_preview_pins_uuid_and_confirmed_write_uses_router_service():
    hub, executor = make_executor()
    preview = executor.preview("router.firewall.toggle", {"rule": "Sun", "enabled": False})

    assert preview["arguments"] == {"rule": "fw-sun", "enabled": False}
    result = executor.execute("router.firewall.toggle", preview["arguments"], allow_write=True)

    assert hub.ROUTER_SERVICE.calls[-1] == ("firewall_toggle", "fw-sun", False)
    assert result["enabled"] is False


@pytest.mark.parametrize(
    ("tool_id", "arguments"),
    [
        ("router.upnp.set", {"enabled": "false", "wan": "WAN1"}),
        ("router.firewall.toggle", {"rule": "Sun", "enabled": "false"}),
        ("router.native_portmap.create", {
            "name": "bad", "interface": "WAN1", "proto": "tcp",
            "extPort": "8080", "intIp": "192.168.5.30", "intPort": 80,
        }),
        ("router.native_portmap.create", {
            "name": "bad", "interface": "WAN1", "proto": "tcp",
            "extPort": 70000, "intIp": "192.168.5.30", "intPort": 80,
        }),
    ],
)
def test_router_core_write_preview_rejects_coerced_booleans_and_invalid_ports(tool_id, arguments):
    hub, executor = make_executor()

    with pytest.raises(ToolError) as excinfo:
        executor.preview(tool_id, arguments)

    assert excinfo.value.code == "INVALID_ARGUMENTS"
    assert hub.ROUTER_SERVICE.calls == []


def test_nat_diagnostic_is_catalogued_and_executes_router_core_task_without_navigation():
    hub, executor = make_executor()
    result = executor.execute("router.nat.diagnostic", {"mode": "5780", "interface": "wan1"})

    assert hub.task_calls == [("nat", {"mode": "5780", "interface": "wan1"})]
    assert result["kind"] == "nat"
    assert result["task"]["result"]["nat_type"] == "Port Restricted Cone NAT"
    assert "clientAction" not in result
    assert "navigate" not in json.dumps(result, ensure_ascii=False).lower()


def test_router_network_diagnostic_executes_router_core_task_without_navigation():
    hub, executor = make_executor()
    result = executor.execute("router.diagnostic", {})

    assert hub.task_calls == [("diagnostic", {})]
    assert result["kind"] == "diagnostic"
    assert result["task"]["result"]["process"] == "100%"
    assert "clientAction" not in result


def test_generic_network_self_check_is_summary_only_and_never_navigates():
    _, executor = make_executor()
    result = executor.execute("network.self_check", {})

    assert result["kind"] == "network"
    assert result["summary"]["agent"]["online"] is True
    assert result["summary"]["portmapRules"] == 1
    assert "clientAction" not in result


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


def test_firewall_rule_create_defaults_summary_and_message():
    hub, executor = make_executor()
    with pytest.raises(ToolError) as excinfo:
        executor.execute("router.firewall.rule.create", {"ruleName": "Web"})
    assert excinfo.value.code == "CONFIRMATION_REQUIRED"
    preview = executor.preview("router.firewall.rule.create", {"ruleName": "Web", "destPort": "9443"})
    assert "Web" in preview["summary"] and "转发" in preview["summary"]
    result = executor.execute("router.firewall.rule.create", {
        "ruleName": "Web", "destPort": "9443", "ipVersion": "ipv6",
    }, allow_write=True)
    assert result["ok"] is True
    assert "已创建防火墙规则" in result["message"]
    kind, payload = hub.ROUTER_SERVICE.calls[-1]
    assert kind == "firewall_add"
    assert payload["direction"] == "forward" and payload["ipVersion"] == "ipv6"
    assert payload["destPort"] == "9443" and payload["target"] == "ACCEPT"
    assert payload["inIface"] == "wan" and payload["outIface"] == "lan" and payload["enable"] == "1"


def test_firewall_rule_create_outbound_clears_inbound_interface():
    hub, executor = make_executor()
    executor.execute("router.firewall.rule.create", {
        "ruleName": "Out", "direction": "outbound", "proto": "udp",
    }, allow_write=True)
    _, payload = hub.ROUTER_SERVICE.calls[-1]
    assert payload["inIface"] == "" and payload["outIface"] == "lan"


def test_firewall_rule_create_matches_app_dual_and_non_port_protocols():
    hub, executor = make_executor()
    executor.execute("router.firewall.rule.create", {
        "ruleName": "Ping", "ipVersion": "dual", "proto": "icmp",
        "srcPort": "123", "destPort": "456",
    }, allow_write=True)
    _, payload = hub.ROUTER_SERVICE.calls[-1]
    assert payload["ipVersion"] == "dual" and payload["proto"] == "icmp"
    assert payload["srcPort"] == "" and payload["destPort"] == ""


def test_firewall_rule_update_pins_uuid_and_merges_existing_fields():
    hub, executor = make_executor()
    preview = executor.preview("router.firewall.rule.update", {"rule": "Sun", "destPort": "2186,9001"})
    assert preview["arguments"]["rule"] == "fw-sun"
    result = executor.execute("router.firewall.rule.update", {"rule": "fw-sun", "destPort": "2186,9001"},
                              allow_write=True)
    assert result["ok"] is True and "已修改防火墙规则" in result["message"]
    kind, uuid_value, payload = hub.ROUTER_SERVICE.calls[-1]
    assert kind == "firewall_update" and uuid_value == "fw-sun"
    assert payload["destPort"] == "2186,9001"
    assert payload["ruleName"] == "Sun"
    assert "uuid" not in payload


def test_firewall_rule_update_can_clear_fields_and_submits_full_whitelist():
    hub, executor = make_executor()
    hub.ROUTER_SERVICE.firewall["rules"][0].update({
        "ruleName": "Sun", "direction": "forward", "ipVersion": "ipv4", "proto": "tcp",
        "srcIP": "192.168.1.2", "destIP": "10.0.0.1", "srcPort": "1000",
        "destPort": "2000", "target": "ACCEPT", "enable": "1",
        "ipv6SuffixSrc": "", "ipv6SuffixDest": "", "inIface": "wan", "outIface": "lan",
    })
    executor.execute("router.firewall.rule.update", {
        "rule": "fw-sun", "srcIP": "", "destIP": "", "proto": "any",
    }, allow_write=True)
    _, _, payload = hub.ROUTER_SERVICE.calls[-1]
    assert payload["srcIP"] == "" and payload["destIP"] == ""
    assert payload["proto"] == "any" and payload["srcPort"] == "" and payload["destPort"] == ""
    assert set(payload) == {
        "ruleName", "direction", "ipVersion", "proto", "srcIP", "destIP", "srcPort", "destPort",
        "target", "enable", "ipv6SuffixSrc", "ipv6SuffixDest", "inIface", "outIface",
    }


def test_firewall_rule_remove_resolves_by_name():
    hub, executor = make_executor()
    result = executor.execute("router.firewall.rule.remove", {"rule": "Sun"}, allow_write=True)
    assert result["deleted"] is True
    assert "已删除防火墙规则" in result["message"]
    assert hub.ROUTER_SERVICE.calls[-1] == ("firewall_delete", "fw-sun")
    assert hub.ROUTER_SERVICE.get_firewall()["data"]["rules"] == []


def test_stun_and_portmap_write_results_carry_readable_messages():
    _, executor = make_executor()
    added = executor.execute("relay.stun.rule.add", {
        "targetIpv4": "192.168.5.30", "targetPort": 5001,
    }, allow_write=True)
    assert "已新增 STUN 穿透规则" in added["message"]
    removed = executor.execute("relay.stun.rule.remove", {"rule": added["rule"]["name"]}, allow_write=True)
    assert "已删除 STUN 穿透规则" in removed["message"]


def test_firmware_check_formats_chinese_digest():
    hub, executor = make_executor()
    snapshot = {
        "kind": "beta", "state": "succeeded", "stageText": "版本检测完成",
        "result": {
            "cur": "EW_3.0(1)B11P279",
            "new": {
                "totalCount": 1, "msg": "发现新版本",
                "firmwareList": [{"version": "EW_3.0(1)B11P280", "size": 20480000,
                                  "releaseNotes": "修复 2.5G 口协商问题", "downloadUrl": "https://fw/280"}],
            },
            "checkedAt": 1,
        },
    }
    hub.ROUTER_TASK_MANAGER = SimpleNamespace(
        start_beta=lambda: {"kind": "beta", "state": "queued"},
        snapshot=lambda kind: snapshot,
    )
    result = executor.execute("router.firmware.check", {}, allow_write=False)
    assert result["ok"] is True
    content = result["content"]
    assert "EW_3.0(1)B11P279" in content
    assert "1 个可更新版本" in content
    assert "EW_3.0(1)B11P280" in content
    assert "修复 2.5G 口协商问题" in content
    assert "19.5 MB" in content
    assert "firmwareList" not in content and "{" not in content
    status = executor.execute("router.firmware.status", {})
    assert "最近一次" in status["message"]


def test_firmware_status_without_snapshot_prompts_check():
    hub, executor = make_executor()
    hub.ROUTER_TASK_MANAGER.snapshot = lambda kind: {"kind": "beta", "state": "idle"}
    result = executor.execute("router.firmware.status", {})
    assert "还没有检测过" in result["message"] and "content" in result
