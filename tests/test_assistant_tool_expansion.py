import json
from types import SimpleNamespace

import pytest

from assistant.catalog import _TOOLS, register_tool, tool_spec
from assistant.tools import ToolError, ToolExecutor


def make_hub(tmp_path):
    events_file = tmp_path / "events.json"
    events_file.write_text(json.dumps([
        {"id": 1, "type": "device_online", "name": "ANS", "createdAt": "2026-08-28 08:00:00"},
        {"id": 2, "type": "device_offline", "name": "Mate60", "createdAt": "2026-08-28 09:00:00"},
        {"id": 3, "type": "device_online", "name": "NAS", "createdAt": "2026-08-28 10:00:00", "deleted": True},
    ]), encoding="utf-8")

    def load_json(path, default):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return default

    return SimpleNamespace(
        EVENTS_FILE=events_file,
        load_json=load_json,
        agent_presence_snapshot=lambda: {
            "online": True, "lastSeenAt": "2026-08-28 10:00:00", "hookToken": "leak-me",
        },
        STUN_SERVICE=SimpleNamespace(rules_snapshot=lambda: {
            "revision": 3, "updatedAt": "2026-08-28 10:00:00",
            "rules": [{"id": "r1", "comment": "nas"}],
        }),
        WIREGUARD_SERVICE=SimpleNamespace(document=lambda: {
            "revision": 5,
            "server": {"name": "wg0", "privateKey": "must-not-leak", "endpoint": "hub:51820"},
        }),
    )


def test_events_list_returns_newest_first_without_deleted(tmp_path):
    executor = ToolExecutor(make_hub(tmp_path))
    result = executor.execute("events.list", {"limit": 2})
    assert [row["id"] for row in result["events"]] == [2, 1]
    assert result["total"] == 2


def test_events_list_rejects_out_of_range_and_non_integer_limit(tmp_path):
    executor = ToolExecutor(make_hub(tmp_path))
    for value in (999, "2", True):
        with pytest.raises(ToolError) as error:
            executor.execute("events.list", {"limit": value})
        assert error.value.code == "INVALID_ARGUMENTS"


def test_integer_schema_accepts_real_integer_only(tmp_path):
    executor = ToolExecutor(make_hub(tmp_path))
    assert len(executor.execute("events.list", {"limit": 1})["events"]) == 1


def test_agent_status_hides_token_like_fields(tmp_path):
    executor = ToolExecutor(make_hub(tmp_path))
    result = executor.execute("agent.status", {})
    assert result["agent"]["online"] is True
    assert "leak-me" not in json.dumps(result)


def test_stun_rules_list_reads_service_snapshot(tmp_path):
    executor = ToolExecutor(make_hub(tmp_path))
    result = executor.execute("stun.rules.list", {})
    assert result["revision"] == 3
    assert result["rules"][0]["id"] == "r1"


def test_wireguard_status_redacts_private_key_material(tmp_path):
    executor = ToolExecutor(make_hub(tmp_path))
    result = executor.execute("wireguard.status", {})
    dumped = json.dumps(result)
    assert "must-not-leak" not in dumped
    assert result["wireguard"]["server"]["endpoint"] == "hub:51820"


def test_wireguard_server_toggle_is_revision_pinned_and_requires_confirmation(tmp_path):
    hub = make_hub(tmp_path)
    document = {
        "revision": 7,
        "server": {
            "interfaceName": "labwg0", "address": "10.77.0.1/24",
            "listenPort": 51820, "mtu": 1420, "enabled": True,
            "peers": [], "endpointProfiles": [],
        },
    }
    calls = []

    def put(payload, expected_revision):
        calls.append((dict(payload), expected_revision))
        assert expected_revision == document["revision"]
        document["revision"] += 1
        document["server"] = dict(payload)
        return dict(document)

    hub.WIREGUARD_SERVICE = SimpleNamespace(document=lambda: dict(document), put=put)
    executor = ToolExecutor(hub)
    with pytest.raises(ToolError, match="二次确认"):
        executor.execute("wireguard.server.toggle", {"enabled": False})

    preview = executor.preview("wireguard.server.toggle", {"enabled": False})
    assert preview["arguments"] == {"enabled": False, "expectedRevision": 7}
    assert "所有 WireGuard 客户端将断开" in preview["summary"]
    result = executor.execute("wireguard.server.toggle", preview["arguments"], allow_write=True)
    assert result["enabled"] is False and result["revision"] == 8
    assert calls == [({**document["server"], "enabled": False}, 7)]


def test_wireguard_toggle_rejects_unconfigured_gateway_and_non_boolean_value(tmp_path):
    hub = make_hub(tmp_path)
    hub.WIREGUARD_SERVICE = SimpleNamespace(document=lambda: {"revision": 0, "server": None})
    executor = ToolExecutor(hub)
    with pytest.raises(ToolError) as missing:
        executor.preview("wireguard.server.toggle", {"enabled": False})
    assert missing.value.code == "WIREGUARD_NOT_CONFIGURED"
    with pytest.raises(ToolError) as invalid:
        executor.preview("wireguard.server.toggle", {"enabled": "false"})
    assert invalid.value.code == "INVALID_ARGUMENTS"


def test_missing_service_returns_503(tmp_path):
    hub = make_hub(tmp_path)
    hub.WIREGUARD_SERVICE = None
    executor = ToolExecutor(hub)
    with pytest.raises(ToolError) as excinfo:
        executor.execute("wireguard.status", {})
    assert excinfo.value.status_code == 503


def test_registered_tool_extension_point(tmp_path, monkeypatch):
    monkeypatch.setattr("assistant.catalog._TOOLS", [dict(tool) for tool in _TOOLS])
    executor = ToolExecutor(make_hub(tmp_path))
    spec = {
        "id": "demo.ping",
        "version": "1",
        "name": "演示",
        "description": "extension point demo",
        "examples": [],
        "risk": "read",
        "confirmation": "none",
        "scope": "demo.read",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    }
    register_tool(spec)
    executor.register_handler("demo.ping", lambda exec_, args, ctx: {"pong": True})
    assert executor.execute("demo.ping", {}) == {"pong": True}
    assert tool_spec("demo.ping")["name"] == "演示"


def test_register_tool_rejects_duplicate_and_malformed():
    with pytest.raises(ValueError):
        register_tool({
            "id": "status.get", "version": "1", "name": "重复", "description": "x",
            "examples": [], "risk": "read", "confirmation": "none", "scope": "s",
            "inputSchema": {"type": "object", "properties": {}},
        })
    with pytest.raises(ValueError):
        register_tool({
            "id": "demo.bad", "version": "1", "name": "坏", "description": "x",
            "examples": [], "risk": "nuclear", "confirmation": "none", "scope": "s",
            "inputSchema": {"type": "object", "properties": {}},
        })
