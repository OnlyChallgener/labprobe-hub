from types import SimpleNamespace

from agent_presence_patch import _presence


def _hub(status):
    return SimpleNamespace(
        PORTMAP_ROUTER_STATUS_FILE="runtime.json",
        AGENT_STATUS_FILE="status.json",
        load_json=lambda path, default=None: status.get(path, default),
        primary_router_name=lambda: "router",
        clean_saved_value=lambda value: str(value or "").strip(),
        _normalize_router_alias=lambda value: str(value or "").lower(),
    )


def test_presence_exposes_validated_multi_wan_capabilities():
    snapshot = _presence(_hub({
        "runtime.json": {},
        "status.json": {"router": {
            "lastSeenEpoch": 9999999999,
            "version": "0.2.80",
            "protocolVersion": "2",
            "capabilities": ["relay.multiWan", "relay.wanTelemetry", "bad value"],
            "wanIds": ["WAN", "wan1", "WAN"],
        }},
    }))
    assert snapshot["agentProtocolVersion"] == 2
    assert snapshot["agentCapabilities"] == ["relay.multiWan", "relay.wanTelemetry"]
    assert snapshot["agentWanIds"] == ["wan", "wan1"]


def test_presence_tolerates_malformed_legacy_protocol_field():
    snapshot = _presence(_hub({
        "runtime.json": {},
        "status.json": {"router": {"lastSeenEpoch": 9999999999, "protocolVersion": "bad"}},
    }))
    assert snapshot["agentProtocolVersion"] == 0
    assert snapshot["agentCapabilities"] == []
    assert snapshot["agentWanIds"] == []
