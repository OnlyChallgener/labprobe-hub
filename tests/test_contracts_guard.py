"""Contract Guard Tests.

Guards the frozen contract defined in docs/contracts/app-hub-contract-v1.json.
Ensures zero contract drift across refactorings.
"""

import json
from pathlib import Path
import pytest


def load_frozen_contract():
    root = Path(__file__).resolve().parent.parent
    contract_path = root / "docs" / "contracts" / "app-hub-contract-v1.json"
    assert contract_path.exists(), f"Contract file not found at {contract_path}"
    with open(contract_path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_frozen_contract_structure():
    data = load_frozen_contract()
    assert data["version"] == "1.0.0"
    assert "extractedAt" in data
    assert len(data["rest"]) == data["totalRestEndpoints"]
    assert len(data["websocket"][0]["frames"]) == data["totalWebSocketTypes"]
    assert data["totalRestEndpoints"] == 74
    assert data["totalWebSocketTypes"] == 8


def test_frozen_contract_endpoints_integrity():
    data = load_frozen_contract()
    required_endpoints = {
        ("/api/router/capabilities", "GET"),
        ("/api/router/status", "GET"),
        ("/api/router/port-mapping", "GET"),
        ("/api/router/port-mapping", "POST"),
        ("/api/router/port-mapping/{ruleName}", "PUT"),
        ("/api/router/port-mapping/{ruleName}", "DELETE"),
        ("/api/router/upnp", "GET"),
        ("/api/router/upnp", "PUT"),
        ("/api/router/firewall", "GET"),
        ("/api/router/firewall/rules", "POST"),
        ("/api/router/firewall/rules/{uuid}", "PUT"),
        ("/api/router/firewall/rules/{uuid}/enabled", "PATCH"),
        ("/api/router/firewall/rules/{uuid}", "DELETE"),
        ("/api/router/firewall/reorder", "POST"),
        ("/api/router/ddns", "GET"),
        ("/api/router/ddns", "POST"),
        ("/api/router/ddns/{serviceId}", "PUT"),
        ("/api/router/ddns/{serviceId}", "DELETE"),
        ("/api/ddns", "GET"),
        ("/api/ddns/providers", "GET"),
        ("/api/ddns", "POST"),
        ("/api/ddns/{recordId}", "PUT"),
        ("/api/ddns/{recordId}", "DELETE"),
        ("/api/ddns/{recordId}/update", "POST"),
        ("/api/router/ipv6/status", "GET"),
        ("/api/router/ipv6/config", "GET"),
        ("/api/router/ipv6/clients", "GET"),
        ("/api/router/ipv6/config", "PUT"),
        ("/api/router/diagnostic", "GET"),
        ("/api/router/diagnostic", "POST"),
        ("/api/portmaps", "GET"),
        ("/api/portmaps", "POST"),
        ("/api/portmaps/{id}", "PUT"),
        ("/api/portmaps/{id}", "DELETE"),
        ("/api/portmaps/{id}/{action}", "POST"),
        ("/api/portmaps/{id}/history", "GET"),
        ("/api/stun", "GET"),
        ("/api/stun", "POST"),
        ("/api/stun/{id}", "PUT"),
        ("/api/stun/{id}/{action}", "POST"),
        ("/api/stun/{id}", "DELETE"),
        ("/api/stun/{id}/addresses", "GET"),
        ("/api/wireguard/server", "GET"),
        ("/api/wireguard/server", "PUT"),
        ("/api/wireguard/endpoints/{id}", "PATCH"),
        ("/api/router/firewall/automation", "GET"),
        ("/api/router/firewall/automation/{firewallUuid}", "PUT"),
        ("/api/router/firewall/automation/{firewallUuid}", "DELETE"),
        ("/api/router/firewall/automation/{firewallUuid}/sync", "POST"),
        ("/api/router/tasks/{kind}", "GET"),
        ("/api/router/nat-diagnostic", "POST"),
        ("/api/router/beta-upgrade", "POST"),
        ("/api/router/realtime", "GET"),
        ("/api/devices/realtime", "GET"),
        ("/api/agent/update/check", "GET"),
        ("/api/agent/update", "POST"),
        ("/api/agent/update/status", "GET"),
        ("/api/agent/cleanup", "POST"),
        ("/api/agent/cleanup/status", "GET"),
        ("/api/status", "GET"),
        ("/api/router/dashboard", "GET"),
        ("/api/router/dashboard/refresh", "POST"),
        ("/api/devices", "GET"),
        ("/api/sync/changes", "GET"),
        ("/api/sync/snapshot", "GET"),
        ("/api/sync/revision", "GET"),
        ("/api/events", "GET"),
        ("/api/events/{id}", "DELETE"),
        ("/api/daily", "GET"),
        ("/api/daily/latest", "GET"),
        ("/api/daily/list", "GET"),
        ("/api/daily/note", "PUT"),
        ("/api/wol", "POST"),
        ("/api/geo", "GET"),
    }

    found = {(item["endpoint"], item["method"]) for item in data["rest"]}
    missing = required_endpoints - found
    assert not missing, f"Missing required endpoints from frozen contract: {missing}"


def test_frozen_contract_websocket_and_watchdog():
    data = load_frozen_contract()
    ws = data["websocket"][0]
    assert ws["endpoint"] == "/api/realtime/ws"

    wd = ws["watchdog"]
    assert wd["okhttpPingIntervalSeconds"] == 10
    assert wd["watchdogCheckIntervalSeconds"] == 1
    assert wd["serverFrameTimeoutSeconds"] == 45

    frame_types = {frame["type"] for frame in ws["frames"]}
    expected_types = {
        "ready",
        "router",
        "devices",
        "devices_snapshot",
        "task",
        "config",
        "agent",
        "keepalive",
    }
    assert frame_types == expected_types
