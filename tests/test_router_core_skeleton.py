"""Router Core Compatibility Skeleton Tests.

Verifies:
1. Data contracts serialization.
2. Driver adapter delegation without extra RPC calls.
3. RouterService data wrapping {"data": ...} and notification dispatch.
4. Error translation equivalence.
"""

from typing import Any, Dict, List, Optional
import pytest

from router_core.contracts import (
    RouterCapabilities,
    RouterStatus,
    NativePortMapRule,
    UpnpRule,
    UpnpState,
    FirewallRule,
    FirewallState,
    DdnsRecord,
    DdnsState,
    Ipv6Config,
    RouterDiagnostic,
)
from router_core.errors import (
    RouterCoreError,
    RouterNotConfiguredError,
    RouterUnreachableError,
    RouterAuthError,
    from_legacy_error,
)
from router_core.driver.base import RouterDriver
from router_core.driver.reyee import ReyeeEWebDriver
from router_core.service.router_service import RouterService


class MockLegacyClient:
    """Mock simulating existing RuijieRouterClient without network."""

    def __init__(self):
        self.call_counts: Dict[str, int] = {}
        self.config = {"address": "https://192.168.110.1"}

    def _record(self, name: str):
        self.call_counts[name] = self.call_counts.get(name, 0) + 1

    def dashboard(self, force: bool = False) -> Dict[str, Any]:
        self._record("dashboard")
        return {"hardware": {"cpu": 12.5}}

    def devices(self, force: bool = False) -> List[Dict[str, Any]]:
        self._record("devices")
        return [{"mac": "AA:BB:CC:DD:EE:FF"}]

    def native_port_mapping(self, force: bool = False) -> Dict[str, Any]:
        self._record("native_port_mapping")
        return {"rules": [{"name": "web", "extPort": 8080}]}

    def add_native_port_mapping(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        self._record("add_native_port_mapping")
        return {"rules": [rule]}

    def firewall(self, force: bool = False) -> Dict[str, Any]:
        self._record("firewall")
        return {"wanInboundAllow": False, "rules": []}

    def add_firewall_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        self._record("add_firewall_rule")
        return {"wanInboundAllow": False, "rules": [rule]}

    def upnp(self, force: bool = False) -> Dict[str, Any]:
        self._record("upnp")
        return {"enabled": True, "wan": "WAN", "rules": []}

    def ddns(self, force: bool = False) -> Dict[str, Any]:
        self._record("ddns")
        return {"services": []}

    def ipv6_status(self) -> Dict[str, Any]:
        self._record("ipv6_status")
        return {"enabled": True, "wanAddress": "240e::1"}

    def diagnostic(self) -> Dict[str, Any]:
        self._record("diagnostic")
        return {"process": "100%", "List": []}


def test_contracts_to_dict():
    cap = RouterCapabilities(configured=True, dashboard=True, firewall=True)
    d = cap.to_dict()
    assert d["configured"] is True
    assert d["features"]["dashboard"] is True
    assert d["features"]["firewall"] is True
    assert d["features"]["upnp"] is False

    rule = NativePortMapRule(name="ssh", extPort=2222, intPort=22)
    assert rule.to_dict()["extPort"] == 2222


def test_legacy_reyee_driver_adapter():
    client = MockLegacyClient()
    driver = ReyeeEWebDriver(client)

    # Test capabilities
    caps = driver.get_capabilities()
    assert caps["configured"] is True
    assert caps["features"]["dashboard"] is True

    # Test dashboard single call
    dash = driver.get_dashboard(force=True)
    assert dash["hardware"]["cpu"] == 12.5
    assert client.call_counts["dashboard"] == 1

    # Test devices
    devs = driver.get_devices()
    assert len(devs) == 1
    assert client.call_counts["devices"] == 1


def test_router_service_data_wrapping_and_notifications():
    client = MockLegacyClient()
    driver = ReyeeEWebDriver(client)
    notifications = []

    def on_notify(resource: str, action: str, data: Dict[str, Any]):
        notifications.append((resource, action, data))

    service = RouterService(driver, notify_config_change=on_notify)

    # 1. get_port_mappings ensures {"data": {"rules": [...]}}
    res = service.get_port_mappings(force=True)
    assert "data" in res
    assert "rules" in res["data"]
    assert client.call_counts["native_port_mapping"] == 1

    # 2. add_port_mapping dispatches notification
    new_rule = {"name": "test_port", "extPort": 9000, "intPort": 9000, "interface": "WAN", "proto": "tcp", "enabled": True}
    add_res = service.add_port_mapping(new_rule)
    assert "data" in add_res
    assert len(notifications) == 1
    assert notifications[0][0] == "portMappings"
    assert notifications[0][1] == "add"

    # 3. get_firewall ensures {"data": ...}
    fw_res = service.get_firewall()
    assert "data" in fw_res
    assert "wanInboundAllow" in fw_res["data"]

    # 4. Zero additional RPC calls
    assert client.call_counts.get("dashboard", 0) == 0
    dash = service.get_dashboard()
    assert dash["hardware"]["cpu"] == 12.5
    assert client.call_counts.get("dashboard", 0) == 1


def test_error_translation_equivalence():
    class DummyAuthErr(Exception):
        pass

    class DummyUnreachErr(Exception):
        pass

    err1 = from_legacy_error(DummyAuthErr("Router login failed (401)"))
    assert isinstance(err1, RouterAuthError)
    assert err1.status_code == 401
    assert err1.code == "LOGIN_FAILED"

    err2 = from_legacy_error(DummyUnreachErr("Connection refused - router unreachable"))
    assert isinstance(err2, RouterUnreachableError)
    assert err2.status_code == 502
    assert err2.code == "ROUTER_UNREACHABLE"
