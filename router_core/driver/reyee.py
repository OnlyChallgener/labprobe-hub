"""Reyee/Ruijie Router Driver Adapter (Legacy Adapter).

Phase 1 Compatibility Adapter:
Wraps the existing stable RuijieRouterClient / RouterController without modifying
AES, login, SID, CookieJar, Session refresh, or RPC wire serialization.
"""

from typing import Any, Dict, List, Optional
from .base import RouterDriver
from router_core.errors import from_legacy_error


class ReyeeEWebDriver(RouterDriver):
    """Legacy Adapter for Reyee eWeb OS router hardware."""

    def __init__(self, client: Any, controller: Optional[Any] = None):
        self._client = client
        self._controller = controller

    @property
    def client(self) -> Any:
        return self._client

    @property
    def controller(self) -> Optional[Any]:
        return self._controller

    def get_capabilities(self) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "capabilities"):
                return self._client.capabilities()
            configured = bool(getattr(self._client, "config", {}).get("address"))
            return {
                "configured": configured,
                "features": {
                    "dashboard": configured,
                    "devices": configured,
                    "firewall": configured,
                    "nativePortMapping": configured,
                    "upnp": configured,
                    "ddns": configured,
                    "diagnostic": configured,
                },
            }
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_status(self) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "status"):
                return self._client.status()
            if hasattr(self._client, "get_status"):
                return self._client.get_status()
            # Default compatibility fallback from client session state
            session = getattr(self._client, "session", None)
            connected = bool(session and getattr(session, "sid", None) and getattr(session, "valid_locally", False))
            return {
                "state": "connected" if connected else "checking",
                "connected": connected,
                "sessionConnected": connected,
                "dataAvailable": connected,
                "message": "路由连接正常" if connected else "正在准备路由控制数据",
                "errorCode": "",
                "lastSuccessAt": int(getattr(session, "obtained_at", 0) * 1000) if session else 0,
            }
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_dashboard(self, force: bool = False) -> Dict[str, Any]:
        try:
            return self._client.dashboard(force=force)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_devices(self, force: bool = False) -> List[Dict[str, Any]]:
        try:
            res = self._client.devices(force=force)
            if isinstance(res, list):
                return res
            if isinstance(res, dict) and "devices" in res:
                return res["devices"]
            return []
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_port_mappings(self, force: bool = False) -> Dict[str, Any]:
        try:
            return self._client.native_port_mapping(force=force)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_port_mapping(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "add_native_port_mapping"):
                return self._client.add_native_port_mapping(rule)
            raise NotImplementedError("add_native_port_mapping not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_port_mapping(self, old_name: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "update_native_port_mapping"):
                return self._client.update_native_port_mapping(old_name, rule)
            raise NotImplementedError("update_native_port_mapping not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_port_mapping(self, rule_name: str) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "delete_native_port_mapping"):
                return self._client.delete_native_port_mapping(rule_name)
            raise NotImplementedError("delete_native_port_mapping not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_upnp(self, force: bool = False) -> Dict[str, Any]:
        try:
            return self._client.upnp(force=force)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def set_upnp(self, enabled: bool, wan: str) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "set_upnp"):
                return self._client.set_upnp(enabled, wan)
            raise NotImplementedError("set_upnp not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_firewall(self, force: bool = False) -> Dict[str, Any]:
        try:
            return self._client.firewall(force=force)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_firewall_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "add_firewall_rule"):
                return self._client.add_firewall_rule(rule)
            raise NotImplementedError("add_firewall_rule not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_firewall_rule(self, uuid: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "update_firewall_rule"):
                return self._client.update_firewall_rule(uuid, rule)
            raise NotImplementedError("update_firewall_rule not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def set_firewall_rule_enabled(self, uuid: str, enabled: bool) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "set_firewall_rule_enabled"):
                return self._client.set_firewall_rule_enabled(uuid, enabled)
            raise NotImplementedError("set_firewall_rule_enabled not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_firewall_rule(self, uuid: str) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "delete_firewall_rule"):
                return self._client.delete_firewall_rule(uuid)
            raise NotImplementedError("delete_firewall_rule not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def reorder_firewall_rules(self, scope: str, uuids: List[str]) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "reorder_firewall_rules"):
                return self._client.reorder_firewall_rules(scope, uuids)
            raise NotImplementedError("reorder_firewall_rules not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_ddns(self, force: bool = False) -> Dict[str, Any]:
        try:
            return self._client.ddns(force=force)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_ddns(self, record: Dict[str, Any], password: str) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "add_ddns"):
                return self._client.add_ddns(record, password)
            raise NotImplementedError("add_ddns not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_ddns(self, service_id: str, record: Dict[str, Any], password: Optional[str]) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "update_ddns"):
                return self._client.update_ddns(service_id, record, password)
            raise NotImplementedError("update_ddns not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_ddns(self, service_id: str) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "delete_ddns"):
                return self._client.delete_ddns(service_id)
            raise NotImplementedError("delete_ddns not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_ipv6_status(self) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "ipv6_status"):
                return self._client.ipv6_status()
            raise NotImplementedError("ipv6_status not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_ipv6_config(self) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "ipv6_config"):
                return self._client.ipv6_config()
            raise NotImplementedError("ipv6_config not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_dhcpv6_clients(self) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "dhcpv6_clients"):
                return self._client.dhcpv6_clients()
            raise NotImplementedError("dhcpv6_clients not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def save_ipv6_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "save_ipv6_config"):
                return self._client.save_ipv6_config(config)
            raise NotImplementedError("save_ipv6_config not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_diagnostic(self) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "diagnostic"):
                return self._client.diagnostic()
            raise NotImplementedError("diagnostic not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def start_diagnostic(self) -> Dict[str, Any]:
        try:
            if hasattr(self._client, "start_diagnostic"):
                return self._client.start_diagnostic()
            raise NotImplementedError("start_diagnostic not supported on client")
        except Exception as exc:
            raise from_legacy_error(exc) from exc
