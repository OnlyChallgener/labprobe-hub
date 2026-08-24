"""Router Core Service Compatibility Layer.

Acts as the formal bridge between Hub HTTP routes and Router Drivers.
Guarantees 100% contract fidelity with docs/contracts/app-hub-contract-v1.json:
- Exact JSON response wrapping {"data": ...}
- Exact field naming and defaults
- Accurate mutation read-back
- Seamless config notification triggers
- Unified error translation
"""

from typing import Any, Callable, Dict, List, Optional
from router_core.driver.base import RouterDriver
from router_core.errors import RouterCoreError, from_legacy_error


class RouterService:
    """Core domain service for router native capabilities."""

    def __init__(
        self,
        driver: RouterDriver,
        notify_config_change: Optional[Callable[[str, str, Dict[str, Any]], None]] = None,
    ):
        self._driver = driver
        self._notify_config_change = notify_config_change

    @property
    def driver(self) -> RouterDriver:
        return self._driver

    def _notify(self, resource: str, action: str, data: Dict[str, Any]) -> None:
        if self._notify_config_change:
            try:
                self._notify_config_change(resource, action, data)
            except Exception:
                pass

    def _ensure_data_wrapper(self, res: Any) -> Dict[str, Any]:
        """Ensures the response has the standard {"data": ...} wrapper expected by App."""
        if isinstance(res, dict) and "data" in res:
            return res
        return {"data": res if isinstance(res, dict) else {}}

    # --- Capabilities & Status ---

    def get_capabilities(self) -> Dict[str, Any]:
        try:
            return self._driver.get_capabilities()
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_status(self) -> Dict[str, Any]:
        try:
            return self._driver.get_status()
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_dashboard(self, force: bool = False) -> Dict[str, Any]:
        try:
            return self._driver.get_dashboard(force=force)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_devices(self, force: bool = False) -> List[Dict[str, Any]]:
        try:
            return self._driver.get_devices(force=force)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Native Port Mapping ---

    def get_port_mappings(self, force: bool = False) -> Dict[str, Any]:
        try:
            res = self._driver.get_port_mappings(force=force)
            return self._ensure_data_wrapper(res)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_port_mapping(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            res = self._driver.add_port_mapping(rule)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("portMappings", "add", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_port_mapping(self, old_name: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            res = self._driver.update_port_mapping(old_name, rule)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("portMappings", "update", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_port_mapping(self, rule_name: str) -> Dict[str, Any]:
        try:
            res = self._driver.delete_port_mapping(rule_name)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("portMappings", "delete", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- UPnP ---

    def get_upnp(self, force: bool = False) -> Dict[str, Any]:
        try:
            res = self._driver.get_upnp(force=force)
            return self._ensure_data_wrapper(res)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def set_upnp(self, enabled: bool, wan: str) -> Dict[str, Any]:
        try:
            res = self._driver.set_upnp(enabled, wan)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("upnp", "update", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Firewall ---

    def get_firewall(self, force: bool = False) -> Dict[str, Any]:
        try:
            res = self._driver.get_firewall(force=force)
            return self._ensure_data_wrapper(res)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_firewall_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            res = self._driver.add_firewall_rule(rule)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("firewall", "add", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_firewall_rule(self, uuid: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            res = self._driver.update_firewall_rule(uuid, rule)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("firewall", "update", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def set_firewall_rule_enabled(self, uuid: str, enabled: bool) -> Dict[str, Any]:
        try:
            res = self._driver.set_firewall_rule_enabled(uuid, enabled)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("firewall", "update", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_firewall_rule(self, uuid: str) -> Dict[str, Any]:
        try:
            res = self._driver.delete_firewall_rule(uuid)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("firewall", "delete", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def reorder_firewall_rules(self, scope: str, uuids: List[str]) -> Dict[str, Any]:
        try:
            res = self._driver.reorder_firewall_rules(scope, uuids)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("firewall", "reorder", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Native DDNS ---

    def get_ddns(self, force: bool = False) -> Dict[str, Any]:
        try:
            res = self._driver.get_ddns(force=force)
            return self._ensure_data_wrapper(res)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_ddns(self, record: Dict[str, Any], password: str) -> Dict[str, Any]:
        try:
            res = self._driver.add_ddns(record, password)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("ddns", "add", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_ddns(self, service_id: str, record: Dict[str, Any], password: Optional[str]) -> Dict[str, Any]:
        try:
            res = self._driver.update_ddns(service_id, record, password)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("ddns", "update", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_ddns(self, service_id: str) -> Dict[str, Any]:
        try:
            res = self._driver.delete_ddns(service_id)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("ddns", "delete", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- IPv6 ---

    def get_ipv6_status(self) -> Dict[str, Any]:
        try:
            res = self._driver.get_ipv6_status()
            return self._ensure_data_wrapper(res)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_ipv6_config(self) -> Dict[str, Any]:
        try:
            res = self._driver.get_ipv6_config()
            return self._ensure_data_wrapper(res)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_dhcpv6_clients(self) -> Dict[str, Any]:
        try:
            res = self._driver.get_dhcpv6_clients()
            return self._ensure_data_wrapper(res)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def save_ipv6_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        try:
            res = self._driver.save_ipv6_config(config)
            wrapped = self._ensure_data_wrapper(res)
            self._notify("ipv6", "update", wrapped.get("data", {}))
            return wrapped
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Diagnostic ---

    def get_diagnostic(self) -> Dict[str, Any]:
        try:
            res = self._driver.get_diagnostic()
            return self._ensure_data_wrapper(res)
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def start_diagnostic(self) -> Dict[str, Any]:
        try:
            res = self._driver.start_diagnostic()
            return self._ensure_data_wrapper(res)
        except Exception as exc:
            raise from_legacy_error(exc) from exc
