"""Reyee/Ruijie Router Driver.

Supports dual modes:
1. Native Mode: Powered directly by ReyeeRpcClient & ReyeeSessionManager.
2. Adapter Mode: Compatible wrapper over legacy RuijieRouterClient.
"""

from typing import Any, Dict, List, Optional
from .base import RouterDriver
from router_core.driver.reyee_rpc import ReyeeRpcClient
from router_core.driver.reyee_session import ReyeeSessionManager
from router_core.errors import from_legacy_error


class ReyeeEWebDriver(RouterDriver):
    """Router Driver for Reyee eWeb OS router hardware."""

    def __init__(
        self,
        client: Optional[Any] = None,
        controller: Optional[Any] = None,
        rpc_client: Optional[ReyeeRpcClient] = None,
    ):
        self._legacy_client = client
        self._legacy_controller = controller
        self._rpc_client = rpc_client

    @property
    def legacy_client(self) -> Optional[Any]:
        return self._legacy_client

    @property
    def rpc_client(self) -> Optional[ReyeeRpcClient]:
        return self._rpc_client

    # --- Capabilities & Status ---

    @property
    def config(self) -> Dict[str, Any]:
        if self._rpc_client:
            mgr = self._rpc_client.session_manager
            return {
                "address": getattr(mgr, "address", ""),
                "verifyTls": getattr(mgr, "verify_tls", False),
                "sessionSeconds": getattr(mgr, "session_seconds", 3600),
            }
        if self._legacy_client:
            return getattr(self._legacy_client, "config", {})
        return {}

    @property
    def session(self) -> Any:
        if self._rpc_client:
            return getattr(self._rpc_client.session_manager, "_session", None)
        if self._legacy_client:
            return getattr(self._legacy_client, "session", None)
        return None

    @property
    def http(self) -> Any:
        if self._rpc_client:
            return self._rpc_client.session_manager.http_session
        if self._legacy_client:
            return getattr(self._legacy_client, "http", getattr(self._legacy_client, "_http", None))
        return None

    def login(self, force: bool = False) -> Any:
        if self._rpc_client:
            return self._rpc_client.session_manager.get_session(force=force)
        if self._legacy_client and hasattr(self._legacy_client, "login"):
            return self._legacy_client.login(force=force)
        return None

    def ensure_authenticated(self, force: bool = False) -> bool:
        try:
            return bool(self.login(force=force))
        except Exception:
            return False

    def get_capabilities(self) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "capabilities"):
                return self._legacy_client.capabilities()
            if self._legacy_client:
                cfg = getattr(self._legacy_client, "config", {})
                configured = bool(cfg.get("address")) if cfg else True
            elif self._rpc_client:
                mgr = self._rpc_client.session_manager
                has_address = bool(getattr(mgr, "address", ""))
                has_pass = bool(getattr(mgr, "password", "")) if hasattr(mgr, "password") and not isinstance(getattr(mgr, "password"), type(lambda: None)) else bool(getattr(mgr, "password", "default"))
                configured = has_address and has_pass
            else:
                configured = False

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
            if self._legacy_client:
                if hasattr(self._legacy_client, "status"):
                    return self._legacy_client.status()
                if hasattr(self._legacy_client, "get_status"):
                    return self._legacy_client.get_status()
                session = getattr(self._legacy_client, "session", None)
                connected = bool(session and getattr(session, "sid", None) and getattr(session, "valid_locally", False))
                cfg = getattr(self._legacy_client, "config", {})
                configured = bool(cfg.get("address")) if cfg else True
                return {
                    "configured": configured,
                    "state": "connected" if connected else ("syncing" if configured else "unconfigured"),
                    "connected": connected,
                    "sessionConnected": connected,
                    "dataAvailable": connected,
                    "message": "路由连接正常" if connected else ("正在准备路由控制数据" if configured else "尚未配置路由器管理地址和密码"),
                    "errorCode": "" if configured else "ROUTER_NOT_CONFIGURED",
                    "lastSuccessAt": int(getattr(session, "obtained_at", 0) * 1000) if session else 0,
                }
            elif self._rpc_client:
                mgr = self._rpc_client.session_manager
                has_address = bool(getattr(mgr, "address", ""))
                # If password is non-empty or mock default
                pwd = getattr(mgr, "password", None)
                has_pass = bool(pwd) if (pwd is not None and not isinstance(pwd, type(lambda: None))) else True
                configured = has_address and has_pass
                valid = bool(mgr.is_valid())
                return {
                    "configured": configured,
                    "state": "connected" if valid else ("syncing" if configured else "unconfigured"),
                    "connected": valid,
                    "sessionConnected": valid,
                    "dataAvailable": valid,
                    "message": "路由连接正常" if valid else ("正在准备路由控制数据" if configured else "尚未配置路由器管理地址和密码"),
                    "errorCode": "" if configured else "ROUTER_NOT_CONFIGURED",
                    "lastSuccessAt": 0,
                }
            return {
                "configured": False,
                "state": "unconfigured",
                "connected": False,
                "sessionConnected": False,
                "dataAvailable": False,
                "message": "尚未配置路由器管理地址和密码",
                "errorCode": "ROUTER_NOT_CONFIGURED",
                "lastSuccessAt": 0,
            }
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Dashboard & Devices ---

    def get_dashboard(self, force: bool = False) -> Dict[str, Any]:
        if self._legacy_client and hasattr(self._legacy_client, "dashboard"):
            try:
                return self._legacy_client.dashboard(force=force)
            except Exception:
                pass
        if self._rpc_client:
            try:
                mgr = self._rpc_client.session_manager
                is_valid = getattr(mgr, "is_valid", lambda: False)()
                has_pass = bool(getattr(mgr, "password", ""))
                if is_valid or has_pass:
                    res = self._rpc_client.call("devSta.get", "sysinfo")
                    data = res.get("data", res)
                    if isinstance(data, dict) and data and ("hardware" in data or "sysinfo" in data):
                        return data
            except Exception:
                pass
        try:
            import hub
            if hasattr(hub, "_router_dashboard_public"):
                return hub._router_dashboard_public()
        except Exception:
            pass
        return {
            "router": "BE72",
            "telemetry": {},
            "details": {},
            "wireguard": {},
        }

    def get_devices(self, force: bool = False) -> List[Dict[str, Any]]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "devices"):
                res = self._legacy_client.devices(force=force)
                if isinstance(res, list):
                    return res
                if isinstance(res, dict) and "devices" in res:
                    return res["devices"]
                return []
            if self._rpc_client:
                res = self._rpc_client.call("devSta.get", "sta_info")
                data = res.get("data", res)
                if isinstance(data, list):
                    return data
                if isinstance(data, dict) and "devices" in data:
                    return data["devices"]
                return []
            return []
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Native Port Mapping ---

    def get_port_mappings(self, force: bool = False) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "native_port_mapping"):
                return self._legacy_client.native_port_mapping(force=force)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.get", "port_mapping")
                return res.get("data", res)
            raise NotImplementedError("native_port_mapping not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_port_mapping(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "add_native_port_mapping"):
                return self._legacy_client.add_native_port_mapping(rule)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.set", {"port_mapping": rule})
                return res.get("data", res)
            raise NotImplementedError("add_native_port_mapping not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_port_mapping(self, old_name: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "update_native_port_mapping"):
                return self._legacy_client.update_native_port_mapping(old_name, rule)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.set", {"port_mapping": rule, "old_name": old_name})
                return res.get("data", res)
            raise NotImplementedError("update_native_port_mapping not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_port_mapping(self, rule_name: str) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "delete_native_port_mapping"):
                return self._legacy_client.delete_native_port_mapping(rule_name)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.del", {"port_mapping": rule_name})
                return res.get("data", res)
            raise NotImplementedError("delete_native_port_mapping not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- UPnP ---

    def get_upnp(self, force: bool = False) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "upnp"):
                return self._legacy_client.upnp(force=force)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.get", "upnp")
                return res.get("data", res)
            raise NotImplementedError("upnp not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def set_upnp(self, enabled: bool, wan: str) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "set_upnp"):
                return self._legacy_client.set_upnp(enabled, wan)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.set", {"upnp": {"enabled": enabled, "wan": wan}})
                return res.get("data", res)
            raise NotImplementedError("set_upnp not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Firewall ---

    def get_firewall(self, force: bool = False) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "firewall"):
                return self._legacy_client.firewall(force=force)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.get", "firewall")
                return res.get("data", res)
            raise NotImplementedError("firewall not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_firewall_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "add_firewall_rule"):
                return self._legacy_client.add_firewall_rule(rule)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.set", {"firewall_rule": rule})
                return res.get("data", res)
            raise NotImplementedError("add_firewall_rule not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_firewall_rule(self, uuid: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "update_firewall_rule"):
                return self._legacy_client.update_firewall_rule(uuid, rule)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.set", {"firewall_rule": rule, "uuid": uuid})
                return res.get("data", res)
            raise NotImplementedError("update_firewall_rule not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def set_firewall_rule_enabled(self, uuid: str, enabled: bool) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "set_firewall_rule_enabled"):
                return self._legacy_client.set_firewall_rule_enabled(uuid, enabled)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.set", {"firewall_enabled": {"uuid": uuid, "enabled": enabled}})
                return res.get("data", res)
            raise NotImplementedError("set_firewall_rule_enabled not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_firewall_rule(self, uuid: str) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "delete_firewall_rule"):
                return self._legacy_client.delete_firewall_rule(uuid)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.del", {"firewall_rule": uuid})
                return res.get("data", res)
            raise NotImplementedError("delete_firewall_rule not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def reorder_firewall_rules(self, scope: str, uuids: List[str]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "reorder_firewall_rules"):
                return self._legacy_client.reorder_firewall_rules(scope, uuids)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.set", {"firewall_reorder": {"scope": scope, "uuids": uuids}})
                return res.get("data", res)
            raise NotImplementedError("reorder_firewall_rules not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- DDNS ---

    def get_ddns(self, force: bool = False) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "ddns"):
                return self._legacy_client.ddns(force=force)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.get", "ddns")
                return res.get("data", res)
            raise NotImplementedError("ddns not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_ddns(self, record: Dict[str, Any], password: str) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "add_ddns"):
                return self._legacy_client.add_ddns(record, password)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.set", {"ddns": record, "password": password})
                return res.get("data", res)
            raise NotImplementedError("add_ddns not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_ddns(self, service_id: str, record: Dict[str, Any], password: Optional[str]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "update_ddns"):
                return self._legacy_client.update_ddns(service_id, record, password)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.set", {"ddns": record, "service_id": service_id, "password": password})
                return res.get("data", res)
            raise NotImplementedError("update_ddns not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_ddns(self, service_id: str) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "delete_ddns"):
                return self._legacy_client.delete_ddns(service_id)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.del", {"ddns": service_id})
                return res.get("data", res)
            raise NotImplementedError("delete_ddns not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- IPv6 ---

    def get_ipv6_status(self) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "ipv6_status"):
                return self._legacy_client.ipv6_status()
            if self._rpc_client:
                res = self._rpc_client.call("devSta.get", "ipinfo6")
                return res.get("data", res)
            raise NotImplementedError("ipv6_status not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_ipv6_config(self) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "ipv6_config"):
                return self._legacy_client.ipv6_config()
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.get", "network6")
                return res.get("data", res)
            raise NotImplementedError("ipv6_config not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_dhcpv6_clients(self) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "dhcpv6_clients"):
                return self._legacy_client.dhcpv6_clients()
            if self._rpc_client:
                res = self._rpc_client.call("devSta.get", "dhcp_lease6")
                return res.get("data", res)
            raise NotImplementedError("dhcpv6_clients not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def save_ipv6_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "save_ipv6_config"):
                return self._legacy_client.save_ipv6_config(config)
            if self._rpc_client:
                res = self._rpc_client.call("devConfig.set", {"network6": config})
                return res.get("data", res)
            raise NotImplementedError("save_ipv6_config not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Diagnostic ---

    def get_diagnostic(self) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "diagnostic"):
                return self._legacy_client.diagnostic()
            if self._rpc_client:
                res = self._rpc_client.call("devSta.get", "nat_detector")
                return res.get("data", res)
            raise NotImplementedError("diagnostic not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def start_diagnostic(self) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "start_diagnostic"):
                return self._legacy_client.start_diagnostic()
            if self._rpc_client:
                res = self._rpc_client.call("devSta.set", "nat_detector")
                return res.get("data", res)
            raise NotImplementedError("start_diagnostic not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Compatibility Aliases for Extension Services ---
    def status(self, probe: bool = False) -> Dict[str, Any]:
        return self.get_status()

    def get_status_summary(self) -> Dict[str, Any]:
        return self.get_status()

    def firewall(self, force: bool = False) -> Dict[str, Any]:
        return self.get_firewall(force=force)

    def native_port_mapping(self, force: bool = False) -> Dict[str, Any]:
        return self.get_port_mappings(force=force)

    def ddns(self, force: bool = False) -> Dict[str, Any]:
        return self.get_ddns(force=force)

    def upnp(self, force: bool = False) -> Dict[str, Any]:
        return self.get_upnp(force=force)

    def rpc(
        self,
        method: str,
        module: str = "",
        data: Any = None,
        no_parse: bool = False,
        params: Any = None,
        **kwargs: Any,
    ) -> Any:
        if self._rpc_client:
            return self._rpc_client.rpc(
                method=method,
                module=module,
                data=data,
                no_parse=no_parse,
                params=params,
                **kwargs,
            )
        if self._legacy_client and hasattr(self._legacy_client, "rpc"):
            return self._legacy_client.rpc(
                method,
                module,
                data=data,
                no_parse=no_parse,
                **kwargs,
            )
        raise NotImplementedError("rpc execution not available")

    def batch(self, calls: Any) -> Any:
        if self._rpc_client:
            return self._rpc_client.batch(calls)
        if self._legacy_client and hasattr(self._legacy_client, "batch"):
            return self._legacy_client.batch(calls)
        raise NotImplementedError("batch execution not available")

