"""Reyee/Ruijie Router Driver.

Supports dual modes:
1. Native Mode: Powered directly by ReyeeRpcClient & ReyeeSessionManager.
2. Adapter Mode: Compatible wrapper over legacy RuijieRouterClient.
"""

import json
import threading
import time
from typing import Any, Callable, Dict, List, Optional
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
        cache: Optional[Any] = None,
    ):
        self._legacy_client = client
        self._legacy_controller = controller
        self._rpc_client = rpc_client
        self.cache = cache
        self.write_lock = threading.RLock()
        self._rpc_lock = threading.RLock()

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
                "password": getattr(mgr, "password", ""),
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

    def _cached(self, key: str, ttl: float, loader: Callable[[], Any], force: bool = False) -> Any:
        if self.cache is None:
            return loader()
        return self.cache.get_or_fetch(key, loader, ttl=ttl, force=force)

    def _invalidate(self, prefix: str) -> None:
        if self.cache is not None:
            self.cache.invalidate(prefix)

    @staticmethod
    def _unwrap_json(value: Any) -> Any:
        current = value
        for _ in range(6):
            if isinstance(current, str):
                text = current.strip()
                if text.startswith(("{", "[")):
                    current = json.loads(text)
                    continue
            break
        return current

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
                state = "connected" if valid else ("syncing" if configured else "unconfigured")
                message = (
                    "路由连接正常"
                    if valid
                    else ("正在准备路由控制数据" if configured else "尚未配置路由器管理地址和密码")
                )
                return {
                    "configured": configured,
                    "state": state,
                    "connected": valid,
                    "sessionConnected": valid,
                    "dataAvailable": valid,
                    "message": message,
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
        if not self._rpc_client:
            return {}

        def load() -> Dict[str, Any]:
            def optional(loader: Callable[[], Any], fallback: Any) -> Any:
                try:
                    return loader()
                except Exception:
                    return fallback

            overview = self.batch([
                {"method": "acConfig.get", "module": "network_group", "noParse": True},
                {"method": "devSta.get", "module": "ap_list", "noParse": True},
                {"method": "devSta.get", "module": "esw_neighbor", "noParse": True},
                {
                    "method": "devSta.get",
                    "module": "neighbor",
                    "noParse": True,
                    "data": {"product": "GW_RGOS"},
                },
            ])
            overview_values = overview if isinstance(overview, list) else []
            network = optional(lambda: self.rpc("devConfig.get", "network"), {})
            wan = optional(lambda: self.batch([
                {"method": "devSta.get", "module": "ipinfo", "noParse": True},
                {"method": "devSta.get", "module": "networkConnect", "data": {"ifname": "list"}},
            ]), [])
            wireless = optional(lambda: self.batch([
                {"method": "acConfig.get", "module": "wireless"},
                {"method": "devSta.get", "module": "rcgame"},
            ]), [])
            wan_values = wan if isinstance(wan, list) else []
            wireless_values = wireless if isinstance(wireless, list) else []
            result = {
                "networkGroup": overview_values[0] if len(overview_values) > 0 else None,
                "apList": overview_values[1] if len(overview_values) > 1 else None,
                "eswNeighbor": overview_values[2] if len(overview_values) > 2 else None,
                "neighbor": overview_values[3] if len(overview_values) > 3 else None,
                "network": network,
                "ipinfo": wan_values[0] if len(wan_values) > 0 else None,
                "networkConnect": wan_values[1] if len(wan_values) > 1 else None,
                "wireless": wireless_values[0] if len(wireless_values) > 0 else None,
                "rcgame": wireless_values[1] if len(wireless_values) > 1 else None,
                "portStatus": optional(lambda: self.rpc("devSta.get", "port_status"), {}),
                "updatedAt": int(time.time()),
            }

            # The authenticated router WebSocket is the authoritative source
            # for fast/slow telemetry. Keep it in the same raw dashboard shape
            # consumed by RouterRpcCompatibilitySync instead of maintaining a
            # second projection or polling the router for realtime values.
            monitor = getattr(self, "router_ws_monitor", None)
            if monitor is not None and hasattr(monitor, "snapshot"):
                try:
                    snapshot = monitor.snapshot()
                    if isinstance(snapshot, dict):
                        for key in ("static", "slow", "fast", "recent_wan", "daily_wan", "wsStatus"):
                            if key in snapshot:
                                result[key] = snapshot[key]
                except Exception:
                    pass
            return result

        return self._cached("dashboard", 3.0, load, force)

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
                def load() -> List[Dict[str, Any]]:
                    raw = self._unwrap_json(self.rpc(
                        "devSta.get",
                        "user_list",
                        {"devType": "all", "dataType": "timely"},
                        no_parse=True,
                    ))
                    rows = raw.get("list", []) if isinstance(raw, dict) else []
                    result: List[Dict[str, Any]] = []
                    for item in rows:
                        if not isinstance(item, dict):
                            continue
                        result.append({
                            **item,
                            "mac": str(item.get("mac") or "").lower(),
                            "ipv4": item.get("userIp") or "",
                            "online": True,
                            "realtimeUpBytes": int(item.get("flowUp") or 0),
                            "realtimeDownBytes": int(item.get("flowDown") or 0),
                            "connectionCount": int(item.get("flow_cnt") or 0),
                        })
                    return result
                return self._cached("devices", 2.0, load, force)
            return []
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Native Port Mapping ---

    def _write_and_read(self, prefix: str, write: Callable[[], Any], read: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        with self.write_lock:
            write()
            self._invalidate(prefix)
            return read()

    def get_port_mappings(self, force: bool = False) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "native_port_mapping"):
                return self._legacy_client.native_port_mapping(force=force)
            if self._rpc_client:
                return self._cached(
                    "native-portmap",
                    15.0,
                    lambda: self.rpc("devConfig.get", "port_mapping"),
                    force,
                )
            raise NotImplementedError("native_port_mapping not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_port_mapping(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "add_native_port_mapping"):
                return self._legacy_client.add_native_port_mapping(rule)
            if self._rpc_client:
                return self._write_and_read(
                    "native-portmap",
                    lambda: self.rpc("devConfig.add", "port_mapping", {"list": [rule]}),
                    lambda: self.get_port_mappings(force=True),
                )
            raise NotImplementedError("add_native_port_mapping not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_port_mapping(self, old_name: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "update_native_port_mapping"):
                return self._legacy_client.update_native_port_mapping(old_name, rule)
            if self._rpc_client:
                latest = self.get_port_mappings(force=True)
                rows = latest.get("portMapping") or latest.get("list") or []
                old = next(
                    (row for row in rows if isinstance(row, dict) and str(row.get("ruleName")) == old_name),
                    None,
                )
                if old is None:
                    raise ValueError("Router native port mapping rule does not exist")
                return self._write_and_read(
                    "native-portmap",
                    lambda: self.rpc("devConfig.update", "port_mapping", {"old": old, "new": rule}),
                    lambda: self.get_port_mappings(force=True),
                )
            raise NotImplementedError("update_native_port_mapping not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_port_mapping(self, rule_name: str) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "delete_native_port_mapping"):
                return self._legacy_client.delete_native_port_mapping(rule_name)
            if self._rpc_client:
                return self._write_and_read(
                    "native-portmap",
                    lambda: self.rpc("devConfig.del", "port_mapping", {"ruleName": [rule_name]}),
                    lambda: self.get_port_mappings(force=True),
                )
            raise NotImplementedError("delete_native_port_mapping not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- UPnP ---

    def get_upnp(self, force: bool = False) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "upnp"):
                return self._legacy_client.upnp(force=force)
            if self._rpc_client:
                return self._cached("upnp", 10.0, lambda: self.rpc("devSta.get", "upnp"), force)
            raise NotImplementedError("upnp not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def set_upnp(self, enabled: bool, wan: str) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "set_upnp"):
                return self._legacy_client.set_upnp(enabled, wan)
            if self._rpc_client:
                latest = self.get_upnp(force=True)
                payload = {
                    "enable_upnp": "true" if enabled else "false",
                    "upnpds": latest.get("upnpds") or [],
                    "upnp_line": str(latest.get("upnp_line") or "1"),
                    "wan": str(wan or latest.get("wan") or "AUTO").upper(),
                }
                return self._write_and_read(
                    "upnp",
                    lambda: self.rpc("devSta.set", "upnp", payload),
                    lambda: self.get_upnp(force=True),
                )
            raise NotImplementedError("set_upnp not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Firewall ---

    def get_firewall(self, force: bool = False) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "firewall"):
                return self._legacy_client.firewall(force=force)
            if self._rpc_client:
                def load() -> Dict[str, Any]:
                    data = self.batch([
                        {"method": "devConfig.get", "module": "ip_firewall"},
                        {"method": "devSta.get", "module": "ip_firewall"},
                    ])
                    config = data[0] if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict) else {}
                    stats = data[1] if isinstance(data, list) and len(data) > 1 and isinstance(data[1], dict) else {}
                    stat_map = {
                        str(row.get("uuid")): row
                        for row in stats.get("list", [])
                        if isinstance(row, dict)
                    }
                    rules = [
                        {**rule, "stats": stat_map.get(str(rule.get("uuid")), {"packets": 0, "bytes": 0})}
                        for rule in config.get("list", [])
                        if isinstance(rule, dict)
                    ]
                    return {**config, "list": rules, "updatedAt": int(time.time())}
                return self._cached("firewall", 5.0, load, force)
            raise NotImplementedError("firewall not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_firewall_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "add_firewall_rule"):
                return self._legacy_client.add_firewall_rule(rule)
            if self._rpc_client:
                return self._write_and_read(
                    "firewall",
                    lambda: self.rpc("devConfig.add", "ip_firewall", {"list": [rule]}),
                    lambda: self.get_firewall(force=True),
                )
            raise NotImplementedError("add_firewall_rule not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_firewall_rule(self, uuid: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "update_firewall_rule"):
                return self._legacy_client.update_firewall_rule(uuid, rule)
            if self._rpc_client:
                payload = {**rule, "uuid": uuid}
                return self._write_and_read(
                    "firewall",
                    lambda: self.rpc("devConfig.update", "ip_firewall", {"list": [payload]}),
                    lambda: self.get_firewall(force=True),
                )
            raise NotImplementedError("update_firewall_rule not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def set_firewall_rule_enabled(self, uuid: str, enabled: bool) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "set_firewall_rule_enabled"):
                return self._legacy_client.set_firewall_rule_enabled(uuid, enabled)
            if self._rpc_client:
                return self._write_and_read(
                    "firewall",
                    lambda: self.rpc(
                        "devConfig.update",
                        "ip_firewall",
                        {"list": [{"uuid": uuid, "enable": "1" if enabled else "0"}]},
                    ),
                    lambda: self.get_firewall(force=True),
                )
            raise NotImplementedError("set_firewall_rule_enabled not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_firewall_rule(self, uuid: str) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "delete_firewall_rule"):
                return self._legacy_client.delete_firewall_rule(uuid)
            if self._rpc_client:
                return self._write_and_read(
                    "firewall",
                    lambda: self.rpc("devConfig.del", "ip_firewall", {"uuid": [uuid]}),
                    lambda: self.get_firewall(force=True),
                )
            raise NotImplementedError("delete_firewall_rule not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def reorder_firewall_rules(self, scope: str, uuids: List[str]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "reorder_firewall_rules"):
                return self._legacy_client.reorder_firewall_rules(scope, uuids)
            if self._rpc_client:
                return self._write_and_read(
                    "firewall",
                    lambda: self.rpc(
                        "devConfig.update",
                        "ip_firewall",
                        {"op": "reorder", "scope": scope, "uuids": uuids},
                    ),
                    lambda: self.get_firewall(force=True),
                )
            raise NotImplementedError("reorder_firewall_rules not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- DDNS ---

    def _get_raw_ddns_rows(self) -> List[Dict[str, Any]]:
        raw_res = self.rpc("devSta.get", "ddnsCfg")
        raw = self._unwrap_json(raw_res)
        rows: Any = None
        if isinstance(raw, list):
            rows = raw
        elif isinstance(raw, dict):
            rows = raw.get("list") or raw.get("services") or raw.get("records")
            if rows is None:
                nested = self._unwrap_json(raw.get("data"))
                if isinstance(nested, list):
                    rows = nested
                elif isinstance(nested, dict):
                    rows = nested.get("list") or nested.get("services") or nested.get("records")
            if rows is None and ("service" in raw or "domain" in raw or "service_name" in raw):
                rows = [raw]
        return [row for row in (rows or []) if isinstance(row, dict)]

    def get_ddns(self, force: bool = False) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "ddns"):
                return self._legacy_client.ddns(force=force)
            if self._rpc_client:
                def load() -> Dict[str, Any]:
                    rows = self._get_raw_ddns_rows()
                    clean_rows = []
                    for index, row in enumerate(rows):
                        item = dict(row)
                        domain = str(item.get("domain") or item.get("host") or "").strip()
                        raw_service = str(item.get("service") or "").strip()
                        service_name = str(
                            item.get("service_name")
                            or item.get("provider")
                            or item.get("providerName")
                            or raw_service
                            or "aliyun.com"
                        ).strip()
                        service_id = str(
                            item.get("serviceId")
                            or item.get("service_id")
                            or item.get("id")
                            or raw_service
                            or domain
                            or service_name
                            or f"ddns_{index}"
                        )
                        item["serviceId"] = service_id
                        item["service_name"] = service_name
                        item["domain"] = domain
                        item["passwordConfigured"] = bool(item.get("password") or item.get("passwordConfigured"))
                        item["password"] = ""
                        clean_rows.append(item)
                    return {
                        "list": clean_rows,
                        "services": clean_rows,
                    }
                return self._cached("ddns", 15.0, load, force)
            raise NotImplementedError("ddns not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def add_ddns(self, record: Dict[str, Any], password: str) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "add_ddns"):
                return self._legacy_client.add_ddns(record, password)
            if self._rpc_client:
                payload = {**record, "password": password}
                enabled_raw = payload.get("enable") if "enable" in payload else payload.get("enabled")
                if enabled_raw is not None:
                    payload["enabled"] = "1" if str(enabled_raw).lower() in ("1", "true", "yes") else "0"
                    payload.pop("enable", None)
                return self._write_and_read(
                    "ddns",
                    lambda: self.rpc("devSta.add", "ddnsCfg", data=payload),
                    lambda: self.get_ddns(force=True),
                )
            raise NotImplementedError("add_ddns not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def update_ddns(self, service_id: str, record: Dict[str, Any], password: Optional[str]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "update_ddns"):
                return self._legacy_client.update_ddns(service_id, record, password)
            if self._rpc_client:
                raw_rows = self._get_raw_ddns_rows()
                target_domain = str(record.get("domain") or record.get("host") or "").strip()
                
                old = {}
                if target_domain:
                    old = next((r for r in raw_rows if str(r.get("domain") or r.get("host") or "").strip() == target_domain), {})
                if not old:
                    old = next(
                        (
                            r for r in raw_rows
                            if str(r.get("service")) == service_id
                            or str(r.get("serviceId")) == service_id
                            or str(r.get("id")) == service_id
                            or str(r.get("domain")) == service_id
                            or str(r.get("service_name")) == service_id
                        ),
                        {},
                    )
                
                enable_raw = record.get("enable") if "enable" in record else record.get("enabled")
                if enable_raw is not None:
                    enable_val = "1" if str(enable_raw).lower() in ("1", "true", "yes") else "0"
                else:
                    old_enabled = old.get("enabled") if "enabled" in old else old.get("enable", "1")
                    enable_val = "1" if str(old_enabled).lower() in ("1", "true", "yes") else "0"

                service_val = str(
                    old.get("service")
                    or old.get("serviceId")
                    or old.get("id")
                    or service_id
                ).strip()
                service_name_val = str(
                    record.get("service_name")
                    or record.get("provider")
                    or old.get("service_name")
                    or old.get("provider")
                    or old.get("service")
                    or "aliyun.com"
                ).strip()
                domain_val = str(record.get("domain") or record.get("host") or old.get("domain") or old.get("host") or "").strip()
                user_val = str(record.get("username") or record.get("user") or old.get("username") or old.get("user") or "").strip()
                pass_val = password if password else old.get("password", "")
                use_ipv6_raw = record.get("use_ipv6") if "use_ipv6" in record else record.get("useIpv6", old.get("use_ipv6", "1"))
                use_ipv6_val = "1" if str(use_ipv6_raw).lower() in ("1", "true", "yes") else "0"
                iface_val = str(record.get("interface") or record.get("iface") or old.get("interface") or "wan").strip()

                merged = {
                    **old,
                    **record,
                    "service": service_val,
                    "service_name": service_name_val,
                    "domain": domain_val,
                    "username": user_val,
                    "password": pass_val,
                    "enabled": enable_val,
                    "use_ipv6": use_ipv6_val,
                    "interface": iface_val,
                }
                # BE72 ddnsCfg wire schema uses `enabled`; App's `enable` is
                # an HTTP-contract field and must not leak into the router RPC.
                merged.pop("enable", None)
                merged.pop("status", None)
                merged.pop("ip", None)
                merged.pop("passwordConfigured", None)
                merged.pop("serviceId", None)

                def do_update():
                    self.rpc("devSta.update", "ddnsCfg", {"data": [merged]})

                return self._write_and_read(
                    "ddns",
                    do_update,
                    lambda: self.get_ddns(force=True),
                )
            raise NotImplementedError("update_ddns not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def delete_ddns(self, service_id: str) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "delete_ddns"):
                return self._legacy_client.delete_ddns(service_id)
            if self._rpc_client:
                raw_rows = self._get_raw_ddns_rows()
                target = next(
                    (
                        r for r in raw_rows
                        if str(r.get("domain") or "").strip() == service_id
                        or str(r.get("service")) == service_id
                        or str(r.get("serviceId")) == service_id
                        or str(r.get("id")) == service_id
                    ),
                    {},
                )
                del_id = target.get("service") or target.get("id") or target.get("domain") or service_id

                def do_delete():
                    self.rpc("devSta.del", "ddnsCfg", {"data": [del_id]})

                return self._write_and_read(
                    "ddns",
                    do_delete,
                    lambda: self.get_ddns(force=True),
                )
            raise NotImplementedError("delete_ddns not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- IPv6 ---

    def get_ipv6_status(self) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "ipv6_status"):
                return self._legacy_client.ipv6_status()
            if self._rpc_client:
                from router.ipv6.mapper import map_status
                return map_status(self.rpc("devSta.get", "ipinfo6")).to_dict()
            raise NotImplementedError("ipv6_status not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_ipv6_config(self) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "ipv6_config"):
                return self._legacy_client.ipv6_config()
            if self._rpc_client:
                from router.ipv6.mapper import map_config
                return map_config(self.rpc("devConfig.get", "network6")).to_dict()
            raise NotImplementedError("ipv6_config not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def get_dhcpv6_clients(self) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "dhcpv6_clients"):
                return self._legacy_client.dhcpv6_clients()
            if self._rpc_client:
                from router.ipv6.mapper import map_clients
                rows = map_clients(self.rpc(
                    "devSta.get",
                    "dhcp_lease6",
                    {"index": 1, "size": 100, "macaddr": ""},
                ))
                clients = [row.to_dict() for row in rows]
                return {"clients": clients, "total": len(clients)}
            raise NotImplementedError("dhcpv6_clients not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def save_ipv6_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "save_ipv6_config"):
                return self._legacy_client.save_ipv6_config(config)
            if self._rpc_client:
                from router.ipv6.mapper import map_config, merge_config
                with self.write_lock:
                    current = self.rpc("devConfig.get", "network6")
                    payload = merge_config(current, config)
                    self.rpc("devConfig.set", "network6", payload)
                    verified = self.rpc("devConfig.get", "network6")
                return map_config(verified).to_dict()
            raise NotImplementedError("save_ipv6_config not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Diagnostic ---

    def get_diagnostic(self) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "diagnostic"):
                return self._legacy_client.diagnostic()
            if self._rpc_client:
                return self.rpc("devSta.get", "dev_diag")
            raise NotImplementedError("diagnostic not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    def start_diagnostic(self) -> Dict[str, Any]:
        try:
            if self._legacy_client and hasattr(self._legacy_client, "start_diagnostic"):
                return self._legacy_client.start_diagnostic()
            if self._rpc_client:
                self.rpc("devSta.set", "dev_diag", {"user": "eweb", "action": "start"})
                return self.rpc("devSta.get", "dev_diag")
            raise NotImplementedError("start_diagnostic not available")
        except Exception as exc:
            raise from_legacy_error(exc) from exc

    # --- Compatibility Aliases for Extension Services ---
    def dashboard(self, force: bool = False) -> Dict[str, Any]:
        return self.get_dashboard(force=force)

    def devices(self, force: bool = False) -> Dict[str, Any]:
        rows = self.get_devices(force=force)
        return {"items": rows, "total": len(rows)}

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
            with self._rpc_lock:
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
            with self._rpc_lock:
                return self._rpc_client.batch(calls)
        if self._legacy_client and hasattr(self._legacy_client, "batch"):
            return self._legacy_client.batch(calls)
        raise NotImplementedError("batch execution not available")

