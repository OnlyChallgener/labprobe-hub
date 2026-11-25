from __future__ import annotations

import re
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional

from router_core.contracts import WanInfo, WanInventory
from router_core.wan_telemetry import canonical_wan_rows


_LOGICAL_ID_RE = re.compile(r"wan(?:[0-9]+)?(?:_v6)?$", re.IGNORECASE)
_CONFIG_ID_RE = re.compile(r"wan(?:[0-9]+)?$", re.IGNORECASE)
_USERNAME_KEYS = (
    "username", "user", "account", "pppoeuser", "pppoeusername",
    "pppoe_username", "pppoeaccount", "broadbandaccount", "broadbanduser",
)
_PASSWORD_CONFIGURED_KEYS = (
    "passwordConfigured", "password_configured", "pppoePasswordConfigured",
    "credential_set", "credentialSet",
)


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _flag(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = _text(value).lower()
    if text in {"1", "true", "yes", "on", "online", "connected", "up", "ready", "success"}:
        return True
    if text in {"0", "false", "no", "off", "offline", "disconnected", "down", "disabled"}:
        return False
    return None


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _optional_integer(value: Any, *, positive: bool = False) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None
    if number < 0 or (positive and number == 0):
        return None
    return number


def _rows(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping):
        for key in ("List", "list", "entries", "records", "services", "interface_list", "interfaces", "data"):
            nested = value.get(key)
            if isinstance(nested, list):
                return [dict(item) for item in nested if isinstance(item, Mapping)]
        return []
    return []


def _logical_id(value: Any) -> str:
    text = _text(value)
    return text.lower() if _LOGICAL_ID_RE.fullmatch(text) else ""


def _config_id(row: Mapping[str, Any]) -> str:
    for key in ("wanId", "wan_id", "name", "interface", "ifname", "id"):
        text = _text(row.get(key))
        if _CONFIG_ID_RE.fullmatch(text):
            return text.lower()
    return ""


def _keyed_rows(value: Any) -> Dict[str, Dict[str, Any]]:
    """Index runtime rows only by an explicit logical WAN identity."""
    if isinstance(value, list):
        result: Dict[str, Dict[str, Any]] = {}
        for item in value:
            if not isinstance(item, Mapping):
                continue
            key = _logical_id(item.get("wanId") or item.get("wan_id") or item.get("ifname") or item.get("interface") or item.get("name") or item.get("id"))
            if key:
                result[key] = dict(item)
        return result
    if isinstance(value, Mapping):
        for container in ("List", "list", "entries", "records", "interfaces", "interface_list", "data"):
            if container in value:
                return _keyed_rows(value[container])
        result = {}
        for key, item in value.items():
            if not isinstance(item, Mapping):
                continue
            row_id = _logical_id(item.get("wanId") or item.get("wan_id") or item.get("ifname") or item.get("interface") or item.get("name") or item.get("id")) or _logical_id(key)
            if row_id:
                result[row_id] = dict(item)
        return result
    return {}


def _network_wans(raw: Any) -> Dict[str, Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return {}
    network = raw.get("network") if isinstance(raw.get("network"), Mapping) else raw

    def map_rows(value: Any) -> Dict[str, Dict[str, Any]]:
        result: Dict[str, Dict[str, Any]] = {}
        rows = value if isinstance(value, list) else [value]
        usable = [dict(row) for row in rows if isinstance(row, Mapping)]
        for index, row in enumerate(usable):
            wan_id = _config_id(row)
            # A single anonymous config is the legacy single-WAN shape. With
            # multiple configs, position is not identity and must not be guessed.
            if not wan_id and len(usable) == 1 and index == 0:
                wan_id = "wan"
            if wan_id:
                result[wan_id] = row
        return result

    value = network.get("wan") if isinstance(network, Mapping) else None
    if isinstance(value, Mapping):
        # The outer key is an explicit identity for the legacy object shape.
        result = {"wan": dict(value)}
    elif isinstance(value, list):
        result = map_rows(value)
    elif isinstance(network, list):
        result = map_rows(network)
    else:
        result = {}
    if isinstance(network, Mapping):
        for key in ("wan", "wan1"):
            item = network.get(key)
            if isinstance(item, Mapping) and key not in result:
                result[key] = dict(item)
    return result


def _port_rows(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return []
    return _rows(raw.get("List") or raw.get("list") or raw)


def _port_wan_id(row: Mapping[str, Any]) -> str:
    for key in ("wanId", "wan_id", "wan", "ifname", "interface", "name"):
        wan_id = _logical_id(row.get(key))
        if wan_id and not wan_id.endswith("_v6"):
            return wan_id.removesuffix("_v6")
    # Panel labels such as LAN2/WAN1 explicitly identify the logical WAN. Match
    # complete tokens only; substring matching would confuse WAN and WAN10.
    for key in ("panel_name", "panelName"):
        for token in re.split(r"[^a-z0-9]+", _text(row.get(key)).lower()):
            if _CONFIG_ID_RE.fullmatch(token):
                return token
    return ""


def _dns(value: Any) -> List[str]:
    if isinstance(value, list):
        candidates: Iterable[Any] = value
    else:
        candidates = str(value or "").replace(",", " ").split()
    result: List[str] = []
    for candidate in candidates:
        text = _text(candidate)
        if text and text not in result:
            result.append(text)
    return result


def _first_text(*sources: Mapping[str, Any], keys: Iterable[str]) -> str:
    wanted = tuple(keys)
    for source in sources:
        for key in wanted:
            value = _text(source.get(key))
            if value and value.lower() not in {"none", "null", "undefined", "--"}:
                return value
    return ""


def _first_optional_integer(*sources: Mapping[str, Any], keys: Iterable[str], positive: bool = False) -> Optional[int]:
    wanted = tuple(keys)
    for source in sources:
        for key in wanted:
            if key in source and source.get(key) not in (None, ""):
                value = _optional_integer(source.get(key), positive=positive)
                if value is not None:
                    return value
    return None


def _connection_state(row: Mapping[str, Any]) -> Optional[bool]:
    for key in ("connected", "online", "connect_status", "status", "state"):
        if key in row:
            parsed = _flag(row.get(key))
            if parsed is not None:
                return parsed
    return None


def _verified_operator(*sources: Mapping[str, Any]) -> str:
    for source in sources:
        operator = _first_text(source, keys=("verifiedOperator", "verified_operator", "operatorVerifiedName"))
        if operator:
            return operator
        if _flag(source.get("operatorVerified") or source.get("operator_verified")) is True:
            operator = _text(source.get("operator"))
            if operator:
                return operator
    return ""


def _rcgame_wan_credentials(value: Any) -> Dict[str, Dict[str, Any]]:
    """Find rcgame flow entries without ever crossing their exact WAN scope."""
    result: Dict[str, Dict[str, Any]] = {}
    stack: List[Tuple[Any, str]] = [(value, "")]
    while stack:
        node, inherited_id = stack.pop(0)
        if isinstance(node, list):
            stack.extend((item, inherited_id) for item in node)
            continue
        if not isinstance(node, Mapping):
            continue
        wan_id = _config_id(node) or inherited_id
        username = _first_text(node, keys=_USERNAME_KEYS)
        if wan_id and username and wan_id not in result:
            configured: Optional[bool] = None
            for key in _PASSWORD_CONFIGURED_KEYS:
                if key in node:
                    configured = _flag(node.get(key))
                    if configured is not None:
                        break
            if configured is None:
                for key in ("password", "passwd", "pwd", "pppoePassword", "pppoe_password", "pppoePasswd"):
                    if key not in node:
                        continue
                    password = _text(node.get(key))
                    if password:
                        # A masked value still proves a credential is configured;
                        # the mask itself is never copied into inventory.
                        configured = True
                    else:
                        configured = False
                    break
            result[wan_id] = {"username": username, "passwordConfigured": configured}
        for key, child in node.items():
            # Mapping keys are identities only when they are exactly wan/wan1.
            child_id = str(key).lower() if _CONFIG_ID_RE.fullmatch(str(key)) else ""
            stack.append((child, child_id or wan_id))
    return result


def _observed_at(*sources: Any) -> Optional[int]:
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        for key in ("trafficObservedAt", "observedAt", "observed_at", "timestamp", "time", "sampleEpochMs", "telemetryEpoch", "updatedAt", "lastFastAt"):
            value = source.get(key)
            if value is None or isinstance(value, bool):
                continue
            try:
                number = float(str(value).strip())
            except (TypeError, ValueError):
                continue
            if number <= 0:
                continue
            if number >= 100_000_000_000:
                number /= 1000.0
            return int(number)
    return None


def _traffic_by_wan(raw: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    candidates: List[Tuple[Any, str, Optional[int]]] = []
    flow_audit = raw.get("flowAudit") if isinstance(raw.get("flowAudit"), (Mapping, list)) else raw.get("flow_audit")
    flow_observed = _observed_at(flow_audit, raw)
    if isinstance(flow_audit, Mapping) and isinstance(flow_audit.get("wans"), (Mapping, list)):
        flow_audit = flow_audit.get("wans")
    candidates.append((flow_audit, "flowAudit", flow_observed))

    fast = raw.get("fast") if isinstance(raw.get("fast"), Mapping) else {}
    wan_stat = fast.get("wan_stat") or fast.get("wanStat") or fast.get("wanStatus")
    if not isinstance(wan_stat, Mapping):
        wan_stat = fast.get("network_connect") if isinstance(fast.get("network_connect"), Mapping) else {}
    fast_value: Any = None
    if isinstance(wan_stat, Mapping):
        if isinstance(wan_stat.get("wans"), (Mapping, list)):
            fast_value = wan_stat.get("wans")
        elif isinstance(wan_stat.get("wan"), (Mapping, list)):
            fast_value = wan_stat.get("wan")
    fast_observed = _observed_at(wan_stat, fast, raw.get("wsStatus"), raw)
    candidates.append((fast_value, "fast_wan_stat", fast_observed))

    telemetry = raw.get("telemetry") if isinstance(raw.get("telemetry"), Mapping) else {}
    telemetry_value = telemetry.get("wans")
    candidates.append((telemetry_value, "telemetry", _observed_at(telemetry, raw)))

    result: Dict[str, Dict[str, Any]] = {}
    for value, source, observed in candidates:
        for row in canonical_wan_rows(value, source=source, observed_at=observed):
            result.setdefault(str(row["wanId"]).lower(), row)
    return result


def build_wan_inventory(dashboard: Any) -> Dict[str, Any]:
    raw = dashboard if isinstance(dashboard, Mapping) else {}
    network = _network_wans(raw)
    ipinfo = _keyed_rows(raw.get("ipinfo"))
    ipinfo6 = _keyed_rows(raw.get("ipinfo6"))
    connections = _keyed_rows(raw.get("networkConnect"))
    ports = _port_rows(raw.get("portStatus") or raw.get("port_status"))
    ports_by_wan: Dict[str, Dict[str, Any]] = {}
    for port in ports:
        wan_id = _port_wan_id(port)
        if wan_id:
            ports_by_wan.setdefault(wan_id, port)
    traffic = _traffic_by_wan(raw)
    rcgame_credentials = _rcgame_wan_credentials(raw.get("rcgame"))

    supported_wan = any(
        wan_id in source
        for wan_id in ("wan", "wan_v6")
        for source in (network, ipinfo, ipinfo6, connections, ports_by_wan)
    )
    supported_wan1 = any(
        wan_id in source
        for wan_id in ("wan1", "wan1_v6")
        for source in (network, ipinfo, ipinfo6, connections, ports_by_wan, traffic)
    )
    wan_ids = (["wan"] if supported_wan or "wan" in traffic else []) + (["wan1"] if supported_wan1 else [])
    wans: List[WanInfo] = []
    default_assigned = False
    default_candidates: List[WanInfo] = []
    multi_wan_mode = _text(raw.get("multiWanMode") or raw.get("mwan3Mode"))

    for wan_id in wan_ids:
        config = network.get(wan_id, {})
        connection = connections.get(wan_id, {})
        info = ipinfo.get(wan_id, {})
        info6 = ipinfo.get(f"{wan_id}_v6") or ipinfo6.get(f"{wan_id}_v6") or ipinfo6.get(wan_id, {})
        port = ports_by_wan.get(wan_id, {})
        traffic_row = traffic.get(wan_id, {})
        credential = rcgame_credentials.get(wan_id, {})
        configured = wan_id in network
        proto = _text(config.get("proto") or connection.get("proto"))
        enabled = configured and proto.lower() not in {"none", "disabled", "off", ""}
        ipv4 = _first_text(info, connection, config, keys=("ip", "ipv4", "ipaddr"))
        ipv6 = _first_text(info6, connection, config, keys=("ip", "ipv6", "ipaddr6"))
        gateway = _first_text(info, connection, config, keys=("gateway", "gateway4"))
        gateway6 = _first_text(info6, connection, config, keys=("gateway", "gateway6"))
        dns = _dns(info.get("dnsList") or info.get("dns")) + _dns(info6.get("dnsList") or info6.get("dns6List") or info6.get("dns"))
        dns = list(dict.fromkeys(address for address in dns if address))
        state = _connection_state(connection)
        online = state if state is not None else bool(ipv4 or ipv6)
        default_egress = _flag(connection.get("defaultEgress") or connection.get("default"))
        mode = _text(connection.get("mode") or port.get("mode"))
        if mode and not multi_wan_mode:
            multi_wan_mode = mode
        families = []
        if configured and (ipv4 or proto.lower() in {"pppoe", "dhcp", "static", "none", ""}):
            families.append("ipv4")
        if ipv6 or _text(config.get("ipv6")).lower() in {"1", "true", "on"} or f"{wan_id}_v6" in ipinfo or f"{wan_id}_v6" in ipinfo6:
            families.append("ipv6")
        supported = wan_id == "wan" or supported_wan1
        wan = WanInfo(
            wanId=wan_id,
            logicalInterface=wan_id,
            displayName=_text(port.get("panel_name")) or wan_id.upper(),
            physicalPortId=_integer(port.get("portId")),
            physicalPortName=_text(port.get("panel_name") or port.get("name")),
            role=_text(connection.get("role") or port.get("role")) or ("balance" if mode else ""),
            supported=supported,
            configured=configured,
            enabled=enabled,
            online=bool(online and configured),
            defaultEgress=bool(default_egress),
            families=families,
            proto=proto,
            ipv4=ipv4,
            ipv6=ipv6,
            gateway=gateway,
            gateway6=gateway6,
            dns=dns,
            uptimeSeconds=max(0, _integer(connection.get("uptime") or connection.get("uptimeSeconds"))),
            linkSpeedMbps=max(0, _integer(port.get("speed"))),
            capabilities={
                "portMapping": supported,
                "nativeDdns": configured,
                "upnp": configured,
                "speedtest": configured,
                "natDiagnostic": configured,
            },
            source="firmware",
            ifname=_first_text(config, keys=("ifname", "interface")),
            netmask=_first_text(info, connection, config, keys=("netmask", "mask")),
            mtu=_first_optional_integer(info, connection, config, keys=("mtu",), positive=True),
            vlanId=_first_optional_integer(config, keys=("vlanid", "vlanId", "vid"), positive=True),
            mac=_first_text(config, keys=("mac", "macaddr", "macAddress")),
            remark=_first_text(config, keys=("service", "serviceName")),
            operator=_verified_operator(connection, info, config),
            pppoeUsername=_text(credential.get("username")),
            pppoePasswordConfigured=credential.get("passwordConfigured"),
            dhcpLease=_first_text(info, connection, config, keys=("leasetime", "leaseTime", "dhcpLease")) or None,
            uploadBps=traffic_row.get("uploadBps"),
            downloadBps=traffic_row.get("downloadBps"),
            totalUploadBytes=traffic_row.get("totalUploadBytes"),
            totalDownloadBytes=traffic_row.get("totalDownloadBytes"),
            dailyUploadBytes=traffic_row.get("dailyUploadBytes"),
            dailyDownloadBytes=traffic_row.get("dailyDownloadBytes"),
            trafficSource=_text(traffic_row.get("trafficSource")),
            trafficObservedAt=traffic_row.get("trafficObservedAt"),
            trafficComplete=traffic_row.get("trafficComplete"),
        )
        wans.append(wan)
        if default_egress:
            default_assigned = True
        elif wan.online and wan.configured:
            default_candidates.append(wan)

    # Retain the legacy single-WAN inference, but never choose the first of
    # several anonymous/default candidates by position.
    if not default_assigned and len(default_candidates) == 1:
        default_candidates[0].defaultEgress = True

    return WanInventory(
        wans=wans,
        supported=bool(wans),
        configuredCount=sum(1 for wan in wans if wan.configured),
        onlineCount=sum(1 for wan in wans if wan.online),
        multiWanMode=multi_wan_mode,
        updatedAt=_integer(raw.get("updatedAt")) or int(time.time()),
    ).to_dict()
