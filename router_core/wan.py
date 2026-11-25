from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Mapping, Optional

from router_core.contracts import WanInfo, WanInventory


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


def _keyed_rows(value: Any) -> Dict[str, Dict[str, Any]]:
    if isinstance(value, list):
        result: Dict[str, Dict[str, Any]] = {}
        for item in value:
            if not isinstance(item, Mapping):
                continue
            key = _text(item.get("ifname") or item.get("interface") or item.get("name") or item.get("id"))
            if key:
                result[key.lower()] = dict(item)
        return result
    if isinstance(value, Mapping):
        for container in ("List", "list", "entries", "records", "interfaces", "interface_list", "data"):
            if container in value:
                return _keyed_rows(value[container])
        result = {}
        for key, item in value.items():
            if isinstance(item, Mapping):
                result[str(key).lower()] = dict(item)
        return result
    return {}


def _network_wans(raw: Any) -> Dict[str, Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return {}
    network = raw.get("network") if isinstance(raw.get("network"), Mapping) else raw
    value = network.get("wan") if isinstance(network, Mapping) else None
    if isinstance(value, list):
        result = {}
        for index, item in enumerate(value):
            if not isinstance(item, Mapping):
                continue
            row = dict(item)
            name = _text(row.get("name") or row.get("interface") or row.get("ifname"))
            wan_id = name if name in {"wan", "wan1"} else ("wan" if index == 0 else f"wan{index}")
            result[wan_id] = row
        return result
    if isinstance(value, Mapping):
        result = {}
        if any(key in value for key in ("proto", "ifname", "type", "ipv6")):
            result["wan"] = dict(value)
        for key, item in value.items():
            if isinstance(item, Mapping) and str(key).lower() in {"wan", "wan1"}:
                result[str(key).lower()] = dict(item)
        return result
    result = {}
    for key in ("wan", "wan1"):
        item = network.get(key)
        if isinstance(item, Mapping):
            result[key] = dict(item)
    return result


def _port_rows(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return []
    return _rows(raw.get("List") or raw.get("list") or raw)


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


def _connection_state(row: Mapping[str, Any]) -> Optional[bool]:
    for key in ("connected", "online", "connect_status", "status", "state"):
        if key in row:
            parsed = _flag(row.get(key))
            if parsed is not None:
                return parsed
    return None


def build_wan_inventory(dashboard: Any) -> Dict[str, Any]:
    raw = dashboard if isinstance(dashboard, Mapping) else {}
    network = _network_wans(raw)
    ipinfo = _keyed_rows(raw.get("ipinfo"))
    ipinfo6 = _keyed_rows(raw.get("ipinfo6"))
    connections = _keyed_rows(raw.get("networkConnect"))
    ports = _port_rows(raw.get("portStatus") or raw.get("port_status"))

    supported_wan = (
        "wan" in network
        or "wan" in ipinfo
        or "wan" in connections
        or any(_text(port.get("name")).upper() == "WAN" for port in ports)
    )
    supported_wan1 = "wan1" in network or "wan1" in ipinfo or "wan1" in connections or any(
        "WAN1" in (_text(port.get("panel_name")) + " " + _text(port.get("name"))).upper()
        for port in ports
    )
    wan_ids = (["wan"] if supported_wan else []) + (["wan1"] if supported_wan1 else [])
    wans: List[WanInfo] = []
    default_assigned = False
    multi_wan_mode = _text(raw.get("multiWanMode") or raw.get("mwan3Mode"))

    for wan_id in wan_ids:
        config = network.get(wan_id, {})
        connection = connections.get(wan_id, {})
        info = ipinfo.get(wan_id, {})
        info6 = ipinfo.get(f"{wan_id}_v6") or ipinfo6.get(f"{wan_id}_v6", {})
        port = next(
            (
                item for item in ports
                if _text(item.get("name")).lower() == wan_id
                or wan_id.upper() in _text(item.get("panel_name")).upper()
            ),
            {},
        )
        configured = wan_id in network
        proto = _text(config.get("proto") or connection.get("proto"))
        enabled = configured and proto.lower() not in {"none", "disabled", "off", ""}
        ipv4 = _text(info.get("ip") or info.get("ipv4") or connection.get("ipv4") or port.get("ipaddr"))
        ipv6 = _text(info6.get("ip") or info6.get("ipv6") or connection.get("ipv6"))
        gateway = _text(info.get("gateway") or info.get("gateway4") or connection.get("gateway"))
        gateway6 = _text(info6.get("gateway") or info6.get("gateway6") or connection.get("gateway6"))
        dns = _dns(info.get("dnsList") or info.get("dns")) + _dns(info6.get("dnsList") or info6.get("dns6List") or info6.get("dns"))
        dns = list(dict.fromkeys(address for address in dns if address))
        state = _connection_state(connection)
        online = state if state is not None else bool(ipv4 or ipv6)
        default_egress = _flag(connection.get("defaultEgress") or connection.get("default"))
        if default_egress is None:
            default_egress = bool(online and configured and not default_assigned)
        if default_egress:
            default_assigned = True
        mode = _text(connection.get("mode") or port.get("mode"))
        if mode and not multi_wan_mode:
            multi_wan_mode = mode
        families = []
        if configured and (ipv4 or proto.lower() in {"pppoe", "dhcp", "static", "none", ""}):
            families.append("ipv4")
        if ipv6 or _text(config.get("ipv6")).lower() in {"1", "true", "on"} or f"{wan_id}_v6" in ipinfo or f"{wan_id}_v6" in ipinfo6:
            families.append("ipv6")
        supported = wan_id == "wan" or supported_wan1
        wans.append(
            WanInfo(
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
            )
        )

    return WanInventory(
        wans=wans,
        supported=bool(wans),
        configuredCount=sum(1 for wan in wans if wan.configured),
        onlineCount=sum(1 for wan in wans if wan.online),
        multiWanMode=multi_wan_mode,
        updatedAt=_integer(raw.get("updatedAt")) or int(time.time()),
    ).to_dict()
