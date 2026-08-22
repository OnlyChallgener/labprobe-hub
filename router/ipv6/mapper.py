"""Translate between BE72 ``network6`` records and product-facing models."""
from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Mapping

from .models import (
    Dhcpv6Client,
    Ipv6Config,
    Ipv6Status,
    Ipv6ValidationError,
    LanIpv6Config,
    WanIpv6Config,
)

_RUNTIME_FIELDS = {"configId", "configTime", "currentTime"}
_TRUE_VALUES = {"1", "true", "on", "yes", "enabled", "server", "relay"}
_FALSE_VALUES = {"0", "false", "off", "no", "disabled", "none", ""}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _integer(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _flag(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = _text(value).lower()
    if text in _TRUE_VALUES:
        return True
    if text in _FALSE_VALUES:
        return False
    return default


def _first_mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                return dict(item)
    return {}


def split_dns(value: Any) -> List[str]:
    if isinstance(value, list):
        candidates: Iterable[Any] = value
    else:
        candidates = re.split(r"[,;\s]+", _text(value))
    result: List[str] = []
    for candidate in candidates:
        address = _text(candidate)
        if address and address not in result:
            result.append(address)
    return result


def map_status(raw: Any) -> Ipv6Status:
    root = dict(raw) if isinstance(raw, Mapping) else {}
    wan = _first_mapping(root.get("wan_v6") or root.get("wan6") or root)
    proto = _text(wan.get("proto"))
    address = _text(wan.get("ip6"))
    return Ipv6Status(
        connected=bool(address and proto.lower() not in {"none", "disabled", "off"}),
        proto=proto,
        address=address,
        prefix=_text(wan.get("prefix")),
        gateway=_text(wan.get("gateway6")),
        dns=split_dns(wan.get("dns6List")),
    )


def map_config(raw: Any) -> Ipv6Config:
    root = dict(raw) if isinstance(raw, Mapping) else {}
    wan = _first_mapping(root.get("wan6"))
    lan = _first_mapping(root.get("lan"))
    dhcpv6_type = _text(lan.get("dhcpv6Type"))
    dns_type_raw = _text(wan.get("dnsType")).lower()
    return Ipv6Config(
        wan=WanIpv6Config(
            proto=_text(wan.get("proto")) or "dhcpv6",
            ifname=_text(wan.get("ifname")) or "@wan",
            dns=split_dns(wan.get("dns")),
            dns_type="manual" if dns_type_raw in {"admin", "manual", "static"} else "auto",
            relay=_flag(wan.get("relay")),
        ),
        lan=LanIpv6Config(
            prefix_length=_integer(lan.get("ip6assign"), 64),
            dhcpv6_server=_text(lan.get("dhcpv6")).lower() == "server" or _flag(lan.get("dhcpv6")),
            slaac="slaac" in dhcpv6_type.lower(),
            dhcpv6_type=dhcpv6_type or "DHCPv6+SLAAC",
            ra=_text(lan.get("ra")).lower() == "server" or _flag(lan.get("ra")),
            ra_management=_text(lan.get("ra_management")) or "0",
            lease_minutes=_integer(lan.get("leasetime6"), 120),
            relay=_flag(lan.get("relay")),
        ),
    )


def map_clients(raw: Any) -> List[Dhcpv6Client]:
    root = dict(raw) if isinstance(raw, Mapping) else {}
    rows = root.get("List") or root.get("list") or root.get("data") or []
    if not isinstance(rows, list):
        return []
    result: List[Dhcpv6Client] = []
    for item in rows:
        if not isinstance(item, Mapping):
            continue
        result.append(
            Dhcpv6Client(
                hostname=_text(item.get("hostname")),
                ipv6=_text(item.get("ipv6")),
                lease_minutes=max(0, _integer(item.get("leasetime"), 0)),
                duid=_text(item.get("duid")),
            )
        )
    return result


def _require_mapping(root: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = root.get(key)
    if not isinstance(value, Mapping):
        raise Ipv6ValidationError(f"缺少 {key} IPv6 配置")
    return value


def _validate_dns(value: Any, manual: bool) -> List[str]:
    addresses = split_dns(value)
    if manual and not addresses:
        raise Ipv6ValidationError("手动 DNS 至少需要填写一个 IPv6 地址")
    if len(addresses) > 4:
        raise Ipv6ValidationError("IPv6 DNS 最多填写 4 个地址")
    for address in addresses:
        try:
            ipaddress.IPv6Address(address)
        except ValueError as exc:
            raise Ipv6ValidationError(f"IPv6 DNS 地址无效：{address}") from exc
    return addresses


def _dhcpv6_type(server: bool, slaac: bool) -> str:
    if server and slaac:
        return "DHCPv6+SLAAC"
    if server:
        return "DHCPv6"
    if slaac:
        return "SLAAC"
    return "disabled"


def merge_config(current: Any, requested: Any) -> Dict[str, Any]:
    if not isinstance(current, Mapping):
        raise Ipv6ValidationError("路由器未返回完整 network6 配置")
    if not isinstance(requested, Mapping):
        raise Ipv6ValidationError("IPv6 配置请求格式无效")

    wan_request = _require_mapping(requested, "wan")
    lan_request = _require_mapping(requested, "lan")
    merged = copy.deepcopy(dict(current))
    wan_current = _first_mapping(merged.get("wan6"))
    lan_current = _first_mapping(merged.get("lan"))
    if not wan_current or not lan_current:
        raise Ipv6ValidationError("路由器 network6 缺少 WAN 或 LAN 配置")

    proto = _text(wan_request.get("proto") or wan_current.get("proto")).lower()
    if proto not in {"dhcpv6", "relay"}:
        raise Ipv6ValidationError("WAN IPv6 模式仅支持 DHCPv6 或 IPv6 中继")
    dns_type = _text(wan_request.get("dnsType") or wan_current.get("dnsType")).lower()
    manual_dns = dns_type in {"manual", "admin", "static"}
    if dns_type not in {"auto", "manual", "admin", "static"}:
        raise Ipv6ValidationError("IPv6 DNS 模式无效")
    dns = _validate_dns(wan_request.get("dns", wan_current.get("dns")), manual_dns)
    relay = proto == "relay" or _flag(wan_request.get("relay"), False)

    wan_current["proto"] = proto
    wan_current["dnsType"] = "admin" if manual_dns else "auto"
    wan_current["dns"] = ",".join(dns) if manual_dns else ""
    wan_current["relay"] = "1" if relay else "0"

    prefix_length = _integer(lan_request.get("ip6assign"), _integer(lan_current.get("ip6assign"), 64))
    if prefix_length < 1 or prefix_length > 128:
        raise Ipv6ValidationError("IPv6 Prefix 长度必须在 1 到 128 之间")
    lease_minutes = _integer(lan_request.get("leasetime6"), _integer(lan_current.get("leasetime6"), 120))
    if lease_minutes < 1 or lease_minutes > 10080:
        raise Ipv6ValidationError("DHCPv6 租期必须在 1 到 10080 分钟之间")
    server = _flag(lan_request.get("dhcpv6Server", lan_request.get("dhcpv6")), _flag(lan_current.get("dhcpv6")))
    slaac = _flag(lan_request.get("slaac"), "slaac" in _text(lan_current.get("dhcpv6Type")).lower())
    ra = _flag(lan_request.get("ra"), _flag(lan_current.get("ra")))

    lan_current["ip6assign"] = str(prefix_length)
    lan_current["dhcpv6"] = "server" if server else "disabled"
    lan_current["dhcpv6Type"] = _dhcpv6_type(server, slaac)
    lan_current["ra"] = "server" if ra else "disabled"
    lan_current["ra_management"] = _text(lan_request.get("ra_management")) or ("1" if server else "0")
    lan_current["leasetime6"] = str(lease_minutes)

    if isinstance(merged.get("wan6"), list):
        merged["wan6"][0] = wan_current
    else:
        merged["wan6"] = [wan_current]
    if isinstance(merged.get("lan"), list):
        merged["lan"][0] = lan_current
    else:
        merged["lan"] = [lan_current]
    return strip_runtime_fields(merged)


def strip_runtime_fields(value: Any) -> Any:
    if isinstance(value, list):
        return [strip_runtime_fields(item) for item in value]
    if isinstance(value, Mapping):
        return {
            key: strip_runtime_fields(item)
            for key, item in value.items()
            if key not in _RUNTIME_FIELDS
        }
    return value
