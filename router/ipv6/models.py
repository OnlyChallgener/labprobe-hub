"""Product-facing IPv6 models.

Router RPC response shapes are intentionally kept out of the Flask controller
and the Android application.  Only these normalized values cross the Hub API.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


class Ipv6ValidationError(ValueError):
    """The requested IPv6 configuration cannot be safely sent to the router."""


@dataclass(frozen=True)
class Ipv6Status:
    connected: bool = False
    proto: str = ""
    address: str = ""
    prefix: str = ""
    gateway: str = ""
    dns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "connected": self.connected,
            "proto": self.proto,
            "address": self.address,
            "prefix": self.prefix,
            "gateway": self.gateway,
            "dns": list(self.dns),
        }


@dataclass(frozen=True)
class WanIpv6Config:
    proto: str = "dhcpv6"
    ifname: str = "@wan"
    dns: List[str] = field(default_factory=list)
    dns_type: str = "auto"
    relay: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proto": self.proto,
            "ifname": self.ifname,
            "dns": list(self.dns),
            "dnsType": self.dns_type,
            "relay": self.relay,
        }


@dataclass(frozen=True)
class LanIpv6Config:
    prefix_length: int = 64
    dhcpv6_server: bool = True
    slaac: bool = True
    dhcpv6_type: str = "DHCPv6+SLAAC"
    ra: bool = True
    ra_management: str = "1"
    lease_minutes: int = 120
    relay: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip6assign": self.prefix_length,
            "dhcpv6Server": self.dhcpv6_server,
            "slaac": self.slaac,
            "dhcpv6Type": self.dhcpv6_type,
            "ra": self.ra,
            "ra_management": self.ra_management,
            "leasetime6": self.lease_minutes,
            "relay": self.relay,
        }


@dataclass(frozen=True)
class Ipv6Config:
    wan: WanIpv6Config = field(default_factory=WanIpv6Config)
    lan: LanIpv6Config = field(default_factory=LanIpv6Config)

    def to_dict(self) -> Dict[str, Any]:
        return {"wan": self.wan.to_dict(), "lan": self.lan.to_dict()}


@dataclass(frozen=True)
class Dhcpv6Client:
    hostname: str = ""
    ipv6: str = ""
    lease_minutes: int = 0
    duid: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "ipv6": self.ipv6,
            "leasetime": self.lease_minutes,
            "duid": self.duid,
        }
