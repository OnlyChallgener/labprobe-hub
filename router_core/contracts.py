from __future__ import annotations
"""Router Core Data Contracts and Models.

Defines the exact typed structures consumed and produced by Router Core.
Maintains 100% fidelity with docs/contracts/app-hub-contract-v1.json.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RouterCapabilities:
    configured: bool = False
    dashboard: bool = False
    devices: bool = False
    firewall: bool = False
    nativePortMapping: bool = False
    upnp: bool = False
    ddns: bool = False
    diagnostic: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "configured": self.configured,
            "features": {
                "dashboard": self.dashboard,
                "devices": self.devices,
                "firewall": self.firewall,
                "nativePortMapping": self.nativePortMapping,
                "upnp": self.upnp,
                "ddns": self.ddns,
                "diagnostic": self.diagnostic,
            },
        }


@dataclass
class RouterStatus:
    state: str = "checking"
    connected: bool = False
    sessionConnected: bool = False
    dataAvailable: bool = False
    message: str = "正在准备路由控制数据"
    errorCode: str = ""
    lastSuccessAt: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "connected": self.connected,
            "sessionConnected": self.sessionConnected,
            "dataAvailable": self.dataAvailable,
            "message": self.message,
            "errorCode": self.errorCode,
            "lastSuccessAt": self.lastSuccessAt,
        }


@dataclass
class NativePortMapRule:
    name: str = ""
    interface: str = "WAN"
    proto: str = "tcp"
    extPort: int = 0
    intIp: str = ""
    intPort: int = 0
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "interface": self.interface,
            "proto": self.proto,
            "extPort": self.extPort,
            "intIp": self.intIp,
            "intPort": self.intPort,
            "enabled": self.enabled,
        }


@dataclass
class UpnpRule:
    name: str = ""
    extPort: int = 0
    proto: str = ""
    intIp: str = ""
    intPort: int = 0
    remoteHost: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "extPort": self.extPort,
            "proto": self.proto,
            "intIp": self.intIp,
            "intPort": self.intPort,
            "remoteHost": self.remoteHost,
        }


@dataclass
class UpnpState:
    enabled: bool = False
    wan: str = ""
    rules: List[UpnpRule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "wan": self.wan,
            "rules": [r.to_dict() for r in self.rules],
        }


@dataclass
class FirewallRule:
    uuid: str = ""
    scope: str = "wan"
    name: str = ""
    enabled: bool = True
    action: str = "drop"
    proto: str = "all"
    srcIp: str = ""
    srcPort: str = ""
    destIp: str = ""
    destPort: str = ""
    direction: str = "in"
    time: str = ""
    editable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "uuid": self.uuid,
            "scope": self.scope,
            "name": self.name,
            "enabled": self.enabled,
            "action": self.action,
            "proto": self.proto,
            "srcIp": self.srcIp,
            "srcPort": self.srcPort,
            "destIp": self.destIp,
            "destPort": self.destPort,
            "direction": self.direction,
            "time": self.time,
            "editable": self.editable,
        }


@dataclass
class FirewallState:
    wanInboundAllow: bool = False
    rules: List[FirewallRule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "wanInboundAllow": self.wanInboundAllow,
            "rules": [r.to_dict() for r in self.rules],
        }


@dataclass
class DdnsRecord:
    serviceId: str = ""
    provider: str = ""
    domain: str = ""
    username: str = ""
    enabled: bool = True
    status: str = ""
    lastUpdate: str = ""
    ip: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "serviceId": self.serviceId,
            "provider": self.provider,
            "domain": self.domain,
            "username": self.username,
            "enabled": self.enabled,
            "status": self.status,
            "lastUpdate": self.lastUpdate,
            "ip": self.ip,
        }


@dataclass
class DdnsState:
    services: List[DdnsRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "services": [s.to_dict() for s in self.services],
        }


@dataclass
class Ipv6WanConfig:
    proto: str = "dhcpv6"
    dhcpv6: bool = True
    autoDns: bool = True
    dns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proto": self.proto,
            "dhcpv6": self.dhcpv6,
            "autoDns": self.autoDns,
            "dns": list(self.dns),
        }


@dataclass
class Ipv6LanConfig:
    proto: str = "slaac"
    ip6assign: str = "64"
    dhcpv6: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proto": self.proto,
            "ip6assign": self.ip6assign,
            "dhcpv6": self.dhcpv6,
        }


@dataclass
class Ipv6Config:
    wan: Ipv6WanConfig = field(default_factory=Ipv6WanConfig)
    lan: Ipv6LanConfig = field(default_factory=Ipv6LanConfig)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "wan": self.wan.to_dict(),
            "lan": self.lan.to_dict(),
        }


@dataclass
class Ipv6Status:
    enabled: bool = False
    wanAddress: str = ""
    wanPrefix: str = ""
    lanPrefix: str = ""
    gateway: str = ""
    primaryDns: str = ""
    secondaryDns: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "wanAddress": self.wanAddress,
            "wanPrefix": self.wanPrefix,
            "lanPrefix": self.lanPrefix,
            "gateway": self.gateway,
            "primaryDns": self.primaryDns,
            "secondaryDns": self.secondaryDns,
        }


@dataclass
class Dhcpv6Client:
    hostname: str = ""
    mac: str = ""
    duid: str = ""
    ipv6: str = ""
    iaid: str = ""
    leaseTime: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "mac": self.mac,
            "duid": self.duid,
            "ipv6": self.ipv6,
            "iaid": self.iaid,
            "leaseTime": self.leaseTime,
        }


@dataclass
class RouterDiagnosticItem:
    type: str = ""
    title: str = ""
    status: str = ""
    result: str = ""
    tips: str = ""
    advise: str = ""
    children: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "title": self.title,
            "status": self.status,
            "result": self.result,
            "tips": self.tips,
            "advise": self.advise,
            "children": self.children,
        }


@dataclass
class RouterDiagnostic:
    process: str = "0%"
    error_count: Any = 0
    List: list[RouterDiagnosticItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "process": self.process,
            "error_count": str(self.error_count),
            "List": [item.to_dict() for item in self.List],
        }
