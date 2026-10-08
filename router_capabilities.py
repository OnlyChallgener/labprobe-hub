"""Capabilities of the Hub's implemented router API for each firmware family."""

from __future__ import annotations

import os
from typing import Any, Dict


def is_be50_firmware(name: str = "") -> bool:
    identity = " ".join((
        os.environ.get("ROUTER_FIRMWARE_FAMILY", ""),
        os.environ.get("PRIMARY_ROUTER_NAME", ""),
        name or "",
    )).lower()
    return "be50" in identity or "be5100" in identity


def firmware_features(name: str, configured: bool) -> Dict[str, Any]:
    be50 = is_be50_firmware(name)
    return {
        "dashboard": configured,
        "devices": configured,
        # BE50 has a distinct firewall_wan switch, while this API implements
        # BE72 ip_firewall rules. The BE50 endpoint rejects ip_firewall.
        "firewall": configured and not be50,
        "nativePortMapping": configured,
        "upnp": configured,
        # BE50 eWeb exposes phddns/phtunnel; the BE72 ddnsCfg list/edit model
        # cannot be reused until the BE50 API and App page are implemented.
        "ddns": configured and not be50,
        "diagnostic": configured,
        "wireguard": configured and not be50,
        "ipv6Bridge": configured and not be50,
        "nativeNatDiagnostic": configured and not be50,
        "nativeSpeedTest": configured and not be50,
        "nativeFirmwareUpgrade": configured and not be50,
        "ipv6ConnectionCount": configured and not be50,
        "routerEwebWss": configured and not be50,
    }
