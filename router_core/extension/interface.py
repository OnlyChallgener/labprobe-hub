"""LabRelay Extension Interface.

Formal boundary for LabProbe-owned router extension capabilities (KEEP):
- LabProbe DDNS
- 6to4 and 6to6 Port Mapping
- STUN NAT Keepalive and Public Endpoint
- WireGuard VPN Server and Endpoint Profiles
- Extension Presence, Update, and Cleanup
"""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


@runtime_checkable
class LabRelayExtensionProtocol(Protocol):
    """Protocol defining the formal boundary of the LabRelay Extension."""

    def get_agent_presence(self) -> Dict[str, Any]:
        """Returns the presence and status of the Router Agent."""
        ...

    def get_port_mappings(self) -> Dict[str, Any]:
        """Returns 6to4 and 6to6 mapping rules and runtime states."""
        ...

    def get_stun_snapshot(self) -> Dict[str, Any]:
        """Returns STUN penetration rules and public endpoints."""
        ...

    def get_wireguard_config(self) -> Dict[str, Any]:
        """Returns WireGuard server config and peer status."""
        ...

    def get_ddns_snapshot(self) -> Dict[str, Any]:
        """Returns LabProbe DDNS records and WAN address status."""
        ...
