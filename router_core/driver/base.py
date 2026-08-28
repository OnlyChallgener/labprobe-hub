"""Abstract Router Driver Interface.

Defines the formal contract that all router hardware/vendor drivers must satisfy.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class RouterDriver(ABC):
    """Abstract Base Class for Router Native Drivers."""

    @abstractmethod
    def get_capabilities(self) -> Dict[str, Any]:
        """Returns router feature capabilities."""
        ...

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Returns router connection and health status."""
        ...

    @abstractmethod
    def get_dashboard(self, force: bool = False) -> Dict[str, Any]:
        """Returns full dashboard telemetry (hardware, traffic, network, ports)."""
        ...

    @abstractmethod
    def get_devices(self, force: bool = False) -> List[Dict[str, Any]]:
        """Returns list of connected terminal devices."""
        ...

    @abstractmethod
    def get_port_mappings(self, force: bool = False) -> Dict[str, Any]:
        """Returns native port mapping rules."""
        ...

    @abstractmethod
    def add_port_mapping(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Adds a native port mapping rule."""
        ...

    @abstractmethod
    def update_port_mapping(self, old_name: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Updates an existing native port mapping rule."""
        ...

    @abstractmethod
    def delete_port_mapping(self, rule_name: str) -> Dict[str, Any]:
        """Deletes a native port mapping rule."""
        ...

    @abstractmethod
    def get_upnp(self, force: bool = False) -> Dict[str, Any]:
        """Returns UPnP status and active mappings."""
        ...

    @abstractmethod
    def set_upnp(self, enabled: bool, wan: str) -> Dict[str, Any]:
        """Enables or disables UPnP."""
        ...

    @abstractmethod
    def get_firewall(self, force: bool = False) -> Dict[str, Any]:
        """Returns firewall settings and rules."""
        ...

    @abstractmethod
    def add_firewall_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Adds a firewall rule."""
        ...

    @abstractmethod
    def update_firewall_rule(self, uuid: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Updates a firewall rule."""
        ...

    @abstractmethod
    def set_firewall_rule_enabled(self, uuid: str, enabled: bool) -> Dict[str, Any]:
        """Enables or disables a firewall rule."""
        ...

    @abstractmethod
    def delete_firewall_rule(self, uuid: str) -> Dict[str, Any]:
        """Deletes a firewall rule."""
        ...

    @abstractmethod
    def reorder_firewall_rules(self, scope: str, uuids: List[str]) -> Dict[str, Any]:
        """Reorders firewall rules by UUID."""
        ...

    @abstractmethod
    def get_ddns(self, force: bool = False) -> Dict[str, Any]:
        """Returns router native DDNS configuration."""
        ...

    @abstractmethod
    def add_ddns(self, record: Dict[str, Any], password: str) -> Dict[str, Any]:
        """Adds a router native DDNS record."""
        ...

    @abstractmethod
    def update_ddns(self, service_id: str, record: Dict[str, Any], password: Optional[str]) -> Dict[str, Any]:
        """Updates a router native DDNS record."""
        ...

    @abstractmethod
    def delete_ddns(self, service_id: str) -> Dict[str, Any]:
        """Deletes a router native DDNS record."""
        ...

    @abstractmethod
    def get_ipv6_status(self) -> Dict[str, Any]:
        """Returns IPv6 WAN/LAN address and prefix status."""
        ...

    @abstractmethod
    def get_ipv6_config(self) -> Dict[str, Any]:
        """Returns IPv6 configuration."""
        ...

    @abstractmethod
    def get_dhcpv6_clients(self) -> Dict[str, Any]:
        """Returns DHCPv6 client leases."""
        ...

    @abstractmethod
    def save_ipv6_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Saves IPv6 configuration."""
        ...

    @abstractmethod
    def get_diagnostic(self) -> Dict[str, Any]:
        """Reads network diagnostic results and progress."""
        ...

    @abstractmethod
    def start_diagnostic(self) -> Dict[str, Any]:
        """Triggers a new asynchronous network diagnostic run."""
        ...
