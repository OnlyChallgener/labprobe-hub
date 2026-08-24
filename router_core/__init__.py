"""Router Core v1 Package.

Formal architectural boundary for Router management in LabProbe Hub.
"""

from .service import RouterService
from .contracts import (
    RouterCapabilities,
    RouterStatus,
    NativePortMapRule,
    UpnpRule,
    UpnpState,
    FirewallRule,
    FirewallState,
    DdnsRecord,
    DdnsState,
    Ipv6WanConfig,
    Ipv6LanConfig,
    Ipv6Config,
    Ipv6Status,
    Dhcpv6Client,
    RouterDiagnosticItem,
    RouterDiagnostic,
)
from .errors import (
    RouterCoreError,
    RouterNotConfiguredError,
    RouterUnreachableError,
    RouterAuthError,
    RouterAuthExpiredError,
    RouterFeatureDisabledError,
    RouterRpcExecutionError,
    RouterValidationError,
)

__all__ = [
    "RouterService",
    "RouterCapabilities",
    "RouterStatus",
    "NativePortMapRule",
    "UpnpRule",
    "UpnpState",
    "FirewallRule",
    "FirewallState",
    "DdnsRecord",
    "DdnsState",
    "Ipv6WanConfig",
    "Ipv6LanConfig",
    "Ipv6Config",
    "Ipv6Status",
    "Dhcpv6Client",
    "RouterDiagnosticItem",
    "RouterDiagnostic",
    "RouterCoreError",
    "RouterNotConfiguredError",
    "RouterUnreachableError",
    "RouterAuthError",
    "RouterAuthExpiredError",
    "RouterFeatureDisabledError",
    "RouterRpcExecutionError",
    "RouterValidationError",
]
