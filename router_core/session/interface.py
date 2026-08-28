"""Router Session Interface.

Defines the formal session boundary for future SessionManager implementations.
In Phase 1, this interface is a pure specification; existing session patches remain active.
"""

from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class RouterSessionProtocol(Protocol):
    """Protocol for Router Session Managers."""

    def get_session(self, force: bool = False) -> Any:
        """Returns the active authenticated session or acquires a new one."""
        ...

    def invalidate_session(self) -> None:
        """Explicitly marks the current session as invalid."""
        ...

    def is_valid(self) -> bool:
        """Checks whether the cached session is locally valid without making network calls."""
        ...
