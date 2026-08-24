"""Router Core Unified Error Taxonomy.

Maps 1:1 with existing legacy error codes and HTTP responses without drift.
"""

from typing import Any, Dict, Optional, Tuple


class RouterCoreError(Exception):
    """Base exception for all Router Core operations."""

    def __init__(self, message: str, code: str = "ROUTER_ERROR", status_code: int = 500, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}

    def to_response_dict(self) -> Dict[str, Any]:
        resp: Dict[str, Any] = {
            "ok": False,
            "error": self.message,
            "code": self.code,
            "status": "error",
        }
        if self.details:
            resp["details"] = self.details
        return resp


class RouterNotConfiguredError(RouterCoreError):
    """Raised when router is not configured in Hub settings."""

    def __init__(self, message: str = "Router credentials or address not configured"):
        super().__init__(message, code="ROUTER_NOT_CONFIGURED", status_code=502)


class RouterUnreachableError(RouterCoreError):
    """Raised when router host/port is unreachable over HTTP/HTTPS."""

    def __init__(self, message: str = "Unable to connect to router"):
        super().__init__(message, code="ROUTER_UNREACHABLE", status_code=502)


class RouterAuthError(RouterCoreError):
    """Raised when authentication fails against router."""

    def __init__(self, message: str = "Router authentication failed"):
        super().__init__(message, code="LOGIN_FAILED", status_code=401)


class RouterAuthExpiredError(RouterAuthError):
    """Raised when session is expired and retry limit is exceeded."""

    def __init__(self, message: str = "Router session expired"):
        super().__init__(message)
        self.code = "SESSION_EXPIRED"
        self.status_code = 401


class RouterFeatureDisabledError(RouterCoreError):
    """Raised when the requested feature is disabled on this router."""

    def __init__(self, message: str = "Feature is not supported or disabled"):
        super().__init__(message, code="FEATURE_DISABLED", status_code=400)


class RouterRpcExecutionError(RouterCoreError):
    """Raised when router returns an application-level error during RPC."""

    def __init__(self, message: str, code: str = "RPC_EXECUTION_ERROR", status_code: int = 502):
        super().__init__(message, code=code, status_code=status_code)


class RouterValidationError(RouterCoreError):
    """Raised when input parameters fail validation."""

    def __init__(self, message: str, code: str = "VALIDATION_ERROR"):
        super().__init__(message, code=code, status_code=400)


def from_legacy_error(exc: Exception) -> RouterCoreError:
    """Translates a legacy RouterRpcError or generic Exception to a RouterCoreError."""
    if isinstance(exc, RouterCoreError):
        return exc

    msg = str(exc)
    code = getattr(exc, "code", "ROUTER_ERROR")
    status = getattr(exc, "status_code", getattr(exc, "http_status", 500))

    if "not configured" in msg.lower() or code == "ROUTER_NOT_CONFIGURED":
        return RouterNotConfiguredError(msg)
    if "auth" in msg.lower() or "login" in msg.lower() or status == 401:
        return RouterAuthError(msg)
    if "unreachable" in msg.lower() or "connection" in msg.lower() or status == 502:
        return RouterUnreachableError(msg)
    if status == 400:
        return RouterValidationError(msg, code=code)

    return RouterRpcExecutionError(msg, code=code, status_code=status)
