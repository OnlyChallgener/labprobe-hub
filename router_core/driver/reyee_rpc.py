"""Reyee JSON-RPC Client.

Implements the official Wire Protocol:
- Path: /cgi-bin/luci/api/cmd?auth=<sid> (or module path)
- Headers: Cookie: <cookie_header>, Content-Type: application/json
- Body: {"method": "<method>", "params": <params>}
- Auto-recovery: On HTTP 401/403 or application session invalid, performs single-flight
  re-login and retries original request at most ONCE.
- Circuit breaker protects against infinite retry loops.
"""

from typing import Any, Dict, Optional, Tuple
import requests

from router_core.driver.reyee_session import ReyeeSessionManager
from router_core.errors import (
    RouterAuthError,
    RouterAuthExpiredError,
    RouterRpcExecutionError,
    RouterUnreachableError,
    from_legacy_error,
)


class ReyeeRpcClient:
    """Client for executing wire JSON-RPC commands against Reyee eWeb OS."""

    def __init__(self, session_manager: ReyeeSessionManager):
        self._session_manager = session_manager

    @property
    def session_manager(self) -> ReyeeSessionManager:
        return self._session_manager

    def call(
        self,
        method: str,
        params: Any = None,
        endpoint_path: str = "/cgi-bin/luci/api/cmd",
        timeout: Optional[Tuple[int, int]] = None,
        retry_auth: bool = True,
    ) -> Dict[str, Any]:
        """Executes a JSON-RPC method call with automatic single-flight auth recovery."""
        session = self._session_manager.get_session()
        base_url = self._session_manager.address

        url = f"{base_url}{endpoint_path}?auth={session.sid}"
        payload = {
            "method": method,
            "params": params if params is not None else {},
        }
        headers = {
            "Content-Type": "application/json",
            "Cookie": session.cookie_header,
        }

        req_timeout = timeout or self._session_manager.http_timeout
        http = self._session_manager.http_session

        try:
            resp = http.post(
                url,
                json=payload,
                headers=headers,
                timeout=req_timeout,
                verify=self._session_manager.verify_tls,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise RouterUnreachableError(f"Network error executing RPC '{method}': {exc}") from exc

        # Check for auth expiration at HTTP status level
        if resp.status_code in (401, 403):
            if retry_auth:
                self._session_manager.invalidate_session()
                # Re-login under single-flight and retry exactly once
                return self.call(method, params, endpoint_path, timeout, retry_auth=False)
            raise RouterAuthExpiredError(f"Router returned HTTP {resp.status_code} for method '{method}'")

        if resp.status_code >= 400:
            raise RouterRpcExecutionError(f"Router HTTP error {resp.status_code} on method '{method}'")

        try:
            root = resp.json()
        except Exception as exc:
            raise RouterRpcExecutionError(f"Invalid JSON response for method '{method}': {exc}") from exc

        # Check for application-level session invalidation in JSON body
        code = root.get("code")
        if code in (401, 403, 1001) or root.get("error") == "session_expired":
            if retry_auth:
                self._session_manager.invalidate_session()
                return self.call(method, params, endpoint_path, timeout, retry_auth=False)
            raise RouterAuthExpiredError(f"Router application session invalid on '{method}' (code={code})")

        # Record activity on success (Idle Timeout refresh)
        self._session_manager.record_activity()
        return root
