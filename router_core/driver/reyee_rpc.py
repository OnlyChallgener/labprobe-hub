"""Reyee JSON-RPC Client.

Implements the official Wire Protocol:
- Path: /cgi-bin/luci/api/cmd?auth=<sid> (or module path)
- Headers: Cookie: <cookie_header>, Content-Type: application/json
- Body: {"method": "<method>", "params": <params>}
- Auto-recovery: On HTTP 401/403, LuCI login redirect/page, or application session
  invalid, performs single-flight re-login and retries the request at most ONCE.
- Circuit breaker protects against infinite retry loops.
"""

import hashlib
import json
from typing import Any, Dict, Optional, Tuple, Iterable
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

    def __init__(
        self,
        session_manager: Optional[ReyeeSessionManager] = None,
        session_mgr: Optional[ReyeeSessionManager] = None,
    ):
        mgr = session_manager or session_mgr
        if mgr is None:
            raise ValueError("session_manager is required")
        self._session_manager = mgr

    @property
    def session_manager(self) -> ReyeeSessionManager:
        return self._session_manager

    @staticmethod
    def _wire_json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _eweb_byte_length(value: str) -> int:
        total = 0
        for char in value:
            codepoint = ord(char)
            if codepoint <= 0xFF:
                total += 1
            elif codepoint <= 0xFFFF:
                total += 3
            else:
                total += 4
        return total

    @classmethod
    def _headers(cls, endpoint_path: str, wire: str, cookie: str) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json;charset=UTF-8",
            "Cookie": cookie,
            "User-Agent": "LabProbe-Hub/0.11.2",
        }
        if endpoint_path.rstrip("/").endswith("/cmd"):
            secret = "Web@Rj$2020!"
            headers["Content-Accept"] = hashlib.md5(
                (secret + str(cls._eweb_byte_length(wire))).encode("utf-8")
            ).hexdigest()
            headers["Contents-Accept"] = hashlib.md5(
                (secret + wire).encode("utf-8")
            ).hexdigest()
        return headers

    def _post(
        self,
        endpoint_path: str,
        session: Any,
        payload: Dict[str, Any],
        timeout: Optional[Tuple[int, int]] = None,
    ) -> requests.Response:
        wire = self._wire_json(payload)
        return self._session_manager.http_session.post(
            f"{self._session_manager.address}{endpoint_path}?auth={session.sid}",
            data=wire.encode("utf-8"),
            headers=self._headers(endpoint_path, wire, session.cookie_header),
            timeout=timeout or self._session_manager.http_timeout,
            verify=self._session_manager.verify_tls,
            allow_redirects=False,
        )

    def _session_probe_ok(self, session: Any, timeout: Optional[Tuple[int, int]]) -> bool:
        try:
            response = self._post(
                "/cgi-bin/luci/api/overview",
                session,
                {"method": "getDeviceInfo", "params": None},
                timeout,
            )
            if response.status_code >= 400:
                return False
            root = response.json()
            if not isinstance(root, dict) or root.get("error"):
                return False
            return int(root.get("code") or 0) == 0
        except Exception:
            return False

    @staticmethod
    def _is_login_redirect(response: requests.Response) -> bool:
        """Recognize the LuCI login redirect observed on expired BE72 sessions."""
        if response.status_code not in {301, 302, 303, 307, 308}:
            return False
        location = str(response.headers.get("Location") or "").lower()
        return "luci" in location

    @staticmethod
    def _looks_like_login_page(text: str) -> bool:
        """Use the same narrow login-page markers as the BE72-proven client."""
        low = str(text or "").lower()
        return 'id="password"' in low and 'id="login"' in low and "api/auth" in low

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
        payload = {
            "method": method,
            "params": params if params is not None else {},
        }

        try:
            resp = self._post(endpoint_path, session, payload, timeout)
        except requests.RequestException as exc:
            raise RouterUnreachableError(f"Network error executing RPC '{method}': {exc}") from exc

        # An expired BE72 SID can be reported as 401/403, a redirect to LuCI,
        # or an HTTP-200 login page. These are the same narrow conditions used
        # by the previous client after real-device verification.
        login_redirect = self._is_login_redirect(resp)
        login_page = self._looks_like_login_page(getattr(resp, "text", ""))
        if resp.status_code in (401, 403) or login_redirect or login_page:
            if (
                resp.status_code in (401, 403)
                and not login_redirect
                and not login_page
                and endpoint_path.rstrip("/").endswith("/cmd")
                and self._session_probe_ok(session, timeout)
            ):
                raise RouterRpcExecutionError(
                    "Router session is valid, but the signed cmd RPC was rejected",
                    code="RPC_SIGNATURE_REJECTED",
                    status_code=502,
                )
            self._session_manager.invalidate_session()
            if retry_auth:
                # Re-login under single-flight and retry exactly once
                return self.call(method, params, endpoint_path, timeout, retry_auth=False)
            raise RouterAuthExpiredError(
                f"Router authentication expired for method '{method}' (HTTP {resp.status_code})"
            )

        if resp.status_code >= 400:
            raise RouterRpcExecutionError(f"Router HTTP error {resp.status_code} on method '{method}'")

        try:
            root = resp.json()
        except Exception as exc:
            raise RouterRpcExecutionError(f"Invalid JSON response for method '{method}': {exc}") from exc

        # Check for application-level session invalidation in JSON body
        if not isinstance(root, dict):
            raise RouterRpcExecutionError(f"Router returned a non-object response for '{method}'")
        code = root.get("code")
        if str(code) in {"401", "403", "1001"} or root.get("error") == "session_expired":
            self._session_manager.invalidate_session()
            if retry_auth:
                return self.call(method, params, endpoint_path, timeout, retry_auth=False)
            raise RouterAuthExpiredError(f"Router application session invalid on '{method}' (code={code})")

        if root.get("error"):
            error = root.get("error")
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise RouterRpcExecutionError(message or f"Router rejected method '{method}'")
        try:
            numeric_code = int(code or 0)
        except (TypeError, ValueError):
            numeric_code = -1
        if numeric_code != 0:
            message = root.get("message") or root.get("msg") or f"Router API code {numeric_code}"
            raise RouterRpcExecutionError(str(message), code="RPC_REJECTED", status_code=409)

        # Record activity on success (Idle Timeout refresh)
        self._session_manager.record_activity()
        return root

    def rpc(
        self,
        method: str,
        module: str = "",
        data: Any = None,
        no_parse: bool = False,
        params: Any = None,
        endpoint_path: str = "/cgi-bin/luci/api/cmd",
        timeout: Optional[Tuple[int, int]] = None,
        retry_auth: bool = True,
        **kwargs: Any,
    ) -> Any:
        """Executes a legacy-compatible eWeb module RPC call with module/data/noParse wire payload."""
        if params is None:
            cmd_params: Dict[str, Any] = {
                "module": module,
                "noParse": bool(no_parse),
                "async": None,
                "remoteIp": False,
                "device": "pc",
            }
            if data is not None:
                cmd_params["data"] = data
        else:
            cmd_params = params

        root = self.call(
            method=method,
            params=cmd_params,
            endpoint_path=endpoint_path,
            timeout=timeout,
            retry_auth=retry_auth,
        )
        return root.get("data") if isinstance(root, dict) and "data" in root else root

    def batch(self, calls: Iterable[Dict[str, Any]]) -> Any:
        """Executes a batched eWeb array RPC call (cmdArr)."""
        rows = []
        for call in calls:
            cmd_params: Dict[str, Any] = {
                "module": call.get("module", ""),
                "noParse": bool(call.get("noParse", False)),
                "async": None,
                "remoteIp": False,
            }
            if "data" in call:
                cmd_params["data"] = call["data"]
            rows.append({"method": call.get("method", ""), "params": cmd_params})
        root = self.call("cmdArr", {"device": "pc", "params": rows})
        return root.get("data") if isinstance(root, dict) and "data" in root else root
