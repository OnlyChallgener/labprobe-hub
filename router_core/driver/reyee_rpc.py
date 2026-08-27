"""Reyee JSON-RPC Client.

Implements the BE72-proven eWeb wire protocol:
- Path: /cgi-bin/luci/api/cmd?auth=<sid> (or module path)
- Headers: Content-Accept signs eWeb wire byte length; Contents-Accept signs the transmitted wire
- Body: {"method": "<method>", "params": <params>}
- Auto-recovery: On explicit auth expiry, performs single-flight re-login and retries once.
"""

import hashlib
import json
import time
from typing import Any, Dict, Optional, Tuple, Iterable
import requests

from router_core.driver.reyee_session import ReyeeSessionManager, _normalize_endpoint_url
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
        self._last_success_at_ms = 0
        self._last_error_at_ms = 0
        self._last_error_code = ""
        self._last_error_message = ""

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

    def control_status(self) -> Dict[str, Any]:
        checked = bool(self._last_success_at_ms or self._last_error_at_ms)
        connected = bool(
            self._last_success_at_ms
            and self._last_success_at_ms >= self._last_error_at_ms
        )
        return {
            "checked": checked,
            "connected": connected,
            "lastSuccessAt": int(self._last_success_at_ms),
            "lastErrorAt": int(self._last_error_at_ms),
            "lastErrorCode": self._last_error_code,
            "lastErrorMessage": self._last_error_message,
        }

    def _record_success(self) -> None:
        self._last_success_at_ms = int(time.time() * 1000)
        self._last_error_code = ""
        self._last_error_message = ""

    def _record_error(self, code: str, message: str) -> None:
        self._last_error_at_ms = int(time.time() * 1000)
        self._last_error_code = str(code or "RPC_FAILED")
        self._last_error_message = str(message or "Router RPC failed")

    @classmethod
    def _headers(
        cls,
        endpoint_path: str,
        payload: Dict[str, Any],
        wire: str,
        cookie: str,
    ) -> Dict[str, str]:
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
        auth_param: Optional[str] = None,
    ) -> requests.Response:
        wire = self._wire_json(payload)
        auth = auth_param or getattr(session, "sid", "")
        url = _normalize_endpoint_url(
            self._session_manager.address,
            f"{endpoint_path}?auth={auth}",
        )
        return self._session_manager.http_session.post(
            url,
            data=wire.encode("utf-8"),
            headers=self._headers(endpoint_path, payload, wire, session.cookie_header),
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
                auth_param=getattr(session, "sid", ""),
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
        if response.status_code not in {301, 302, 303, 307, 308}:
            return False
        location = str(response.headers.get("Location") or "").lower()
        return "luci" in location

    @staticmethod
    def _looks_like_login_page(text: str) -> bool:
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
            self._record_error("ROUTER_UNREACHABLE", str(exc))
            raise RouterUnreachableError(f"Network error executing RPC '{method}': {exc}") from exc

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
                message = "Router session is valid, but the signed cmd RPC was rejected"
                self._record_error("RPC_SIGNATURE_REJECTED", message)
                raise RouterRpcExecutionError(
                    message,
                    code="RPC_SIGNATURE_REJECTED",
                    status_code=502,
                )
            self._session_manager.invalidate_session()
            if retry_auth:
                return self.call(method, params, endpoint_path, timeout, retry_auth=False)
            message = f"Router authentication expired for method '{method}' (HTTP {resp.status_code})"
            self._record_error("AUTH_EXPIRED", message)
            raise RouterAuthExpiredError(message)

        if resp.status_code >= 400:
            message = f"Router HTTP error {resp.status_code} on method '{method}'"
            self._record_error("RPC_HTTP_ERROR", message)
            raise RouterRpcExecutionError(message)

        try:
            root = resp.json()
        except Exception as exc:
            message = f"Invalid JSON response for method '{method}': {exc}"
            self._record_error("RPC_INVALID_RESPONSE", message)
            raise RouterRpcExecutionError(message) from exc

        if not isinstance(root, dict):
            message = f"Router returned a non-object response for '{method}'"
            self._record_error("RPC_INVALID_RESPONSE", message)
            raise RouterRpcExecutionError(message)
        code = root.get("code")
        if str(code) in {"401", "403", "1001"} or root.get("error") == "session_expired":
            self._session_manager.invalidate_session()
            if retry_auth:
                return self.call(method, params, endpoint_path, timeout, retry_auth=False)
            message = f"Router application session invalid on '{method}' (code={code})"
            self._record_error("AUTH_EXPIRED", message)
            raise RouterAuthExpiredError(message)

        if root.get("error"):
            error = root.get("error")
            message = error.get("message") if isinstance(error, dict) else str(error)
            self._record_error("RPC_REJECTED", message or f"Router rejected method '{method}'")
            raise RouterRpcExecutionError(message or f"Router rejected method '{method}'")
        try:
            numeric_code = int(code or 0)
        except (TypeError, ValueError):
            numeric_code = -1
        if numeric_code != 0:
            message = root.get("message") or root.get("msg") or f"Router API code {numeric_code}"
            self._record_error("RPC_REJECTED", str(message))
            raise RouterRpcExecutionError(str(message), code="RPC_REJECTED", status_code=409)

        self._session_manager.record_activity()
        self._record_success()
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
