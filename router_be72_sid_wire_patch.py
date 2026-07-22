"""Final BE72 wire behavior from browser and developer captures.

Confirmed rules:
- login returns token, sid and sn;
- every business API uses ``?auth=<sid>``;
- the session cookie is ``<sn>=<sid>``;
- overview/system/common calls work directly after login;
- cmd calls additionally carry the two Reyee MD5 request signatures.

A cmd signature rejection must not invalidate a session that still passes the
plain overview probe.  This keeps Hub connected while reporting the cmd failure
as an operation error instead of repeatedly logging into the router.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

import requests

import router_be72_auth_patch as be72
import router_rpc_v010 as runtime
from router_http_developer_transport_patch import _configured_base
from router_rpc import (
    AUTH_RETRY_BACKOFF_SECONDS,
    GLOBAL_ROUTER_SESSION_CACHE,
    RouterAuthExpired,
    RouterRpcError,
    RouterSession,
    _wire_json,
)


def _sid_only_candidates(self: Any, api_path: str, session: RouterSession) -> List[Tuple[str, str]]:
    sid = str(session.sid or "").strip()
    return [("sid", sid)] if sid else []


def _session_cookie(session: RouterSession) -> str:
    serial = str(session.serial_number or "").strip()
    sid = str(session.sid or "").strip()
    return f"{serial}={sid}" if serial and sid else ""


def _headers_for_api(
    self: Any,
    api_path: str,
    payload: Dict[str, Any],
    session: RouterSession,
) -> Dict[str, str]:
    headers = {"Content-Type": "application/json;charset=UTF-8"}

    # The browser adds these headers only to the protected cmd RPC family.
    # RuijieRouterClient._headers_for implements the captured formulas:
    #   Content-Accept  = MD5("Web@Rj$2020!" + canonical request data)
    #   Contents-Accept = MD5("Web@Rj$2020!" + wire request data)
    if api_path == "cmd":
        headers.update(self._headers_for(payload, session))

    cookie = _session_cookie(session)
    if cookie:
        headers["Cookie"] = cookie
    return headers


def _raw_api_call_browser_path(
    self: Any,
    cfg: Dict[str, Any],
    credential: str,
    cookie: str,
    api_path: str,
    payload: Dict[str, Any],
):
    del cookie  # Use the exact SN=sid cookie derived from the active session.
    base = _configured_base(cfg.get("address", ""))
    wire = _wire_json(payload)
    session = self.session
    headers = _headers_for_api(self, api_path, payload, session)
    try:
        response = self.http.post(
            base + f"/cgi-bin/luci/api/{api_path}?auth={credential}",
            data=wire.encode("utf-8"),
            headers=headers,
            timeout=(4, 15),
            verify=cfg.get("verifyTls", False),
            allow_redirects=False,
        )
    except requests.Timeout as exc:
        raise RouterRpcError("Router API timed out", "RPC_TIMEOUT", 504) from exc
    except requests.RequestException as exc:
        raise RouterRpcError(
            f"Router API request failed: {exc}",
            "ROUTER_UNREACHABLE",
            502,
        ) from exc

    root: Dict[str, Any] = {}
    if response.status_code < 400:
        root = be72._parse_json(response)
    return response, root


def _root_ok(response: requests.Response, root: Dict[str, Any]) -> bool:
    if response.status_code >= 400 or not isinstance(root, dict) or root.get("error"):
        return False
    try:
        return int(root.get("code") or 0) == 0
    except (TypeError, ValueError):
        return False


def _post_api(
    self: Any,
    api_path: str,
    payload: Dict[str, Any],
    retry_auth: bool = True,
) -> Any:
    session = self.login()
    cfg = self.config
    sid = str(session.sid or "").strip()
    if not sid:
        error = RouterAuthExpired("Router login returned no sid")
        self._mark_failure(error)
        raise error

    response, root = _raw_api_call_browser_path(self, cfg, sid, "", api_path, payload)

    if response.status_code in {401, 403}:
        # cmd has a separate signature layer.  Prove whether the login session is
        # still valid before throwing it away and causing another router login.
        if api_path == "cmd":
            probe_response, probe_root = _raw_api_call_browser_path(
                self,
                cfg,
                sid,
                "",
                "overview",
                {"method": "getDeviceInfo", "params": None},
            )
            if _root_ok(probe_response, probe_root):
                error = RouterRpcError(
                    "Router session is valid, but the signed cmd RPC was rejected",
                    "RPC_SIGNATURE_REJECTED",
                    502,
                )
                self.logger.warning(
                    "router eweb cmd signature rejected status=%s sid=True session_probe=ok",
                    response.status_code,
                )
                self._mark_failure(error)
                raise error

        config_key = self._session_cache_key(cfg)
        self.logger.warning(
            "router eweb auth rejected api=%s status=%s sid=True",
            api_path,
            response.status_code,
        )
        with self.login_lock:
            current = self.session
            same_session = current.sid == session.sid and current.obtained_at == session.obtained_at
            if same_session:
                self.clear_session()
                if retry_auth:
                    self.login(force=True)
                else:
                    GLOBAL_ROUTER_SESSION_CACHE.block_login(
                        config_key,
                        AUTH_RETRY_BACKOFF_SECONDS,
                    )
        if retry_auth:
            return _post_api(self, api_path, payload, retry_auth=False)
        error = RouterAuthExpired()
        self._mark_failure(error)
        raise error

    if response.status_code >= 400:
        error = RouterRpcError(
            f"Router returned HTTP {response.status_code}",
            "RPC_HTTP_ERROR",
            502,
        )
        self._mark_failure(error)
        raise error

    if root.get("error"):
        message = root["error"].get("message") if isinstance(root["error"], dict) else str(root["error"])
        error = RouterRpcError(message or "Router rejected the API call", "RPC_REJECTED", 409)
        self._mark_failure(error)
        raise error
    try:
        code = int(root.get("code") or 0)
    except (TypeError, ValueError):
        code = -1
    if code != 0:
        error = RouterRpcError(
            str(root.get("error") or root.get("message") or f"Router API code {code}"),
            "RPC_REJECTED",
            409,
        )
        self._mark_failure(error)
        raise error

    self._mark_success()
    return root.get("data") if "data" in root else root


def install_router_be72_sid_wire_patch() -> None:
    """Apply the captured SID, cookie and per-API signing behavior."""
    be72._auth_candidates = _sid_only_candidates
    be72._raw_api_call = _raw_api_call_browser_path
    client_class = runtime.StableRuijieRouterClient
    client_class._post_api = _post_api
