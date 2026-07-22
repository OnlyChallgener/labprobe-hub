"""Final BE72 wire correction from the browser capture.

The login response contains ``token`` and ``sid``.  The browser sends the SID in
``?auth=...`` for subsequent requests, including ``/api/cmd``.  Keep the exact
observed double slash in ``/cgi-bin/luci//api/...`` and do not retry with token.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

import requests

import router_be72_auth_patch as be72
from router_http_developer_transport_patch import _configured_base
from router_rpc import RouterRpcError, RouterSession, _wire_json


def _sid_only_candidates(self: Any, api_path: str, session: RouterSession) -> List[Tuple[str, str]]:
    sid = str(session.sid or "").strip()
    return [("sid", sid)] if sid else []


def _raw_api_call_browser_path(
    self: Any,
    cfg: Dict[str, Any],
    credential: str,
    cookie: str,
    api_path: str,
    payload: Dict[str, Any],
):
    base = _configured_base(cfg.get("address", ""))
    wire = _wire_json(payload)
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    try:
        response = self.http.post(
            base + f"/cgi-bin/luci//api/{api_path}?auth={credential}",
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


def install_router_be72_sid_wire_patch() -> None:
    """Apply the captured SID-only API behavior to the BE72 runtime."""
    be72._auth_candidates = _sid_only_candidates
    be72._raw_api_call = _raw_api_call_browser_path
