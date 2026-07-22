"""HTTP transport correction for the developer-supplied Reyee eWeb flow.

The BE72 Pro management page is only reachable over plain HTTP on the user's
LAN.  Keep the developer's exact authentication sequence (dynamic AES key,
username=admin, pwd payload, sid + first Set-Cookie), but preserve the scheme
and port from ROUTER_EWEB_URL instead of forcing HTTPS/443.
"""
from __future__ import annotations

import re
from typing import Any, Dict
from urllib.parse import urlparse

import requests

import router_developer_flow_patch as developer_flow
from router_rpc import RouterNotConfigured, RouterRpcError


_KEY_PATTERNS = (
    re.compile(r'GibberishAES\.enc\(passwordEl\.value,\s*"([a-f0-9]+)"\)', re.I),
    re.compile(r"GibberishAES\s*\.\s*enc\s*\(\s*passwordEl\.value\s*,\s*['\"]([a-f0-9]+)['\"]\s*\)", re.I),
)


def _configured_base(address: str) -> str:
    """Return the configured HTTP/HTTPS origin without changing its scheme."""
    raw = str(address or "").strip().rstrip("/")
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname or ""
    if not host:
        return ""
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    scheme = (parsed.scheme or "http").lower()
    if scheme not in {"http", "https"}:
        scheme = "http"
    default_port = 443 if scheme == "https" else 80
    port = parsed.port or default_port
    suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{display_host}{suffix}"


def _extract_key(text: str) -> str:
    for pattern in _KEY_PATTERNS:
        match = pattern.search(text or "")
        if match:
            return match.group(1)
    return ""


def _fetch_login_key_http(self: Any, cfg: Dict[str, Any]) -> str:
    """Fetch the real HTTP login page and extract the developer AES key."""
    base = _configured_base(cfg.get("address", ""))
    if not base:
        raise RouterNotConfigured()

    # First enter the root address so the router can generate its own
    # /cgi-bin/luci/?stamp=... URL.  Keep the direct LuCI URL as a fallback.
    urls = (base + "/", base + "/cgi-bin/luci/")
    last_status = 0
    last_url = ""
    for url in urls:
        try:
            response = self.http.get(
                url,
                timeout=(4, 12),
                verify=cfg.get("verifyTls", False),
                allow_redirects=True,
                headers={"Accept": "text/html,application/xhtml+xml"},
            )
        except requests.RequestException as exc:
            raise RouterRpcError(
                f"Unable to fetch the router login page over HTTP: {exc}",
                "ROUTER_UNREACHABLE",
                502,
            ) from exc

        last_status = response.status_code
        last_url = str(response.url or url)
        if response.status_code >= 400:
            continue
        key = _extract_key(response.text)
        if key:
            self.logger.info(
                "router eweb dynamic AES key extracted transport=%s login_url=%s",
                urlparse(base).scheme,
                last_url,
            )
            return key

    raise RouterRpcError(
        f"Could not find GibberishAES key in the HTTP login HTML (status={last_status}, url={last_url})",
        "LOGIN_KEY_NOT_FOUND",
        502,
    )


def install_router_http_developer_transport_patch() -> None:
    """Patch the developer flow before it is installed on the runtime client."""
    developer_flow._https_base = _configured_base
    developer_flow._fetch_login_key = _fetch_login_key_http
