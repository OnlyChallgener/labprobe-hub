"""HTTP transport correction for the developer-supplied Reyee eWeb flow.

BE72 Pro is reachable over plain HTTP.  Enter the configured root URL, allow the
router to generate its own ``/cgi-bin/luci/?stamp=...`` redirect, and extract the
per-page GibberishAES key when the firmware exposes it.  Some BE72 builds keep
the key outside the returned HTML; those builds use the already proven Reyee
legacy AES password for the same ``/api/auth`` request.
"""
from __future__ import annotations

import re
from typing import Any, Dict
from urllib.parse import urlparse

import requests

import router_developer_flow_patch as developer_flow
from router_rpc import LOGIN_AES_PASSWORD, RouterNotConfigured, RouterRpcError


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
    """Fetch the real HTTP login page and return its dynamic or BE72 key."""
    base = _configured_base(cfg.get("address", ""))
    if not base:
        raise RouterNotConfigured()

    urls = (base + "/", base + "/cgi-bin/luci/")
    last_status = 0
    last_url = ""
    fetched_ok = False
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
        fetched_ok = True
        key = _extract_key(response.text)
        if key:
            self.logger.info(
                "router eweb dynamic AES key extracted transport=%s login_url=%s",
                urlparse(base).scheme,
                last_url,
            )
            return key

    if fetched_ok:
        self.logger.info(
            "router eweb HTTP login page has no inline AES key; using BE72 compatible key login_url=%s",
            last_url,
        )
        return LOGIN_AES_PASSWORD

    raise RouterRpcError(
        f"Router HTTP login page was unavailable (status={last_status}, url={last_url})",
        "RPC_HTTP_ERROR",
        502,
    )


def install_router_http_developer_transport_patch() -> None:
    """Patch the developer flow before it is installed on the runtime client."""
    developer_flow._https_base = _configured_base
    developer_flow._fetch_login_key = _fetch_login_key_http
