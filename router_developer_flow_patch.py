"""Exact Reyee eWeb authentication flow supplied by the router developer.

The reference implementation uses HTTPS/443, fetches ``/cgi-bin/luci/`` to
extract the per-page GibberishAES key, logs in with the ``username/pwd`` JSON
shape, keeps the first Set-Cookie pair, and calls every API with
``?auth=<sid>`` plus that cookie.  This patch intentionally avoids browser
fallbacks, legacy fixed keys, alternate login payloads, and proprietary request
signature headers so Hub matches the validated Node.js sequence byte-for-byte
where practical.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests

import router_rpc_v010 as runtime
from router_rpc import (
    AUTH_RETRY_BACKOFF_SECONDS,
    GLOBAL_ROUTER_SESSION_CACHE,
    RouterAuthExpired,
    RouterNotConfigured,
    RouterRpcError,
    RouterSession,
    _safe_int,
    _wire_json,
    gibberish_aes_encrypt,
)


_KEY_RE = re.compile(
    r'GibberishAES\.enc\(passwordEl\.value,\s*"([a-f0-9]+)"\)',
    re.I,
)


def _https_base(address: str) -> str:
    """Use the developer-tested HTTPS/443 transport regardless of saved HTTP UI URL."""
    raw = str(address or "").strip().rstrip("/")
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = parsed.hostname or ""
    if not host:
        return ""
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    port = parsed.port if parsed.scheme.lower() == "https" and parsed.port else 443
    suffix = "" if port == 443 else f":{port}"
    return f"https://{display_host}{suffix}"


def _first_set_cookie(response: requests.Response) -> str:
    values = []
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None:
        getter = getattr(raw_headers, "getlist", None)
        if callable(getter):
            values = list(getter("Set-Cookie") or [])
        if not values:
            getter = getattr(raw_headers, "get_all", None)
            if callable(getter):
                values = list(getter("Set-Cookie") or [])
    if not values:
        value = str(response.headers.get("Set-Cookie") or "").strip()
        if value:
            values = [value]
    if not values:
        return ""
    return str(values[0]).split(";", 1)[0].strip()


def _install_cookie(client: Any, cookie_header: str, base: str) -> None:
    if not cookie_header or "=" not in cookie_header:
        return
    name, value = cookie_header.split("=", 1)
    host = urlparse(base).hostname or ""
    client.http.cookies.set(name.strip(), value.strip(), domain=host, path="/")


def _current_cookie_header(client: Any) -> str:
    explicit = str(getattr(client, "_developer_cookie_header", "") or "").strip()
    if explicit:
        return explicit
    for cookie in client.http.cookies:
        return f"{cookie.name}={cookie.value}"
    return ""


def _fetch_login_key(self: Any, cfg: Dict[str, Any]) -> str:
    base = _https_base(cfg.get("address", ""))
    if not base:
        raise RouterNotConfigured()
    try:
        response = self.http.get(
            base + "/cgi-bin/luci/",
            timeout=(4, 12),
            verify=cfg.get("verifyTls", False),
            allow_redirects=False,
            headers={"Accept": "text/html,application/xhtml+xml"},
        )
    except requests.RequestException as exc:
        raise RouterRpcError(
            f"Unable to fetch the router login page over HTTPS: {exc}",
            "ROUTER_UNREACHABLE",
            502,
        ) from exc
    if response.status_code >= 400:
        raise RouterRpcError(
            f"Router HTTPS login page returned HTTP {response.status_code}",
            "RPC_HTTP_ERROR",
            502,
        )
    match = _KEY_RE.search(response.text or "")
    if not match:
        raise RouterRpcError(
            "Could not find GibberishAES key in the HTTPS login HTML",
            "LOGIN_KEY_NOT_FOUND",
            502,
        )
    return match.group(1)


def _parse_json(response: requests.Response) -> Dict[str, Any]:
    try:
        root = response.json()
    except ValueError as exc:
        raise RouterRpcError(
            "Router returned invalid JSON",
            "RPC_INVALID_RESPONSE",
            502,
        ) from exc
    if not isinstance(root, dict):
        raise RouterRpcError(
            "Router returned an invalid JSON object",
            "RPC_INVALID_RESPONSE",
            502,
        )
    return root


def _raw_api_call(
    self: Any,
    cfg: Dict[str, Any],
    sid: str,
    cookie_header: str,
    api_path: str,
    payload: Dict[str, Any],
) -> Tuple[requests.Response, Dict[str, Any]]:
    base = _https_base(cfg.get("address", ""))
    wire = _wire_json(payload)
    headers = {"Content-Type": "application/json"}
    if cookie_header:
        headers["Cookie"] = cookie_header
    try:
        response = self.http.post(
            base + f"/cgi-bin/luci/api/{api_path}?auth={sid}",
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
        root = _parse_json(response)
    return response, root


def _login(self: Any, force: bool = False) -> RouterSession:
    with self.login_lock:
        cfg = self.config
        config_key = self._session_cache_key(cfg)
        retry_after = GLOBAL_ROUTER_SESSION_CACHE.retry_after(config_key)
        if not force and retry_after > 0:
            error = RouterAuthExpired(f"Router auth retry paused for {retry_after}s")
            self._mark_failure(error)
            raise error

        cached = GLOBAL_ROUTER_SESSION_CACHE.restore(config_key, self.http)
        if not force and cached.valid_locally and cached.sid and _current_cookie_header(self):
            return cached
        if not cfg.get("address") or not cfg.get("password"):
            error = RouterNotConfigured()
            self._mark_failure(error)
            raise error

        self.http.cookies.clear()
        self._developer_cookie_header = ""
        encryption_key = _fetch_login_key(self, cfg)
        encrypted_password = re.sub(
            r"\s+",
            "",
            gibberish_aes_encrypt(str(cfg["password"]), encryption_key),
        )
        timestamp = str(round(time.time()))
        body = {
            "method": "login",
            "params": {
                "username": "admin",
                "time": timestamp,
                "encry": True,
                "pwd": encrypted_password,
                "isCheckReadAgreement": "true",
            },
        }
        base = _https_base(cfg.get("address", ""))
        wire = _wire_json(body)
        try:
            response = self.http.post(
                base + "/cgi-bin/luci/api/auth",
                data=wire.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=(4, 12),
                verify=cfg.get("verifyTls", False),
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            error = RouterRpcError(
                f"Unable to connect to the router login API: {exc}",
                "ROUTER_UNREACHABLE",
                502,
            )
            self._mark_failure(error)
            raise error from exc

        root = _parse_json(response)
        data = root.get("data") if isinstance(root.get("data"), dict) else {}
        token = str(data.get("token") or "").strip()
        sid = str(data.get("sid") or "").strip()
        serial = str(data.get("sn") or "").strip()
        cookie_header = _first_set_cookie(response)

        if response.status_code >= 400 or not token or not sid:
            self.clear_session()
            error = RouterRpcError(
                f"Router login failed: http={response.status_code} code={root.get('code')}",
                "LOGIN_FAILED",
                401,
            )
            self._mark_failure(error)
            raise error

        _install_cookie(self, cookie_header, base)
        self._developer_cookie_header = cookie_header or _current_cookie_header(self)
        session_seconds = _safe_int(
            data.get("sessiontime") or data.get("sessionTime"),
            cfg.get("sessionSeconds", 3600),
            600,
            7200,
        )
        session = RouterSession(
            sid=sid,
            auth_token=token,
            serial_number=serial,
            obtained_at=time.time(),
            session_seconds=session_seconds,
        )
        self.session = session
        self._save_session_cookies(cfg)

        # Match the developer test: immediately validate sid + first cookie on
        # /api/overview before declaring the session usable.
        validation_response, validation_root = _raw_api_call(
            self,
            cfg,
            sid,
            self._developer_cookie_header,
            "overview",
            {"method": "getDeviceInfo", "params": None},
        )
        if validation_response.status_code >= 400 or int(validation_root.get("code") or 0) != 0:
            self.clear_session()
            error = RouterAuthExpired(
                f"Developer-flow session validation failed: HTTP {validation_response.status_code}"
            )
            self._mark_failure(error)
            raise error

        self.login_key = encryption_key
        self.login_variant = "developer-pwd-https"
        self._mark_success()
        self.logger.info(
            "router eweb developer login ok address=%s sn=%s session=%ss auth=sid cookie=%s transport=https",
            cfg.get("address"),
            serial or "unknown",
            session_seconds,
            bool(self._developer_cookie_header),
        )
        return session


def _post_api(
    self: Any,
    api_path: str,
    payload: Dict[str, Any],
    retry_auth: bool = True,
) -> Any:
    session = self.login()
    cfg = self.config
    sid = str(session.sid or "").strip()
    cookie_header = _current_cookie_header(self)
    if not sid or not cookie_header:
        error = RouterAuthExpired("Router developer-flow session is incomplete")
        self._mark_failure(error)
        raise error

    response, root = _raw_api_call(
        self,
        cfg,
        sid,
        cookie_header,
        api_path,
        payload,
    )
    if response.status_code in {401, 403}:
        config_key = self._session_cache_key(cfg)
        self.logger.warning(
            "router developer-flow auth rejected api=%s status=%s sid=%s cookie=%s",
            api_path,
            response.status_code,
            bool(sid),
            bool(cookie_header),
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


def install_router_developer_flow_patch() -> None:
    """Install the exact developer-auth methods before the blueprint is created."""
    client_class = runtime.StableRuijieRouterClient
    if getattr(client_class, "_labprobe_developer_flow_patch", False):
        return
    client_class._fetch_login_key = _fetch_login_key
    client_class.login = _login
    client_class._post_api = _post_api
    client_class._labprobe_developer_flow_patch = True
