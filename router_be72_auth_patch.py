"""BE72 Pro authentication behavior observed in the browser network panel.

The BE72 page is HTTP-only, implicitly uses the administrator account ``admin``,
and sends the encrypted password in the ``password`` field.  The login response
contains both ``token`` and ``sid``.  Reyee firmware families do not use those two
values consistently across endpoints, so Hub validates and remembers the working
credential per API path instead of assuming one value for every endpoint.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Tuple

import requests

import router_developer_flow_patch as developer_flow
import router_rpc_v010 as runtime
from router_http_developer_transport_patch import _configured_base
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


def _parse_json(response: requests.Response) -> Dict[str, Any]:
    try:
        root = response.json()
    except ValueError as exc:
        raise RouterRpcError("Router returned invalid JSON", "RPC_INVALID_RESPONSE", 502) from exc
    if not isinstance(root, dict):
        raise RouterRpcError("Router returned an invalid JSON object", "RPC_INVALID_RESPONSE", 502)
    return root


def _cookie_header(client: Any) -> str:
    explicit = str(getattr(client, "_developer_cookie_header", "") or "").strip()
    if explicit:
        return explicit
    for cookie in client.http.cookies:
        return f"{cookie.name}={cookie.value}"
    return ""


def _first_set_cookie(response: requests.Response) -> str:
    values: List[str] = []
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
    return str(values[0]).split(";", 1)[0].strip() if values else ""


def _install_cookie(client: Any, header: str, base: str) -> None:
    if not header or "=" not in header:
        return
    name, value = header.split("=", 1)
    from urllib.parse import urlparse

    host = urlparse(base).hostname or ""
    client.http.cookies.set(name.strip(), value.strip(), domain=host, path="/")


def _raw_api_call(
    self: Any,
    cfg: Dict[str, Any],
    credential: str,
    cookie: str,
    api_path: str,
    payload: Dict[str, Any],
) -> Tuple[requests.Response, Dict[str, Any]]:
    base = _configured_base(cfg.get("address", ""))
    wire = _wire_json(payload)
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
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
        raise RouterRpcError(f"Router API request failed: {exc}", "ROUTER_UNREACHABLE", 502) from exc

    root: Dict[str, Any] = {}
    if response.status_code < 400:
        root = _parse_json(response)
    return response, root


def _auth_candidates(self: Any, api_path: str, session: RouterSession) -> List[Tuple[str, str]]:
    preferred = getattr(self, "_be72_auth_preference", {})
    remembered = str(preferred.get(api_path) or "")

    # Browser captures show /api/cmd uses the login auth token on BE72, while the
    # developer's overview/system sample uses sid.  Try the observed value first
    # and automatically fall back to the other one without re-logging in.
    default_order = ["token", "sid"] if api_path == "cmd" else ["sid", "token"]
    order = ([remembered] if remembered else []) + default_order
    values = {"token": str(session.auth_token or "").strip(), "sid": str(session.sid or "").strip()}
    result: List[Tuple[str, str]] = []
    seen = set()
    for label in order:
        value = values.get(label, "")
        if value and value not in seen:
            result.append((label, value))
            seen.add(value)
    return result


def _remember_auth(self: Any, api_path: str, label: str) -> None:
    mapping = dict(getattr(self, "_be72_auth_preference", {}) or {})
    mapping[api_path] = label
    self._be72_auth_preference = mapping


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
        if not force and cached.valid_locally and cached.sid and cached.auth_token and _cookie_header(self):
            return cached
        if not cfg.get("address") or not cfg.get("password"):
            error = RouterNotConfigured()
            self._mark_failure(error)
            raise error

        self.http.cookies.clear()
        self._developer_cookie_header = ""
        self._be72_auth_preference = {}
        encryption_key = developer_flow._fetch_login_key(self, cfg)
        encrypted = re.sub(r"\s+", "", gibberish_aes_encrypt(str(cfg["password"]), encryption_key))
        timestamp = str(round(time.time()))
        username = str(os.environ.get("ROUTER_EWEB_USERNAME", "admin") or "admin").strip() or "admin"

        # Exact BE72 browser payload.  The Web UI hides the username because the
        # account is implicitly admin; it does not send a username field on wire.
        body = {
            "method": "login",
            "params": {
                "password": encrypted,
                "time": timestamp,
                "encry": True,
                "limit": False,
                "setInit": False,
            },
        }
        base = _configured_base(cfg.get("address", ""))
        try:
            response = self.http.post(
                base + "/cgi-bin/luci/api/auth",
                data=_wire_json(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=(4, 12),
                verify=cfg.get("verifyTls", False),
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            error = RouterRpcError(f"Unable to connect to the router login API: {exc}", "ROUTER_UNREACHABLE", 502)
            self._mark_failure(error)
            raise error from exc

        root = _parse_json(response)
        data = root.get("data") if isinstance(root.get("data"), dict) else {}
        token = str(data.get("token") or "").strip()
        sid = str(data.get("sid") or "").strip()
        serial = str(data.get("sn") or "").strip()
        cookie = _first_set_cookie(response)
        if response.status_code >= 400 or int(root.get("code") or 0) != 0 or not token or not sid:
            self.clear_session()
            error = RouterRpcError(
                f"Router login failed: http={response.status_code} code={root.get('code')}",
                "LOGIN_FAILED",
                401,
            )
            self._mark_failure(error)
            raise error

        _install_cookie(self, cookie, base)
        self._developer_cookie_header = cookie or _cookie_header(self)
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

        # Validate the stored session using the developer-tested overview call.
        validated = False
        for label, credential in _auth_candidates(self, "overview", session):
            check_response, check_root = _raw_api_call(
                self,
                cfg,
                credential,
                self._developer_cookie_header,
                "overview",
                {"method": "getDeviceInfo", "params": None},
            )
            if check_response.status_code < 400 and int(check_root.get("code") or 0) == 0:
                _remember_auth(self, "overview", label)
                validated = True
                break
        if not validated:
            self.clear_session()
            error = RouterAuthExpired("BE72 login succeeded but sid/token session validation failed")
            self._mark_failure(error)
            raise error

        self.login_key = encryption_key
        self.login_variant = "be72-password-http"
        self._mark_success()
        self.logger.info(
            "router eweb BE72 login ok address=%s user=%s sn=%s session=%ss cookie=%s transport=%s",
            cfg.get("address"),
            username,
            serial or "unknown",
            session_seconds,
            bool(self._developer_cookie_header),
            _configured_base(cfg.get("address", "")).split(":", 1)[0],
        )
        return session


def _post_api(self: Any, api_path: str, payload: Dict[str, Any], retry_auth: bool = True) -> Any:
    session = self.login()
    cfg = self.config
    cookie = _cookie_header(self)
    if not cookie:
        error = RouterAuthExpired("BE72 session cookie is missing")
        self._mark_failure(error)
        raise error

    auth_rejected = False
    for label, credential in _auth_candidates(self, api_path, session):
        response, root = _raw_api_call(self, cfg, credential, cookie, api_path, payload)
        if response.status_code in {401, 403}:
            auth_rejected = True
            self.logger.info(
                "router eweb BE72 credential rejected api=%s credential=%s status=%s; trying alternate",
                api_path,
                label,
                response.status_code,
            )
            continue
        if response.status_code >= 400:
            error = RouterRpcError(f"Router returned HTTP {response.status_code}", "RPC_HTTP_ERROR", 502)
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

        _remember_auth(self, api_path, label)
        self._mark_success()
        return root.get("data") if "data" in root else root

    if auth_rejected:
        config_key = self._session_cache_key(cfg)
        with self.login_lock:
            current = self.session
            same_session = current.sid == session.sid and current.obtained_at == session.obtained_at
            if same_session:
                self.clear_session()
                if retry_auth:
                    self.login(force=True)
                else:
                    GLOBAL_ROUTER_SESSION_CACHE.block_login(config_key, AUTH_RETRY_BACKOFF_SECONDS)
        if retry_auth:
            return _post_api(self, api_path, payload, retry_auth=False)
        error = RouterAuthExpired()
        self._mark_failure(error)
        raise error

    error = RouterAuthExpired("BE72 login session has no usable auth credential")
    self._mark_failure(error)
    raise error


def install_router_be72_auth_patch() -> None:
    """Override the generic developer flow with the observed BE72 behavior."""
    client_class = runtime.StableRuijieRouterClient
    if getattr(client_class, "_labprobe_be72_auth_patch", False):
        return
    client_class.login = _login
    client_class._post_api = _post_api
    client_class._labprobe_be72_auth_patch = True
