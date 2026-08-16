"""Stable direct Reyee/Ruijie eWeb authentication for LabProbe Hub 0.9.12.

The router login page publishes a per-page GibberishAES key.  Hub fetches that
page, encrypts the management password with the extracted key, logs in through
``/cgi-bin/luci/api/auth``, and keeps the returned sid and cookies in memory.
Business API calls use ``?auth=<sid>`` and reuse the same requests.Session.
Only a real 401/403, login-page redirect, or local session expiry triggers one
serialized re-login.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import requests
from flask import Blueprint

import router_rpc_v099 as v099
from router_rpc import (
    AUTH_RETRY_BACKOFF_SECONDS,
    EncryptedRouterConfigStore,
    GLOBAL_ROUTER_SESSION_CACHE,
    RouterAuthExpired,
    RouterNotConfigured,
    RouterRpcError,
    RouterSession,
    _safe_int,
    _wire_json,
    gibberish_aes_encrypt,
)


class StableRuijieRouterClient(v099.ReliableRuijieRouterClient):
    """Direct HTTP client using the router's dynamic AES key and sid cookie session."""

    CONNECTION_ERROR_CODES = {
        "AUTH_EXPIRED",
        "LOGIN_FAILED",
        "ROUTER_UNREACHABLE",
        "RPC_TIMEOUT",
        "RPC_HTTP_ERROR",
        "RPC_INVALID_RESPONSE",
        "RPC_PATH_NOT_FOUND",
        "LOGIN_KEY_NOT_FOUND",
    }

    _KEY_PATTERNS: Tuple[re.Pattern[str], ...] = (
        re.compile(
            r"GibberishAES\s*\.\s*enc\s*\(\s*[^,]+,\s*['\"]([A-Fa-f0-9]{16,128})['\"]\s*\)",
            re.I,
        ),
        re.compile(
            r"(?:encrypt(?:ion)?Key|aesKey|loginKey)\s*[:=]\s*['\"]([A-Fa-f0-9]{16,128})['\"]",
            re.I,
        ),
    )

    def __init__(self, store: EncryptedRouterConfigStore, logger: Any):
        super().__init__(store, logger)
        self.http.headers["User-Agent"] = "LabProbe-Hub/0.9.12"
        self.login_key = ""
        self.login_variant = ""

    @classmethod
    def _extract_login_key(cls, html: str) -> str:
        for pattern in cls._KEY_PATTERNS:
            match = pattern.search(html or "")
            if match:
                return match.group(1).strip()
        return ""

    def _fetch_login_key(self, cfg: Dict[str, Any]) -> str:
        configured = str(os.environ.get("ROUTER_EWEB_AES_KEY", "")).strip()
        if configured:
            return configured
        try:
            response = self.http.get(
                cfg["address"] + "/cgi-bin/luci/",
                timeout=(4, 12),
                verify=cfg["verifyTls"],
                allow_redirects=True,
                headers={"Accept": "text/html,application/xhtml+xml"},
            )
        except requests.RequestException as exc:
            raise RouterRpcError(
                f"Unable to fetch the router login page: {exc}",
                "ROUTER_UNREACHABLE",
                502,
            ) from exc
        if response.status_code >= 400:
            raise RouterRpcError(
                f"Router login page returned HTTP {response.status_code}",
                "RPC_HTTP_ERROR",
                502,
            )
        key = self._extract_login_key(response.text)
        if not key:
            raise RouterRpcError(
                "The dynamic eWeb encryption key was not found in the login page",
                "LOGIN_KEY_NOT_FOUND",
                502,
            )
        return key

    @staticmethod
    def _login_payloads(password: str, encryption_key: str) -> Iterable[Tuple[str, Dict[str, Any]]]:
        encrypted = re.sub(r"\s+", "", gibberish_aes_encrypt(password, encryption_key))
        timestamp = str(int(time.time()))

        # BE72/ReyeeOS payload observed in the user's browser capture.
        yield (
            "password",
            {
                "method": "login",
                "params": {
                    "password": encrypted,
                    "time": timestamp,
                    "encry": True,
                    "limit": False,
                    "setInit": False,
                },
            },
        )

        # Alternate eWeb payload supplied and successfully tested by the router developer.
        yield (
            "pwd",
            {
                "method": "login",
                "params": {
                    "username": "admin",
                    "time": timestamp,
                    "encry": True,
                    "pwd": encrypted,
                    "isCheckReadAgreement": "true",
                },
            },
        )

    @staticmethod
    def _parse_auth_response(response: requests.Response) -> Tuple[Dict[str, Any], int]:
        try:
            root = response.json()
        except ValueError:
            return {}, -1
        if not isinstance(root, dict):
            return {}, -1
        data = root.get("data") if isinstance(root.get("data"), dict) else {}
        try:
            code = int(root.get("code") or 0)
        except (TypeError, ValueError):
            code = -1
        return data, code

    def login(self, force: bool = False) -> RouterSession:
        with self.login_lock:
            cfg = self.config
            config_key = self._session_cache_key(cfg)
            retry_after = GLOBAL_ROUTER_SESSION_CACHE.retry_after(config_key)
            if not force and retry_after > 0:
                error = RouterAuthExpired(f"Router auth retry paused for {retry_after}s")
                self._mark_failure(error)
                raise error

            cached = GLOBAL_ROUTER_SESSION_CACHE.restore(config_key, self.http)
            if not force and cached.valid_locally and cached.sid:
                return cached
            if not cfg.get("address") or not cfg.get("password"):
                error = RouterNotConfigured()
                self._mark_failure(error)
                raise error

            last_message = ""
            for variant_index in range(2):
                # Fetch a fresh page/key for each payload attempt. This also establishes
                # any initial cookies expected by the selected firmware generation.
                self.http.cookies.clear()
                encryption_key = self._fetch_login_key(cfg)
                payloads = list(self._login_payloads(str(cfg["password"]), encryption_key))
                variant_name, body = payloads[variant_index]
                try:
                    response = self.http.post(
                        cfg["address"] + "/cgi-bin/luci/api/auth",
                        data=_wire_json(body).encode("utf-8"),
                        timeout=(4, 12),
                        verify=cfg["verifyTls"],
                        allow_redirects=False,
                    )
                except requests.RequestException as exc:
                    error = RouterRpcError(
                        f"Unable to connect to the router: {exc}",
                        "ROUTER_UNREACHABLE",
                        502,
                    )
                    self._mark_failure(error)
                    raise error from exc

                auth_data, auth_code = self._parse_auth_response(response)
                sid = str(auth_data.get("sid") or "").strip()
                token = str(
                    auth_data.get("token")
                    or auth_data.get("auth_token")
                    or auth_data.get("auth")
                    or ""
                ).strip()
                serial = str(auth_data.get("sn") or auth_data.get("serialNumber") or "").strip()

                cookie_map = {cookie.name: cookie.value for cookie in self.http.cookies}
                serial = serial or str(cookie_map.get("SN") or "").strip()
                if serial:
                    sid = sid or str(cookie_map.get(serial) or "").strip()

                if response.status_code < 400 and auth_code == 0 and sid:
                    session_seconds = _safe_int(
                        auth_data.get("sessiontime") or auth_data.get("sessionTime"),
                        cfg["sessionSeconds"],
                        600,
                        7200,
                    )
                    session = RouterSession(
                        sid=sid,
                        auth_token=token or sid,
                        serial_number=serial,
                        obtained_at=time.time(),
                        session_seconds=session_seconds,
                    )
                    self.session = session
                    self._save_session_cookies(cfg)
                    self.login_key = encryption_key
                    self.login_variant = variant_name
                    self._mark_success()
                    self.logger.info(
                        "router eweb login ok address=%s sn=%s session=%ss variant=%s auth=sid cookie_names=%s",
                        cfg["address"],
                        serial or "unknown",
                        session_seconds,
                        variant_name,
                        sorted(cookie_map),
                    )
                    return session

                last_message = (
                    f"variant={variant_name} http={response.status_code} code={auth_code} "
                    f"sid={bool(sid)} token={bool(token)}"
                )
                self.logger.warning("router eweb login attempt rejected %s", last_message)

            self.clear_session()
            error = RouterRpcError(
                f"Router login failed; check the management password ({last_message})",
                "LOGIN_FAILED",
                401,
            )
            self._mark_failure(error)
            raise error

    def _post_api(self, api_path: str, payload: Dict[str, Any], retry_auth: bool = True) -> Any:
        session = self.login()
        cfg = self.config
        sid = str(session.sid or "").strip()
        if not sid:
            error = RouterAuthExpired("Router login returned no sid")
            self._mark_failure(error)
            raise error

        wire = _wire_json(payload)
        url = cfg["address"] + f"/cgi-bin/luci/api/{api_path}?auth={sid}"
        safe_url = cfg["address"] + f"/cgi-bin/luci/api/{api_path}?auth=<sid-redacted>"
        self.logger.debug(
            "router eweb rpc request api=%s sid=%s cookie_names=%s url=%s",
            api_path,
            bool(sid),
            sorted({cookie.name for cookie in self.http.cookies}),
            safe_url,
        )
        try:
            response = self.http.post(
                url,
                data=wire.encode("utf-8"),
                headers=self._headers_for(payload, session),
                timeout=(4, 15),
                verify=cfg["verifyTls"],
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            error = RouterRpcError("Router RPC timed out", "RPC_TIMEOUT", 504)
            self._mark_failure(error)
            raise error from exc
        except requests.RequestException as exc:
            error = RouterRpcError(f"Router RPC request failed: {exc}", "ROUTER_UNREACHABLE", 502)
            self._mark_failure(error)
            raise error from exc

        redirect_to_login = response.status_code in {301, 302, 303, 307, 308} and "luci" in str(
            response.headers.get("Location") or ""
        ).lower()
        login_page = self._looks_like_login_page(response.text)
        if response.status_code in {401, 403} or redirect_to_login or login_page:
            self.logger.warning(
                "router eweb rpc auth rejected api=%s status=%s redirect=%s cookie_names=%s sid=%s",
                api_path,
                response.status_code,
                redirect_to_login,
                sorted({cookie.name for cookie in self.http.cookies}),
                bool(sid),
            )
            config_key = self._session_cache_key(cfg)
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
                return self._post_api(api_path, payload, retry_auth=False)
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

        try:
            root = response.json()
        except ValueError as exc:
            error = RouterRpcError(
                "Router returned an invalid RPC response",
                "RPC_INVALID_RESPONSE",
                502,
            )
            self._mark_failure(error)
            raise error from exc

        if isinstance(root, dict) and root.get("error"):
            message = root["error"].get("message") if isinstance(root["error"], dict) else str(root["error"])
            error = RouterRpcError(message or "Router rejected the RPC operation", "RPC_REJECTED", 409)
            self._mark_failure(error)
            raise error
        if isinstance(root, dict):
            try:
                code = int(root.get("code") or 0)
            except (TypeError, ValueError):
                code = -1
            if code != 0:
                error = RouterRpcError(
                    str(root.get("error") or root.get("message") or f"Router RPC code {code}"),
                    "RPC_REJECTED",
                    409,
                )
                self._mark_failure(error)
                raise error

        self._mark_success()
        return root.get("data") if isinstance(root, dict) and "data" in root else root

    def _set_session_time(self, seconds: int) -> None:
        """Keep the requested session lifetime locally; no extra login-time RPC."""
        seconds = _safe_int(seconds, 3600, 600, 7200)
        session = self.session
        if session.sid:
            session.session_seconds = seconds
            session.obtained_at = time.time()
            self.session = session

    def logout(self) -> None:
        self.clear_session()

    def status(self, probe: bool = False) -> Dict[str, Any]:
        cfg = self.config
        configured = bool(cfg.get("address") and cfg.get("password"))
        if probe and configured:
            try:
                self._post_api("overview", {"method": "getDeviceInfo", "params": None})
            except Exception:
                pass
        now = time.time()
        remaining = 0
        if self.session.sid:
            remaining = max(0, int(self.session.session_seconds - (now - self.session.obtained_at)))
        with self._status_lock:
            connection_error = self.last_error_code in self.CONNECTION_ERROR_CODES
            connected = bool(configured and self.session.valid_locally and self.session.sid and not connection_error)
            recovering = bool(configured and not connected and self.last_error_code in {"", "AUTH_EXPIRED"})
            state = "connected" if connected else ("recovering" if recovering else ("error" if configured else "unconfigured"))
            return {
                "configured": configured,
                "connected": connected,
                "recovering": recovering,
                "connectionState": state,
                "sessionActive": bool(self.session.sid and self.session.valid_locally),
                "sessionRemainingSeconds": remaining,
                "lastSuccessAt": int(self.last_success_at),
                "lastError": self.last_error if connection_error else "",
                "lastErrorCode": self.last_error_code if connection_error else "",
                "lastOperationError": self.last_error if self.last_error and not connection_error else "",
                "statusText": "已连接" if connected else ("正在恢复" if recovering else ("连接异常" if configured else "未配置")),
                "serialNumber": self.session.serial_number,
                "authMode": "direct-sid-cookie",
                "loginVariant": self.login_variant,
            }


def create_router_blueprint_v010(
    check_app_token: Callable[[], bool],
    logger: Any,
    config_dir: Path,
) -> Blueprint:
    """Reuse the complete 0.9.9 product whitelist with the 0.9.12 sid client."""
    original_client = v099.ReliableRuijieRouterClient
    v099.ReliableRuijieRouterClient = StableRuijieRouterClient
    try:
        return v099.create_router_blueprint_v099(check_app_token, logger, config_dir)
    finally:
        v099.ReliableRuijieRouterClient = original_client
