"""Stable Ruijie/Reyee router RPC runtime for LabProbe Hub 0.9.11.

This compatibility layer fixes two firmware-specific eWeb session problems:

* some builds reject ``common/setSessionTime`` immediately after login;
* the browser stores ``SN=<serial>`` and ``<serial>=<sid>`` cookies under
  ``/cgi-bin/luci`` before issuing authenticated RPC requests.

Hub tracks the requested lifetime locally, recreates the browser cookies after
login, and keeps the existing automatic 401/403 re-login path.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import router_rpc_v099 as v099
from flask import Blueprint
from router_rpc import EncryptedRouterConfigStore, RouterSession, _safe_int


class StableRuijieRouterClient(v099.ReliableRuijieRouterClient):
    """0.9.11 client with browser-compatible session persistence."""

    CONNECTION_ERROR_CODES = {
        "AUTH_EXPIRED",
        "LOGIN_FAILED",
        "ROUTER_UNREACHABLE",
        "RPC_TIMEOUT",
        "RPC_HTTP_ERROR",
        "RPC_INVALID_RESPONSE",
        "RPC_PATH_NOT_FOUND",
    }

    def __init__(self, store: EncryptedRouterConfigStore, logger: Any):
        super().__init__(store, logger)
        self.http.headers["User-Agent"] = "LabProbe-Hub/0.9.11"

    def _install_browser_session_cookies(self, session: RouterSession) -> None:
        """Mirror the cookies written by the Reyee eWeb JavaScript client.

        The bundled eWeb frontend performs the equivalent of::

            Cookie.set("SN", serial)
            Cookie.set(serial, sid, {path: "/cgi-bin/luci"})

        The RPC URL must use ``auth=<token>`` from the login response, while
        the cookies still carry the serial-number SID pair.
        """
        serial = (session.serial_number or "").strip()
        sid = (session.sid or "").strip()
        if not serial or not sid:
            return
        cookie_path = "/cgi-bin/luci"
        self.http.cookies.set("SN", serial, path=cookie_path)
        self.http.cookies.set(serial, sid, path=cookie_path)

    def _headers_for(self, payload: Dict[str, Any], session: Optional[RouterSession] = None) -> Dict[str, str]:
        headers = super()._headers_for(payload, session)
        session = session or self.session
        serial = (session.serial_number or "").strip()
        sid = (session.sid or "").strip()
        cookies = {cookie.name: cookie.value for cookie in self.http.cookies}
        if serial and sid:
            cookies["SN"] = serial
            cookies[serial] = sid
        if cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
        if session.stok:
            headers["Referer"] = f"{self.config['address']}/cgi-bin/luci/;stok={session.stok}/"
        else:
            headers["Referer"] = f"{self.config['address']}/cgi-bin/luci/"
        return headers

    def login(self, force: bool = False) -> RouterSession:
        session = super().login(force=force)
        # Reinstall on every access so a cookie-jar clear or replacement cannot
        # leave a locally valid SID without the browser cookies required by RPC.
        self._install_browser_session_cookies(session)
        return session

    def _set_session_time(self, seconds: int) -> None:
        """Track the requested lifetime locally without invalidating a new SID.

        Some ReyeeOS builds return 401 for common/setSessionTime even though the
        newly issued SID is valid for cmd RPC calls. Hub keepalive and automatic
        401/403 re-login make a remote timeout write unnecessary.
        """
        seconds = _safe_int(seconds, 3600, 600, 7200)
        self.session.session_seconds = seconds
        self.session.obtained_at = time.time()
        self.logger.debug("router session lifetime tracked locally: %ss", seconds)

    def status(self, probe: bool = False) -> Dict[str, Any]:
        cfg = self.config
        configured = bool(cfg.get("address") and cfg.get("password"))
        if probe and configured:
            try:
                self.rpc("acConfig.get", "network_group", no_parse=True)
            except Exception:
                # The precise error is already retained by _mark_failure().
                pass

        now = time.time()
        remaining = 0
        if self.session.sid:
            remaining = max(0, int(self.session.session_seconds - (now - self.session.obtained_at)))

        with self._status_lock:
            connection_error = self.last_error_code in self.CONNECTION_ERROR_CODES
            connected = bool(configured and self.session.valid_locally and not connection_error)
            recovering = bool(configured and not connected and self.last_error_code in {"", "AUTH_EXPIRED"})
            connection_state = "connected" if connected else ("recovering" if recovering else ("error" if configured else "unconfigured"))
            connection_message = self.last_error if connection_error else ""
            operation_message = self.last_error if self.last_error and not connection_error else ""
            return {
                "configured": configured,
                "connected": connected,
                "recovering": recovering,
                "connectionState": connection_state,
                "sessionActive": self.session.valid_locally,
                "sessionRemainingSeconds": remaining,
                "lastSuccessAt": int(self.last_success_at),
                "lastError": connection_message,
                "lastErrorCode": self.last_error_code if connection_error else "",
                "lastOperationError": operation_message,
                "statusText": "已连接" if connected else ("正在恢复" if recovering else ("连接异常" if configured else "未配置")),
                "serialNumber": self.session.serial_number,
            }


def create_router_blueprint_v010(
    check_app_token: Callable[[], bool],
    logger: Any,
    config_dir: Path,
) -> Blueprint:
    """Reuse the 0.9.9 whitelist routes with the 0.9.11 stable client."""
    original_client = v099.ReliableRuijieRouterClient
    v099.ReliableRuijieRouterClient = StableRuijieRouterClient
    try:
        return v099.create_router_blueprint_v099(check_app_token, logger, config_dir)
    finally:
        v099.ReliableRuijieRouterClient = original_client
