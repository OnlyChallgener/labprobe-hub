"""Stable Ruijie/Reyee router RPC runtime for LabProbe Hub 0.9.10.

This compatibility layer fixes the eWeb login loop seen on firmware that rejects
setSessionTime immediately after authentication. Session duration is tracked by
Hub locally; a real RPC is still used to verify the login, and HTTP 401/403 is
handled by the existing automatic re-login path.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, Dict

import router_rpc_v099 as v099
from flask import Blueprint
from router_rpc import EncryptedRouterConfigStore, _safe_int


class StableRuijieRouterClient(v099.ReliableRuijieRouterClient):
    """0.9.10 client with non-destructive session timeout tracking."""

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
        self.http.headers["User-Agent"] = "LabProbe-Hub/0.9.10"

    def _set_session_time(self, seconds: int) -> None:
        """Track the requested lifetime locally without invalidating a new SID.

        Some ReyeeOS builds return 401 for common/setSessionTime even though the
        newly issued SID is valid for cmd RPC calls. The old implementation
        cleared that SID, producing an endless login -> setSessionTime -> 401
        loop. Hub keepalive and automatic 401/403 re-login make a remote timeout
        write unnecessary.
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
                self.rpc("devSta.get", "ws_sysinfo", {"get": "fast"})
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
    """Reuse the 0.9.9 whitelist routes with the 0.9.10 stable client."""
    original_client = v099.ReliableRuijieRouterClient
    v099.ReliableRuijieRouterClient = StableRuijieRouterClient
    try:
        return v099.create_router_blueprint_v099(check_app_token, logger, config_dir)
    finally:
        v099.ReliableRuijieRouterClient = original_client
