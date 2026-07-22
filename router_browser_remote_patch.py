"""Use the dedicated router-browser sidecar for Reyee eWeb sessions.

The Hub stays lightweight and talks to a separate Firefox/WebDriver service over
HTTP.  The sidecar owns the real browser page, dynamic eWeb token, cookies and
same-origin RPC calls.  This module preserves the RouterBrowserSession contract
used by router_rpc_v010 without importing Playwright in the Hub image.
"""
from __future__ import annotations

import os
from typing import Any, Dict

import requests

import router_rpc_v010 as runtime


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(str(os.environ.get(name, default)).strip())
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


class RemoteRouterBrowserSession:
    """Router browser session implemented by the router-browser sidecar."""

    def __init__(self, logger: Any):
        self.logger = logger
        self.base_url = str(
            os.environ.get("ROUTER_BROWSER_REMOTE_URL", "http://127.0.0.1:4445")
        ).rstrip("/")
        self.token = str(os.environ.get("ROUTER_BROWSER_TOKEN", "")).strip()
        self.http = requests.Session()
        self.http.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "LabProbe-Hub/0.9.12 router-browser-client",
            }
        )

    def _timeout(self, rpc: bool = False) -> tuple[float, float]:
        login_ms = _bounded_int(
            "ROUTER_BROWSER_LOGIN_TIMEOUT_MS", 30000, 8000, 120000
        )
        action_ms = _bounded_int(
            "ROUTER_BROWSER_ACTION_TIMEOUT_MS", 15000, 5000, 90000
        )
        read_seconds = (
            login_ms * 2 + action_ms + 20000 if rpc else login_ms * 2 + 20000
        ) / 1000.0
        return (5.0, max(30.0, min(300.0, read_seconds)))

    def _post(
        self,
        path: str,
        payload: Dict[str, Any],
        *,
        rpc: bool = False,
        allow_unavailable: bool = False,
    ) -> Dict[str, Any]:
        headers: Dict[str, str] = {}
        if self.token:
            headers["X-Router-Browser-Token"] = self.token
        try:
            response = self.http.post(
                f"{self.base_url}{path}",
                json=payload,
                headers=headers,
                timeout=self._timeout(rpc=rpc),
            )
        except requests.RequestException as exc:
            if allow_unavailable:
                return {}
            raise runtime.RouterBrowserError(
                f"Router browser service is unavailable: {exc}",
                "BROWSER_UNAVAILABLE",
                503,
            ) from exc

        try:
            root = response.json()
        except ValueError as exc:
            if allow_unavailable:
                return {}
            raise runtime.RouterBrowserError(
                f"Router browser service returned HTTP {response.status_code} with invalid JSON",
                "BROWSER_SESSION_FAILED",
                502,
            ) from exc

        if response.status_code >= 400 or not isinstance(root, dict) or not root.get("ok"):
            error = root.get("error") if isinstance(root, dict) else None
            if isinstance(error, dict):
                message = str(error.get("message") or "Router browser request failed")
                code = str(error.get("code") or "BROWSER_SESSION_FAILED")
                status = int(error.get("httpStatus") or response.status_code or 502)
            else:
                message = str(error or "Router browser request failed")
                code = "BROWSER_SESSION_FAILED"
                status = response.status_code or 502
            raise runtime.RouterBrowserError(message, code, status)

        data = root.get("data")
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _config_payload(cfg: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "address": str(cfg.get("address") or "").rstrip("/"),
            "password": str(cfg.get("password") or ""),
            "sessionSeconds": int(cfg.get("sessionSeconds") or 3600),
            "verifyTls": bool(cfg.get("verifyTls", False)),
        }

    def login(self, cfg: Dict[str, Any], force: bool = False) -> Dict[str, Any]:
        payload = self._config_payload(cfg)
        payload["force"] = bool(force)
        snapshot = self._post("/v1/login", payload)
        self.logger.debug(
            "router browser sidecar login complete address=%s force=%s",
            payload.get("address"),
            force,
        )
        return snapshot

    def rpc(
        self,
        cfg: Dict[str, Any],
        api_path: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        body = self._config_payload(cfg)
        body.update(
            {
                "apiPath": str(api_path),
                "payload": payload,
                "headers": headers,
            }
        )
        return self._post("/v1/rpc", body, rpc=True)

    def reset(self) -> None:
        self._post("/v1/reset", {}, allow_unavailable=True)


def install_browser_remote_patch() -> None:
    if getattr(runtime, "_labprobe_remote_browser_patch", False):
        return
    runtime.RouterBrowserSession = RemoteRouterBrowserSession
    runtime._labprobe_remote_browser_patch = True
