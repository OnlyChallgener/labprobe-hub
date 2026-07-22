"""Align outer browser-worker waits with the full Playwright login sequence.

The eWeb login routine can legitimately spend time in page navigation, locating the
password field, waiting for the auth response and waiting for the post-login URL.
The original fixed 50-second queue wait could expire while Chromium was still
working, leaving later router requests queued behind a successful-but-abandoned
login. This patch gives login/RPC calls a budget derived from the configured
Playwright timeouts without changing the login protocol itself.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from router_rpc_v010 import RouterBrowserSession


def _bounded_ms(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(str(os.environ.get(name, default)).strip())
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _login_budget_seconds() -> float:
    login_ms = _bounded_ms("ROUTER_BROWSER_LOGIN_TIMEOUT_MS", 25000, 8000, 90000)
    login_s = login_ms / 1000.0
    # goto + password locator + auth response + post-login URL, plus startup margin.
    return max(70.0, min(320.0, login_s * 3.0 + min(login_s, 15.0) + 20.0))


def _rpc_budget_seconds() -> float:
    action_ms = _bounded_ms("ROUTER_BROWSER_ACTION_TIMEOUT_MS", 15000, 5000, 60000)
    # A rejected RPC may perform one forced browser login before retrying once.
    return max(90.0, min(380.0, _login_budget_seconds() + action_ms / 1000.0 + 25.0))


def install_browser_timeout_patch() -> None:
    if getattr(RouterBrowserSession, "_labprobe_timeout_patch", False):
        return

    def login(self: RouterBrowserSession, cfg: Dict[str, Any], force: bool = False) -> Dict[str, Any]:
        return self._submit(
            "login",
            timeout=_login_budget_seconds(),
            cfg=cfg,
            force=force,
        )

    def rpc(
        self: RouterBrowserSession,
        cfg: Dict[str, Any],
        api_path: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        return self._submit(
            "rpc",
            timeout=_rpc_budget_seconds(),
            cfg=cfg,
            api_path=api_path,
            payload=payload,
            headers=headers,
        )

    RouterBrowserSession.login = login
    RouterBrowserSession.rpc = rpc
    RouterBrowserSession._labprobe_timeout_patch = True
