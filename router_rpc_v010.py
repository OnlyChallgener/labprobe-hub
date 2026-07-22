"""Stable Ruijie/Reyee router RPC runtime for LabProbe Hub 0.9.12.

The BE72 eWeb frontend establishes more state than the raw ``api/auth`` call.
This runtime therefore supports a browser-owned session: a single headless
Chromium instance logs in through the real eWeb page and executes RPC requests
inside that authenticated browser context. Direct requests remain available
only when explicitly selected as a compatibility fallback.
"""
from __future__ import annotations

import json
import os
import queue
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import router_rpc_v099 as v099
from flask import Blueprint
from router_rpc import (
    EncryptedRouterConfigStore,
    RouterRpcError,
    RouterSession,
    RuijieRouterClient,
    _safe_int,
)


class RouterBrowserError(RouterRpcError):
    def __init__(
        self,
        message: str,
        code: str = "BROWSER_SESSION_FAILED",
        http_status: int = 502,
    ):
        super().__init__(message, code, http_status)


class RouterBrowserSession:
    """Own Playwright on one dedicated thread.

    Playwright's sync API is thread-affine. Flask requests may arrive on
    different threads, so all browser work is serialized through this worker
    rather than sharing page objects directly between request handlers.
    """

    PASSWORD_SELECTORS = (
        'input[type="password"]',
        'input[autocomplete="current-password"]',
        'input[name="password"]',
        '#password',
        'input[placeholder*="密码"]',
        'input[placeholder*="Password" i]',
    )
    LOGIN_SELECTORS = (
        'button:has-text("登录")',
        'button:has-text("Login")',
        'button[type="submit"]',
        'input[type="submit"]',
        '#login',
        '.login-btn',
        '[class*="login"] button',
    )

    def __init__(self, logger: Any):
        self.logger = logger
        self._commands: "queue.Queue[tuple[str, Dict[str, Any], queue.Queue[Any]]]" = queue.Queue()
        self._thread = threading.Thread(
            target=self._worker,
            name="router-eweb-browser",
            daemon=True,
        )
        self._thread.start()

    def _submit(self, action: str, timeout: float = 50.0, **kwargs: Any) -> Any:
        reply: "queue.Queue[Any]" = queue.Queue(maxsize=1)
        self._commands.put((action, kwargs, reply))
        try:
            ok, value = reply.get(timeout=timeout)
        except queue.Empty as exc:
            raise RouterBrowserError(
                f"Router browser {action} timed out",
                "BROWSER_TIMEOUT",
                504,
            ) from exc
        if ok:
            return value
        if isinstance(value, Exception):
            raise value
        raise RouterBrowserError(str(value))

    def login(self, cfg: Dict[str, Any], force: bool = False) -> Dict[str, Any]:
        return self._submit("login", cfg=cfg, force=force)

    def rpc(
        self,
        cfg: Dict[str, Any],
        api_path: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        return self._submit(
            "rpc",
            cfg=cfg,
            api_path=api_path,
            payload=payload,
            headers=headers,
        )

    def reset(self) -> None:
        try:
            self._submit("reset", timeout=10.0)
        except Exception:
            pass

    @staticmethod
    def _token_from_url(url: str) -> str:
        match = re.search(r";stok=([A-Za-z0-9]+)", url or "", re.I)
        if match:
            return match.group(1)
        match = re.search(r"[?&]auth=([^&#\s]+)", url or "", re.I)
        return match.group(1) if match else ""

    @staticmethod
    def _visible_locator(page: Any, selectors: tuple[str, ...], timeout_ms: int) -> Any:
        deadline = time.monotonic() + max(1.0, timeout_ms / 1000.0)
        while time.monotonic() < deadline:
            for frame in page.frames:
                for selector in selectors:
                    try:
                        locator = frame.locator(selector).first
                        if locator.count() and locator.is_visible(timeout=200):
                            return locator
                    except Exception:
                        continue
            page.wait_for_timeout(150)
        raise RouterBrowserError(
            "Router eWeb login form was not found",
            "BROWSER_LOGIN_FORM_NOT_FOUND",
            502,
        )

    def _worker(self) -> None:
        playwright = None
        browser = None
        context = None
        page = None
        token = ""
        sid = ""
        serial = ""
        obtained_at = 0.0
        session_seconds = 3600
        current_address = ""

        def close_context() -> None:
            nonlocal context, page, token, sid, serial, obtained_at, current_address
            try:
                if context is not None:
                    context.close()
            except Exception:
                pass
            context = None
            page = None
            token = ""
            sid = ""
            serial = ""
            obtained_at = 0.0
            current_address = ""

        def ensure_browser() -> Any:
            nonlocal playwright, browser
            if browser is not None:
                return browser
            try:
                from playwright.sync_api import sync_playwright
            except Exception as exc:
                raise RouterBrowserError(
                    "Playwright is not installed in the Hub image",
                    "BROWSER_UNAVAILABLE",
                    503,
                ) from exc
            try:
                playwright = sync_playwright().start()
                browser = playwright.chromium.launch(
                    headless=str(os.environ.get("ROUTER_BROWSER_HEADLESS", "true")).lower() != "false",
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-background-networking",
                    ],
                )
                return browser
            except Exception as exc:
                raise RouterBrowserError(
                    f"Chromium could not start: {exc}",
                    "BROWSER_UNAVAILABLE",
                    503,
                ) from exc

        def install_context(cfg: Dict[str, Any]) -> None:
            nonlocal context, page
            close_context()
            launched = ensure_browser()
            try:
                context = launched.new_context(
                    ignore_https_errors=not bool(cfg.get("verifyTls", False)),
                    viewport={"width": 1365, "height": 768},
                    locale="zh-CN",
                )
                page = context.new_page()
                page.set_default_timeout(
                    _safe_int(
                        os.environ.get("ROUTER_BROWSER_ACTION_TIMEOUT_MS"),
                        15000,
                        5000,
                        60000,
                    )
                )
            except Exception as exc:
                close_context()
                raise RouterBrowserError(
                    f"Router browser context could not start: {exc}",
                    "BROWSER_UNAVAILABLE",
                    503,
                ) from exc

        def browser_snapshot() -> Dict[str, Any]:
            cookies: List[Dict[str, Any]] = context.cookies() if context is not None else []
            return {
                "token": token,
                "sid": sid,
                "serialNumber": serial,
                "obtainedAt": obtained_at,
                "sessionSeconds": session_seconds,
                "url": page.url if page is not None and not page.is_closed() else "",
                "cookies": cookies,
            }

        def do_login(cfg: Dict[str, Any], force: bool = False) -> Dict[str, Any]:
            nonlocal token, sid, serial, obtained_at, session_seconds, current_address, page
            address = str(cfg.get("address") or "").rstrip("/")
            password = str(cfg.get("password") or "")
            if not address or not password:
                raise RouterBrowserError(
                    "Router management address and password are required",
                    "ROUTER_NOT_CONFIGURED",
                    409,
                )
            session_seconds = _safe_int(cfg.get("sessionSeconds"), 3600, 600, 7200)
            locally_valid = (
                not force
                and page is not None
                and not page.is_closed()
                and current_address == address
                and bool(token)
                and time.time() - obtained_at < max(60, session_seconds - 300)
            )
            if locally_valid:
                return browser_snapshot()

            install_context(cfg)
            login_url = f"{address}/cgi-bin/luci/?stamp={int(time.time())}"
            timeout_ms = _safe_int(
                os.environ.get("ROUTER_BROWSER_LOGIN_TIMEOUT_MS"),
                25000,
                8000,
                90000,
            )
            try:
                page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
                password_field = self._visible_locator(page, self.PASSWORD_SELECTORS, timeout_ms)
                password_field.fill(password)

                def is_auth_response(response: Any) -> bool:
                    return (
                        "/cgi-bin/luci/api/auth" in response.url
                        and response.request.method.upper() == "POST"
                    )

                with page.expect_response(is_auth_response, timeout=timeout_ms) as pending:
                    try:
                        button = self._visible_locator(page, self.LOGIN_SELECTORS, 2500)
                        button.click()
                    except RouterBrowserError:
                        password_field.press("Enter")
                auth_response = pending.value
                auth_root = auth_response.json()
                auth_data = auth_root.get("data") if isinstance(auth_root, dict) else None
                auth_data = auth_data if isinstance(auth_data, dict) else {}
                auth_code = 0
                if isinstance(auth_root, dict):
                    try:
                        auth_code = int(auth_root.get("code") or 0)
                    except (TypeError, ValueError):
                        auth_code = -1
                if auth_response.status >= 400 or auth_code != 0:
                    message = ""
                    if isinstance(auth_root, dict):
                        message = str(auth_root.get("error") or auth_root.get("message") or "")
                    raise RouterBrowserError(
                        message or f"Router eWeb login returned HTTP {auth_response.status}",
                        "BROWSER_LOGIN_FAILED",
                        401,
                    )

                token = str(
                    auth_data.get("token")
                    or auth_data.get("auth")
                    or auth_data.get("stok")
                    or ""
                ).strip()
                sid = str(auth_data.get("sid") or "").strip()
                serial = str(
                    auth_data.get("sn")
                    or auth_data.get("serialNumber")
                    or ""
                ).strip()

                try:
                    page.wait_for_url(
                        re.compile(r".*(;stok=|home_overview).*"),
                        timeout=min(timeout_ms, 15000),
                    )
                except Exception:
                    page.wait_for_timeout(1200)

                token = token or self._token_from_url(page.url)
                cookies = context.cookies()
                cookie_map = {str(row.get("name")): str(row.get("value")) for row in cookies}
                serial = serial or cookie_map.get("SN", "")
                if serial:
                    sid = sid or cookie_map.get(serial, "")
                if not token:
                    raise RouterBrowserError(
                        "Router login succeeded but no eWeb token was returned",
                        "BROWSER_TOKEN_MISSING",
                        502,
                    )

                current_address = address
                obtained_at = time.time()
                self.logger.info(
                    "router eweb browser login ok address=%s sn=%s session=%ss",
                    address,
                    serial or "unknown",
                    session_seconds,
                )
                return browser_snapshot()
            except RouterRpcError:
                close_context()
                raise
            except Exception as exc:
                close_context()
                raise RouterBrowserError(
                    f"Router browser login failed: {exc}",
                    "BROWSER_LOGIN_FAILED",
                    401,
                ) from exc

        def do_rpc(
            cfg: Dict[str, Any],
            api_path: str,
            payload: Dict[str, Any],
            headers: Dict[str, str],
            retry_auth: bool = True,
        ) -> Dict[str, Any]:
            nonlocal page
            snapshot = do_login(cfg, force=False)
            address = str(cfg.get("address") or "").rstrip("/")
            request_url = f"{address}/cgi-bin/luci/api/{api_path}?auth={snapshot['token']}"
            safe_url = f"{address}/cgi-bin/luci/api/{api_path}?auth=<redacted>"
            browser_headers = {
                key: value
                for key, value in headers.items()
                if key.lower() not in {
                    "cookie",
                    "referer",
                    "host",
                    "content-length",
                    "origin",
                    "user-agent",
                }
            }
            browser_headers.setdefault("Content-Type", "application/json")
            browser_headers.setdefault("Accept", "application/json, text/plain, */*")
            browser_headers.setdefault("X-Requested-With", "XMLHttpRequest")
            try:
                result = page.evaluate(
                    """async ({url, payload, headers}) => {
                        const response = await fetch(url, {
                            method: "POST",
                            credentials: "include",
                            cache: "no-store",
                            headers,
                            body: JSON.stringify(payload)
                        });
                        return {
                            status: response.status,
                            redirected: response.redirected,
                            finalUrl: response.url,
                            text: await response.text()
                        };
                    }""",
                    {
                        "url": request_url,
                        "payload": payload,
                        "headers": browser_headers,
                    },
                )
            except Exception as exc:
                if retry_auth:
                    do_login(cfg, force=True)
                    return do_rpc(cfg, api_path, payload, headers, retry_auth=False)
                raise RouterBrowserError(
                    f"Router browser RPC failed: {exc}",
                    "BROWSER_RPC_FAILED",
                    502,
                ) from exc

            status = int(result.get("status") or 0)
            text = str(result.get("text") or "")
            looks_like_login = (
                "<html" in text.lower()
                and ("api/auth" in text.lower() or 'type="password"' in text.lower())
            )
            if status in {401, 403} or looks_like_login:
                self.logger.warning(
                    "router eweb browser rpc auth rejected api=%s status=%s url=%s",
                    api_path,
                    status,
                    safe_url,
                )
                if retry_auth:
                    do_login(cfg, force=True)
                    return do_rpc(cfg, api_path, payload, headers, retry_auth=False)
                raise RouterBrowserError(
                    "Router browser session was rejected after one re-login",
                    "AUTH_EXPIRED",
                    401,
                )
            if status >= 400:
                raise RouterBrowserError(
                    f"Router returned HTTP {status}",
                    "RPC_HTTP_ERROR",
                    502,
                )
            return {
                "status": status,
                "text": text,
                "finalUrl": str(result.get("finalUrl") or ""),
                "redirected": bool(result.get("redirected")),
                "session": browser_snapshot(),
            }

        while True:
            action, kwargs, reply = self._commands.get()
            try:
                if action == "login":
                    value = do_login(kwargs["cfg"], bool(kwargs.get("force")))
                elif action == "rpc":
                    value = do_rpc(
                        kwargs["cfg"],
                        str(kwargs["api_path"]),
                        kwargs["payload"],
                        kwargs["headers"],
                    )
                elif action == "reset":
                    close_context()
                    value = True
                else:
                    raise RouterBrowserError(f"Unknown browser action: {action}")
                reply.put((True, value))
            except Exception as exc:
                reply.put((False, exc))


class StableRuijieRouterClient(v099.ReliableRuijieRouterClient):
    """0.9.12 client with optional real-browser eWeb authentication."""

    CONNECTION_ERROR_CODES = {
        "AUTH_EXPIRED",
        "LOGIN_FAILED",
        "ROUTER_UNREACHABLE",
        "RPC_TIMEOUT",
        "RPC_HTTP_ERROR",
        "RPC_INVALID_RESPONSE",
        "RPC_PATH_NOT_FOUND",
        "BROWSER_SESSION_FAILED",
        "BROWSER_TIMEOUT",
        "BROWSER_UNAVAILABLE",
        "BROWSER_LOGIN_FORM_NOT_FOUND",
        "BROWSER_LOGIN_FAILED",
        "BROWSER_TOKEN_MISSING",
        "BROWSER_RPC_FAILED",
    }

    def __init__(self, store: EncryptedRouterConfigStore, logger: Any):
        super().__init__(store, logger)
        self.http.headers["User-Agent"] = "LabProbe-Hub/0.9.12"
        mode = str(os.environ.get("ROUTER_BROWSER_AUTH_MODE", "off")).strip().lower()
        self.browser_auth_mode = mode if mode in {"off", "preferred", "required"} else "required"
        self.browser_session = RouterBrowserSession(logger) if self.browser_auth_mode != "off" else None

    def _install_browser_cookies(self, snapshot: Dict[str, Any]) -> None:
        self.http.cookies.clear()
        for row in snapshot.get("cookies") or []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "")
            value = str(row.get("value") or "")
            if not name:
                continue
            kwargs: Dict[str, Any] = {"path": str(row.get("path") or "/")}
            domain = str(row.get("domain") or "").lstrip(".")
            if domain:
                kwargs["domain"] = domain
            try:
                self.http.cookies.set(name, value, **kwargs)
            except Exception:
                self.http.cookies.set(name, value)

    def _browser_login(self, force: bool = False) -> RouterSession:
        if self.browser_session is None:
            raise RouterBrowserError("Router browser authentication is disabled", "BROWSER_UNAVAILABLE", 503)
        cfg = self.config
        snapshot = self.browser_session.login(cfg, force=force)
        self._install_browser_cookies(snapshot)
        session = RouterSession(
            sid=str(snapshot.get("sid") or ""),
            auth_token=str(snapshot.get("token") or ""),
            serial_number=str(snapshot.get("serialNumber") or ""),
            obtained_at=float(snapshot.get("obtainedAt") or time.time()),
            session_seconds=_safe_int(
                snapshot.get("sessionSeconds"),
                cfg.get("sessionSeconds", 3600),
                600,
                7200,
            ),
        )
        self.session = session
        self._save_session_cookies(cfg)
        self._mark_success()
        return session

    def login(self, force: bool = False) -> RouterSession:
        if self.browser_auth_mode == "off":
            return super().login(force=force)
        try:
            return self._browser_login(force=force)
        except Exception as exc:
            self._mark_failure(exc)
            if self.browser_auth_mode == "preferred":
                self.logger.warning("router browser login failed, falling back to direct auth: %s", exc)
                return super().login(force=force)
            raise

    def clear_session(self) -> None:
        if getattr(self, "browser_session", None) is not None:
            self.browser_session.reset()
        super().clear_session()

    def _post_api(self, api_path: str, payload: Dict[str, Any], retry_auth: bool = True) -> Any:
        if self.browser_auth_mode == "off":
            return super()._post_api(api_path, payload, retry_auth=retry_auth)
        try:
            session = self.login()
            headers = RuijieRouterClient._headers_for(self, payload, session)
            result = self.browser_session.rpc(
                self.config,
                api_path,
                payload,
                headers,
            )
            root = json.loads(str(result.get("text") or ""))
            if isinstance(root, dict) and root.get("error"):
                message = root["error"].get("message") if isinstance(root["error"], dict) else str(root["error"])
                error = RouterRpcError(message or "Router rejected the RPC operation", "RPC_REJECTED", 409)
                self._mark_failure(error)
                raise error
            self._mark_success()
            return root.get("data") if isinstance(root, dict) and "data" in root else root
        except RouterRpcError as exc:
            self._mark_failure(exc)
            if self.browser_auth_mode == "preferred":
                self.logger.warning("router browser RPC failed, falling back to direct auth: %s", exc)
                return super()._post_api(api_path, payload, retry_auth=retry_auth)
            raise
        except (TypeError, ValueError) as exc:
            error = RouterRpcError("Router returned an invalid browser RPC response", "RPC_INVALID_RESPONSE", 502)
            self._mark_failure(error)
            raise error from exc

    def _set_session_time(self, seconds: int) -> None:
        """Track lifetime locally; browser login owns the actual eWeb session."""
        seconds = _safe_int(seconds, 3600, 600, 7200)
        session = self.session
        session.session_seconds = seconds
        session.obtained_at = time.time()
        self.session = session
        self.logger.debug("router browser session lifetime tracked locally: %ss", seconds)

    def logout(self) -> None:
        if self.browser_session is not None:
            self.browser_session.reset()
        super().clear_session()

    def status(self, probe: bool = False) -> Dict[str, Any]:
        cfg = self.config
        configured = bool(cfg.get("address") and cfg.get("password"))
        if probe and configured:
            try:
                self.rpc("acConfig.get", "network_group", no_parse=True)
            except Exception:
                pass

        now = time.time()
        remaining = 0
        if self.session.auth_token:
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
                "authMode": "browser" if self.browser_auth_mode != "off" else "direct",
            }


def create_router_blueprint_v010(
    check_app_token: Callable[[], bool],
    logger: Any,
    config_dir: Path,
) -> Blueprint:
    """Reuse the 0.9.9 whitelist routes with the 0.9.12 stable client."""
    original_client = v099.ReliableRuijieRouterClient
    v099.ReliableRuijieRouterClient = StableRuijieRouterClient
    try:
        return v099.create_router_blueprint_v099(check_app_token, logger, config_dir)
    finally:
        v099.ReliableRuijieRouterClient = original_client
