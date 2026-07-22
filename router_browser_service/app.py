"""Dedicated Firefox/WebDriver service for Reyee eWeb login and RPC.

The service deliberately owns one browser session and serializes all operations.
It enters the router through the root address, follows the router-generated
``/cgi-bin/luci/?stamp=...`` redirect, captures the real ``/api/auth`` response,
and performs later RPC calls inside the same authenticated page context.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import quote

from flask import Flask, jsonify, request
from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.ui import WebDriverWait


APP_VERSION = "0.1.0"
PORT = int(os.environ.get("PORT", "4445"))
HEADLESS = str(os.environ.get("ROUTER_BROWSER_HEADLESS", "true")).lower() != "false"
API_TOKEN = str(os.environ.get("ROUTER_BROWSER_TOKEN", "")).strip()
LOGS_DIR = Path(os.environ.get("LOGS_DIR", "/app/logs"))
LOGS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=getattr(logging, str(os.environ.get("LOG_LEVEL", "INFO")).upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
LOGGER = logging.getLogger("router-browser")
app = Flask(__name__)


class BrowserServiceError(RuntimeError):
    def __init__(self, message: str, code: str = "BROWSER_SESSION_FAILED", http_status: int = 502):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def _int_value(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(maximum, number))


def _authorized() -> bool:
    if not API_TOKEN:
        return True
    supplied = str(request.headers.get("X-Router-Browser-Token", "")).strip()
    return bool(supplied) and supplied == API_TOKEN


def _visible(element: WebElement) -> bool:
    try:
        return element.is_displayed() and element.is_enabled()
    except WebDriverException:
        return False


def _metadata(element: WebElement) -> str:
    values = []
    for attribute in (
        "type",
        "name",
        "id",
        "class",
        "placeholder",
        "autocomplete",
        "aria-label",
        "value",
    ):
        try:
            value = element.get_attribute(attribute)
        except WebDriverException:
            value = None
        if value:
            values.append(str(value))
    try:
        text = element.text
    except WebDriverException:
        text = ""
    if text:
        values.append(text)
    return " ".join(values).strip().lower()


def _safe_headers(headers: Any) -> Dict[str, str]:
    blocked = {
        "cookie",
        "referer",
        "host",
        "content-length",
        "origin",
        "user-agent",
        "connection",
    }
    result: Dict[str, str] = {}
    if isinstance(headers, dict):
        for key, value in headers.items():
            name = str(key)
            if name.lower() in blocked:
                continue
            result[name] = str(value)
    result.setdefault("Content-Type", "application/json")
    result.setdefault("Accept", "application/json, text/plain, */*")
    result.setdefault("X-Requested-With", "XMLHttpRequest")
    return result


class RouterBrowserManager:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.driver: Optional[webdriver.Firefox] = None
        self.address = ""
        self.password_fingerprint = ""
        self.token = ""
        self.sid = ""
        self.serial = ""
        self.obtained_at = 0.0
        self.session_seconds = 3600

    def _start_driver(self, timeout_seconds: int) -> webdriver.Firefox:
        if self.driver is not None:
            return self.driver
        options = Options()
        if HEADLESS:
            options.add_argument("-headless")
        options.set_preference("browser.cache.disk.enable", False)
        options.set_preference("browser.cache.memory.enable", False)
        options.set_preference("browser.shell.checkDefaultBrowser", False)
        options.set_preference("datareporting.policy.dataSubmissionEnabled", False)
        options.set_preference("toolkit.telemetry.enabled", False)
        options.set_preference("network.http.speculative-parallel-limit", 0)
        options.set_preference("network.prefetch-next", False)
        try:
            driver = webdriver.Firefox(options=options)
            driver.set_page_load_timeout(timeout_seconds)
            driver.set_script_timeout(timeout_seconds)
            driver.set_window_size(1365, 768)
            self.driver = driver
            LOGGER.info("router browser Firefox started headless=%s", HEADLESS)
            return driver
        except Exception as exc:
            raise BrowserServiceError(
                f"Firefox could not start: {exc}",
                "BROWSER_UNAVAILABLE",
                503,
            ) from exc

    def _close_driver(self) -> None:
        driver, self.driver = self.driver, None
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
        self.address = ""
        self.password_fingerprint = ""
        self.token = ""
        self.sid = ""
        self.serial = ""
        self.obtained_at = 0.0

    @staticmethod
    def _fingerprint(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _snapshot(self) -> Dict[str, Any]:
        cookies = []
        current_url = ""
        if self.driver is not None:
            try:
                cookies = self.driver.get_cookies()
            except Exception:
                cookies = []
            try:
                current_url = self.driver.current_url
            except Exception:
                current_url = ""
        return {
            "token": self.token,
            "sid": self.sid,
            "serialNumber": self.serial,
            "obtainedAt": self.obtained_at,
            "sessionSeconds": self.session_seconds,
            "url": current_url,
            "cookies": cookies,
        }

    def _locally_valid(self, address: str, password: str) -> bool:
        return bool(
            self.driver is not None
            and self.address == address
            and self.password_fingerprint == self._fingerprint(password)
            and self.token
            and time.time() - self.obtained_at < max(60, self.session_seconds - 300)
        )

    def _diagnostic(self, reason: str) -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        prefix = LOGS_DIR / f"router-browser-login-{stamp}"
        png_path = prefix.with_suffix(".png")
        json_path = prefix.with_suffix(".json")
        snapshot: Dict[str, Any] = {
            "reason": reason,
            "url": "",
            "title": "",
            "inputs": [],
            "controls": [],
        }
        driver = self.driver
        if driver is not None:
            try:
                snapshot["url"] = driver.current_url
            except Exception:
                pass
            try:
                snapshot["title"] = driver.title
            except Exception:
                pass
            try:
                snapshot.update(
                    driver.execute_script(
                        """return {
                            bodyText: (document.body?.innerText || '').slice(0, 1500),
                            inputs: Array.from(document.querySelectorAll('input')).slice(0, 50).map(el => ({
                                type: el.type || '', name: el.name || '', id: el.id || '',
                                className: String(el.className || ''), placeholder: el.placeholder || '',
                                autocomplete: el.autocomplete || '', ariaLabel: el.getAttribute('aria-label') || '',
                                valueLength: String(el.value || '').length,
                                visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                            })),
                            controls: Array.from(document.querySelectorAll('button,[role=button],input[type=submit],input[type=button]'))
                                .slice(0, 80).map(el => ({
                                    tag: el.tagName, id: el.id || '', className: String(el.className || ''),
                                    text: String(el.innerText || el.value || '').slice(0, 180),
                                    visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                                }))
                        };"""
                    )
                    or {}
                )
            except Exception as exc:
                snapshot["diagnosticError"] = str(exc)
            try:
                driver.save_screenshot(str(png_path))
                snapshot["screenshot"] = str(png_path)
            except Exception as exc:
                snapshot["screenshotError"] = str(exc)
        try:
            json_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        LOGGER.warning(
            "router eweb diagnostic reason=%s url=%s file=%s",
            reason,
            snapshot.get("url") or "unknown",
            json_path,
        )
        return str(json_path)

    @staticmethod
    def _find_password(driver: webdriver.Firefox, timeout_seconds: int) -> WebElement:
        deadline = time.monotonic() + timeout_seconds
        selectors: Iterable[str] = (
            'input[type="password"]',
            'input[autocomplete="current-password"]',
            'input[name="password"]',
            '#password',
            'input[placeholder*="管理员密码"]',
            'input[placeholder*="密码"]',
            'input[placeholder*="Password" i]',
            '.el-input__inner',
        )
        while time.monotonic() < deadline:
            for selector in selectors:
                try:
                    for element in driver.find_elements(By.CSS_SELECTOR, selector):
                        if _visible(element):
                            return element
                except WebDriverException:
                    continue
            candidates = []
            try:
                inputs = driver.find_elements(
                    By.CSS_SELECTOR,
                    'input:not([type="hidden"]):not([disabled])',
                )
            except WebDriverException:
                inputs = []
            visible_inputs = []
            for element in inputs[:50]:
                if not _visible(element):
                    continue
                visible_inputs.append(element)
                metadata = _metadata(element)
                element_type = str(element.get_attribute("type") or "text").lower()
                score = 0
                if element_type == "password":
                    score += 120
                if "current-password" in metadata:
                    score += 100
                if any(word in metadata for word in ("管理员密码", "密码", "password", "passwd", "pwd")):
                    score += 90
                if "el-input__inner" in metadata:
                    score += 25
                if element_type in {"", "text", "password"}:
                    score += 5
                candidates.append((score, element))
            if candidates:
                candidates.sort(key=lambda row: row[0], reverse=True)
                if candidates[0][0] >= 25:
                    return candidates[0][1]
            if len(visible_inputs) == 1:
                return visible_inputs[0]
            time.sleep(0.2)
        raise BrowserServiceError(
            "Router eWeb login form was not found",
            "BROWSER_LOGIN_FORM_NOT_FOUND",
            502,
        )

    @staticmethod
    def _find_login_control(driver: webdriver.Firefox, timeout_seconds: int) -> Optional[WebElement]:
        deadline = time.monotonic() + timeout_seconds
        selectors = (
            'button[type="submit"]',
            'input[type="submit"]',
            'button',
            '[role="button"]',
            '.el-button',
            '#login',
            '.login-btn',
            '[class*="login"]',
            '[class*="submit"]',
        )
        while time.monotonic() < deadline:
            scored = []
            seen = set()
            for selector in selectors:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, selector)
                except WebDriverException:
                    continue
                for element in elements[:80]:
                    key = getattr(element, "id", None)
                    if key in seen or not _visible(element):
                        continue
                    seen.add(key)
                    metadata = _metadata(element)
                    score = 0
                    if any(word in metadata for word in ("登录", "login", "sign in", "进入")):
                        score += 120
                    if "submit" in metadata:
                        score += 35
                    if "login" in metadata:
                        score += 35
                    if score:
                        scored.append((score, element))
            if scored:
                scored.sort(key=lambda row: row[0], reverse=True)
                return scored[0][1]
            time.sleep(0.2)
        return None

    @staticmethod
    def _install_auth_capture(driver: webdriver.Firefox) -> None:
        driver.execute_script(
            """(() => {
                window.__labprobeAuthResponse = null;
                if (window.fetch && !window.__labprobeFetchWrapped) {
                    window.__labprobeFetchWrapped = true;
                    const originalFetch = window.fetch.bind(window);
                    window.fetch = async (...args) => {
                        const response = await originalFetch(...args);
                        try {
                            const rawUrl = typeof args[0] === 'string' ? args[0] : (args[0]?.url || '');
                            const url = new URL(rawUrl, location.href).href;
                            if (url.includes('/cgi-bin/luci/api/auth')) {
                                const clone = response.clone();
                                clone.text().then(text => {
                                    window.__labprobeAuthResponse = {url, status: response.status, text};
                                });
                            }
                        } catch (_) {}
                        return response;
                    };
                }
                if (!window.__labprobeXhrWrapped) {
                    window.__labprobeXhrWrapped = true;
                    const originalOpen = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
                        this.__labprobeUrl = new URL(url, location.href).href;
                        return originalOpen.call(this, method, url, ...rest);
                    };
                    const originalSend = XMLHttpRequest.prototype.send;
                    XMLHttpRequest.prototype.send = function(...args) {
                        this.addEventListener('load', () => {
                            try {
                                if ((this.__labprobeUrl || '').includes('/cgi-bin/luci/api/auth')) {
                                    window.__labprobeAuthResponse = {
                                        url: this.__labprobeUrl,
                                        status: this.status,
                                        text: this.responseText || ''
                                    };
                                }
                            } catch (_) {}
                        });
                        return originalSend.apply(this, args);
                    };
                }
            })();"""
        )

    @staticmethod
    def _token_from_url(url: str) -> str:
        match = re.search(r";stok=([A-Za-z0-9]+)", url or "", re.I)
        if match:
            return match.group(1)
        match = re.search(r"[?&]auth=([^&#\s]+)", url or "", re.I)
        return match.group(1) if match else ""

    @staticmethod
    def _storage_tokens(driver: webdriver.Firefox) -> Dict[str, str]:
        try:
            data = driver.execute_script(
                """const read = storage => {
                    const out = {};
                    for (let i = 0; i < storage.length; i++) {
                        const key = storage.key(i);
                        out[key] = storage.getItem(key);
                    }
                    return out;
                };
                return {local: read(localStorage), session: read(sessionStorage)};"""
            )
        except Exception:
            return {}
        output: Dict[str, str] = {}
        if isinstance(data, dict):
            for group in data.values():
                if not isinstance(group, dict):
                    continue
                for key, value in group.items():
                    name = str(key).lower()
                    text = str(value or "")
                    if any(word in name for word in ("token", "auth", "stok", "sid", "sn")):
                        output[name] = text
        return output

    def login(self, cfg: Dict[str, Any], force: bool = False) -> Dict[str, Any]:
        with self.lock:
            address = str(cfg.get("address") or "").rstrip("/")
            password = str(cfg.get("password") or "")
            if not address or not password:
                raise BrowserServiceError(
                    "Router management address and password are required",
                    "ROUTER_NOT_CONFIGURED",
                    409,
                )
            self.session_seconds = _int_value(cfg.get("sessionSeconds"), 3600, 600, 7200)
            if not force and self._locally_valid(address, password):
                return self._snapshot()

            timeout_ms = _int_value(
                os.environ.get("ROUTER_BROWSER_LOGIN_TIMEOUT_MS", 30000),
                30000,
                8000,
                120000,
            )
            timeout_seconds = max(8, int(timeout_ms / 1000))
            if force:
                self._close_driver()
            driver = self._start_driver(timeout_seconds)
            try:
                # Enter through the root URL. The router itself generates the dynamic
                # /cgi-bin/luci/?stamp=... redirect and any initial session state.
                driver.get(address)
                WebDriverWait(driver, timeout_seconds).until(
                    lambda current: (
                        "/cgi-bin/luci" in (current.current_url or "")
                        or current.execute_script("return document.readyState") in {"interactive", "complete"}
                    )
                )
                WebDriverWait(driver, timeout_seconds).until(
                    lambda current: current.execute_script("return document.readyState") == "complete"
                )
                time.sleep(0.8)
                self._install_auth_capture(driver)
                password_field = self._find_password(driver, timeout_seconds)
                password_field.click()
                password_field.clear()
                password_field.send_keys(password)

                control = self._find_login_control(driver, min(timeout_seconds, 8))
                if control is not None:
                    control.click()
                else:
                    password_field.send_keys(Keys.ENTER)

                WebDriverWait(driver, timeout_seconds).until(
                    lambda current: bool(
                        current.execute_script("return window.__labprobeAuthResponse || null")
                        or ";stok=" in (current.current_url or "")
                        or "home_overview" in (current.current_url or "")
                    )
                )
                time.sleep(0.5)
                captured = driver.execute_script("return window.__labprobeAuthResponse || null")
                auth_root: Dict[str, Any] = {}
                auth_status = 0
                if isinstance(captured, dict):
                    auth_status = int(captured.get("status") or 0)
                    try:
                        parsed = json.loads(str(captured.get("text") or ""))
                        auth_root = parsed if isinstance(parsed, dict) else {}
                    except ValueError:
                        auth_root = {}
                auth_data = auth_root.get("data") if isinstance(auth_root.get("data"), dict) else {}
                code = auth_root.get("code") if auth_root else 0
                try:
                    code_value = int(code or 0)
                except (TypeError, ValueError):
                    code_value = -1
                if auth_status >= 400 or code_value != 0:
                    message = str(auth_root.get("error") or auth_root.get("message") or "")
                    raise BrowserServiceError(
                        message or f"Router eWeb login returned HTTP {auth_status}",
                        "BROWSER_LOGIN_FAILED",
                        401,
                    )

                self.token = str(
                    auth_data.get("token")
                    or auth_data.get("auth")
                    or auth_data.get("stok")
                    or self._token_from_url(driver.current_url)
                    or ""
                ).strip()
                self.sid = str(auth_data.get("sid") or "").strip()
                self.serial = str(
                    auth_data.get("sn") or auth_data.get("serialNumber") or ""
                ).strip()
                storage = self._storage_tokens(driver)
                if not self.token:
                    for key, value in storage.items():
                        if any(word in key for word in ("token", "auth", "stok")) and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", value):
                            self.token = value
                            break
                cookies = driver.get_cookies()
                cookie_map = {str(row.get("name")): str(row.get("value")) for row in cookies}
                self.serial = self.serial or cookie_map.get("SN", "")
                if self.serial:
                    self.sid = self.sid or cookie_map.get(self.serial, "")
                if not self.token:
                    debug_path = self._diagnostic("login succeeded but token was not captured")
                    raise BrowserServiceError(
                        f"Router login succeeded but no eWeb token was returned; diagnostic saved to {debug_path}",
                        "BROWSER_TOKEN_MISSING",
                        502,
                    )

                self.address = address
                self.password_fingerprint = self._fingerprint(password)
                self.obtained_at = time.time()
                LOGGER.info(
                    "router eweb browser login ok address=%s url=%s sn=%s session=%ss",
                    address,
                    driver.current_url,
                    self.serial or "unknown",
                    self.session_seconds,
                )
                return self._snapshot()
            except BrowserServiceError as exc:
                if exc.code == "BROWSER_LOGIN_FORM_NOT_FOUND":
                    debug_path = self._diagnostic(str(exc))
                    self._close_driver()
                    raise BrowserServiceError(
                        f"Router eWeb login form was not found; diagnostic saved to {debug_path}",
                        exc.code,
                        exc.http_status,
                    ) from exc
                self._close_driver()
                raise
            except Exception as exc:
                debug_path = self._diagnostic(str(exc))
                self._close_driver()
                raise BrowserServiceError(
                    f"Router browser login failed: {exc}; diagnostic saved to {debug_path}",
                    "BROWSER_LOGIN_FAILED",
                    401,
                ) from exc

    def rpc(
        self,
        cfg: Dict[str, Any],
        api_path: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
        retry_auth: bool = True,
    ) -> Dict[str, Any]:
        with self.lock:
            snapshot = self.login(cfg, force=False)
            driver = self.driver
            if driver is None:
                raise BrowserServiceError("Firefox session is unavailable", "BROWSER_UNAVAILABLE", 503)
            address = str(cfg.get("address") or "").rstrip("/")
            api_path = str(api_path or "cmd").strip("/")
            request_url = f"{address}/cgi-bin/luci/api/{quote(api_path)}?auth={quote(str(snapshot.get('token') or ''))}"
            action_ms = _int_value(
                os.environ.get("ROUTER_BROWSER_ACTION_TIMEOUT_MS", 15000),
                15000,
                5000,
                90000,
            )
            driver.set_script_timeout(max(5, int(action_ms / 1000)))
            try:
                result = driver.execute_async_script(
                    """const url = arguments[0];
                    const payload = arguments[1];
                    const headers = arguments[2];
                    const done = arguments[arguments.length - 1];
                    fetch(url, {
                        method: 'POST', credentials: 'include', cache: 'no-store',
                        headers, body: JSON.stringify(payload)
                    }).then(async response => done({
                        status: response.status,
                        redirected: response.redirected,
                        finalUrl: response.url,
                        text: await response.text()
                    })).catch(error => done({error: String(error)}));""",
                    request_url,
                    payload,
                    _safe_headers(headers),
                )
            except Exception as exc:
                if retry_auth:
                    self.login(cfg, force=True)
                    return self.rpc(cfg, api_path, payload, headers, retry_auth=False)
                raise BrowserServiceError(
                    f"Router browser RPC failed: {exc}",
                    "BROWSER_RPC_FAILED",
                    502,
                ) from exc
            if not isinstance(result, dict):
                raise BrowserServiceError(
                    "Router browser RPC returned an invalid result",
                    "RPC_INVALID_RESPONSE",
                    502,
                )
            if result.get("error"):
                if retry_auth:
                    self.login(cfg, force=True)
                    return self.rpc(cfg, api_path, payload, headers, retry_auth=False)
                raise BrowserServiceError(
                    f"Router browser RPC failed: {result.get('error')}",
                    "BROWSER_RPC_FAILED",
                    502,
                )
            status = int(result.get("status") or 0)
            text = str(result.get("text") or "")
            looks_like_login = "<html" in text.lower() and (
                "api/auth" in text.lower() or "管理员密码" in text or 'type="password"' in text.lower()
            )
            if status in {401, 403} or looks_like_login:
                LOGGER.warning("router eweb rpc auth rejected api=%s status=%s", api_path, status)
                if retry_auth:
                    self.login(cfg, force=True)
                    return self.rpc(cfg, api_path, payload, headers, retry_auth=False)
                raise BrowserServiceError(
                    "Router browser session was rejected after one re-login",
                    "AUTH_EXPIRED",
                    401,
                )
            if status >= 400:
                raise BrowserServiceError(
                    f"Router returned HTTP {status}",
                    "RPC_HTTP_ERROR",
                    502,
                )
            result["session"] = self._snapshot()
            return result

    def reset(self) -> None:
        with self.lock:
            self._close_driver()
            LOGGER.info("router browser session reset")


MANAGER = RouterBrowserManager()


@app.before_request
def check_token() -> Any:
    if request.path == "/health":
        return None
    if not _authorized():
        return jsonify(
            {
                "ok": False,
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "Router browser API authentication failed",
                    "httpStatus": 401,
                },
            }
        ), 401
    return None


@app.get("/health")
def health() -> Any:
    return jsonify(
        {
            "ok": True,
            "version": APP_VERSION,
            "browserRunning": MANAGER.driver is not None,
            "sessionActive": bool(MANAGER.token),
        }
    )


@app.post("/v1/login")
def login_endpoint() -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        data = MANAGER.login(payload, force=bool(payload.get("force")))
        return jsonify({"ok": True, "data": data})
    except BrowserServiceError as exc:
        LOGGER.warning("router browser login failed code=%s message=%s", exc.code, exc)
        return jsonify(
            {
                "ok": False,
                "error": {
                    "code": exc.code,
                    "message": str(exc),
                    "httpStatus": exc.http_status,
                },
            }
        ), exc.http_status


@app.post("/v1/rpc")
def rpc_endpoint() -> Any:
    body = request.get_json(silent=True) or {}
    try:
        data = MANAGER.rpc(
            body,
            str(body.get("apiPath") or "cmd"),
            body.get("payload") if isinstance(body.get("payload"), dict) else {},
            body.get("headers") if isinstance(body.get("headers"), dict) else {},
        )
        return jsonify({"ok": True, "data": data})
    except BrowserServiceError as exc:
        LOGGER.warning("router browser rpc failed code=%s message=%s", exc.code, exc)
        return jsonify(
            {
                "ok": False,
                "error": {
                    "code": exc.code,
                    "message": str(exc),
                    "httpStatus": exc.http_status,
                },
            }
        ), exc.http_status


@app.post("/v1/reset")
def reset_endpoint() -> Any:
    MANAGER.reset()
    return jsonify({"ok": True, "data": {"reset": True}})


if __name__ == "__main__":
    app.run(host=os.environ.get("BIND_HOST", "0.0.0.0"), port=PORT, threaded=True)
