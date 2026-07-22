"""Harden Reyee eWeb login control discovery and preserve safe diagnostics.

Some BE72 firmware builds render the password field as a generic Element-UI input
instead of a literal ``input[type=password]``.  The browser login runtime must also
allow delayed Vue rendering and nested frames.  This patch replaces only the
browser-session class used by the v0.9.12 runtime; router RPC and APP/Hub auth
contracts remain unchanged.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Iterable, Optional

import router_rpc_v010 as runtime


def _visible(locator: Any) -> bool:
    try:
        return bool(locator.count()) and locator.is_visible(timeout=200)
    except Exception:
        return False


def _text(locator: Any) -> str:
    parts = []
    for attr in ("type", "name", "id", "class", "placeholder", "autocomplete", "aria-label", "value"):
        try:
            value = locator.get_attribute(attr)
        except Exception:
            value = None
        if value:
            parts.append(str(value))
    try:
        value = locator.inner_text(timeout=200)
    except Exception:
        value = ""
    if value:
        parts.append(value)
    return " ".join(parts).strip().lower()


def _best_password_input(frame: Any) -> Optional[Any]:
    try:
        inputs = frame.locator('input:not([type="hidden"]):not([disabled])')
        count = min(inputs.count(), 40)
    except Exception:
        return None

    visible_inputs = []
    scored = []
    for index in range(count):
        locator = inputs.nth(index)
        if not _visible(locator):
            continue
        visible_inputs.append(locator)
        metadata = _text(locator)
        try:
            input_type = (locator.get_attribute("type") or "text").lower()
        except Exception:
            input_type = "text"
        score = 0
        if input_type == "password":
            score += 120
        if "current-password" in metadata:
            score += 100
        if any(word in metadata for word in ("password", "passwd", "pwd", "密码", "管理密码")):
            score += 80
        if "el-input__inner" in metadata:
            score += 20
        if input_type in {"", "text", "password"}:
            score += 5
        scored.append((score, locator))

    if scored:
        scored.sort(key=lambda row: row[0], reverse=True)
        if scored[0][0] >= 25:
            return scored[0][1]
    # BE72 login has only one editable field. Some builds mask it with CSS while
    # leaving type=text, so a single visible input is a safe final fallback.
    return visible_inputs[0] if len(visible_inputs) == 1 else None


def _best_login_control(frame: Any) -> Optional[Any]:
    selectors: Iterable[str] = (
        'button',
        '[role="button"]',
        'input[type="submit"]',
        'input[type="button"]',
        '.el-button',
        '[class*="login"]',
        '[class*="submit"]',
        '[class*="btn"]',
    )
    candidates = []
    for selector in selectors:
        try:
            group = frame.locator(selector)
            count = min(group.count(), 60)
        except Exception:
            continue
        for index in range(count):
            locator = group.nth(index)
            if not _visible(locator):
                continue
            metadata = _text(locator)
            score = 0
            if any(word in metadata for word in ("登录", "login", "sign in", "进入", "确定")):
                score += 100
            if "submit" in metadata:
                score += 30
            if "login" in metadata:
                score += 30
            if score:
                candidates.append((score, locator))
    if not candidates:
        return None
    candidates.sort(key=lambda row: row[0], reverse=True)
    return candidates[0][1]


def _write_debug(page: Any, logger: Any, reason: str) -> str:
    logs_dir = Path(os.environ.get("LOGS_DIR", "/app/logs")).resolve()
    logs_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    prefix = logs_dir / f"router-browser-login-{stamp}"
    screenshot_path = str(prefix.with_suffix(".png"))
    json_path = str(prefix.with_suffix(".json"))

    snapshot = {"reason": reason, "url": "", "title": "", "frames": []}
    try:
        snapshot["url"] = page.url
    except Exception:
        pass
    try:
        snapshot["title"] = page.title()
    except Exception:
        pass
    try:
        for frame in page.frames:
            info = frame.evaluate(
                """() => ({
                    url: location.href,
                    readyState: document.readyState,
                    bodyText: (document.body?.innerText || '').slice(0, 1200),
                    inputs: Array.from(document.querySelectorAll('input')).slice(0, 40).map(el => ({
                        type: el.type || '', name: el.name || '', id: el.id || '',
                        className: String(el.className || ''), placeholder: el.placeholder || '',
                        autocomplete: el.autocomplete || '', ariaLabel: el.getAttribute('aria-label') || '',
                        valueLength: String(el.value || '').length,
                        visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                    })),
                    controls: Array.from(document.querySelectorAll('button,[role=button],input[type=submit],input[type=button]'))
                        .slice(0, 60).map(el => ({
                            tag: el.tagName, id: el.id || '', className: String(el.className || ''),
                            text: String(el.innerText || el.value || '').slice(0, 160),
                            visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                        }))
                })"""
            )
            snapshot["frames"].append(info)
    except Exception as exc:
        snapshot["diagnosticError"] = str(exc)
    try:
        page.screenshot(path=screenshot_path, full_page=True)
        snapshot["screenshot"] = screenshot_path
    except Exception as exc:
        snapshot["screenshotError"] = str(exc)
    try:
        Path(json_path).write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass
    logger.warning(
        "router eweb login controls not found url=%s title=%s debug=%s",
        snapshot.get("url") or "unknown",
        snapshot.get("title") or "unknown",
        json_path,
    )
    return json_path


def install_browser_locator_patch(logger: Any) -> None:
    base = runtime.RouterBrowserSession
    if getattr(base, "_labprobe_locator_patch", False):
        return

    class PatchedRouterBrowserSession(base):
        _labprobe_locator_patch = True

        def _visible_locator(self, page: Any, selectors: tuple[str, ...], timeout_ms: int) -> Any:
            is_password = tuple(selectors) == tuple(self.PASSWORD_SELECTORS)
            is_login = tuple(selectors) == tuple(self.LOGIN_SELECTORS)
            deadline = time.monotonic() + max(1.0, timeout_ms / 1000.0)
            last_generic = None

            while time.monotonic() < deadline:
                for frame in page.frames:
                    for selector in selectors:
                        try:
                            locator = frame.locator(selector).first
                            if _visible(locator):
                                return locator
                        except Exception:
                            continue

                    if is_password:
                        candidate = _best_password_input(frame)
                        if candidate is not None:
                            last_generic = candidate
                            # Let Vue finish replacing its initial placeholder DOM.
                            if time.monotonic() + 1.0 < deadline:
                                page.wait_for_timeout(250)
                            if _visible(candidate):
                                return candidate
                    elif is_login:
                        candidate = _best_login_control(frame)
                        if candidate is not None:
                            return candidate

                page.wait_for_timeout(180)

            if last_generic is not None and _visible(last_generic):
                return last_generic
            debug_path = _write_debug(
                page,
                logger,
                "password control missing" if is_password else "login control missing",
            )
            raise runtime.RouterBrowserError(
                f"Router eWeb login form was not found; diagnostic saved to {debug_path}",
                "BROWSER_LOGIN_FORM_NOT_FOUND",
                502,
            )

    runtime.RouterBrowserSession = PatchedRouterBrowserSession
