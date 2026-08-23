"""Restricted OpenClaw WeChat control surface.

LabProbe never stores the WeChat bot token. QR login and account persistence stay
inside the Tencent-maintained OpenClaw channel plugin; this module only calls the
local OpenClaw Gateway CLI with a fixed allow-list of arguments.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
from typing import Any, Callable, Dict, Optional

from flask import Blueprint, jsonify, request


PLUGIN_PACKAGE = "@tencent-weixin/openclaw-weixin"
CHANNEL_ID = "openclaw-weixin"
INSTALL_CONFIRMATION = "INSTALL_OPENCLAW_WEIXIN"
LOGIN_ID_PATTERN = re.compile(r"^labprobe-[0-9a-f]{16}$")


class OpenClawCommandError(RuntimeError):
    pass


def _find_json(text: str) -> Dict[str, Any]:
    clean = str(text or "").strip()
    try:
        value = json.loads(clean)
        return value if isinstance(value, dict) else {"value": value}
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    decoder = json.JSONDecoder()
    for index, char in enumerate(clean):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(clean[index:])
        except (ValueError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            return value
    raise OpenClawCommandError("OpenClaw 没有返回可识别的 JSON")


def _payload(value: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("result", "data", "payload"):
        nested = value.get(key)
        if isinstance(nested, dict):
            return nested
    return value


class OpenClawWeChatBridge:
    def __init__(self, logger: Any = None, runner: Optional[Callable[..., subprocess.CompletedProcess]] = None):
        configured = str(os.environ.get("OPENCLAW_CLI_PATH") or "").strip()
        self.cli_path = configured or shutil.which("openclaw") or ""
        self.logger = logger
        self.runner = runner or subprocess.run
        self._sessions: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _run(self, arguments: list[str], timeout: int = 30) -> str:
        if not self.cli_path:
            raise OpenClawCommandError("未检测到 OpenClaw，请先按官方命令安装")
        try:
            result = self.runner(
                [self.cli_path, *arguments],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(3, min(int(timeout), 240)),
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise OpenClawCommandError("OpenClaw 命令执行失败") from exc
        if int(result.returncode or 0) != 0:
            if self.logger:
                self.logger.warning("OpenClaw command failed rc=%s", result.returncode)
            raise OpenClawCommandError("OpenClaw 返回失败，请检查 Gateway 与插件状态")
        return str(result.stdout or "")[:256_000]

    def _json_call(self, arguments: list[str], timeout: int = 30) -> Dict[str, Any]:
        return _payload(_find_json(self._run(arguments, timeout=timeout)))

    def status(self) -> Dict[str, Any]:
        notification_target_configured = bool(str(os.environ.get("WECHAT_NOTIFY_TO") or "").strip())
        if not self.cli_path:
            return {
                "available": False,
                "pluginInstalled": False,
                "connected": False,
                "message": "未检测到 OpenClaw",
                "notificationTargetConfigured": notification_target_configured,
                "installCommand": "npx -y @tencent-weixin/openclaw-weixin-cli install",
            }
        version = self._run(["--version"], timeout=10).strip().splitlines()[-1][:80]
        plugin_installed = False
        connected = False
        message = "OpenClaw 已安装，微信插件待安装"
        try:
            plugins = self._json_call(["plugins", "list", "--json"], timeout=20)
            plugin_text = json.dumps(plugins, ensure_ascii=False).lower()
            plugin_installed = CHANNEL_ID in plugin_text or PLUGIN_PACKAGE.lower() in plugin_text
        except OpenClawCommandError:
            plugin_installed = False
        if plugin_installed:
            message = "微信插件已安装，等待扫码连接"
            try:
                channels = self._json_call(["channels", "status", "--probe", "--json"], timeout=30)
                channel_text = json.dumps(channels, ensure_ascii=False).lower()
                connected = CHANNEL_ID in channel_text and any(
                    marker in channel_text for marker in ('"connected": true', '"running": true', '"configured": true')
                )
                if connected:
                    message = "微信 ClawBot 已连接"
            except OpenClawCommandError:
                pass
        return {
            "available": True,
            "version": version,
            "pluginInstalled": plugin_installed,
            "connected": connected,
            "message": message,
            "notificationTargetConfigured": notification_target_configured,
            "installCommand": "npx -y @tencent-weixin/openclaw-weixin-cli install",
        }

    def send_message(self, target: str, message: str) -> Dict[str, Any]:
        safe_target = str(target or "").strip()
        safe_message = str(message or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9@._:+-]{1,256}", safe_target):
            raise OpenClawCommandError("微信通知目标无效")
        if not safe_message:
            raise OpenClawCommandError("微信通知内容为空")
        result = self._json_call([
            "message", "send", "--channel", CHANNEL_ID,
            "--target", safe_target, "--message", safe_message[:3000], "--json",
        ], timeout=35)
        return {"ok": True, "messageId": str(result.get("messageId") or result.get("id") or "")[:160]}

    def install_plugin(self) -> Dict[str, Any]:
        if not self.cli_path:
            raise OpenClawCommandError("未检测到 OpenClaw，请先在 Gateway 主机安装 OpenClaw")
        self._run(["plugins", "install", PLUGIN_PACKAGE], timeout=180)
        self._run(["config", "set", f"plugins.entries.{CHANNEL_ID}.enabled", "true"], timeout=30)
        self._run(["config", "set", "session.dmScope", "per-account-channel-peer"], timeout=30)
        self._run(["gateway", "restart", "--safe", "--json"], timeout=90)
        return {"ok": True, "message": "微信插件已安装并重启 Gateway"}

    def start_login(self) -> Dict[str, Any]:
        login_id = "labprobe-" + secrets.token_hex(8)
        params = json.dumps({"accountId": login_id, "force": False, "timeoutMs": 30_000}, separators=(",", ":"))
        result = self._json_call(
            ["gateway", "call", "web.login.start", "--params", params, "--timeout", "35000", "--json"],
            timeout=40,
        )
        qr_content = str(result.get("qrDataUrl") or "").strip()
        if not qr_content:
            raise OpenClawCommandError(str(result.get("message") or "未获取到微信二维码"))
        with self._lock:
            self._sessions[login_id] = time.monotonic() + 300
        return {
            "loginId": login_id,
            "qrContent": qr_content,
            "expiresInSeconds": 300,
            "message": "请使用手机微信扫码并确认",
        }

    def wait_login(self, login_id: str) -> Dict[str, Any]:
        safe_id = str(login_id or "").strip()
        if not LOGIN_ID_PATTERN.fullmatch(safe_id):
            raise OpenClawCommandError("登录会话无效")
        with self._lock:
            expires_at = self._sessions.get(safe_id, 0)
        if expires_at < time.monotonic():
            with self._lock:
                self._sessions.pop(safe_id, None)
            raise OpenClawCommandError("二维码已过期，请重新生成")
        params = json.dumps({"accountId": safe_id, "timeoutMs": 25_000}, separators=(",", ":"))
        result = self._json_call(
            ["gateway", "call", "web.login.wait", "--params", params, "--timeout", "30000", "--json"],
            timeout=35,
        )
        connected = bool(result.get("connected"))
        if connected or bool(result.get("alreadyConnected")):
            with self._lock:
                self._sessions.pop(safe_id, None)
        return {
            "connected": connected,
            "alreadyConnected": bool(result.get("alreadyConnected")),
            "message": str(result.get("message") or ("连接成功" if connected else "等待扫码确认"))[:200],
        }


def create_wechat_blueprint(*, check_app_token: Callable[[], bool], logger: Any = None,
                            bridge: Optional[OpenClawWeChatBridge] = None) -> Blueprint:
    bp = Blueprint("assistant_wechat", __name__, url_prefix="/api/ai/wechat")
    control = bridge or OpenClawWeChatBridge(logger=logger)

    def authorized():
        if not check_app_token():
            return jsonify({"error": "unauthorized"}), 401
        return None

    def failure(exc: OpenClawCommandError):
        return jsonify({"error": str(exc)}), 409

    @bp.get("/status")
    def status():
        denial = authorized()
        if denial:
            return denial
        try:
            return jsonify(control.status())
        except OpenClawCommandError as exc:
            return failure(exc)

    @bp.post("/install")
    def install():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        if body.get("confirmation") != INSTALL_CONFIRMATION:
            return jsonify({"error": "需要明确确认安装微信插件"}), 409
        try:
            return jsonify(control.install_plugin())
        except OpenClawCommandError as exc:
            return failure(exc)

    @bp.post("/login/start")
    def login_start():
        denial = authorized()
        if denial:
            return denial
        try:
            return jsonify(control.start_login())
        except OpenClawCommandError as exc:
            return failure(exc)

    @bp.post("/login/wait")
    def login_wait():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        try:
            return jsonify(control.wait_login(str(body.get("loginId") or "")))
        except OpenClawCommandError as exc:
            return failure(exc)

    return bp
