"""Hub 0.9.32 final stability corrections.

- Freeze elapsed time when NAT/diagnostic/Beta tasks reach a terminal state.
- Expose an asynchronous Agent update-check endpoint that always returns quickly.
- Keep HTTP 502/HTML gateway bodies out of APP-facing messages.
"""
from __future__ import annotations

import threading
import time
from types import MethodType
from typing import Any, Dict

from flask import jsonify, request


TERMINAL_TASK_STATES = {"succeeded", "failed", "timed_out", "cancelled"}


def _friendly_update_error(value: Any) -> str:
    text = str(value or "").strip()
    lower = text.lower()
    if "502" in lower or "<!doctype" in lower or "<html" in lower:
        return "更新源暂时不可用（网关 502），Hub 已保留上次版本信息"
    if "timeout" in lower or "timed out" in lower or "read timed out" in lower:
        return "更新源响应超时，Hub 将继续在后台重试"
    if "404" in lower:
        return "更新清单不存在，请检查 HTTPS 更新仓配置"
    if "ssl" in lower or "certificate" in lower:
        return "HTTPS 更新源证书校验失败，请检查证书或系统时间"
    return f"更新检查失败：{text[:120]}" if text else "更新检查失败，已保留上次版本信息"


def _freeze_router_task_timing(hub: Any) -> None:
    manager = getattr(hub, "ROUTER_TASK_MANAGER", None)
    if manager is None or getattr(manager, "_final_timing_patched", False):
        return

    def snapshot_locked(self: Any, kind: str) -> Dict[str, Any]:
        value = dict(self.tasks[kind])
        started = int(value.get("startedAt") or 0)
        state = str(value.get("state") or "idle")
        now = int(time.time())
        if started > 0:
            if state not in TERMINAL_TASK_STATES and state != "idle":
                value["elapsedSeconds"] = max(0, now - started)
            elif state in TERMINAL_TASK_STATES:
                frozen = int(value.get("elapsedSeconds") or 0)
                if frozen <= 0:
                    ended = int(value.get("completedAt") or value.get("updatedAt") or now)
                    frozen = max(0, ended - started)
                value["elapsedSeconds"] = frozen
        value["log"] = list(value.get("log") or [])
        value["result"] = dict(value.get("result") or {}) if isinstance(value.get("result"), dict) else {}
        return value

    def update(self: Any, kind: str, **changes: Any) -> Dict[str, Any]:
        with self.lock:
            current = self.tasks[kind]
            current.update(changes)
            now = int(time.time())
            state = str(current.get("state") or "idle")
            started = int(current.get("startedAt") or 0)
            if state in TERMINAL_TASK_STATES:
                current["completedAt"] = int(current.get("completedAt") or now)
                if int(current.get("elapsedSeconds") or 0) <= 0 and started > 0:
                    current["elapsedSeconds"] = max(0, current["completedAt"] - started)
            current["updatedAt"] = now
            snapshot = self._snapshot_locked(kind)
            self._save()
        self._publish(kind)
        return snapshot

    manager._snapshot_locked = MethodType(snapshot_locked, manager)
    manager._update = MethodType(update, manager)
    manager._final_timing_patched = True

    # Migrate already-finished persisted tasks so opening the APP cannot resume counting.
    with manager.lock:
        now = int(time.time())
        for current in manager.tasks.values():
            state = str(current.get("state") or "idle")
            started = int(current.get("startedAt") or 0)
            if state in TERMINAL_TASK_STATES and started > 0:
                ended = int(current.get("completedAt") or current.get("updatedAt") or now)
                current["completedAt"] = ended
                if int(current.get("elapsedSeconds") or 0) <= 0:
                    current["elapsedSeconds"] = max(0, ended - started)
        manager._save()
    hub.LOGGER.info("terminal router task elapsed time is now frozen")


def _install_agent_check_routes(hub: Any) -> None:
    if getattr(hub, "_final_agent_check_patched", False):
        return

    state_lock = threading.RLock()
    check_state: Dict[str, Any] = {
        "state": "idle",
        "message": "等待检查更新",
        "startedAt": 0,
        "updatedAt": 0,
        "latestVersion": "",
    }

    def snapshot_state() -> Dict[str, Any]:
        with state_lock:
            return dict(check_state)

    def start_check(force: bool = True) -> Dict[str, Any]:
        now = int(time.time())
        with state_lock:
            if check_state.get("state") == "checking" and now - int(check_state.get("startedAt") or 0) < 20:
                return dict(check_state)
            check_state.update({
                "state": "checking",
                "message": "Hub 正在通过 HTTPS 后台检查 Agent 更新",
                "startedAt": now,
                "updatedAt": now,
            })

        def worker() -> None:
            try:
                manifest = hub.agent_release_manifest(force=force)
                latest = hub.clean_saved_value(manifest.get("versionName") or manifest.get("version"))
                if not latest:
                    raise RuntimeError("更新清单缺少版本号")
                with state_lock:
                    check_state.update({
                        "state": "ready",
                        "message": "HTTPS 更新检查完成",
                        "latestVersion": latest,
                        "updatedAt": int(time.time()),
                    })
            except Exception as exc:
                message = _friendly_update_error(exc)
                hub.LOGGER.warning("background agent update check failed: %s", message)
                with state_lock:
                    check_state.update({
                        "state": "failed",
                        "message": message,
                        "updatedAt": int(time.time()),
                    })

        threading.Thread(target=worker, name="agent-update-check", daemon=True).start()
        return snapshot_state()

    def update_check() -> Any:
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        current = start_check(force=True)
        return jsonify({
            "ok": True,
            "accepted": True,
            "state": current.get("state", "checking"),
            "message": current.get("message", "Hub 正在后台检查更新"),
            "protocol": "HTTPS",
        }), 202

    def update_status() -> Any:
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        router = hub.resolve_agent_router(
            hub.clean_saved_value(request.args.get("router")) or hub.primary_router_name()
        ) or "router"
        agent = hub.agent_status_for(router)
        command = hub.latest_agent_command(router, "update")
        cached = hub.AGENT_RELEASE_CACHE.get("data")
        manifest = cached if isinstance(cached, dict) else {}
        passive = snapshot_state()
        if request.args.get("refresh") == "1" or (not manifest and passive.get("state") not in {"checking", "failed"}):
            passive = start_check(force=bool(request.args.get("refresh") == "1"))

        latest = hub.clean_saved_value(manifest.get("versionName") or manifest.get("version"))
        if not latest:
            latest = hub.clean_saved_value(passive.get("latestVersion")) or "未知"
        current = hub.clean_saved_value(agent.get("version")) or "未知"
        available = latest != "未知" and current != "未知" and hub.version_parts(latest) > hub.version_parts(current)

        command_state = hub.clean_saved_value(command.get("state"))
        command_message = hub.clean_saved_value(command.get("message"))
        if command_message:
            command_message = _friendly_update_error(command_message) if any(
                marker in command_message.lower() for marker in ("502", "<!doctype", "<html", "timed out", "timeout")
            ) else command_message
        if command_state in {"preparing", "pending", "accepted", "scheduled", "downloading", "installing"}:
            state_value = command_state
            message = command_message or "Agent 更新任务正在进行"
        elif command_state == "failed":
            state_value = "failed"
            message = command_message or "Agent 更新任务失败"
        else:
            state_value = str(passive.get("state") or "idle")
            message = str(passive.get("message") or "")
            if state_value == "ready":
                message = "发现新版本" if available else "当前已是最新版本"
            elif not message:
                message = "等待检查更新"

        return jsonify({
            "ok": True,
            "router": router,
            "currentVersion": current,
            "latestVersion": latest,
            "updateAvailable": available,
            "state": state_value,
            "message": message,
            "lastSeenAt": agent.get("lastSeenAt", ""),
            "manifestUrl": hub.AGENT_MANIFEST_URL,
            "installerUrl": hub.AGENT_INSTALLER_URL,
            "protocol": "HTTPS",
            "checkedAt": int(passive.get("updatedAt") or 0),
        })

    # Replace the old status handler and add a dedicated async check endpoint.
    hub.app.view_functions["api_agent_update_status"] = update_status
    if "api_agent_update_check" not in hub.app.view_functions:
        hub.app.add_url_rule(
            "/api/agent/update/check",
            endpoint="api_agent_update_check",
            view_func=update_check,
            methods=["POST"],
        )
    else:
        hub.app.view_functions["api_agent_update_check"] = update_check

    hub._final_agent_check_state = check_state
    hub._final_agent_check_patched = True
    hub.LOGGER.info("asynchronous HTTPS Agent update checks enabled")


def install_final_stability_patch(hub: Any) -> None:
    if getattr(hub, "FINAL_STABILITY_PATCHED", False):
        return
    _freeze_router_task_timing(hub)
    _install_agent_check_routes(hub)
    hub.FINAL_STABILITY_PATCHED = True
