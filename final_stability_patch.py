"""Hub 0.9.32 final stability corrections.

- Freeze elapsed time when NAT/diagnostic/Beta tasks reach a terminal state.
- Expose an asynchronous Agent update-check endpoint that always returns quickly.
- Keep HTTP 502/HTML gateway bodies out of APP-facing messages.
- Serve a resilient local /agent update repository with an installer fallback.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from types import MethodType
from typing import Any, Dict

from flask import abort, jsonify, request, send_file


TERMINAL_TASK_STATES = {"succeeded", "failed", "timed_out", "cancelled"}
AGENT_ASSET_NAMES = {
    "latest.json",
    "install.sh",
    "labprobe-install.sh",
    "checksums.txt",
    "labrelay-linux-arm64",
    "labrelay-linux-aarch64",
    "labrelay-aarch64-musl",
    "labrelay-linux-amd64",
    "labrelay-linux-x86_64",
    "labrelay-x86_64-musl",
}


def _friendly_update_error(value: Any) -> str:
    text = str(value or "").strip()
    lower = text.lower()
    if "502" in lower or "<!doctype" in lower or "<html" in lower:
        return "更新源暂时不可用（网关 502），Hub 已保留上次版本信息"
    if "timeout" in lower or "timed out" in lower or "read timed out" in lower:
        return "更新源响应超时，Hub 将继续在后台重试"
    if "404" in lower:
        return "更新清单不存在，Hub 已切换本地更新清单"
    if "ssl" in lower or "certificate" in lower:
        return "HTTPS 更新源证书校验失败，请检查证书或系统时间"
    return f"更新检查失败：{text[:120]}" if text else "更新检查失败，已保留上次版本信息"


def _update_repository_dir() -> Path:
    return Path(os.environ.get("UPDATE_REPOSITORY_DIR", "/app/update-repository")).resolve()


def _local_agent_asset(name: str) -> Path | None:
    if name not in AGENT_ASSET_NAMES:
        return None
    roots = (
        _update_repository_dir() / "agent",
        _update_repository_dir(),
        Path("/app/agent"),
    )
    for root in roots:
        candidate = (root / name).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            continue
        if candidate.is_file():
            return candidate
    return None


def _fallback_manifest(hub: Any) -> Dict[str, Any]:
    local = _local_agent_asset("latest.json")
    if local is not None:
        try:
            value = hub.json.loads(local.read_text(encoding="utf-8"))
            if isinstance(value, dict) and value.get("versionName"):
                return value
        except Exception as exc:
            hub.LOGGER.warning("local agent manifest parse failed: %s", exc)

    version = (os.environ.get("LABRELAY_RELEASE_VERSION") or "0.2.12").strip()
    public_root = (os.environ.get("UPDATE_REPOSITORY_ROOT") or "").strip().rstrip("/")
    fallback_root = "https://github.com/OnlyChallgener/labprobe-hub/releases/latest/download"
    if not public_root:
        public_root = fallback_root
    return {
        "schemaVersion": 1,
        "versionName": version,
        "changelog": "LabRelay OpenWrt installer and update-source stability fixes.",
        "installUrl": f"{public_root}/agent/install.sh",
        "checksumsUrl": f"{public_root}/agent/checksums.txt",
        "binaries": {
            "arm64": {
                "url": f"{public_root}/agent/labrelay-linux-arm64",
                "fallbackUrl": f"{fallback_root}/labrelay-linux-arm64",
            },
            "amd64": {
                "url": f"{public_root}/agent/labrelay-linux-amd64",
                "fallbackUrl": f"{fallback_root}/labrelay-linux-amd64",
            },
        },
        "installer": {
            "url": f"{public_root}/agent/install.sh",
            "fallbackUrl": f"{fallback_root}/labprobe-install.sh",
        },
        "source": "hub-local-fallback",
    }


def _install_update_repository_routes(hub: Any) -> None:
    if getattr(hub, "_final_update_repository_patched", False):
        return

    def agent_asset(name: str) -> Any:
        if name not in AGENT_ASSET_NAMES:
            abort(404)
        local = _local_agent_asset(name)
        if local is not None:
            mimetype = {
                "latest.json": "application/json; charset=utf-8",
                "checksums.txt": "text/plain; charset=utf-8",
                "install.sh": "text/x-shellscript; charset=utf-8",
                "labprobe-install.sh": "text/x-shellscript; charset=utf-8",
            }.get(name, "application/octet-stream")
            return send_file(local, mimetype=mimetype, conditional=True, max_age=0)
        if name == "latest.json":
            return jsonify(_fallback_manifest(hub))
        if name == "labprobe-install.sh":
            installer = _local_agent_asset("install.sh")
            if installer is not None:
                return send_file(installer, mimetype="text/x-shellscript; charset=utf-8", conditional=True, max_age=0)
        abort(404)

    def repository_health() -> Any:
        manifest = _fallback_manifest(hub)
        assets = {}
        for name in sorted(AGENT_ASSET_NAMES):
            local = _local_agent_asset(name)
            if local is not None:
                assets[name] = {"available": True, "sizeBytes": local.stat().st_size}
        return jsonify({
            "ok": True,
            "repositoryDir": str(_update_repository_dir()),
            "manifestVersion": manifest.get("versionName", ""),
            "assets": assets,
            "installerAvailable": _local_agent_asset("install.sh") is not None,
            "binaryAvailable": any(name.startswith("labrelay-") for name in assets),
        })

    if "final_agent_asset" not in hub.app.view_functions:
        hub.app.add_url_rule(
            "/agent/<path:name>",
            endpoint="final_agent_asset",
            view_func=agent_asset,
            methods=["GET", "HEAD"],
        )
    else:
        hub.app.view_functions["final_agent_asset"] = agent_asset
    if "api_agent_repository_health" not in hub.app.view_functions:
        hub.app.add_url_rule(
            "/api/agent/repository/health",
            endpoint="api_agent_repository_health",
            view_func=repository_health,
            methods=["GET"],
        )
    else:
        hub.app.view_functions["api_agent_repository_health"] = repository_health

    hub._final_update_repository_patched = True
    hub.LOGGER.info("local Agent update repository enabled dir=%s", _update_repository_dir())


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
            remote_error = ""
            try:
                manifest = hub.agent_release_manifest(force=force)
            except Exception as exc:
                remote_error = _friendly_update_error(exc)
                manifest = _fallback_manifest(hub)
            latest = hub.clean_saved_value(manifest.get("versionName") or manifest.get("version"))
            if latest:
                with state_lock:
                    check_state.update({
                        "state": "ready",
                        "message": "已使用 Hub 本地更新清单" if remote_error else "HTTPS 更新检查完成",
                        "latestVersion": latest,
                        "updatedAt": int(time.time()),
                        "remoteWarning": remote_error,
                    })
                hub.AGENT_RELEASE_CACHE["data"] = manifest
                hub.AGENT_RELEASE_CACHE["at"] = time.time()
                if remote_error:
                    hub.LOGGER.warning("remote Agent manifest unavailable; local fallback active: %s", remote_error)
                return
            message = remote_error or "更新清单缺少版本号"
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
            "remoteWarning": passive.get("remoteWarning", ""),
        })

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
    _install_update_repository_routes(hub)
    _freeze_router_task_timing(hub)
    _install_agent_check_routes(hub)
    hub.FINAL_STABILITY_PATCHED = True
