"""Follow-up stability fixes for Hub 0.9.31.

- Keep the router-local two-second terminal rate lane warm even when the APP is in
  the background. Hub still stores only compact in-memory samples.
- Queue Agent update commands before touching the remote update repository, so a
  transient HTTP 502/timeout becomes a task result instead of a failed button.
- Keep local daily-summary reads out of unrelated long request locks.
"""
from __future__ import annotations

import threading
import time
from types import MethodType
from typing import Any, Dict

from flask import g, jsonify, request


_MANIFEST_REFRESH_LOCK = threading.Lock()
_MANIFEST_REFRESH_STATE_LOCK = threading.Lock()
_MANIFEST_REFRESH_IN_FLIGHT = 0


def _manifest_refresh_started() -> None:
    global _MANIFEST_REFRESH_IN_FLIGHT
    with _MANIFEST_REFRESH_STATE_LOCK:
        _MANIFEST_REFRESH_IN_FLIGHT += 1


def _manifest_refresh_finished() -> None:
    global _MANIFEST_REFRESH_IN_FLIGHT
    with _MANIFEST_REFRESH_STATE_LOCK:
        _MANIFEST_REFRESH_IN_FLIGHT = max(0, _MANIFEST_REFRESH_IN_FLIGHT - 1)


def _manifest_refresh_active() -> bool:
    with _MANIFEST_REFRESH_STATE_LOCK:
        return _MANIFEST_REFRESH_IN_FLIGHT > 0


def _update_command(hub: Any, command_id: str, values: Dict[str, Any]) -> Dict[str, Any]:
    data = hub.load_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": []})
    commands = data.get("commands", []) if isinstance(data, dict) else []
    updated: Dict[str, Any] = {}
    for row in commands:
        if isinstance(row, dict) and row.get("id") == command_id:
            row.update(values)
            row["updatedAt"] = hub.now_str()
            updated = dict(row)
            break
    if updated:
        hub.save_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": commands[-100:]})
    return updated


def _start_manifest_refresh(hub: Any, command_id: str = "", force: bool = False) -> None:
    def worker() -> None:
        # A real update command must never be left in "preparing" merely because a
        # passive status refresh was already using the manifest lock. It waits in
        # this background thread; status-only refreshes remain best-effort.
        acquired = False
        try:
            acquired = _MANIFEST_REFRESH_LOCK.acquire(blocking=bool(command_id))
            if not acquired:
                return
            manifest = hub.agent_release_manifest(force=force)
            if command_id:
                target = hub.clean_saved_value(manifest.get("versionName") or manifest.get("version"))
                if not target:
                    raise RuntimeError("更新清单缺少版本号")
                _update_command(
                    hub,
                    command_id,
                    {
                        "state": "pending",
                        "targetVersion": target,
                        "repositoryRoot": manifest.get("_repositoryRoot") or hub.UPDATE_REPOSITORY_ROOT,
                        "manifestUrl": manifest.get("_manifestUrl") or hub.AGENT_MANIFEST_URL,
                        "installerUrl": manifest.get("_installerUrl") or hub.AGENT_INSTALLER_URL,
                        "message": "更新清单已就绪，等待路由器领取指令",
                    },
                )
        except Exception as exc:
            hub.LOGGER.warning("agent update manifest preparation failed: %s", exc)
            if command_id:
                _update_command(
                    hub,
                    command_id,
                    {
                        "state": "failed",
                        "message": f"更新仓暂不可用：{exc}",
                    },
                )
        finally:
            if acquired:
                _MANIFEST_REFRESH_LOCK.release()
            _manifest_refresh_finished()

    _manifest_refresh_started()
    try:
        threading.Thread(target=worker, name="agent-manifest-refresh", daemon=True).start()
    except Exception:
        _manifest_refresh_finished()
        raise


def _install_continuous_terminal_demand(hub: Any, realtime: Any) -> None:
    if realtime is None or getattr(realtime, "_continuous_terminal_demand_patched", False):
        return
    original = realtime._demand_payload_locked

    def continuous_payload(_self: Any) -> Dict[str, Any]:
        payload = dict(original())
        payload["devicesActive"] = True
        payload["continuousDevices"] = True
        return payload

    realtime._demand_payload_locked = MethodType(continuous_payload, realtime)
    realtime._continuous_terminal_demand_patched = True
    with realtime._demand:
        realtime._demand_sequence += 1
        realtime._demand.notify_all()
    hub.LOGGER.info("continuous two-second terminal rate cache enabled")


def _install_fast_daily_lock_path(hub: Any) -> None:
    functions = hub.app.before_request_funcs.get(None, [])
    for index, function in enumerate(list(functions)):
        if getattr(function, "__name__", "") != "lock_request_data":
            continue
        original = function

        def fast_local_reads() -> Any:
            if request.method == "GET" and request.path.startswith("/api/daily"):
                # aggregate_daily/load_json acquire the SQLite lock only around the
                # actual reads. Do not queue this local page behind unrelated work.
                g.data_lock_acquired = False
                return None
            return original()

        fast_local_reads.__name__ = "lock_request_data_followup"
        functions[index] = fast_local_reads
        return


def _install_agent_update_routes(hub: Any) -> None:
    def update_request() -> Any:
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        payload = request.get_json(silent=True) or {}
        router = hub.resolve_agent_router(
            hub.clean_saved_value(payload.get("router")) or hub.primary_router_name()
        ) or "router"
        data = hub.load_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": []})
        commands = data.get("commands", []) if isinstance(data, dict) else []
        changed = False
        now_epoch = time.time()
        for row in commands:
            if not isinstance(row, dict) or row.get("router") != router:
                continue
            if row.get("action") != "update" or row.get("state") not in {"preparing", "pending", "accepted", "scheduled"}:
                continue
            updated_epoch = hub.time_to_epoch(row.get("updatedAt") or row.get("createdAt") or 0)
            if updated_epoch > 0 and now_epoch - updated_epoch > 900:
                row.update({
                    "state": "failed",
                    "updatedAt": hub.now_str(),
                    "message": "旧更新任务已过期，请重新发起",
                })
                changed = True
        if changed:
            hub.save_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": commands[-100:]})
        active = next(
            (
                row for row in reversed(commands)
                if isinstance(row, dict)
                and row.get("router") == router
                and row.get("action") == "update"
                and row.get("state") in {"preparing", "pending", "accepted", "scheduled"}
            ),
            None,
        )
        if active:
            return jsonify({
                "ok": True,
                "commandId": active.get("id", ""),
                "targetVersion": active.get("targetVersion", ""),
                "state": active.get("state", "pending"),
                "message": active.get("message", "已有更新任务正在进行"),
                "deduplicated": True,
            }), 202

        command = {
            "id": hub.secrets.token_hex(12),
            "router": router,
            "action": "update",
            "state": "preparing",
            "targetVersion": "",
            "repositoryRoot": hub.UPDATE_REPOSITORY_ROOT,
            "manifestUrl": hub.AGENT_MANIFEST_URL,
            "installerUrl": hub.AGENT_INSTALLER_URL,
            "createdAt": hub.now_str(),
            "updatedAt": hub.now_str(),
            "message": "更新任务已创建，正在读取更新清单",
        }
        commands.append(command)
        hub.save_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": commands[-100:]})
        _start_manifest_refresh(hub, command["id"], force=True)
        return jsonify({
            "ok": True,
            "commandId": command["id"],
            "targetVersion": "",
            "state": "preparing",
            "message": command["message"],
        }), 202

    def update_status() -> Any:
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        router = hub.resolve_agent_router(
            hub.clean_saved_value(request.args.get("router")) or hub.primary_router_name()
        ) or "router"
        status = hub.agent_status_for(router)
        command = hub.latest_agent_command(router, "update")
        cached = hub.AGENT_RELEASE_CACHE.get("data")
        manifest = cached if isinstance(cached, dict) else {}
        refresh_started = request.args.get("refresh") == "1" or not manifest
        if refresh_started:
            _start_manifest_refresh(hub, force=bool(request.args.get("refresh") == "1"))
        latest = hub.clean_saved_value(manifest.get("versionName") or manifest.get("version")) or "未知"
        current = hub.clean_saved_value(status.get("version")) or "未知"
        available = latest != "未知" and current != "未知" and hub.version_parts(latest) > hub.version_parts(current)
        refreshing = refresh_started or _manifest_refresh_active()
        command_state = "checking" if refreshing else (command.get("state") or status.get("updateState") or "idle")
        message = hub.clean_saved_value(command.get("message"))
        if refreshing:
            message = "正在后台检查更新"
        elif not message:
            message = hub.clean_saved_value(manifest.get("changelog"))
        if not message:
            message = "正在后台检查更新" if latest == "未知" else ("发现新版本" if available else "当前已是最新版本")
        return jsonify({
            "ok": True,
            "router": router,
            "currentVersion": current,
            "latestVersion": latest,
            "updateAvailable": available,
            "state": command_state,
            "message": message,
            "lastSeenAt": status.get("lastSeenAt", ""),
            "manifestUrl": manifest.get("_manifestUrl") or hub.AGENT_MANIFEST_URL,
            "installerUrl": manifest.get("_installerUrl") or hub.AGENT_INSTALLER_URL,
        })

    def update_check() -> Any:
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        # The release repositories are external to Hub. Never hold the request
        # data lock while waiting for them: doing so can starve router config
        # reads and the optional snapshots sent after the WSS ready frame.
        _start_manifest_refresh(hub, force=True)
        return jsonify({
            "ok": True,
            "state": "checking",
            "message": "正在后台检查更新",
        }), 202

    hub.app.view_functions["api_agent_update_request"] = update_request
    hub.app.view_functions["api_agent_update_status"] = update_status
    hub.app.view_functions["api_agent_update_check"] = update_check


def install_followup_stability_patch(hub: Any, realtime: Any) -> None:
    if getattr(hub, "FOLLOWUP_STABILITY_PATCHED", False):
        return
    _install_continuous_terminal_demand(hub, realtime)
    _install_fast_daily_lock_path(hub)
    _install_agent_update_routes(hub)
    hub.FOLLOWUP_STABILITY_PATCHED = True
