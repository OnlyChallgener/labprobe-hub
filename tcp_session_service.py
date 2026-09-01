"""Bounded one-shot TCP peak-connection tasks for LabRelay hosts.

The Hub owns command delivery and a short-lived status snapshot only.  Socket
creation and release happen in the LabRelay daemon and never enter Router Core,
PortMap desired state, realtime fan-out, or the Agent heartbeat state machine.
"""

from __future__ import annotations

import copy
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List

from flask import Blueprint, jsonify, request


ACTIVE_STATES = {"queued", "accepted", "running", "stop_requested", "releasing"}
TERMINAL_STATES = {"completed", "stopped", "failed", "interrupted"}
FAMILIES = {"ipv4", "ipv6", "both"}
COMMAND_RETRY_SECONDS = 12
COMMAND_MAX_ATTEMPTS = 5
STATUS_STALE_SECONDS = 25
QUEUE_TIMEOUT_SECONDS = 35


def _now() -> int:
    return int(time.time())


def _text(value: Any, limit: int = 240) -> str:
    return str(value or "").strip()[:limit]


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _decimal(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _metric(value: Any) -> Dict[str, Any]:
    row = value if isinstance(value, dict) else {}
    return {
        "current": max(0, _integer(row.get("current"))),
        "peak": max(0, _integer(row.get("peak"))),
        "success": max(0, _integer(row.get("success"))),
        "failure": max(0, _integer(row.get("failure"))),
        "cps": max(0, _integer(row.get("cps"))),
        "status": _text(row.get("status")) or "待测试",
        "elapsedMs": max(0, _integer(row.get("elapsedMs"))),
        "finishReason": _text(row.get("finishReason")),
    }


class TcpSessionService:
    def __init__(self, hub: Any):
        self.hub = hub
        self.lock = threading.RLock()
        self.state_path = Path(hub.DATA_DIR) / "tcp_session_task.json"
        self.commands_path = Path(hub.DATA_DIR) / "tcp_session_commands.json"
        self.live_state: Dict[str, Any] | None = None

    def _state(self) -> Dict[str, Any]:
        if self.live_state is not None:
            return copy.deepcopy(self.live_state)
        raw = self.hub.load_json(self.state_path, {})
        return copy.deepcopy(raw) if isinstance(raw, dict) else {}

    def _save_state(self, task: Dict[str, Any], persist: bool = True) -> Dict[str, Any]:
        value = copy.deepcopy(task)
        self.live_state = value
        if persist:
            self.hub.save_json(self.state_path, value)
        return value

    def _commands(self) -> List[Dict[str, Any]]:
        raw = self.hub.load_json(self.commands_path, {"commands": []})
        rows = raw.get("commands", []) if isinstance(raw, dict) else []
        return [dict(row) for row in rows if isinstance(row, dict)]

    def _save_commands(self, rows: Iterable[Dict[str, Any]]) -> None:
        compact = []
        for source in rows:
            row = dict(source)
            if row.get("status") in {"done", "failed"}:
                row["payload"] = {"taskId": _text(row.get("taskId"))}
            compact.append(row)
        terminal = [row for row in compact if row.get("status") in {"done", "failed"}][-30:]
        active = [row for row in compact if row.get("status") not in {"done", "failed"}][-10:]
        self.hub.save_json(self.commands_path, {"commands": active + terminal})

    def _queue(self, action: str, task_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        rows = self._commands()
        command = {
            "id": f"tcp-session-{uuid.uuid4().hex[:16]}",
            "taskId": task_id,
            "action": action,
            "payload": copy.deepcopy(payload),
            "status": "pending",
            "attempts": 0,
            "createdEpoch": _now(),
        }
        rows.append(command)
        self._save_commands(rows)
        return command

    @staticmethod
    def _config(payload: Dict[str, Any]) -> Dict[str, Any]:
        host = _text(payload.get("host"), 253).removeprefix("[").removesuffix("]")
        if not host or any(char.isspace() for char in host) or "://" in host:
            raise ValueError("请输入有效的测试目标主机")
        port = _integer(payload.get("port"), 443)
        if port not in range(1, 65536):
            raise ValueError("目标端口必须是 1–65535")
        family = _text(payload.get("family")).lower() or "both"
        if family not in FAMILIES:
            raise ValueError("测试协议只能选择 IPv4、IPv6 或分别测试")
        return {
            "host": host,
            "port": port,
            "family": family,
            "targetConnections": max(1, min(65535, _integer(payload.get("targetConnections"), 65535))),
            "cps": max(1, min(10000, _integer(payload.get("cps"), 500))),
            "extremeMode": payload.get("extremeMode") is True,
            "connectTimeoutMs": max(300, min(10000, _integer(payload.get("connectTimeoutMs"), 1500))),
            "maxDurationSeconds": max(10, min(300, _integer(payload.get("maxDurationSeconds"), 180))),
        }

    def _materialized(self, task: Dict[str, Any]) -> Dict[str, Any]:
        if not task:
            return {}
        value = copy.deepcopy(task)
        state = _text(value.get("state"))
        age = max(0, _now() - _integer(value.get("updatedEpoch"), _integer(value.get("createdEpoch"))))
        timed_out = state in {"queued", "accepted"} and age > QUEUE_TIMEOUT_SECONDS
        stale = state in {"running", "stop_requested", "releasing"} and age > STATUS_STALE_SECONDS
        if timed_out or stale:
            value.update({
                "state": "interrupted",
                "status": "Relay 状态超时，测试已中断",
                "finishReason": "Hub 等待 Relay 超时",
                "finishedEpoch": _now(),
                "updatedEpoch": _now(),
            })
            value.pop("config", None)
            self._save_state(value)
        value["statusAgeSeconds"] = age
        return value

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return self._materialized(self._state())

    def start(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        config = self._config(payload)
        with self.lock:
            current = self._materialized(self._state())
            if _text(current.get("state")) in ACTIVE_STATES:
                raise RuntimeError("已有 TCP 峰值连接数测试正在运行")
            now = _now()
            task_id = f"tcp-{uuid.uuid4().hex[:16]}"
            task = {
                "id": task_id,
                "side": "relay",
                "state": "queued",
                "status": "等待 Relay 领取测试任务",
                "finishReason": "",
                "config": config,
                "ipv4": _metric(None),
                "ipv6": _metric(None),
                "logs": [],
                "conntrackPeak": 0,
                "cpuPeak": 0.0,
                "memoryMinAvailableMb": 0,
                "resourcesReleased": False,
                "releaseStatus": "等待测试开始",
                "createdEpoch": now,
                "startedEpoch": 0,
                "updatedEpoch": now,
                "finishedEpoch": 0,
            }
            self._save_state(task)
            self._queue("start", task_id, {"taskId": task_id, "config": config})
            return task

    def stop(self, task_id: str = "") -> Dict[str, Any]:
        with self.lock:
            current = self._materialized(self._state())
            if not current:
                raise RuntimeError("当前没有可停止的测试")
            current_id = _text(current.get("id"))
            if task_id and task_id != current_id:
                raise RuntimeError("测试任务已经变化，请刷新后重试")
            if _text(current.get("state")) in TERMINAL_STATES:
                return current
            if _text(current.get("state")) != "stop_requested":
                self._queue("stop", current_id, {"taskId": current_id})
            current.update({"state": "stop_requested", "status": "正在通知 Relay 停止并释放连接", "updatedEpoch": _now()})
            return self._save_state(current)

    def deliver(self, router: str, limit: int) -> List[Dict[str, Any]]:
        del router  # The deployment currently has one authenticated Relay identity.
        with self.lock:
            rows, selected, changed, now = self._commands(), [], False, _now()
            for row in rows:
                retry = row.get("status") == "delivered" and now - _integer(row.get("deliveredEpoch")) >= COMMAND_RETRY_SECONDS and _integer(row.get("attempts")) < COMMAND_MAX_ATTEMPTS
                if row.get("status") == "pending" or retry:
                    row.update({"status": "delivered", "deliveredEpoch": now, "attempts": _integer(row.get("attempts")) + 1})
                    selected.append({key: row.get(key) for key in ("id", "taskId", "action", "payload", "createdEpoch")})
                    changed = True
                    if len(selected) >= limit:
                        break
            if changed:
                self._save_commands(rows)
            return selected

    def acknowledge(self, acknowledgements: Any) -> int:
        values = {
            _text(row.get("id")): row
            for row in acknowledgements if isinstance(row, dict) and _text(row.get("id"))
        } if isinstance(acknowledgements, list) else {}
        with self.lock:
            rows, changed = self._commands(), 0
            task = self._state()
            for row in rows:
                ack = values.get(_text(row.get("id")))
                if not ack:
                    continue
                ok = bool(ack.get("ok"))
                row.update({"status": "done" if ok else "failed", "result": ack.get("result"), "finishedEpoch": _now()})
                if _text(task.get("id")) == _text(row.get("taskId")):
                    if not ok:
                        task.update({
                            "state": "failed",
                            "status": "Relay 未能执行测试任务",
                            "finishReason": _text((ack.get("result") or {}).get("error") if isinstance(ack.get("result"), dict) else ack.get("result")) or "Relay 命令执行失败",
                            "updatedEpoch": _now(),
                            "finishedEpoch": _now(),
                        })
                        task.pop("config", None)
                    elif row.get("action") == "start" and _text(task.get("state")) == "queued":
                        task.update({"state": "accepted", "status": "Relay 已领取测试任务", "updatedEpoch": _now()})
                    self._save_state(task)
                changed += 1
            if changed:
                self._save_commands(rows)
            return changed

    def accept_status(self, payload: Dict[str, Any]) -> bool:
        task_id = _text(payload.get("id") or payload.get("taskId"))
        if not task_id:
            return False
        with self.lock:
            current = self._state()
            if _text(current.get("id")) != task_id:
                return False
            previous_state = _text(current.get("state"))
            state = _text(payload.get("state"))
            if state not in ACTIVE_STATES | TERMINAL_STATES:
                state = "interrupted"
            logs = payload.get("logs") if isinstance(payload.get("logs"), list) else []
            current.update({
                "state": state,
                "status": _text(payload.get("status")) or "Relay 测试状态已更新",
                "finishReason": _text(payload.get("finishReason")),
                "ipv4": _metric(payload.get("ipv4")),
                "ipv6": _metric(payload.get("ipv6")),
                "logs": [_text(line) for line in logs[-80:] if _text(line)],
                "conntrackPeak": max(0, _integer(payload.get("conntrackPeak"))),
                "cpuPeak": max(0.0, min(100.0, _decimal(payload.get("cpuPeak")))),
                "memoryMinAvailableMb": max(0, _integer(payload.get("memoryMinAvailableMb"))),
                "resourcesReleased": bool(payload.get("resourcesReleased")),
                "releaseStatus": _text(payload.get("releaseStatus")) or "等待资源状态更新",
                "startedEpoch": max(0, _integer(payload.get("startedEpoch"), _integer(current.get("startedEpoch")))),
                "updatedEpoch": _now(),
                "finishedEpoch": max(0, _integer(payload.get("finishedEpoch"))),
            })
            if state in TERMINAL_STATES and not current["finishedEpoch"]:
                current["finishedEpoch"] = _now()
            if state in TERMINAL_STATES:
                current.pop("config", None)
            self._save_state(current, persist=state in TERMINAL_STATES or state != previous_state)
            return True


def create_tcp_session_blueprint(hub: Any, service: TcpSessionService) -> Blueprint:
    bp = Blueprint("tcp_session_service", __name__, url_prefix="/api")

    @bp.get("/tcp-session-test")
    def snapshot():
        if not hub.check_read_token():
            return jsonify({"ok": False, "error": "未授权"}), 401
        return jsonify({"ok": True, "task": service.snapshot(), "serverEpoch": _now()})

    @bp.post("/tcp-session-test/start")
    def start():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "未授权"}), 401
        try:
            return jsonify({"ok": True, "task": service.start(request.get_json(silent=True) or {})})
        except RuntimeError as error:
            return jsonify({"ok": False, "error": str(error)}), 409
        except ValueError as error:
            return jsonify({"ok": False, "error": str(error)}), 400

    @bp.post("/tcp-session-test/stop")
    def stop():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "未授权"}), 401
        try:
            body = request.get_json(silent=True) or {}
            return jsonify({"ok": True, "task": service.stop(_text(body.get("taskId")))})
        except RuntimeError as error:
            return jsonify({"ok": False, "error": str(error)}), 409

    @bp.get("/router/tcp-session-test/commands")
    def agent_commands():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "Hook 令牌无效"}), 401
        limit = max(1, min(10, _integer(request.args.get("limit"), 5)))
        return jsonify({"ok": True, "commands": service.deliver(_text(request.args.get("router")), limit)})

    @bp.post("/router/tcp-session-test/ack")
    def agent_ack():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "Hook 令牌无效"}), 401
        body = request.get_json(silent=True) or {}
        return jsonify({"ok": True, "acknowledged": service.acknowledge(body.get("acks", []))})

    @bp.post("/router/tcp-session-test/status")
    def agent_status():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "Hook 令牌无效"}), 401
        accepted = service.accept_status(request.get_json(silent=True) or {})
        return jsonify({"ok": True, "accepted": accepted, "receivedEpoch": _now()})

    return bp


def install_tcp_session_service(hub: Any) -> TcpSessionService:
    existing = getattr(hub, "TCP_SESSION_SERVICE", None)
    if existing is not None:
        return existing
    service = TcpSessionService(hub)
    hub.TCP_SESSION_SERVICE = service
    hub.app.register_blueprint(create_tcp_session_blueprint(hub, service))
    return service
