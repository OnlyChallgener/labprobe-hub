"""Bounded one-shot TCP peak-connection tasks for LabRelay hosts.

The Hub owns command delivery and a short-lived status snapshot only.  Socket
creation and release happen in the LabRelay daemon and never enter Router Core,
PortMap desired state, realtime fan-out, or the Agent heartbeat state machine.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
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
PER_WAN_CAPABILITIES = {"relay.perWanTcpSession", "relay.multiWan"}


class RelayMultiWanUnsupported(RuntimeError):
    """An explicit WAN was requested from a Relay that cannot honor it."""

    code = "RELAY_MULTI_WAN_UNSUPPORTED"

    def __init__(self) -> None:
        super().__init__(self.code)


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


def _wan_id(value: Any) -> str:
    wan_id = "" if value is None else str(value).strip().lower()
    if len(wan_id) > 64 or (wan_id and not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", wan_id)):
        raise ValueError("WAN ID 格式无效")
    return wan_id


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
        self.history_path = Path(hub.DATA_DIR) / "tcp_session_history.json"
        self.live_state: Dict[str, Any] | None = None

    def _default_router(self) -> str:
        primary = getattr(self.hub, "primary_router_name", None)
        return _text(primary() if callable(primary) else "") or "router"

    def _router(self, value: Any = "") -> str:
        preferred = _text(value) or self._default_router()
        resolve = getattr(self.hub, "resolve_agent_router", None)
        return _text(resolve(preferred) if callable(resolve) else preferred) or preferred or "router"

    @staticmethod
    def _task_key(router: str, wan_id: str) -> str:
        return json.dumps([_text(router), _wan_id(wan_id)], ensure_ascii=False, separators=(",", ":"))

    def _document(self) -> Dict[str, Any]:
        if isinstance(self.live_state, dict) and isinstance(self.live_state.get("tasks"), dict):
            return copy.deepcopy(self.live_state)
        raw = self.hub.load_json(self.state_path, {})
        if isinstance(raw, dict) and isinstance(raw.get("tasks"), dict):
            return copy.deepcopy(raw)
        # A pre-contract state file contains one task directly.  Keep accepting
        # that shape while moving new multi-WAN state to the task envelope.
        task = copy.deepcopy(raw) if isinstance(raw, dict) and raw.get("id") else {}
        if task:
            task["router"] = _text(task.get("router")) or self._default_router()
            task["wanId"] = _wan_id(task.get("wanId"))
            key = self._task_key(task["router"], task["wanId"])
            return {"version": 2, "currentKey": key, "tasks": {key: task}}
        return {"version": 2, "currentKey": "", "tasks": {}}

    def _save_document(self, document: Dict[str, Any]) -> None:
        value = copy.deepcopy(document)
        self.live_state = value
        tasks = value.get("tasks", {})
        # Preserve the legacy on-disk shape while only one logical task exists.
        persisted = next(iter(tasks.values())) if len(tasks) == 1 else value
        self.hub.save_json(self.state_path, persisted)

    def _save_state(self, task: Dict[str, Any], persist: bool = True) -> Dict[str, Any]:
        value = copy.deepcopy(task)
        value["router"] = _text(value.get("router")) or self._default_router()
        value["wanId"] = _wan_id(value.get("wanId"))
        document = self._document()
        key = self._task_key(value["router"], value["wanId"])
        document["version"] = 2
        document["currentKey"] = key
        document["tasks"][key] = value
        if persist:
            self._save_document(document)
            self._archive(value)
        else:
            self.live_state = document
        return value

    def _select_task(
        self,
        document: Dict[str, Any],
        router: str = "",
        wan_id: str | None = None,
        task_id: str = "",
    ) -> Dict[str, Any]:
        tasks = document.get("tasks", {})
        rows = [row for row in tasks.values() if isinstance(row, dict)]
        if task_id:
            rows = [row for row in rows if _text(row.get("id")) == task_id]
        if router:
            rows = [row for row in rows if _text(row.get("router")) == router]
        if wan_id is not None:
            rows = [row for row in rows if _wan_id(row.get("wanId")) == wan_id]
        if not rows:
            return {}
        if len(rows) == 1:
            return copy.deepcopy(rows[0])
        current_key = _text(document.get("currentKey"))
        current = tasks.get(current_key)
        if isinstance(current, dict) and current in rows:
            return copy.deepcopy(current)
        return copy.deepcopy(max(rows, key=lambda row: (_integer(row.get("updatedEpoch")), _integer(row.get("createdEpoch")))))

    def _state(self) -> Dict[str, Any]:
        return self._select_task(self._document())

    def _archive(self, task: Dict[str, Any]) -> None:
        if task.get("state") not in TERMINAL_STATES or not task.get("id"):
            return
        saved = self.hub.load_json(self.history_path, {"tasks": []})
        saved = saved if isinstance(saved, dict) else {"tasks": []}
        if task["id"] in saved.get("deletedTaskIds", []):
            return
        rows = saved.get("tasks", []) if isinstance(saved, dict) else []
        row = copy.deepcopy(task)
        row.pop("config", None)
        rows = [r for r in rows if isinstance(r, dict) and r.get("id") != row["id"]]
        rows.insert(0, row)
        rows.sort(key=lambda r: _integer(r.get("createdEpoch")), reverse=True)
        saved["tasks"] = rows[:5]
        self.hub.save_json(self.history_path, saved)

    def remove_history(self, task_id: str) -> List[Dict[str, Any]]:
        if not task_id:
            raise ValueError("缺少测试记录 ID")
        with self.lock:
            raw = self.hub.load_json(self.history_path, {"tasks": []})
            saved = raw if isinstance(raw, dict) else {"tasks": []}
            saved["tasks"] = [r for r in saved.get("tasks", []) if isinstance(r, dict) and r.get("id") != task_id][:5]
            deleted = saved.get("deletedTaskIds", [])
            saved["deletedTaskIds"] = ([task_id] + [v for v in deleted if v != task_id])[:128]
            self.hub.save_json(self.history_path, saved)
            return self.history()

    def history(self) -> List[Dict[str, Any]]:
        with self.lock:
            raw = self.hub.load_json(self.history_path, {"tasks": []})
            rows = raw.get("tasks", []) if isinstance(raw, dict) else []
            return [copy.deepcopy(r) for r in rows if isinstance(r, dict)][:5]

    def _commands(self) -> List[Dict[str, Any]]:
        raw = self.hub.load_json(self.commands_path, {"commands": []})
        rows = raw.get("commands", []) if isinstance(raw, dict) else []
        return [dict(row) for row in rows if isinstance(row, dict)]

    def _save_commands(self, rows: Iterable[Dict[str, Any]]) -> None:
        compact = []
        for source in rows:
            row = dict(source)
            if row.get("status") in {"done", "failed"}:
                payload = {"taskId": _text(row.get("taskId"))}
                if _text(row.get("wanId")):
                    payload["router"] = _text(row.get("router"))
                    payload["wanId"] = _wan_id(row.get("wanId"))
                row["payload"] = payload
            compact.append(row)
        terminal = [row for row in compact if row.get("status") in {"done", "failed"}][-30:]
        active = [row for row in compact if row.get("status") not in {"done", "failed"}][-10:]
        self.hub.save_json(self.commands_path, {"commands": active + terminal})

    def _queue(
        self,
        action: str,
        task_id: str,
        payload: Dict[str, Any],
        router: str = "",
        wan_id: str = "",
    ) -> Dict[str, Any]:
        rows = self._commands()
        command = {
            "id": f"tcp-session-{uuid.uuid4().hex[:16]}",
            "taskId": task_id,
            "router": _text(router),
            "wanId": _wan_id(wan_id),
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
        raw = str(payload.get("host") or "").strip()
        if not raw or len(raw) > 2048 or "://" in raw:
            raise ValueError("请输入有效的测试目标主机")
        hosts = []
        for item in re.split(r"[,，;；\s]+", raw):
            if not item:
                continue
            item = item.removeprefix("[").removesuffix("]").lower().rstrip(".")
            if ":" in item:
                try:
                    item = str(ipaddress.IPv6Address(item))
                except ValueError as error:
                    raise ValueError("IPv6 目标格式无效；端口请在目标端口栏填写") from error
            else:
                try:
                    item = item.encode("idna").decode("ascii")
                except UnicodeError as error:
                    raise ValueError("测试目标域名格式无效") from error
                if len(item) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in item.split(".")):
                    raise ValueError("请输入有效的 IP 或域名，不含协议头、端口和路径")
            if item not in hosts:
                hosts.append(item)
        if not hosts or len(hosts) > 8:
            raise ValueError("一次最多填写 8 个目标 IP 或域名")
        host = ",".join(hosts)
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
            "wanId": _wan_id(payload.get("wanId")),
            "targetConnections": max(1, min(131072, _integer(payload.get("targetConnections"), 131072))),
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
        value["statusAgeSeconds"] = age
        return value

    def _materialized_document(self) -> Dict[str, Any]:
        document = self._document()
        changed = False
        for key, source in list(document.get("tasks", {}).items()):
            if not isinstance(source, dict):
                continue
            task = self._materialized(source)
            if task.get("state") != source.get("state"):
                document["tasks"][key] = task
                self._archive(task)
                changed = True
        if changed:
            self._save_document(document)
        return document

    def snapshot(self, router: str = "", wan_id: str | None = None) -> Dict[str, Any]:
        with self.lock:
            document = self._materialized_document()
            return self._select_task(document, self._router(router) if router else "", wan_id)

    def _require_per_wan(self, router: str, wan_id: str) -> None:
        if not wan_id:
            return
        presence_fn = getattr(self.hub, "agent_presence_snapshot", None)
        try:
            presence = presence_fn(router) if callable(presence_fn) else {}
        except Exception:
            presence = {}
        presence = presence if isinstance(presence, dict) else {}
        capabilities = presence.get("agentCapabilities", presence.get("capabilities", []))
        capabilities = {item for item in capabilities if isinstance(item, str)} if isinstance(capabilities, (list, tuple, set)) else set()
        online = presence.get("agentOnline", presence.get("online")) is True
        wan_ids = presence.get("agentWanIds", [])
        available = {item.strip().lower() for item in wan_ids if isinstance(item, str)} if isinstance(wan_ids, list) else set()
        if not online or not capabilities.intersection(PER_WAN_CAPABILITIES) or wan_id not in available:
            raise RelayMultiWanUnsupported()

    def start(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        config = self._config(payload)
        router = self._router(payload.get("router"))
        wan_id = config["wanId"]
        # Capability validation deliberately precedes any state or queue write.
        self._require_per_wan(router, wan_id)
        with self.lock:
            document = self._materialized_document()
            active = [
                row for row in document.get("tasks", {}).values()
                if isinstance(row, dict) and _text(row.get("state")) in ACTIVE_STATES
            ]
            router_active = [row for row in active if _text(row.get("router")) == router]
            same_wan = any(_wan_id(row.get("wanId")) == wan_id for row in router_active)
            legacy_active = any(not _wan_id(row.get("wanId")) for row in router_active)
            # Blank WAN keeps the original one-active-task contract.  Explicit
            # WANs may run concurrently only when their (router, WAN) keys differ.
            if (not wan_id and router_active) or same_wan or legacy_active:
                current = self._select_task(document, router, wan_id) or (router_active[0] if router_active else {})
                status_desc = current.get("status") or _text(current.get("state"))
                raise RuntimeError(f"已有 TCP 峰值连接数测试正在运行（状态：{status_desc}），请等待完成或点击停止")
            now = _now()
            task_id = f"tcp-{uuid.uuid4().hex[:16]}"
            task = {
                "id": task_id,
                "router": router,
                "wanId": wan_id,
                "side": "relay",
                "state": "queued",
                "status": "等待 Relay 领取测试任务",
                "finishReason": "",
                "config": config,
                "target": {key: config[key] for key in ("host", "port", "family")},
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
            self._queue("start", task_id, {"taskId": task_id, "router": router, "wanId": wan_id, "config": config}, router, wan_id)
            return task

    def stop(self, task_id: str = "", router: str = "", wan_id: str | None = None) -> Dict[str, Any]:
        with self.lock:
            document = self._materialized_document()
            router = self._router(router) if router else ""
            current = self._select_task(document, router, wan_id, task_id)
            if task_id and not current:
                raise RuntimeError("测试任务已经变化，请刷新后重试")
            if not current:
                raise RuntimeError("当前没有可停止的测试")
            current_id = _text(current.get("id"))
            if _text(current.get("state")) in TERMINAL_STATES:
                return current
            current_router = _text(current.get("router")) or self._default_router()
            current_wan = _wan_id(current.get("wanId"))
            if _text(current.get("state")) != "stop_requested":
                self._queue("stop", current_id, {"taskId": current_id, "router": current_router, "wanId": current_wan}, current_router, current_wan)
            current.update({"state": "stop_requested", "status": "正在通知 Relay 停止并释放连接", "updatedEpoch": _now()})
            return self._save_state(current)

    def deliver(self, router: str, limit: int) -> List[Dict[str, Any]]:
        router = self._router(router)
        with self.lock:
            rows, selected, changed, now = self._commands(), [], False, _now()
            for row in rows:
                row_router = _text(row.get("router"))
                if row_router and self._router(row_router) != router:
                    continue
                retry = row.get("status") == "delivered" and now - _integer(row.get("deliveredEpoch")) >= COMMAND_RETRY_SECONDS and _integer(row.get("attempts")) < COMMAND_MAX_ATTEMPTS
                if row.get("status") == "pending" or retry:
                    row.update({"status": "delivered", "deliveredEpoch": now, "attempts": _integer(row.get("attempts")) + 1})
                    selected.append({key: row.get(key) for key in ("id", "taskId", "router", "wanId", "action", "payload", "createdEpoch")})
                    changed = True
                    if len(selected) >= limit:
                        break
            if changed:
                self._save_commands(rows)
            return selected

    @staticmethod
    def _correlation_matches(
        task: Dict[str, Any],
        payload: Dict[str, Any],
        router: str = "",
        *,
        require_wan: bool = False,
    ) -> bool:
        task_router = _text(task.get("router"))
        payload_router = _text(payload.get("router"))
        if payload_router:
            if payload_router != task_router:
                return False
        elif router and router != task_router:
            return False
        elif task_router and _text(task.get("wanId")):
            # Explicit-WAN commands must echo the complete correlation tuple.
            return False
        try:
            task_wan = _wan_id(task.get("wanId"))
            payload_wan = _wan_id(payload.get("wanId")) if "wanId" in payload else None
        except ValueError:
            return False
        if task_wan or require_wan or "wanId" in payload:
            if "wanId" not in payload or payload_wan != task_wan:
                return False
        return True

    def acknowledge(self, acknowledgements: Any, router: str = "") -> int:
        values = {
            _text(row.get("id")): row
            for row in acknowledgements if isinstance(row, dict) and _text(row.get("id"))
        } if isinstance(acknowledgements, list) else {}
        router = self._router(router) if router else ""
        with self.lock:
            rows, changed = self._commands(), 0
            document = self._document()
            for row in rows:
                ack = values.get(_text(row.get("id")))
                if not ack:
                    continue
                task_id = _text(row.get("taskId"))
                row_router = _text(row.get("router")) or self._default_router()
                row_wan = _wan_id(row.get("wanId"))
                if _text(ack.get("taskId")) and _text(ack.get("taskId")) != task_id:
                    continue
                if row_wan and not _text(ack.get("taskId")):
                    continue
                identity = {"router": row_router, "wanId": row_wan}
                if not self._correlation_matches(identity, ack, router, require_wan=bool(row_wan)):
                    continue
                key = self._task_key(row_router, row_wan)
                task = document.get("tasks", {}).get(key)
                if not isinstance(task, dict) or _text(task.get("id")) != task_id:
                    continue
                ok = bool(ack.get("ok"))
                row.update({"status": "done" if ok else "failed", "result": ack.get("result"), "finishedEpoch": _now()})
                if not ok:
                    task.update({
                        "state": "failed",
                        "status": "Relay 未能执行测试任务",
                        "finishReason": _text((ack.get("result") or {}).get("error") if isinstance(ack.get("result"), dict) else ack.get("result")) or "Relay 命令执行失败",
                        "updatedEpoch": _now(),
                        "finishedEpoch": _now(),
                    })
                    task.pop("config", None)
                    saved = self._save_state(task)
                    document["tasks"][key] = saved
                elif row.get("action") == "start" and _text(task.get("state")) == "queued":
                    task.update({"state": "accepted", "status": "Relay 已领取测试任务", "updatedEpoch": _now()})
                    saved = self._save_state(task)
                    document["tasks"][key] = saved
                changed += 1
            if changed:
                self._save_commands(rows)
            return changed

    def accept_status(self, payload: Dict[str, Any], router: str = "") -> bool:
        payload_id = _text(payload.get("id"))
        payload_task_id = _text(payload.get("taskId"))
        if payload_id and payload_task_id and payload_id != payload_task_id:
            return False
        task_id = payload_id or payload_task_id
        if not task_id:
            return False
        router = self._router(router) if router else ""
        with self.lock:
            document = self._document()
            candidates = [
                row for row in document.get("tasks", {}).values()
                if isinstance(row, dict) and _text(row.get("id")) == task_id
            ]
            if router:
                candidates = [row for row in candidates if _text(row.get("router")) == router]
            if len(candidates) != 1:
                return False
            current = candidates[0]
            if not self._correlation_matches(current, payload, router):
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
        try:
            wan_id = _wan_id(request.args.get("wanId")) if "wanId" in request.args else None
        except ValueError as error:
            return jsonify({"ok": False, "error": str(error)}), 400
        return jsonify({"ok": True, "task": service.snapshot(_text(request.args.get("router")), wan_id), "history": service.history(), "serverEpoch": _now()})

    @bp.post("/tcp-session-test/history/remove")
    def remove_history():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "未授权"}), 401
        try:
            body = request.get_json(silent=True) or {}
            return jsonify({"ok": True, "history": service.remove_history(_text(body.get("taskId")))})
        except ValueError as error:
            return jsonify({"ok": False, "error": str(error)}), 400

    @bp.post("/tcp-session-test/start")
    def start():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "未授权"}), 401
        try:
            return jsonify({"ok": True, "task": service.start(request.get_json(silent=True) or {})})
        except RelayMultiWanUnsupported as error:
            return jsonify({"ok": False, "error": error.code, "code": error.code, "message": "Relay 不支持或未在线提供指定 WAN 的 TCP 会话测试"}), 409
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
            wan_id = _wan_id(body.get("wanId")) if "wanId" in body else None
            return jsonify({"ok": True, "task": service.stop(_text(body.get("taskId")), _text(body.get("router")), wan_id)})
        except RuntimeError as error:
            return jsonify({"ok": False, "error": str(error)}), 409
        except ValueError as error:
            return jsonify({"ok": False, "error": str(error)}), 400

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
        router = _text(body.get("router") or request.args.get("router"))
        return jsonify({"ok": True, "acknowledged": service.acknowledge(body.get("acks", []), router)})

    @bp.post("/router/tcp-session-test/status")
    def agent_status():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "Hook 令牌无效"}), 401
        body = request.get_json(silent=True) or {}
        router = _text(body.get("router") or request.args.get("router"))
        accepted = service.accept_status(body, router)
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
