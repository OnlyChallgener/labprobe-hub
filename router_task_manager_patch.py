"""Hub-owned task state for NAT diagnostics, network self-test and Beta checks.

Long-running router operations are started once, continue after the APP page exits,
and expose an in-memory/persisted task snapshot. APP reads this snapshot or receives
it over the existing Hub WSS; it never polls the router directly.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict

from flask import Blueprint, jsonify, request

import router_rpc_v099 as v099
from router_native_features_patch import normalize_nat_request, _normalize_nat_payload, _nat_terminal

TERMINAL = {"succeeded", "failed", "timed_out", "cancelled"}
NAT_MAX_SECONDS = max(180, int(os.environ.get("ROUTER_NAT_MAX_RUNTIME_SEC", "600")))
DIAGNOSTIC_MAX_SECONDS = max(30, int(os.environ.get("ROUTER_DIAGNOSTIC_MAX_RUNTIME_SEC", "180")))
BETA_MAX_SECONDS = max(15, int(os.environ.get("ROUTER_BETA_MAX_RUNTIME_SEC", "45")))
POLL_SECONDS = 2.0


def _now() -> int:
    return int(time.time())


def _translate_beta_message(value: Any) -> str:
    text = str(value or "").strip()
    lower = text.lower()
    if not text:
        return "检测完成"
    if "no new version" in lower or "latest version" in lower or "no update" in lower:
        return "暂无可用的新版本"
    if "new version" in lower or "update available" in lower:
        return "发现可用的新版本"
    if "timeout" in lower or "timed out" in lower:
        return "版本检测超时"
    if "failed" in lower or "error" in lower:
        return "版本检测失败"
    return text


def _task(kind: str) -> Dict[str, Any]:
    return {
        "kind": kind,
        "taskId": "",
        "state": "idle",
        "stage": "idle",
        "stageText": "尚未开始",
        "startedAt": 0,
        "updatedAt": 0,
        "lastRouterResponseAt": 0,
        "elapsedSeconds": 0,
        "message": "",
        "log": [],
        "result": {},
    }


class RouterTaskManager:
    def __init__(self, hub: Any, client: Any, logger: Any):
        self.hub = hub
        self.client = client
        self.logger = logger
        self.lock = threading.RLock()
        data_dir = Path(os.environ.get("DATA_DIR", "./data")).resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "router_tasks.json"
        self.tasks: Dict[str, Dict[str, Any]] = {
            "nat": _task("nat"),
            "diagnostic": _task("diagnostic"),
            "beta": _task("beta"),
        }
        self._load()

    def _load(self) -> None:
        try:
            root = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
            if not isinstance(root, dict):
                return
            for kind in self.tasks:
                value = root.get(kind)
                if isinstance(value, dict):
                    restored = {**_task(kind), **value}
                    if restored.get("state") not in TERMINAL and restored.get("state") != "idle":
                        restored["state"] = "failed"
                        restored["stage"] = "interrupted"
                        restored["stageText"] = "Hub 重启，任务已中断"
                        restored["message"] = "任务未完成，可重新开始"
                    self.tasks[kind] = restored
        except Exception as exc:
            self.logger.warning("router task cache load failed: %s", exc)

    def _save(self) -> None:
        try:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.tasks, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            tmp.replace(self.path)
        except Exception as exc:
            self.logger.debug("router task cache save deferred: %s", exc)

    def _snapshot_locked(self, kind: str) -> Dict[str, Any]:
        value = dict(self.tasks[kind])
        started = int(value.get("startedAt") or 0)
        if started > 0 and value.get("state") != "idle":
            value["elapsedSeconds"] = max(0, _now() - started)
        value["log"] = list(value.get("log") or [])
        value["result"] = dict(value.get("result") or {}) if isinstance(value.get("result"), dict) else {}
        return value

    def snapshot(self, kind: str) -> Dict[str, Any]:
        with self.lock:
            return self._snapshot_locked(kind)

    def _publish(self, kind: str) -> None:
        snapshot = self.snapshot(kind)
        ws = getattr(self.hub, "HUB_REALTIME_WEBSOCKET", None)
        publish = getattr(ws, "_publish", None)
        if callable(publish):
            try:
                publish("task", snapshot)
            except Exception:
                self.logger.debug("router task WSS publish deferred", exc_info=True)

    def _update(self, kind: str, **changes: Any) -> Dict[str, Any]:
        with self.lock:
            current = self.tasks[kind]
            current.update(changes)
            current["updatedAt"] = _now()
            snapshot = self._snapshot_locked(kind)
            self._save()
        self._publish(kind)
        return snapshot

    def _append_log(self, kind: str, line: str) -> None:
        text = str(line or "").strip()
        if not text:
            return
        with self.lock:
            lines = list(self.tasks[kind].get("log") or [])
            if not lines or lines[-1] != text:
                lines.append(text)
                self.tasks[kind]["log"] = lines[-300:]
                self.tasks[kind]["updatedAt"] = _now()
                self._save()
        self._publish(kind)

    def _begin(self, kind: str, stage_text: str) -> tuple[str, Dict[str, Any], bool]:
        with self.lock:
            active = self.tasks[kind]
            if active.get("state") in {"queued", "running"}:
                return str(active.get("taskId") or ""), self._snapshot_locked(kind), False
            task_id = f"{kind}-{uuid.uuid4().hex[:12]}"
            self.tasks[kind] = {
                **_task(kind),
                "taskId": task_id,
                "state": "queued",
                "stage": "queued",
                "stageText": stage_text,
                "startedAt": _now(),
                "updatedAt": _now(),
            }
            self._save()
            snapshot = self._snapshot_locked(kind)
        self._publish(kind)
        return task_id, snapshot, True

    def start_nat(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        request_data = normalize_nat_request(payload)
        task_id, snapshot, created = self._begin("nat", "检测任务已排队")
        if not created:
            return snapshot
        threading.Thread(
            target=self._run_nat,
            args=(task_id, request_data),
            name=f"router-task-nat-{task_id[-6:]}",
            daemon=True,
        ).start()
        return snapshot

    def _run_nat(self, task_id: str, requested: Dict[str, Any]) -> None:
        kind = "nat"
        try:
            self._update(kind, state="running", stage="command", stageText="正在向路由器发送检测指令", request=requested)
            self._append_log(kind, "Hub 已接受 NAT 检测任务")
            start = self.client.rpc("devSta.set", "nat_detector", requested)
            self._update(kind, lastRouterResponseAt=_now(), stage="router_running", stageText="路由器正在执行 NAT 检测")
            self._append_log(kind, "检测指令已发送到路由器")
            deadline = time.monotonic() + NAT_MAX_SECONDS
            latest: Any = start
            while time.monotonic() < deadline:
                with self.lock:
                    if self.tasks[kind].get("taskId") != task_id:
                        return
                if isinstance(latest, dict):
                    normalized = _normalize_nat_payload(latest)
                    if isinstance(normalized, dict):
                        normalized = dict(normalized)
                        normalized["requested_host"] = requested.get("host", "")
                        normalized["requested_port"] = int(requested.get("port") or 3478)
                        normalized["requested_interface"] = requested.get("interface", "wan")
                        normalized["requested_mode"] = requested.get("mode", "classic")
                        normalized.setdefault("mode", requested.get("mode", "classic"))
                        raw_log = normalized.get("log")
                        if raw_log:
                            for line in str(raw_log).splitlines():
                                self._append_log(kind, line)
                        mapping = str(normalized.get("mapping_behavior") or "").strip()
                        filtering = str(normalized.get("filtering_behavior") or "").strip()
                        stage_text = "路由器正在执行 NAT 检测"
                        stage = "router_running"
                        if mapping and not filtering:
                            stage, stage_text = "mapping_done", "映射行为已返回，等待过滤行为"
                        elif filtering:
                            stage, stage_text = "filtering_done", "过滤行为已返回，正在整理结果"
                        self._update(kind, stage=stage, stageText=stage_text, lastRouterResponseAt=_now(), result=normalized)
                        if _nat_terminal(normalized):
                            status = str(normalized.get("status") or "").lower()
                            failed = status in {"failed", "error", "timeout", "cancelled", "canceled"}
                            self._update(
                                kind,
                                state="failed" if failed else "succeeded",
                                stage="finished",
                                stageText="检测失败" if failed else "检测完成",
                                message=str(normalized.get("message") or ("检测失败" if failed else "检测完成")),
                                result=normalized,
                            )
                            return
                time.sleep(POLL_SECONDS)
                try:
                    latest = self.client.rpc("devSta.get", "nat_detector")
                except Exception as exc:
                    self.logger.debug("NAT task poll deferred: %s", exc)
                    self._update(kind, stage="router_running", stageText="路由器仍在检测，等待下一次状态响应")
            self._update(kind, state="timed_out", stage="timeout", stageText="检测超时", message="路由器长时间未返回最终检测结果")
            self._append_log(kind, f"已等待 {NAT_MAX_SECONDS} 秒，任务结束")
        except Exception as exc:
            self.logger.warning("NAT task failed: %s", exc)
            self._update(kind, state="failed", stage="failed", stageText="检测失败", message=str(exc) or "NAT 检测失败")

    def start_diagnostic(self) -> Dict[str, Any]:
        task_id, snapshot, created = self._begin("diagnostic", "网络自检已排队")
        if not created:
            return snapshot
        threading.Thread(
            target=self._run_diagnostic,
            args=(task_id,),
            name=f"router-task-diagnostic-{task_id[-6:]}",
            daemon=True,
        ).start()
        return snapshot

    def _run_diagnostic(self, task_id: str) -> None:
        kind = "diagnostic"
        try:
            self._update(kind, state="running", stage="command", stageText="正在向路由器发送自检指令")
            self._append_log(kind, "Hub 已接受网络自检任务")
            self.client.rpc("devSta.set", "dev_diag", {"user": "eweb", "action": "start"})
            self._update(kind, lastRouterResponseAt=_now(), stage="router_running", stageText="路由器正在执行网络自检")
            self._append_log(kind, "自检指令已发送到路由器")
            deadline = time.monotonic() + DIAGNOSTIC_MAX_SECONDS
            while time.monotonic() < deadline:
                with self.lock:
                    if self.tasks[kind].get("taskId") != task_id:
                        return
                try:
                    latest = self.client.rpc("devSta.get", "dev_diag")
                    latest = latest if isinstance(latest, dict) else {}
                    process = str(latest.get("process") or latest.get("progress") or "0%").strip()
                    digits = "".join(ch for ch in process if ch.isdigit())
                    percent = min(100, int(digits or 0))
                    self._update(
                        kind,
                        stage="router_running" if percent < 100 else "finished",
                        stageText=f"网络自检进行中（{percent}%）" if percent < 100 else "网络自检完成",
                        lastRouterResponseAt=_now(),
                        result=latest,
                    )
                    if percent >= 100:
                        self._update(kind, state="succeeded", stage="finished", stageText="网络自检完成", message="检测完成", result=latest)
                        return
                except Exception as exc:
                    self.logger.debug("diagnostic task poll deferred: %s", exc)
                    self._update(kind, stageText="路由器仍在自检，等待下一次状态响应")
                time.sleep(POLL_SECONDS)
            self._update(kind, state="timed_out", stage="timeout", stageText="网络自检超时", message="路由器长时间未返回完整自检结果")
        except Exception as exc:
            self.logger.warning("diagnostic task failed: %s", exc)
            self._update(kind, state="failed", stage="failed", stageText="网络自检失败", message=str(exc) or "网络自检失败")

    def start_beta(self) -> Dict[str, Any]:
        task_id, snapshot, created = self._begin("beta", "版本检测已排队")
        if not created:
            return snapshot
        threading.Thread(
            target=self._run_beta,
            args=(task_id,),
            name=f"router-task-beta-{task_id[-6:]}",
            daemon=True,
        ).start()
        return snapshot

    def _run_beta(self, task_id: str) -> None:
        kind = "beta"
        try:
            self._update(kind, state="running", stage="router_query", stageText="正在向路由器查询 Beta 版本")
            started = time.monotonic()
            data = self.client.rpc("devSta.get", "ehr_beta_upgrade", {"action": "version"})
            if time.monotonic() - started > BETA_MAX_SECONDS:
                self._update(kind, state="timed_out", stage="timeout", stageText="版本检测超时", message="版本检测超时")
                return
            result = data if isinstance(data, dict) else {"raw": data}
            next_data = result.get("new") if isinstance(result.get("new"), dict) else {}
            message = _translate_beta_message(next_data.get("msg") or result.get("msg"))
            if isinstance(next_data, dict):
                next_data = dict(next_data)
                next_data["msg"] = message
                result["new"] = next_data
            result["checkedAt"] = _now()
            self._update(kind, state="succeeded", stage="finished", stageText="版本检测完成", message=message, lastRouterResponseAt=_now(), result=result)
        except Exception as exc:
            text = _translate_beta_message(exc)
            self.logger.warning("beta task failed: %s", exc)
            self._update(kind, state="failed", stage="failed", stageText="版本检测失败", message=text)


def install_router_task_manager_patch(hub: Any) -> None:
    if getattr(v099, "_labprobe_task_manager_patch", False):
        return
    original_factory = v099.create_router_blueprint_v099

    def wrapped_factory(check_app_token: Callable[[], bool], logger: Any, config_dir: Any) -> Blueprint:
        captured: Dict[str, Any] = {}
        original_constructor = v099.ReliableRuijieRouterClient

        def capture_client(*args: Any, **kwargs: Any) -> Any:
            client = original_constructor(*args, **kwargs)
            captured["client"] = client
            return client

        v099.ReliableRuijieRouterClient = capture_client
        try:
            bp = original_factory(check_app_token, logger, config_dir)
        finally:
            v099.ReliableRuijieRouterClient = original_constructor
        client = captured.get("client")
        if client is None:
            raise RuntimeError("router task manager client capture failed")
        manager = RouterTaskManager(hub, client, logger)
        hub.ROUTER_TASK_MANAGER = manager

        @bp.get("/tasks/<kind>")
        def task_get(kind: str):
            if kind not in {"nat", "diagnostic", "beta"}:
                return jsonify({"ok": False, "error": "未知任务类型"}), 404
            return jsonify({"ok": True, "data": manager.snapshot(kind)})

        @bp.post("/tasks/<kind>")
        def task_start(kind: str):
            if kind == "nat":
                data = manager.start_nat(request.get_json(silent=True) or {})
            elif kind == "diagnostic":
                data = manager.start_diagnostic()
            elif kind == "beta":
                data = manager.start_beta()
            else:
                return jsonify({"ok": False, "error": "未知任务类型"}), 404
            return jsonify({"ok": True, "data": data}), 202

        return bp

    v099.create_router_blueprint_v099 = wrapped_factory
    v099._labprobe_task_manager_patch = True
