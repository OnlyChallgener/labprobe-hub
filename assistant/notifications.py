"""Token-free assistant inbox for watched-device and daily summary messages."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from .storage import AIStore

SHANGHAI = timezone(timedelta(hours=8), name="Asia/Shanghai")


TERMINAL_TASK_STATES = {"succeeded", "completed", "failed", "timed_out"}
ACTIVE_TASK_STATES = {"", "idle", "queued", "running"}

TASK_KINDS = (("nat", "路由器 NAT 检测"), ("diagnostic", "路由器网络自检"))


class AssistantNotificationService:
    def __init__(self, hub_runtime: Any, store: AIStore, logger: Any):
        self.hub = hub_runtime
        self.store = store
        self.logger = logger
        self.stop_event = threading.Event()
        self._task_states: Dict[str, str] = {}
        self._recent_device_events: Dict[str, float] = {}
        self.thread = threading.Thread(target=self._run, name="assistant-notifications", daemon=True)

    def _is_watched(self, event: Dict[str, Any]) -> bool:
        watched = self.hub.cfg_get("watched_devices", []) or []
        event_mac = self.hub.norm_mac(event.get("mac"))
        event_name = str(event.get("name") or "").strip().lower()
        for item in watched:
            if not isinstance(item, dict):
                continue
            if event_mac and self.hub.norm_mac(item.get("mac")) == event_mac:
                return True
            if event_name and str(item.get("name") or "").strip().lower() == event_name:
                return True
        return False

    def publish_event(self, event: Dict[str, Any]) -> None:
        if not isinstance(event, dict) or event.get("type") not in {"device_online", "device_offline"}:
            return
        if not self._is_watched(event):
            return
        # 抖动保护：同一设备 120 秒内只投递第一次状态变化，避免
        # online/offline 快速交替时连续刷屏。
        identity = self.hub.norm_mac(event.get("mac")) or str(event.get("name") or "").strip().lower()
        now_ts = time.monotonic()
        previous_ts = self._recent_device_events.get(identity)
        if previous_ts is not None and now_ts - previous_ts < 120:
            return
        self._recent_device_events[identity] = now_ts
        online = event.get("type") == "device_online"
        name = str(event.get("name") or event.get("mac") or "关注设备")
        at = str(event.get("createdAt") or event.get("time") or self.hub.now_str())
        address = str(event.get("ip") or event.get("lastIp") or "").strip()
        title = f"{name}{'上线' if online else '离线'}"
        details = [at]
        if address:
            details.append(address)
        if not online and event.get("onlineDurationText"):
            details.append("本次在线 " + str(event["onlineDurationText"]))
        event_id = event.get("id") or f"{event.get('type')}:{event.get('mac')}:{at}"
        notification_id = self.store.add_notification(
            "device", title, title + " · " + " · ".join(details),
            f"event:{event_id}", {"event": event},
        )

    def publish_daily(self, day: str) -> None:
        daily = self.hub.aggregate_daily(day)
        summary = daily.get("summary") if isinstance(daily, dict) else {}
        summary = summary if isinstance(summary, dict) else {}
        ai_usage = daily.get("aiUsage") if isinstance(daily, dict) else {}
        ai_usage = ai_usage if isinstance(ai_usage, dict) else {}
        content = (
            f"{day} 每日记录 · 设备变化 {int(summary.get('deviceChanges') or 0)} 次"
            f"（上线 {int(summary.get('deviceOnline') or 0)} / 下线 {int(summary.get('deviceOffline') or 0)}）"
            f" · 网络变化 {int(summary.get('networkChanges') or 0)} 次"
            f" · AI {int(ai_usage.get('requests') or 0)} 次 / {int(ai_usage.get('total_tokens') or 0)} Token"
        )
        notification_id = self.store.add_notification(
            "daily", "22:30 每日网络记录", content, f"daily:{day}", {"daily": daily},
        )
    def _publish_task_transitions(self) -> None:
        """Notify when a router NAT/diagnostic task reaches a terminal state.

        The chat flow answers within its request window, but the user may have
        navigated away; this turns the finished task into an inbox notification
        that reaches the APP through the same channel as device events.
        """
        manager = getattr(self.hub, "ROUTER_TASK_MANAGER", None)
        snapshot = getattr(manager, "snapshot", None)
        if not callable(snapshot):
            return
        for kind, label in TASK_KINDS:
            try:
                task = snapshot(kind)
            except Exception:
                continue
            if not isinstance(task, dict):
                continue
            state = str(task.get("state") or "")
            previous = self._task_states.get(kind)
            self._task_states[kind] = state
            if previous is None or state == previous:
                continue
            if state in ACTIVE_TASK_STATES or previous not in ACTIVE_TASK_STATES:
                continue
            if state not in TERMINAL_TASK_STATES:
                continue
            # Imported lazily: assistant.api imports this module at startup.
            from .api import nat_diagnostic_content, router_diagnostic_content

            content = (nat_diagnostic_content(task) if kind == "nat"
                       else router_diagnostic_content(task)).strip()[:600]
            suffix = {"failed": "失败", "timed_out": "超时"}.get(state, "完成")
            identity = str(task.get("taskId") or task.get("finishedAt") or task.get("updatedAt") or "")
            self.store.add_notification(
                "task", f"{label}{suffix}", content,
                f"task:{kind}:{identity}:{state}", {"task": task},
            )

    def start(self) -> None:
        original = getattr(self.hub, "add_event", None)
        if callable(original) and not getattr(original, "_assistant_notifications_wrapped", False):
            service = self

            def wrapped(event: Dict[str, Any]):
                saved = original(event)
                try:
                    service.publish_event(saved)
                except Exception:
                    if service.logger:
                        service.logger.debug("assistant device notification deferred", exc_info=True)
                return saved

            wrapped._assistant_notifications_wrapped = True
            self.hub.add_event = wrapped
        if not self.thread.is_alive():
            self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.wait(20):
            try:
                self._publish_task_transitions()
            except Exception:
                if self.logger:
                    self.logger.debug("assistant task notification deferred", exc_info=True)
            try:
                now = datetime.now(SHANGHAI)
                if (now.hour, now.minute) >= (22, 30):
                    self.publish_daily(now.date().isoformat())
            except Exception:
                if self.logger:
                    self.logger.debug("assistant daily notification deferred", exc_info=True)
