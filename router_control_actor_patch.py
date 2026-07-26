"""Priority actor for every router eWeb RPC.

All HTTP/RPC control calls are serialized through one worker. The router-native
WebSocket receiver is not wrapped and therefore cannot be blocked or restarted
by settings reads, background polling, NAT/Beta tasks, or user commands.
"""
from __future__ import annotations

import itertools
import queue
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from flask import has_request_context, request

import router_rpc

PRIORITY_COMMAND = 10
PRIORITY_TASK = 20
PRIORITY_READ = 30
PRIORITY_BACKGROUND = 50


@dataclass(order=True)
class _ActorItem:
    priority: int
    sequence: int
    label: str = field(compare=False)
    callback: Callable[[], Any] = field(compare=False)
    done: threading.Event = field(compare=False, default_factory=threading.Event)
    value: Any = field(compare=False, default=None)
    error: Optional[BaseException] = field(compare=False, default=None)


class RouterControlActor:
    def __init__(self) -> None:
        self._queue: queue.PriorityQueue[_ActorItem] = queue.PriorityQueue(maxsize=96)
        self._sequence = itertools.count()
        self._state_lock = threading.RLock()
        self._active_priority: Optional[int] = None
        self._foreground_pending = 0
        self._worker_ident = 0
        self._worker = threading.Thread(target=self._run, name="router-control-actor", daemon=True)
        self._worker.start()

    def _run(self) -> None:
        self._worker_ident = threading.get_ident()
        while True:
            item = self._queue.get()
            with self._state_lock:
                self._active_priority = item.priority
                if item.priority < PRIORITY_BACKGROUND:
                    self._foreground_pending = max(0, self._foreground_pending - 1)
            try:
                item.value = item.callback()
            except BaseException as exc:
                item.error = exc
            finally:
                with self._state_lock:
                    self._active_priority = None
                item.done.set()
                self._queue.task_done()

    def submit(self, priority: int, label: str, callback: Callable[[], Any]) -> Any:
        if threading.get_ident() == self._worker_ident:
            return callback()
        with self._state_lock:
            if priority >= PRIORITY_BACKGROUND and (
                self._active_priority is not None
                or self._foreground_pending > 0
                or not self._queue.empty()
            ):
                raise router_rpc.RouterRpcError(
                    "后台同步已让位于用户操作",
                    "BACKGROUND_DEFERRED",
                    503,
                )
            if priority < PRIORITY_BACKGROUND:
                self._foreground_pending += 1
        item = _ActorItem(priority, next(self._sequence), label, callback)
        try:
            self._queue.put(item, timeout=1.0)
        except queue.Full as exc:
            with self._state_lock:
                if priority < PRIORITY_BACKGROUND:
                    self._foreground_pending = max(0, self._foreground_pending - 1)
            raise router_rpc.RouterRpcError(
                "路由控制队列繁忙，请稍后重试",
                "CONTROL_QUEUE_BUSY",
                503,
            ) from exc
        timeout = 35.0 if priority <= PRIORITY_TASK else 25.0
        if not item.done.wait(timeout):
            raise router_rpc.RouterRpcError(
                "路由控制任务等待超时",
                "CONTROL_QUEUE_TIMEOUT",
                504,
            )
        if item.error is not None:
            raise item.error
        return item.value

    def snapshot(self) -> dict[str, Any]:
        with self._state_lock:
            return {
                "activePriority": self._active_priority,
                "foregroundPending": self._foreground_pending,
                "queued": self._queue.qsize(),
            }


ACTOR = RouterControlActor()


def _request_priority() -> int:
    if not has_request_context():
        # NAT continues in a dedicated Hub worker after the HTTP 202 response. It
        # remains a user-started task, not disposable dashboard/device polling.
        thread_name = threading.current_thread().name.lower()
        if thread_name.startswith("router-nat-diagnostic-"):
            return PRIORITY_TASK
        return PRIORITY_BACKGROUND
    method = str(request.method or "GET").upper()
    path = str(request.path or "")
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        if any(token in path for token in ("nat-diagnostic", "diagnostic", "beta-upgrade")):
            return PRIORITY_TASK
        return PRIORITY_COMMAND
    if any(token in path for token in ("nat-diagnostic", "diagnostic", "beta-upgrade")):
        return PRIORITY_TASK
    return PRIORITY_READ


def install_router_control_actor_patch() -> None:
    if getattr(router_rpc, "_labprobe_control_actor_patch", False):
        return
    original_rpc = router_rpc.RuijieRouterClient.rpc
    original_batch = router_rpc.RuijieRouterClient.batch

    def rpc(self: Any, method: str, module: str, data: Any = None, no_parse: bool = False) -> Any:
        priority = _request_priority()
        label = f"rpc:{method}:{module}"
        return ACTOR.submit(
            priority,
            label,
            lambda: original_rpc(self, method, module, data, no_parse),
        )

    def batch(self: Any, calls: Any) -> Any:
        priority = _request_priority()
        rows = list(calls)
        return ACTOR.submit(
            priority,
            f"batch:{len(rows)}",
            lambda: original_batch(self, rows),
        )

    router_rpc.RuijieRouterClient.rpc = rpc
    router_rpc.RuijieRouterClient.batch = batch
    router_rpc.ROUTER_CONTROL_ACTOR = ACTOR
    router_rpc._labprobe_control_actor_patch = True
