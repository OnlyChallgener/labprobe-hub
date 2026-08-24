"""Authoritative five-second terminal snapshot synchronization.

The router web UI reads ``devSta.get/user_list`` with ``dataType=timely`` every
five seconds. This service uses the same read through Hub's low-priority router
control actor, publishes the complete normalized snapshot over the existing WSS,
and lets the durable history service write to disk at a lower cadence.

A failed or transiently empty poll never clears the last good APP snapshot.
User commands always win because background RPCs are deferred by the actor.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import date
from typing import Any, Dict, List, Set

from flask import jsonify


POLL_INTERVAL_SECONDS = max(2.0, float(os.environ.get("ROUTER_DEVICE_LIVE_POLL_SEC", "2")))
PERSIST_INTERVAL_SECONDS = max(
    POLL_INTERVAL_SECONDS,
    float(os.environ.get("ROUTER_DEVICE_PERSIST_SEC", "30")),
)
EMPTY_CONFIRMATIONS = 2


def _as_int(value: Any) -> int:
    try:
        return max(0, int(float(str(value or "0").strip())))
    except (TypeError, ValueError):
        return 0


def _unwrap_user_list(value: Any) -> Dict[str, Any]:
    """Accept direct RPC, cmdArr and nested string response shapes."""
    current = value
    for _ in range(8):
        if isinstance(current, str):
            text = current.strip()
            if not text:
                return {"list": [], "total": 0}
            current = json.loads(text)
            continue
        if isinstance(current, list):
            match = next(
                (
                    row
                    for row in current
                    if isinstance(row, dict) and isinstance(row.get("list"), list)
                ),
                None,
            )
            if match is not None:
                current = match
                continue
            if len(current) == 1:
                current = current[0]
                continue
            return {"list": [], "total": 0}
        if not isinstance(current, dict):
            return {"list": [], "total": 0}
        if isinstance(current.get("list"), list):
            return current
        data = current.get("data")
        if data is not None:
            current = data
            continue
        result = current.get("result")
        if result is not None:
            current = result
            continue
        return {"list": [], "total": 0}
    return {"list": [], "total": 0}


class RouterDeviceLiveSync:
    def __init__(self, hub: Any, client: Any, *, start: bool = True):
        self.hub = hub
        self.client = client
        self.logger = hub.LOGGER
        self.lock = threading.RLock()
        self.latest: Dict[str, Any] = {}
        self.last_persist_at = 0.0
        self.last_success_at = 0.0
        self.last_error = ""
        self.last_error_log_at = 0.0
        self.empty_streak = 0
        self.last_macs: Set[str] = set()
        if start:
            threading.Thread(
                target=self._worker,
                name="router-device-live-sync",
                daemon=True,
            ).start()

    def _hydrate(self, payload: Dict[str, Any]) -> tuple[List[Dict[str, Any]], int]:
        online, total = self.hub.parse_ruijie_devices(payload)
        archive = self.hub.load_device_archive()
        stamp = self.hub.now_str()
        now_epoch = int(time.time())
        today = date.today().isoformat()
        with self.lock:
            previous_epoch = int(self.latest.get("sampleEpochMs") or 0) // 1000
            previous_rows = self.latest.get("devices") if isinstance(self.latest.get("devices"), list) else []
            previous = {
                self.hub.norm_mac(row.get("mac")): row
                for row in previous_rows
                if isinstance(row, dict) and self.hub.norm_mac(row.get("mac"))
            }
        rows: List[Dict[str, Any]] = []
        for device in online:
            row = self.hub.hydrate_device_with_archive(device, archive)
            raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
            mac = self.hub.norm_mac(row.get("mac"))
            old = previous.get(mac, {})
            router_seconds = _as_int(row.get("todayOnlineDurationSec"))
            old_seconds = _as_int(old.get("todayOnlineDurationSec")) if old.get("todayOnlineDate") == today else 0
            observed_delta = max(0, min(30, now_epoch - previous_epoch)) if previous_epoch else 0
            observed_seconds = old_seconds + observed_delta if old else 0
            seconds = max(router_seconds, observed_seconds)
            row.update(
                {
                    "online": True,
                    "lastSeenAt": stamp,
                    "offlineAt": None,
                    "uploadBps": _as_int(raw.get("flowUp")),
                    "downloadBps": _as_int(raw.get("flowDown")),
                    "connectionCount": _as_int(raw.get("flow_cnt")),
                    "todayOnlineDurationSec": seconds,
                    "todayOnlineDurationText": self.hub.human_duration(seconds),
                    "todayOnlineDate": today,
                }
            )
            rows.append(row)
        rows = self.hub.attach_hub_local_ipv6_to_nas_devices(rows)
        rows.sort(key=lambda row: self.hub.norm_mac(row.get("mac")))
        return rows, total

    def _frame(
        self,
        rows: List[Dict[str, Any]],
        total: int,
        *,
        confirmed_empty: bool = False,
    ) -> Dict[str, Any]:
        now_ms = int(time.time() * 1000)
        return {
            "ok": True,
            "fullSnapshot": True,
            "accepted": True,
            "confirmedEmpty": bool(confirmed_empty),
            "source": "hub_router_user_list_timely",
            "sampleEpochMs": now_ms,
            "updatedAt": self.hub.now_str(),
            "onlineDeviceCount": len(rows),
            "total": total,
            "devices": rows,
        }

    def _publish(self, frame: Dict[str, Any]) -> None:
        realtime = getattr(self.hub, "ROUTER_REALTIME", None)
        publish = getattr(realtime, "accept_devices_snapshot", None)
        if callable(publish):
            publish(frame)

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return dict(self.latest)

    def status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "ok": True,
                "pollIntervalSeconds": POLL_INTERVAL_SECONDS,
                "persistIntervalSeconds": PERSIST_INTERVAL_SECONDS,
                "lastSuccessAt": int(self.last_success_at),
                "lastPersistAt": int(self.last_persist_at),
                "lastError": self.last_error,
                "onlineDeviceCount": int(self.latest.get("onlineDeviceCount") or 0),
                "sampleEpochMs": int(self.latest.get("sampleEpochMs") or 0),
            }

    def poll_once(self) -> Dict[str, Any]:
        raw = self.client.rpc(
            "devSta.get",
            "user_list",
            {"devType": "all", "dataType": "timely"},
            no_parse=True,
        )
        payload = _unwrap_user_list(raw)
        rows, total = self._hydrate(payload)

        with self.lock:
            previous_non_empty = bool(self.latest.get("devices"))
            confirmed_empty = False
            if not rows and previous_non_empty:
                self.empty_streak += 1
                if self.empty_streak < EMPTY_CONFIRMATIONS:
                    return {
                        "accepted": False,
                        "deferredEmpty": True,
                        "emptyStreak": self.empty_streak,
                    }
                confirmed_empty = True
            else:
                self.empty_streak = 0

            frame = self._frame(rows, total, confirmed_empty=confirmed_empty)
            self.latest = frame
            self.last_success_at = time.time()
            self.last_error = ""
            macs = {self.hub.norm_mac(row.get("mac")) for row in rows if row.get("mac")}
            membership_changed = macs != self.last_macs
            self.last_macs = macs
            persist_due = (
                not self.last_persist_at
                or membership_changed
                or time.time() - self.last_persist_at >= PERSIST_INTERVAL_SECONDS
            )

        self._publish(frame)

        if persist_due:
            history = getattr(self.hub, "DURABLE_DEVICE_HISTORY", None)
            ingest = getattr(history, "ingest", None)
            if callable(ingest):
                # Persist the already-normalized five-second sample. Passing
                # the raw payload here loses online seconds for routers whose
                # user_list has no usable activeTime/onlinetime fields.
                ingest(payload, prepared_online=rows, prepared_total=total)
                with self.lock:
                    self.last_persist_at = time.time()
        return frame

    def _worker(self) -> None:
        while True:
            started = time.monotonic()
            try:
                self.poll_once()
            except Exception as exc:
                text = str(exc)
                with self.lock:
                    self.last_error = text
                # BACKGROUND_DEFERRED is normal: user settings and long tasks win.
                if "BACKGROUND_DEFERRED" not in text and "后台同步已让位" not in text:
                    now = time.time()
                    if now - self.last_error_log_at >= 60:
                        self.last_error_log_at = now
                        self.logger.warning("router terminal live sync deferred/failed: %s", exc)
            elapsed = time.monotonic() - started
            time.sleep(max(0.25, POLL_INTERVAL_SECONDS - elapsed))


def install_router_device_live_sync_patch(hub: Any, client: Any) -> RouterDeviceLiveSync:
    existing = getattr(hub, "ROUTER_DEVICE_LIVE_SYNC", None)
    if existing is not None:
        return existing
    service = RouterDeviceLiveSync(hub, client)
    hub.ROUTER_DEVICE_LIVE_SYNC = service

    @hub.app.get("/api/router/devices/live/status")
    def api_router_devices_live_status():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return jsonify(service.status())

    return service
