"""Durable device snapshots, daily rollups and summary enrichment.

The two-second APP realtime lane is intentionally memory-only.  This patch adds a
separate full user_list ingestion path that is always sampled by LabRelay at a
low cadence.  Only this authoritative path updates device history, daily online
time, traffic counters and daily summaries.
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import jsonify, request


ROLLUP_RETENTION_DAYS = 120
EMPTY_CONFIRMATIONS = 2


def _integer(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(float(str(value).strip())))
    except (TypeError, ValueError):
        return default


def _clean(hub: Any, value: Any) -> str:
    return hub.clean_saved_value(value)


def _device_map(hub: Any, rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {
        hub.norm_mac(row.get("mac")): row
        for row in rows
        if isinstance(row, dict) and hub.norm_mac(row.get("mac"))
    }


def _traffic_counter(row: Dict[str, Any], *keys: str) -> int:
    for key in keys:
        if key in row and row.get(key) not in (None, ""):
            return _integer(row.get(key))
    return 0


def _advance_counter(entry: Dict[str, Any], field: str, current: int) -> None:
    """Accumulate a monotonic daily counter and survive a router counter reset."""
    last_key = f"last{field[0].upper()}{field[1:]}Counter"
    total_key = f"{field}Bytes"
    last = _integer(entry.get(last_key))
    total = _integer(entry.get(total_key))
    if last <= 0:
        total = max(total, current)
    elif current >= last:
        total += current - last
    else:
        # Router reboot/counter reset: the new counter is additional traffic.
        total += current
    entry[last_key] = current
    entry[total_key] = total


class DurableDeviceHistory:
    def __init__(self, hub: Any):
        self.hub = hub
        self.logger = hub.LOGGER
        self.lock = threading.RLock()
        self.rollup_path: Path = hub.DAILY_FILE
        self.health_path: Path = Path(hub.DATA_DIR) / "device_snapshot_health.json"
        self.empty_streak = 0
        self.last_snapshot_at = ""
        self.last_error = ""
        self._load_health()

    def _load_health(self) -> None:
        root = self.hub.load_json(self.health_path, {})
        if isinstance(root, dict):
            self.empty_streak = _integer(root.get("emptyStreak"))
            self.last_snapshot_at = _clean(self.hub, root.get("lastSnapshotAt"))
            self.last_error = _clean(self.hub, root.get("lastError"))

    def _save_health(self, *, accepted: bool, count: int, error: str = "") -> None:
        if error:
            self.last_error = error
        elif accepted:
            self.last_error = ""
            self.last_snapshot_at = self.hub.now_str()
        self.hub.save_json(self.health_path, {
            "accepted": accepted,
            "onlineDeviceCount": count,
            "emptyStreak": self.empty_streak,
            "lastSnapshotAt": self.last_snapshot_at,
            "lastError": self.last_error,
            "updatedAt": self.hub.now_str(),
        })

    def _load_rollups(self) -> Dict[str, Any]:
        root = self.hub.load_json(self.rollup_path, {})
        if not isinstance(root, dict):
            root = {}
        days = root.get("days")
        if not isinstance(days, dict):
            # Preserve an old document without treating unrelated keys as dates.
            days = {}
        return {"version": 2, "days": days, "updatedAt": root.get("updatedAt", "")}

    def _save_rollups(self, root: Dict[str, Any]) -> None:
        days = root.get("days") if isinstance(root.get("days"), dict) else {}
        for day in sorted(days)[:-ROLLUP_RETENTION_DAYS]:
            days.pop(day, None)
        root["days"] = days
        root["version"] = 2
        root["updatedAt"] = self.hub.now_str()
        self.hub.save_json(self.rollup_path, root)

    def _update_rollup(
        self,
        online: List[Dict[str, Any]],
        previous_online: Dict[str, Dict[str, Any]],
        now: datetime,
    ) -> None:
        day = now.date().isoformat()
        stamp = now.strftime("%Y-%m-%d %H:%M:%S")
        root = self._load_rollups()
        days = root["days"]
        day_row = days.get(day) if isinstance(days.get(day), dict) else {}
        entries = day_row.get("devices") if isinstance(day_row.get("devices"), dict) else {}
        current = _device_map(self.hub, online)

        for mac, dev in current.items():
            entry = entries.get(mac) if isinstance(entries.get(mac), dict) else {}
            entry["mac"] = mac
            entry["name"] = _clean(self.hub, dev.get("name")) or _clean(self.hub, entry.get("name")) or mac
            entry["ip"] = _clean(self.hub, dev.get("ip") or dev.get("lastIp")) or _clean(self.hub, entry.get("ip"))
            entry["online"] = True
            entry["onlineSince"] = _clean(self.hub, dev.get("onlineSince")) or _clean(self.hub, entry.get("onlineSince")) or stamp
            entry["firstSeenAt"] = _clean(self.hub, entry.get("firstSeenAt")) or stamp
            entry["lastSeenAt"] = stamp
            entry["offlineAt"] = ""
            entry["onlineDurationSec"] = max(
                _integer(entry.get("onlineDurationSec")),
                _integer(dev.get("todayOnlineDurationSec")),
            )
            upload = _traffic_counter(dev, "todayUpload", "dailyUpBytes")
            download = _traffic_counter(dev, "todayDownload", "dailyDownBytes")
            _advance_counter(entry, "upload", upload)
            _advance_counter(entry, "download", download)
            entries[mac] = entry

        for mac, old in previous_online.items():
            if mac in current:
                continue
            entry = entries.get(mac) if isinstance(entries.get(mac), dict) else {}
            entry["mac"] = mac
            entry["name"] = _clean(self.hub, old.get("name")) or _clean(self.hub, entry.get("name")) or mac
            entry["ip"] = _clean(self.hub, old.get("ip") or old.get("lastIp")) or _clean(self.hub, entry.get("ip"))
            entry["online"] = False
            entry["onlineSince"] = _clean(self.hub, old.get("onlineSince")) or _clean(self.hub, entry.get("onlineSince"))
            entry["lastSeenAt"] = _clean(self.hub, old.get("lastSeenAt")) or _clean(self.hub, entry.get("lastSeenAt"))
            entry["offlineAt"] = stamp
            entry["onlineDurationSec"] = max(
                _integer(entry.get("onlineDurationSec")),
                _integer(old.get("todayOnlineDurationSec")),
            )
            entries[mac] = entry

        day_row.update({"date": day, "updatedAt": stamp, "devices": entries})
        days[day] = day_row
        self._save_rollups(root)

    def _add_transition_event(
        self,
        typ: str,
        device: Dict[str, Any],
        stamp: str,
        previous: Optional[Dict[str, Any]] = None,
    ) -> None:
        previous = previous or {}
        online = typ == "device_online"
        name = _clean(self.hub, device.get("name")) or _clean(self.hub, previous.get("name")) or self.hub.norm_mac(device.get("mac")) or "未知设备"
        online_since = _clean(self.hub, device.get("onlineSince")) or _clean(self.hub, previous.get("onlineSince")) or (stamp if online else "")
        offline_at = "" if online else stamp
        duration = ""
        if not online:
            duration = self.hub.duration_between(online_since, offline_at)
            if not duration:
                duration = _clean(self.hub, previous.get("todayOnlineDurationText") or previous.get("onlineDurationText"))
        self.hub.add_event({
            "type": typ,
            "source": "durable_device_snapshot",
            "title": f"{name} {'上线' if online else '离线'}",
            "name": name,
            "mac": self.hub.norm_mac(device.get("mac") or previous.get("mac")),
            "createdAt": stamp,
            "time": stamp,
            "ip": _clean(self.hub, device.get("ip") or device.get("lastIp") or previous.get("ip") or previous.get("lastIp")),
            "lastIp": _clean(self.hub, device.get("ip") or device.get("lastIp") or previous.get("ip") or previous.get("lastIp")),
            "rssi": device.get("rssi", previous.get("rssi")),
            "band": device.get("band", previous.get("band")),
            "rxrate": device.get("rxrate", previous.get("rxrate")),
            "ssid": device.get("ssid", previous.get("ssid")),
            "connectType": device.get("connectType", previous.get("connectType")),
            "onlineSince": online_since,
            "offlineAt": offline_at,
            "onlineDurationText": duration,
            "oldValue": "offline" if online else "online",
            "newValue": "online" if online else "offline",
            "device": device if online else previous,
        })

    def ingest(self, payload: Any) -> Dict[str, Any]:
        with self.lock:
            now = datetime.now()
            stamp = now.strftime("%Y-%m-%d %H:%M:%S")
            try:
                online, total = self.hub.parse_ruijie_devices(payload)
            except Exception as exc:
                self._save_health(accepted=False, count=0, error=str(exc))
                raise

            previous_state = self.hub.load_json(
                self.hub.DEVICES_FILE,
                {"online": [], "watched": [], "updatedAt": None},
            )
            if not isinstance(previous_state, dict):
                previous_state = {"online": [], "watched": [], "updatedAt": None}
            previous_rows = previous_state.get("online") if isinstance(previous_state.get("online"), list) else []
            previous_online = _device_map(self.hub, previous_rows)

            if not online and previous_online:
                self.empty_streak += 1
                if self.empty_streak < EMPTY_CONFIRMATIONS:
                    self._save_health(accepted=False, count=0, error="empty snapshot awaiting confirmation")
                    return {
                        "accepted": False,
                        "deferredEmpty": True,
                        "emptyStreak": self.empty_streak,
                        "onlineDeviceCount": len(previous_online),
                    }
            else:
                self.empty_streak = 0

            online = self.hub.update_daily_online_durations(online, now)
            try:
                neighbors = self.hub.parse_ipv6_neighbors(payload)
                self.hub.merge_ipv6_neighbors_to_archive(neighbors)
            except Exception:
                self.logger.debug("full device snapshot IPv6 merge deferred", exc_info=True)

            archive = self.hub.load_device_archive()
            hydrated: List[Dict[str, Any]] = []
            for dev in online:
                current = self.hub.hydrate_device_with_archive(dev, archive)
                current["online"] = True
                current["lastSeenAt"] = stamp
                current["offlineAt"] = None
                hydrated.append(current)
            hydrated = self.hub.attach_hub_local_ipv6_to_nas_devices(hydrated)
            current_online = _device_map(self.hub, hydrated)

            for mac, dev in current_online.items():
                if mac not in previous_online:
                    self._add_transition_event("device_online", dev, stamp)
            for mac, old in previous_online.items():
                if mac in current_online:
                    continue
                offline = dict(old)
                offline["online"] = False
                offline["lastIp"] = _clean(self.hub, old.get("ip") or old.get("lastIp"))
                offline["ip"] = None
                offline["offlineAt"] = stamp
                offline["lastChangedAt"] = stamp
                self._add_transition_event("device_offline", offline, stamp, old)
                self.hub.archive_device_snapshot(offline)

            for dev in hydrated:
                self.hub.archive_device_snapshot(dev)

            watched = self.hub.build_watched_devices(hydrated)
            devices_state = {
                "source": "labrelay_durable_snapshot",
                "updatedAt": stamp,
                "onlineDeviceCount": len(hydrated),
                "total": total,
                "online": hydrated,
                "watched": watched,
            }
            self.hub.save_json(self.hub.DEVICES_FILE, devices_state)

            state = self.hub.load_json(self.hub.STATE_FILE, {})
            if not isinstance(state, dict):
                state = {}
            state.setdefault("router", {})
            state["router"].update({
                "name": self.hub.primary_router_name(),
                "mode": "labrelay_durable_snapshot",
                "onlineDeviceCount": len(hydrated),
                "total": total,
                "devicesUpdatedAt": stamp,
            })
            state["devices"] = watched
            state["updatedAt"] = stamp
            self.hub.save_json(self.hub.STATE_FILE, state)
            self._update_rollup(hydrated, previous_online, now)
            self._save_health(accepted=True, count=len(hydrated))
            return {
                "accepted": True,
                "onlineDeviceCount": len(hydrated),
                "watchedCount": len(watched),
                "updatedAt": stamp,
            }

    def day_devices(self, day: str) -> Dict[str, Dict[str, Any]]:
        root = self._load_rollups()
        row = root.get("days", {}).get(day)
        if not isinstance(row, dict):
            return {}
        devices = row.get("devices")
        return devices if isinstance(devices, dict) else {}

    def enrich_daily(self, result: Dict[str, Any], day: str) -> Dict[str, Any]:
        rows = self.day_devices(day)
        if not rows:
            return result
        result = dict(result or {})
        sections = dict(result.get("sections") or {})
        existing = sections.get("devices") if isinstance(sections.get("devices"), list) else []
        by_name = {
            _clean(self.hub, item.get("name")).lower(): dict(item)
            for item in existing
            if isinstance(item, dict) and _clean(self.hub, item.get("name"))
        }
        upload_total = 0
        download_total = 0
        active_count = 0
        for mac, entry in rows.items():
            name = _clean(self.hub, entry.get("name")) or mac
            key = name.lower()
            item = by_name.get(key, {"name": name, "online": 0, "offline": 0})
            seconds = _integer(entry.get("onlineDurationSec"))
            upload = _integer(entry.get("uploadBytes"))
            download = _integer(entry.get("downloadBytes"))
            upload_total += upload
            download_total += download
            if bool(entry.get("online")):
                active_count += 1
            duration_text = self.hub.human_duration_precise(seconds)
            traffic_text = f"上传 {self.hub.human_bytes(upload)} · 下载 {self.hub.human_bytes(download)}"
            details = []
            if duration_text:
                details.append(f"在线 {duration_text}")
            if upload or download:
                details.append(traffic_text)
            if _clean(self.hub, entry.get("ip")):
                details.append(_clean(self.hub, entry.get("ip")))
            transition = f"上线 {item.get('online', 0)} 次 · 下线 {item.get('offline', 0)} 次"
            if details:
                transition += " · " + " · ".join(details)
            item.update({
                "mac": mac,
                "name": name,
                "onlineDurationSec": seconds,
                "onlineDurationText": duration_text,
                "todayUpload": upload,
                "todayDownload": download,
                "trafficText": traffic_text,
                "currentlyOnline": bool(entry.get("online")),
                "onlineSince": _clean(self.hub, entry.get("onlineSince")),
                "offlineAt": _clean(self.hub, entry.get("offlineAt")),
                "lastSeenAt": _clean(self.hub, entry.get("lastSeenAt")),
                "lastIp": _clean(self.hub, entry.get("ip")),
                "text": f"{name}\n{transition}",
            })
            by_name[key] = item
        sections["devices"] = sorted(
            by_name.values(),
            key=lambda item: (
                not bool(item.get("currentlyOnline")),
                -_integer(item.get("todayDownload")) - _integer(item.get("todayUpload")),
                str(item.get("name", "")),
            ),
        )
        summary = dict(result.get("summary") or {})
        summary.update({
            "trackedDevices": len(rows),
            "activeDevices": active_count,
            "trafficUploadBytes": upload_total,
            "trafficDownloadBytes": download_total,
            "hasDurableDeviceSnapshot": True,
        })
        result.update({"date": day, "summary": summary, "sections": sections})
        return result


def install_device_history_patch(hub: Any) -> DurableDeviceHistory:
    existing = getattr(hub, "DURABLE_DEVICE_HISTORY", None)
    if existing is not None:
        return existing

    service = DurableDeviceHistory(hub)
    hub.DURABLE_DEVICE_HISTORY = service

    @hub.app.post("/api/router/devices/snapshot")
    def api_router_devices_snapshot():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad agent token"}), 401
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify({"ok": False, "error": "empty snapshot"}), 400
        try:
            result = service.ingest(payload)
            return jsonify({"ok": True, **result, "time": hub.now_str()})
        except Exception as exc:
            service.logger.warning("durable device snapshot rejected: %s", exc)
            return jsonify({"ok": False, "error": str(exc), "time": hub.now_str()}), 400

    @hub.app.get("/api/router/devices/snapshot/status")
    def api_router_devices_snapshot_status():
        if not hub.check_read_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        health = hub.load_json(service.health_path, {})
        return jsonify({"ok": True, **(health if isinstance(health, dict) else {})})

    original_aggregate_daily = hub.aggregate_daily

    def aggregate_daily(day: str) -> Dict[str, Any]:
        return service.enrich_daily(original_aggregate_daily(day), day)

    hub.aggregate_daily = aggregate_daily
    return service
