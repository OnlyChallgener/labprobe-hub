"""Command queue and public-model validation for Child Internet Phase 2A.

The Hub deliberately knows nothing about UCI section names or raw sniffer
objects.  It transports stable Child Guard operations over the existing
Hub/Relay command polling channel and returns the adapter's normalized result.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


_UID_RE = re.compile(r"^[A-Za-z0-9_-]{6,128}$")
_PLAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,128}$")
_RDPI_ID_RE = re.compile(r"^\d+-\d+-\d+-\d+$")
_TIME_RE = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
_WEEKDAYS = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
_WEEKDAY_NUMBERS = {"1": "mon", "2": "tue", "3": "wed", "4": "thu", "5": "fri", "6": "sat", "7": "sun"}
_MODES = {"internet_window", "app_allowlist", "app_blocklist"}
_ACTIONS = {
    "get_capabilities",
    "get_users",
    "get_plans",
    "get_runtime_state",
    "get_usage",
    "get_usage_stats",
    "list_devices",
    "create_plan",
    "update_plan",
    "delete_plan",
    "set_plan_enabled",
    "add_device",
    "remove_device",
    "pause_device",
    "resume_device",
}


class ChildGuardValidationError(ValueError):
    """Raised before a malformed command can reach a router."""


def _now_text() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _read_json(path: Path, fallback: Any) -> Any:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return fallback


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def validate_uid(value: Any) -> str:
    uid = str(value or "").strip()
    if not _UID_RE.fullmatch(uid):
        raise ChildGuardValidationError("invalid device uid")
    return uid


def router_alias(value: Any) -> str:
    """Normalize router display names so "Ruijie BE72" matches the agent's "BE72".

    Mirrors the alias rules used elsewhere in the Hub; without this the agent
    polls `?router=BE72` while App requests are stored under the display name
    and every command stays pending forever.
    """
    cleaned = str(value or "").strip().casefold()
    for prefix in ("ruijie-", "ruijie_", "ruijie ", "rg-", "rg_"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):].strip("-_ ")
    return cleaned.replace("-", "").replace("_", "").replace(" ", "")


def validate_plan_id(value: Any) -> str:
    plan_id = str(value or "").strip()
    if not _PLAN_ID_RE.fullmatch(plan_id):
        raise ChildGuardValidationError("invalid plan id")
    return plan_id


def expand_application_rdpi_ids(applications: Any) -> List[str]:
    """Flatten catalog families while preserving deterministic first-seen order."""
    if applications is None:
        return []
    if not isinstance(applications, list):
        raise ChildGuardValidationError("applications must be a list")
    result: List[str] = []
    seen = set()
    for application in applications:
        if not isinstance(application, dict):
            raise ChildGuardValidationError("application must be an object")
        values = application.get("rdpiIds", [])
        if not isinstance(values, list):
            raise ChildGuardValidationError("application rdpiIds must be a list")
        for raw in values:
            value = str(raw or "").strip()
            if not _RDPI_ID_RE.fullmatch(value):
                raise ChildGuardValidationError(f"invalid RDPI id: {value}")
            if value not in seen:
                seen.add(value)
                result.append(value)
    return result


def clean_plan(payload: Any, *, plan_id: str = "") -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ChildGuardValidationError("plan body must be an object")
    name = str(payload.get("name") or "上网计划").strip()[:80] or "上网计划"
    mode = str(payload.get("mode") or "internet_window").strip()
    if mode not in _MODES:
        raise ChildGuardValidationError("invalid plan mode")
    start_time = str(payload.get("startTime") or "00:00").strip()
    end_time = str(payload.get("endTime") or "23:59").strip()
    if not _TIME_RE.fullmatch(start_time) or not _TIME_RE.fullmatch(end_time):
        raise ChildGuardValidationError("invalid plan time")
    raw_weekdays = payload.get("weekdays", [])
    if not isinstance(raw_weekdays, list):
        raise ChildGuardValidationError("weekdays must be a list")
    weekdays: List[str] = []
    for raw in raw_weekdays:
        value = str(raw or "").strip().lower()
        value = _WEEKDAY_NUMBERS.get(value, value)
        if value not in _WEEKDAYS:
            raise ChildGuardValidationError(f"invalid weekday: {value}")
        if value not in weekdays:
            weekdays.append(value)
    if not weekdays:
        raise ChildGuardValidationError("at least one weekday is required")

    applications = payload.get("applications", [])
    rdpi_ids = expand_application_rdpi_ids(applications)
    if mode in {"app_allowlist", "app_blocklist"} and not rdpi_ids:
        raise ChildGuardValidationError("application plan requires at least one RDPI id")

    public_id = plan_id or str(payload.get("id") or "").strip()
    if public_id:
        public_id = validate_plan_id(public_id)
    clean_apps = []
    for app in applications:
        clean_apps.append({
            "id": str(app.get("id") or "").strip()[:128],
            "name": str(app.get("name") or "").strip()[:120],
            "rdpiIds": [str(item).strip() for item in app.get("rdpiIds", [])],
        })
    return {
        **({"id": public_id} if public_id else {}),
        "name": name,
        "enabled": bool(payload.get("enabled", True)),
        "startTime": start_time,
        "endTime": end_time,
        "weekdays": weekdays,
        "mode": mode,
        "applications": clean_apps,
        "applicationRdpiIds": rdpi_ids,
        "deviceMac": str(payload.get("deviceMac") or "").strip().lower()[:32],
        "deviceName": str(payload.get("deviceName") or "").strip()[:120],
    }


@dataclass(frozen=True)
class CommandResult:
    state: str
    result: Dict[str, Any]
    error: str = ""


class ChildGuardCommandStore:
    """Small durable queue using the same polling/ack pattern as other Agent jobs."""

    def __init__(self, data_dir: Path):
        self.commands_path = Path(data_dir) / "child_guard_commands.json"
        self.lock = threading.RLock()
        self.changed = threading.Condition(self.lock)

    @staticmethod
    def canonical_router(value: Any) -> str:
        router = str(value or "router").strip()
        return router[:128] or "router"

    def _load(self) -> List[Dict[str, Any]]:
        document = _read_json(self.commands_path, {"commands": []})
        rows = document.get("commands", []) if isinstance(document, dict) else []
        return [row for row in rows if isinstance(row, dict)]

    def _save(self, rows: Iterable[Dict[str, Any]]) -> None:
        _write_json(self.commands_path, {"commands": list(rows)[-500:]})

    def enqueue(self, router: Any, action: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if action not in _ACTIONS:
            raise ChildGuardValidationError("unsupported child guard action")
        command = {
            "id": secrets.token_hex(12),
            "router": self.canonical_router(router),
            "action": action,
            "payload": payload if isinstance(payload, dict) else {},
            "status": "pending",
            "attempts": 0,
            "createdAt": _now_text(),
            "createdEpoch": int(time.time()),
        }
        with self.changed:
            rows = self._load()
            rows.append(command)
            self._save(rows)
            self.changed.notify_all()
        return command

    def take(self, router: Any, limit: int = 10) -> List[Dict[str, Any]]:
        canonical = self.canonical_router(router)
        canonical_alias = router_alias(canonical)
        selected: List[Dict[str, Any]] = []
        now = int(time.time())
        with self.lock:
            rows = self._load()
            changed = False
            for command in rows:
                if router_alias(command.get("router")) != canonical_alias:
                    continue
                status = command.get("status")
                created = int(command.get("createdEpoch") or 0)
                if status == "pending" and created and now - created > 600:
                    command.update({
                        "status": "failed",
                        "finishedAt": _now_text(),
                        "error": "stale command expired before delivery",
                        "result": {"ok": False, "errorCode": "stale_command"},
                    })
                    changed = True
                    continue
                status = command.get("status")
                age = now - int(command.get("deliveredEpoch") or 0)
                attempts = int(command.get("attempts") or 0)
                retry = status == "delivered" and age >= 20 and attempts < 3
                if status == "delivered" and age >= 20 and attempts >= 3:
                    command.update({
                        "status": "failed",
                        "finishedAt": _now_text(),
                        "error": "delivery timeout after 3 attempts",
                        "result": {"ok": False, "errorCode": "delivery_timeout"},
                    })
                    changed = True
                    continue
                if status != "pending" and not retry:
                    continue
                command.update({
                    "status": "delivered",
                    "deliveredAt": _now_text(),
                    "deliveredEpoch": now,
                    "attempts": attempts + 1,
                })
                selected.append({
                    "id": command["id"],
                    "action": command["action"],
                    "payload": command.get("payload", {}),
                    "createdAt": command["createdAt"],
                })
                changed = True
                if len(selected) >= max(1, min(20, int(limit or 10))):
                    break
            if changed:
                self._save(rows)
        return selected

    def acknowledge(self, router: Any, acknowledgements: Any) -> int:
        canonical = self.canonical_router(router)
        canonical_alias = router_alias(canonical)
        if not isinstance(acknowledgements, list):
            return 0
        ack_map = {
            str(item.get("id") or ""): item
            for item in acknowledgements
            if isinstance(item, dict) and item.get("id")
        }
        count = 0
        with self.changed:
            rows = self._load()
            for command in rows:
                if router_alias(command.get("router")) != canonical_alias:
                    continue
                acknowledgement = ack_map.get(str(command.get("id") or ""))
                if not acknowledgement or command.get("status") not in {"pending", "delivered"}:
                    continue
                result = acknowledgement.get("result")
                result = result if isinstance(result, dict) else {}
                ok = bool(acknowledgement.get("ok")) and bool(result.get("ok", True))
                command.update({
                    "status": "done" if ok else "failed",
                    "result": result,
                    "finishedAt": _now_text(),
                })
                if not ok:
                    command["error"] = str(
                        acknowledgement.get("error") or result.get("error") or "agent reported failure"
                    )[:500]
                count += 1
            if count:
                self._save(rows)
                self.changed.notify_all()
        return count

    def result(self, command_id: str) -> Optional[CommandResult]:
        with self.lock:
            command = next(
                (item for item in reversed(self._load()) if item.get("id") == command_id),
                None,
            )
        if not command:
            return None
        value = command.get("result")
        return CommandResult(
            state=str(command.get("status") or "missing"),
            result=value if isinstance(value, dict) else {},
            error=str(command.get("error") or ""),
        )

    def wait(self, command_id: str, timeout_seconds: float = 35.0) -> CommandResult:
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        with self.changed:
            while True:
                current = self.result(command_id)
                if current is None:
                    return CommandResult("missing", {}, "command not found")
                if current.state in {"done", "failed"}:
                    return current
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return CommandResult("timeout", {}, "router did not finish the command in time")
                self.changed.wait(timeout=min(remaining, 0.5))
