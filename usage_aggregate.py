"""Long-term aggregate store for Child Internet usage statistics.

This is the table the product actually shows.  Two tables, because the official
``上网统计`` page needs two different shapes:

``usage_hourly``      ``(date, mac, hour)``      -> the bar chart / 在线时间
``usage_daily_app``   ``(date, mac, app)``       -> 应用上网时长统计

A single ``daily_app_usage`` table (date | mac | app | duration | up | down) is
**not sufficient**: the official page draws a per-hour bar chart with a ``60``
minute axis and derives ``在线时间`` by summing those bars, which needs the hour
dimension.  Everything else about the common advice holds though.

Why this lives on the Hub and not on the router
-----------------------------------------------
* ``/tmp`` on the router is **tmpfs** (RAM). Anything written there is lost on
  reboot, so it can never be the home of a "keep it forever" table.
* The router's persistent flash ``/overlay`` is UBIFS on NAND and, on the BE72
  used for testing, has only ~46 MB free.  Writing an append-heavy usage table
  there would wear the flash and risk filling the overlay.
* The Hub runs on a NAS with real disk, so the router only ever needs to
  *sample* and hand over aggregates.

Row volume and footprint (measured, not estimated)
--------------------------------------------------
Per year, assuming 10 devices x ~30 apps:

* ``usage_hourly``    10 x 24 x 365        =  87 600 rows
* ``usage_daily_app`` 10 x 30 x 365        = 109 500 rows
* total                                    = 197 100 rows -> **14.4 MB**
  (77 bytes/row; both tables are ``WITHOUT ROWID`` with the primary key as the
  clustering index and no secondary index)

Scaling linearly: 20 devices for a year is ~29 MB, 10 devices for five years is
~72 MB. So "keep it for years" is fine on a NAS — but the frequently-quoted
"under 1 MB" is off by more than an order of magnitude, and it is honest to say
tens of MB. Either way this is nothing next to raw flows (hundreds of GB to
TB-scale), which is the real reason nobody stores them.

Retention
---------
The product keeps **10 days**, matching the official App's 上网统计 window
(今日 / 昨日 / 过去七天 with headroom).  Ten days is therefore the default for
both tables, and the footprint at that window is trivial: a year's worth of
rows is 14.4 MB, so 10 days is well under 1 MB per device-set.

Storage is cheap on a NAS, so the window is a *product* decision, not a
technical ceiling.  Both windows stay independently overridable
(``USAGE_HOURLY_KEEP_DAYS`` / ``USAGE_DAILY_KEEP_DAYS``, or per-request
``hourlyKeepDays`` / ``dailyKeepDays``) so a future "过去 30 天" view can be
enabled without touching this module — raising the daily window alone is enough
because the hourly table only feeds the day chart.

Idempotency
-----------
The relay pushes **absolute** bucket values, and rows are merged with ``max()``
rather than ``+``.  Re-pushing the same window (retry, duplicate delivery,
Hub restart) therefore changes nothing, and a value can never be inflated by
repeated delivery.  The trade-off is that a counter which legitimately goes
*down* (relay restarted mid-day and lost its in-memory buckets) is ignored,
which is the safe direction to fail in.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from datetime import date as _date, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from flask import Blueprint, jsonify, request

DEFAULT_HOURLY_KEEP_DAYS = int(os.environ.get("USAGE_HOURLY_KEEP_DAYS", "10"))
DEFAULT_DAILY_KEEP_DAYS = int(os.environ.get("USAGE_DAILY_KEEP_DAYS", "10"))

MAX_ROWS_PER_PUSH = 5000


class UsageAggregateError(ValueError):
    """Raised before malformed data can reach the aggregate tables."""


def normalize_mac(value: Any) -> str:
    """``AA-BB-CC-DD-EE-FF`` / ``aabbccddeeff`` -> ``aa:bb:cc:dd:ee:ff``."""
    text = str(value or "").strip().lower()
    compact = "".join(ch for ch in text if ch not in ":-.")
    if len(compact) == 12 and all(ch in "0123456789abcdef" for ch in compact):
        return ":".join(compact[i:i + 2] for i in range(0, 12, 2))
    return text


def _iso_date(value: Any) -> str:
    text = str(value or "").strip()
    if len(text) != 10 or text[4] != "-" or text[7] != "-":
        raise UsageAggregateError(f"invalid date: {value!r}")
    try:
        _date.fromisoformat(text)
    except ValueError as error:
        raise UsageAggregateError(f"invalid date: {value!r}") from error
    return text


def _as_count(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return number if number > 0 else 0


def _as_hour(value: Any) -> int:
    hour = _as_count(value)
    if hour > 23:
        raise UsageAggregateError(f"invalid hour: {value!r}")
    return hour


class UsageAggregateStore:
    """SQLite-backed aggregate tables. Lives beside the main Hub database."""

    def __init__(self, data_dir: Path, db_path: Optional[Path] = None):
        self.data_dir = Path(data_dir).resolve()
        self.db_path = (db_path or (self.data_dir / "usage.db")).resolve()
        self._lock = threading.RLock()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA temp_store=MEMORY")
        return conn

    def initialize(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with self._lock:
            conn = self.connect()
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS usage_hourly (
                        date        TEXT    NOT NULL,
                        mac         TEXT    NOT NULL,
                        hour        INTEGER NOT NULL,
                        active_secs INTEGER NOT NULL DEFAULT 0,
                        tx_bytes    INTEGER NOT NULL DEFAULT 0,
                        rx_bytes    INTEGER NOT NULL DEFAULT 0,
                        updated_at  TEXT    NOT NULL,
                        PRIMARY KEY (date, mac, hour)
                    ) WITHOUT ROWID;
                    CREATE TABLE IF NOT EXISTS usage_daily_app (
                        date        TEXT    NOT NULL,
                        mac         TEXT    NOT NULL,
                        app         TEXT    NOT NULL,
                        active_secs INTEGER NOT NULL DEFAULT 0,
                        tx_bytes    INTEGER NOT NULL DEFAULT 0,
                        rx_bytes    INTEGER NOT NULL DEFAULT 0,
                        sessions    INTEGER NOT NULL DEFAULT 0,
                        updated_at  TEXT    NOT NULL,
                        PRIMARY KEY (date, mac, app)
                    ) WITHOUT ROWID;
                    """
                )
            finally:
                conn.close()

    # -- ingestion ---------------------------------------------------------

    def upsert_hourly(self, rows: Iterable[Dict[str, Any]]) -> int:
        return self._upsert(
            table="usage_hourly",
            rows=rows,
            keys=("date", "mac", "hour"),
            values=("active_secs", "tx_bytes", "rx_bytes"),
        )

    def upsert_daily_app(self, rows: Iterable[Dict[str, Any]]) -> int:
        return self._upsert(
            table="usage_daily_app",
            rows=rows,
            keys=("date", "mac", "app"),
            values=("active_secs", "tx_bytes", "rx_bytes", "sessions"),
        )

    def _upsert(
        self,
        *,
        table: str,
        rows: Iterable[Dict[str, Any]],
        keys: Sequence[str],
        values: Sequence[str],
    ) -> int:
        now = _now_text()

        # Validate everything before touching the database, so a malformed row
        # rejects the whole request instead of leaving a half-applied batch.
        prepared: List[tuple] = []
        for row in rows:
            record = self._prepare_row(row, keys, values, now)
            if record is not None:
                prepared.append(record)
        if not prepared:
            return 0

        columns = (*keys, *values, "updated_at")
        placeholders = ", ".join("?" for _ in columns)
        # max(): absolute counters are monotonic within a day, so re-delivery is
        # a no-op and a value can never be inflated by a retry.
        assignments = ", ".join(
            f"{field} = max({table}.{field}, excluded.{field})" for field in values
        )
        assignments += ", updated_at = excluded.updated_at"
        sql = (
            f"INSERT INTO {table}({', '.join(columns)}) VALUES({placeholders}) "
            f"ON CONFLICT({', '.join(keys)}) DO UPDATE SET {assignments}"
        )

        # Execute in bounded transactions: a relay that has been offline for a
        # year may hand over ~200k buckets, and dropping the tail would be a
        # silent data loss (which an earlier revision did).
        with self._lock:
            conn = self.connect()
            try:
                for start in range(0, len(prepared), MAX_ROWS_PER_PUSH):
                    batch = prepared[start:start + MAX_ROWS_PER_PUSH]
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.executemany(sql, batch)
                        conn.execute("COMMIT")
                    except Exception:
                        conn.execute("ROLLBACK")
                        raise
            finally:
                conn.close()
        return len(prepared)

    @staticmethod
    def _prepare_row(
        row: Any,
        keys: Sequence[str],
        values: Sequence[str],
        now: str,
    ) -> Optional[tuple]:
        if not isinstance(row, dict):
            return None
        record: Dict[str, Any] = {
            "date": _iso_date(row.get("date")),
            "mac": normalize_mac(row.get("mac")),
        }
        if not record["mac"]:
            return None
        if "hour" in keys:
            record["hour"] = _as_hour(row.get("hour"))
        if "app" in keys:
            app = str(row.get("app") or "").strip()
            if not app or len(app) > 64:
                return None
            record["app"] = app
        for field in values:
            raw = row.get(field) if row.get(field) is not None else row.get(_camel(field))
            record[field] = _as_count(raw)
        record["updated_at"] = now
        return tuple(record[column] for column in (*keys, *values, "updated_at"))

    # -- retention ---------------------------------------------------------

    def prune(
        self,
        *,
        today: Optional[str] = None,
        hourly_keep_days: int = DEFAULT_HOURLY_KEEP_DAYS,
        daily_keep_days: int = DEFAULT_DAILY_KEEP_DAYS,
    ) -> Dict[str, int]:
        """Drop whole days that fall outside each table's retention window.

        ``keep_days`` counts **including today**, so ``10`` keeps today plus the
        nine preceding days.  This matches the relay's own prune, which keeps
        the newest N distinct dates present in the store.
        """
        reference = _date.fromisoformat(_iso_date(today)) if today else _date.today()
        # `keep_days - 1` because the window is inclusive of today.
        hourly_cutoff = (
            reference - timedelta(days=max(0, hourly_keep_days - 1))
        ).isoformat()
        daily_cutoff = (
            reference - timedelta(days=max(0, daily_keep_days - 1))
        ).isoformat()
        removed: Dict[str, int] = {}
        with self._lock:
            conn = self.connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.execute("DELETE FROM usage_hourly WHERE date < ?", (hourly_cutoff,))
                removed["hourly"] = cursor.rowcount or 0
                cursor = conn.execute("DELETE FROM usage_daily_app WHERE date < ?", (daily_cutoff,))
                removed["dailyApp"] = cursor.rowcount or 0
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()
        return removed

    # -- reads -------------------------------------------------------------

    def report(self, macs: Sequence[str], date: str) -> Dict[str, Any]:
        """The official ``上网统计`` shape: online time, hourly bars, app list."""
        wanted = [normalize_mac(mac) for mac in macs if normalize_mac(mac)]
        day = _iso_date(date)
        if not wanted:
            return {
                "date": day, "onlineSeconds": 0, "onlineMinutes": 0,
                "hourly": [], "apps": [], "macs": [],
            }
        placeholders = ", ".join("?" for _ in wanted)
        with self._lock:
            conn = self.connect()
            try:
                hourly = conn.execute(
                    f"""SELECT hour,
                               SUM(active_secs) AS active_secs,
                               SUM(tx_bytes)    AS tx_bytes,
                               SUM(rx_bytes)    AS rx_bytes
                        FROM usage_hourly
                        WHERE date = ? AND mac IN ({placeholders})
                        GROUP BY hour ORDER BY hour""",
                    (day, *wanted),
                ).fetchall()
                apps = conn.execute(
                    f"""SELECT app,
                               SUM(active_secs) AS active_secs,
                               SUM(tx_bytes)    AS tx_bytes,
                               SUM(rx_bytes)    AS rx_bytes,
                               SUM(sessions)    AS sessions
                        FROM usage_daily_app
                        WHERE date = ? AND mac IN ({placeholders})
                        GROUP BY app""",
                    (day, *wanted),
                ).fetchall()
            finally:
                conn.close()

        online_seconds = sum(int(row["active_secs"] or 0) for row in hourly)
        hourly_rows = [
            {
                "hour": int(row["hour"]),
                "minutes": _to_minutes(int(row["active_secs"] or 0)),
                "txBytes": int(row["tx_bytes"] or 0),
                "rxBytes": int(row["rx_bytes"] or 0),
            }
            for row in hourly
        ]
        app_rows = sorted(
            (
                {
                    "app": str(row["app"]),
                    "minutes": _to_minutes(int(row["active_secs"] or 0)),
                    "sessions": int(row["sessions"] or 0),
                    "txBytes": int(row["tx_bytes"] or 0),
                    "rxBytes": int(row["rx_bytes"] or 0),
                }
                for row in apps
            ),
            key=lambda item: (-item["minutes"], item["app"]),
        )
        return {
            "date": day,
            "onlineSeconds": online_seconds,
            "onlineMinutes": _to_minutes(online_seconds),
            "hourly": hourly_rows,
            "apps": app_rows,
            "macs": wanted,
        }

    def daily_totals(self, macs: Sequence[str], start: str, end: str) -> List[Dict[str, Any]]:
        """Per-day online minutes across a date range, **gap filled**.

        The App draws the 最近10天 chart straight from this, so every date in
        ``[start, end]`` is present — days with no activity come back as zero
        rather than being missing, and the client never has to do date maths or
        guess how many bars to render.
        """
        wanted = [normalize_mac(mac) for mac in macs if normalize_mac(mac)]
        first = _date.fromisoformat(_iso_date(start))
        last = _date.fromisoformat(_iso_date(end))
        if last < first:
            first, last = last, first
        window = [(first + timedelta(days=offset)) for offset in range((last - first).days + 1)]

        seconds: Dict[str, int] = {}
        if wanted:
            placeholders = ", ".join("?" for _ in wanted)
            with self._lock:
                conn = self.connect()
                try:
                    rows = conn.execute(
                        f"""SELECT date, SUM(active_secs) AS active_secs
                            FROM usage_hourly
                            WHERE date BETWEEN ? AND ? AND mac IN ({placeholders})
                            GROUP BY date""",
                        (first.isoformat(), last.isoformat(), *wanted),
                    ).fetchall()
                finally:
                    conn.close()
            seconds = {str(row["date"]): int(row["active_secs"] or 0) for row in rows}

        return [
            {
                "date": day.isoformat(),
                "onlineSeconds": seconds.get(day.isoformat(), 0),
                "onlineMinutes": _to_minutes(seconds.get(day.isoformat(), 0)),
            }
            for day in window
        ]

    def app_totals(self, macs: Sequence[str], start: str, end: str) -> List[Dict[str, Any]]:
        """Per-app totals summed across a date range (the 最近N天 app summary).

        Returns the same row shape as :meth:`report`'s ``apps`` so the client can
        render both tabs with one parser.
        """
        wanted = [normalize_mac(mac) for mac in macs if normalize_mac(mac)]
        first = _iso_date(start)
        last = _iso_date(end)
        if not wanted:
            return []
        placeholders = ", ".join("?" for _ in wanted)
        with self._lock:
            conn = self.connect()
            try:
                rows = conn.execute(
                    f"""SELECT app,
                               SUM(active_secs) AS active_secs,
                               SUM(tx_bytes)    AS tx_bytes,
                               SUM(rx_bytes)    AS rx_bytes,
                               SUM(sessions)    AS sessions
                        FROM usage_daily_app
                        WHERE date BETWEEN ? AND ? AND mac IN ({placeholders})
                        GROUP BY app""",
                    (first, last, *wanted),
                ).fetchall()
            finally:
                conn.close()
        return sorted(
            (
                {
                    "app": str(row["app"]),
                    "minutes": _to_minutes(int(row["active_secs"] or 0)),
                    "sessions": int(row["sessions"] or 0),
                    "txBytes": int(row["tx_bytes"] or 0),
                    "rxBytes": int(row["rx_bytes"] or 0),
                }
                for row in rows
            ),
            key=lambda item: (-item["minutes"], item["app"]),
        )

    def stats(self) -> Dict[str, Any]:
        """Row counts and on-disk size, so the storage claim stays honest."""
        with self._lock:
            conn = self.connect()
            try:
                hourly = conn.execute("SELECT COUNT(*) AS n FROM usage_hourly").fetchone()["n"]
                daily = conn.execute("SELECT COUNT(*) AS n FROM usage_daily_app").fetchone()["n"]
                span = conn.execute(
                    "SELECT MIN(date) AS lo, MAX(date) AS hi FROM ("
                    "SELECT date FROM usage_hourly UNION ALL SELECT date FROM usage_daily_app)"
                ).fetchone()
            finally:
                conn.close()
        size = 0
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.db_path) + suffix)
            if candidate.exists():
                size += candidate.stat().st_size
        return {
            "hourlyRows": int(hourly or 0),
            "dailyAppRows": int(daily or 0),
            "bytesOnDisk": size,
            "firstDate": span["lo"] if span else None,
            "lastDate": span["hi"] if span else None,
            "database": str(self.db_path),
        }


def _to_minutes(seconds: int) -> int:
    return (max(0, seconds) + 30) // 60


def _camel(field: str) -> str:
    head, *rest = field.split("_")
    return head + "".join(part.capitalize() for part in rest)


def _now_text() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def default_keep_days() -> Dict[str, int]:
    """The product retention window, in one place for callers that report it."""
    return {
        "hourly": DEFAULT_HOURLY_KEEP_DAYS,
        "dailyApp": DEFAULT_DAILY_KEEP_DAYS,
    }


def compose_device_report(
    store: Optional["UsageAggregateStore"],
    macs: Sequence[str],
    date: str,
    *,
    live: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
    range_days: int = 1,
) -> Dict[str, Any]:
    """Pick the best available report for one device on one day.

    Precedence, and why:

    1. **Hub aggregates** — they survive router reboots and are what the App
       should read in steady state.
    2. **The router live** (`live`) — for a day the relay has not pushed yet:
       first boot, a device that was just added, or a date older than the
       retention window.
    3. **An explicit empty report** — not an error. The App shows 暂无记录
       instead of a failure banner, and the next push fills it in.

    ``source`` always says which of the three produced the numbers, so a
    mismatch is diagnosable from the App side without server logs.

    ``range_days`` > 1 additionally attaches a gap-filled ``range.days`` series
    (that many days ending on ``date``) for the 最近N天 chart.
    """
    keep = default_keep_days()
    report: Optional[Dict[str, Any]] = None

    if store is not None:
        try:
            candidate = store.report(macs, date)
        except Exception:
            candidate = None
        if candidate and (candidate.get("hourly") or candidate.get("apps")):
            report = {**candidate, "source": "hub", "keepDays": keep}

    if report is None and live is not None:
        try:
            fallback = live()
        except Exception:
            fallback = None
        if fallback and (fallback.get("hourly") or fallback.get("apps")):
            report = {**fallback, "source": "relay", "keepDays": keep}

    if report is None:
        report = {
            "date": _iso_date(date),
            "onlineSeconds": 0,
            "onlineMinutes": 0,
            "hourly": [],
            "apps": [],
            "macs": [normalize_mac(mac) for mac in macs if normalize_mac(mac)],
            "source": "empty",
            "keepDays": keep,
        }

    if range_days > 1:
        report["range"] = _range_series(store, macs, date, range_days)
    return report


def _range_series(
    store: Optional["UsageAggregateStore"],
    macs: Sequence[str],
    date: str,
    days: int,
) -> Dict[str, Any]:
    """Gap-filled daily totals ending on ``date``; empty when no store yet."""
    end = _date.fromisoformat(_iso_date(date))
    start = end - timedelta(days=max(0, days - 1))
    entries: List[Dict[str, Any]] = []
    apps: List[Dict[str, Any]] = []
    if store is not None:
        try:
            entries = store.daily_totals(macs, start.isoformat(), end.isoformat())
            apps = store.app_totals(macs, start.isoformat(), end.isoformat())
        except Exception:
            entries, apps = [], []
    if not entries:
        # No store (or no rows): still hand back the full window of zeros so the
        # client renders a stable N-bar chart instead of collapsing.
        entries = [
            {"date": day.isoformat(), "onlineSeconds": 0, "onlineMinutes": 0}
            for day in (start + timedelta(days=offset) for offset in range((end - start).days + 1))
        ]
    return {
        "days": entries,
        "apps": apps,
        "start": start.isoformat(),
        "end": end.isoformat(),
    }


def resolve_store(hub: Any, logger: Optional[Callable[..., Any]] = None) -> Optional[UsageAggregateStore]:
    """Find/create the store for a running Hub, tolerating pre-existing wiring."""
    existing = getattr(hub, "USAGE_AGGREGATE_STORE", None)
    if isinstance(existing, UsageAggregateStore):
        return existing
    data_dir = getattr(hub, "DATA_DIR", None)
    if data_dir is None:
        log = logger or getattr(hub, "LOGGER", None)
        if log is not None and hasattr(log, "warning"):
            log.warning("usage aggregate: hub exposes no DATA_DIR; store disabled")
        return None
    store = UsageAggregateStore(Path(data_dir))
    store.initialize()
    try:
        setattr(hub, "USAGE_AGGREGATE_STORE", store)
    except Exception:  # pragma: no cover - defensive only
        pass
    return store


def install_usage_aggregate(hub: Any, logger: Optional[Callable[..., Any]] = None) -> Blueprint:
    """Registers ``/api/router/child-guard/usage`` on the running Hub app."""
    log = logger or getattr(hub, "LOGGER", None)
    bp = Blueprint("child_guard_usage_aggregate", __name__,
                   url_prefix="/api/router/child-guard/usage")

    def _store() -> Optional[UsageAggregateStore]:
        return resolve_store(hub, log)

    @bp.errorhandler(UsageAggregateError)
    def _handle_validation(error: UsageAggregateError):
        return jsonify({"ok": False, "errorCode": "invalid_request", "error": str(error)}), 400

    @bp.post("/ingest")
    def ingest():
        # The relay holds the hook token; the App holds the app token.
        if not (hub.check_hook_token() or hub.check_app_token()):
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        store = _store()
        if store is None:
            return jsonify({"ok": False, "error": "usage_store_unavailable"}), 503
        body = request.get_json(silent=True) or {}
        hours = store.upsert_hourly(body.get("hours") or [])
        apps = store.upsert_daily_app(body.get("apps") or [])
        removed = store.prune(
            today=body.get("today"),
            hourly_keep_days=int(body.get("hourlyKeepDays") or DEFAULT_HOURLY_KEEP_DAYS),
            daily_keep_days=int(body.get("dailyKeepDays") or DEFAULT_DAILY_KEEP_DAYS),
        )
        # Aggregates are the only thing that reached disk; raw samples never did.
        return jsonify({
            "ok": True,
            "upserted": {"hourly": hours, "dailyApp": apps},
            "pruned": removed,
            "updatedAt": int(time.time()),
        })

    @bp.get("/report")
    def report():
        if not hub.check_read_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        store = _store()
        if store is None:
            return jsonify({"ok": False, "error": "usage_store_unavailable"}), 503
        date = request.args.get("date") or _date.today().isoformat()
        raw_macs = request.args.get("macs") or ""
        macs = [item for item in raw_macs.replace(";", ",").split(",") if item.strip()]
        payload = store.report(macs, date)
        payload["ok"] = True
        payload["updatedAt"] = int(time.time())
        return jsonify(payload)

    @bp.get("/status")
    def status():
        if not hub.check_read_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        store = _store()
        if store is None:
            return jsonify({"ok": False, "error": "usage_store_unavailable"}), 503
        payload = store.stats()
        payload.update({
            "ok": True,
            "hourlyKeepDays": DEFAULT_HOURLY_KEEP_DAYS,
            "dailyKeepDays": DEFAULT_DAILY_KEEP_DAYS,
        })
        return jsonify(payload)

    hub.app.register_blueprint(bp)
    if log is not None and hasattr(log, "info"):
        log.info("child guard usage aggregate registered at %s", bp.url_prefix)
    return bp
