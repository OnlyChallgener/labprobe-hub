"""Long-term aggregate store for Child Internet usage statistics.

This is the data the product actually shows.  Since v3 the router ships **natural
minute buckets**, which is the only honest basis for a duration: a minute is
either active or it is not, so ``08:15`` with five seconds of traffic and
``08:15`` with fifty-five seconds of traffic are both exactly one minute.

``usage_device_minute``  ``(date, mac, minute)``  -> 在线时间 / 小时柱状图
``usage_app_minute``     ``(date, mac, app, min)`` -> 应用上网时长统计 + 时段
``usage_device_traffic`` ``(date, mac)``           -> 设备总流量（固件计数器）

The legacy tables stay readable so the 10-day history of routers still on v2
does not go blank, but a day is rendered from **one** basis only: minute rows
when the router reported them, the old second-accumulating tables otherwise.
Nothing is ever averaged, blended or extrapolated across the two.

Device traffic is a separate concern from durations and comes exclusively from
``usage_device_traffic`` — the router's firmware per-device day counters.  The
per-flow / per-app byte columns of the legacy tables are RDPI-classified flow
sums; they are a different measurement (only classified traffic, double-counted
across apps) and are therefore never re-assembled into a device total.

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
Minute buckets are bounded by the calendar, not by traffic: a device can produce
at most ``24 x 60 = 1440`` device minutes a day, so the primary table has a hard
ceiling of

* ``usage_device_minute`` 10 devices x 1440 x 365 = 5 256 000 rows/year

which at the 10-day product window is at most 144 000 rows for ten devices.
App minutes are bounded by the apps actually used; the same 1440-minute ceiling
applies per (device, app), and the router only marks an app active in a minute
when classified traffic for it was actually seen in that minute.

For the two legacy fixed-cardinality summary tables, per year, assuming 10
devices x ~30 apps:

* ``usage_hourly``    10 x 24 x 365        =  87 600 rows
* ``usage_daily_app`` 10 x 30 x 365        = 109 500 rows
* total                                    = 197 100 rows -> **14.4 MB**
  (77 bytes/row; both tables are ``WITHOUT ROWID`` with the primary key as the
  clustering index and no secondary index)

Session-range volume varies with actual interaction count, so it is not folded
into that fixed 14.4 MB claim. It is bounded by the same 10-day retention as the
daily app table. Each row stores only start/end/credited seconds; remote IPs,
ports and raw flows never reach the Hub.

Retention
---------
This implementation keeps **10 days** by default, which covers the current App
reporting window with headroom.  The UI window is not evidence that the vendor
backend retains only ten days.  The same configurable default applies to all
three local tables, and the footprint at that window is trivial: a year's worth
of summary rows is 14.4 MB, so a ten-day summary window is well under 1 MB per
device-set (session rows vary with real interaction count).

Storage is cheap on a NAS, so the window is a *product* decision, not a
technical ceiling.  Both windows stay independently overridable
(``USAGE_HOURLY_KEEP_DAYS`` / ``USAGE_DAILY_KEEP_DAYS``, or per-request
``hourlyKeepDays`` / ``dailyKeepDays``) so a future "过去 30 天" view can be
enabled without touching this module — raising the daily window alone is enough
because the hourly table only feeds the day chart.

Idempotency
-----------
Minute rows are a set, not a counter: the router only pushes minutes it has not
pushed before and the Hub writes them with ``INSERT OR IGNORE``, so a retry, a
duplicate delivery or a Hub restart cannot double-count a minute.  Traffic rows
are **absolute** per-day firmware counters and are merged with ``max()`` per
column, so re-delivery is a no-op and a value can never be inflated by a retry.
The trade-off for traffic is that a counter which legitimately goes *down*
(router reboot clears its day counter) is ignored, which avoids inflation but is
not lossless.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import date as _date, datetime as _datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from flask import Blueprint, jsonify, request

from child_guard_schedule import schedule_state

DEFAULT_HOURLY_KEEP_DAYS = int(os.environ.get("USAGE_HOURLY_KEEP_DAYS", "10"))
DEFAULT_DAILY_KEEP_DAYS = int(os.environ.get("USAGE_DAILY_KEEP_DAYS", "10"))
#: 分钟桶是 v3 的唯一原始记录，保留窗口独立可配，默认与日报表同为 10 天。
DEFAULT_MINUTE_KEEP_DAYS = int(os.environ.get("USAGE_MINUTE_KEEP_DAYS", "10"))

MAX_ROWS_PER_PUSH = 5000

MINUTE_SECONDS = 60
#: 相邻时段之间允许跨过这么多个「空分钟」仍然算同一段。固件会周期性地把一条长
#: 连接重新分类一次，于是微信的一条通话会被记成 08:15、08:16、(缺 08:17)、08:18
#: —— 时长还是真实的那三分钟，只是不再被拆成两段显示。
#: 白天容差：实测（2026-09-20 BE72 微信 135 分钟）53 个洞是 1 个空分钟、23 个是
#: 2 个，所以 2 足够把一次真实使用拼回一段。
DAY_MERGE_GAP_MINUTES = int(os.environ.get("USAGE_DAY_MERGE_GAP_MINUTES", "2"))
#: 夜间容差：夜里一次真实使用被重分类切得更碎，容差太小会把一个 5 分钟段拆成两
#: 段 3 分钟，再被 ``NIGHT_MIN_RUN_MINUTES`` 整段误杀。
NIGHT_MERGE_GAP_MINUTES = int(os.environ.get("USAGE_NIGHT_MERGE_GAP_MINUTES", "4"))
#: 不足这么长的连续段既不计入时长，也不出现在时段列表里。夜间 5 分钟是实测拐点
#: （2026-09-21 BE72）：00:00-05:59 有 65 段只有 1 分钟，全是保活/推送唤醒，这条
#: 规则把它们全部剔除，而 00:01-01:11 刷抖音那种真实使用一段都还有 27 分钟。
NIGHT_MIN_RUN_MINUTES = int(os.environ.get("USAGE_NIGHT_MIN_RUN_MINUTES", "5"))
DAY_MIN_RUN_MINUTES = int(os.environ.get("USAGE_DAY_MIN_RUN_MINUTES", "3"))
#: 打开就是为了完成一次短交互的应用：扫码付款、搜一下、问一句 AI。这种一分钟就
#: 是真实使用，套 3 分钟 / 5 分钟的连续段门槛会把整段抹掉，所以它们全天都单独放行。
#: 夜间仍然要求「有应用归属」——7 小时 51 分那个根因是未识别的后台字节，不在这里
#: 放行，也不会被放回来。
INSTANT_USE_MIN_RUN_MINUTES = int(os.environ.get("USAGE_INSTANT_MIN_RUN_MINUTES", "1"))
INSTANT_USE_APPS = frozenset(os.environ.get(
    "USAGE_INSTANT_USE_APPS",
    # 百度的官方特征条目就叫 baiduAPP，两个名字都要认。
    "支付宝,微信支付,云闪付,百度,baiduAPP,百度贴吧,DeepSeek,豆包,夸克,Kimi,元宝,即梦"
).split(","))
#: 银行类 App 名字各异，按后缀统一放行。
INSTANT_USE_SUFFIXES = ("银行", "支付")


def _is_instant_use(app: str) -> bool:
    name = str(app or "").strip()
    return name in INSTANT_USE_APPS or any(name.endswith(s) for s in INSTANT_USE_SUFFIXES)


def _min_run_minutes(app: str, *, night: bool) -> int:
    """这个应用在这一段该按多长的连续段门槛计。短交互应用全天都放行到 1 分钟。"""
    if _is_instant_use(app):
        return INSTANT_USE_MIN_RUN_MINUTES
    return NIGHT_MIN_RUN_MINUTES if night else DAY_MIN_RUN_MINUTES
#: A day has at most this many minute buckets; more than that is malformed input.
MAX_MINUTES_PER_ROW = 24 * 60
#: 家长请注意 window is 00:00-06:00 Beijing time, i.e. hours 0..5.
LATE_NIGHT_END_HOUR = 6
#: Epoch bounds outside which a "minute" is garbage, not data (2001 .. 2100).
MINUTE_EPOCH_FLOOR = 1_000_000_000
MINUTE_EPOCH_CEILING = 4_102_444_800
#: Session epochs and minute epochs are router-local (Beijing, UTC+8); the hour
#: is derived with a fixed +8h offset instead of the Hub's own timezone.
BEIJING_OFFSET_SQL = "'unixepoch', '+8 hours'"
#: v3: 一台设备的数据多久没有推进就算「不新鲜」。中继每 30 秒推一次，
#: 超过这个窗口说明路由侧统计已经停了，页面必须显示为过期而不是 0 分钟。
STALE_AFTER_SECONDS = 180
#: 「今日用得偏多」的提醒阈值（分钟），只认真实分钟行。
ATTENTION_NOTICE_MINUTES = int(os.environ.get("USAGE_ATTENTION_NOTICE_MINUTES", "120"))
#: 「正在上网」允许的落后量：一个自然分钟只在其结束后才被结算，所以当前分钟
#: 本来就慢一格，判定时取「本分钟或上一分钟」。
ACTIVE_NOW_LAG_SECONDS = MINUTE_SECONDS


class UsageAggregateError(ValueError):
    """Raised before malformed data can reach the aggregate tables."""


def normalize_mac(value: Any) -> str:
    """``AA-BB-CC-DD-EE-FF`` / ``aabbccddeeff`` -> ``aa:bb:cc:dd:ee:ff``."""
    text = str(value or "").strip().lower()
    compact = "".join(ch for ch in text if ch not in ":-.")
    if len(compact) == 12 and all(ch in "0123456789abcdef" for ch in compact):
        return ":".join(compact[i:i + 2] for i in range(0, 12, 2))
    return text


def router_key(value: Any) -> str:
    """The stable router id a write is filed under.

    Ingest has no router in its body (the relay only sends the buckets), so the
    Hub resolves it once per request and both sides of every read use the same
    normalized form — ``Ruijie BE72`` and ``BE72`` must not become two devices.
    """
    return str(value or "").strip().lower()[:128] or "router"


def _router_clause(value: Any) -> tuple[str, List[str]]:
    """Read-side router filter; an empty value means "any router"."""
    key = str(value or "").strip().lower()[:128]
    if not key:
        return "", []
    return "router = ? AND ", [key]


#: Sentinel mac in ``usage_ingest_meta`` holding "this router pushed at …", so
#: payload-level freshness is one row lookup instead of a scan over devices.
ROUTER_META_MAC = "*"


def _with_router(rows: Any, router: Any) -> List[Dict[str, Any]]:
    """Tag every row of a v3 array with the router the push came from.

    The payload has no router field, so the write key has to be attached here;
    ``router_key`` only sees what the row itself says.
    """
    key = router_key(router)
    prepared: List[Dict[str, Any]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        prepared.append({**row, "router": row.get("router") or key})
    return prepared


#: 中继在拿不到任何身份信息时回的就是这些占位串 —— 它们不是名字。缓存里一旦被
#: 它们覆盖，上一次真读到的「华为Mate60」就没了，界面上只能退回一长串 UID。
GUARD_NAME_PLACEHOLDERS = frozenset({"受守护设备", "受保护设备", "labprobe 设备", "未知设备"})


def _guard_name(value: Any) -> str:
    name = str(value or "").strip()[:120]
    return "" if name.casefold() in GUARD_NAME_PLACEHOLDERS else name


def _guard_uid(value: Any) -> str:
    """Normalise a child-guard uid the way ``child_guard_service`` stores it.

    Router-generated uids are 16-byte hex shown in upper case; anything else is
    kept verbatim.  Both sides of the ``child_guard_device`` table must use this
    form or a cache hit turns into a router round-trip.
    """
    uid = str(value or "").strip()
    if len(uid) == 32 and all(ch in "0123456789abcdefABCDEF" for ch in uid):
        return uid.upper()
    return uid[:128]


def _split_macs(value: Any) -> List[str]:
    """``"aa:bb:..,cc:dd:.."`` -> list of normalized MACs (stored form)."""
    if isinstance(value, (list, tuple)):
        raw: Iterable[Any] = value
    else:
        raw = str(value or "").replace(";", ",").split(",")
    return [normalize_mac(item) for item in raw if str(item or "").strip()]


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


def _as_minute_epoch(value: Any) -> int:
    """Validate one minute-start epoch and snap it to its minute bucket.

    The router sends UTC-aligned minute starts (China is a whole-hour offset, so
    these are Beijing minute starts too).  Millisecond epochs are rescaled and a
    stray few seconds is floored onto its minute: that is the bucket the sample
    belongs to, not an invented duration.
    """
    try:
        if isinstance(value, bool):
            raise ValueError(value)
        if isinstance(value, (int, float)):
            number = int(value)
        else:
            number = int(str(value).strip())
    except (TypeError, ValueError):
        raise UsageAggregateError(f"invalid minute epoch: {value!r}")
    if number >= 10_000_000_000:  # milliseconds
        number //= 1000
    number -= number % MINUTE_SECONDS
    if not MINUTE_EPOCH_FLOOR <= number <= MINUTE_EPOCH_CEILING:
        raise UsageAggregateError(f"minute epoch out of range: {value!r}")
    return number


#: 中继 v4 随每分钟一起上报的四列证据，以及它们在 payload 里的短名。
_EVIDENCE_FIELDS = (("up", "up_bytes"), ("down", "down_bytes"),
                    ("win", "windows"), ("flow", "new_flows"))


def _u64_list(value: Any) -> List[int]:
    """One evidence column: non-negative ints, positionally aligned with minutes."""
    if not isinstance(value, (list, tuple)):
        return []
    out: List[int] = []
    for item in value:
        try:
            if isinstance(item, bool):
                raise ValueError(item)
            out.append(max(0, int(float(item))))
        except (TypeError, ValueError):
            out.append(0)
    return out


def _minute_evidence(row: Any) -> Dict[int, Tuple[int, int, int, int]]:
    """``{"minutes":[..], "up":[..], "down":[..], "win":[..], "flow":[..]}`` -> 按分钟对齐。

    按分钟值对齐而不是按数组下标：下面还要去重排序，一旦下标错位，某分钟的字节就
    记到另一分钟头上了。同一分钟重复出现时每列取最大值（中继不会这么发，防的是坏包）。

    返回里没有的分钟 = 证据未知（v3 中继、或这一行根本没带数组），调用方必须把它
    当成「没测到」，不能当成「零字节」。
    """
    if not isinstance(row, dict):
        return {}
    marks = row.get("minutes")
    if not isinstance(marks, (list, tuple)):
        return {}
    columns = [_u64_list(row.get(short)) for short, _ in _EVIDENCE_FIELDS]
    if not any(columns):
        return {}
    merged: Dict[int, List[int]] = {}
    for index, value in enumerate(marks):
        try:
            minute = _as_minute_epoch(value)
        except UsageAggregateError:
            continue
        slot = merged.setdefault(minute, [0, 0, 0, 0])
        for column, values in enumerate(columns):
            if index < len(values):
                slot[column] = max(slot[column], values[index])
    return {minute: (values[0], values[1], values[2], values[3])
            for minute, values in merged.items()}


def _row_evidence(row: Any) -> Optional[Tuple[int, int, int, int]]:
    """一条分钟行的证据；中继没测过就是 None。

    v3 中继写的行四列全 0，而 v4 的活跃分钟必然 up+down>0（活跃判定本身就要求
    字节）。所以全 0 只能读成「未知」，不能读成「零字节」—— 否则这次上线会把昨天
    已经报出去的数字改小，用户看到的是「昨天的统计自己变了」。
    """
    try:
        values = (int(row["up_bytes"] or 0), int(row["down_bytes"] or 0),
                  int(row["windows"] or 0), int(row["new_flows"] or 0))
    except (IndexError, KeyError):
        return None
    return values if any(values) else None


def _evidence_map(minutes: Any) -> Dict[int, Optional[Tuple[int, int, int, int]]]:
    """接受 ``{minute: evidence}`` 或旧的裸分钟集合，统一成带证据的映射。

    裸集合里的分钟一律按「未知」处理，口径与 v3 完全一致，所以历史数据和现有测试
    不会因为加了证据这一层而改变结论。
    """
    if isinstance(minutes, Mapping):
        return {int(minute): (tuple(values) if values and any(values) else None)
                for minute, values in minutes.items()}
    return {int(minute): None for minute in minutes}


#: v3 tables that were first created without the ``router`` column.
_LEGACY_V3_TABLES = {
    "usage_device_minute": ("mac", "date", "minute_epoch", "updated_at"),
    "usage_app_minute": ("mac", "date", "app", "minute_epoch", "updated_at"),
    "usage_device_traffic": ("mac", "date", "tx_bytes", "rx_bytes", "updated_at"),
}


def _migrate_router_columns(conn: sqlite3.Connection) -> None:
    """Rebuild v3 tables that predate per-router scoping.

    ``CREATE TABLE IF NOT EXISTS`` never changes an existing primary key, so the
    rows the first v3 revision stored under ``(date, mac, ...)`` are moved into
    the router-scoped shape once, under the default router name. Reads accept
    "any router" for a day that has no rows under the requested name, so those
    rows stay visible instead of silently vanishing from the 10 天 chart.
    """
    for table, columns in _LEGACY_V3_TABLES.items():
        present = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if not present or "router" in present:
            continue
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(f"ALTER TABLE {table} RENAME TO {table}_pregate")
            conn.execute(
                f"CREATE TABLE {table} ("
                + ", ".join(f"{name} {'INTEGER' if name.endswith(('_epoch', '_bytes', '_at')) else 'TEXT'} NOT NULL"
                            for name in ("router", *columns))
                + f", PRIMARY KEY (router, {', '.join(c for c in columns if c != 'updated_at')}))"
                + " WITHOUT ROWID"
            )
            conn.execute(
                f"INSERT OR IGNORE INTO {table}(router, {', '.join(columns)}) "
                f"SELECT 'router', {', '.join(columns)} FROM {table}_pregate"
            )
            conn.execute(f"DROP TABLE {table}_pregate")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


#: 老库补新列用的清单：``CREATE TABLE IF NOT EXISTS`` 不会改已存在的表。
_EVIDENCE_COLUMNS = (
    ("up_bytes", "INTEGER NOT NULL DEFAULT 0"),
    ("down_bytes", "INTEGER NOT NULL DEFAULT 0"),
    ("windows", "INTEGER NOT NULL DEFAULT 0"),
    ("new_flows", "INTEGER NOT NULL DEFAULT 0"),
)
_ADDED_COLUMNS = {
    "child_guard_device": (("pass_until", "INTEGER NOT NULL DEFAULT 0"),),
    # v4：分钟桶带上中继已经算好的证据。老行是 0，含义是「未知」而不是「零字节」，
    # 规则据此退回 v3 口径，绝不拿没有测过的东西当测量值。
    "usage_device_minute": _EVIDENCE_COLUMNS,
    "usage_app_minute": _EVIDENCE_COLUMNS,
}


def _migrate_added_columns(conn: sqlite3.Connection) -> None:
    for table, columns in _ADDED_COLUMNS.items():
        present = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if not present:
            continue
        for name, declaration in columns:
            if name not in present:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")


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
                    CREATE TABLE IF NOT EXISTS usage_app_session (
                        date         TEXT    NOT NULL,
                        mac          TEXT    NOT NULL,
                        app          TEXT    NOT NULL,
                        start_epoch  INTEGER NOT NULL,
                        end_epoch    INTEGER NOT NULL,
                        active_secs  INTEGER NOT NULL DEFAULT 0,
                        updated_at   TEXT    NOT NULL,
                        PRIMARY KEY (date, mac, app, start_epoch)
                    ) WITHOUT ROWID;
                    /* v4: a minute is still a set member, but it now carries the
                       evidence that made it count — the split bytes and the
                       5-second sampling facts from the relay. All four are 0 for
                       rows written by a v3 relay, which means "unknown", not
                       "zero bytes": the rules must fall back, never conclude. */
                    CREATE TABLE IF NOT EXISTS usage_device_minute (
                        router       TEXT    NOT NULL,
                        mac          TEXT    NOT NULL,
                        date         TEXT    NOT NULL,
                        minute_epoch INTEGER NOT NULL,
                        up_bytes     INTEGER NOT NULL DEFAULT 0,
                        down_bytes   INTEGER NOT NULL DEFAULT 0,
                        windows      INTEGER NOT NULL DEFAULT 0,
                        new_flows    INTEGER NOT NULL DEFAULT 0,
                        updated_at   INTEGER NOT NULL,
                        PRIMARY KEY (router, mac, date, minute_epoch)
                    ) WITHOUT ROWID;
                    CREATE TABLE IF NOT EXISTS usage_app_minute (
                        router       TEXT    NOT NULL,
                        mac          TEXT    NOT NULL,
                        date         TEXT    NOT NULL,
                        app          TEXT    NOT NULL,
                        minute_epoch INTEGER NOT NULL,
                        up_bytes     INTEGER NOT NULL DEFAULT 0,
                        down_bytes   INTEGER NOT NULL DEFAULT 0,
                        windows      INTEGER NOT NULL DEFAULT 0,
                        new_flows    INTEGER NOT NULL DEFAULT 0,
                        updated_at   INTEGER NOT NULL,
                        PRIMARY KEY (router, mac, date, app, minute_epoch)
                    ) WITHOUT ROWID;
                    /* v3: per-day device totals straight from the firmware
                       counters. max-merged per column; the byte columns of the
                       legacy tables are flow sums and are not traffic. */
                    CREATE TABLE IF NOT EXISTS usage_device_traffic (
                        router     TEXT    NOT NULL,
                        mac        TEXT    NOT NULL,
                        date       TEXT    NOT NULL,
                        tx_bytes   INTEGER NOT NULL DEFAULT 0,
                        rx_bytes   INTEGER NOT NULL DEFAULT 0,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (router, mac, date)
                    ) WITHOUT ROWID;
                    /* When did this device's data last advance? Answered from
                       one row instead of a minute scan, so the overview stays
                       cheap. The newest minute epoch is still the source of
                       truth for ``lastSampleAt``; this is only max-ed with it. */
                    CREATE TABLE IF NOT EXISTS usage_ingest_meta (
                        router         TEXT    NOT NULL,
                        mac            TEXT    NOT NULL,
                        last_sample_at INTEGER NOT NULL DEFAULT 0,
                        updated_at     INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (router, mac)
                    ) WITHOUT ROWID;
                    /* uid -> MACs / name / blocked, cached from the child-guard
                       results the Hub already served. Reads must never ask the
                       router who the guarded devices are. */
                    CREATE TABLE IF NOT EXISTS child_guard_device (
                        router        TEXT    NOT NULL,
                        uid           TEXT    NOT NULL,
                        name          TEXT    NOT NULL DEFAULT '',
                        macs          TEXT    NOT NULL DEFAULT '',
                        blocked       INTEGER NOT NULL DEFAULT 0,
                        blocked_until INTEGER NOT NULL DEFAULT 0,
                        pass_until    INTEGER NOT NULL DEFAULT 0,
                        updated_at    INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (router, uid)
                    ) WITHOUT ROWID;

                    CREATE TABLE IF NOT EXISTS child_guard_plan_cache (
                        router       TEXT    NOT NULL,
                        uid          TEXT    NOT NULL,
                        plans_json   TEXT    NOT NULL DEFAULT '[]',
                        updated_at   INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (router, uid)
                    ) WITHOUT ROWID;
                    """
                )
                _migrate_router_columns(conn)
                _migrate_added_columns(conn)
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

    def upsert_sessions(self, rows: Iterable[Dict[str, Any]]) -> int:
        return self._upsert(
            table="usage_app_session",
            rows=rows,
            keys=("date", "mac", "app", "start_epoch"),
            values=("end_epoch", "active_secs"),
        )

    def insert_device_minutes(self, rows: Iterable[Dict[str, Any]], *,
                              router: Any = None) -> int:
        """``{"mac","date","minutes":[<minute-start epoch>, ..]}`` -> set insert."""
        return self._insert_minutes("usage_device_minute", rows, with_app=False,
                                    router=router)

    def insert_app_minutes(self, rows: Iterable[Dict[str, Any]], *,
                           router: Any = None) -> int:
        """``{"mac","date","app","minutes":[..]}`` -> set insert."""
        return self._insert_minutes("usage_app_minute", rows, with_app=True,
                                    router=router)

    def upsert_device_traffic(self, rows: Iterable[Dict[str, Any]], *,
                              router: Any = None) -> int:
        """Absolute per-day firmware counters; max-merged per column."""
        return self._upsert(
            table="usage_device_traffic",
            rows=_with_router(rows, router),
            keys=("router", "mac", "date"),
            values=("tx_bytes", "rx_bytes"),
            integer_timestamp=True,
        )

    def ingest_v3(self, body: Dict[str, Any], *, router: Any = None) -> Dict[str, int]:
        """Store one v3 push: 自然分钟桶 + 固件日字节数 + 样本时间。

        幂等：分钟是集合（``INSERT OR IGNORE``），流量是按列 ``max()``，meta 只
        往未来走。中继重试同一批不会让任何一个数字变大。
        """
        key = router_key(router)
        generated = _as_count(body.get("generatedAt") or body.get("generated_at"))
        device_rows = _with_router(body.get("deviceMinutes") or [], key)
        app_rows = _with_router(body.get("appMinutes") or [], key)
        stored = {
            "deviceMinutes": self.insert_device_minutes(device_rows, router=key),
            "appMinutes": self.insert_app_minutes(app_rows, router=key),
            "traffic": self.upsert_device_traffic(
                _with_router(body.get("traffic") or [], key), router=key),
        }
        newest: Dict[str, int] = {}
        for row in (*device_rows, *app_rows):
            mac = normalize_mac(row.get("mac"))
            if not mac:
                continue
            for value in row.get("minutes") or []:
                try:
                    minute = _as_minute_epoch(value)
                except UsageAggregateError:
                    continue  # 真正的畸形值在写分钟时已经拒过整个请求了
                newest[mac] = max(newest.get(mac, 0), minute)
        for row in body.get("traffic") or []:
            mac = normalize_mac(row.get("mac")) if isinstance(row, dict) else ""
            if mac:
                newest.setdefault(mac, generated)
        stored["meta"] = self.note_samples(key, newest, generated_at=generated)
        return stored

    def note_samples(self, router: Any, latest_by_mac: Dict[str, int], *,
                     generated_at: int = 0) -> int:
        """``usage_ingest_meta``: 这台设备的数据最后一次推进到什么时候。

        有分钟行本身就能算出来，但 overview 想知道「整台路由器有多新」时不该去
        扫分钟表；meta 取 ``max(已存, generatedAt, 这批最新分钟)``，只会往前走。
        """
        key = router_key(router)
        now = int(time.time())
        prepared: List[tuple] = []
        for mac, latest in (latest_by_mac or {}).items():
            clean = normalize_mac(mac)
            if not clean:
                continue
            prepared.append((key, clean, max(0, int(latest or 0)), now))
        if generated_at:
            # 路由器级别的「最近有过一次推送」，与单台设备是否有新分钟无关。
            prepared.append((key, ROUTER_META_MAC, max(0, int(generated_at)), now))
        if not prepared:
            return 0
        sql = (
            "INSERT INTO usage_ingest_meta(router, mac, last_sample_at, updated_at) "
            "VALUES(?, ?, ?, ?) "
            "ON CONFLICT(router, mac) DO UPDATE SET "
            "last_sample_at = max(usage_ingest_meta.last_sample_at, "
            "excluded.last_sample_at), updated_at = excluded.updated_at"
        )
        return self._write(sql, prepared)

    # -- 管控设备目录（uid -> MACs / 名称 / 封禁）---------------------------

    def remember_guard_devices(self, router: Any,
                               devices: Iterable[Dict[str, Any]]) -> int:
        """缓存 ``get_users``/``add_device``/``pause_device`` 的结果。

        只带 uid 的增量（pause/resume）不会清空已经存着的 macs 或名称，否则一次
        封禁操作就会把设备的身份抹掉。
        """
        key = router_key(router)
        now = int(time.time())
        stored = 0
        for device in devices or []:
            if not isinstance(device, dict):
                continue
            uid = _guard_uid(device.get("uid"))
            if not uid:
                continue
            macs = device.get("macs")
            clean_macs = [normalize_mac(mac) for mac in macs if str(mac or "").strip()] \
                if isinstance(macs, (list, tuple)) else None
            name = _guard_name(device.get("name")) or _guard_name(device.get("userDefinedName"))
            blocked = device.get("blocked")
            until = _as_count(device.get("blockedUntilEpoch"))
            # 「临时放行」用的是固件的 pause，「禁网」用的是 block —— 两个相反的
            # 状态。以前把 pausedUntilEpoch 兜进 blockedUntilEpoch，放行中会被显示
            # 成禁网中，所以各存各的列。
            passed = device.get("pausedUntilEpoch")
            with self._lock:
                conn = self.connect()
                try:
                    existing = conn.execute(
                        "SELECT name, macs, blocked, blocked_until, pass_until "
                        "FROM child_guard_device WHERE router = ? AND uid = ?", (key, uid)).fetchone()
                    merged_name = name or (str(existing["name"]) if existing else "")
                    merged_macs = clean_macs if clean_macs is not None else _split_macs(
                        str(existing["macs"]) if existing else "")
                    merged_blocked = (
                        1 if blocked else 0) if blocked is not None else (
                        int(existing["blocked"]) if existing else 0)
                    merged_until = until if (blocked is not None or until) else (
                        int(existing["blocked_until"]) if existing else 0)
                    merged_pass = _as_count(passed) if passed is not None else (
                        int(existing["pass_until"]) if existing else 0)
                    conn.execute(
                        "INSERT INTO child_guard_device"
                        "(router, uid, name, macs, blocked, blocked_until, pass_until, updated_at) "
                        "VALUES(?, ?, ?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(router, uid) DO UPDATE SET "
                        "name = excluded.name, macs = excluded.macs, "
                        "blocked = excluded.blocked, blocked_until = excluded.blocked_until, "
                        "pass_until = excluded.pass_until, "
                        "updated_at = excluded.updated_at",
                        (key, uid, merged_name, ",".join(merged_macs),
                         merged_blocked, merged_until, merged_pass, now),
                    )
                finally:
                    conn.close()
            stored += 1
        return stored

    def guard_devices(self, router: Any) -> List[Dict[str, Any]]:
        """这个路由器下 Hub 已知的全部受管控设备；空表 = Hub 还没见过任何设备。"""
        key = router_key(router)
        with self._lock:
            conn = self.connect()
            try:
                rows = conn.execute(
                    "SELECT uid, name, macs, blocked, blocked_until, pass_until, updated_at "
                    "FROM child_guard_device WHERE router = ? ORDER BY uid", (key,)
                ).fetchall()
            finally:
                conn.close()
        return [
            {
                "uid": str(row["uid"]),
                "name": str(row["name"] or ""),
                "macs": _split_macs(str(row["macs"] or "")),
                "blocked": bool(int(row["blocked"] or 0)),
                "blockedUntilEpoch": int(row["blocked_until"] or 0),
                "passUntilEpoch": int(row["pass_until"] or 0),
                "updatedAt": int(row["updated_at"] or 0),
            }
            for row in rows
        ]

    def remember_guard_plans(self, router: Any, uid: Any,
                             plans: Iterable[Dict[str, Any]]) -> bool:
        """缓存一台设备的上网计划，只用于总览那句「此刻生效态」。

        计划的事实存在路由器上，这里存的是最后一次成功读到的快照：路由器暂时
        不可达时总览仍然能说出「禁网中 · 至 17:00」，而不是把读失败摊给用户。
        """
        key = router_key(router)
        identity = _guard_uid(uid)
        if not identity:
            return False
        payload = json.dumps(
            [plan for plan in (plans or []) if isinstance(plan, dict)], ensure_ascii=False)
        with self._lock:
            conn = self.connect()
            try:
                conn.execute(
                    "INSERT INTO child_guard_plan_cache(router, uid, plans_json, updated_at)"
                    " VALUES(?, ?, ?, ?) ON CONFLICT(router, uid) DO UPDATE SET"
                    " plans_json = excluded.plans_json, updated_at = excluded.updated_at",
                    (key, identity, payload, int(time.time())),
                )
            finally:
                conn.close()
        return True

    def guard_plans(self, router: Any) -> Dict[str, List[Dict[str, Any]]]:
        """``uid -> 计划快照``；总览一次读全部，再逐台算生效态。"""
        key = router_key(router)
        with self._lock:
            conn = self.connect()
            try:
                rows = conn.execute(
                    "SELECT uid, plans_json FROM child_guard_plan_cache WHERE router = ?",
                    (key,),
                ).fetchall()
            finally:
                conn.close()
        out: Dict[str, List[Dict[str, Any]]] = {}
        for row in rows:
            try:
                value = json.loads(str(row["plans_json"] or "[]"))
            except Exception:  # pragma: no cover - 坏 JSON 当成没有缓存
                continue
            if isinstance(value, list):
                out[str(row["uid"])] = [item for item in value if isinstance(item, dict)]
        return out

    def guard_plan_snapshot(self, router: Any, uid: Any) -> Optional[List[Dict[str, Any]]]:
        """这台设备最后一次读到的完整计划列表；None = 从没读过。

        ``None`` 和 ``[]`` 是两件事：前者是「不知道」，后者是路由器明确说「一条
        也没有」。生效态卡片对这两句的说法完全不同，所以这里不能合并成空列表。
        """
        key = router_key(router)
        wanted = _guard_uid(uid)
        if not wanted:
            return None
        return self.guard_plans(key).get(wanted)

    def guard_plans_updated_at(self, router: Any, uid: Any) -> int:
        """计划快照的落盘时间；0 = 没有快照。"""
        key = router_key(router)
        wanted = _guard_uid(uid)
        if not wanted:
            return 0
        with self._lock:
            conn = self.connect()
            try:
                row = conn.execute(
                    "SELECT updated_at FROM child_guard_plan_cache WHERE router = ? AND uid = ?",
                    (key, wanted)).fetchone()
            finally:
                conn.close()
        return int(row["updated_at"] or 0) if row is not None else 0

    def guard_device(self, router: Any, uid: Any) -> Optional[Dict[str, Any]]:
        """单台设备的缓存条目；None = Hub 从未见过这个 uid（才允许问路由器）。"""
        key = router_key(router)
        wanted = _guard_uid(uid)
        if not wanted:
            return None
        with self._lock:
            conn = self.connect()
            try:
                row = conn.execute(
                    "SELECT uid, name, macs, blocked, blocked_until, pass_until, updated_at "
                    "FROM child_guard_device WHERE router = ? AND uid = ?",
                    (key, wanted)).fetchone()
            finally:
                conn.close()
        if row is None:
            return None
        return {
            "uid": str(row["uid"]),
            "name": str(row["name"] or ""),
            "macs": _split_macs(str(row["macs"] or "")),
            "blocked": bool(int(row["blocked"] or 0)),
            "blockedUntilEpoch": int(row["blocked_until"] or 0),
            "passUntilEpoch": int(row["pass_until"] or 0),
            "updatedAt": int(row["updated_at"] or 0),
        }

    def forget_guard_device(self, router: Any, uid: Any) -> int:
        key = router_key(router)
        wanted = _guard_uid(uid)
        if not wanted:
            return 0
        with self._lock:
            conn = self.connect()
            try:
                cursor = conn.execute(
                    "DELETE FROM child_guard_device WHERE router = ? AND uid = ?",
                    (key, wanted))
                conn.execute(
                    "DELETE FROM child_guard_plan_cache WHERE router = ? AND uid = ?",
                    (key, wanted))
                return cursor.rowcount or 0
            finally:
                conn.close()

    def guard_snapshot(self, router: Any, macs: Sequence[str],
                       date: str) -> Dict[str, Any]:
        """overview 的全部读取：一个连接、四条语句，问都不问路由器。

        返回的是**原始事实**（分钟列表、每应用分钟数、每 mac 最新分钟、meta），
        设备级的合并（同一台设备多块网卡在同一分钟只算一次）留给
        :func:`build_guard_overview`，因为去重必须按设备分组做。
        """
        wanted = [normalize_mac(mac) for mac in macs if normalize_mac(mac)]
        day = _iso_date(date)
        empty = {
            "date": day, "minutesByMac": {}, "appsByMac": {}, "latestByMac": {},
            "metaByMac": {}, "routerLastSampleAt": 0, "routerUpdatedAt": 0,
        }
        if not wanted:
            return empty
        with self._lock:
            conn = self.connect()
            try:
                snapshot = _guard_read(conn, wanted, day, router)
                if not any((snapshot["minutesByMac"], snapshot["appsByMac"],
                            snapshot["latestByMac"], snapshot["metaByMac"])):
                    # 归属名对不上时退回「任意路由器」，理由同 report()。
                    snapshot = _guard_read(conn, wanted, day, "")
            finally:
                conn.close()
        return snapshot

    def _insert_minutes(
        self, table: str, rows: Iterable[Dict[str, Any]], *,
        with_app: bool, router: Any = None,
    ) -> int:
        now = int(time.time())
        prepared: List[tuple] = []
        for row in rows:
            prepared.extend(self._expand_minute_row(
                row, with_app=with_app, now=now, router=router))
        columns = ("router", "mac", "date") + (("app",) if with_app else ()) \
            + ("minute_epoch",) + tuple(name for _, name in _EVIDENCE_FIELDS) + ("updated_at",)
        placeholders = ", ".join("?" for _ in columns)
        # The router only pushes minutes it has not pushed before, so this is an
        # idempotent set insert: a duplicate delivery cannot double-count.
        sql = (
            f"INSERT OR IGNORE INTO {table}({', '.join(columns)}) "
            f"VALUES({placeholders})"
        )
        return self._write(sql, prepared)

    @staticmethod
    def _expand_minute_row(row: Any, *, with_app: bool, now: int,
                           router: Any = None) -> List[tuple]:
        if not isinstance(row, dict):
            return []
        router = router_key(row.get("router") or router)
        day = _iso_date(row.get("date"))
        mac = normalize_mac(row.get("mac"))
        if not mac:
            return []
        app = ""
        if with_app:
            app = str(row.get("app") or "").strip()
            if not app or len(app) > 64:
                return []
        raw_minutes = row.get("minutes")
        if raw_minutes is None:
            return []
        if not isinstance(raw_minutes, (list, tuple)):
            raise UsageAggregateError(f"minutes must be a list: {raw_minutes!r}")
        unique = sorted({_as_minute_epoch(value) for value in raw_minutes})
        if len(unique) > MAX_MINUTES_PER_ROW:
            raise UsageAggregateError(
                f"row carries {len(unique)} minutes for one day; max {MAX_MINUTES_PER_ROW}"
            )
        evidence = _minute_evidence(row)
        if with_app:
            head: Tuple[Any, ...] = (router, mac, day, app)
        else:
            head = (router, mac, day)
        # 没有证据的分钟补 0，含义是「未知」；规则里 0 只会让判断退回旧口径。
        return [(*head, minute, *evidence.get(minute, (0, 0, 0, 0)), now)
                for minute in unique]

    def _upsert(
        self,
        *,
        table: str,
        rows: Iterable[Dict[str, Any]],
        keys: Sequence[str],
        values: Sequence[str],
        integer_timestamp: bool = False,
    ) -> int:
        now: Any = int(time.time()) if integer_timestamp else _now_text()

        # Validate everything before touching the database, so a malformed row
        # rejects the whole request instead of leaving a half-applied batch.
        prepared: List[tuple] = []
        for row in rows:
            record = self._prepare_row(row, keys, values, now)
            if record is not None:
                prepared.append(record)

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
        return self._write(sql, prepared)

    def _write(self, sql: str, prepared: List[tuple]) -> int:
        """Run one statement over validated rows in bounded transactions."""
        if not prepared:
            return 0
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
        now: Any,
    ) -> Optional[tuple]:
        if not isinstance(row, dict):
            return None
        record: Dict[str, Any] = {
            "date": _iso_date(row.get("date")),
            "mac": normalize_mac(row.get("mac")),
        }
        if "router" in keys:
            # The v3 payload has no router field; the Hub files the row under the
            # router it received it from (``router_key`` default) so a second
            # router can never overwrite the first one's day.
            record["router"] = router_key(row.get("router"))
        if not record["mac"]:
            return None
        if "hour" in keys:
            record["hour"] = _as_hour(row.get("hour"))
        if "app" in keys:
            app = str(row.get("app") or "").strip()
            if not app or len(app) > 64:
                return None
            record["app"] = app
        if "start_epoch" in keys:
            raw = row.get("start_epoch") if row.get("start_epoch") is not None else row.get("startEpoch")
            record["start_epoch"] = _as_count(raw)
            if record["start_epoch"] <= 0:
                return None
        for field in values:
            raw = row.get(field) if row.get(field) is not None else row.get(_camel(field))
            record[field] = _as_count(raw)
        if "end_epoch" in values:
            if record["end_epoch"] < record["start_epoch"]:
                raise UsageAggregateError("session end precedes start")
            if record["active_secs"] > record["end_epoch"] - record["start_epoch"]:
                raise UsageAggregateError("session active time exceeds its range")
        record["updated_at"] = now
        return tuple(record[column] for column in (*keys, *values, "updated_at"))

    # -- retention ---------------------------------------------------------

    def prune(
        self,
        *,
        today: Optional[str] = None,
        hourly_keep_days: int = DEFAULT_HOURLY_KEEP_DAYS,
        daily_keep_days: int = DEFAULT_DAILY_KEEP_DAYS,
        minute_keep_days: Optional[int] = None,
    ) -> Dict[str, int]:
        """Drop whole days that fall outside each table's retention window.

        ``keep_days`` counts **including today**, so ``10`` keeps today plus the
        nine preceding days.  This matches the relay's own prune, which keeps
        the newest N distinct dates present in the store.  The v3 minute and
        traffic tables are the primary record, so they keep at least as long as
        either legacy window unless told otherwise.
        """
        reference = _date.fromisoformat(_iso_date(today)) if today else _date.today()
        # `keep_days - 1` because the window is inclusive of today.
        hourly_cutoff = (
            reference - timedelta(days=max(0, hourly_keep_days - 1))
        ).isoformat()
        daily_cutoff = (
            reference - timedelta(days=max(0, daily_keep_days - 1))
        ).isoformat()
        minute_keep = int(minute_keep_days or max(
            hourly_keep_days, daily_keep_days, DEFAULT_DAILY_KEEP_DAYS))
        minute_cutoff = (reference - timedelta(days=max(0, minute_keep - 1))).isoformat()
        removed: Dict[str, int] = {}
        with self._lock:
            conn = self.connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.execute("DELETE FROM usage_hourly WHERE date < ?", (hourly_cutoff,))
                removed["hourly"] = cursor.rowcount or 0
                cursor = conn.execute("DELETE FROM usage_daily_app WHERE date < ?", (daily_cutoff,))
                removed["dailyApp"] = cursor.rowcount or 0
                cursor = conn.execute("DELETE FROM usage_app_session WHERE date < ?", (daily_cutoff,))
                removed["sessions"] = cursor.rowcount or 0
                cursor = conn.execute(
                    "DELETE FROM usage_device_minute WHERE date < ?", (minute_cutoff,))
                removed["deviceMinutes"] = cursor.rowcount or 0
                cursor = conn.execute(
                    "DELETE FROM usage_app_minute WHERE date < ?", (minute_cutoff,))
                removed["appMinutes"] = cursor.rowcount or 0
                cursor = conn.execute(
                    "DELETE FROM usage_device_traffic WHERE date < ?", (minute_cutoff,))
                removed["traffic"] = cursor.rowcount or 0
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()
        return removed

    # -- reads -------------------------------------------------------------

    def report(self, macs: Sequence[str], date: str, router: str = "") -> Dict[str, Any]:
        """The official ``上网统计`` shape: online minutes, hourly bars, apps.

        One day is rendered from exactly **one** basis: the v3 minute buckets
        when the router reported any for that day, the legacy
        second-accumulating tables otherwise.  ``basis`` says which.  Device
        traffic always comes from the firmware counters, never from flow bytes.
        ``router`` narrows the read to one router; empty means any.

        纯读 SQLite，附带新鲜度字段（``generatedAt`` / ``lastSampleAt`` /
        ``stale``）与 ``hasData`` —— 那一天什么都没记过是「暂无数据」，不是 0 分钟。
        """
        wanted = [normalize_mac(mac) for mac in macs if normalize_mac(mac)]
        day = _iso_date(date)
        if not wanted:
            return _decorate_report(_empty_report(day, [], basis="none"), None, day)
        with self._lock:
            conn = self.connect()
            try:
                key = str(router or "").strip().lower()[:128]
                traffic = _traffic_snapshot(conn, wanted, day, day, key)
                minutes = _minute_snapshot(conn, wanted, day, day, key)
                meta = _meta_snapshot(conn, wanted, key)
                latest = _latest_minute(conn, wanted, key)
                if not (traffic["daily"] or minutes or latest
                        or (meta or {}).get("lastSampleByMac")
                        or (meta or {}).get("routerLastSampleAt")):
                    # 归属键对不上（例如升级前记的行没有 router 名）时按「任意路由
                    # 器」重读一次，宁可少一个过滤条件也不要让用户看到空白页。
                    traffic = _traffic_snapshot(conn, wanted, day, day, "")
                    minutes = _minute_snapshot(conn, wanted, day, day, "")
                    meta = _meta_snapshot(conn, wanted, "")
                    latest = _latest_minute(conn, wanted, "")
                minute_day = minutes.get(day)
                if minute_day is not None:
                    report = _minute_report(day, wanted, minute_day, traffic)
                else:
                    legacy = _legacy_day_report(conn, wanted, day)
                    basis = "legacy" if (legacy.get("coverage") or {}).get("hasRecords") else "none"
                    report = {**legacy, "traffic": traffic, "basis": basis}
            finally:
                conn.close()
        return _decorate_report(report, meta, day, latest=latest)

    def traffic_report(
        self, macs: Sequence[str], start: str, end: str, router: str = ""
    ) -> Dict[str, Any]:
        """Per-day firmware device counters over a window (public read helper)."""
        wanted = [normalize_mac(mac) for mac in macs if normalize_mac(mac)]
        first, last = _iso_date(start), _iso_date(end)
        if not wanted:
            return _empty_traffic_block()
        with self._lock:
            conn = self.connect()
            try:
                return _traffic_snapshot(conn, wanted, first, last, router)
            finally:
                conn.close()

    def daily_totals(
        self, macs: Sequence[str], start: str, end: str, router: str = ""
    ) -> List[Dict[str, Any]]:
        """Per-day online minutes across a date range, **gap filled**.

        The App draws the 最近10天 chart straight from this, so every date in
        ``[start, end]`` is present — days with no activity come back as zero
        rather than being missing, and the client never has to do date maths or
        guess how many bars to render.  Each day keeps its own ``basis``.
        """
        wanted = [normalize_mac(mac) for mac in macs if normalize_mac(mac)]
        first = _date.fromisoformat(_iso_date(start))
        last = _date.fromisoformat(_iso_date(end))
        if last < first:
            first, last = last, first
        window = [(first + timedelta(days=offset)) for offset in range((last - first).days + 1)]

        minute_days: Dict[str, Dict[str, Any]] = {}
        seconds: Dict[str, tuple[int, int]] = {}
        late_ranges: Dict[str, List[Dict[str, Any]]] = {}
        if wanted:
            placeholders = ", ".join("?" for _ in wanted)
            with self._lock:
                conn = self.connect()
                try:
                    minute_days = _minute_snapshot(conn, wanted,
                                                   first.isoformat(), last.isoformat(),
                                                   router)
                    # Legacy rows are only read for days the router never sent
                    # minute buckets for, so a day can never be counted twice.
                    rows = conn.execute(
                        f"""SELECT date,
                                   SUM(active_secs) AS active_secs,
                                   SUM(CASE WHEN hour < ? THEN active_secs ELSE 0 END)
                                       AS late_night_secs
                            FROM usage_hourly
                            WHERE date BETWEEN ? AND ? AND mac IN ({placeholders})
                            GROUP BY date""",
                        (LATE_NIGHT_END_HOUR, first.isoformat(), last.isoformat(), *wanted),
                    ).fetchall()
                    # 家长请注意 needs the concrete late-night windows, not just a
                    # total. Session epochs are router-local (Beijing, UTC+8), so
                    # the hour is derived with a fixed +8h offset instead of the
                    # hub's own timezone.
                    session_rows = conn.execute(
                        f"""SELECT date, app, start_epoch, end_epoch, active_secs
                            FROM usage_app_session
                            WHERE date BETWEEN ? AND ? AND mac IN ({placeholders})
                              AND CAST(strftime('%H', start_epoch, {BEIJING_OFFSET_SQL})
                                       AS INTEGER) < ?
                            ORDER BY date, start_epoch""",
                        (first.isoformat(), last.isoformat(), *wanted, LATE_NIGHT_END_HOUR),
                    ).fetchall()
                finally:
                    conn.close()
            seconds = {
                str(row["date"]): (
                    int(row["active_secs"] or 0),
                    int(row["late_night_secs"] or 0),
                )
                for row in rows
                if str(row["date"]) not in minute_days
            }
            for row in session_rows:
                if str(row["date"]) in minute_days:
                    continue
                active = int(row["active_secs"] or 0)
                late_ranges.setdefault(str(row["date"]), []).append({
                    "app": str(row["app"]),
                    "startEpoch": int(row["start_epoch"]),
                    "endEpoch": int(row["end_epoch"]),
                    "minutes": _to_minutes(active),
                })

        entries: List[Dict[str, Any]] = []
        for day in window:
            key = day.isoformat()
            minute_day = minute_days.get(key)
            if minute_day is not None:
                online_minutes = int(minute_day["onlineMinutes"])
                late_minutes = int(minute_day["lateNightMinutes"])
                entries.append({
                    "date": key,
                    "onlineSeconds": online_minutes * MINUTE_SECONDS,
                    "onlineMinutes": online_minutes,
                    "lateNightSeconds": late_minutes * MINUTE_SECONDS,
                    "lateNightMinutes": late_minutes,
                    "lateNightRanges": _late_night_ranges(minute_day),
                    "coverage": "recorded",
                    "basis": "minutes",
                })
                continue
            legacy = seconds.get(key, (0, 0))
            entries.append({
                "date": key,
                "onlineSeconds": legacy[0],
                "onlineMinutes": _to_minutes(legacy[0]),
                "lateNightSeconds": legacy[1],
                "lateNightMinutes": _to_minutes(legacy[1]),
                "lateNightRanges": late_ranges.get(key, []),
                "coverage": "recorded" if key in seconds else "no_record",
                "basis": "legacy" if key in seconds else "none",
            })
        return entries

    def app_totals(
        self, macs: Sequence[str], start: str, end: str, router: str = ""
    ) -> List[Dict[str, Any]]:
        """Per-app totals summed across a date range (the 最近N天 app summary).

        Returns the same row shape as :meth:`report`'s ``apps`` so the client can
        render both tabs with one parser.  Each day of the window contributes on
        its own basis: minute buckets where they exist, legacy rows elsewhere.
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
                minute_days = _minute_snapshot(conn, wanted, first, last, router)
                rows = conn.execute(
                    f"""SELECT date, app,
                               SUM(active_secs) AS active_secs,
                               SUM(tx_bytes)    AS tx_bytes,
                               SUM(rx_bytes)    AS rx_bytes,
                               SUM(sessions)    AS sessions
                        FROM usage_daily_app
                        WHERE date BETWEEN ? AND ? AND mac IN ({placeholders})
                        GROUP BY date, app""",
                    (first, last, *wanted),
                ).fetchall()
                session_rows = conn.execute(
                    f"""SELECT date, app, start_epoch, end_epoch, active_secs
                        FROM usage_app_session
                        WHERE date BETWEEN ? AND ? AND mac IN ({placeholders})
                        ORDER BY date, app, start_epoch""",
                    (first, last, *wanted),
                ).fetchall()
            finally:
                conn.close()

        # app -> aggregate over the window; each day contributes on its own
        # basis, so a day is never counted twice.
        totals: Dict[str, Dict[str, Any]] = {}

        def slot(app: str) -> Dict[str, Any]:
            return totals.setdefault(app, {
                "minutes": 0, "minuteRuns": 0, "sessionRows": 0, "sessionColumn": 0,
                "txBytes": 0, "rxBytes": 0, "ranges": [],
            })

        for row in rows:
            if str(row["date"]) in minute_days:
                continue
            entry = slot(str(row["app"]))
            active_seconds = int(row["active_secs"] or 0)
            entry["minutes"] += _to_minutes(active_seconds)
            entry["txBytes"] += int(row["tx_bytes"] or 0)
            entry["rxBytes"] += int(row["rx_bytes"] or 0)
            # A day without session rows has no verifiable ranges to count, so
            # its reported session count falls back to the legacy column.
            entry["sessionColumn"] += int(row["sessions"] or 0)
        for row in session_rows:
            if str(row["date"]) in minute_days:
                continue
            entry = slot(str(row["app"]))
            active_seconds = int(row["active_secs"] or 0)
            entry["sessionRows"] += 1
            entry["ranges"].append({
                "startEpoch": int(row["start_epoch"]),
                "endEpoch": int(row["end_epoch"]),
                "activeSeconds": active_seconds,
                "minutes": _to_minutes(active_seconds),
            })
        for day in minute_days.values():
            for app, data in day["apps"].items():
                entry = slot(app)
                entry["minutes"] += int(data["minutes"])
                entry["minuteRuns"] += len(data["runs"])
                # The v3 payload carries no per-app bytes: reconstructing them
                # would be invented data, so they stay 0.
                entry["ranges"].extend(dict(run) for run in data["runs"])
        for entry in totals.values():
            entry["sessions"] = entry["minuteRuns"] + (
                entry["sessionRows"] or entry["sessionColumn"])
            entry["sessionRanges"] = sorted(
                entry["ranges"], key=lambda item: int(item.get("startEpoch") or 0)
            )
        return sorted(
            (
                {
                    "app": app,
                    "minutes": entry["minutes"],
                    "sessions": entry["sessions"],
                    "sessionRanges": entry["sessionRanges"],
                    "txBytes": entry["txBytes"],
                    "rxBytes": entry["rxBytes"],
                }
                for app, entry in totals.items()
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
                sessions = conn.execute("SELECT COUNT(*) AS n FROM usage_app_session").fetchone()["n"]
                device_minutes = conn.execute(
                    "SELECT COUNT(*) AS n FROM usage_device_minute").fetchone()["n"]
                app_minutes = conn.execute(
                    "SELECT COUNT(*) AS n FROM usage_app_minute").fetchone()["n"]
                traffic_rows = conn.execute(
                    "SELECT COUNT(*) AS n FROM usage_device_traffic").fetchone()["n"]
                guard_rows = conn.execute(
                    "SELECT COUNT(*) AS n FROM child_guard_device").fetchone()["n"]
                meta = conn.execute(
                    "SELECT COUNT(*) AS n, MAX(last_sample_at) AS newest "
                    "FROM usage_ingest_meta WHERE mac <> '*'").fetchone()
                span = conn.execute(
                    "SELECT MIN(date) AS lo, MAX(date) AS hi FROM ("
                    "SELECT date FROM usage_hourly UNION ALL "
                    "SELECT date FROM usage_daily_app UNION ALL "
                    "SELECT date FROM usage_app_session UNION ALL "
                    "SELECT date FROM usage_device_minute UNION ALL "
                    "SELECT date FROM usage_app_minute UNION ALL "
                    "SELECT date FROM usage_device_traffic)"
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
            "sessionRows": int(sessions or 0),
            "deviceMinuteRows": int(device_minutes or 0),
            "appMinuteRows": int(app_minutes or 0),
            "trafficRows": int(traffic_rows or 0),
            "guardDeviceRows": int(guard_rows or 0),
            "ingestMetaRows": int((meta["n"] if meta else 0) or 0),
            "lastSampleAt": int((meta["newest"] if meta else 0) or 0),
            "bytesOnDisk": size,
            "firstDate": span["lo"] if span else None,
            "lastDate": span["hi"] if span else None,
            "database": str(self.db_path),
        }


# -- report composition ------------------------------------------------------
#
# Every helper below reads what the router actually reported.  Nothing here
# estimates a duration from bytes, averages a bucket over its neighbours, or
# fills an empty hour with a plausible value: an hour with no minute rows is 0.


def _empty_report(date_value: str, macs: Sequence[str], *, basis: str) -> Dict[str, Any]:
    """The explicit ``暂无记录`` skeleton: no bars, no invented numbers."""
    return {
        "date": date_value,
        "onlineSeconds": 0,
        "onlineMinutes": 0,
        "lateNightSeconds": 0,
        "lateNightMinutes": 0,
        "hourly": [],
        "apps": [],
        "macs": [normalize_mac(mac) for mac in macs if normalize_mac(mac)],
        "basis": basis,
        "traffic": _empty_traffic_block(),
        "coverage": {"status": "no_record", "hasRecords": False},
    }


def _empty_traffic_block() -> Dict[str, Any]:
    return {"txBytes": 0, "rxBytes": 0, "totalBytes": 0, "daily": []}


def _beijing_hour(minute_epoch: int) -> int:
    """分钟戳所属的北京小时，与 ``BEIJING_OFFSET_SQL`` 同一套换算。"""
    return ((int(minute_epoch) + 8 * 3600) // 3600) % 24


#: RDPI 的官方 name 直接来自固件特征库，命名并不统一：百度 App 在库里叫
#: ``baiduAPP_homePage`` / ``baiduAPP_search``，中继按 ``_`` 截断后只剩
#: ``baiduAPP``，家长端就显示成了一个英文串。这里在读取时归一，老数据和新数据
#: 一起生效，不需要动中继也不需要重装 App。
#: 只归一已经核对过的：``百度网盘`` / ``百度贴吧`` 是另外两个应用，不能并进来。
APP_DISPLAY_ALIASES: Dict[str, str] = {
    "baiduAPP": "百度",
}


def display_app_name(app: Any) -> str:
    name = str(app or "").strip()
    return APP_DISPLAY_ALIASES.get(name, name)


def _minute_runs(minutes: Iterable[int], gap_minutes: int) -> List[List[int]]:
    """把分钟戳切成连续段：中间空了超过 ``gap_minutes`` 个空分钟就断成两段。"""
    ordered = sorted({int(value) for value in minutes})
    runs: List[List[int]] = []
    current: List[int] = []
    limit = MINUTE_SECONDS * (int(gap_minutes) + 1)
    for value in ordered:
        if current and value - current[-1] > limit:
            runs.append(current)
            current = []
        current.append(value)
    if current:
        runs.append(current)
    return runs


def _run_row(run: List[int]) -> Dict[str, Any]:
    """一段连续使用的展示行。时段结束在最后一个活跃分钟的末尾。"""
    return {
        "startEpoch": min(run),
        "endEpoch": max(run) + MINUTE_SECONDS,
        # 一个自然分钟只能确认「这一分钟里有过流量」，确认不了它占了多少秒。按
        # 秒计真实跨度要等中继把分钟内的首末活跃窗口一起报上来。
        "activeSeconds": len(run) * MINUTE_SECONDS,
        "minutes": len(run),
    }


def _kept_runs(minutes: Iterable[int], *, gap_minutes: int,
               min_run_minutes: int) -> List[List[int]]:
    return [run for run in _minute_runs(minutes, gap_minutes)
            if len(run) >= min_run_minutes]


#: 夜间即时应用的证据门槛。一个 window = 一个带 ≥256B payload 的 5 秒采样窗口，
#: 所以 6 个约等于「这一分钟里至少 30 秒真在传东西」；心跳包一个窗口就完事。
NIGHT_INSTANT_MIN_WINDOWS = int(os.environ.get("USAGE_NIGHT_INSTANT_MIN_WINDOWS", "6"))
#: 夜间算「有人在用」的上行门槛：设备主动发过东西，而不是只被推送、被备份、被更新。
NIGHT_MIN_UP_BYTES = int(os.environ.get("USAGE_NIGHT_MIN_UP_BYTES", str(10 * 1024)))


def _instant_minute_counts(evidence: Optional[Tuple[int, int, int, int]]) -> bool:
    """即时应用（支付/搜索）的夜间单分钟门槛。None = 中继没测过 -> 退回旧口径。"""
    if evidence is None:
        return True
    up, _down, windows, _flows = evidence
    return windows >= NIGHT_INSTANT_MIN_WINDOWS and up >= NIGHT_MIN_UP_BYTES


def _run_has_uplink(run: Sequence[int],
                    evidence_by_minute: Mapping[int, Optional[Tuple[int, int, int, int]]]) -> bool:
    """普通应用的夜间段门槛：整段里至少有一分钟设备真的上行过。

    段内只要有一分钟没有证据（v3 写的行），就当作未知放行 —— 拿「没测到」当
    「没发生」，会把升级当天的数字凭空砍一截。
    """
    minutes = list(run)
    if any(evidence_by_minute.get(minute) is None for minute in minutes):
        return True
    return any((evidence_by_minute[minute] or (0, 0, 0, 0))[0] >= NIGHT_MIN_UP_BYTES
               for minute in minutes)


def _qualifying_usage(
    device_minutes: Any,
    app_minutes: Mapping[str, Any],
) -> Dict[str, Any]:
    """一天的分钟行 -> 家长端计入统计的分钟。列表页与详情页共用这一份口径。

    夜间（00:00-05:59）只认「有应用归属、且这一段连续到
    ``NIGHT_MIN_RUN_MINUTES``」的分钟。设备分钟在夜间不能用：中继按固件的每 IP
    字节差值判定活跃，门槛是整分钟 1KB 或一条新连接，睡眠中的手机每分钟都过，
    实测（2026-09-21 BE72）00:00-05:59 有 75% 的分钟根本没有应用归属。

    白天（06:00-23:59）仍按设备分钟计，只丢掉整段不足 ``DAY_MIN_RUN_MINUTES``
    的——RDPI 认不出的真实使用（浏览器、PC 游戏、新装应用）不能一并抹掉。

    中继 v4 起，每个分钟还带着它自己的证据（上下行字节、5 秒窗口数、新连接数），
    于是夜间还能再问一句「这台设备那会儿真的在发东西吗」：即时应用要单分钟够
    ``NIGHT_INSTANT_MIN_WINDOWS`` 且上行过 ``NIGHT_MIN_UP_BYTES``，普通应用要整段
    里出现过上行。没有证据的行（v3 中继、升级前写的历史）一律退回上面那套旧口径。

    被过滤掉的分钟彻底丢弃，不另立「后台活动」池。
    """
    device_map = _evidence_map(device_minutes)
    unique_device = set(device_map)
    night_device = {m for m in unique_device if _beijing_hour(m) < LATE_NIGHT_END_HOUR}
    counted = {m for run in _kept_runs(unique_device - night_device,
                                       gap_minutes=DAY_MERGE_GAP_MINUTES,
                                       min_run_minutes=DAY_MIN_RUN_MINUTES)
               for m in run}

    apps: Dict[str, Dict[str, Any]] = {}
    for app, values in app_minutes.items():
        evidence = _evidence_map(values)
        unique = set(evidence)
        night = {m for m in unique if _beijing_hour(m) < LATE_NIGHT_END_HOUR}
        instant = _is_instant_use(app)
        # 证据门槛只能筛「夜间段要不要算」，绝不能把筛掉的分钟挪回白天：
        # 白天的集合是从下面 unique - night 来的，所以 night 本身保持原样。
        candidates = ({m for m in night if _instant_minute_counts(evidence.get(m))}
                      if instant else night)
        night_runs = _kept_runs(candidates, gap_minutes=NIGHT_MERGE_GAP_MINUTES,
                                min_run_minutes=_min_run_minutes(app, night=True))
        day_runs = _kept_runs(unique - night, gap_minutes=DAY_MERGE_GAP_MINUTES,
                              min_run_minutes=_min_run_minutes(app, night=False))
        if not instant:
            night_runs = [run for run in night_runs if _run_has_uplink(run, evidence)]
        counted.update(m for run in night_runs for m in run)
        if instant:
            # 短交互应用的分钟也要进设备时长，否则应用列表里写着 1 分钟、上面的
            # 「今日上网时长」却一分都不涨。夜间那部分已经由 night_runs 带进来了。
            counted.update(m for run in day_runs for m in run)
        kept = night_runs + day_runs
        if not kept:
            continue
        apps[app] = {
            "minutes": len({m for run in kept for m in run}),
            "runs": [_run_row(run) for run in kept],
            "lateNightRuns": [_run_row(run) for run in night_runs],
        }

    hourly: Dict[int, int] = {}
    for value in counted:
        hour = _beijing_hour(value)
        hourly[hour] = hourly.get(hour, 0) + 1
    return {
        "hourly": hourly,
        "onlineMinutes": len(counted),
        "lateNightMinutes": sum(count for hour, count in hourly.items()
                                if hour < LATE_NIGHT_END_HOUR),
        "apps": apps,
    }


def _minute_snapshot(
    conn: sqlite3.Connection,
    wanted: Sequence[str],
    first: str,
    last: str,
    router: str = "",
) -> Dict[str, Dict[str, Any]]:
    """Minute-bucket facts per day, keyed by the date the router reported.

    Only days that actually have minute rows appear, which is what lets the
    caller decide the basis per day instead of blending two measurements.
    ``router`` narrows the read to one router; empty means every router the Hub
    has heard from, which is what a single-router installation sees anyway.

    过滤口径全在 :func:`_qualifying_usage`，和 ``/overview`` 用的是同一个函数：
    列表页的「凌晨还在上网」和详情页的夜间时长不能是两个数。
    """
    holders = ", ".join("?" for _ in wanted)
    clause, prefix = _router_clause(router)
    window = (*prefix, first, last, *wanted)
    device: Dict[str, Dict[int, Optional[Tuple[int, int, int, int]]]] = {}
    for row in conn.execute(
        f"""SELECT DISTINCT date, minute_epoch, up_bytes, down_bytes, windows, new_flows
            FROM usage_device_minute
            WHERE {clause}date BETWEEN ? AND ? AND mac IN ({holders})""",
        window,
    ):
        device.setdefault(str(row["date"]), {})[int(row["minute_epoch"])] = _row_evidence(row)
    apps: Dict[str, Dict[str, Dict[int, Optional[Tuple[int, int, int, int]]]]] = {}
    for row in conn.execute(
        f"""SELECT DISTINCT date, app, minute_epoch, up_bytes, down_bytes, windows, new_flows
            FROM usage_app_minute
            WHERE {clause}date BETWEEN ? AND ? AND mac IN ({holders})""",
        window,
    ):
        apps.setdefault(str(row["date"]), {}).setdefault(
            display_app_name(row["app"]), {})[int(row["minute_epoch"])] = _row_evidence(row)

    days: Dict[str, Dict[str, Any]] = {}
    for day in sorted(set(device) | set(apps)):
        usage = _qualifying_usage(device.get(day, {}), apps.get(day, {}))
        usage["rawMinutes"] = len(device.get(day, {})) + sum(
            len(minutes) for minutes in apps.get(day, {}).values())
        days[day] = usage
    return days


def _late_night_ranges(minute_day: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The 家长请注意 windows, from the same minute rows as everything else."""
    ranges: List[Dict[str, Any]] = []
    for app, data in minute_day.get("apps", {}).items():
        for run in data.get("lateNightRuns") or []:
            ranges.append({
                "app": app,
                "startEpoch": run["startEpoch"],
                "endEpoch": run["endEpoch"],
                "minutes": run["minutes"],
            })
    return sorted(ranges, key=lambda item: int(item["startEpoch"]))


def _minute_report(
    day: str,
    wanted: Sequence[str],
    minute_day: Dict[str, Any],
    traffic: Dict[str, Any],
) -> Dict[str, Any]:
    """The v3 report: every minute count is a count of minute rows."""
    hourly_minutes = {int(hour): int(minutes) for hour, minutes in minute_day["hourly"].items()}
    online_minutes = int(minute_day["onlineMinutes"])
    late_night_minutes = int(minute_day["lateNightMinutes"])
    apps: Dict[str, Dict[str, Any]] = minute_day["apps"]
    app_rows = sorted(
        (
            {
                "app": app,
                "minutes": int(data["minutes"]),
                "sessions": len(data["runs"]),
                "sessionRanges": [dict(run) for run in data["runs"]],
                # The v3 payload has no per-app bytes and nothing else measures
                # them per app, so they are 0 rather than a reconstruction.
                "txBytes": 0,
                "rxBytes": 0,
            }
            for app, data in apps.items()
        ),
        key=lambda item: (-item["minutes"], item["app"]),
    )
    # 「路由器那天记过分钟行」和「过滤后还剩多少」是两件事：一整晚只有保活唤醒
    # 的一天是 0 分钟，不是「暂无记录」。
    recorded = bool(minute_day.get("rawMinutes") or online_minutes or app_rows)
    return {
        "date": day,
        "onlineSeconds": online_minutes * MINUTE_SECONDS,
        "onlineMinutes": online_minutes,
        "lateNightSeconds": late_night_minutes * MINUTE_SECONDS,
        "lateNightMinutes": late_night_minutes,
        # App 的单日视图直接读顶层这个字段，缺了它「深夜时段」列表就永远是空的。
        "lateNightRanges": _late_night_ranges(minute_day),
        # A full 24-slot axis; hours without minute rows are 0, never invented.
        "hourly": [
            {
                "hour": hour,
                "minutes": hourly_minutes.get(hour, 0),
                "txBytes": 0,
                "rxBytes": 0,
            }
            for hour in range(24)
        ],
        "apps": app_rows,
        "macs": list(wanted),
        "basis": "minutes",
        "traffic": traffic,
        "coverage": {"status": "recorded" if recorded else "no_record",
                     "hasRecords": recorded},
    }


def _traffic_snapshot(
    conn: sqlite3.Connection,
    wanted: Sequence[str],
    first: str,
    last: str,
    router: str = "",
) -> Dict[str, Any]:
    """Per-day device traffic, straight from the firmware counters."""
    holders = ", ".join("?" for _ in wanted)
    clause, prefix = _router_clause(router)
    rows = conn.execute(
        f"""SELECT date, SUM(tx_bytes) AS tx_bytes, SUM(rx_bytes) AS rx_bytes
            FROM usage_device_traffic
            WHERE {clause}date BETWEEN ? AND ? AND mac IN ({holders})
            GROUP BY date ORDER BY date""",
        (*prefix, first, last, *wanted),
    ).fetchall()
    daily: List[Dict[str, Any]] = []
    total_tx = total_rx = 0
    for row in rows:
        tx = int(row["tx_bytes"] or 0)
        rx = int(row["rx_bytes"] or 0)
        total_tx += tx
        total_rx += rx
        daily.append({
            "date": str(row["date"]),
            "txBytes": tx,
            "rxBytes": rx,
            # Derived here, never stored, so the three figures cannot disagree.
            "totalBytes": tx + rx,
        })
    return {
        "txBytes": total_tx,
        "rxBytes": total_rx,
        "totalBytes": total_tx + total_rx,
        "daily": daily,
    }


# -- freshness ---------------------------------------------------------------


def _beijing_date(epoch: float) -> str:
    """The router-local calendar day an epoch falls on (UTC+8, no DST)."""
    return time.strftime("%Y-%m-%d", time.gmtime(int(epoch) + 8 * 3600))


def _minute_floor(epoch: float) -> int:
    return int(epoch) - int(epoch) % MINUTE_SECONDS


def _meta_snapshot(conn: sqlite3.Connection, wanted: Sequence[str],
                   router: str = "") -> Dict[str, Any]:
    """``usage_ingest_meta``: 样本到过哪里，以及这台路由器最后一次推算是何时。"""
    holders = ", ".join("?" for _ in (*wanted, ROUTER_META_MAC))
    clause, prefix = _router_clause(router)
    rows = conn.execute(
        f"""SELECT mac, last_sample_at, updated_at FROM usage_ingest_meta
            WHERE {clause}mac IN ({holders})""",
        (*prefix, *wanted, ROUTER_META_MAC),
    ).fetchall()
    per_mac: Dict[str, int] = {}
    router_seen = 0
    for row in rows:
        stamp = int(row["last_sample_at"] or 0)
        mac = str(row["mac"])
        if mac == ROUTER_META_MAC:
            router_seen = max(router_seen, stamp)
        else:
            per_mac[mac] = max(per_mac.get(mac, 0), stamp)
    return {"lastSampleByMac": per_mac, "routerLastSampleAt": router_seen}


def _latest_minute(conn: sqlite3.Connection, wanted: Sequence[str],
                   router: str = "") -> Dict[str, int]:
    """Newest device-minute row per MAC over the whole retained window."""
    holders = ", ".join("?" for _ in wanted)
    clause, prefix = _router_clause(router)
    rows = conn.execute(
        f"""SELECT mac, MAX(minute_epoch) AS newest FROM usage_device_minute
            WHERE {clause}mac IN ({holders}) GROUP BY mac""",
        (*prefix, *wanted),
    ).fetchall()
    return {str(row["mac"]): int(row["newest"] or 0) for row in rows}


def _decorate_report(
    report: Dict[str, Any],
    meta: Optional[Dict[str, Any]],
    day: str,
    *,
    latest: Optional[Dict[str, int]] = None,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Attach the fields the App needs to tell 0 分钟 and 暂无数据 apart.

    ``lastSampleAt`` is the newest thing actually observed for these MACs: the
    sample stamp the relay reported and the newest minute row, whichever is
    later.  ``stale`` only ever applies to *today* — yesterday's numbers are
    complete, not out of date, so a past date is never flagged.
    """
    stamp = int(now if now is not None else time.time())
    samples = dict((meta or {}).get("lastSampleByMac") or {})
    newest = dict(latest or {})
    macs = [str(mac) for mac in report.get("macs") or []]
    device_sample = max([*(_value_or_zero(samples, mac) for mac in macs),
                         *(_value_or_zero(newest, mac) for mac in macs)], default=0)
    last_sample = max(device_sample, int((meta or {}).get("routerLastSampleAt") or 0))
    is_today = str(report.get("date") or day) == _beijing_date(stamp)
    covered = bool((report.get("coverage") or {}).get("hasRecords"))
    traffic_days = (report.get("traffic") or {}).get("daily") or []
    online_minutes = int(report.get("onlineMinutes") or 0)
    newest_minute = max((_value_or_zero(newest, mac) for mac in macs), default=0)
    return {
        **report,
        "generatedAt": stamp,
        "lastSampleAt": last_sample,
        "stale": bool(is_today and (last_sample <= 0
                                    or stamp - last_sample > STALE_AFTER_SECONDS)),
        "hasData": bool(covered or traffic_days or online_minutes),
        "todayMinutes": online_minutes,
        # 一个自然分钟只在其结束后结算，所以「正在上网」看本分钟或上一分钟。
        "activeNow": bool(is_today and newest_minute
                          >= _minute_floor(stamp) - ACTIVE_NOW_LAG_SECONDS),
    }


def _value_or_zero(mapping: Dict[str, int], mac: str) -> int:
    try:
        return int(mapping.get(mac) or 0)
    except (TypeError, ValueError):
        return 0


def _guard_read(conn: sqlite3.Connection, wanted: Sequence[str], day: str,
                router: Any) -> Dict[str, Any]:
    """The overview's reads on one connection: 分钟行、应用分钟、meta。"""
    holders = ", ".join("?" for _ in wanted)
    key = str(router or "").strip().lower()[:128]
    clause, prefix = _router_clause(key)

    minutes: Dict[str, Dict[int, Optional[Tuple[int, int, int, int]]]] = {}
    for row in conn.execute(
        f"""SELECT DISTINCT mac, minute_epoch, up_bytes, down_bytes, windows, new_flows
            FROM usage_device_minute
            WHERE {clause}date = ? AND mac IN ({holders})
            ORDER BY mac, minute_epoch""",
        (*prefix, day, *wanted),
    ):
        minutes.setdefault(str(row["mac"]), {})[int(row["minute_epoch"])] = _row_evidence(row)

    apps: Dict[str, Dict[str, Dict[int, Optional[Tuple[int, int, int, int]]]]] = {}
    for row in conn.execute(
        f"""SELECT DISTINCT mac, app, minute_epoch, up_bytes, down_bytes, windows, new_flows
            FROM usage_app_minute
            WHERE {clause}date = ? AND mac IN ({holders})
            ORDER BY mac, app, minute_epoch""",
        (*prefix, day, *wanted),
    ):
        apps.setdefault(str(row["mac"]), {}).setdefault(
            display_app_name(row["app"]), {})[int(row["minute_epoch"])] = _row_evidence(row)

    latest: Dict[str, int] = {}
    for row in conn.execute(
        f"""SELECT mac, MAX(minute_epoch) AS newest FROM usage_device_minute
            WHERE {clause}mac IN ({holders}) GROUP BY mac""",
        (*prefix, *wanted),
    ):
        latest[str(row["mac"])] = int(row["newest"] or 0)

    seen: Dict[str, int] = {}
    router_seen = 0
    meta_holders = ", ".join("?" for _ in (*wanted, ROUTER_META_MAC))
    for row in conn.execute(
        f"""SELECT mac, last_sample_at FROM usage_ingest_meta
            WHERE {clause}mac IN ({meta_holders})""",
        (*prefix, *wanted, ROUTER_META_MAC),
    ):
        stamp = int(row["last_sample_at"] or 0)
        if str(row["mac"]) == ROUTER_META_MAC:
            router_seen = max(router_seen, stamp)
        else:
            seen[str(row["mac"])] = max(seen.get(str(row["mac"]), 0), stamp)

    return {
        "date": day,
        "minutesByMac": minutes,
        "appsByMac": apps,
        "latestByMac": latest,
        "metaByMac": seen,
        "routerLastSampleAt": router_seen,
    }


def _merge_minutes(target: Dict[int, Optional[Tuple[int, int, int, int]]],
                   source: Mapping[Any, Any]) -> None:
    """把同一台设备另一块网卡的分钟并进来。

    分钟仍是集合（同一分钟只算一次），字节和窗口数按列相加。任何一侧没有证据，
    合并结果就按「未知」处理 —— 拿「没测到」去参与判断，列表页和详情页就会变成
    两个口径，这正是这个函数所在路径以前出过的错。
    """
    for minute, values in (source or {}).items():
        slot = int(minute)
        evidence = tuple(values) if values and any(values) else None
        if slot not in target:
            target[slot] = evidence
        elif target[slot] is None or evidence is None:
            target[slot] = None
        else:
            target[slot] = tuple(a + b for a, b in zip(target[slot], evidence))


def build_guard_overview(
    store: Optional[UsageAggregateStore],
    *,
    router: str = "",
    devices: Optional[Iterable[Dict[str, Any]]] = None,
    presence: Optional[Dict[str, bool]] = None,
    now_epoch: Optional[int] = None,
    top_app_limit: int = 3,
) -> Dict[str, Any]:
    """整台路由器的设备概览：一次 SQL 读取，零路由器流量。

    App 的列表页以前要为每台设备 fan-out plans/runtime/usage-report/usage，其中
    任何一个都可能把读取挂在路由器上。这里所有数字都来自 Hub 已经收到的分钟行，
    所以``online`` 只能给不出时才给 ``null``，绝不为了它去问路由器。

    ``devices`` 是 ``child_guard_device`` 的行（``uid`` / ``macs`` / ``name`` /
    ``blocked`` / ``blockedUntilEpoch`` / ``updatedAt``）；``presence`` 是 Hub 设备
    快照里的 ``mac -> 是否在线``，``None`` 表示 Hub 这边没有可信的在线状态。
    """
    stamp = int(now_epoch if now_epoch is not None else time.time())
    day = _beijing_date(stamp)
    rows = [device for device in (devices or []) if isinstance(device, dict)]
    macs: List[str] = []
    for device in rows:
        for mac in _split_macs(device.get("macs")):
            if mac not in macs:
                macs.append(mac)
    snapshot: Dict[str, Any] = {
        "minutesByMac": {}, "appsByMac": {}, "latestByMac": {}, "metaByMac": {},
        "routerLastSampleAt": 0,
    }
    if store is not None and macs:
        try:
            snapshot = store.guard_snapshot(router, macs, day)
        except Exception:  # pragma: no cover - 概览宁可空着也不要 500
            snapshot = {**snapshot}
    minutes_by_mac = snapshot.get("minutesByMac") or {}
    apps_by_mac = snapshot.get("appsByMac") or {}
    latest_by_mac = snapshot.get("latestByMac") or {}
    meta_by_mac = snapshot.get("metaByMac") or {}
    active_floor = _minute_floor(stamp) - ACTIVE_NOW_LAG_SECONDS
    # 计划是 Hub 缓存的快照：读它零路由器流量，所以生效态跟今天时长一样，
    # 路由器掉线时也照样能报「禁网中 · 至 17:00」。
    plans_by_uid: Dict[str, List[Dict[str, Any]]] = {}
    if store is not None:
        try:
            plans_by_uid = store.guard_plans(router)
        except Exception:  # pragma: no cover - 概览宁可少一个字段也不要 500
            plans_by_uid = {}

    entries: List[Dict[str, Any]] = []
    device_last_sample = 0
    for device in rows:
        device_macs = [mac for mac in _split_macs(device.get("macs")) if mac]
        # 同一台设备的两块网卡在同一分钟只算一次：分钟是集合，不是求和。
        raw_device: Dict[int, Optional[Tuple[int, int, int, int]]] = {}
        for mac in device_macs:
            _merge_minutes(raw_device, minutes_by_mac.get(mac) or {})
        raw_apps: Dict[str, Dict[int, Optional[Tuple[int, int, int, int]]]] = {}
        for mac in device_macs:
            for app, minutes in (apps_by_mac.get(mac) or {}).items():
                _merge_minutes(raw_apps.setdefault(str(app), {}), minutes or {})
        # 和详情页同一个函数：列表页的「凌晨还在上网」不能和点进去的夜间时长是
        # 两个数。
        usage = _qualifying_usage(raw_device, raw_apps)
        today_minutes = int(usage["onlineMinutes"])
        late_minutes = int(usage["lateNightMinutes"])
        top_apps = [
            {"app": app, "minutes": data["minutes"]}
            for app, data in sorted(
                usage["apps"].items(), key=lambda item: (-item[1]["minutes"], item[0])
            )[:max(1, top_app_limit)]
        ]
        seen = max([_value_or_zero(meta_by_mac, mac) for mac in device_macs]
                   + [_value_or_zero(latest_by_mac, mac) for mac in device_macs],
                   default=0)
        device_last_sample = max(device_last_sample, seen)
        has_rows = bool(raw_device or raw_apps)
        # 「此刻在不在上网」是物理事实，用未过滤的分钟判断：过滤只决定时长怎么算。
        active_now = any(minute >= active_floor for minute in raw_device)
        # 「从未有过数据」和「今天还没上网」是两件事，App 显示的文字也不同。
        has_data = bool(has_rows or seen > 0)
        uid = _guard_uid(device.get("uid"))
        schedule = schedule_state(plans_by_uid.get(uid), stamp)
        entries.append({
            "uid": str(device.get("uid") or ""),
            "macs": device_macs,
            "name": str(device.get("name") or ""),
            "online": _device_online(device_macs, presence),
            "activeNow": bool(active_now),
            "todayMinutes": today_minutes,
            "hasData": has_data,
            "topApps": top_apps,
            # 临时放行走的是固件的 skip 通道：pause 期间 block 不生效。所以「此刻是否
            # 被禁网」必须同时看两个字段 —— 只读 block 会出现界面上「禁网中」、孩子
            # 实际能上网的反向假象。
            "blocked": bool(device.get("blocked")) and _as_count(device.get("passUntilEpoch")) <= stamp,
            "blockedUntilEpoch": (
                0 if _as_count(device.get("passUntilEpoch")) > stamp
                else _as_count(device.get("blockedUntilEpoch"))
            ),
            "passUntilEpoch": _as_count(device.get("passUntilEpoch")),
            "planCount": schedule["planCount"],
            "schedule": schedule["schedule"],
            "currentRange": schedule["currentRange"],
            "blockedRange": schedule.get("blockedRange"),
            "nextChangeAtEpoch": schedule["nextChangeAtEpoch"],
            "minutesToChange": schedule["minutesToChange"],
            "attention": _attention_state(today_minutes, late_minutes, has_rows),
            "lastSampleAt": seen,
            "stale": bool(seen <= 0 or stamp - seen > STALE_AFTER_SECONDS),
            "updatedAt": _as_count(device.get("updatedAt")),
        })

    last_sample = max([device_last_sample,
                       int(snapshot.get("routerLastSampleAt") or 0)], default=0)
    return {
        "router": router_key(router),
        "date": day,
        "generatedAt": stamp,
        "lastSampleAt": last_sample,
        "stale": bool(last_sample <= 0 or stamp - last_sample > STALE_AFTER_SECONDS),
        "devices": entries,
    }


def _device_online(device_macs: Sequence[str],
                   presence: Optional[Dict[str, bool]]) -> Optional[bool]:
    """Hub 快照里的在线状态；缺信息就是 ``None``（unknown），不是「离线」。"""
    if presence is None or not device_macs:
        return None
    states = [presence.get(mac) for mac in device_macs]
    if any(state is True for state in states):
        return True
    if any(state is None for state in states):
        return None
    return False


def _attention_state(today_minutes: int, late_minutes: int,
                     has_rows: bool) -> Dict[str, Any]:
    """提醒只认真实分钟行；那一天没数据时状态是 unknown，不是「没事」。"""
    if not has_rows:
        state, text = "unknown", ""
    elif late_minutes > 0:
        state, text = "alert", f"凌晨还在上网（{late_minutes} 分钟）"
    elif today_minutes >= ATTENTION_NOTICE_MINUTES:
        state, text = "notice", f"今天已上网 {today_minutes} 分钟"
    else:
        state, text = "none", ""
    return {
        "state": state,
        "lateNightMinutes": int(late_minutes),
        "text": text,
        "hasAttention": state in ("alert", "notice"),
    }


def _legacy_day_report(
    conn: sqlite3.Connection, wanted: Sequence[str], day: str
) -> Dict[str, Any]:
    """Yesterday's report, from the second-accumulating tables.

    Kept so the 10-day history of routers still on the v2 payload does not go
    blank.  This is the *only* place ``_to_minutes`` (round seconds to minutes)
    still runs, and the caller labels it ``basis: "legacy"``.
    """
    placeholders = ", ".join("?" for _ in wanted)
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
    sessions = conn.execute(
        f"""SELECT app, start_epoch, end_epoch, active_secs
            FROM usage_app_session
            WHERE date = ? AND mac IN ({placeholders})
            ORDER BY app, start_epoch""",
        (day, *wanted),
    ).fetchall()

    online_seconds = sum(int(row["active_secs"] or 0) for row in hourly)
    # 家长请注意分析窗口固定为 00:00–06:00 北京时间，与分钟口径同一边界。
    late_night_seconds = sum(
        int(row["active_secs"] or 0)
        for row in hourly
        if int(row["hour"]) < LATE_NIGHT_END_HOUR
    )
    hourly_rows = [
        {
            "hour": int(row["hour"]),
            "minutes": _to_minutes(int(row["active_secs"] or 0)),
            "txBytes": int(row["tx_bytes"] or 0),
            "rxBytes": int(row["rx_bytes"] or 0),
        }
        for row in hourly
    ]
    ranges_by_app: Dict[str, List[Dict[str, int]]] = {}
    for row in sessions:
        active_seconds = int(row["active_secs"] or 0)
        ranges_by_app.setdefault(str(row["app"]), []).append({
            "startEpoch": int(row["start_epoch"]),
            "endEpoch": int(row["end_epoch"]),
            "activeSeconds": active_seconds,
            "minutes": _to_minutes(active_seconds),
        })

    app_rows = sorted(
        (
            {
                "app": str(row["app"]),
                "minutes": _to_minutes(int(row["active_secs"] or 0)),
                "sessions": len(ranges_by_app.get(str(row["app"]), []))
                or int(row["sessions"] or 0),
                "sessionRanges": ranges_by_app.get(str(row["app"]), []),
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
        "lateNightSeconds": late_night_seconds,
        "lateNightMinutes": _to_minutes(late_night_seconds),
        "hourly": hourly_rows,
        "apps": app_rows,
        "macs": list(wanted),
        "coverage": {
            "status": "recorded" if hourly or apps or sessions else "no_record",
            "hasRecords": bool(hourly or apps or sessions),
        },
    }


def _to_minutes(seconds: int) -> int:
    """Round accumulated seconds onto minutes.

    Legacy-only: the v2 payload stores seconds, so a day rendered from the old
    tables has nothing better than this rounding.  Minute-bucket days count rows
    and never pass through here.
    """
    return (max(0, seconds) + 30) // 60


def _camel(field: str) -> str:
    head, *rest = field.split("_")
    return head + "".join(part.capitalize() for part in rest)


def _now_text() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def default_keep_days() -> Dict[str, int]:
    """The product retention window, in one place for callers that report it.

    ``minute`` is the v3 window: it covers the primary minute/traffic tables, so
    a reader clamping a ``days`` parameter clamps to the data that actually
    exists rather than to one of the two legacy summaries.
    """
    return {
        "hourly": DEFAULT_HOURLY_KEEP_DAYS,
        "dailyApp": DEFAULT_DAILY_KEEP_DAYS,
        "minute": DEFAULT_MINUTE_KEEP_DAYS,
    }


def _live_version(live: Dict[str, Any]) -> int:
    try:
        return int(live.get("version") or 0)
    except (TypeError, ValueError):
        return 0


def _live_traffic_block(live: Dict[str, Any], date_value: str) -> Dict[str, Any]:
    """The relay's own firmware counters, in the same shape as the hub block."""
    tx = _as_count(live.get("todayTxBytes") or live.get("txBytes"))
    rx = _as_count(live.get("todayRxBytes") or live.get("rxBytes"))
    if not (tx or rx):
        return _empty_traffic_block()
    return {
        "txBytes": tx,
        "rxBytes": rx,
        "totalBytes": tx + rx,
        "daily": [{"date": date_value, "txBytes": tx, "rxBytes": rx, "totalBytes": tx + rx}],
    }


def _minutes_from_live(live: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Adapt a v3 relay live report into the minute-bucket report shape.

    The relay's live reply has minute counts and consecutive-minute runs, not
    hour bars, so ``hourly`` stays empty: distributing its minutes over the day
    would mean inventing which hours they fell in.  The next push writes the
    real minute rows and the Hub-side report has the bars.
    """
    online_minutes = _as_count(live.get("onlineMinutes"))
    apps: List[Dict[str, Any]] = []
    for row in live.get("apps") or []:
        if not isinstance(row, dict):
            continue
        app = str(row.get("app") or "").strip()
        if not app:
            continue
        runs: List[Dict[str, int]] = []
        for item in row.get("ranges") or []:
            if not isinstance(item, dict):
                continue
            minutes = _as_count(item.get("minutes"))
            if minutes <= 0:
                continue
            runs.append({
                "startEpoch": _as_count(item.get("startEpoch")),
                "endEpoch": _as_count(item.get("endEpoch")),
                "activeSeconds": minutes * MINUTE_SECONDS,
                "minutes": minutes,
            })
        minutes_total = _as_count(row.get("minutes")) or sum(r["minutes"] for r in runs)
        apps.append({
            "app": app,
            "minutes": minutes_total,
            "sessions": len(runs),
            "sessionRanges": runs,
            "txBytes": 0,
            "rxBytes": 0,
        })
    if not online_minutes and not apps:
        return None
    apps.sort(key=lambda item: (-item["minutes"], item["app"]))
    date_value = str(live.get("date") or "").strip()
    try:
        date_value = _iso_date(date_value)
    except UsageAggregateError:
        date_value = ""
    return {
        "date": date_value,
        "onlineSeconds": online_minutes * MINUTE_SECONDS,
        "onlineMinutes": online_minutes,
        "lateNightSeconds": 0,
        "lateNightMinutes": 0,
        "hourly": [],
        "apps": apps,
        "macs": [normalize_mac(mac) for mac in live.get("macs") or []],
        "basis": "minutes",
        "traffic": _live_traffic_block(live, date_value),
        "coverage": {"status": "recorded", "hasRecords": True},
    }


def _merge_live_report(
    report: Dict[str, Any], live: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Overlay fresher relay buckets onto a **legacy** hub report for one day.

    Returns None when the live report carries nothing new, so callers keep the
    original source label. Both sides are absolute counters, so merging is by
    max and re-delivery stays idempotent.  Only ever called for a day that has
    no minute rows: a minute-basis report and an hour-basis live report measure
    different things and must not be blended.
    """
    live_hours = {int(row.get("hour", -1)): row for row in live.get("hourly") or []}
    hub_hours = {int(row.get("hour", -1)): row for row in report.get("hourly") or []}

    fresher = any(hour not in hub_hours for hour in live_hours) or any(
        int(live_hours[hour].get("minutes") or 0) > int(hub_hours[hour].get("minutes") or 0)
        for hour in live_hours
        if hour in hub_hours
    )
    live_apps = {str(row.get("app")): row for row in live.get("apps") or []}
    hub_apps = {str(row.get("app")): row for row in report.get("apps") or []}
    fresher = fresher or any(
        str(app) not in hub_apps
        or int(live_apps[app].get("minutes") or 0) > int(hub_apps[app].get("minutes") or 0)
        for app in live_apps
    )
    if not fresher:
        return None

    hourly: Dict[int, Dict[str, Any]] = {hour: dict(row) for hour, row in hub_hours.items()}
    for hour, row in live_hours.items():
        slot = hourly.setdefault(hour, {"hour": hour, "minutes": 0, "txBytes": 0, "rxBytes": 0})
        slot["minutes"] = max(int(slot.get("minutes") or 0), int(row.get("minutes") or 0))
        slot["txBytes"] = max(int(slot.get("txBytes") or 0), int(row.get("txBytes") or 0))
        slot["rxBytes"] = max(int(slot.get("rxBytes") or 0), int(row.get("rxBytes") or 0))

    apps: Dict[str, Dict[str, Any]] = {app: dict(row) for app, row in hub_apps.items()}
    for app, row in live_apps.items():
        slot = apps.setdefault(app, {
            "app": app, "minutes": 0, "sessions": 0, "sessionRanges": [],
            "txBytes": 0, "rxBytes": 0,
        })
        for field in ("minutes", "sessions", "txBytes", "rxBytes"):
            slot[field] = max(int(slot.get(field) or 0), int(row.get(field) or 0))
        ranges = {int(r.get("startEpoch", -1)): r for r in slot.get("sessionRanges") or []}
        for item in row.get("sessionRanges") or []:
            key = int(item.get("startEpoch", -1))
            if key not in ranges or int(item.get("activeSeconds") or 0) > int(ranges[key].get("activeSeconds") or 0):
                ranges[key] = item
        slot["sessionRanges"] = [ranges[key] for key in sorted(ranges)]

    hourly_rows = [hourly[hour] for hour in sorted(hourly)]
    online_minutes = sum(int(row.get("minutes") or 0) for row in hourly_rows)
    late_night_minutes = sum(
        int(row.get("minutes") or 0)
        for row in hourly_rows
        if int(row.get("hour", 24)) < LATE_NIGHT_END_HOUR
    )
    merged = {
        **report,
        "hourly": hourly_rows,
        "apps": sorted(apps.values(), key=lambda item: (-int(item.get("minutes") or 0), str(item.get("app")))),
        "onlineMinutes": max(int(report.get("onlineMinutes") or 0), online_minutes),
        "lateNightMinutes": max(int(report.get("lateNightMinutes") or 0), late_night_minutes),
        "source": "hub+live",
    }
    return merged


def compose_device_report(
    store: Optional["UsageAggregateStore"],
    macs: Sequence[str],
    date: str,
    *,
    live: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
    range_days: int = 1,
    now: Optional[_datetime] = None,
    router: str = "",
) -> Dict[str, Any]:
    """Pick the best available report for one device on one day.

    Precedence, and why:

    1. **Hub minute buckets** (``source`` ``hub+minutes``) — what the v3 router
       pushes, and the only basis that can state a duration in whole minutes.
    2. **Hub legacy tables** (``hub+legacy``) — days recorded before the router
       moved to v3, kept so the 10-day history does not go blank.
    3. **The router live** (``relay``) — for a day nothing was pushed for yet:
       first boot, a device that was just added, or a date outside retention.
    4. **An explicit empty report** — not an error. The App shows 暂无记录
       instead of a failure banner, and the next push fills it in.

    One day never blends two bases: whichever of the four produces the numbers
    produces all of them, and ``source`` plus ``basis`` say which it was.  No
    presence sampling and no byte-rate estimate feeds this report — device
    traffic comes from the firmware counters and nothing else.

    ``range_days`` > 1 additionally attaches a gap-filled ``range.days`` series
    (that many days ending on ``date``) for the 最近N天 chart.

    ``now`` exists so a test can pin the freshness cut-off; production callers
    leave it out and get the wall clock.

    ``router`` scopes the read to one router; empty means every router the Hub
    has rows for, which is what a single-router installation sees anyway.
    """
    keep = default_keep_days()
    report: Optional[Dict[str, Any]] = None

    if store is not None:
        try:
            candidate = store.report(macs, date, router)
        except Exception:
            candidate = None
        if candidate and (candidate.get("hourly") or candidate.get("apps")):
            basis = str(candidate.get("basis") or "legacy")
            report = {**candidate, "source": f"hub+{basis}", "keepDays": keep}

    live_report: Optional[Dict[str, Any]] = None
    # The live probe costs an agent round-trip, so only pay it when the hub
    # rows for today may be stale: nothing recorded yet, or no active bucket
    # covering the previous hour. Fresh hub data stands on its own.
    hub_fresh = False
    if report is not None:
        try:
            now_hour = (now or _datetime.now()).hour
            hours = [
                int(row.get("hour", -1)) for row in report.get("hourly") or []
                if int(row.get("minutes") or 0) > 0
            ]
            hub_fresh = any(hour >= now_hour - 1 for hour in hours)
        except Exception:
            hub_fresh = False
    if not hub_fresh and live is not None:
        try:
            live_report = live()
        except Exception:
            live_report = None

    live_is_minutes = bool(live_report) and _live_version(live_report) >= 3
    if report is None and live_report is not None:
        fallback = _minutes_from_live(live_report) if live_is_minutes else live_report
        if fallback and (fallback.get("hourly") or fallback.get("apps")
                         or fallback.get("onlineMinutes")):
            report = {**fallback, "source": "relay", "keepDays": keep}
            report.setdefault("coverage", {"status": "recorded", "hasRecords": True})
            report.setdefault("basis", "legacy")
            report.setdefault("traffic", _empty_traffic_block())

    if report is None:
        report = {**_empty_report(_iso_date(date), macs, basis="none"),
                  "source": "empty", "keepDays": keep,
                  "coverage": {"status": "unavailable", "hasRecords": False}}

    # The hub DB only advances when the relay pushes; if the push pipeline
    # stalls the App would sit on the same stale numbers forever. When the live
    # relay has fresher *legacy* buckets for the same day, overlay them (both
    # sides are absolute counters, so max-merge is idempotent). A minute-basis
    # report is left alone: its numbers come from rows, and hour buckets cannot
    # add a minute to a set.
    if (live_report and not live_is_minutes
            and live_report.get("date") == report.get("date")
            and report.get("basis") != "minutes"):
        merged = _merge_live_report(report, live_report)
        if merged is not None:
            report = merged

    # 每条路径都必须带 generatedAt / lastSampleAt / stale / hasData：App 用
    # ``optInt("todayMinutes", 0)`` 读数，缺字段就等于把「暂无数据」显示成 0 分钟。
    if "generatedAt" not in report:
        report = _decorate_report(report, None, _iso_date(date))

    if range_days > 1:
        report["range"] = _range_series(store, macs, date, range_days, router)
    return report


def _range_series(
    store: Optional["UsageAggregateStore"],
    macs: Sequence[str],
    date: str,
    days: int,
    router: str = "",
) -> Dict[str, Any]:
    """Gap-filled daily totals ending on ``date``; empty when no store yet."""
    end = _date.fromisoformat(_iso_date(date))
    start = end - timedelta(days=max(0, days - 1))
    entries: List[Dict[str, Any]] = []
    apps: List[Dict[str, Any]] = []
    traffic = _empty_traffic_block()
    if store is not None:
        window = (start.isoformat(), end.isoformat(), router)
        try:
            entries = store.daily_totals(macs, *window)
            apps = store.app_totals(macs, *window)
            traffic = store.traffic_report(macs, *window)
        except Exception:
            entries, apps = [], []
    if not entries:
        # No store (or no rows): still hand back the full window of zeros so the
        # client renders a stable N-bar chart instead of collapsing.
        entries = [
            {"date": day.isoformat(), "onlineSeconds": 0, "onlineMinutes": 0,
             "lateNightSeconds": 0, "lateNightMinutes": 0, "lateNightRanges": [],
             "coverage": "no_record", "basis": "none"}
            for day in (start + timedelta(days=offset) for offset in range((end - start).days + 1))
        ]
    recorded_days = sum(1 for entry in entries if entry.get("coverage") == "recorded")
    return {
        "days": entries,
        "apps": apps,
        "traffic": traffic,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "coverage": {
            "status": "recorded" if recorded_days == len(entries) else (
                "partial" if recorded_days else "no_record"
            ),
            "recordedDays": recorded_days,
            "requestedDays": len(entries),
        },
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

    def _ingest_router(body: Dict[str, Any]) -> str:
        """这批数据归属哪台路由器 —— 中继的 v3 body 里没有这个信息，只能 Hub 定。

        中继只知道自己那台路由器，所以 Hub 侧的解析钩子（``CHILD_GUARD_USAGE_ROUTER``）
        决定归属键；查询串或 body 里显式带了 router 时以它为准。写入与读取必须用
        同一个键，否则 ``Ruijie BE72`` 和 ``be72`` 会变成两台互不相干的设备。
        """
        explicit = str(request.args.get("router") or body.get("router") or "").strip()
        if not explicit:
            resolver = getattr(hub, "CHILD_GUARD_USAGE_ROUTER", None)
            if callable(resolver):
                try:
                    explicit = str(resolver(body) or "").strip()
                except Exception:  # pragma: no cover - 归属失败退回默认键
                    explicit = ""
        return router_key(explicit)

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
        version = _as_count(body.get("version"))
        router = _ingest_router(body)
        # v3 ships minute buckets + firmware traffic counters; v2 ships hour/app
        # second sums.  Both are handled off the same body, so a router that is
        # mid-upgrade (or one still on v2) keeps working unchanged.
        minute_counts = {"deviceMinutes": 0, "appMinutes": 0, "traffic": 0, "meta": 0}
        if version >= 3 or any(
            body.get(key) for key in ("deviceMinutes", "appMinutes", "traffic")
        ):
            minute_counts = store.ingest_v3(body, router=router)
        hours = store.upsert_hourly(body.get("hours") or [])
        apps = store.upsert_daily_app(body.get("apps") or [])
        sessions = store.upsert_sessions(body.get("sessions") or [])
        keep_days = _as_count(body.get("keepDays")) or None
        removed = store.prune(
            today=body.get("today"),
            hourly_keep_days=_as_count(body.get("hourlyKeepDays"))
            or keep_days or DEFAULT_HOURLY_KEEP_DAYS,
            daily_keep_days=_as_count(body.get("dailyKeepDays"))
            or keep_days or DEFAULT_DAILY_KEEP_DAYS,
            minute_keep_days=_as_count(body.get("minuteKeepDays"))
            or keep_days or DEFAULT_MINUTE_KEEP_DAYS,
        )
        # Aggregates are the only thing that reached disk; raw samples never did.
        return jsonify({
            "ok": True,
            "version": version,
            "router": router,
            "upserted": {
                "hourly": hours, "dailyApp": apps, "sessions": sessions,
                "deviceMinutes": minute_counts["deviceMinutes"],
                "appMinutes": minute_counts["appMinutes"],
                "traffic": minute_counts["traffic"],
            },
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
        payload = store.report(macs, date, str(request.args.get("router") or ""))
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
            "minuteKeepDays": DEFAULT_MINUTE_KEEP_DAYS,
            "staleAfterSeconds": STALE_AFTER_SECONDS,
        })
        return jsonify(payload)

    hub.app.register_blueprint(bp)
    if log is not None and hasattr(log, "info"):
        log.info("child guard usage aggregate registered at %s", bp.url_prefix)
    return bp
