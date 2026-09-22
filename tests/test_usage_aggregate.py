"""Aggregate-table tests for Child Internet usage statistics."""

from __future__ import annotations

import sqlite3
from datetime import date, datetime, timedelta, timezone

import pytest
from flask import Flask

from usage_aggregate import (
    DAY_MERGE_GAP_MINUTES,
    DAY_MIN_RUN_MINUTES,
    DEFAULT_DAILY_KEEP_DAYS,
    DEFAULT_HOURLY_KEEP_DAYS,
    NIGHT_MERGE_GAP_MINUTES,
    NIGHT_MIN_RUN_MINUTES,
    UsageAggregateError,
    UsageAggregateStore,
    compose_device_report,
    default_keep_days,
    install_usage_aggregate,
    normalize_mac,
)


@pytest.fixture()
def store(tmp_path):
    aggregate = UsageAggregateStore(tmp_path)
    aggregate.initialize()
    return aggregate


def hourly(mac, day, hour, secs, tx=0, rx=0):
    return {"date": day, "mac": mac, "hour": hour,
            "active_secs": secs, "tx_bytes": tx, "rx_bytes": rx}


def daily(mac, day, app, secs, sessions=1, tx=0, rx=0):
    return {"date": day, "mac": mac, "app": app,
            "active_secs": secs, "sessions": sessions,
            "tx_bytes": tx, "rx_bytes": rx}


def session(mac, day, app, start, end, active):
    return {"date": day, "mac": mac, "app": app,
            "startEpoch": start, "endEpoch": end, "activeSecs": active}


def bj_minute(day: str, hour: int, minute: int = 0) -> int:
    """Minute-start epoch for a Beijing wall-clock time (UTC-aligned, as v3 sends)."""
    moment = datetime.strptime(f"{day} {hour:02d}:{minute:02d}", "%Y-%m-%d %H:%M")
    return int(moment.replace(tzinfo=timezone(timedelta(hours=8))).timestamp())


def run_from(start: int, count: int) -> list:
    """从 ``start`` 起连续 ``count`` 个自然分钟。"""
    return [start + offset * 60 for offset in range(count)]


def with_evidence(row: dict, values: list) -> dict:
    """给一行分钟挂上 v4 的四条并列证据数组（按分钟顺序对齐）。

    每条形如 ``(up, down, windows, new_flows)``。中继一个 window 就是一个带
    ≥256B payload 的 5 秒采样窗口，所以 ``windows=8`` 读作「这一分钟有约 40 秒在传」。
    """
    out = dict(row)
    out["up"] = [value[0] for value in values]
    out["down"] = [value[1] for value in values]
    out["win"] = [value[2] for value in values]
    out["flow"] = [value[3] for value in values]
    return out


def device_minutes_row(mac, day, minutes):
    return {"mac": mac, "date": day, "minutes": list(minutes)}


def app_minutes_row(mac, day, app, minutes):
    return {"mac": mac, "date": day, "app": app, "minutes": list(minutes)}


def traffic_row(mac, day, tx, rx):
    return {"mac": mac, "date": day, "txBytes": tx, "rxBytes": rx, "totalBytes": tx + rx}


MAC_A = "da:1f:85:0c:19:fc"
MAC_B = "6c:1f:f7:76:71:04"
DAY = "2026-09-18"


class TestNormalizeMac:
    def test_variants_collapse_to_one_form(self):
        for value in ("DA:1F:85:0C:19:FC", "da-1f-85-0c-19-fc", "da1f850c19fc"):
            assert normalize_mac(value) == MAC_A

    def test_garbage_is_passed_through_lowered(self):
        assert normalize_mac("not-a-mac") == "not-a-mac"


class TestIngest:
    def test_report_matches_the_official_page_shape(self, store):
        # 12 时 50 分钟 + 16 时 32 分钟 -> 在线时间 82 分钟
        store.upsert_hourly([
            hourly(MAC_A, DAY, 12, 50 * 60, tx=1000, rx=2000),
            hourly(MAC_A, DAY, 16, 32 * 60, tx=500, rx=600),
        ])
        store.upsert_daily_app([
            daily(MAC_A, DAY, "小红书", 88 * 60, sessions=4),
            daily(MAC_A, DAY, "微信", 69 * 60, sessions=12),
            daily(MAC_A, DAY, "京东", 32 * 60, sessions=3),
        ])

        report = store.report([MAC_A], DAY)
        assert report["onlineMinutes"] == 82
        assert report["onlineSeconds"] == 82 * 60
        assert [row["hour"] for row in report["hourly"]] == [12, 16]
        assert [row["minutes"] for row in report["hourly"]] == [50, 32]
        assert [row["hour"] for row in report["hourly"]] == [12, 16]
        assert [row["app"] for row in report["apps"]] == ["小红书", "微信", "京东"]
        assert report["apps"][0]["sessions"] == 4

    def test_online_time_is_the_sum_of_the_hourly_bars(self, store):
        # This is the property the official UI relies on: the headline 在线时间
        # is nothing more than the bars added up.
        store.upsert_hourly([
            hourly(MAC_A, DAY, hour, minutes * 60)
            for hour, minutes in ((9, 60), (14, 17), (18, 41))
        ])
        report = store.report([MAC_A], DAY)
        assert report["onlineMinutes"] == sum(row["minutes"] for row in report["hourly"]) == 118

    def test_repush_is_idempotent_and_never_inflates(self, store):
        rows = [hourly(MAC_A, DAY, 12, 600, tx=100, rx=200)]
        store.upsert_hourly(rows)
        first = store.report([MAC_A], DAY)

        store.upsert_hourly(rows)  # duplicate delivery
        assert store.report([MAC_A], DAY)["onlineSeconds"] == first["onlineSeconds"]

        # A smaller value must be ignored rather than lowering (or raising) it.
        store.upsert_hourly([hourly(MAC_A, DAY, 12, 60, tx=1, rx=1)])
        again = store.report([MAC_A], DAY)
        assert again["onlineSeconds"] == first["onlineSeconds"]
        assert again["hourly"][0]["txBytes"] == 100

    def test_monotonic_growth_is_kept(self, store):
        store.upsert_hourly([hourly(MAC_A, DAY, 12, 600)])
        store.upsert_hourly([hourly(MAC_A, DAY, 12, 1200)])
        assert store.report([MAC_A], DAY)["onlineSeconds"] == 1200

    def test_sessions_merge_by_max_not_sum(self, store):
        store.upsert_daily_app([daily(MAC_A, DAY, "微信", 60, sessions=3)])
        store.upsert_daily_app([daily(MAC_A, DAY, "微信", 120, sessions=7)])
        assert store.report([MAC_A], DAY)["apps"][0]["sessions"] == 7

    def test_accepts_camel_case_from_the_relay(self, store):
        store.upsert_hourly([
            {"date": DAY, "mac": MAC_A, "hour": 12, "activeSecs": 900, "txBytes": 5, "rxBytes": 6}
        ])
        store.upsert_daily_app([
            {"date": DAY, "mac": MAC_A, "app": "微信", "activeSecs": 900,
             "sessions": 2, "txBytes": 5, "rxBytes": 6}
        ])
        report = store.report([MAC_A], DAY)
        assert report["onlineSeconds"] == 900
        assert report["apps"][0]["minutes"] == 15

    def test_rows_are_per_device_and_per_app(self, store):
        store.upsert_daily_app([
            daily(MAC_A, DAY, "微信", 600),
            daily(MAC_B, DAY, "微信", 900),
            daily(MAC_A, DAY, "抖音", 1800),
        ])
        report = store.report([MAC_A], DAY)
        assert [row["app"] for row in report["apps"]] == ["抖音", "微信"]
        assert report["apps"][1]["minutes"] == 10
        both = store.report([MAC_A, MAC_B], DAY)
        assert both["apps"][1]["minutes"] == 25  # 600 + 900 merged

    def test_real_session_ranges_override_legacy_flow_count(self, store):
        store.upsert_hourly([
            hourly(MAC_A, DAY, 0, 120),
            hourly(MAC_A, DAY, 1, 60),
        ])
        store.upsert_daily_app([daily(MAC_A, DAY, "微信", 180, sessions=99)])
        rows = [
            session(MAC_A, DAY, "微信", 1_789_700_000, 1_789_700_120, 60),
            session(MAC_A, DAY, "微信", 1_789_700_600, 1_789_700_780, 120),
        ]
        assert store.upsert_sessions(rows) == 2
        assert store.upsert_sessions(rows) == 2  # absolute re-push is idempotent

        report = store.report([MAC_A], DAY)
        app = report["apps"][0]
        assert app["sessions"] == 2
        assert app["sessionRanges"] == [
            {"startEpoch": 1_789_700_000, "endEpoch": 1_789_700_120,
             "activeSeconds": 60, "minutes": 1},
            {"startEpoch": 1_789_700_600, "endEpoch": 1_789_700_780,
             "activeSeconds": 120, "minutes": 2},
        ]
        assert report["lateNightSeconds"] == 180
        assert report["lateNightMinutes"] == 3
        assert report["coverage"] == {"status": "recorded", "hasRecords": True}

    def test_session_extension_keeps_start_and_maxima(self, store):
        start = 1_789_700_000
        store.upsert_sessions([session(MAC_A, DAY, "抖音", start, start + 60, 60)])
        store.upsert_sessions([session(MAC_A, DAY, "抖音", start, start + 240, 120)])
        store.upsert_daily_app([daily(MAC_A, DAY, "抖音", 120, sessions=50)])
        app = store.report([MAC_A], DAY)["apps"][0]
        assert app["sessions"] == 1
        assert app["sessionRanges"][0]["endEpoch"] == start + 240
        assert app["sessionRanges"][0]["activeSeconds"] == 120


class TestMinuteIngest:
    """v3: minutes are a set, so re-delivery cannot double-count them."""

    def test_repushing_the_same_minutes_changes_nothing(self, store):
        minutes = [bj_minute(DAY, 8, 15), bj_minute(DAY, 8, 16), bj_minute(DAY, 8, 17)]
        rows = [device_minutes_row(MAC_A, DAY, minutes),
                app_minutes_row(MAC_A, DAY, "微信", minutes)]

        assert store.insert_device_minutes(rows[:1]) == 3
        assert store.insert_app_minutes(rows[1:]) == 3
        first = store.report([MAC_A], DAY)
        stats = store.stats()

        # Duplicate delivery of the same three minutes, in the same row and in a
        # separate one: the set insert ignores them all.
        assert store.insert_device_minutes(rows[:1]) == 3
        assert store.insert_device_minutes([
            device_minutes_row(MAC_A, DAY, [minutes[0], minutes[1], minutes[2]])
        ]) == 3
        assert store.insert_app_minutes(rows[1:]) == 3
        again = store.report([MAC_A], DAY)

        assert again["onlineMinutes"] == first["onlineMinutes"] == 3
        assert again["apps"][0]["minutes"] == 3
        assert store.stats() == {**stats, "bytesOnDisk": stats["bytesOnDisk"]}

    def test_a_minute_is_counted_whatever_happens_inside_it(self, store):
        """5 s of traffic and 55 s of traffic in a minute are both one minute."""
        store.insert_device_minutes([device_minutes_row(
            MAC_A, DAY, run_from(bj_minute(DAY, 9), DAY_MIN_RUN_MINUTES))])
        report = store.report([MAC_A], DAY)
        assert report["onlineMinutes"] == DAY_MIN_RUN_MINUTES
        assert report["onlineSeconds"] == DAY_MIN_RUN_MINUTES * 60

    def test_off_minute_epoch_lands_in_its_own_bucket(self, store):
        start = bj_minute(DAY, 9)
        store.insert_device_minutes([
            device_minutes_row(MAC_A, DAY,
                               [start + 5, start + 55] + run_from(start + 60, 2))
        ])
        assert store.report([MAC_A], DAY)["onlineMinutes"] == 3

    def test_a_full_day_of_minutes_is_the_whole_day(self, store):
        minutes = [bj_minute(DAY, 0) + offset * 60 for offset in range(24 * 60)]
        assert store.insert_device_minutes([device_minutes_row(MAC_A, DAY, minutes)]) == 1440
        # 夜间那一半要有应用归属才算上网，所以把整晚的应用分钟也补上。
        assert store.insert_app_minutes([
            app_minutes_row(MAC_A, DAY, "微信", minutes[:6 * 60])]) == 360
        report = store.report([MAC_A], DAY)
        assert report["onlineMinutes"] == 1440
        assert [row["minutes"] for row in report["hourly"]] == [60] * 24

    def test_unattributed_night_minutes_are_never_online_time(self, store):
        """睡眠设备的固件字节差值每分钟都过门槛：夜间没有应用归属就不算上网。

        这就是 2026-09-21 那个「才 8 点就统计到 7 小时 51 分」的根因。
        """
        night = [bj_minute(DAY, 0) + offset * 60 for offset in range(6 * 60)]
        store.insert_device_minutes([device_minutes_row(MAC_A, DAY, night)])
        report = store.report([MAC_A], DAY)
        assert report["onlineMinutes"] == 0
        assert report["lateNightMinutes"] == 0
        assert [row["minutes"] for row in report["hourly"][:6]] == [0] * 6, \
            "整晚满格的小时柱就是家长端看到的那条假曲线"
        assert report["coverage"]["hasRecords"] is True, \
            "路由器确实记过这些分钟，只是不计入时长，不是「暂无记录」"

    def test_more_minutes_than_a_day_has_is_rejected(self, store):
        minutes = [bj_minute(DAY, 0) + offset * 60 for offset in range(1441)]
        with pytest.raises(UsageAggregateError):
            store.insert_device_minutes([device_minutes_row(MAC_A, DAY, minutes)])

    def test_minutes_are_per_mac_and_per_day(self, store):
        store.insert_device_minutes([
            device_minutes_row(MAC_A, DAY, run_from(bj_minute(DAY, 8), DAY_MIN_RUN_MINUTES)),
            device_minutes_row(MAC_B, DAY, run_from(bj_minute(DAY, 8), DAY_MIN_RUN_MINUTES)),
            device_minutes_row(MAC_A, "2026-09-17",
                               run_from(bj_minute("2026-09-17", 8), DAY_MIN_RUN_MINUTES)),
        ])
        assert store.report([MAC_A], DAY)["onlineMinutes"] == DAY_MIN_RUN_MINUTES
        assert store.report([MAC_A, MAC_B], DAY)["onlineMinutes"] == DAY_MIN_RUN_MINUTES, \
            "one shared minute across two MACs is still one minute of the card"
        assert store.report([MAC_A], "2026-09-17")["onlineMinutes"] == DAY_MIN_RUN_MINUTES
        assert store.report([MAC_A], "2026-09-16")["onlineMinutes"] == 0


class TestMinuteReport:
    def test_hourly_is_a_full_axis_of_real_counts(self, store):
        morning = [bj_minute(DAY, 8, 15), bj_minute(DAY, 8, 16), bj_minute(DAY, 8, 17)]
        store.insert_device_minutes([device_minutes_row(MAC_A, DAY, morning)])
        report = store.report([MAC_A], DAY)

        assert [row["hour"] for row in report["hourly"]] == list(range(24))
        assert sum(row["minutes"] for row in report["hourly"]) == report["onlineMinutes"] == 3
        assert report["onlineSeconds"] == 180
        assert report["hourly"][8] == {"hour": 8, "minutes": 3, "txBytes": 0, "rxBytes": 0}
        assert report["hourly"][9]["minutes"] == 0, "an empty hour is 0, never invented"
        assert report["basis"] == "minutes"

    def test_hour_binning_uses_beijing_time_not_the_hub_clock(self, store):
        # 23:30 Beijing on the requested day is hour 23 no matter what UTC says.
        night = run_from(bj_minute(DAY, 0, 5), NIGHT_MIN_RUN_MINUTES)
        store.insert_device_minutes([device_minutes_row(
            MAC_A, DAY,
            night + run_from(bj_minute(DAY, 23, 30), DAY_MIN_RUN_MINUTES))])
        store.insert_app_minutes([app_minutes_row(MAC_A, DAY, "微信", night)])
        report = store.report([MAC_A], DAY)
        assert report["hourly"][0]["minutes"] == NIGHT_MIN_RUN_MINUTES
        assert report["hourly"][23]["minutes"] == DAY_MIN_RUN_MINUTES
        assert report["hourly"][1]["minutes"] == 0

    def test_consecutive_minutes_form_one_range_and_gaps_split_them(self, store):
        run = run_from(bj_minute(DAY, 8, 15), DAY_MIN_RUN_MINUTES)
        store.insert_app_minutes([app_minutes_row(MAC_A, DAY, "抖音", run)])
        app = store.report([MAC_A], DAY)["apps"][0]
        assert app["minutes"] == DAY_MIN_RUN_MINUTES
        assert app["sessions"] == 1
        assert app["sessionRanges"] == [{
            "startEpoch": run[0], "endEpoch": run[-1] + 60,
            "activeSeconds": DAY_MIN_RUN_MINUTES * 60, "minutes": DAY_MIN_RUN_MINUTES,
        }]

        gapped = (run_from(bj_minute(DAY, 8, 15), DAY_MIN_RUN_MINUTES)
                  + run_from(bj_minute(DAY, 8, 25), DAY_MIN_RUN_MINUTES)
                  + run_from(bj_minute(DAY, 8, 35), DAY_MIN_RUN_MINUTES))
        store.insert_app_minutes([app_minutes_row(MAC_B, DAY, "抖音", gapped)])
        both = store.report([MAC_B], DAY)["apps"][0]
        assert both["minutes"] == 3 * DAY_MIN_RUN_MINUTES
        assert both["sessions"] == 3, "空 7 分钟远超容差，必须断开"
        assert ([row["minutes"] for row in both["sessionRanges"]]
                == [DAY_MIN_RUN_MINUTES] * 3)

    def test_a_two_minute_hole_stays_one_range_but_loses_no_minute(self, store):
        """固件周期性重分类长连接 → 真实分钟之间会缺一两格。

        时段可以跨过这个洞（否则一条微信通话会被说成 75 次），但时长只能数
        真实活跃过的分钟：08:15/08:16/(缺 08:17)/08:18 显示 08:15–08:19，
        仍然是 3 分钟。
        """
        minutes = [bj_minute(DAY, 8, 15), bj_minute(DAY, 8, 16),
                   bj_minute(DAY, 8, 18), bj_minute(DAY, 8, 22), bj_minute(DAY, 8, 23),
                   bj_minute(DAY, 8, 24)]
        store.insert_app_minutes([app_minutes_row(MAC_A, DAY, "微信", minutes)])
        app = store.report([MAC_A], DAY)["apps"][0]
        assert app["minutes"] == 6
        assert [row["minutes"] for row in app["sessionRanges"]] == [3, 3]
        assert app["sessionRanges"][0]["startEpoch"] == minutes[0]
        assert app["sessionRanges"][0]["endEpoch"] == minutes[2] + 60
        assert app["sessionRanges"][0]["activeSeconds"] == 180
        # 缺 3 格（08:19/20/21）就断开：白天的容差是「最多跨过两个空分钟」。
        assert app["sessionRanges"][1]["startEpoch"] == minutes[3]
        assert app["sessions"] == 2

    def test_apps_have_no_invented_bytes_on_the_minute_basis(self, store):
        store.insert_app_minutes([
            app_minutes_row(MAC_A, DAY, "微信", run_from(bj_minute(DAY, 12), 4)),
            app_minutes_row(MAC_A, DAY, "小红书",
                            run_from(bj_minute(DAY, 13), DAY_MIN_RUN_MINUTES)),
        ])
        store.upsert_daily_app([daily(MAC_A, DAY, "微信", 9_999, tx=9_999, rx=8_888)])
        report = store.report([MAC_A], DAY)
        assert [row["app"] for row in report["apps"]] == ["微信", "小红书"]
        assert all(row["txBytes"] == 0 and row["rxBytes"] == 0 for row in report["apps"])
        assert [row["minutes"] for row in report["apps"]] == [4, DAY_MIN_RUN_MINUTES]

    def test_late_night_boundary_is_six_am_beijing(self, store):
        # 一次跨过 06:00 的使用：夜里那 6 格算深夜，06:00 起的 3 格算白天。
        app_minutes = (run_from(bj_minute(DAY, 5, 54), 6)
                       + run_from(bj_minute(DAY, 6, 0), DAY_MIN_RUN_MINUTES))
        store.insert_device_minutes([device_minutes_row(MAC_A, DAY, [
            *app_minutes,
            bj_minute(DAY, 23, 59),  # 孤零零一格，够不到白天的门檻
        ])])
        store.insert_app_minutes([app_minutes_row(MAC_A, DAY, "微信", app_minutes)])
        report = store.report([MAC_A], DAY)
        assert report["lateNightMinutes"] == 6
        assert report["lateNightSeconds"] == 360
        assert report["onlineMinutes"] == 9, "6 格深夜 + 3 格白天，23:59 那格不计"
        assert report["hourly"][6]["minutes"] == DAY_MIN_RUN_MINUTES, \
            "06:00 起是白天，但照样计入小时柱"
        assert report["hourly"][23]["minutes"] == 0

        app = report["apps"][0]
        assert app["minutes"] == 9
        assert app["sessions"] == 2, "06:00 那一格在窗口外，时段必须断开"
        expected = [{"app": "微信", "startEpoch": bj_minute(DAY, 5, 54),
                     "endEpoch": bj_minute(DAY, 6, 0), "minutes": 6}]
        assert report["lateNightRanges"] == expected, \
            "单日报告也得带深夜时段，App 读的就是顶层这个字段"
        assert store.daily_totals([MAC_A], DAY, DAY)[0]["lateNightRanges"] == expected

    def test_a_short_night_wake_is_not_usage_time(self, store):
        """整晚的保活唤醒都是 1 分钟孤段：一条都不算深夜上网。"""
        wakes = [bj_minute(DAY, 1, 0), bj_minute(DAY, 2, 30), bj_minute(DAY, 3, 45)]
        store.insert_device_minutes([device_minutes_row(MAC_A, DAY, wakes)])
        store.insert_app_minutes([app_minutes_row(MAC_A, DAY, "微信", wakes)])
        report = store.report([MAC_A], DAY)
        assert report["lateNightMinutes"] == 0
        assert report["onlineMinutes"] == 0
        assert report["apps"] == [], "不足 NIGHT_MIN_RUN_MINUTES 的段不展示"
        assert report["lateNightRanges"] == []
        assert report["coverage"]["hasRecords"] is True

    def test_a_short_day_run_is_dropped_from_stats_and_display(self, store):
        minutes = run_from(bj_minute(DAY, 9), DAY_MIN_RUN_MINUTES - 1)
        store.insert_device_minutes([device_minutes_row(MAC_A, DAY, minutes)])
        store.insert_app_minutes([app_minutes_row(MAC_A, DAY, "抖音", minutes)])
        report = store.report([MAC_A], DAY)
        assert report["onlineMinutes"] == 0
        assert report["apps"] == []

    def test_short_payment_and_ai_sessions_still_count(self, store):
        """扫码付款、搜一下、问一句 AI：白天一分钟就是真实使用，不该被门槛抹掉。"""
        isolated = [bj_minute(DAY, 10), bj_minute(DAY, 14), bj_minute(DAY, 16)]
        store.insert_device_minutes([device_minutes_row(MAC_A, DAY, isolated)])
        store.insert_app_minutes([
            app_minutes_row(MAC_A, DAY, "支付宝", isolated),
            app_minutes_row(MAC_A, DAY, "微信支付", isolated),
            app_minutes_row(MAC_A, DAY, "DeepSeek", isolated),
            app_minutes_row(MAC_A, DAY, "baiduAPP", isolated),
            app_minutes_row(MAC_A, DAY, "抖音", isolated),
        ])
        report = store.report([MAC_A], DAY)
        apps = {row["app"]: row for row in report["apps"]}
        assert "抖音" not in apps, "普通应用的一分钟孤段照旧按白天 3 分钟门槛过滤"
        for name in ("支付宝", "微信支付", "DeepSeek", "百度"):
            assert apps[name]["minutes"] == 3, name
            assert apps[name]["sessions"] == 3, name
        assert "baiduAPP" not in apps, "入库名先归一成「百度」，再按短交互放行"
        assert report["onlineMinutes"] == 3, "设备时长必须认这些分钟，不能只出现在应用列表里"

    def test_a_bank_app_matches_by_suffix(self, store):
        minutes = [bj_minute(DAY, 11)]
        store.insert_device_minutes([device_minutes_row(MAC_A, DAY, minutes)])
        store.insert_app_minutes([app_minutes_row(MAC_A, DAY, "中国工商银行", minutes)])
        assert store.report([MAC_A], DAY)["apps"][0]["minutes"] == 1

    def test_instant_use_apps_are_relaxed_around_the_clock(self, store):
        """短交互应用全天都按 1 分钟放行；夜间「必须有应用归属」这条不放。"""
        isolated = [bj_minute(DAY, 2), bj_minute(DAY, 3, 30)]
        store.insert_device_minutes([device_minutes_row(
            MAC_A, DAY, [*isolated, bj_minute(DAY, 4)])])
        store.insert_app_minutes([app_minutes_row(MAC_A, DAY, "支付宝", isolated)])
        report = store.report([MAC_A], DAY)
        assert report["lateNightMinutes"] == 2, "凌晨扫一次码就是一分钟，不该被抹掉"
        assert report["onlineMinutes"] == 2, "04:00 那一格只有后台字节，仍然不算"
        assert report["apps"][0]["sessions"] == 2

    def test_night_tolerates_a_wider_hole_than_day(self, store):
        """夜里一次真实使用被重分类切得更碎，容差比白天宽。"""
        empty = NIGHT_MERGE_GAP_MINUTES  # 刚好落在容差内的空分钟数
        joined = (run_from(bj_minute(DAY, 1, 0), NIGHT_MIN_RUN_MINUTES)
                  + run_from(bj_minute(DAY, 1, 5 + empty), NIGHT_MIN_RUN_MINUTES))
        store.insert_app_minutes([app_minutes_row(MAC_A, DAY, "微信", joined)])
        app = store.report([MAC_A], DAY)["apps"][0]
        assert app["sessions"] == 1, "跨得过空分钟就还是一段"
        assert app["minutes"] == 2 * NIGHT_MIN_RUN_MINUTES

        split = (run_from(bj_minute(DAY, 3, 0), NIGHT_MIN_RUN_MINUTES)
                 + run_from(bj_minute(DAY, 3, 6 + empty), NIGHT_MIN_RUN_MINUTES))
        store.insert_app_minutes([app_minutes_row(MAC_B, DAY, "微信", split)])
        other = store.report([MAC_B], DAY)["apps"][0]
        assert other["sessions"] == 2, "超出夜间容差就得断开"

    def test_a_night_run_without_any_uplink_is_not_usage(self, store):
        """整段没有一次像样的上行 = 设备在收东西，不是有人在用。"""
        minutes = run_from(bj_minute(DAY, 2, 0), NIGHT_MIN_RUN_MINUTES)
        # windows=3 让分钟窗口门槛放行，这样拦下它的只能是「整段没有上行」。
        heartbeat = [(200, 4_000_000, 3, 0) for _ in minutes]
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "微信", minutes), heartbeat)])
        report = store.report([MAC_A], DAY)
        assert report["apps"] == [], "整段没有上行，这个应用今天夜里就没被用过"
        assert report["lateNightMinutes"] == 0, "4GB 下行、每次 200B 上行，是推送不是熬夜"

    def test_a_night_run_that_sent_anything_counts(self, store):
        """同一段，只要有一分钟真的上行过，就是人在用。

        填充分钟给 windows=3：这条测的是「段内要有上行」，不能被分钟窗口门槛
        （`APP_MINUTE_MIN_WINDOWS`）顺手拦掉，两件事得各测各的。
        """
        minutes = run_from(bj_minute(DAY, 2, 0), NIGHT_MIN_RUN_MINUTES)
        evidence = [(200, 50_000, 3, 0)] * (len(minutes) - 1) + [(30_000, 50_000, 6, 1)]
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "微信", minutes), evidence)])
        app = store.report([MAC_A], DAY)["apps"][0]
        assert app["minutes"] == NIGHT_MIN_RUN_MINUTES

    def test_night_instant_use_needs_thirty_seconds_and_uplink(self, store):
        """凌晨扫码：一两秒的心跳不算，真打开用了几十秒才算。

        两分钟分开写：分钟行是集合，同一分钟重投会被 IGNORE 掉，证据不会更新。
        """
        tap = bj_minute(DAY, 3, 20)
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_B, DAY, "支付宝", [tap]), [(300, 9_000, 1, 1)])])
        report = store.report([MAC_B], DAY)
        assert report["lateNightMinutes"] == 0, \
            "一个窗口 + 300B 上行，是分推送，不是孩子起来扫码"
        # 被夜间门槛拒掉的分钟绝不能改天白名单混进白天 —— 白天门槛只有 3 分钟，
        # 而且凌晨根本没有"白天"。
        assert report["onlineMinutes"] == 0

        used = bj_minute(DAY, 3, 25)
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_B, DAY, "支付宝", [used]), [(24_000, 180_000, 8, 1)])])
        assert store.report([MAC_B], DAY)["lateNightMinutes"] == 1

    def test_minutes_without_evidence_keep_the_old_verdict(self, store):
        """v3 中继写的行没有证据：必须照旧口径计，否则升级会把昨天的数字改小。"""
        minutes = run_from(bj_minute(DAY, 2, 0), NIGHT_MIN_RUN_MINUTES)
        store.insert_app_minutes([app_minutes_row(MAC_A, DAY, "微信", minutes)])
        app = store.report([MAC_A], DAY)["apps"][0]
        assert app["minutes"] == NIGHT_MIN_RUN_MINUTES, "全 0 是「未知」，不是「没上行」"

    def test_evidence_is_stored_per_minute_and_survives_a_repush(self, store):
        minutes = [bj_minute(DAY, 10, 0), bj_minute(DAY, 10, 1)]
        row = with_evidence(device_minutes_row(MAC_A, DAY, minutes),
                            [(1_000, 20_000, 4, 1), (2_000, 30_000, 7, 0)])
        assert store.insert_device_minutes([row]) == 2
        # 重复投递同一分钟不能把数字改大：分钟是集合。
        assert store.insert_device_minutes([row]) == 2
        with store.connect() as conn:
            stored = conn.execute(
                "SELECT minute_epoch, up_bytes, down_bytes, windows, new_flows"
                " FROM usage_device_minute ORDER BY minute_epoch").fetchall()
        assert [tuple(row_) for row_ in stored] == [
            (minutes[0], 1_000, 20_000, 4, 1), (minutes[1], 2_000, 30_000, 7, 0)]

    def test_a_short_evidence_array_does_not_shift_the_other_minutes(self, store):
        """证据数组比分钟数组短（坏包）时，缺的那几分钟按未知处理，
        绝不能把后面的证据挪到前面的分钟上。"""
        minutes = [bj_minute(DAY, 11, 0), bj_minute(DAY, 11, 1)]
        row = dict(device_minutes_row(MAC_A, DAY, minutes))
        row.update({"up": [5_000], "down": [90_000], "win": [9], "flow": [2]})
        store.insert_device_minutes([row])
        with store.connect() as conn:
            stored = conn.execute(
                "SELECT minute_epoch, up_bytes, windows FROM usage_device_minute"
                " ORDER BY minute_epoch").fetchall()
        assert [tuple(r) for r in stored] == [(minutes[0], 5_000, 9), (minutes[1], 0, 0)]

    def test_periodic_app_heartbeats_do_not_become_usage(self, store):
        """微信后台每 2-3 分钟一次 finder 心跳：936B/579B/1 窗口，不该攒成「看了 11 分钟视频号」。

        实测数据形状（2026-09-21 iQOO Neo3 21:18-21:42）。间隔 2 分钟正好落在白天合并
        容差里，所以段长过滤拦不住，必须在分钟这一级按窗口数拦。
        """
        base = bj_minute(DAY, 21, 18)
        beats = [base, base + 180, base + 360, base + 540, base + 720]
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "微信视频号", beats),
            [(936, 579, 1, 1)] * len(beats))])
        report = store.report([MAC_A], DAY)
        assert report["apps"] == [], "全是 1 个窗口的固定包，一分钟都不该算"
        assert report["onlineMinutes"] == 0

    def test_the_same_minutes_with_real_payload_still_count(self, store):
        base = bj_minute(DAY, 21, 18)
        beats = [base, base + 180, base + 360, base + 540, base + 720]
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "微信视频号", beats),
            [(224_118, 141_661, 7, 7)] * len(beats))])
        app = store.report([MAC_A], DAY)["apps"][0]
        assert app["minutes"] == len(beats)

    def test_p2p_uplink_minutes_are_not_watching_time(self, store):
        """整段都在传东西，但那一分钟只下来几 KB、上行是下行的五倍 —— 那是应用在拿
        本机做 P2P 加速，不是人在看内容。实测（2026-09-22 iQOO Neo3）凌晨
        03:54-04:34 记成「微信视频号连续 37 分钟」，其中 32 个分钟就是这个形状。
        """
        minutes = run_from(bj_minute(DAY, 3, 54), 41)
        evidence = [(30_000, 6_000, 3, 2)] * 41
        for index in (13, 17, 25, 33):          # 少数几分钟真的下来了内容
            evidence[index] = (90_000, 2_500_000, 5, 4)
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "微信视频号", minutes), evidence)])
        assert store.report([MAC_A], DAY)["apps"] == [], \
            "四个孤立的内容分钟撑不起一段 5 分钟的连续段"

    def test_dozed_batch_wake_pulses_do_not_chain_into_a_session(self, store):
        """Doze 每 ~6 分钟醒一次、每次两分钟，正好被 4 分钟的夜间合并容差粘成「一段」：
        段长够了，密度只有 35%，照样不算。实测（2026-09-22 华为Mate60）03:49-04:58
        那台没人在用的手机，小红书记了 20 分钟、抖音 10 分钟、百度/淘宝各 15 分钟。
        """
        base = bj_minute(DAY, 3, 49)
        minutes = []
        for offset in range(0, 70, 6):
            minutes.extend([base + offset * 60, base + (offset + 1) * 60])
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "小红书", minutes),
            [(14_000, 37_000, 3, 2)] * len(minutes))])
        assert store.report([MAC_A], DAY)["apps"] == []

    def test_a_dense_night_session_is_still_counted(self, store):
        """夜里真正刷了 27 分钟，一分钟都不该少 —— 新门槛只能砍形状，不能砍时长。"""
        minutes = run_from(bj_minute(DAY, 1, 0), 27)
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "抖音", minutes),
            [(180_000, 8_000_000, 9, 3)] * len(minutes))])
        assert store.report([MAC_A], DAY)["apps"][0]["minutes"] == 27

    def test_light_downlink_chat_minutes_still_count(self, store):
        """每分钟只收几十 KB 的文字聊天是真实使用：下行占优，就不该被 P2P 那条剔掉。"""
        minutes = run_from(bj_minute(DAY, 20, 0), 12)
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "微信", minutes),
            [(9_000, 34_000, 2, 1)] * len(minutes))])
        assert store.report([MAC_A], DAY)["apps"][0]["minutes"] == 12

    def test_a_sparse_but_real_night_session_survives_the_density_gate(self, store):
        """夜里边看边放下，段里有一半是空分钟（实测真实微信段的密度是 58%）—— 密度
        门槛必须放得下这种段，不能把真实使用一并抹掉。
        """
        base = bj_minute(DAY, 2, 0)
        minutes = [base + offset * 180 + step for offset in range(30) for step in (0, 60)]
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "哔哩哔哩", minutes),
            [(40_000, 3_200_000, 6, 2)] * len(minutes))])
        assert store.report([MAC_A], DAY)["apps"][0]["minutes"] == len(minutes)

    def test_a_single_minute_of_real_content_counts_even_when_isolated(self, store):
        """白天单分钟下来 2.79MB 就是真在用，落单也算一段。

        实测（2026-09-22 华为Mate60）12:38-12:40 连续三分钟 + 12:46 孤立一分钟
        2.79MB —— 旧口径只报 3 分钟，把 12:46 那次真的刷小红书抹掉了。
        """
        base = bj_minute(DAY, 12, 38)
        minutes = [base, base + 60, base + 120, base + 480]
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "小红书", minutes),
            [(151_508, 3_714_028, 3, 3), (188_642, 2_478_886, 10, 0),
             (75_254, 396_152, 7, 0), (163_104, 2_785_610, 3, 3)])])
        app = store.report([MAC_A], DAY)["apps"][0]
        assert app["minutes"] == 4, "落单的那一分钟内容比前三分钟都大，不能丢"
        assert [run["minutes"] for run in app["sessionRanges"]] == [3, 1]

    def test_isolated_small_minutes_still_need_a_run(self, store):
        """反向守：单分钟几十 KB 的碎片仍然要凑够连续段，别把 P1 变成新的漏口。"""
        base = bj_minute(DAY, 12, 38)
        minutes = [base, base + 480, base + 960]
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "小红书", minutes),
            [(151_508, 470_000, 3, 3)] * 3)])
        assert store.report([MAC_A], DAY)["apps"] == []

    def test_the_heavy_minute_exemption_does_not_reopen_the_night(self, store):
        """夜里 2.9MB 的孤立分钟是预拉流（03:54-04:34 微信视频号那段就是这么来的），
        白天的放宽不能漏到夜间。"""
        base = bj_minute(DAY, 3, 54)
        minutes = [base, base + 600, base + 1500]
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "微信视频号", minutes),
            [(86_384, 2_871_950, 5, 4), (90_559, 622_495, 4, 4), (130_837, 2_279_954, 5, 5)])])
        assert store.report([MAC_A], DAY)["apps"] == []

    def test_instant_apps_are_exempt_from_the_window_floor(self, store):
        """扫码支付一下就锁屏：一个窗口也要算，这是用户定的「即时应用放宽」。"""
        minute = bj_minute(DAY, 22, 5)
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "支付宝", [minute]), [(1_584, 5_172, 1, 1)])])
        report = store.report([MAC_A], DAY)
        assert report["apps"][0]["minutes"] == 1
        assert report["onlineMinutes"] == 1

    def test_instant_apps_still_need_some_downlink(self, store):
        """免检不等于全放：百度搜索卡片每 ~10 分钟自己醒一次，每次下行 1KB 不到，
        实测（2026-09-22 华为Mate60）一天这样攒出 15 分钟「用了百度」。
        """
        base = bj_minute(DAY, 7, 0)
        pings = [base + offset * 600 for offset in range(9)]
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "百度", pings),
            [(489, 873, 1, 1)] * len(pings))])
        assert store.report([MAC_A], DAY)["apps"] == []
        paid = bj_minute(DAY, 9, 30)
        store.insert_app_minutes([with_evidence(
            app_minutes_row(MAC_A, DAY, "微信支付", [paid]), [(15_521, 10_478, 2, 1)])])
        assert store.report([MAC_A], DAY)["apps"][0]["minutes"] == 1, "真付一次款还是要算"

    def test_baidu_app_is_reported_under_its_chinese_name(self, store):
        """中继按 `_` 截断后剩下 `baiduAPP`，家长端要看到的是「百度」。"""
        store.insert_app_minutes([
            app_minutes_row(MAC_A, DAY, "baiduAPP",
                            run_from(bj_minute(DAY, 9), DAY_MIN_RUN_MINUTES)),
            app_minutes_row(MAC_A, DAY, "百度网盘",
                            run_from(bj_minute(DAY, 10), DAY_MIN_RUN_MINUTES)),
        ])
        assert [row["app"] for row in store.report([MAC_A], DAY)["apps"]] == \
            ["百度", "百度网盘"], "百度网盘是另一个应用，不能并进来"

    def test_empty_day_has_no_bar_array(self, store):
        report = store.report([MAC_A], DAY)
        assert report["hourly"] == []
        assert report["apps"] == []
        assert report["basis"] == "none"
        assert report["coverage"] == {"status": "no_record", "hasRecords": False}


class TestDeviceTraffic:
    """Device traffic is the firmware counter, never a sum of flow bytes."""

    def test_traffic_is_max_merged_per_column(self, store):
        store.upsert_device_traffic([traffic_row(MAC_A, DAY, 1_000, 2_000)])
        report = store.report([MAC_A], DAY)["traffic"]
        assert report["totalBytes"] == report["txBytes"] + report["rxBytes"] == 3_000

        # Re-delivery and a lower value change nothing; a higher one is kept.
        store.upsert_device_traffic([traffic_row(MAC_A, DAY, 1_000, 2_000)])
        store.upsert_device_traffic([traffic_row(MAC_A, DAY, 900, 1_500)])
        assert store.report([MAC_A], DAY)["traffic"]["totalBytes"] == 3_000

        store.upsert_device_traffic([traffic_row(MAC_A, DAY, 1_500, 2_000)])
        merged = store.report([MAC_A], DAY)["traffic"]
        assert (merged["txBytes"], merged["rxBytes"]) == (1_500, 2_000)
        assert merged["totalBytes"] == 3_500

    def test_traffic_sums_the_devices_macs_and_lists_days(self, store):
        store.upsert_device_traffic([
            traffic_row(MAC_A, DAY, 10, 20),
            traffic_row(MAC_B, DAY, 5, 7),
            traffic_row(MAC_A, "2026-09-17", 1, 1),
        ])
        window = store.traffic_report([MAC_A, MAC_B], "2026-09-17", DAY)
        assert window["txBytes"] == 16
        assert window["rxBytes"] == 28
        assert window["totalBytes"] == 44
        assert window["daily"] == [
            {"date": "2026-09-17", "txBytes": 1, "rxBytes": 1, "totalBytes": 2},
            {"date": DAY, "txBytes": 15, "rxBytes": 27, "totalBytes": 42},
        ]
        for day in window["daily"]:
            assert day["totalBytes"] == day["txBytes"] + day["rxBytes"]

    def test_traffic_is_zero_without_counters_even_if_flow_bytes_exist(self, store):
        # The legacy hourly bytes are RDPI flow sums; they must not surface as
        # the device total, and per-app bytes never add up to one either.
        store.upsert_hourly([hourly(MAC_A, DAY, 12, 600, tx=500_000, rx=900_000)])
        store.upsert_daily_app([daily(MAC_A, DAY, "微信", 600, tx=500_000, rx=900_000)])
        traffic = store.report([MAC_A], DAY)["traffic"]
        assert traffic == {"txBytes": 0, "rxBytes": 0, "totalBytes": 0, "daily": []}

    def test_traffic_block_is_present_on_both_bases(self, store):
        store.insert_device_minutes([device_minutes_row(MAC_A, DAY, [bj_minute(DAY, 8)])])
        store.upsert_device_traffic([traffic_row(MAC_A, DAY, 3, 4)])
        minute_day = store.report([MAC_A], DAY)
        store.upsert_hourly([hourly(MAC_A, "2026-09-17", 8, 120)])
        legacy_day = store.report([MAC_A], "2026-09-17")
        assert minute_day["basis"] == "minutes"
        assert legacy_day["basis"] == "legacy"
        for report in (minute_day, legacy_day):
            assert report["traffic"]["totalBytes"] == report["traffic"]["txBytes"] + \
                report["traffic"]["rxBytes"]
        assert minute_day["traffic"]["totalBytes"] == 7
        assert legacy_day["traffic"]["totalBytes"] == 0


class TestMinuteAndLegacyNeverMix:
    def test_minute_rows_shadows_the_legacy_numbers_for_the_same_day(self, store):
        """A day with minute rows must not also add its old second sums."""
        run = run_from(bj_minute(DAY, 8), DAY_MIN_RUN_MINUTES)
        store.upsert_hourly([hourly(MAC_A, DAY, 8, 40 * 60)])
        store.upsert_daily_app([daily(MAC_A, DAY, "微信", 40 * 60, sessions=9)])
        store.insert_device_minutes([device_minutes_row(MAC_A, DAY, run)])
        store.insert_app_minutes([app_minutes_row(MAC_A, DAY, "微信", run)])

        report = store.report([MAC_A], DAY)
        assert report["basis"] == "minutes"
        assert report["onlineMinutes"] == DAY_MIN_RUN_MINUTES, \
            f"not {DAY_MIN_RUN_MINUTES} + the legacy 40 minutes"
        assert report["onlineSeconds"] == DAY_MIN_RUN_MINUTES * 60
        assert report["apps"][0]["minutes"] == DAY_MIN_RUN_MINUTES
        assert report["apps"][0]["sessions"] == 1

    def test_legacy_only_days_still_report(self, store):
        store.upsert_hourly([hourly(MAC_A, DAY, 8, 5 * 60)])
        report = store.report([MAC_A], DAY)
        assert report["basis"] == "legacy"
        assert report["onlineMinutes"] == 5
        assert report["onlineSeconds"] == 300

    def test_range_days_pick_one_basis_each(self, store):
        store.upsert_hourly([hourly(MAC_A, "2026-09-17", 8, 30 * 60)])
        store.insert_device_minutes([device_minutes_row(
            MAC_A, "2026-09-17", [bj_minute("2026-09-17", 8) + offset * 60
                                  for offset in range(4)])])
        store.insert_device_minutes([device_minutes_row(
            MAC_A, DAY, run_from(bj_minute(DAY, 21), DAY_MIN_RUN_MINUTES))])
        days = {row["date"]: row for row in store.daily_totals([MAC_A], "2026-09-16", DAY)}
        assert days["2026-09-16"] == {
            "date": "2026-09-16", "onlineSeconds": 0, "onlineMinutes": 0,
            "lateNightSeconds": 0, "lateNightMinutes": 0, "lateNightRanges": [],
            "coverage": "no_record", "basis": "none",
        }
        assert days["2026-09-17"]["onlineMinutes"] == 4
        assert days["2026-09-17"]["basis"] == "minutes"
        assert days[DAY]["onlineMinutes"] == DAY_MIN_RUN_MINUTES
        assert days[DAY]["basis"] == "minutes"

    def test_range_apps_never_count_a_minute_day_twice(self, store):
        store.upsert_daily_app([
            daily(MAC_A, DAY, "微信", 40 * 60, sessions=9),
            daily(MAC_A, "2026-09-17", "微信", 10 * 60, sessions=2),
        ])
        store.insert_app_minutes([app_minutes_row(
            MAC_A, DAY, "微信", run_from(bj_minute(DAY, 8), DAY_MIN_RUN_MINUTES))])
        apps = store.app_totals([MAC_A], "2026-09-17", DAY)
        assert apps[0]["app"] == "微信"
        assert apps[0]["minutes"] == DAY_MIN_RUN_MINUTES + 10, \
            "v3 那天的一段 + legacy 那天的 10 分钟"
        assert apps[0]["sessions"] == 3, "v3 的一段 + legacy 那天的 2 次"
        assert apps[0]["txBytes"] == 0


class TestComposeMinuteSources:
    def test_minute_day_is_labelled_and_never_merged_with_live_hours(self, store):
        store.insert_device_minutes([device_minutes_row(
            MAC_A, DAY, run_from(bj_minute(DAY, 8), DAY_MIN_RUN_MINUTES))])
        report = compose_device_report(
            store, [MAC_A], DAY,
            live=lambda: {"date": DAY, "hourly": [{"hour": 8, "minutes": 500}],
                          "apps": [{"app": "微信", "minutes": 500}]},
            now=datetime(2026, 9, 18, 8, 30),
        )
        assert report["source"] == "hub+minutes"
        assert report["onlineMinutes"] == DAY_MIN_RUN_MINUTES, \
            "hour buckets cannot add minutes to a set"
        assert report["apps"] == []

    def test_legacy_day_may_still_be_topped_up_by_the_relay(self, store):
        store.upsert_hourly([hourly(MAC_A, DAY, 8, 60)])
        report = compose_device_report(
            store, [MAC_A], DAY,
            live=lambda: {"date": DAY,
                          "hourly": [{"hour": 9, "minutes": 5}],
                          "apps": []},
            # Late in the day, so the 08:00 hub row is stale and the relay is
            # worth asking for the missing hour.
            now=datetime(2026, 9, 18, 23, 0),
        )
        assert report["source"] == "hub+live"
        assert report["onlineMinutes"] == 6

    def test_a_v3_live_report_keeps_the_minute_shape(self, store):
        start = bj_minute(DAY, 8)
        report = compose_device_report(
            store, [MAC_A], DAY,
            live=lambda: {
                "version": 3, "date": DAY, "onlineMinutes": 3,
                "todayTxBytes": 1_000, "todayRxBytes": 2_000, "todayTotalBytes": 3_000,
                "macs": [MAC_A],
                "apps": [{"app": "微信", "minutes": 3, "ranges": [
                    {"startEpoch": start, "endEpoch": start + 180, "minutes": 3}]}],
            },
        )
        assert report["source"] == "relay"
        assert report["basis"] == "minutes"
        assert report["onlineMinutes"] == 3
        assert report["onlineSeconds"] == 180
        assert report["hourly"] == [], "the live reply has no hour detail to show"
        assert report["apps"][0]["sessionRanges"][0]["activeSeconds"] == 180
        assert report["traffic"] == {
            "txBytes": 1_000, "rxBytes": 2_000, "totalBytes": 3_000,
            "daily": [{"date": DAY, "txBytes": 1_000, "rxBytes": 2_000, "totalBytes": 3_000}],
        }

    def test_empty_report_exposes_the_new_keys(self, store):
        report = compose_device_report(store, [MAC_A], DAY, live=lambda: None)
        assert report["source"] == "empty"
        assert report["basis"] == "none"
        assert report["traffic"] == {"txBytes": 0, "rxBytes": 0, "totalBytes": 0, "daily": []}
        assert report["coverage"] == {"status": "unavailable", "hasRecords": False}

    def test_range_carries_a_traffic_window(self, store):
        store.insert_device_minutes([device_minutes_row(MAC_A, DAY, [bj_minute(DAY, 8)])])
        store.upsert_device_traffic([
            traffic_row(MAC_A, DAY, 100, 200),
            traffic_row(MAC_A, "2026-09-17", 1, 2),
        ])
        report = compose_device_report(store, [MAC_A], DAY, range_days=2)
        assert report["range"]["traffic"]["totalBytes"] == 303
        assert [row["date"] for row in report["range"]["traffic"]["daily"]] == [
            "2026-09-17", DAY]


class TestInputValidation:
    @pytest.mark.parametrize("bad", ["2026-9-18", "18/09/2026", "", "not-a-date", "2026-13-01"])
    def test_bad_dates_are_rejected(self, store, bad):
        with pytest.raises(UsageAggregateError):
            store.upsert_hourly([hourly(MAC_A, bad, 12, 60)])

    def test_hour_out_of_range_is_rejected(self, store):
        with pytest.raises(UsageAggregateError):
            store.upsert_hourly([hourly(MAC_A, DAY, 24, 60)])

    def test_rows_without_a_mac_or_app_are_skipped(self, store):
        assert store.upsert_hourly([hourly("", DAY, 12, 60)]) == 0
        assert store.upsert_daily_app([daily(MAC_A, DAY, "   ", 60)]) == 0

    def test_negative_counters_clamp_to_zero(self, store):
        store.upsert_hourly([hourly(MAC_A, DAY, 12, -500, tx=-1, rx=-2)])
        report = store.report([MAC_A], DAY)
        assert report["onlineSeconds"] == 0
        assert report["hourly"][0]["txBytes"] == 0

    def test_impossible_session_range_is_rejected(self, store):
        with pytest.raises(UsageAggregateError):
            store.upsert_sessions([
                session(MAC_A, DAY, "微信", 100, 90, 10),
            ])
        with pytest.raises(UsageAggregateError):
            store.upsert_sessions([
                session(MAC_A, DAY, "微信", 100, 110, 11),
            ])


class TestReportFiltering:
    def test_report_only_includes_matching_mac_and_date(self, store):
        store.upsert_daily_app([
            daily(MAC_A, DAY, "微信", 600),
            daily(MAC_B, DAY, "微信", 600),
            daily(MAC_A, "2026-09-17", "微信", 600),
        ])
        report = store.report([MAC_A], DAY)
        assert report["apps"][0]["minutes"] == 10

        assert store.report([MAC_A], "2026-09-16")["apps"] == []
        assert store.report([], DAY)["onlineMinutes"] == 0

    def test_mac_matching_is_case_insensitive(self, store):
        store.upsert_hourly([hourly(MAC_A, DAY, 12, 600)])
        assert store.report([MAC_A.upper()], DAY)["onlineSeconds"] == 600


class TestRetention:
    def test_prune_drops_days_outside_each_window(self, store):
        today = date(2026, 9, 18)
        fresh = today.isoformat()
        old_hourly = (today - timedelta(days=500)).isoformat()
        recent_hourly = (today - timedelta(days=100)).isoformat()
        old_daily = (today - timedelta(days=2000)).isoformat()

        store.upsert_hourly([
            hourly(MAC_A, fresh, 12, 60),
            hourly(MAC_A, recent_hourly, 12, 60),
            hourly(MAC_A, old_hourly, 12, 60),
        ])
        store.upsert_daily_app([
            daily(MAC_A, fresh, "微信", 60),
            daily(MAC_A, old_daily, "微信", 60),
        ])

        removed = store.prune(today=fresh, hourly_keep_days=400, daily_keep_days=1095)
        assert removed == {"hourly": 1, "dailyApp": 1, "sessions": 0,
                           "deviceMinutes": 0, "appMinutes": 0, "traffic": 0}

        # the 100-day-old hourly row survives a 400-day hourly window
        assert store.report([MAC_A], recent_hourly)["onlineSeconds"] == 60
        assert store.report([MAC_A], old_hourly)["apps"] == []

    def test_prune_is_a_noop_within_the_window(self, store):
        store.upsert_hourly([hourly(MAC_A, DAY, 12, 60)])
        assert store.prune(today=DAY, hourly_keep_days=400, daily_keep_days=1095) == {
            "hourly": 0, "dailyApp": 0, "sessions": 0,
            "deviceMinutes": 0, "appMinutes": 0, "traffic": 0,
        }

    def test_ten_days_keeps_today_plus_nine(self, store):
        """``keep_days`` counts today, so the product's 10-day window keeps
        exactly ten calendar dates: today and the nine before it."""
        today = date(2026, 9, 18)
        rows = [
            hourly(MAC_A, (today - timedelta(days=offset)).isoformat(), 12, 60)
            for offset in range(14)
        ]
        store.upsert_hourly(rows)

        removed = store.prune(
            today=today.isoformat(),
            hourly_keep_days=10,
            daily_keep_days=10,
        )
        assert removed["hourly"] == 4, "days 10..13 back must be dropped"

        oldest_kept = (today - timedelta(days=9)).isoformat()
        assert store.report([MAC_A], oldest_kept)["onlineSeconds"] == 60
        assert store.report([MAC_A], (today - timedelta(days=10)).isoformat())["onlineSeconds"] == 0

    def test_default_retention_matches_the_official_window(self):
        assert DEFAULT_HOURLY_KEEP_DAYS == 10
        assert DEFAULT_DAILY_KEEP_DAYS == 10

    def test_keep_days_helper_reports_every_window(self):
        # ``minute`` is the v3 window; the App's date picker clamps to it, so it
        # has to be reported next to the two legacy summaries.
        assert default_keep_days() == {"hourly": 10, "dailyApp": 10, "minute": 10}


class TestComposeDeviceReport:
    """The Hub-vs-relay precedence the App depends on.

    The App should never see an error just because the router has not pushed
    yet — but it must be able to tell where the numbers came from.
    """

    def test_hub_aggregates_win_when_present(self, store):
        store.upsert_hourly([hourly(MAC_A, DAY, 20, 600)])
        store.upsert_daily_app([daily(MAC_A, DAY, "微信", 600)])
        calls = []

        def live():
            calls.append(True)
            return {"hourly": [{"hour": 20, "minutes": 1}], "apps": []}

        report = compose_device_report(store, [MAC_A], DAY, live=live,
                                       now=datetime(2026, 9, 18, 20, 30))
        assert report["source"] == "hub+legacy", "v2 rows are labelled as such"
        assert report["onlineSeconds"] == 600
        assert calls == [], "the router must not be queried when the Hub has data"

    def test_falls_back_to_the_relay_for_a_day_without_aggregates(self, store):
        # Store has yesterday, we ask about today.
        store.upsert_hourly([hourly(MAC_A, "2026-09-17", 20, 600)])
        report = compose_device_report(
            store,
            [MAC_A],
            DAY,
            live=lambda: {
                "date": DAY,
                "onlineSeconds": 120,
                "onlineMinutes": 2,
                "hourly": [{"hour": 20, "minutes": 1}, {"hour": 21, "minutes": 1}],
                "apps": [{"app": "抖音", "minutes": 2, "sessions": 1}],
            },
        )
        assert report["source"] == "relay"
        assert report["onlineMinutes"] == 2
        assert default_keep_days() == report["keepDays"]

    def test_returns_an_empty_report_rather_than_an_error(self, store):
        report = compose_device_report(store, [MAC_A], DAY, live=lambda: None)
        assert report["source"] == "empty"
        assert report["date"] == DAY
        assert report["onlineSeconds"] == 0
        assert report["onlineMinutes"] == 0
        assert report["hourly"] == []
        assert report["apps"] == []
        assert report["macs"] == [MAC_A]

    def test_a_failing_relay_fallback_still_yields_an_empty_report(self, store):
        def boom():
            raise RuntimeError("agent_timeout")

        report = compose_device_report(store, [MAC_A], DAY, live=boom)
        assert report["source"] == "empty"

    def test_a_broken_store_does_not_block_the_relay_fallback(self, store):
        class Broken:
            def report(self, macs, date):
                raise sqlite3.OperationalError("database is locked")

        report = compose_device_report(
            Broken(),
            [MAC_A],
            DAY,
            live=lambda: {"onlineSeconds": 60, "onlineMinutes": 1,
                          "hourly": [{"hour": 9, "minutes": 1}], "apps": []},
        )
        assert report["source"] == "relay", "a wedged DB must not blank the page"

    def test_macs_are_normalized_in_the_empty_report(self, store):
        report = compose_device_report(store, ["AA-BB-CC-DD-EE-FF"], DAY)
        assert report["macs"] == ["aa:bb:cc:dd:ee:ff"]


class TestRangeSeries:
    """The 最近10天 chart: one call, a stable number of bars, no client date maths."""

    def test_range_is_gap_filled_with_zeros(self, store):
        # Only two of the ten days have activity.
        store.upsert_hourly([
            hourly(MAC_A, "2026-09-18", 20, 600),
            hourly(MAC_A, "2026-09-15", 20, 1_200),
        ])
        report = compose_device_report(store, [MAC_A], "2026-09-18", range_days=10)
        days = report["range"]["days"]
        assert len(days) == 10, "the chart expects a fixed-width window"
        assert report["range"]["start"] == "2026-09-09"
        assert report["range"]["end"] == "2026-09-18"
        assert [day["date"] for day in days] == sorted(day["date"] for day in days)
        minutes = {day["date"]: day["onlineMinutes"] for day in days}
        assert minutes["2026-09-18"] == 10
        assert minutes["2026-09-15"] == 20
        assert minutes["2026-09-14"] == 0, "a quiet day must be present as zero"
        by_date = {day["date"]: day for day in days}
        assert by_date["2026-09-18"]["coverage"] == "recorded"
        assert by_date["2026-09-14"]["coverage"] == "no_record"
        assert report["range"]["coverage"]["status"] == "partial"

    def test_range_days_include_late_night_minutes(self, store):
        # 家长请注意 window is 00:00-06:00 Beijing time; hour 23 is not late night.
        store.upsert_hourly([
            hourly(MAC_A, "2026-09-18", 1, 600),
            hourly(MAC_A, "2026-09-18", 14, 1_200),
            hourly(MAC_A, "2026-09-17", 5, 300),
        ])
        days = compose_device_report(store, [MAC_A], DAY, range_days=2)["range"]["days"]
        assert days[0]["lateNightMinutes"] == 5
        assert days[1]["lateNightMinutes"] == 10

    def test_range_is_absent_unless_requested(self, store):
        store.upsert_hourly([hourly(MAC_A, DAY, 20, 600)])
        assert "range" not in compose_device_report(store, [MAC_A], DAY)

    def test_range_still_returns_a_full_window_without_a_store(self):
        report = compose_device_report(None, [MAC_A], "2026-09-18", range_days=10)
        assert report["source"] == "empty"
        assert len(report["range"]["days"]) == 10
        assert all(day["onlineMinutes"] == 0 for day in report["range"]["days"])

    def test_range_only_counts_the_requested_macs(self, store):
        store.upsert_hourly([
            hourly(MAC_A, DAY, 20, 600),
            hourly(MAC_B, DAY, 21, 3_600),
        ])
        report = compose_device_report(store, [MAC_A], DAY, range_days=2)
        today = report["range"]["days"][-1]
        assert today["onlineMinutes"] == 10, "MAC_B's hour must not leak into MAC_A"

    def test_range_carries_a_per_app_summary_too(self, store):
        store.upsert_hourly([hourly(MAC_A, DAY, 20, 600)])
        store.upsert_daily_app([
            daily(MAC_A, "2026-09-18", "抖音", 600, sessions=3),
            daily(MAC_A, "2026-09-16", "抖音", 300, sessions=1),
            daily(MAC_A, "2026-09-16", "微信", 900, sessions=5),
        ])
        report = compose_device_report(store, [MAC_A], DAY, range_days=10)
        apps = {row["app"]: row for row in report["range"]["apps"]}
        assert apps["抖音"]["minutes"] == 15, "10 + 5 minutes across two days"
        assert apps["抖音"]["sessions"] == 4
        assert apps["微信"]["minutes"] == 15
        assert list(report["range"]["apps"])[0]["minutes"] >= list(report["range"]["apps"])[-1]["minutes"]

    def test_range_apps_are_empty_without_a_store(self):
        report = compose_device_report(None, [MAC_A], DAY, range_days=5)
        assert report["range"]["apps"] == []

    def test_daily_totals_rejects_a_broken_range(self, store):
        with pytest.raises(UsageAggregateError):
            store.daily_totals([MAC_A], "not-a-date", DAY)


class TestStorageFootprint:
    def test_a_whole_year_for_ten_devices_stays_tiny(self, store):
        """The storage claim in the plan, checked rather than asserted.

        10 devices x 24 hours x 365 days of hourly bars, plus
        10 devices x 30 apps x 365 days of per-app rows.
        """
        devices = [f"aa:bb:cc:dd:ee:{index:02x}" for index in range(10)]
        apps = [f"app-{index}" for index in range(30)]
        start = date(2025, 9, 18)

        hour_rows, app_rows = [], []
        for offset in range(365):
            day = (start + timedelta(days=offset)).isoformat()
            for mac in devices:
                for hour in range(24):
                    hour_rows.append(hourly(mac, day, hour, 600, tx=1000, rx=2000))
                for app in apps:
                    app_rows.append(daily(mac, day, app, 120, sessions=2, tx=500, rx=800))

        assert len(hour_rows) == 87_600
        assert len(app_rows) == 109_500
        # Upserts must chunk, not truncate: an earlier revision silently dropped
        # everything past the first batch, which this many-row case exposes.
        store.upsert_hourly(hour_rows)
        store.upsert_daily_app(app_rows)

        stats = store.stats()
        assert stats["hourlyRows"] == 87_600
        assert stats["dailyAppRows"] == 109_500
        assert stats["firstDate"] == "2025-09-18"
        assert stats["lastDate"] == "2026-09-17"
        # Measured, not assumed: ~197k aggregate rows for 10 devices x 1 year.
        # The common advice ("under 1 MB") is off by roughly an order of
        # magnitude -- it is tens of MB -- but the conclusion still holds: this
        # is trivial next to raw flows (which we never store) and safe to keep
        # for years on the NAS. Both tables are WITHOUT ROWID with the primary
        # key as the clustering index, and carry no secondary index.
        rows = stats["hourlyRows"] + stats["dailyAppRows"]
        assert stats["bytesOnDisk"] < 48 * 1024 * 1024
        assert stats["bytesOnDisk"] / rows < 200, stats["bytesOnDisk"]


class FakeHub:
    def __init__(self, data_dir):
        self.DATA_DIR = str(data_dir)
        self.app = Flask(__name__)
        self.read_ok = True
        self.app_ok = True
        self.hook_ok = True

    def check_read_token(self):
        return self.read_ok

    def check_app_token(self):
        return self.app_ok

    def check_hook_token(self):
        return self.hook_ok


class TestBlueprint:
    @pytest.fixture()
    def client(self, tmp_path):
        hub = FakeHub(tmp_path)
        install_usage_aggregate(hub)
        return hub, hub.app.test_client()

    def test_ingest_then_report(self, client):
        _hub, http = client
        response = http.post("/api/router/child-guard/usage/ingest", json={
            "hours": [{"date": DAY, "mac": MAC_A, "hour": 12, "activeSecs": 3000}],
            "apps": [{"date": DAY, "mac": MAC_A, "app": "微信", "activeSecs": 4140, "sessions": 9}],
            "sessions": [session(MAC_A, DAY, "微信", 1_789_700_000, 1_789_700_060, 60)],
            "today": DAY,
        })
        assert response.status_code == 200
        body = response.get_json()
        assert body["ok"] is True
        assert body["upserted"] == {"hourly": 1, "dailyApp": 1, "sessions": 1,
                                    "deviceMinutes": 0, "appMinutes": 0, "traffic": 0}

        report = http.get(
            f"/api/router/child-guard/usage/report?date={DAY}&macs={MAC_A}"
        ).get_json()
        assert report["ok"] is True
        assert report["onlineMinutes"] == 50
        assert report["apps"][0]["app"] == "微信"
        assert report["apps"][0]["minutes"] == 69
        assert report["apps"][0]["sessions"] == 1
        assert report["apps"][0]["sessionRanges"][0]["activeSeconds"] == 60

    def test_v3_ingest_then_report_end_to_end(self, client):
        """A whole v3 push over HTTP: minutes in, minutes + traffic out."""
        _hub, http = client
        body = {
            "version": 3,
            "keepDays": 10,
            "today": DAY,
            "deviceMinutes": [
                device_minutes_row(MAC_A, DAY, [bj_minute(DAY, 8, m) for m in (15, 16, 17)]),
            ],
            "appMinutes": [
                app_minutes_row(MAC_A, DAY, "抖音", [bj_minute(DAY, 8, m) for m in (15, 16, 17)]),
            ],
            "traffic": [traffic_row(MAC_A, DAY, 1_500_000, 2_500_000)],
        }
        response = http.post("/api/router/child-guard/usage/ingest", json=body)
        assert response.status_code == 200
        pushed = response.get_json()
        assert pushed["version"] == 3
        assert pushed["upserted"] == {"hourly": 0, "dailyApp": 0, "sessions": 0,
                                      "deviceMinutes": 3, "appMinutes": 3, "traffic": 1}
        assert pushed["pruned"]["deviceMinutes"] == 0

        report = http.get(
            f"/api/router/child-guard/usage/report?date={DAY}&macs={MAC_A}"
        ).get_json()
        assert report["basis"] == "minutes"
        assert report["onlineMinutes"] == 3
        assert report["onlineSeconds"] == 180
        assert report["hourly"][8]["minutes"] == 3
        assert report["hourly"][9]["minutes"] == 0
        assert report["apps"] == [{
            "app": "抖音", "minutes": 3, "sessions": 1,
            "sessionRanges": [{
                "startEpoch": bj_minute(DAY, 8, 15),
                "endEpoch": bj_minute(DAY, 8, 18),
                "activeSeconds": 180, "minutes": 3,
            }],
            "txBytes": 0, "rxBytes": 0,
        }]
        assert report["traffic"] == {
            "txBytes": 1_500_000, "rxBytes": 2_500_000, "totalBytes": 4_000_000,
            "daily": [{"date": DAY, "txBytes": 1_500_000, "rxBytes": 2_500_000,
                       "totalBytes": 4_000_000}],
        }

        # Relay retries: the identical push must not move a single number.
        retry = http.post("/api/router/child-guard/usage/ingest", json=body).get_json()
        assert retry["upserted"]["deviceMinutes"] == 3
        again = http.get(
            f"/api/router/child-guard/usage/report?date={DAY}&macs={MAC_A}"
        ).get_json()
        assert again["onlineMinutes"] == 3
        assert again["traffic"]["totalBytes"] == 4_000_000
        status = http.get("/api/router/child-guard/usage/status").get_json()
        assert status["deviceMinuteRows"] == 3
        assert status["appMinuteRows"] == 3
        assert status["trafficRows"] == 1

    def test_v3_and_v2_bodies_share_one_endpoint(self, client):
        """A router still on v2 posts hours and keeps getting the legacy shape."""
        _hub, http = client
        http.post("/api/router/child-guard/usage/ingest", json={
            "version": 2,
            "hours": [{"date": DAY, "mac": MAC_A, "hour": 12, "activeSecs": 600}],
            "today": DAY,
        })
        report = http.get(
            f"/api/router/child-guard/usage/report?date={DAY}&macs={MAC_A}"
        ).get_json()
        assert report["basis"] == "legacy"
        assert report["onlineMinutes"] == 10
        # The legacy shape is untouched: sparse hour rows, exactly as before v3.
        assert report["hourly"] == [{"hour": 12, "minutes": 10,
                                     "txBytes": 0, "rxBytes": 0}]
        assert report["traffic"]["totalBytes"] == 0

    def test_ingest_rejects_bad_minute_payload(self, client):
        _hub, http = client
        response = http.post("/api/router/child-guard/usage/ingest", json={
            "version": 3,
            "deviceMinutes": [{"mac": MAC_A, "date": DAY, "minutes": "not-a-list"}],
        })
        assert response.status_code == 400
        assert response.get_json()["errorCode"] == "invalid_request"

    def test_ingest_rejects_bad_payload(self, client):
        _hub, http = client
        response = http.post("/api/router/child-guard/usage/ingest", json={
            "hours": [{"date": "bogus", "mac": MAC_A, "hour": 12, "activeSecs": 60}],
        })
        assert response.status_code == 400
        assert response.get_json()["errorCode"] == "invalid_request"
    def test_unauthorized_is_rejected(self, client):
        hub, http = client
        hub.hook_ok = False
        hub.app_ok = False
        assert http.post("/api/router/child-guard/usage/ingest", json={}).status_code == 401

        hub.read_ok = False
        assert http.get("/api/router/child-guard/usage/report").status_code == 401
        assert http.get("/api/router/child-guard/usage/status").status_code == 401

    def test_status_exposes_retention_and_size(self, client):
        _hub, http = client
        body = http.get("/api/router/child-guard/usage/status").get_json()
        assert body["ok"] is True
        assert body["hourlyRows"] == 0
        assert body["hourlyKeepDays"] > 0
        assert body["dailyKeepDays"] >= body["hourlyKeepDays"]

    def test_report_defaults_to_today(self, client):
        _hub, http = client
        body = http.get(f"/api/router/child-guard/usage/report?macs={MAC_A}").get_json()
        assert body["date"] == date.today().isoformat()


# ---------------------------------------------------------------------------
# v3 分钟存储 / 设备目录 / overview / 页面读取的纯度
# ---------------------------------------------------------------------------

import time  # noqa: E402

from usage_aggregate import (  # noqa: E402
    ATTENTION_NOTICE_MINUTES,
    LATE_NIGHT_END_HOUR,
    MINUTE_SECONDS,
    build_guard_overview,
)
from child_guard_schedule import BEIJING, WEEKDAY_KEYS  # noqa: E402

UID = "0123456789ABCDEF0123456789ABCDEF"
ROUTER = "be72"


def beijing_date(epoch: int) -> str:
    """The router-local day an epoch falls on (the Hub box may be elsewhere)."""
    return time.strftime("%Y-%m-%d", time.gmtime(int(epoch) + 8 * 3600))


def floor_minute(epoch: int) -> int:
    return int(epoch) - int(epoch) % MINUTE_SECONDS


def v3_body(day, minutes, *, app_minutes=None, traffic=None, generated=None,
            mac=MAC_A):
    """A relay-shaped v3 push: 分钟桶 + 固件日字节数。"""
    stamp = int(generated if generated is not None else
                (max(minutes) + 30 if minutes else time.time()))
    return {
        "version": 3,
        "keepDays": 10,
        "generatedAt": stamp,
        "deviceMinutes": [{"mac": mac, "date": day, "minutes": list(minutes)}],
        "appMinutes": ([{"mac": mac, "date": day, "app": "微信",
                         "minutes": list(app_minutes)}]
                       if app_minutes is not None else []),
        "traffic": (traffic if traffic is not None
                    else [{"mac": mac, "date": day, "txBytes": 123,
                           "rxBytes": 456, "totalBytes": 579}]),
    }


class TestV3IngestStorage:
    """What the relay's v3 push does to the tables, and what it cannot do."""

    def test_repeated_push_never_double_counts_a_minute(self, store):
        day = beijing_date(bj_minute(DAY, 10))
        minutes = run_from(bj_minute(DAY, 10), 4)
        body = v3_body(day, minutes)
        store.ingest_v3(body, router=ROUTER)
        first = store.report([MAC_A], day, ROUTER)
        for _ in range(3):
            store.ingest_v3(body, router=ROUTER)
        again = store.report([MAC_A], day, ROUTER)
        assert again["onlineMinutes"] == first["onlineMinutes"] == 4
        assert again["todayMinutes"] == 4

    def test_one_new_minute_moves_today_minutes_by_exactly_one(self, store):
        day = beijing_date(bj_minute(DAY, 10))
        base = run_from(bj_minute(DAY, 10), DAY_MIN_RUN_MINUTES)
        store.ingest_v3(v3_body(day, base), router=ROUTER)
        assert store.report([MAC_A], day, ROUTER)["todayMinutes"] == DAY_MIN_RUN_MINUTES
        store.ingest_v3(v3_body(day, [base[-1] + 60]), router=ROUTER)
        assert store.report([MAC_A], day, ROUTER)["todayMinutes"] == DAY_MIN_RUN_MINUTES + 1

    def test_traffic_days_are_never_summed_into_a_bigger_total(self, store):
        day = beijing_date(bj_minute(DAY, 10))
        rows = [{"mac": MAC_A, "date": day, "txBytes": 1000, "rxBytes": 2000,
                 "totalBytes": 3000}]
        store.ingest_v3(v3_body(day, [bj_minute(DAY, 10)], traffic=rows), router=ROUTER)
        # A re-delivery and a *smaller* counter (router reboot) must both leave
        # the day alone; only real growth moves it.
        store.ingest_v3(v3_body(day, [], traffic=rows), router=ROUTER)
        store.ingest_v3(v3_body(day, [], traffic=[{
            "mac": MAC_A, "date": day, "txBytes": 1, "rxBytes": 1, "totalBytes": 2}]),
            router=ROUTER)
        report = store.report([MAC_A], day, ROUTER)
        assert report["traffic"]["txBytes"] == 1000
        assert report["traffic"]["rxBytes"] == 2000
        assert report["traffic"]["totalBytes"] == 3000
        store.ingest_v3(v3_body(day, [], traffic=[{
            "mac": MAC_A, "date": day, "txBytes": 1500, "rxBytes": 2000,
            "totalBytes": 3500}]), router=ROUTER)
        assert store.report([MAC_A], day, ROUTER)["traffic"]["totalBytes"] == 3500

    def test_sample_time_is_recorded_per_device(self, store):
        day = beijing_date(bj_minute(DAY, 10))
        newest = bj_minute(DAY, 10) + 60
        store.ingest_v3(v3_body(day, [bj_minute(DAY, 10), newest]), router=ROUTER)
        snapshot = store.guard_snapshot(ROUTER, [MAC_A], day)
        # 每台设备的 meta 是「它自己的数据推进到哪一分钟」，取分钟本身；载荷的
        # generatedAt 记在路由器那一行上，所以下一条才是 newest + 30。
        assert snapshot["metaByMac"][MAC_A] == newest
        assert snapshot["latestByMac"][MAC_A] == newest
        assert snapshot["routerLastSampleAt"] == newest + 30

    def test_two_routers_keep_their_own_rows(self, store):
        day = beijing_date(bj_minute(DAY, 10))
        store.ingest_v3(v3_body(day, run_from(bj_minute(DAY, 10),
                                              DAY_MIN_RUN_MINUTES)), router=ROUTER)
        store.ingest_v3(v3_body(day, run_from(bj_minute(DAY, 10), DAY_MIN_RUN_MINUTES)
                                + run_from(bj_minute(DAY, 11), DAY_MIN_RUN_MINUTES),
                                mac=MAC_B), router="other")
        assert store.report([MAC_A], day, ROUTER)["todayMinutes"] == DAY_MIN_RUN_MINUTES
        assert (store.report([MAC_B], day, "other")["todayMinutes"]
                == 2 * DAY_MIN_RUN_MINUTES)
        # A router name the Hub has never filed rows under still reads, because
        # an empty result is more likely a naming mismatch than a real zero.
        assert store.report([MAC_A], day, "Ruijie BE72")["todayMinutes"] == DAY_MIN_RUN_MINUTES


class TestV3ReportFields:
    """The keys the App reads with silent defaults must always be there."""

    @staticmethod
    def _skip_night_window(now: float) -> None:
        """拿"现在"造分钟时，0-6 点会落进夜间口径 —— 只有设备分钟、没有应用归属的段
        按设计不计数（2026-09-21 实测：凌晨 236MB 流量对 0 分钟就是这条规则）。"""
        if datetime.fromtimestamp(now, BEIJING).hour < LATE_NIGHT_END_HOUR:
            pytest.skip("night window excludes device-only minutes by design")

    def test_report_states_freshness_and_data_presence(self, store):
        now = floor_minute(time.time())
        self._skip_night_window(now)
        day = beijing_date(now)
        store.ingest_v3(v3_body(day, run_from(now - 120, DAY_MIN_RUN_MINUTES),
                                generated=now), router=ROUTER)
        report = store.report([MAC_A], day, ROUTER)
        assert report["hasData"] is True
        assert report["todayMinutes"] == report["onlineMinutes"] == DAY_MIN_RUN_MINUTES
        assert report["lastSampleAt"] == now
        assert report["stale"] is False
        assert report["activeNow"] is True
        assert report["generatedAt"] >= now

    def test_a_day_with_nothing_recorded_says_no_data_not_zero_minutes(self, store):
        report = store.report([MAC_A], "2026-09-18", ROUTER)
        assert report["hasData"] is False
        assert report["todayMinutes"] == 0
        assert report["onlineMinutes"] == 0

    def test_a_stalled_pipeline_is_stale_not_zero_minutes(self, store):
        now = floor_minute(time.time())
        self._skip_night_window(now)
        # 六到八分钟前的一段真实使用：数据是真的，但早已不再推进。
        idle = run_from(now - 480, DAY_MIN_RUN_MINUTES)
        day = beijing_date(idle[0])
        if beijing_date(now) != day:  # pragma: no cover - 午夜几分钟内
            pytest.skip("too close to midnight to distinguish stale")
        store.ingest_v3(v3_body(day, idle, generated=idle[-1]), router=ROUTER)
        report = store.report([MAC_A], day, ROUTER)
        assert report["hasData"] is True
        assert report["todayMinutes"] == DAY_MIN_RUN_MINUTES
        assert report["stale"] is True

    def test_a_past_day_is_never_marked_stale(self, store):
        store.insert_device_minutes([device_minutes_row(
            MAC_A, DAY, [bj_minute(DAY, 20)])])
        report = store.report([MAC_A], DAY)
        assert report["stale"] is False
        assert report["activeNow"] is False
        assert report["hasData"] is True

    def test_the_minute_window_is_what_callers_clamp_to(self):
        assert default_keep_days()["minute"] >= 1
        assert set(default_keep_days()) == {"hourly", "dailyApp", "minute"}


class TestGuardDeviceDirectory:
    """uid -> MACs/名称/封禁 lives in SQLite so reads never ask the router."""

    def test_devices_round_trip(self, store):
        assert store.guard_devices(ROUTER) == []
        store.remember_guard_devices(ROUTER, [
            {"uid": UID.lower(), "macs": ["DA-1F-85-0C-19-FC"], "name": "电脑"},
        ])
        rows = store.guard_devices(ROUTER)
        assert [row["uid"] for row in rows] == [UID]
        assert rows[0]["macs"] == [MAC_A]
        assert rows[0]["name"] == "电脑"
        assert rows[0]["blocked"] is False
        assert store.guard_device(ROUTER, UID.lower())["macs"] == [MAC_A]
        assert store.guard_device(ROUTER, "another") is None

    def test_a_blocked_only_update_keeps_the_identity(self, store):
        store.remember_guard_devices(ROUTER, [
            {"uid": UID, "macs": [MAC_A], "name": "电脑"}])
        store.remember_guard_devices(ROUTER, [
            {"uid": UID, "blocked": True, "blockedUntilEpoch": 1789862400}])
        row = store.guard_device(ROUTER, UID)
        assert (row["macs"], row["name"]) == ([MAC_A], "电脑")
        assert row["blocked"] is True and row["blockedUntilEpoch"] == 1789862400
        store.remember_guard_devices(ROUTER, [{"uid": UID, "blocked": False}])
        assert store.guard_device(ROUTER, UID)["blocked"] is False

    def test_a_pass_window_has_its_own_column_and_a_block_only_update_keeps_it(self, store):
        store.remember_guard_devices(ROUTER, [
            {"uid": UID, "macs": [MAC_A], "blocked": True, "blockedUntilEpoch": 1789862400}])
        store.remember_guard_devices(ROUTER, [{"uid": UID, "pausedUntilEpoch": 1789866000}])
        row = store.guard_device(ROUTER, UID)
        # 「禁到 22:00」和「放行到 23:00」是两件事：一个把另一个抹掉，界面上就会
        # 出现放行中还显示禁网中（或反过来）。
        assert (row["blocked"], row["blockedUntilEpoch"]) == (True, 1789862400)
        assert row["passUntilEpoch"] == 1789866000
        store.remember_guard_devices(ROUTER, [{"uid": UID, "pausedUntilEpoch": 0}])
        assert store.guard_device(ROUTER, UID)["passUntilEpoch"] == 0
        assert store.guard_device(ROUTER, UID)["blockedUntilEpoch"] == 1789862400

    def test_devices_are_scoped_per_router(self, store):
        store.remember_guard_devices(ROUTER, [{"uid": UID, "macs": [MAC_A]}])
        assert store.guard_devices("other") == []

    def test_a_placeholder_name_never_eats_the_real_one(self, store):
        """中继没有身份信息时回的是占位串，写进缓存会把真名字抹掉。

        界面上那「一长串设备名」就是这条链路：真名字被抹了，App 只能退回 UID。
        """
        store.remember_guard_devices(ROUTER, [{"uid": UID, "macs": [MAC_A], "name": "华为Mate60"}])
        store.remember_guard_devices(ROUTER, [{"uid": UID, "name": "LabProbe 设备"}])
        assert store.guard_device(ROUTER, UID)["name"] == "华为Mate60"
        store.remember_guard_devices(ROUTER, [{"uid": "OTHERUID", "name": "受守护设备"}])
        assert store.guard_device(ROUTER, "OTHERUID")["name"] == ""
        store.remember_guard_devices(ROUTER, [{"uid": UID, "userDefinedName": "爸爸的手机"}])
        assert store.guard_device(ROUTER, UID)["name"] == "爸爸的手机"

    def test_forget_drops_only_that_uid(self, store):
        store.remember_guard_devices(ROUTER, [
            {"uid": UID, "macs": [MAC_A]}, {"uid": "OTHERUID", "macs": [MAC_B]}])
        assert store.forget_guard_device(ROUTER, UID.lower()) == 1
        assert [row["uid"] for row in store.guard_devices(ROUTER)] == ["OTHERUID"]

    def test_forget_also_drops_the_cached_plans(self, store):
        store.remember_guard_devices(ROUTER, [{"uid": UID, "macs": [MAC_A]}])
        store.remember_guard_plans(ROUTER, UID, [{"id": "p1"}])
        store.forget_guard_device(ROUTER, UID)
        assert store.guard_plan_snapshot(ROUTER, UID) is None


class TestGuardPlanCache:
    """计划快照是总览生效态的唯一来源 —— 「没读过」不等于「没有计划」。"""

    def test_an_unread_device_has_no_snapshot(self, store):
        assert store.guard_plan_snapshot(ROUTER, UID) is None

    def test_an_empty_snapshot_is_not_the_same_as_no_snapshot(self, store):
        store.remember_guard_plans(ROUTER, UID, [])
        assert store.guard_plan_snapshot(ROUTER, UID) == []

    def test_the_uid_normalises_on_both_ends(self, store):
        store.remember_guard_plans(ROUTER, UID.lower(), [{"id": "p1"}])
        assert store.guard_plan_snapshot(ROUTER, UID) == [{"id": "p1"}]

    def test_the_latest_snapshot_replaces_the_old_one(self, store):
        store.remember_guard_plans(ROUTER, UID, [{"id": "p1"}, {"id": "p2"}])
        store.remember_guard_plans(ROUTER, UID, [{"id": "p3"}])
        assert [plan["id"] for plan in store.guard_plan_snapshot(ROUTER, UID)] == ["p3"]

    def test_plans_are_scoped_per_router(self, store):
        store.remember_guard_plans(ROUTER, UID, [{"id": "p1"}])
        assert store.guard_plan_snapshot("other", UID) is None

    def test_a_non_dict_plan_is_dropped_instead_of_breaking_the_json(self, store):
        store.remember_guard_plans(ROUTER, UID, [{"id": "p1"}, "junk", None])
        assert store.guard_plan_snapshot(ROUTER, UID) == [{"id": "p1"}]


class TestGuardOverview:
    """One set of SQL reads, zero router traffic, honest unknowns."""

    def build(self, store, devices, *, now_epoch, presence=None, router=ROUTER):
        return build_guard_overview(store, router=router, devices=devices,
                                    presence=presence, now_epoch=now_epoch)

    def test_a_device_with_no_rows_is_unknown_not_all_clear(self, store):
        reference = bj_minute(DAY, 13)
        day = beijing_date(reference)
        rows = [{"uid": UID, "macs": [MAC_A], "name": "电脑", "blocked": False,
                 "blockedUntilEpoch": 0, "updatedAt": reference}]
        payload = self.build(store, rows, now_epoch=reference + 30)
        device = payload["devices"][0]
        assert device["hasData"] is False
        assert device["todayMinutes"] == 0
        assert device["attention"]["state"] == "unknown"
        assert device["attention"]["hasAttention"] is False
        assert device["online"] is None
        assert device["stale"] is True
        assert payload["stale"] is True and payload["lastSampleAt"] == 0

    def test_a_minute_in_the_current_bucket_is_active_now(self, store):
        reference = bj_minute(DAY, 13)
        day = beijing_date(reference)
        minutes = run_from(reference - (DAY_MIN_RUN_MINUTES - 1) * 60, DAY_MIN_RUN_MINUTES)
        store.ingest_v3(v3_body(day, minutes), router=ROUTER)
        rows = [{"uid": UID, "macs": [MAC_A], "name": "电脑"}]
        device = self.build(store, rows, now_epoch=reference + 5,
                            presence={MAC_A: True})["devices"][0]
        assert device["activeNow"] is True
        assert device["todayMinutes"] == DAY_MIN_RUN_MINUTES
        assert device["hasData"] is True
        assert device["attention"]["state"] == "none"
        assert device["online"] is True
        assert device["stale"] is False

    def test_the_previous_bucket_also_counts_as_active(self, store):
        reference = bj_minute(DAY, 13)
        day = beijing_date(reference)
        store.ingest_v3(v3_body(day, [reference]), router=ROUTER)
        # 分钟要等它结束才结算，所以本分钟还没有行时上一格就算「正在上网」。
        device = self.build(store, [{"uid": UID, "macs": [MAC_A]}],
                            now_epoch=reference + MINUTE_SECONDS + 59)["devices"][0]
        assert device["activeNow"] is True

    def test_two_macs_of_one_device_share_a_minute_once(self, store):
        reference = bj_minute(DAY, 13)
        day = beijing_date(reference)
        minutes = run_from(reference, DAY_MIN_RUN_MINUTES)
        store.ingest_v3(v3_body(day, minutes), router=ROUTER)
        store.ingest_v3(v3_body(day, minutes, mac=MAC_B), router=ROUTER)
        device = self.build(
            store, [{"uid": UID, "macs": [MAC_A, MAC_B]}],
            now_epoch=reference + 5)["devices"][0]
        assert device["todayMinutes"] == DAY_MIN_RUN_MINUTES, \
            "两块网卡报同一分钟，设备时长只多一格"

    def test_late_night_minutes_are_an_alert(self, store):
        reference = bj_minute(DAY, 13)
        day = beijing_date(reference)
        late = run_from(bj_minute(day, 2, 5), NIGHT_MIN_RUN_MINUTES)
        store.ingest_v3(v3_body(day, late, app_minutes=late), router=ROUTER)
        device = self.build(store, [{"uid": UID, "macs": [MAC_A]}],
                            now_epoch=reference + 5)["devices"][0]
        assert device["attention"]["state"] == "alert"
        assert device["attention"]["lateNightMinutes"] == NIGHT_MIN_RUN_MINUTES
        assert device["attention"]["hasAttention"] is True
        assert "凌晨" in device["attention"]["text"]
        assert device["activeNow"] is False

    def test_a_night_keepalive_wake_is_not_an_alert(self, store):
        """整晚的保活唤醒都是孤零零一两格：既不是时长，也不是「凌晨还在上网」。"""
        reference = bj_minute(DAY, 13)
        day = beijing_date(reference)
        wakes = [bj_minute(day, 1, 0), bj_minute(day, 2, 30), bj_minute(day, 3, 45)]
        store.ingest_v3(v3_body(day, wakes, app_minutes=wakes[:2]), router=ROUTER)
        device = self.build(store, [{"uid": UID, "macs": [MAC_A]}],
                            now_epoch=reference + 5)["devices"][0]
        assert device["attention"]["state"] == "none"
        assert device["attention"]["lateNightMinutes"] == 0
        assert device["todayMinutes"] == 0
        assert device["hasData"] is True, "记过分钟，只是没到计入口径"

    def test_a_long_day_crosses_the_notice_threshold(self, store):
        reference = bj_minute(DAY, 23)
        day = beijing_date(reference)
        minutes = [bj_minute(day, 9) + offset * MINUTE_SECONDS
                   for offset in range(ATTENTION_NOTICE_MINUTES)]
        store.ingest_v3(v3_body(day, minutes), router=ROUTER)
        device = self.build(store, [{"uid": UID, "macs": [MAC_A]}],
                            now_epoch=reference + 5)["devices"][0]
        assert device["todayMinutes"] == ATTENTION_NOTICE_MINUTES
        assert device["attention"]["state"] == "notice"
        assert device["attention"]["hasAttention"] is True

    def test_top_apps_come_from_the_app_minute_rows(self, store):
        reference = bj_minute(DAY, 13)
        day = beijing_date(reference)
        wechat = run_from(bj_minute(DAY, 11), 4)
        douyin = run_from(bj_minute(DAY, 12), DAY_MIN_RUN_MINUTES)
        store.insert_app_minutes([
            app_minutes_row(MAC_A, day, "微信", wechat),
            app_minutes_row(MAC_A, day, "抖音", douyin),
        ], router=ROUTER)
        store.insert_device_minutes([device_minutes_row(MAC_A, day, wechat + douyin)],
                                    router=ROUTER)
        device = self.build(store, [{"uid": UID, "macs": [MAC_A]}],
                            now_epoch=reference + 5)["devices"][0]
        assert device["topApps"] == [{"app": "微信", "minutes": 4},
                                     {"app": "抖音", "minutes": DAY_MIN_RUN_MINUTES}]

    def test_presence_unknown_is_reported_as_none_not_offline(self, store):
        reference = bj_minute(DAY, 13)
        rows = [{"uid": UID, "macs": [MAC_A, MAC_B]}]
        online = self.build(store, rows, now_epoch=reference + 5,
                            presence={MAC_A: False, MAC_B: True})["devices"][0]
        assert online["online"] is True
        missing = self.build(store, rows, now_epoch=reference + 5,
                             presence={MAC_A: False})["devices"][0]
        assert missing["online"] is None
        off = self.build(store, rows, now_epoch=reference + 5,
                         presence={MAC_A: False, MAC_B: False})["devices"][0]
        assert off["online"] is False

    def schedule(self, store, plans, *, hour=13, minute=0):
        reference = bj_minute(DAY, hour, minute)
        store.remember_guard_plans(ROUTER, UID, plans)
        device = self.build(store, [{"uid": UID, "macs": [MAC_A]}],
                            now_epoch=reference)["devices"][0]
        return reference, device

    def test_no_cached_snapshot_is_unknown_not_unrestricted(self, store):
        reference = bj_minute(DAY, 13)
        device = self.build(store, [{"uid": UID, "macs": [MAC_A]}],
                            now_epoch=reference)["devices"][0]
        assert device["schedule"] == "unknown"
        assert device["planCount"] == 0
        assert device["currentRange"] is None

    def test_an_empty_snapshot_means_the_router_said_no_plans(self, store):
        _reference, device = self.schedule(store, [])
        assert device["schedule"] == "unrestricted"
        assert device["planCount"] == 0

    def test_a_cached_window_drives_the_effective_state(self, store):
        today = WEEKDAY_KEYS[datetime.fromtimestamp(bj_minute(DAY, 13), BEIJING).weekday()]
        reference, device = self.schedule(
            store, [{"id": "p1", "enabled": True, "mode": "internet_window",
                     "startTime": "17:00", "endTime": "21:30", "weekdays": [today]}],
            hour=14, minute=41)
        assert device["schedule"] == "blocked"
        assert device["planCount"] == 1
        assert device["blockedRange"] == {"start": "00:00", "end": "17:00", "kind": "block"}
        assert device["minutesToChange"] == 139
        assert device["nextChangeAtEpoch"] == reference + 139 * MINUTE_SECONDS

    def test_inside_a_window_the_card_names_the_range(self, store):
        today = WEEKDAY_KEYS[datetime.fromtimestamp(bj_minute(DAY, 18), BEIJING).weekday()]
        _reference, device = self.schedule(
            store, [{"id": "p1", "enabled": True, "mode": "app_allowlist",
                     "startTime": "17:00", "endTime": "21:30", "weekdays": [today]}],
            hour=18)
        assert device["schedule"] == "partial"
        assert device["blockedRange"] is None
        assert device["currentRange"]["start"] == "17:00"
        assert device["currentRange"]["end"] == "21:30"


    def test_the_router_is_never_part_of_an_overview(self, store):
        class NoStore:
            def guard_snapshot(self, *args, **kwargs):
                raise AssertionError("overview must read SQLite only")

        with pytest.raises(AssertionError):
            NoStore().guard_snapshot(ROUTER, [MAC_A], DAY)
        payload = build_guard_overview(None, router=ROUTER,
                                        devices=[{"uid": UID, "macs": [MAC_A]}],
                                        now_epoch=bj_minute(DAY, 13))
        assert payload["devices"][0]["todayMinutes"] == 0

