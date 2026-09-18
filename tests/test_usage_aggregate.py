"""Aggregate-table tests for Child Internet usage statistics."""

from __future__ import annotations

import sqlite3
from datetime import date, timedelta

import pytest
from flask import Flask

from usage_aggregate import (
    DEFAULT_DAILY_KEEP_DAYS,
    DEFAULT_HOURLY_KEEP_DAYS,
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
        assert removed == {"hourly": 1, "dailyApp": 1}

        # the 100-day-old hourly row survives a 400-day hourly window
        assert store.report([MAC_A], recent_hourly)["onlineSeconds"] == 60
        assert store.report([MAC_A], old_hourly)["apps"] == []

    def test_prune_is_a_noop_within_the_window(self, store):
        store.upsert_hourly([hourly(MAC_A, DAY, 12, 60)])
        assert store.prune(today=DAY, hourly_keep_days=400, daily_keep_days=1095) == {
            "hourly": 0, "dailyApp": 0,
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

    def test_keep_days_helper_reports_both_windows(self):
        assert default_keep_days() == {"hourly": 10, "dailyApp": 10}


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

        report = compose_device_report(store, [MAC_A], DAY, live=live)
        assert report["source"] == "hub"
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
        assert report["keepDays"] == {"hourly": 10, "dailyApp": 10}

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
            "today": DAY,
        })
        assert response.status_code == 200
        body = response.get_json()
        assert body["ok"] is True
        assert body["upserted"] == {"hourly": 1, "dailyApp": 1}

        report = http.get(
            f"/api/router/child-guard/usage/report?date={DAY}&macs={MAC_A}"
        ).get_json()
        assert report["ok"] is True
        assert report["onlineMinutes"] == 50
        assert report["apps"][0]["app"] == "微信"
        assert report["apps"][0]["minutes"] == 69

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
