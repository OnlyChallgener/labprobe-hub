"""每日时长限额：Hub 侧策略值的读写、目录同步不丢、概览限状态。

固件没有「每天最多上多久」这个概念，额度是 Hub 自己的策略，所以它必须活过
固件目录的整表重建 —— 这一层最容易在「删表重插」时被静默清零。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from usage_aggregate import UsageAggregateStore, build_guard_overview

MAC_A = "da:1f:85:0c:19:fc"
DAY = "2026-09-18"
ROUTER = "be50"
UID = "u-1001"


@pytest.fixture()
def store(tmp_path):
    aggregate = UsageAggregateStore(tmp_path)
    aggregate.initialize()
    return aggregate


def bj_minute(day: str, hour: int, minute: int = 0) -> int:
    moment = datetime.strptime(f"{day} {hour:02d}:{minute:02d}", "%Y-%m-%d %H:%M")
    return int(moment.replace(tzinfo=timezone(timedelta(hours=8))).timestamp())


def run_from(start: int, count: int) -> list:
    return [start + offset * 60 for offset in range(count)]


def seed_device(store: UsageAggregateStore) -> None:
    store.remember_guard_devices(ROUTER, [
        {"uid": UID, "name": "小明的平板", "macs": [MAC_A], "blocked": False},
    ])


def test_limit_round_trips_through_the_store(store):
    seed_device(store)

    assert store.set_guard_daily_limit(ROUTER, UID, 120) == 120
    assert store.guard_daily_limits(ROUTER) == {UID: 120}
    assert store.guard_devices(ROUTER)[0]["dailyLimitMinutes"] == 120

    assert store.set_guard_daily_limit(ROUTER, UID, 0) == 0
    assert store.guard_daily_limits(ROUTER) == {UID: 0}
    assert store.guard_devices(ROUTER)[0]["dailyLimitMinutes"] == 0, "0 是取消，不是没读到"


def test_unknown_device_is_not_created(store):
    seed_device(store)

    assert store.set_guard_daily_limit(ROUTER, "u-9999", 60) is None
    assert store.guard_daily_limits(ROUTER) == {UID: 0}, "不存在的设备不能被凭空插一行"


def test_limit_survives_a_directory_refresh(store):
    seed_device(store)
    store.set_guard_daily_limit(ROUTER, UID, 90)

    # 固件目录每次同步都会重写设备行，限额不是固件字段，必须原样留着。
    store.remember_guard_devices(ROUTER, [
        {"uid": UID, "name": "小明的平板", "macs": [MAC_A], "blocked": True},
    ])

    assert store.guard_daily_limits(ROUTER) == {UID: 90}
    assert store.guard_devices(ROUTER)[0]["blocked"] is True


def test_limit_survives_the_membership_rebuild(store):
    seed_device(store)
    store.set_guard_daily_limit(ROUTER, UID, 45)

    # 这一层是 DELETE + 整表重插，最容易把非固件字段丢掉。
    assert store.reconcile_guard_membership(
        ROUTER, "get_users",
        [{"uid": UID, "name": "小明的平板", "macs": [MAC_A], "blocked": False}],
        UID, 7) is True

    assert store.guard_daily_limits(ROUTER) == {UID: 45}


def test_limit_dies_with_the_device(store):
    seed_device(store)
    store.set_guard_daily_limit(ROUTER, UID, 60)

    store.forget_guard_device(ROUTER, UID)

    assert store.guard_daily_limits(ROUTER) == {}


def overview_entry(store: UsageAggregateStore, limit: int) -> dict:
    store.set_guard_daily_limit(ROUTER, UID, limit)
    overview = build_guard_overview(
        store, router=ROUTER, devices=store.guard_devices(ROUTER),
        now_epoch=bj_minute(DAY, 12))
    return overview["devices"][0]


@pytest.fixture()
def store_with_one_hour(store):
    seed_device(store)
    store.insert_device_minutes(
        [{"mac": MAC_A, "date": DAY, "minutes": run_from(bj_minute(DAY, 9), 60)}],
        router=ROUTER)
    return store


def test_overview_reports_no_limit_as_none(store_with_one_hour):
    entry = overview_entry(store_with_one_hour, 0)

    assert entry["todayMinutes"] == 60
    assert entry["dailyLimitMinutes"] == 0
    assert entry["limitState"] == "none", "没配限额时不能说「已用完」"


def test_overview_calls_a_roomy_limit_ok(store_with_one_hour):
    entry = overview_entry(store_with_one_hour, 120)

    assert (entry["todayMinutes"], entry["dailyLimitMinutes"]) == (60, 120)
    assert entry["limitState"] == "ok"


def test_overview_calls_eighty_percent_approaching(store_with_one_hour):
    entry = overview_entry(store_with_one_hour, 70)  # 60 >= 70 * 0.8

    assert entry["limitState"] == "approaching"


def test_overview_calls_a_spent_limit_reached(store_with_one_hour):
    entry = overview_entry(store_with_one_hour, 60)  # 恰好用完

    assert entry["limitState"] == "reached"


def test_an_over_limit_day_is_still_reached(store_with_one_hour):
    entry = overview_entry(store_with_one_hour, 30)

    assert entry["todayMinutes"] > entry["dailyLimitMinutes"]
    assert entry["limitState"] == "reached"
