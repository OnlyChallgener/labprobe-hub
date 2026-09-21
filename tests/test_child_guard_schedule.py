"""计划生效态纯函数的口径测试：卡片上「XX分钟后被禁网」每个数字都出自这里。"""

from datetime import datetime, timedelta, timezone

import pytest

from child_guard_schedule import (
    BEIJING,
    WEEKDAY_KEYS,
    clean_pass_until,
    pass_deadline,
    plan_day_ranges,
    schedule_state,
)


def _epoch(year: int, month: int, day: int, hour: int, minute: int) -> int:
    return int(datetime(year, month, day, hour, minute, tzinfo=BEIJING).timestamp())


def _weekday_key(epoch: int) -> str:
    return WEEKDAY_KEYS[datetime.fromtimestamp(epoch, BEIJING).weekday()]


def _plan(start: str, end: str, days=None, mode="internet_window", plan_id="p1",
          enabled=True, times=None):
    return {
        "id": plan_id,
        "enabled": enabled,
        "mode": mode,
        "startTime": start,
        "endTime": end,
        "weekdays": days or [_weekday_key(_epoch(2026, 9, 20, 12, 0))],
        **({"times": times} if times else {}),
    }


def test_no_plan_means_unrestricted():
    assert schedule_state([], _epoch(2026, 9, 20, 14, 41))["schedule"] == "unrestricted"
    assert schedule_state([], _epoch(2026, 9, 20, 14, 41))["planCount"] == 0


def test_missing_snapshot_is_unknown_not_unrestricted():
    """没有读到过计划 ≠ 没有计划：界面这时什么生效态都不该说。"""
    state = schedule_state(None, _epoch(2026, 9, 20, 14, 41))
    assert state["schedule"] == "unknown"
    assert state["planCount"] == 0
    assert state["nextChangeAtEpoch"] is None
    assert state["minutesToChange"] is None


def test_disabled_plan_is_not_a_plan_at_all():
    state = schedule_state([_plan("17:00", "21:30", enabled=False)], _epoch(2026, 9, 20, 14, 41))
    assert state["schedule"] == "unrestricted"
    assert state["planCount"] == 0


def test_outside_the_window_is_blocked_with_minutes_to_change():
    today = _weekday_key(_epoch(2026, 9, 20, 12, 0))
    now = _epoch(2026, 9, 20, 14, 41)
    state = schedule_state([_plan("17:00", "21:30", days=[today])], now)
    assert state["schedule"] == "blocked"
    assert state["minutesToChange"] == 139          # 14:41 -> 17:00
    assert state["blockedRange"] == {"start": "00:00", "end": "17:00", "kind": "block"}
    assert datetime.fromtimestamp(state["nextChangeAtEpoch"], BEIJING).strftime("%H:%M") == "17:00"


def test_inside_the_window_reports_the_range_and_the_end_boundary():
    today = _weekday_key(_epoch(2026, 9, 20, 12, 0))
    state = schedule_state([_plan("17:00", "21:30", days=[today])], _epoch(2026, 9, 20, 18, 0))
    assert state["schedule"] == "allowed"
    assert state["currentRange"]["start"] == "17:00"
    assert state["currentRange"]["end"] == "21:30"
    assert state["minutesToChange"] == 210          # 18:00 -> 21:30


def test_app_scoped_window_is_partial_not_allowed():
    today = _weekday_key(_epoch(2026, 9, 20, 12, 0))
    state = schedule_state(
        [_plan("17:00", "21:30", days=[today], mode="app_allowlist")], _epoch(2026, 9, 20, 18, 0))
    assert state["schedule"] == "partial"
    assert state["currentRange"]["kind"] == "partial"


def test_plan_for_other_weekdays_blocks_today_and_looks_ahead():
    now = _epoch(2026, 9, 20, 12, 0)
    today = _weekday_key(now)
    other = next(day for day in WEEKDAY_KEYS if day != today)
    state = schedule_state([_plan("14:44", "15:44", days=[other])], now)
    assert state["schedule"] == "blocked"
    # 下一次变化落在「另一个星期」的 14:44，而不是今天。
    target = datetime.fromtimestamp(state["nextChangeAtEpoch"], BEIJING)
    assert target.strftime("%H:%M") == "14:44"
    assert WEEKDAY_KEYS[target.weekday()] == other
    assert 0 < state["minutesToChange"] <= 7 * 24 * 60


def test_official_style_per_day_times_win_over_the_flattened_view():
    now = _epoch(2026, 9, 20, 12, 0)
    today = _weekday_key(now)
    plan = _plan("09:00", "10:00", days=[today], times={today: [["11:00", "12:30"]]})
    assert plan_day_ranges(plan, today) == [["11:00", "12:30"]]
    state = schedule_state([plan], now)
    # 12:00 落在 times 给的 11:00-12:30 里，说明扁平字段里的 09:00-10:00 没被采信。
    assert state["schedule"] == "allowed"
    assert state["currentRange"] == {
        "start": "11:00", "end": "12:30", "kind": "allow", "planIds": ["p1"]}
    assert state["minutesToChange"] == 30           # 12:00 -> 12:30


def test_overlapping_windows_merge_into_one_segment():
    today = _weekday_key(_epoch(2026, 9, 20, 12, 0))
    plans = [_plan("08:00", "12:00", days=[today], plan_id="a"),
             _plan("11:00", "14:00", days=[today], plan_id="b")]
    state = schedule_state(plans, _epoch(2026, 9, 20, 13, 0))
    assert state["schedule"] == "allowed"
    assert state["currentRange"]["start"] == "08:00"
    assert state["currentRange"]["end"] == "14:00"
    assert set(state["currentRange"]["planIds"]) == {"a", "b"}


def test_malformed_times_are_ignored_instead_of_raising():
    today = _weekday_key(_epoch(2026, 9, 20, 12, 0))
    broken = {"id": "x", "enabled": True, "mode": "internet_window",
              "startTime": "25:99", "endTime": "aa:bb", "weekdays": [today]}
    state = schedule_state([broken], _epoch(2026, 9, 20, 12, 0))
    assert state["schedule"] == "blocked"
    assert state["planCount"] == 1


def test_pass_presets_become_absolute_deadlines_and_cancel_is_zero():
    now = _epoch(2026, 9, 20, 12, 0)
    assert clean_pass_until("10m", now) == now + 600
    assert clean_pass_until("30m", now) == now + 1800
    assert clean_pass_until("1h", now) == now + 3600
    assert clean_pass_until("cancel", now) == 0


def test_today_pass_ends_at_beijing_midnight_tonight():
    now = _epoch(2026, 9, 20, 12, 0)
    assert clean_pass_until("today", now) == _epoch(2026, 9, 21, 0, 0)
    # 固件的硬上限就是这个数：再晚一秒它就整条拒收（实测 endtime unsupport）。
    assert pass_deadline(now) == _epoch(2026, 9, 21, 0, 0)


def test_a_pass_near_midnight_is_clamped_instead_of_rejected_by_the_firmware():
    now = _epoch(2026, 9, 20, 23, 30)
    assert clean_pass_until("1h", now) == _epoch(2026, 9, 21, 0, 0) - 1


def test_an_unknown_pass_preset_is_refused_before_it_reaches_the_router():
    with pytest.raises(ValueError):
        clean_pass_until("99h", _epoch(2026, 9, 20, 12, 0))
