"""计划生效态：把「星期 + 允许时段」翻译成「此刻能不能上网、多久之后变」。

计划的事实存在路由器上，Hub 只是缓存了一份用于展示。这个模块是纯函数，不读
数据库也不问路由器，所以「当前时段允许上网，59分钟后被禁网」这句话里的每个
数字都能被单测钉住。

口径与 App 的 ``dayPlanSegments`` 保持一致：
* 一条启用计划都没有 —— 今天不受限（``unrestricted``）；
* 有计划的日子里，没被任何允许时段覆盖的时间一律算禁网；
* 计划是「允许上网的时段」，所以跨天的下一次变化要往后找，官方显示的
  「下周三14:44后允许上网」就是这个 lookahead。
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

BEIJING = timezone(timedelta(hours=8))

# datetime.weekday(): 周一=0 … 周日=6，与 Hub/App 的 mon..sun 键一一对应。
WEEKDAY_KEYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

_DAY_START = "00:00"
_DAY_END = "23:59"
_LOOKAHEAD_DAYS = 7


def _minutes(text: Any) -> Optional[int]:
    """``HH:mm`` -> 当天分钟数；不是这个格式就当没有。"""
    value = str(text or "").strip()
    if len(value) != 5 or value[2:3] != ":":
        return None
    hour, minute = value[:2], value[3:]
    if not (hour.isdigit() and minute.isdigit()):
        return None
    total = int(hour) * 60 + int(minute)
    return total if 0 <= total <= 24 * 60 - 1 else None


def _label(total: int) -> str:
    return f"{total // 60:02d}:{total % 60:02d}"


def plan_day_ranges(plan: Mapping[str, Any], day_key: str) -> List[List[str]]:
    """这台计划在该星期生效的允许时段，``[["17:00","21:30"], …]``。

    官方式多规则放在 ``times`` 里（按星期分列），它是事实来源；只有旧版扁平
    字段（``weekdays`` + ``startTime``/``endTime``）时才退回单条时段。
    """
    if not plan.get("enabled", True):
        return []
    times = plan.get("times")
    if isinstance(times, Mapping):
        raw = times.get(day_key)
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
            ranges: List[List[str]] = []
            for item in raw:
                pair = list(item) if isinstance(item, Sequence) and not isinstance(item, (str, bytes)) else []
                if len(pair) != 2:
                    continue
                start, end = str(pair[0]), str(pair[1])
                if _minutes(start) is None or _minutes(end) is None:
                    continue
                if _minutes(start) >= _minutes(end):
                    continue
                ranges.append([start, end])
            if ranges:
                return ranges
    weekdays = [str(day).strip().lower() for day in (plan.get("weekdays") or [])]
    start, end = str(plan.get("startTime") or ""), str(plan.get("endTime") or "")
    if day_key in weekdays and _minutes(start) is not None and _minutes(end) is not None:
        if _minutes(start) < _minutes(end):
            return [[start, end]]
    return []


def _merge(intervals: Iterable[Sequence[int]]) -> List[List[int]]:
    """按分钟合并重叠/相接的允许区间。"""
    merged: List[List[int]] = []
    for start, end in sorted((int(a), int(b)) for a, b in intervals):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def _windows_on(plans: Sequence[Mapping[str, Any]], day_key: str) -> List[Dict[str, Any]]:
    """该星期所有启用计划的允许区间，附带「是全部允许还是部分 APP」。"""
    intervals: List[Sequence[int]] = []
    partial: List[bool] = []
    owners: List[List[str]] = []
    for plan in plans:
        if not plan.get("enabled", True):
            continue
        is_partial = str(plan.get("mode") or "") in {"app_allowlist", "app_blocklist"}
        for start, end in plan_day_ranges(plan, day_key):
            intervals.append((_minutes(start), _minutes(end)))
            partial.append(is_partial)
            owners.append([str(plan.get("id") or "")] if plan.get("id") else [])
    if not intervals:
        return []
    # 合并时逐条判断是否 partial：任一允许区间带 APP 限定，整段就是「部分APP」。
    marks: List[List[Any]] = []
    for (start, end), flag, owner in zip(intervals, partial, owners):
        merged_hit = False
        for mark in marks:
            if start <= mark[1] and end >= mark[0]:
                mark[0] = min(mark[0], start)
                mark[1] = max(mark[1], end)
                mark[2] = mark[2] or flag
                mark[3].extend(o for o in owner if o and o not in mark[3])
                merged_hit = True
                break
        if not merged_hit:
            marks.append([start, end, flag, list(owner)])
    return [
        {"start": int(head), "end": int(tail), "partial": bool(flag), "planIds": ids}
        for head, tail, flag, ids in sorted(marks, key=lambda item: item[0])
    ]


def schedule_state(plans: Optional[Sequence[Mapping[str, Any]]], now_epoch: int) -> Dict[str, Any]:
    """此刻这台设备的计划生效态。

    ``plans is None`` 表示 Hub 手上没有这台设备的计划快照 —— 那既不是「不受限」
    也不是「禁网」，只能报 ``unknown``，让界面闭嘴而不是猜一个。空列表才是真的
    「路由器上说这台设备一条计划都没有」。
    """
    if plans is None:
        return {
            "planCount": 0,
            "schedule": "unknown",
            "currentRange": None,
            "blockedRange": None,
            "nextChangeAtEpoch": None,
            "minutesToChange": None,
        }
    active = [plan for plan in (plans or []) if isinstance(plan, Mapping) and plan.get("enabled", True)]
    stamp = datetime.fromtimestamp(int(now_epoch), BEIJING)
    minute = stamp.hour * 60 + stamp.minute
    today = WEEKDAY_KEYS[stamp.weekday()]
    todays = _windows_on(active, today)

    if not active:
        return {
            "planCount": 0,
            "schedule": "unrestricted",
            "currentRange": None,
            "blockedRange": None,
            "nextChangeAtEpoch": None,
            "minutesToChange": None,
        }

    inside = next((window for window in todays if window["start"] <= minute < window["end"]), None)
    if inside is not None:
        state = "partial" if inside["partial"] else "allowed"
    else:
        state = "blocked"

    # 下一次变化 = 今天余下的边界，没有就往后 7 天找第一个允许起点。
    boundaries = sorted({
        int(now_epoch) + (edge - minute) * 60
        for window in todays
        for edge in (window["start"], window["end"])
        if edge > minute
    })
    next_change = boundaries[0] if boundaries else None
    if next_change is None:
        midnight = stamp.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        for offset in range(_LOOKAHEAD_DAYS):
            day = midnight + timedelta(days=offset)
            windows = _windows_on(active, WEEKDAY_KEYS[day.weekday()])
            if not windows:
                continue
            candidate = day.replace(hour=0, minute=0) + timedelta(minutes=windows[0]["start"])
            next_change = int(candidate.timestamp())
            break

    return {
        "planCount": len(active),
        "schedule": state,
        "currentRange": None if inside is None else {
            "start": _label(inside["start"]),
            "end": _label(inside["end"]),
            "kind": "partial" if inside["partial"] else "allow",
            "planIds": inside["planIds"],
        },
        "blockedRange": None if inside is not None or state == "unrestricted" else _blocked_now(todays, minute),
        "nextChangeAtEpoch": next_change,
        "minutesToChange": None if next_change is None else max(0, int((next_change - int(now_epoch)) // 60)),
    }


def _blocked_now(todays: Sequence[Mapping[str, Any]], minute: int) -> Optional[Dict[str, Any]]:
    """当前这段禁网的起止（禁到下一个允许时段开始）。"""
    ends = [window["start"] for window in todays if window["start"] > minute]
    start = max([window["end"] for window in todays if window["end"] <= minute] or [0])
    return {
        "start": _label(start),
        "end": _label(min(ends)) if ends else _DAY_END,
        "kind": "block",
    }


#: 界面上的临时放行时长预设（秒）。固件只认绝对截止时间。
PASS_PRESET_SECONDS = {"10m": 600, "30m": 1800, "1h": 3600}


def pass_deadline(now_epoch: int) -> int:
    """北京时间「明天零点」—— 固件的 pause 硬上限（超过直接回 endtime unsupport）。"""
    stamp = datetime.fromtimestamp(int(now_epoch), BEIJING)
    tomorrow = stamp.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    return int(tomorrow.timestamp())


def clean_pass_until(preset: Any, now_epoch: int) -> int:
    """把「放行多久」换算成绝对截止时间（epoch 秒）；``cancel`` 返回 0。

    换算只能发生在 Hub：中继在路由器上算不出「今天还剩多久」，而 23:30 点
    「放行 1 小时」会被固件整条拒收 —— 贴到今天结束更诚实，也比报错强。
    """
    now = max(0, int(now_epoch))
    deadline = pass_deadline(now)
    key = str(preset or "").strip().lower()
    if key == "cancel":
        return 0
    if key == "today":
        return deadline
    seconds = PASS_PRESET_SECONDS.get(key)
    if seconds is None:
        raise ValueError("未知的放行时长，请重新选择")
    until = now + seconds
    return deadline - 1 if until >= deadline else until
