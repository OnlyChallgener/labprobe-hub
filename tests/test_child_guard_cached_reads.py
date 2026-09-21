"""读接口缓存优先：路由器慢或不在，页面也要立刻有东西可看。

Hub 前面那台 Lucky 反代在第几秒就回一整页 502 HTML，而 ``get_plans`` /
``get_runtime_state`` 以前会替 App 死等路由器。本地有快照时这两读根本不该出
门：过期就先发旧的、再补一次后台读，路由器最多 30 秒被问一次。
"""

import time

import hub
from child_guard_service import RouterCommandStore
from usage_aggregate import UsageAggregateStore

UID = "0123456789ABCDEF0123456789ABCDEF"
ROUTER = "be72"
PLANS_PATH = f"/api/router/child-guard/devices/{UID}/plans"
RUNTIME_PATH = f"/api/router/child-guard/devices/{UID}/runtime"


def _aggregate(tmp_path):
    aggregate = UsageAggregateStore(tmp_path / "usage")
    aggregate.initialize()
    return aggregate


def _prepare(monkeypatch, tmp_path, aggregate):
    monkeypatch.setattr(hub, "CHILD_GUARD_COMMANDS", RouterCommandStore(tmp_path))
    monkeypatch.setattr(hub, "CHILD_GUARD_SYNC_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(hub, "notify_agent_commands_changed", lambda *a, **k: None)
    monkeypatch.setattr(hub, "check_read_token", lambda: True)
    monkeypatch.setattr(hub, "_usage_aggregate_store", lambda: aggregate)
    monkeypatch.setattr(hub, "_child_guard_router", lambda payload=None: ROUTER)
    hub._CHILD_GUARD_REFRESH_AT.clear()
    enqueued = []
    monkeypatch.setattr(hub, "_child_guard_execute",
                        lambda action, payload=None, **kw: enqueued.append(action) or (
                            {"ok": True, "pending": True, "commandId": "c" * 24}, 202))
    return hub.app.test_client(), enqueued


def _plan(plan_id="p1", start="17:00", end="21:30", enabled=True):
    return {"id": plan_id, "enabled": enabled, "mode": "internet_window",
            "startTime": start, "endTime": end, "weekdays": ["fri"],
            "times": {"fri": [[start, end]]}}


def test_a_cached_plan_list_never_touches_the_router(monkeypatch, tmp_path):
    aggregate = _aggregate(tmp_path)
    aggregate.remember_guard_plans(ROUTER, UID, [_plan()])
    client, asked = _prepare(monkeypatch, tmp_path, aggregate)
    body = client.get(PLANS_PATH).get_json()
    assert asked == []
    assert body["cached"] is True and body["stale"] is False
    assert [plan["id"] for plan in body["plans"]] == ["p1"]


def test_a_freshly_empty_list_is_an_answer_and_not_a_miss(monkeypatch, tmp_path):
    """路由器说过「一条计划都没有」，那就别为了一次空列表去敲路由器。"""
    aggregate = _aggregate(tmp_path)
    aggregate.remember_guard_plans(ROUTER, UID, [])
    client, asked = _prepare(monkeypatch, tmp_path, aggregate)
    body = client.get(PLANS_PATH).get_json()
    assert asked == []
    assert body["plans"] == [] and body["cached"] is True


def test_a_never_read_device_still_asks_the_router(monkeypatch, tmp_path):
    client, asked = _prepare(monkeypatch, tmp_path, _aggregate(tmp_path))
    response = client.get(PLANS_PATH)
    assert asked == ["get_plans"]
    assert response.status_code == 202


def test_an_expired_snapshot_is_served_and_refreshed_once(monkeypatch, tmp_path):
    aggregate = _aggregate(tmp_path)
    aggregate.remember_guard_plans(ROUTER, UID, [_plan()])
    client, _asked = _prepare(monkeypatch, tmp_path, aggregate)
    enqueued = []
    monkeypatch.setattr(hub.CHILD_GUARD_COMMANDS, "enqueue",
                        lambda *args, **kwargs: enqueued.append(args))
    monkeypatch.setattr(hub, "CHILD_GUARD_PLANS_TTL_SECONDS", -1)
    for _ in range(3):
        body = client.get(PLANS_PATH).get_json()
        assert body["stale"] is True and body["cached"] is True
    # 30 秒的节流窗口里，三次页面刷新只补一次真读。
    assert len(enqueued) == 1
    assert enqueued[0][1] == "get_plans"


def test_runtime_blocked_state_comes_from_the_device_cache(monkeypatch, tmp_path):
    aggregate = _aggregate(tmp_path)
    aggregate.remember_guard_devices(ROUTER, [
        {"uid": UID, "macs": ["1A:9C:C5:C5:B7:BB"], "name": "Mate60",
         "blocked": True, "blockedUntilEpoch": int(time.time()) + 600}])
    client, asked = _prepare(monkeypatch, tmp_path, aggregate)
    body = client.get(RUNTIME_PATH).get_json()
    assert asked == []
    runtime = body["runtime"]
    assert runtime["blocked"] is True
    assert runtime["blockedUntilEpoch"] > int(time.time())


def test_runtime_for_an_unknown_device_falls_back_to_the_router(monkeypatch, tmp_path):
    client, asked = _prepare(monkeypatch, tmp_path, _aggregate(tmp_path))
    client.get(RUNTIME_PATH)
    assert asked == ["get_runtime_state"]


def test_a_stale_runtime_snapshot_does_not_re_ask_the_router(monkeypatch, tmp_path):
    """BE72 上 ``ubus call sniffer.user show`` 实测 8 秒必超时。

    所以 runtime 这一读过期了也只回缓存，不再补问：问了就是往队列里塞一条
    注定失败的命令（真机日志里 17:07–17:19 每一条 get_runtime_state 都是红的）。
    """
    aggregate = _aggregate(tmp_path)
    aggregate.remember_guard_devices(ROUTER, [
        {"uid": UID, "macs": ["1A:9C:C5:C5:B7:BB"], "name": "Mate60", "blocked": True,
         "blockedUntilEpoch": int(time.time()) + 600}])
    client, _asked = _prepare(monkeypatch, tmp_path, aggregate)
    enqueued = []
    monkeypatch.setattr(hub.CHILD_GUARD_COMMANDS, "enqueue",
                        lambda *args, **kwargs: enqueued.append(args))
    monkeypatch.setattr(hub, "CHILD_GUARD_RUNTIME_TTL_SECONDS", -1)
    body = client.get(RUNTIME_PATH).get_json()
    assert body["stale"] is True and body["cached"] is True
    assert body["runtime"]["blocked"] is True
    assert enqueued == []


def test_a_plan_write_invalidates_the_cached_list(monkeypatch, tmp_path):
    """新增/删除之后总览那句「生效态」必须跟着变，靠的就是同一份快照。"""
    aggregate = _aggregate(tmp_path)
    client, _asked = _prepare(monkeypatch, tmp_path, aggregate)
    hub._child_guard_remember_devices(
        "get_plans", {"ok": True, "uid": UID, "plans": [_plan("p1"), _plan("p2")]},
        ROUTER, {"uid": UID})
    assert [plan["id"] for plan in aggregate.guard_plan_snapshot(ROUTER, UID)] == ["p1", "p2"]
    hub._child_guard_remember_devices(
        "delete_plan", {"ok": True, "uid": UID, "plan": None}, ROUTER,
        {"uid": UID, "planId": "p1"})
    assert [plan["id"] for plan in aggregate.guard_plan_snapshot(ROUTER, UID)] == ["p2"]
    hub._child_guard_remember_devices(
        "update_plan", {"ok": True, "uid": UID,
                        "plan": {"id": "p2", "enabled": False}}, ROUTER,
        {"uid": UID, "planId": "p2"})
    updated = aggregate.guard_plan_snapshot(ROUTER, UID)
    assert [plan["id"] for plan in updated] == ["p2"]
    assert updated[0]["enabled"] is False and updated[0]["startTime"] == "17:00"


def test_a_mutation_without_a_snapshot_does_not_invent_one(monkeypatch, tmp_path):
    """只见过一条计划就报「一共一条」，会把三台计划说成一个禁网窗口。"""
    aggregate = _aggregate(tmp_path)
    _client, _asked = _prepare(monkeypatch, tmp_path, aggregate)
    hub._child_guard_remember_devices(
        "create_plan", {"ok": True, "uid": UID, "plan": _plan("new")}, ROUTER,
        {"uid": UID, "plan": _plan("new")})
    assert aggregate.guard_plan_snapshot(ROUTER, UID) is None


def test_the_overview_warms_the_snapshots_it_is_missing(monkeypatch, tmp_path):
    """列表页那句生效态不能永远停在 unknown：总览顺手把缺的读一次。"""
    aggregate = _aggregate(tmp_path)
    aggregate.remember_guard_devices(ROUTER, [
        {"uid": UID, "macs": ["1A:9C:C5:C5:B7:BB"], "name": "Mate60"}])
    client, _asked = _prepare(monkeypatch, tmp_path, aggregate)
    enqueued = []
    monkeypatch.setattr(hub.CHILD_GUARD_COMMANDS, "enqueue",
                        lambda *args, **kwargs: enqueued.append(args))
    body = client.get("/api/router/child-guard/overview").get_json()
    device = body["devices"][0]
    assert device["schedule"] == "unknown"
    assert [item[1] for item in enqueued] == ["get_plans"]
    # App 是 20 秒一轮的轮询，节流必须挡住「每轮都替全网设备问一次路由器」。
    for _ in range(3):
        client.get("/api/router/child-guard/overview")
    assert len(enqueued) == 1
