"""The global plan pause is independent of individual plans and usage rows."""
import hub
from usage_aggregate import UsageAggregateStore


def store_at(path):
    store = UsageAggregateStore(path)
    store.initialize()
    return store


def test_master_cache_is_router_scoped_durable_and_rejects_old_results(tmp_path):
    store = store_at(tmp_path)
    assert store.guard_master("BE72") is None
    store.remember_guard_master("BE72", False, 4)
    store.remember_guard_master("BE50", True, 1)
    store.remember_guard_master("BE72", True, 3)
    assert store.guard_master("BE72")["masterEnabled"] is False
    assert store.guard_master("BE50")["masterEnabled"] is True
    reopened = store_at(tmp_path)
    assert reopened.guard_master("BE72")["masterRevision"] == 4


def test_global_pause_preserves_plan_cache_and_manual_device_block(tmp_path, monkeypatch):
    store = store_at(tmp_path)
    store.remember_guard_devices("be72", [{"uid":"device1","macs":["aa:bb:cc:dd:ee:ff"],"blocked":True,"blockedUntilEpoch":1}])
    plans = [{"id":"plan1","enabled":True,"times":{"fri":[["08:00","10:00"]]}}]
    store.remember_guard_plans("be72", "device1", plans)
    store.remember_guard_master("be72", False, 1)
    monkeypatch.setattr(hub, "_usage_aggregate_store", lambda: store)
    monkeypatch.setattr(hub, "_child_guard_presence_by_mac", lambda: {})
    result = hub._child_guard_overview_payload("be72")
    assert result["masterEnabled"] is False
    assert result["devices"][0]["blocked"] is True
    assert store.guard_plans("be72")["device1"] == plans


def test_global_http_routes_use_a_single_router_command_without_plan_ids(monkeypatch):
    calls = []
    monkeypatch.setattr(hub, "check_app_token", lambda: True)
    monkeypatch.setattr(hub, "check_read_token", lambda: True)
    monkeypatch.setattr(hub, "_child_guard_execute", lambda action,payload=None,**kw: calls.append((action,payload)) or {"ok":True})
    client = hub.app.test_client()
    assert client.post("/api/router/child-guard/master", json={"enabled":True,"router":"BE72"}).status_code == 200
    assert calls == [("set_master_enabled", {"enabled":True,"router":"BE72"})]
    assert client.post("/api/router/child-guard/master", json={"enabled":"true"}).status_code == 400
    assert client.get("/api/router/child-guard/master").status_code == 200
    assert calls[-1][0] == "get_master_state"


def test_missing_master_warms_one_independent_read_and_never_claims_off(tmp_path, monkeypatch):
    store = store_at(tmp_path)
    calls = []
    monkeypatch.setattr(hub, "_usage_aggregate_store", lambda: store)
    monkeypatch.setattr(hub, "_child_guard_presence_by_mac", lambda: {})
    monkeypatch.setattr(hub, "_child_guard_refresh_async", lambda key,action,payload: calls.append((key,action)))
    result = hub._child_guard_overview_payload("be72")
    assert "masterEnabled" not in result
    assert calls == [("be72", "get_master_state")]
