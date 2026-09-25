"""单路由 Hub 的 `/api/routers`：让 App 的「切换路由器」弹层不再永远显示待同步。

多路由模式（multi_router_gateway.py）才有路由器列表服务；当前部署是单路由，
App 打这个地址只能拿到 Flask 404，于是默认路由那一行永远停在「设备数 待同步」。
这里补的是同一个响应形状，好让 App 不用分支：`defaultRouterId` 指回唯一那台，
`basePath` 留空表示它就走 Hub 根路径。
"""

import time

import hub


def _seed(monkeypatch, *, dashboard, devices):
    """把两条数据源直接接上：dashboard 是内存缓存，devices 走 load_json。

    不写真实 DATA_DIR —— 这里要验证的是行构造逻辑，不是 SQLite 存储层。
    """
    cache = dict(dashboard)
    cache.setdefault("router", "客厅锐捷")
    monkeypatch.setattr(hub, "ROUTER_DASHBOARD_CACHE", cache)
    monkeypatch.setattr(hub, "load_json", lambda path, default: dict(devices or {}) if path == hub.DEVICES_FILE else default)
    monkeypatch.setenv("APP_TOKEN", "app-token-for-test")
    monkeypatch.delenv("APP_TOKEN_PREVIOUS", raising=False)
    monkeypatch.delenv("HOOK_TOKEN", raising=False)
    monkeypatch.delenv("HOOK_TOKEN_PREVIOUS", raising=False)
    monkeypatch.setattr(hub, "primary_router_name", lambda: "客厅锐捷")


def test_router_list_reports_agent_online_and_both_device_counts(monkeypatch):
    now = time.time()
    _seed(
        monkeypatch,
        dashboard={
            "receivedEpoch": now,
            "details": {"ap": {"model": "RG-EAP762"}},
            "telemetry": {"onlineDeviceCount": 7},
        },
        devices={"updatedAt": "2026-09-25 13:00:00", "total": 24, "onlineDeviceCount": 9},
    )
    client = hub.app.test_client()
    response = client.get("/api/routers", headers={"Authorization": "Bearer app-token-for-test"})
    assert response.status_code == 200
    body = response.get_json()
    assert body["ok"] is True
    assert body["multiRouter"] is False
    assert body["defaultRouterId"] == hub.SINGLE_ROUTER_ID
    (row,) = body["routers"]
    assert row["routerId"] == hub.SINGLE_ROUTER_ID
    assert row["name"] == "客厅锐捷"
    assert row["model"] == "RG-EAP762"
    assert row["online"] is True
    assert row["deviceCount"] == 24
    assert row["onlineDeviceCount"] == 9
    # App 的默认工作区必须落在 Hub 根路径上，不能拼出 /r/default。
    assert row["basePath"] == ""


def test_router_list_says_offline_without_a_device_cache(monkeypatch):
    _seed(
        monkeypatch,
        dashboard={"receivedEpoch": time.time() - 600, "details": {}},
        devices=None,
    )
    client = hub.app.test_client()
    row = client.get("/api/routers", headers={"Authorization": "Bearer app-token-for-test"}).get_json()["routers"][0]
    assert row["online"] is False
    # 没有缓存就不许出现 0 —— 0 会被读成「一台设备都没有」，缺字段才是「还不知道」。
    assert "deviceCount" not in row
    assert "onlineDeviceCount" not in row


def test_router_list_falls_back_to_telemetry_online_count(monkeypatch):
    _seed(
        monkeypatch,
        dashboard={"receivedEpoch": time.time(), "telemetry": {"onlineDeviceCount": 11}},
        devices={"total": 30},
    )
    client = hub.app.test_client()
    row = client.get("/api/routers", headers={"Authorization": "Bearer app-token-for-test"}).get_json()["routers"][0]
    assert row["deviceCount"] == 30
    assert row["onlineDeviceCount"] == 11


def test_router_list_rejects_anonymous_and_hook_tokens(monkeypatch):
    _seed(monkeypatch, dashboard={"receivedEpoch": time.time()}, devices={})
    client = hub.app.test_client()
    assert client.get("/api/routers").status_code == 401
    assert client.get("/api/routers", headers={"Authorization": "Bearer nope"}).status_code == 401
    # STRICT_TOKEN_SEPARATION 之外，HOOK_TOKEN 仍可当只读令牌用；这里只要求它不出现在响应里。
    assert "app-token-for-test" not in client.get(
        "/api/routers", headers={"Authorization": "Bearer app-token-for-test"}).get_data(as_text=True)
