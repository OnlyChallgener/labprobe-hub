"""特征库副本走 agent 出站推送，不再靠 Hub 反向 SSH 进路由器。

回归的是 2026-09-20 的现场：`rdpi_signature_service.py:25-26` 把路由器公网 IP 和
SSH 端口写成默认值，路由器一重拨两个都变，`GET /api/router/rdpi/signatures` 直接
报 "Unable to connect to port 13512 on 111.23.167.108"，卡片四个徽章全空。
"""

import json
import time

import pytest


APPS = [
    {"index": "18-4-1-14", "name": "支付宝", "rules": []},
    {"index": "7-1-2-0", "name": "微信", "rules": []},
    {"index": "9-207-1-0", "name": "饿了么", "rules": []},
]


@pytest.fixture()
def hub_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    for module in ("hub", "hub_entry"):
        import sys
        sys.modules.pop(module, None)
    import hub as hub_module
    hub_module.DATA_DIR = tmp_path
    hub_module.RDPI_ROUTER_DB_FILE = tmp_path / "rdpi_router_db.json"
    hub_module.app.config["TESTING"] = True
    return hub_module.app.test_client()


def _headers(token="hooktok"):
    return {"X-LabProbe-Token": token}


def test_agent_pushed_copy_answers_the_card(hub_client, monkeypatch):
    import hub as hub_module
    monkeypatch.setattr(hub_module, "check_hook_token", lambda: True)
    monkeypatch.setattr(hub_module, "check_app_token", lambda: True)
    # SSH 那条路必须彻底断：证明卡片不再依赖它。
    def explode():
        raise RuntimeError("Unable to connect to port 13512 on 111.23.167.108")
    import rdpi_signature_service
    monkeypatch.setattr(rdpi_signature_service, "get_rdpi_signatures_summary", explode)

    pushed = hub_client.post("/api/router/rdpi/ingest", json={
        "router": "BE72", "apps": APPS, "fingerprint": 1234, "readAtEpoch": int(time.time()),
    }, headers=_headers())
    assert pushed.status_code == 202

    body = hub_client.get("/api/router/rdpi/signatures").get_json()
    assert body["ok"] is True
    assert body["source"] == "agent"
    assert body["totalCount"] == 3
    # 9- 段是我们自己加的，其余算官方条目。
    assert body["customCount"] == 1
    assert [a["name"] for a in body["customSignatures"]] == ["饿了么"]


def test_a_stale_copy_falls_back_instead_of_lying(hub_client, monkeypatch):
    """过期副本不能当实况用 —— 宁可回落到别的读法。"""
    import hub as hub_module
    hub_module.RDPI_ROUTER_DB_FILE.write_text(json.dumps({
        "apps": APPS,
        "receivedAt": int(time.time()) - hub_module.RDPI_SNAPSHOT_MAX_AGE_SECONDS - 60,
    }), encoding="utf-8")
    assert hub_module._rdpi_router_snapshot() is None


def test_an_empty_push_is_refused(hub_client, monkeypatch):
    import hub as hub_module
    monkeypatch.setattr(hub_module, "check_hook_token", lambda: True)
    bad = hub_client.post("/api/router/rdpi/ingest", json={"apps": []}, headers=_headers())
    assert bad.status_code == 400
