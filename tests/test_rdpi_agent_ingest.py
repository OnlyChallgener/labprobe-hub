"""特征库读写全部走 agent 出站通道，Hub 不再反向 SSH 进路由器。

回归的是 2026-09-20/21 的现场：`rdpi_signature_service.py` 把路由器公网 IP 和 SSH
端口写成默认值，路由器一重拨两个都变，`GET /api/router/rdpi/signatures` 直接报
"Unable to connect to port 13512 on 111.23.167.108"，卡片四个徽章全空。
"""

import json
import time
from pathlib import Path

import pytest


APPS = [
    {"index": "18-4-1-14", "name": "支付宝", "rules": []},
    {"index": "7-1-2-0", "name": "微信", "rules": []},
    {"index": "9-207-1-0", "name": "饿了么", "rules": []},
]
DB_TEXT = json.dumps({"apps": APPS, "version": "2.1"}, ensure_ascii=False, indent=2)


@pytest.fixture()
def hub_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    for module in ("hub", "hub_entry"):
        import sys
        sys.modules.pop(module, None)
    import hub as hub_module
    hub_module.DATA_DIR = tmp_path
    hub_module.RDPI_ROUTER_DB_FILE = tmp_path / "rdpi_router_db.json"
    hub_module.RDPI_COMMANDS = hub_module.RouterCommandStore(
        tmp_path, "rdpi_commands.json", hub_module.RDPI_COMMANDS.actions)
    hub_module.app.config["TESTING"] = True
    return hub_module.app.test_client()


def _tokens(hub_module, monkeypatch):
    monkeypatch.setattr(hub_module, "check_hook_token", lambda: True)
    monkeypatch.setattr(hub_module, "check_app_token", lambda: True)
    monkeypatch.setattr(hub_module, "check_read_token", lambda: True)


def _push(hub_client, hub_module, text=DB_TEXT, fingerprint=1234):
    response = hub_client.post("/api/router/rdpi/ingest", json={
        "router": "BE72", "dbText": text, "apps": APPS,
        "fingerprint": fingerprint, "readAtEpoch": int(time.time()),
    }, headers={"X-LabProbe-Token": "hooktok"})
    assert response.status_code == 202
    return response


def _ack_when_taken(hub_module, captured, result):
    """模拟中继这一轮就把命令领走：取出来记下，再 ack。"""
    real_wait = hub_module.RDPI_COMMANDS.wait

    def fake_wait(command_id, timeout_seconds=0.0):
        taken = hub_module.RDPI_COMMANDS.take("router", 5)
        captured.extend(taken)
        hub_module.RDPI_COMMANDS.acknowledge("router", [
            {"id": item["id"], "ok": bool(result.get("ok")), "result": result} for item in taken
        ])
        return real_wait(command_id, timeout_seconds)

    hub_module.RDPI_COMMANDS.wait = fake_wait


def test_hub_source_no_longer_imports_paramiko():
    import rdpi_signature_service
    source = Path(rdpi_signature_service.__file__).read_text(encoding="utf-8")
    assert "import paramiko" not in source
    assert "SSHClient" not in source


def test_agent_pushed_copy_answers_the_card(hub_client, monkeypatch):
    import hub as hub_module
    _tokens(hub_module, monkeypatch)
    _push(hub_client, hub_module)

    body = hub_client.get("/api/router/rdpi/signatures").get_json()
    assert body["ok"] is True
    assert body["source"] == "agent"
    assert body["totalCount"] == 3
    # 9- 段是我们自己加的，其余算官方条目。
    assert body["customCount"] == 1
    assert [a["name"] for a in body["customSignatures"]] == ["饿了么"]


def test_a_stale_copy_is_not_used_as_live_data(hub_client, monkeypatch):
    """过期副本不能当实况用 —— 读接口宁可说拿不到。"""
    import hub as hub_module
    _tokens(hub_module, monkeypatch)
    hub_module.RDPI_ROUTER_DB_FILE.write_text(json.dumps({
        "apps": APPS,
        "receivedAt": int(time.time()) - hub_module.RDPI_SNAPSHOT_MAX_AGE_SECONDS - 60,
    }), encoding="utf-8")
    assert hub_module._rdpi_router_snapshot() is None
    body = hub_client.get("/api/router/rdpi/signatures").get_json()
    assert body["errorCode"] == "library_unavailable"


def test_an_empty_push_is_refused(hub_client, monkeypatch):
    import hub as hub_module
    _tokens(hub_module, monkeypatch)
    bad = hub_client.post("/api/router/rdpi/ingest", json={"apps": []},
                          headers={"X-LabProbe-Token": "hooktok"})
    assert bad.status_code == 400


def test_write_goes_back_as_a_command_carrying_the_verbatim_library(hub_client, monkeypatch):
    """合并必须在 Hub，落盘必须在中继，而且顶层 `version` 不能丢。"""
    import hub as hub_module
    _tokens(hub_module, monkeypatch)
    _push(hub_client, hub_module)
    captured = []
    _ack_when_taken(hub_module, captured, {"ok": True, "fingerprint": 9999,
                                           "message": "已写入路由器并触发热重载"})

    response = hub_client.post("/api/router/rdpi/signatures", json={
        "index": "999-1-1-0", "name": "自定义", "rules": [{"protocol": "host", "hosts": ["b.com"]}],
    })
    assert response.status_code == 200
    assert response.get_json()["totalCount"] == 4

    assert [item["action"] for item in captured] == ["write_db"]
    payload = captured[0]["payload"]
    assert payload["expectedFingerprint"] == 1234
    written = json.loads(payload["dbText"])
    assert written["version"] == "2.1"
    assert [app["name"] for app in written["apps"]][-1] == "自定义"

    # 写成功后卡片立刻反映新内容，不用等中继下一轮推送。
    body = hub_client.get("/api/router/rdpi/signatures").get_json()
    assert body["totalCount"] == 4
    assert body["customCount"] == 2


def test_the_router_refusal_reaches_the_caller(hub_client, monkeypatch):
    """中继按指纹拒收旧副本时，界面上必须看到同一句话，而不是假成功。"""
    import hub as hub_module
    _tokens(hub_module, monkeypatch)
    _push(hub_client, hub_module)
    _ack_when_taken(hub_module, [], {
        "ok": False, "errorCode": "stale_library",
        "error": "路由器上的特征库在这份副本之后又被改过，本次写入已取消，请重新点一次",
    })

    response = hub_client.post("/api/router/rdpi/signatures", json={
        "index": "999-1-1-0", "name": "自定义", "rules": [{"protocol": "host", "hosts": ["b.com"]}],
    })
    assert response.status_code == 409
    body = response.get_json()
    assert body["ok"] is False
    assert body["errorCode"] == "stale_library"


def test_an_old_relay_copy_can_be_read_but_not_written(hub_client, monkeypatch):
    """0.2.63 只推 apps：够算数字，不够整库写回。"""
    import hub as hub_module
    _tokens(hub_module, monkeypatch)
    hub_client.post("/api/router/rdpi/ingest", json={
        "router": "BE72", "apps": APPS, "fingerprint": 1234, "readAtEpoch": int(time.time()),
    }, headers={"X-LabProbe-Token": "hooktok"})
    assert hub_client.get("/api/router/rdpi/signatures").get_json()["totalCount"] == 3

    response = hub_client.post("/api/router/rdpi/signatures", json={
        "index": "999-1-1-0", "name": "自定义", "rules": [{"protocol": "host", "hosts": ["b.com"]}],
    })
    assert response.get_json()["errorCode"] == "relay_too_old"


def test_a_delete_that_matches_nothing_sends_no_command(hub_client, monkeypatch):
    import hub as hub_module
    _tokens(hub_module, monkeypatch)
    _push(hub_client, hub_module)
    captured = []
    _ack_when_taken(hub_module, captured, {"ok": True})

    body = hub_client.delete("/api/router/rdpi/signatures/999-9-9-9").get_json()
    assert body["ok"] is False
    assert captured == []
