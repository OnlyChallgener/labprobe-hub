"""写命令异步化：路由器没 ack 时立刻交回 commandId。

同步挂 35 秒会被 Hub 前面的反向代理判成 502，用户在 App 里看到的是整页失败
（正文还是反代自己的 HTML），所以超时必须变成「还在处理」而不是错误。
"""

import hub
from child_guard_service import ChildGuardCommandStore


def _prepare(monkeypatch, tmp_path):
    monkeypatch.setattr(hub, "CHILD_GUARD_COMMANDS", ChildGuardCommandStore(tmp_path))
    monkeypatch.setattr(hub, "CHILD_GUARD_SYNC_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(hub, "notify_agent_commands_changed", lambda *a, **k: None)
    monkeypatch.setattr(hub, "_child_guard_remember_devices", lambda *a, **k: None)
    monkeypatch.setattr(hub, "check_read_token", lambda: True)
    return hub.app.test_client()


def test_unacked_command_returns_202_with_command_id(monkeypatch, tmp_path):
    client = _prepare(monkeypatch, tmp_path)
    response = client.get("/api/router/child-guard/capabilities")
    assert response.status_code == 202
    body = response.get_json()
    assert body["ok"] is True
    assert body["pending"] is True
    assert body["commandId"]


def test_command_status_replays_the_result_after_the_agent_acks(monkeypatch, tmp_path):
    client = _prepare(monkeypatch, tmp_path)
    command_id = client.get("/api/router/child-guard/capabilities").get_json()["commandId"]

    pending = client.get(f"/api/router/child-guard/command/{command_id}")
    assert pending.status_code == 200
    assert pending.get_json()["pending"] is True

    hub.CHILD_GUARD_COMMANDS.acknowledge("router", [{
        "id": command_id,
        "ok": True,
        "result": {"ok": True, "childGuard": {"available": True}},
    }])

    done = client.get(f"/api/router/child-guard/command/{command_id}")
    assert done.status_code == 200
    body = done.get_json()
    assert body["childGuard"] == {"available": True}
    assert "pending" not in body


def test_command_status_rejects_malformed_and_unknown_ids(monkeypatch, tmp_path):
    client = _prepare(monkeypatch, tmp_path)
    assert client.get("/api/router/child-guard/command/nope").status_code == 400
    assert client.get(f"/api/router/child-guard/command/{'a' * 24}").status_code == 404
