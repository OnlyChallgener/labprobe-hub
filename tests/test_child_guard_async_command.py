"""写命令异步化：路由器没 ack 时立刻交回 commandId。

同步挂 35 秒会被 Hub 前面的反向代理判成 502，用户在 App 里看到的是整页失败
（正文还是反代自己的 HTML），所以超时必须变成「还在处理」而不是错误。
"""

import re
import time
from pathlib import Path

import hub
from child_guard_service import RouterCommandStore


def _prepare(monkeypatch, tmp_path):
    monkeypatch.setattr(hub, "CHILD_GUARD_COMMANDS", RouterCommandStore(tmp_path))
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


def test_a_pass_request_carries_the_deadline_the_hub_computed(monkeypatch, tmp_path):
    """App 只说「放行 30 分钟」：绝对截止时间由 Hub 换算，中继只收 epoch。"""
    client = _prepare(monkeypatch, tmp_path)
    monkeypatch.setattr(hub, "check_app_token", lambda: True)
    response = client.post(f"/api/router/child-guard/devices/{'A' * 32}/pass",
                           json={"preset": "30m"})
    assert response.status_code == 202
    command = hub.CHILD_GUARD_COMMANDS.take("router", 5)[0]
    assert command["action"] == "set_device_pass"
    remaining = command["payload"]["untilEpoch"] - int(time.time())
    assert 1700 <= remaining <= 1800


def test_an_unknown_pass_preset_never_reaches_the_router(monkeypatch, tmp_path):
    client = _prepare(monkeypatch, tmp_path)
    monkeypatch.setattr(hub, "check_app_token", lambda: True)
    response = client.post(f"/api/router/child-guard/devices/{'A' * 32}/pass", json={"preset": "99h"})
    assert response.status_code == 400
    assert hub.CHILD_GUARD_COMMANDS.take("router", 5) == []


def test_every_enqueued_action_is_whitelisted():
    """路由器支持一个新动作，不等于 Hub 允许入队它。

    2026-09-21 实测：``set_all_plans_enabled`` 已经写进中继的 dispatch，Hub 路由
    却在 ``enqueue`` 就被 ``unsupported action`` 抛出去，接口直接 500，App 点
    「全设备上网计划」必然失败回弹。动作白名单和路由调用点分处两个文件，靠人记住
    一定会再漏，所以扫 hub.py 的调用点来对账。
    """
    source = Path(hub.__file__).read_text(encoding="utf-8")

    def enqueued(*patterns: str) -> set:
        return {hit for pattern in patterns for hit in re.findall(pattern, source)}

    guard = enqueued(r'_child_guard_execute\(\s*"([a-z_]+)"',
                     r'CHILD_GUARD_COMMANDS\.enqueue\([^,]+,\s*"([a-z_]+)"')
    assert guard, "hub.py 里一个入队调用都没扫到，扫描式断言本身失效了"
    missing = sorted(guard - hub.CHILD_GUARD_COMMANDS.actions)
    assert not missing, f"hub.py 入队了白名单之外的儿童上网动作，接口会 500：{missing}"

    rdpi = enqueued(r'RDPI_COMMANDS\.enqueue\([^,]+,\s*"([a-z_]+)"')
    assert rdpi == {"write_db"}, f"特征库命令通道的调用点变了，核对一下：{rdpi}"
    assert not rdpi - hub.RDPI_COMMANDS.actions, "特征库动作没进白名单，接口会 500"
