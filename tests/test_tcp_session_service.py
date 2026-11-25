import json
from pathlib import Path

import pytest
from flask import Flask

import tcp_session_service as module
from tcp_session_service import TcpSessionService, create_tcp_session_blueprint


class FakeHub:
    def __init__(self, root: Path):
        self.DATA_DIR = root
        self.app = Flask(__name__)
        self.save_counts = {}
        self.presence = {}

    @staticmethod
    def primary_router_name():
        return "Router"

    def agent_presence_snapshot(self, router=""):
        return self.presence(router) if callable(self.presence) else self.presence

    @staticmethod
    def load_json(path, default):
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default

    def save_json(self, path, value):
        self.save_counts[str(path)] = self.save_counts.get(str(path), 0) + 1
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def check_read_token():
        return True

    @staticmethod
    def check_app_token():
        return True

    @staticmethod
    def check_hook_token():
        return True


def build(tmp_path):
    hub = FakeHub(tmp_path)
    service = TcpSessionService(hub)
    hub.app.register_blueprint(create_tcp_session_blueprint(hub, service))
    return hub.app.test_client(), service


def test_history_deletion_survives_late_status_and_restart(tmp_path):
    client, service = build(tmp_path)
    row = {"id": "tcp-delete", "state": "completed", "createdEpoch": 1, "target": {"host": "example.com", "port": 443}}
    service._save_state(row)
    response = client.post("/api/tcp-session-test/history/remove", json={"taskId": row["id"]})
    assert response.status_code == 200 and response.json["history"] == []
    service._save_state({**row, "updatedEpoch": 2})
    assert service.history() == []
    assert TcpSessionService(service.hub).history() == []
    assert service.snapshot()["id"] == row["id"]
    assert client.post("/api/tcp-session-test/history/remove", json={}).status_code == 400


def test_multiple_targets_are_normalized_and_bounded():
    value = TcpSessionService._config(start_payload(host=" EXAMPLE.com，192.0.2.1; [2001:db8::1]\nexample.com "))
    assert value["host"] == "example.com,192.0.2.1,2001:db8::1"
    for host in [",".join(f"host{i}.example" for i in range(9)), "https://example.com", "example.com/path", "example.com:443"]:
        with pytest.raises(ValueError):
            TcpSessionService._config(start_payload(host=host))


def start_payload(**overrides):
    return {
        "host": "example.com",
        "port": 443,
        "family": "both",
        "targetConnections": 65535,
        "cps": 500,
        "connectTimeoutMs": 1500,
        "maxDurationSeconds": 180,
        **overrides,
    }


def test_result_history_keeps_five_terminal_tasks_with_target_after_restart(tmp_path, monkeypatch):
    client, service = build(tmp_path)
    latest = None
    for i in range(7):
        monkeypatch.setattr(module, '_now', lambda i=i: 1000 + i)
        task = client.post('/api/tcp-session-test/start', json=start_payload(host=f'host{i}.example')).get_json()['task']
        assert all(row['id'] != task['id'] for row in service.history()), 'queued tasks are not results'
        latest = {'id': task['id'], 'state': 'completed', 'ipv4': {'success': 10, 'peak': 10}, 'resourcesReleased': True}
        assert service.accept_status(latest)
    history = client.get('/api/tcp-session-test').get_json()['history']
    assert [r['target']['host'] for r in history] == [f'host{i}.example' for i in range(6, 1, -1)]
    assert all('config' not in row for row in history)
    assert service.accept_status({**latest, 'ipv4': {'success': 12, 'peak': 12}})
    restarted = TcpSessionService(FakeHub(tmp_path))
    assert len(restarted.history()) == 5
    assert restarted.history()[0]['ipv4']['peak'] == 12
    assert len({r['id'] for r in restarted.history()}) == 5


def test_result_histories_are_isolated_by_router_data_directory(tmp_path):
    _, first = build(tmp_path / 'be72')
    _, second = build(tmp_path / 'be50')
    task = first.start(start_payload())
    first.accept_status({'id': task['id'], 'state': 'stopped', 'resourcesReleased': True})
    assert len(first.history()) == 1
    assert second.history() == []


def test_start_is_bounded_and_rejects_duplicate(tmp_path):
    client, _ = build(tmp_path)
    task = client.post("/api/tcp-session-test/start", json=start_payload(targetConnections=999999, cps=99999, extremeMode=True)).get_json()["task"]

    assert task["state"] == "queued"
    assert task["config"]["targetConnections"] == 131072
    assert task["config"]["cps"] == 10000
    assert task["config"]["extremeMode"] is True
    duplicate = client.post("/api/tcp-session-test/start", json=start_payload())
    assert duplicate.status_code == 409
    assert "正在运行" in duplicate.get_json()["error"]


def test_agent_command_ack_and_status_are_short_lived_snapshots(tmp_path):
    client, _ = build(tmp_path)
    task = client.post("/api/tcp-session-test/start", json=start_payload()).get_json()["task"]
    commands = client.get("/api/router/tcp-session-test/commands?router=Router").get_json()["commands"]
    assert [row["action"] for row in commands] == ["start"]

    command = commands[0]
    ack = client.post("/api/router/tcp-session-test/ack", json={"acks": [{"id": command["id"], "ok": True, "result": {"ok": True}}]})
    assert ack.get_json()["acknowledged"] == 1
    assert client.get("/api/tcp-session-test").get_json()["task"]["state"] == "accepted"
    stored_commands = json.loads((tmp_path / "tcp_session_commands.json").read_text(encoding="utf-8"))["commands"]
    assert stored_commands[0]["payload"] == {"taskId": task["id"]}

    status = {
        "id": task["id"],
        "state": "running",
        "status": "IPv4 建连中",
        "ipv4": {"current": 1200, "peak": 1200, "success": 1200, "failure": 3, "cps": 480, "elapsedMs": 3000},
        "conntrackPeak": 1710,
        "cpuPeak": 38.5,
        "memoryMinAvailableMb": 604,
        "resourcesReleased": False,
        "releaseStatus": "测试中",
        "logs": ["开始测试", "IPv4 活动连接 1200"],
    }
    assert client.post("/api/router/tcp-session-test/status", json=status).get_json()["accepted"] is True
    current = client.get("/api/tcp-session-test").get_json()["task"]
    assert current["ipv4"]["current"] == 1200
    assert current["conntrackPeak"] == 1710
    assert current["cpuPeak"] == 38.5
    assert current["memoryMinAvailableMb"] == 604
    assert current["resourcesReleased"] is False
    assert current["logs"][-1] == "IPv4 活动连接 1200"

    completed = {**status, "state": "completed", "resourcesReleased": True, "releaseStatus": "资源已释放"}
    assert client.post("/api/router/tcp-session-test/status", json=completed).get_json()["accepted"] is True
    assert "config" not in client.get("/api/tcp-session-test").get_json()["task"]


def test_stop_is_idempotent_and_queues_only_one_stop(tmp_path):
    client, _ = build(tmp_path)
    task = client.post("/api/tcp-session-test/start", json=start_payload()).get_json()["task"]
    first = client.post("/api/tcp-session-test/stop", json={"taskId": task["id"]})
    second = client.post("/api/tcp-session-test/stop", json={"taskId": task["id"]})
    assert first.get_json()["task"]["state"] == "stop_requested"
    assert second.get_json()["task"]["state"] == "stop_requested"
    commands = client.get("/api/router/tcp-session-test/commands?router=Router&limit=10").get_json()["commands"]
    assert [row["action"] for row in commands].count("stop") == 1


def test_missing_fields_and_old_agent_status_do_not_replace_current_task(tmp_path):
    client, _ = build(tmp_path)
    task = client.post("/api/tcp-session-test/start", json=start_payload()).get_json()["task"]
    assert client.post("/api/router/tcp-session-test/status", json={}).get_json()["accepted"] is False
    assert client.post("/api/router/tcp-session-test/status", json={"id": "old", "state": "completed"}).get_json()["accepted"] is False
    assert client.get("/api/tcp-session-test").get_json()["task"]["id"] == task["id"]


def test_running_telemetry_stays_in_memory_between_state_transitions(tmp_path):
    _, service = build(tmp_path)
    task = service.start(start_payload())
    status_path = str(tmp_path / "tcp_session_task.json")
    service.accept_status({"id": task["id"], "state": "running", "ipv4": {"current": 1}})
    writes_after_transition = service.hub.save_counts[status_path]

    service.accept_status({"id": task["id"], "state": "running", "ipv4": {"current": 2}})

    assert service.snapshot()["ipv4"]["current"] == 2
    assert service.hub.save_counts[status_path] == writes_after_transition


def test_queue_and_running_status_have_bounded_timeout(tmp_path, monkeypatch):
    now = 1_000
    monkeypatch.setattr(module, "_now", lambda: now)
    _, service = build(tmp_path)
    queued = service.start(start_payload())
    now += module.QUEUE_TIMEOUT_SECONDS + 1
    assert service.snapshot()["state"] == "interrupted"

    running = service.start(start_payload())
    assert service.accept_status({"id": running["id"], "state": "running", "status": "测试中"}) is True
    now += module.STATUS_STALE_SECONDS + 1
    stale = service.snapshot()
    assert stale["state"] == "interrupted"
    assert "超时" in stale["finishReason"]


def test_invalid_host_and_family_return_chinese_errors(tmp_path):
    client, _ = build(tmp_path)
    invalid_host = client.post("/api/tcp-session-test/start", json=start_payload(host="https://example.com"))
    invalid_family = client.post("/api/tcp-session-test/start", json=start_payload(family="udp"))
    assert invalid_host.status_code == 400
    assert "目标主机" in invalid_host.get_json()["error"]
    assert invalid_family.status_code == 400
    assert "IPv4" in invalid_family.get_json()["error"]


@pytest.mark.parametrize("wan_payload", [{}, {"wanId": ""}, {"wanId": "   "}])
def test_legacy_blank_wan_keeps_default_behavior_without_presence(tmp_path, wan_payload):
    client, service = build(tmp_path)
    response = client.post("/api/tcp-session-test/start", json=start_payload(**wan_payload))
    assert response.status_code == 200
    task = response.get_json()["task"]
    assert task["wanId"] == ""
    assert task["config"]["wanId"] == ""
    commands = client.get("/api/router/tcp-session-test/commands?router=Router").get_json()["commands"]
    assert commands[0]["wanId"] == ""
    assert commands[0]["payload"]["wanId"] == ""
    assert service.accept_status({"id": task["id"], "state": "running"}) is True


@pytest.mark.parametrize("capability", ["relay.perWanTcpSession", "relay.multiWan"])
def test_explicit_wan1_is_accepted_with_advertised_capability(tmp_path, capability):
    client, service = build(tmp_path)
    service.hub.presence = {"agentOnline": True, "agentCapabilities": [capability]}
    response = client.post("/api/tcp-session-test/start", json=start_payload(wanId=" WAN1 "))
    assert response.status_code == 200
    task = response.get_json()["task"]
    assert task["router"] == "Router"
    assert task["wanId"] == "wan1"
    assert task["config"]["wanId"] == "wan1"
    command = client.get("/api/router/tcp-session-test/commands?router=Router").get_json()["commands"][0]
    assert command["router"] == "Router"
    assert command["wanId"] == "wan1"
    assert command["payload"]["taskId"] == task["id"]
    assert command["payload"]["router"] == "Router"
    assert command["payload"]["wanId"] == "wan1"
    assert command["payload"]["config"]["wanId"] == "wan1"


@pytest.mark.parametrize("presence", [
    {},
    {"agentOnline": True, "agentCapabilities": ["relay.wanTelemetry"]},
    {"agentOnline": False, "agentCapabilities": ["relay.perWanTcpSession"]},
    {"agentOnline": True, "agentCapabilities": "relay.perWanTcpSession"},
])
def test_explicit_wan1_is_rejected_before_queueing_without_online_capability(tmp_path, presence):
    client, service = build(tmp_path)
    service.hub.presence = presence
    response = client.post("/api/tcp-session-test/start", json=start_payload(wanId="wan1"))
    assert response.status_code == 409
    assert response.get_json()["error"] == "RELAY_MULTI_WAN_UNSUPPORTED"
    assert service.snapshot() == {}
    assert not (tmp_path / "tcp_session_task.json").exists()
    assert not (tmp_path / "tcp_session_commands.json").exists()


def test_explicit_wan_status_and_ack_mismatches_do_not_mutate_state(tmp_path):
    client, service = build(tmp_path)
    service.hub.presence = {"agentOnline": True, "agentCapabilities": ["relay.perWanTcpSession"]}
    task = client.post("/api/tcp-session-test/start", json=start_payload(wanId="wan1")).get_json()["task"]
    command = client.get("/api/router/tcp-session-test/commands?router=Router").get_json()["commands"][0]
    before = service._state()

    assert client.post("/api/router/tcp-session-test/status", json={
        "id": task["id"], "router": "Router", "wanId": "wan2", "state": "completed",
    }).get_json()["accepted"] is False
    assert client.post("/api/router/tcp-session-test/status", json={
        "id": task["id"], "router": "Other", "wanId": "wan1", "state": "completed",
    }).get_json()["accepted"] is False
    assert client.post("/api/router/tcp-session-test/status", json={
        "id": task["id"], "router": "Router", "state": "completed",
    }).get_json()["accepted"] is False
    assert client.post("/api/router/tcp-session-test/status", json={
        "id": "other-task", "router": "Router", "wanId": "wan1", "state": "completed",
    }).get_json()["accepted"] is False
    assert client.post("/api/router/tcp-session-test/status", json={
        "id": task["id"], "taskId": "other-task", "router": "Router", "wanId": "wan1", "state": "completed",
    }).get_json()["accepted"] is False
    assert client.post("/api/router/tcp-session-test/status", json={
        "id": task["id"], "router": "Router", "wanId": "bad wan", "state": "completed",
    }).get_json()["accepted"] is False
    assert service._state() == before

    ack = {"id": command["id"], "taskId": task["id"], "router": "Router", "wanId": "wan2", "ok": True}
    assert client.post("/api/router/tcp-session-test/ack", json={"acks": [ack]}).get_json()["acknowledged"] == 0
    for mismatch in [
        {**ack, "taskId": "other-task"},
        {**ack, "router": "Other"},
        {key: value for key, value in ack.items() if key != "wanId"},
        {key: value for key, value in ack.items() if key != "router"},
    ]:
        assert client.post("/api/router/tcp-session-test/ack", json={"acks": [mismatch]}).get_json()["acknowledged"] == 0
        assert service._state() == before
    stored = json.loads((tmp_path / "tcp_session_commands.json").read_text(encoding="utf-8"))["commands"]
    assert stored[0]["status"] == "delivered"

    ack["wanId"] = "wan1"
    assert client.post("/api/router/tcp-session-test/ack", json={"acks": [ack]}).get_json()["acknowledged"] == 1
    assert service.snapshot(wan_id="wan1")["state"] == "accepted"


def test_active_tasks_are_scoped_by_router_and_wan_with_legacy_single_active(tmp_path):
    client, service = build(tmp_path)
    service.hub.presence = {"agentOnline": True, "agentCapabilities": ["relay.perWanTcpSession"]}
    wan1 = client.post("/api/tcp-session-test/start", json=start_payload(wanId="wan1")).get_json()["task"]
    wan2 = client.post("/api/tcp-session-test/start", json=start_payload(wanId="wan2")).get_json()["task"]
    assert wan1["id"] != wan2["id"]
    assert service.snapshot(wan_id="wan1")["id"] == wan1["id"]
    assert service.snapshot(wan_id="wan2")["id"] == wan2["id"]
    assert client.post("/api/tcp-session-test/start", json=start_payload(wanId="wan1")).status_code == 409
    assert client.post("/api/tcp-session-test/start", json=start_payload()).status_code == 409

    other = client.post("/api/tcp-session-test/start", json=start_payload(router="Other", wanId="wan1"))
    assert other.status_code == 200
    assert service.snapshot(router="Other", wan_id="wan1")["id"] == other.get_json()["task"]["id"]

    assert service.accept_status({"id": wan1["id"], "router": "Router", "wanId": "wan1", "state": "completed", "resourcesReleased": True})
    assert service.snapshot(wan_id="wan1")["state"] == "completed"
    assert service.snapshot(wan_id="wan2")["state"] == "queued"


def test_legacy_active_task_still_blocks_explicit_wan_start(tmp_path):
    client, service = build(tmp_path)
    service.hub.presence = {"agentOnline": True, "agentCapabilities": ["relay.perWanTcpSession"]}
    assert client.post("/api/tcp-session-test/start", json=start_payload()).status_code == 200
    response = client.post("/api/tcp-session-test/start", json=start_payload(wanId="wan1"))
    assert response.status_code == 409
    assert "正在运行" in response.get_json()["error"]
    assert service.snapshot()["wanId"] == ""


def test_per_wan_history_preserves_wan_identity_and_five_item_limit_after_restart(tmp_path):
    client, service = build(tmp_path)
    service.hub.presence = {"agentOnline": True, "agentCapabilities": ["relay.perWanTcpSession"]}
    expected = []
    for index in range(7):
        wan_id = "wan1" if index % 2 == 0 else ""
        payload = start_payload(host=f"host{index}.example", wanId=wan_id)
        task = client.post("/api/tcp-session-test/start", json=payload).get_json()["task"]
        status = {"id": task["id"], "router": "Router", "state": "completed", "resourcesReleased": True}
        if wan_id:
            status["wanId"] = wan_id
        assert service.accept_status(status)
        expected.insert(0, (task["id"], wan_id))

    history = client.get("/api/tcp-session-test").get_json()["history"]
    assert [(row["id"], row["wanId"]) for row in history] == expected[:5]
    assert all("config" not in row for row in history)
    restarted = TcpSessionService(service.hub)
    assert [(row["id"], row["wanId"]) for row in restarted.history()] == expected[:5]
