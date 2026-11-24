import json
from pathlib import Path

from flask import Flask

import tcp_session_service as module
from tcp_session_service import TcpSessionService, create_tcp_session_blueprint


class FakeHub:
    def __init__(self, root: Path):
        self.DATA_DIR = root
        self.app = Flask(__name__)
        self.save_counts = {}

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
    import pytest
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
