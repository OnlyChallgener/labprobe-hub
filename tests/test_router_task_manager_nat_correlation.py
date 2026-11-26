from types import SimpleNamespace

import pytest
from flask import Flask

import router_task_manager_patch as task_patch
from router_core.service.blueprint import create_router_blueprint_v1
from router_native_features_patch import DEFAULT_STUN_HOST
from router_task_manager_patch import RouterTaskManager, _task


class FakeNatClient:
    def __init__(self, start, polls):
        self.start = start
        self.polls = list(polls)
        self.set_calls = []
        self.get_calls = 0

    def rpc(self, method, module, data=None):
        if method == "devSta.set":
            assert module == "nat_detector"
            self.set_calls.append(dict(data or {}))
            return self.start
        assert method == "devSta.get"
        assert module == "nat_detector"
        self.get_calls += 1
        if not self.polls:
            raise AssertionError("unexpected NAT poll")
        return self.polls.pop(0)


@pytest.fixture
def nat_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setattr(task_patch, "_now", lambda: 200)
    monkeypatch.setattr(task_patch, "POLL_SECONDS", 0)
    threads = []

    class DeferredThread:
        def __init__(self, *, target, args=(), name=None, daemon=None):
            self.target = target
            self.args = args
            self.name = name
            self.daemon = daemon
            threads.append(self)

        def start(self):
            return None

    monkeypatch.setattr(task_patch.threading, "Thread", DeferredThread)
    logger = SimpleNamespace(
        debug=lambda *args, **kwargs: None,
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )
    hub = SimpleNamespace()
    return threads, logger, hub


def make_manager(nat_runtime, client):
    _, logger, hub = nat_runtime
    return RouterTaskManager(hub, client, logger)


def run_deferred(nat_runtime, manager):
    threads, _, _ = nat_runtime
    assert len(threads) == 1
    thread = threads[0]
    thread.target(*thread.args)
    return manager.snapshot("nat")


def test_concurrent_nat_request_returns_busy_instead_of_first_task_id(nat_runtime):
    threads, logger, hub = nat_runtime
    manager = RouterTaskManager(hub, FakeNatClient({"code": 0}, []), logger)
    app = Flask(__name__)
    app.register_blueprint(create_router_blueprint_v1(
        service=SimpleNamespace(),
        check_app_token=lambda: True,
        logger=logger,
        task_manager=manager,
    ))
    client = app.test_client()

    first = client.post("/api/router/tasks/nat", json={"interface": "wan1", "mode": "5780"})
    second = client.post("/api/router/tasks/nat", json={"interface": "wan", "mode": "classic"})

    assert first.status_code == 202
    first_data = first.get_json()["data"]
    assert first_data["state"] == "queued"
    assert first_data["requestId"]
    assert first_data["taskId"]
    assert second.status_code == 409
    error = second.get_json()
    assert error["ok"] is False
    assert error["code"] == "NAT_DIAGNOSTIC_BUSY"
    assert "正在运行" in error["error"]
    assert first_data["taskId"] not in str(error)
    assert len(threads) == 1
    assert manager.client.set_calls == []


def test_stale_firmware_results_cannot_replace_current_nat_result(nat_runtime):
    client = FakeNatClient(
        {"status": "completed", "nat_type": "Old NAT", "timestamp": 199},
        [
            {"status": "running", "timestamp": 200},
            {"status": "completed", "nat_type": "Regressed Old NAT", "timestamp": 199},
            {"status": "completed", "nat_type": "Current NAT", "detected_interface": "wan1", "timestamp": 201},
        ],
    )
    manager = make_manager(nat_runtime, client)
    started = manager.start_nat({"interface": "wan1"})

    snapshot = run_deferred(nat_runtime, manager)

    assert snapshot["state"] == "succeeded"
    assert snapshot["taskId"] == started["taskId"]
    assert snapshot["result"]["nat_type"] == "Current NAT"
    assert snapshot["resultTimestamp"] == 201
    assert snapshot["firmwareResultTimestamp"] == 201
    assert snapshot["result"]["request_id"] == started["requestId"]
    assert snapshot["result"]["task_id"] == started["taskId"]
    assert "Old NAT" not in str(snapshot["result"])
    assert client.get_calls == 3


def test_wan1_result_retains_requested_and_detected_line_and_source_ipv4(nat_runtime):
    client = FakeNatClient(
        {"code": 0, "message": "detection started"},
        [{
            "status": "completed",
            "detected_interface": "wan1",
            "mode": "5780",
            "mapping_behavior": "Endpoint Independent",
            "filtering_behavior": "Address Dependent",
            "timestamp": 200,
            "log": "[2026-11-25 10:00:00] Interface: WAN1\n[2026-11-25 10:00:00] Source IP: 192.0.2.25\nDetection completed\n",
        }],
    )
    manager = make_manager(nat_runtime, client)
    started = manager.start_nat({"interface": "WAN1", "mode": "5780"})

    snapshot = run_deferred(nat_runtime, manager)
    result = snapshot["result"]

    assert snapshot["request"] == {
        "host": DEFAULT_STUN_HOST,
        "port": 3478,
        "interface": "wan1",
        "mode": "5780",
    }
    assert snapshot["requestId"] == started["requestId"]
    assert snapshot["taskId"] == started["taskId"]
    assert snapshot["requestStartedAt"] == snapshot["startedAt"] == 200
    assert snapshot["requestedInterface"] == "wan1"
    assert snapshot["detectedInterface"] == "wan1"
    assert snapshot["sourceIp"] == "192.0.2.25"
    assert snapshot["resultTimestamp"] == 200
    assert result["requested_interface"] == "wan1"
    assert result["detected_interface"] == "wan1"
    assert result["source_ip"] == result["sourceIpv4"] == "192.0.2.25"
    assert result["request_id"] == started["requestId"]
    assert result["task_id"] == started["taskId"]
    assert result["request_started_at"] == 200
    assert result["result_timestamp"] == 200


def test_legacy_default_wan_classic_payload_and_history_remain_compatible(nat_runtime):
    client = FakeNatClient(
        {"code": 0, "message": "detection started"},
        [{"status": "completed", "nat_type": "Full Cone", "timestamp": 200}],
    )
    manager = make_manager(nat_runtime, client)
    started = manager.start_nat({})

    snapshot = run_deferred(nat_runtime, manager)
    result = snapshot["result"]

    expected = {
        "host": DEFAULT_STUN_HOST,
        "port": 3478,
        "interface": "wan",
        "mode": "classic",
    }
    assert client.set_calls == [expected]
    assert snapshot["request"] == expected
    assert snapshot["state"] == "succeeded"
    assert snapshot["requestedInterface"] == "wan"
    assert snapshot["detectedInterface"] == ""
    assert snapshot["sourceIp"] == ""
    assert result["requested_host"] == DEFAULT_STUN_HOST
    assert result["requested_port"] == 3478
    assert result["requested_interface"] == "wan"
    assert result["requested_mode"] == "classic"
    assert result["mode"] == "classic"
    assert result["interface"] == "wan"
    assert result["request_id"] == started["requestId"]
    assert result["task_id"] == started["taskId"]


def test_old_nat_worker_cannot_overwrite_replacement_task(nat_runtime):
    client = FakeNatClient(
        {"status": "completed", "nat_type": "Old Worker", "timestamp": 200},
        [],
    )
    manager = make_manager(nat_runtime, client)
    started = manager.start_nat({"interface": "wan"})
    replacement = {
        **_task("nat"),
        "taskId": "nat-replacement",
        "requestId": "request-replacement",
        "state": "queued",
        "requestedInterface": "wan1",
    }
    manager.tasks["nat"] = replacement
    thread = nat_runtime[0][0]

    thread.target(*thread.args)

    assert manager.snapshot("nat")["taskId"] == "nat-replacement"
    assert manager.snapshot("nat")["requestId"] == "request-replacement"
    assert manager.snapshot("nat")["requestedInterface"] == "wan1"
    assert manager.snapshot("nat")["result"] == {}
    assert started["taskId"] != "nat-replacement"
    assert client.set_calls == []
