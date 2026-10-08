import copy
import json

import pytest

from child_guard_service import RouterCommandStore
from official_child_guard import OfficialGuardClient, OfficialGuardCoordinator, OfficialGuardError, mac_key

UID = "A" * 32
OLD = "B" * 32
OTHER = "C" * 32
MAC = "aa:bb:cc:dd:ee:01"


class Cloud:
    def __init__(self):
        self.rows = []
        self.adds = self.deletes = 0
        self.lost_reply = False

    def client(self, token="", binding=None):
        cloud = self

        class Client:
            def members(self):
                return copy.deepcopy(cloud.rows)

            def add(self, macs, *args):
                cloud.adds += 1
                cloud.rows.append({"staId": UID, "mergeMacs": sorted(macs)})
                if cloud.lost_reply:
                    cloud.lost_reply = False
                    raise OfficialGuardError("official_connection_pending", "pending", retryable=True)

            def remove(self, uid):
                cloud.deletes += 1
                cloud.rows = [r for r in cloud.rows if r["staId"] != uid]

        return Client()


def prepare(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    cloud = Cloud()
    store = RouterCommandStore(tmp_path)
    coordinator = OfficialGuardCoordinator(tmp_path, store, lambda r: "SN72" if r == "BE72" else "SN50",
        lambda: None, client_factory=cloud.client)
    monkeypatch.setattr(coordinator, "start", lambda: None)
    coordinator.install_binding("BE72", {"serial": "SN72", "token": "secret-test-token", "projectId": "p72"})
    return coordinator, cloud, store


def complete(coordinator, store, command_id, native):
    for _ in range(25):
        try:
            coordinator.process(command_id)
        except OfficialGuardError as error:
            assert error.retryable, error.code
        commands = store.take("BE72")
        for command in commands:
            payload = command["payload"]
            if command["action"] == "get_users":
                result = {"devices": copy.deepcopy(native)}
            elif command["action"] == "add_device":
                assert payload["officialUid"] == UID
                if not any(r["uid"] == UID for r in native):
                    native.append({"uid": UID, "macs": payload["macs"]})
                result = {"uid": UID, "macs": payload["macs"]}
            elif command["action"] == "remove_device":
                assert "macs" not in payload  # Exact UID deletion cannot remove its replacement.
                native[:] = [r for r in native if r["uid"] != payload["uid"]]
                result = {"uid": payload["uid"]}
            store.acknowledge("BE72", [{"id": command["id"], "ok": True, "result": {"ok": True, **result}}])
        status = coordinator.status(command_id)
        if not status.get("pending"):
            return status
    pytest.fail("workflow did not finish")


def test_add_reuses_official_uid_and_cleans_only_unrestricted_legacy_duplicate(monkeypatch, tmp_path):
    coordinator, cloud, store = prepare(monkeypatch, tmp_path)
    native = [{"uid": OLD, "macs": [MAC], "planCount": 0}, {"uid": OTHER, "macs": ["aa:bb:cc:dd:ee:02"]}]
    op = coordinator.submit("BE72", "add_device", {"macs": [MAC], "deviceName": "iPad"})
    result = complete(coordinator, store, op["commandId"], native)
    assert result["officialSync"]["state"] == "confirmed"
    assert result["uid"] == UID and cloud.adds == 1
    assert {r["uid"] for r in native} == {UID, OTHER}


def test_lost_cloud_post_reply_reads_before_retrying_and_survives_restart(monkeypatch, tmp_path):
    coordinator, cloud, store = prepare(monkeypatch, tmp_path)
    cloud.lost_reply = True
    cid = coordinator.submit("BE72", "add_device", {"macs": [MAC]})["commandId"]
    with pytest.raises(OfficialGuardError):
        coordinator.process(cid)
    restarted = OfficialGuardCoordinator(tmp_path, store, coordinator.identity, lambda: None, client_factory=cloud.client)
    monkeypatch.setattr(restarted, "start", lambda: None)
    result = complete(restarted, store, cid, [])
    assert result["ok"] and cloud.adds == 1
    saved = restarted.auth_path.read_text()
    assert "secret-test-token" not in saved and "SN72" not in saved


def test_remove_cloud_and_native_and_repair_stale_native_resurrection(monkeypatch, tmp_path):
    coordinator, cloud, store = prepare(monkeypatch, tmp_path)
    cloud.rows = [{"staId": UID, "mergeMacs": [mac_key(MAC)]}]
    native = [{"uid": UID, "macs": [MAC]}]
    cid = coordinator.submit("BE72", "remove_device", {"uid": UID, "macs": [MAC]})["commandId"]
    result = complete(coordinator, store, cid, native)
    assert native == cloud.rows == []
    assert isinstance(result["membershipVersion"], int) and result["membershipVersion"] > 0
    native.append({"uid": UID, "macs": [MAC]})
    coordinator.observe("BE72", native)
    assert coordinator.status(cid)["pending"]
    complete(coordinator, store, cid, native)
    assert not native and cloud.deletes == 1


def test_later_official_manual_change_is_not_overwritten(monkeypatch, tmp_path):
    coordinator, cloud, store = prepare(monkeypatch, tmp_path)
    cid = coordinator.submit("BE72", "add_device", {"macs": [MAC]})["commandId"]
    complete(coordinator, store, cid, [])
    cloud.rows = []
    coordinator.observe("BE72", [])
    coordinator.process(cid)
    assert coordinator.status(cid)["officialSync"]["state"] == "superseded"
    assert cloud.adds == 1


def test_router_identity_mismatch_and_missing_auth_never_write(monkeypatch, tmp_path):
    coordinator, cloud, store = prepare(monkeypatch, tmp_path)
    with pytest.raises(OfficialGuardError, match="授权"):
        coordinator.submit("BE50", "add_device", {"macs": [MAC]})
    cid = coordinator.submit("BE72", "add_device", {"macs": [MAC]})["commandId"]
    coordinator.identity = lambda r: "wrong-serial"
    with pytest.raises(OfficialGuardError, match="不匹配"):
        coordinator.process(cid)
    assert cloud.adds == 0 and store.take("BE72") == []


def test_add_delete_add_preserves_latest_manual_order(monkeypatch, tmp_path):
    coordinator, _, _ = prepare(monkeypatch, tmp_path)
    first = coordinator.submit("BE72", "add_device", {"macs": [MAC]})
    second = coordinator.submit("BE72", "remove_device", {"macs": [MAC], "uid": UID})
    third = coordinator.submit("BE72", "add_device", {"macs": [MAC]})
    assert len({r["commandId"] for r in (first, second, third)}) == 3
    assert coordinator.submit("BE72", "add_device", {"macs": [MAC]})["commandId"] == third["commandId"]


def test_legacy_duplicate_with_plan_is_preserved(monkeypatch, tmp_path):
    coordinator, cloud, store = prepare(monkeypatch, tmp_path)
    cloud.rows = [{"staId": UID, "mergeMacs": [mac_key(MAC)]}]
    cid = coordinator.submit("BE72", "add_device", {"macs": [MAC]})["commandId"]
    with pytest.raises(OfficialGuardError):
        coordinator.process(cid)
    cmd = store.take("BE72")[0]
    store.acknowledge("BE72", [{"id": cmd["id"], "ok": True, "result": {"devices": [{"uid": OLD, "macs": [MAC], "planCount": 1}]}}])
    with pytest.raises(OfficialGuardError) as error:
        coordinator.process(cid)
    assert error.value.code == "official_local_plan_conflict"
    assert store.take("BE72") == []


def test_official_request_uses_compact_mac_and_refuses_redirects():
    class Session:
        def request(self, method, url, **kwargs):
            assert url.startswith("https://shinyaapp.ruijie.com.cn/")
            assert kwargs["allow_redirects"] is False
            assert kwargs["json"]["staList"][0]["staMac"] == "AABBCCDDEE01"
            assert kwargs["json"]["projectId"] == "p72"
            return type("Response", (), {"status_code": 302})()
    with pytest.raises(OfficialGuardError) as error:
        OfficialGuardClient("secret", {"projectId": "p72"}, session=Session()).add({MAC}, "iPad")
    assert error.value.code == "official_request_rejected"


def test_native_add_dedup_does_not_borrow_a_legacy_or_other_cloud_uid(tmp_path):
    store = RouterCommandStore(tmp_path)
    legacy = store.enqueue("BE72", "add_device", {"macs": [MAC]})
    official = store.enqueue("BE72", "add_device", {"macs": [MAC], "officialUid": UID})
    assert official["id"] != legacy["id"]
    assert store.enqueue("BE72", "add_device", {"macs": [MAC], "officialUid": UID})["id"] == official["id"]


def test_membership_http_uses_durable_official_workflow_and_existing_poll_protocol(monkeypatch, tmp_path):
    import hub
    coordinator, cloud, store = prepare(monkeypatch, tmp_path)
    monkeypatch.setattr(hub, "OFFICIAL_CHILD_GUARD", coordinator)
    monkeypatch.setattr(hub, "primary_router_name", lambda: "BE72")
    # Even if the legacy resolver falls back to an online BE72, an explicit
    # BE50 request must retain its original identity and be rejected here.
    monkeypatch.setattr(hub, "resolve_agent_router", lambda r: "BE72")
    monkeypatch.setattr(hub, "check_app_token", lambda: True)
    monkeypatch.setattr(hub, "check_read_token", lambda: True)
    client = hub.app.test_client()
    response = client.post("/api/router/child-guard/devices?router=BE72", json={"macs": [MAC], "deviceName": "iPad"})
    assert response.status_code == 202 and store.take("BE72") == []
    cid = response.get_json()["commandId"]
    assert client.get(f"/api/router/child-guard/command/{cid}").get_json()["pending"]
    complete(coordinator, store, cid, [])
    done = client.get(f"/api/router/child-guard/command/{cid}").get_json()
    assert done["uid"] == UID and done["officialSync"]["routerConfirmed"]
    foreign = client.post("/api/router/child-guard/devices?router=BE50", json={"macs": [MAC]})
    assert foreign.status_code == 409 and not foreign.get_json()["ok"]


def test_official_binding_accepts_generic_eweb_hostname_but_rejects_another_router(monkeypatch):
    import hub
    monkeypatch.setattr(hub, "primary_router_name", lambda: "BE50")
    monkeypatch.setattr(hub, "ROUTER_DASHBOARD_CACHE", {"router": "Ruijie", "details": {"ap": {"serialNumber": "SN50"}}})
    assert hub._official_child_guard_identity("BE50") == "SN50"
    assert hub._official_child_guard_identity("BE72") == ""
    hub.ROUTER_DASHBOARD_CACHE["router"] = "BE72"
    assert hub._official_child_guard_identity("BE50") == ""
