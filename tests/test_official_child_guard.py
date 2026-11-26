import copy
import json
import threading
import time

import pytest

from assistant.security import encrypt_secret
from child_guard_service import RouterCommandStore
from official_child_guard import (
    OfficialGuardClient, OfficialGuardCoordinator, OfficialGuardError,
    mac_key, reject_credentials,
)

UID = "A" * 32
OLD = "B" * 32
OTHER = "C" * 32
MAC = "aa:bb:cc:dd:ee:01"


def binding(**changes):
    value = {"serial": "SN72", "projectId": "p72", "projectName": "Home",
             "createTime": "2026-01-01 00:00:00", "meshSerials": ["SN72"],
             "account": "owner@example.com", "expireTime": int(time.time() * 1000) + 60000,
             "verifiedAt": time.time(), "bindingVersion": 1}
    value.update(changes)
    return value


def payload(action="add_device", **changes):
    value = {"macs": [MAC], "cloudConfirmed": True, "officialUid": UID,
             "operationId": "op-1", "bindingVersion": 1}
    if action == "remove_device":
        value["uid"] = UID
    value.update(changes)
    return value


def prepare(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    store = RouterCommandStore(tmp_path)

    def forbidden_factory(*_args, **_kwargs):
        pytest.fail("production coordinator must never instantiate the cloud client")

    coordinator = OfficialGuardCoordinator(tmp_path, store, lambda r: "SN72" if r == "BE72" else "SN50",
        lambda: None, client_factory=forbidden_factory)
    monkeypatch.setattr(coordinator, "start", lambda: None)
    coordinator.install_binding("BE72", binding())
    return coordinator, store


def complete(coordinator, store, command_id, native):
    for _ in range(30):
        try:
            coordinator.process(command_id)
        except OfficialGuardError as error:
            assert error.retryable, error.code
        for command in store.take("BE72"):
            data = command["payload"]
            if command["action"] == "get_users":
                result = {"devices": copy.deepcopy(native)}
            elif command["action"] == "add_device":
                assert data["officialUid"] == UID
                native[:] = [row for row in native if row["uid"] != UID]
                native.append({"uid": UID, "macs": data["macs"]})
                result = {"uid": UID, "macs": data["macs"]}
            elif command["action"] == "remove_device":
                assert "macs" not in data
                native[:] = [row for row in native if row["uid"] != data["uid"]]
                result = {"uid": data["uid"]}
            else:
                pytest.fail(f"unexpected native action {command['action']}")
            store.acknowledge("BE72", [{"id": command["id"], "ok": True,
                "result": {"ok": True, "membershipVersion": 9, **result}}])
        status = coordinator.status(command_id)
        if not status.get("pending"):
            return status
    pytest.fail("native workflow did not finish")


def test_app_confirmed_add_uses_official_uid_without_any_cloud_call(monkeypatch, tmp_path):
    coordinator, store = prepare(monkeypatch, tmp_path)
    native = [{"uid": OLD, "macs": [MAC], "planCount": 0}, {"uid": OTHER, "macs": ["aa:bb:cc:dd:ee:02"]}]
    op = coordinator.submit("BE72", "add_device", payload())
    assert op["officialSync"] == {"state": "router", "cloudConfirmed": True, "routerConfirmed": False}
    result = complete(coordinator, store, op["commandId"], native)
    assert result["uid"] == UID and result["membershipVersion"] > 0
    assert result["officialSync"] == {"state": "confirmed", "cloudConfirmed": True, "routerConfirmed": True}
    assert {row["uid"] for row in native} == {UID, OTHER}
    assert not hasattr(coordinator, "cloud")


def test_remove_uses_only_app_confirmed_uid_and_repairs_native_resurrection(monkeypatch, tmp_path):
    coordinator, store = prepare(monkeypatch, tmp_path)
    native = [{"uid": UID, "macs": [MAC]}]
    cid = coordinator.submit("BE72", "remove_device", payload("remove_device"))["commandId"]
    assert complete(coordinator, store, cid, native)["removedUids"] == [UID]
    assert native == []
    native.append({"uid": UID, "macs": [MAC]})
    coordinator.observe("BE72", native)
    assert coordinator.status(cid)["pending"]
    complete(coordinator, store, cid, native)
    assert native == []


def test_observe_does_not_reverse_a_later_app_confirmed_operation(monkeypatch, tmp_path):
    coordinator, store = prepare(monkeypatch, tmp_path)
    first = coordinator.submit("BE72", "add_device", payload())["commandId"]
    complete(coordinator, store, first, [])
    second = coordinator.submit("BE72", "remove_device", payload("remove_device", operationId="op-2"))["commandId"]
    complete(coordinator, store, second, [{"uid": UID, "macs": [MAC]}])
    coordinator.observe("BE72", [{"uid": UID, "macs": [MAC]}])
    assert coordinator.status(first)["officialSync"]["state"] == "confirmed"
    assert coordinator.status(second)["pending"]
    complete(coordinator, store, second, [])
    assert coordinator.status(second)["officialSync"]["state"] == "confirmed"


@pytest.mark.parametrize("field", ["password", "token", "refreshToken", "Authorization", "nested"])
def test_binding_and_submit_reject_credentials_at_any_depth(monkeypatch, tmp_path, field):
    coordinator, store = prepare(monkeypatch, tmp_path)
    bad = {"token": "secret"} if field == "nested" else {field: "secret"}
    with pytest.raises(OfficialGuardError) as error:
        coordinator.install_binding("BE72", binding(**bad))
    assert error.value.code == "credentials_forbidden"
    with pytest.raises(OfficialGuardError) as error:
        coordinator.submit("BE72", "add_device", payload(**bad))
    assert error.value.code == "credentials_forbidden"
    assert store.take("BE72") == []
    assert "secret" not in coordinator.auth_path.read_text(encoding="utf-8")


def test_binding_requires_exact_local_sn_future_expiry_and_positive_version(monkeypatch, tmp_path):
    coordinator, _ = prepare(monkeypatch, tmp_path)
    invalid = [binding(serial="SN50"), binding(projectId=""),
               binding(expireTime=int(time.time() * 1000) - 1),
               binding(bindingVersion=0), binding(bindingVersion=True), binding(bindingVersion="1")]
    for value in invalid:
        with pytest.raises(OfficialGuardError):
            coordinator.install_binding("BE72", value)


def test_authorization_verify_is_local_and_reports_binding_version(monkeypatch, tmp_path):
    coordinator, _ = prepare(monkeypatch, tmp_path)
    status = coordinator.authorization_status("BE72", verify=True)
    assert status["authorized"] and status["cloudVerified"] and status["routerVerified"]
    assert status["bindingVersion"] == 1
    coordinator.identity = lambda _: "WRONG"
    status = coordinator.authorization_status("BE72", verify=True)
    assert not status["authorized"] and not status["routerVerified"]
    assert status["errorCode"] == "official_router_mismatch"


def test_connect_refresh_and_logout_never_claim_cloud_revocation(monkeypatch, tmp_path):
    coordinator, _ = prepare(monkeypatch, tmp_path)
    with pytest.raises(OfficialGuardError) as error:
        coordinator.connect("BE72", "owner@example.com", "password")
    assert error.value.code == "password_login_deprecated"
    with pytest.raises(OfficialGuardError) as error:
        coordinator.refresh("BE72")
    assert error.value.code == "cloud_refresh_deprecated"
    result = coordinator.logout("BE72")
    assert result["remoteRevocation"] == "app-managed/confirmed-by-app"
    assert result["localCleared"] and not result["authorized"]


def test_binding_version_mismatch_and_operation_id_reuse_are_rejected(monkeypatch, tmp_path):
    coordinator, store = prepare(monkeypatch, tmp_path)
    with pytest.raises(OfficialGuardError) as error:
        coordinator.submit("BE72", "add_device", payload(bindingVersion=2))
    assert error.value.code == "binding_version_mismatch"
    first = coordinator.submit("BE72", "add_device", payload())
    assert coordinator.submit("BE72", "add_device", payload())["commandId"] == first["commandId"]
    with pytest.raises(OfficialGuardError) as error:
        coordinator.submit("BE72", "remove_device", payload("remove_device"))
    assert error.value.code == "invalid_request"
    coordinator.install_binding("BE72", binding(bindingVersion=2))
    assert coordinator.status(first["commandId"])["errorCode"] == "official_auth_changed"
    assert store.take("BE72") == []


def test_explicit_sync_requires_all_app_confirmation_fields(monkeypatch, tmp_path):
    coordinator, store = prepare(monkeypatch, tmp_path)
    for field in ("cloudConfirmed", "officialUid", "operationId", "bindingVersion"):
        value = payload()
        value.pop(field)
        with pytest.raises(OfficialGuardError):
            coordinator.submit("BE72", "add_device", value)
    with pytest.raises(OfficialGuardError):
        coordinator.submit("BE72", "add_device", payload(cloudConfirmed=False))
    with pytest.raises(OfficialGuardError):
        coordinator.submit("BE72", "add_device", payload(officialUid="not-a-uid"))
    assert store.take("BE72") == []


def test_legacy_migration_strips_token_preserves_metadata_and_supersedes_pending(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    store = RouterCommandStore(tmp_path)
    legacy = binding(authGeneration=7, token="legacy-secret", cloudVerified=True)
    (tmp_path / "official_child_guard_accounts.json").write_text(json.dumps({"be72": encrypt_secret(json.dumps(legacy))}))
    (tmp_path / "official_child_guard_auth_generations.json").write_text(json.dumps({"be72": 7}))
    old_native = store.enqueue("BE72", "add_device", {"macs": [MAC], "officialUid": UID})
    old_op = {"id": "old", "router": "BE72", "routerKey": "be72", "state": "pending",
              "phase": "cloud", "cloudConfirmed": True, "macs": [mac_key(MAC)],
              "payload": {"password": "old-password"},
              "sequence": 1, "native": {"add": old_native["id"]}}
    (tmp_path / "official_child_guard_operations.json").write_text(json.dumps({"old": old_op}))
    calls = []
    import requests
    monkeypatch.setattr(requests.sessions.Session, "request",
        lambda *_args, **_kwargs: pytest.fail("official cloud outbound request after migration"))
    coordinator = OfficialGuardCoordinator(tmp_path, store, lambda _: "SN72", lambda: None,
        client_factory=lambda *_args, **_kwargs: calls.append(True))
    monkeypatch.setattr(coordinator, "start", lambda: None)
    raw = coordinator._raw_binding("BE72")
    assert raw["authGeneration"] == 7 and raw["projectId"] == "p72"
    assert "token" not in raw and "cloudVerified" not in raw
    assert coordinator.ops["old"]["state"] == "superseded"
    assert coordinator.ops["old"]["errorCode"] == "official_cloud_replay_forbidden"
    coordinator.process("old")
    assert calls == [] and store.take("BE72") == []
    assert store.record(old_native["id"])["status"] == "failed"
    saved = (tmp_path / "official_child_guard_accounts.json").read_text()
    assert "legacy-secret" not in saved and "old-password" not in (tmp_path / "official_child_guard_operations.json").read_text(encoding="utf-8")
    restarted = OfficialGuardCoordinator(tmp_path, store, lambda _: "SN72", lambda: None)
    assert restarted._raw_binding("BE72") == raw
    assert restarted.ops["old"]["state"] == "superseded"


def test_corrupt_binding_fails_closed_without_touching_other_configuration(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    auth = tmp_path / "official_child_guard_accounts.json"
    auth.write_text("not-json")
    unrelated = tmp_path / "router.json"
    unrelated.write_text('{"keep": true}')
    store = RouterCommandStore(tmp_path)
    coordinator = OfficialGuardCoordinator(tmp_path, store, lambda _: "SN72", lambda: None)
    status = coordinator.authorization_status("BE72", verify=True)
    assert status["errorCode"] == "official_storage_corrupt" and not status["authorized"]
    assert auth.read_text() == "not-json" and unrelated.read_text() == '{"keep": true}'
    with pytest.raises(OfficialGuardError):
        coordinator.submit("BE72", "add_device", payload())
    assert store.take("BE72") == []


def test_restart_resumes_only_native_confirmed_workflow(monkeypatch, tmp_path):
    coordinator, store = prepare(monkeypatch, tmp_path)
    op = coordinator.submit("BE72", "add_device", payload())
    with pytest.raises(OfficialGuardError):
        coordinator.process(op["commandId"])
    restarted = OfficialGuardCoordinator(tmp_path, store, lambda _: "SN72", lambda: None,
        client_factory=lambda *_args, **_kwargs: pytest.fail("cloud client constructed after restart"))
    monkeypatch.setattr(restarted, "start", lambda: None)
    complete(restarted, store, op["commandId"], [])
    assert restarted.status(op["commandId"])["officialSync"]["routerConfirmed"]


def test_plan_conflict_preserves_legacy_native_rule(monkeypatch, tmp_path):
    coordinator, store = prepare(monkeypatch, tmp_path)
    cid = coordinator.submit("BE72", "add_device", payload())["commandId"]
    with pytest.raises(OfficialGuardError):
        coordinator.process(cid)
    command = store.take("BE72")[0]
    store.acknowledge("BE72", [{"id": command["id"], "ok": True,
        "result": {"devices": [{"uid": OLD, "macs": [MAC], "planCount": 1}]}}])
    with pytest.raises(OfficialGuardError) as error:
        coordinator.process(cid)
    assert error.value.code == "official_local_plan_conflict"
    assert store.take("BE72") == []


def test_logout_cancels_pending_and_waits_for_delivered_native_mutation(monkeypatch, tmp_path):
    coordinator, store = prepare(monkeypatch, tmp_path)
    cid = coordinator.submit("BE72", "add_device", payload())["commandId"]
    with pytest.raises(OfficialGuardError):
        coordinator.process(cid)
    before = store.take("BE72")[0]
    # Complete the before read and enqueue add.
    store.acknowledge("BE72", [{"id": before["id"], "ok": True,
        "result": {"devices": []}}])
    with pytest.raises(OfficialGuardError):
        coordinator.process(cid)
    command = store.take("BE72")[0]
    assert command["action"] == "add_device"
    done = threading.Event()
    thread = threading.Thread(target=lambda: (coordinator.logout("BE72"), done.set()))
    thread.start()
    assert not done.wait(0.1)
    store.acknowledge("BE72", [{"id": command["id"], "ok": True, "result": {"uid": UID, "macs": [MAC]}}])
    thread.join(3)
    assert done.is_set() and coordinator.status(cid)["errorCode"] == "official_logged_out"


def test_hub_http_requires_app_confirmation_and_never_fans_password(monkeypatch, tmp_path):
    import hub
    coordinator, store = prepare(monkeypatch, tmp_path)
    monkeypatch.setattr(hub, "OFFICIAL_CHILD_GUARD", coordinator)
    monkeypatch.setattr(hub, "primary_router_name", lambda: "BE72")
    monkeypatch.setattr(hub, "check_app_token", lambda: True)
    monkeypatch.setattr(hub, "check_read_token", lambda: True)
    monkeypatch.setattr(hub, "_official_account_management_auth", lambda: True)
    client = hub.app.test_client()
    missing = client.post("/api/router/child-guard/devices?router=BE72&sync=official", json={"macs": [MAC]})
    assert missing.status_code == 409 and not missing.get_json()["ok"]
    response = client.post("/api/router/child-guard/devices?router=BE72&sync=official", json=payload())
    assert response.status_code == 202, response.get_json()
    cid = response.get_json()["commandId"]
    complete(coordinator, store, cid, [])
    assert client.get(f"/api/router/child-guard/command/{cid}").get_json()["officialSync"]["routerConfirmed"]


def test_official_account_routes_bind_get_delete_and_reject_login(monkeypatch, tmp_path):
    import hub
    coordinator, store = prepare(monkeypatch, tmp_path)
    monkeypatch.setattr(hub, "OFFICIAL_CHILD_GUARD", coordinator)
    monkeypatch.setattr(hub, "primary_router_name", lambda: "BE72")
    monkeypatch.setattr(hub, "_official_account_management_auth", lambda: True)
    client = hub.app.test_client()
    old = client.post("/api/official-account", json={"account": "owner@example.com", "password": "password"})
    assert old.status_code == 410 and old.get_json()["cloudDirectRequired"]
    refresh = client.post("/api/official-account", json={"action": "refresh"})
    assert refresh.status_code == 410
    credential = client.post("/api/official-account", json={"action": "bind", "binding": binding(token="secret")})
    assert credential.status_code == 410
    project_only = client.post("/api/official-account", json={"action": "bind", "projectId": "p72"})
    assert project_only.status_code in {400, 409}
    rebound = client.post("/api/official-account", json={"action": "bind", "binding": binding(bindingVersion=2)})
    assert rebound.status_code == 200 and rebound.get_json()["authorized"]
    status = client.get("/api/official-account?verify=1")
    assert status.status_code == 200 and status.get_json()["cloudVerified"]
    deleted = client.delete("/api/official-account")
    assert deleted.status_code == 200 and not deleted.get_json()["authorized"]
    assert deleted.get_json()["remoteRevocation"] == "app-managed/confirmed-by-app"
    assert store.take("BE72") == []


def test_single_router_official_management_rejects_hook_token(monkeypatch):
    import hub
    monkeypatch.delenv("APP_TOKEN_PREVIOUS", raising=False)
    monkeypatch.setattr(hub, "get_app_token", lambda: "app-management")
    monkeypatch.setattr(hub, "get_hook_token", lambda: "device-hook")
    monkeypatch.setattr(hub, "_auth_tokens_from_request", lambda: ["device-hook"])
    assert not hub._official_account_management_auth()
    monkeypatch.setattr(hub, "_auth_tokens_from_request", lambda: ["app-management"])
    assert hub._official_account_management_auth()


def test_client_historical_https_contract_is_retained():
    class Session:
        def request(self, method, url, **kwargs):
            assert url.startswith("https://shinyaapp.ruijie.com.cn/")
            assert kwargs["allow_redirects"] is False
            assert kwargs["json"]["staList"][0]["staMac"] == "AABBCCDDEE01"
            return type("Response", (), {"status_code": 302})()
    with pytest.raises(OfficialGuardError):
        OfficialGuardClient("secret", {"projectId": "p72"}, session=Session()).add({MAC}, "iPad")


def test_native_add_dedup_does_not_borrow_legacy_uid(tmp_path):
    store = RouterCommandStore(tmp_path)
    legacy = store.enqueue("BE72", "add_device", {"macs": [MAC]})
    official = store.enqueue("BE72", "add_device", {"macs": [MAC], "officialUid": UID})
    assert official["id"] != legacy["id"]
    assert store.enqueue("BE72", "add_device", {"macs": [MAC], "officialUid": UID})["id"] == official["id"]

def test_client_refresh_and_logout_have_no_body_and_parse_epoch_ms():
    calls = []

    class Session:
        def request(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            expiry = "1893456000000"
            data = {"token": "rotated-token", "expireTime": expiry} if method == "POST" and url.endswith("refreshToken") else None
            class Response:
                status_code = 200

                def json(self):
                    return {"code": 0, "data": data}

            return Response()

    client = OfficialGuardClient("old-token", session=Session())
    assert client.refresh_token() == {"expireTime": 1893456000000}
    assert client.token == "rotated-token"
    client.logout()
    assert [(method, url.rsplit("/", 1)[-1], kwargs["json"]) for method, url, kwargs in calls] == [
        ("POST", "refreshToken", None), ("POST", "logout", None),
    ]
    assert all(kwargs["allow_redirects"] is False for _, _, kwargs in calls)

def test_client_refresh_omits_missing_expiry_instead_of_returning_none():
    class Session:
        def request(self, method, url, **kwargs):
            class Response:
                status_code = 200

                def json(self):
                    return {"code": 0, "data": {"token": "rotated"}}

            return Response()

    client = OfficialGuardClient("old", session=Session())
    assert client.refresh_token() == {}
    assert client.token == "rotated"

def test_projects_paginate_and_deduplicate():
    calls = []

    class Session:
        def request(self, method, url, **kwargs):
            calls.append(kwargs["json"])
            page = int(kwargs["json"]["startPage"])
            rows = [{"buildingId": str(index), "name": str(index)} for index in range(500)] if page == 1 else [
                {"buildingId": "500", "name": "last"}, {"buildingId": "500", "name": "duplicate"},
            ]
            class Response:
                status_code = 200

                def json(self):
                    return {"code": 0, "data": {"dataList": rows, "totalCount": 501}}

            return Response()

    projects = OfficialGuardClient("token", session=Session()).projects()
    assert len(projects) == 501
    assert [row["startPage"] for row in calls] == ["1", "2"]

def test_discover_binding_normalizes_sn_and_never_uses_mesh_or_name():
    class Client(OfficialGuardClient):
        def projects(self):
            return [{"buildingId": "mesh", "name": "SN72"}, {"buildingId": "main", "name": "Other"}]

        def routers(self, project_id):
            self.binding = {"projectId": project_id}
            if project_id == "mesh":
                return {"mainAp": "REALMAIN", "apList": [{"sn": " sn72 ", "createTime": "2026-01-01 00:00:00"}]}
            return {"mainAp": " sn72 ", "apList": [
                {"sn": "MESH1", "createTime": "2026-01-01 00:00:00"},
                {"sn": "sn72", "createTime": "2026-01-01T00:00:00"},
            ]}

        def members(self):
            return []

    binding = Client("token").discover_binding(" Sn72 ")
    assert binding["projectId"] == "main" and binding["serial"] == "SN72"
    assert binding["meshSerials"] == ["MESH1", "SN72"]

def test_app_membership_uses_native_router_without_official_authorization(monkeypatch):
    import hub

    calls = []

    def native(action, payload):
        calls.append((action, payload))
        return hub.jsonify({"ok": True, "uid": UID}), 200

    monkeypatch.setattr(hub, "check_app_token", lambda: True)
    monkeypatch.setattr(hub, "_child_guard_execute", native)
    monkeypatch.setattr(hub, "_child_guard_official_membership",
                        lambda *_: pytest.fail("default App route must not require official cloud"))
    client = hub.app.test_client()
    added = client.post("/api/router/child-guard/devices?router=BE72",
                        json={"macs": [MAC], "deviceName": "iPad"})
    removed = client.delete(f"/api/router/child-guard/devices/{UID}?router=BE72",
                            json={"macs": [MAC]})
    assert added.status_code == removed.status_code == 200
    assert [action for action, _ in calls] == ["add_device", "remove_device"]
    assert calls[1][1] == {"uid": UID, "macs": [MAC], "router": None}

def test_official_identity_ignores_stale_dashboard_and_fails_closed_offline(monkeypatch):
    import hub
    reads = []

    def live():
        reads.append(True)
        return "SN50"

    monkeypatch.setattr(hub, "primary_router_name", lambda: "BE50")
    monkeypatch.setattr(hub, "_official_child_guard_live_serial", live)
    monkeypatch.setattr(hub, "ROUTER_DASHBOARD_CACHE", {
        "router": "BE72", "details": {"ap": {"serialNumber": "POISONED"}},
    })
    assert hub._official_child_guard_identity("BE50") == "SN50"
    assert hub._official_child_guard_identity("BE72") == ""
    assert len(reads) == 1
    monkeypatch.setattr(hub, "_official_child_guard_live_serial", lambda: "")
    assert hub._official_child_guard_identity("BE50") == ""

def test_live_identity_uses_fresh_bounded_eweb_session(monkeypatch):
    import hub
    import router_core.driver.reyee_session as session_module
    import router_rpc

    calls = []

    class Store:
        def __init__(self, _path):
            pass

        def load(self):
            return {"address": "http://192.168.5.1", "password": "secret",
                    "username": "admin", "verifyTls": False, "sessionSeconds": 3600}

    class Manager:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def get_session(self, force=False):
            assert force is True
            return type("Session", (), {"serial_number": " sn72 "})()

    monkeypatch.setattr(router_rpc, "EncryptedRouterConfigStore", Store)
    monkeypatch.setattr(session_module, "ReyeeSessionManager", Manager)
    assert hub._official_child_guard_live_serial() == "SN72"
    assert calls[0]["http_timeout"] == (2, 4)

    def offline(**_kwargs):
        raise OSError("router offline")

    monkeypatch.setattr(session_module, "ReyeeSessionManager", offline)
    assert hub._official_child_guard_live_serial() == ""



def test_corrupt_operation_journal_is_never_overwritten(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    ops = tmp_path / "official_child_guard_operations.json"
    ops.write_text("broken-journal")
    store = RouterCommandStore(tmp_path)
    coordinator = OfficialGuardCoordinator(tmp_path, store, lambda _: "SN72", lambda: None)
    monkeypatch.setattr(coordinator, "start", lambda: None)
    with pytest.raises(OfficialGuardError) as error:
        coordinator.install_binding("BE72", binding())
    assert error.value.code == "official_storage_corrupt"
    assert ops.read_text() == "broken-journal"
    assert json.loads(coordinator.auth_path.read_text(encoding="utf-8")) == {}


def test_official_account_http_app_token_boundary(monkeypatch, tmp_path):
    import hub
    coordinator, _ = prepare(monkeypatch, tmp_path)
    monkeypatch.setattr(hub, "OFFICIAL_CHILD_GUARD", coordinator)
    monkeypatch.setattr(hub, "primary_router_name", lambda: "BE72")
    monkeypatch.delenv("STRICT_TOKEN_SEPARATION", raising=False)
    monkeypatch.delenv("APP_TOKEN_PREVIOUS", raising=False)
    monkeypatch.setenv("APP_TOKEN", "app-secret")
    monkeypatch.setenv("HOOK_TOKEN", "hook-secret")
    coordinator.install_binding("BE72", binding(bindingVersion=2))
    client = hub.app.test_client()
    for method in ("GET", "POST", "DELETE"):
        response = client.open("/api/official-account", method=method,
            headers={"X-LabProbe-Token": "hook-secret"}, json={"action": "bind"} if method == "POST" else None)
        assert response.status_code == 401
    response = client.get("/api/official-account", headers={"X-LabProbe-Token": "app-secret"})
    assert response.status_code == 200 and response.get_json()["authorized"]


def test_add_remove_add_preserves_latest_intent_order(monkeypatch, tmp_path):
    coordinator, _ = prepare(monkeypatch, tmp_path)
    first = coordinator.submit("BE72", "add_device", payload())
    second = coordinator.submit("BE72", "remove_device", payload("remove_device", operationId="op-2"))
    third = coordinator.submit("BE72", "add_device", payload(operationId="op-3"))
    assert len({row["commandId"] for row in (first, second, third)}) == 3
    assert coordinator.submit("BE72", "add_device", payload(operationId="op-3"))["commandId"] == third["commandId"]


def test_identity_change_before_processing_never_enqueues_native(monkeypatch, tmp_path):
    coordinator, store = prepare(monkeypatch, tmp_path)
    cid = coordinator.submit("BE72", "add_device", payload())["commandId"]
    coordinator.identity = lambda _: "WRONG"
    with pytest.raises(OfficialGuardError, match="不匹配"):
        coordinator.process(cid)
    assert store.take("BE72") == []


def test_logout_reports_pending_when_delivered_native_never_settles(monkeypatch, tmp_path):
    import official_child_guard
    coordinator, store = prepare(monkeypatch, tmp_path)
    cid = coordinator.submit("BE72", "add_device", payload())["commandId"]
    with pytest.raises(OfficialGuardError):
        coordinator.process(cid)
    before = store.take("BE72")[0]
    store.acknowledge("BE72", [{"id": before["id"], "ok": True, "result": {"devices": []}}])
    with pytest.raises(OfficialGuardError):
        coordinator.process(cid)
    assert store.take("BE72")[0]["action"] == "add_device"
    monkeypatch.setattr(official_child_guard, "OFFICIAL_LOGOUT_NATIVE_TIMEOUT_SEC", 0.01)
    with pytest.raises(OfficialGuardError) as error:
        coordinator.logout("BE72")
    assert error.value.code == "official_logout_pending"
    with pytest.raises(OfficialGuardError):
        coordinator.binding("BE72")

def test_hook_dashboard_serial_is_not_cached_or_used_for_authorization(monkeypatch, tmp_path):
    import hub
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    monkeypatch.setattr(hub, "primary_router_name", lambda: "BE72")
    monkeypatch.setattr(hub, "check_hook_token", lambda: True)
    monkeypatch.setattr(hub, "_cached_hub_exit_ipv4", lambda: "")
    monkeypatch.setattr(hub, "_schedule_dashboard_operator_probe", lambda: None)
    monkeypatch.setattr(hub, "_persist_router_dashboard_if_due", lambda force=False: None)
    monkeypatch.setattr(hub.MQTT_PUBLISHER, "publish_dashboard", lambda _payload: None)
    monkeypatch.setattr(hub, "LAB_DDNS", None, raising=False)
    monkeypatch.setattr(hub, "ROUTER_DASHBOARD_CACHE", {})
    monkeypatch.setattr(hub, "_official_child_guard_live_serial", lambda: "SN72")
    payload = {
        "router": "BE72", "details": {
            "ap": {"serialNumber": "POISON", "model": "BE72"},
            "identity": {"serialNumber": "POISON", "hostName": "BE72"},
        },
    }
    # hub_entry may install the Relay compatibility ACK over the Flask view;
    # call Hub's original push function directly to exercise its trust boundary.
    with hub.app.test_request_context("/api/router/dashboard/push", method="POST", json=payload):
        pushed = hub.api_router_dashboard_push()
    assert pushed.status_code == 200
    assert hub.ROUTER_DASHBOARD_CACHE["details"]["ap"]["model"] == "BE72"
    assert "serialNumber" not in hub.ROUTER_DASHBOARD_CACHE["details"]["ap"]
    assert "serialNumber" not in hub.ROUTER_DASHBOARD_CACHE["details"]["identity"]

    coordinator = OfficialGuardCoordinator(tmp_path, RouterCommandStore(tmp_path),
        hub._official_child_guard_identity, lambda: None,
        client_factory=lambda *_args, **_kwargs: pytest.fail("cloud client constructed"))
    monkeypatch.setattr(coordinator, "start", lambda: None)
    status = coordinator.install_binding("BE72", {"serial": "SN72", "projectId": "p72",
        "account": "owner@example.com", "expireTime": int(time.time() * 1000) + 60000,
        "bindingVersion": 1})
    assert status["authorized"] and status["serial"] == "SN72"
    assert coordinator._raw_binding("BE72")["serial"] == "SN72"
    monkeypatch.setattr(hub, "_official_child_guard_live_serial", lambda: "")
    offline = coordinator.authorization_status("BE72")
    assert not offline["authorized"] and not offline["routerVerified"]
