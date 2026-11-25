import copy
import json
import threading
import time

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
        self.logouts = 0
        self.verifications = 0
        self.refreshes = 0
        self.fail_logout = False

    def client(self, token="", binding=None):
        cloud = self

        class Client:
            def __init__(self):
                self.token = token

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

            def login_password(self, account, password):
                self.token = "new-secret-token"
                return {"expireTime": int(time.time() * 1000) + 60000}

            def discover_binding(self, serial):
                return {"serial": serial, "projectId": "p72", "projectName": "Home",
                        "createTime": "2026-01-01 00:00:00", "meshSerials": [serial]}

            def verify_binding(self, serial):
                cloud.verifications += 1
                return {"serial": serial, "projectId": "p72", "projectName": "Home",
                        "createTime": "2026-01-01 00:00:00", "meshSerials": [serial]}

            def refresh_token(self):
                cloud.refreshes += 1
                self.token = "refreshed-secret-token"
                return {"expireTime": int(time.time() * 1000) + 120000}

            def logout(self):
                cloud.logouts += 1
                if cloud.fail_logout:
                    raise OfficialGuardError("official_unavailable", "logout failed", retryable=True)

        return Client()


def prepare(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    cloud = Cloud()
    store = RouterCommandStore(tmp_path)
    coordinator = OfficialGuardCoordinator(tmp_path, store, lambda r: "SN72" if r == "BE72" else "SN50",
        lambda: None, client_factory=cloud.client)
    monkeypatch.setattr(coordinator, "start", lambda: None)
    coordinator.install_binding("BE72", {"serial": "SN72", "token": "secret-test-token", "projectId": "p72",
        "expireTime": int(time.time() * 1000) + 60000})
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
    monkeypatch.setattr(hub, "_official_account_management_auth", lambda: True)
    monkeypatch.setattr(hub, "check_read_token", lambda: True)
    client = hub.app.test_client()
    response = client.post("/api/router/child-guard/devices?router=BE72&sync=official", json={"macs": [MAC], "deviceName": "iPad"})
    assert response.status_code == 202 and store.take("BE72") == []
    cid = response.get_json()["commandId"]
    assert client.get(f"/api/router/child-guard/command/{cid}").get_json()["pending"]
    complete(coordinator, store, cid, [])
    done = client.get(f"/api/router/child-guard/command/{cid}").get_json()
    assert done["uid"] == UID and done["officialSync"]["routerConfirmed"]
    foreign = client.post("/api/router/child-guard/devices?router=BE50&sync=official", json={"macs": [MAC]})
    assert foreign.status_code == 409 and not foreign.get_json()["ok"]


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

    cloud = Cloud()
    coordinator = OfficialGuardCoordinator(tmp_path, RouterCommandStore(tmp_path),
        hub._official_child_guard_identity, lambda: None, client_factory=cloud.client)
    monkeypatch.setattr(coordinator, "start", lambda: None)
    status = coordinator.connect("BE72", "owner@example.com", "password")
    assert status["authorized"] and status["serial"] == "SN72"
    assert coordinator._raw_binding("BE72")["serial"] == "SN72"
    monkeypatch.setattr(hub, "_official_child_guard_live_serial", lambda: "")
    offline = coordinator.authorization_status("BE72")
    assert not offline["authorized"] and not offline["routerVerified"]


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


def test_connect_encrypts_account_and_never_persists_password(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    cloud = Cloud()
    coordinator = OfficialGuardCoordinator(tmp_path, RouterCommandStore(tmp_path), lambda _: "SN72",
        lambda: None, client_factory=cloud.client)
    monkeypatch.setattr(coordinator, "start", lambda: None)
    status = coordinator.connect("BE72", "owner@example.com", "never-save-this-password")
    saved = coordinator.auth_path.read_text(encoding="utf-8")
    assert all(secret not in saved for secret in ("owner@example.com", "never-save-this-password", "new-secret-token"))
    assert coordinator._raw_binding("BE72")["account"] == "owner@example.com"
    assert status["account"] == "o***@example.com"
    assert status["authorized"] and status["cloudVerified"] and status["routerVerified"]
    assert status["projectId"] == "p72" and status["serial"] == "SN72"
    assert isinstance(status["expireTime"], int) and status["verifiedAt"]


def test_verify_after_restart_uses_live_projects_and_persists_verification(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    cloud = Cloud()
    coordinator = OfficialGuardCoordinator(tmp_path, RouterCommandStore(tmp_path), lambda _: "SN72",
        lambda: None, client_factory=cloud.client)
    monkeypatch.setattr(coordinator, "start", lambda: None)
    coordinator.connect("BE72", "owner@example.com", "password")
    restarted = OfficialGuardCoordinator(tmp_path, coordinator.commands, coordinator.identity,
        lambda: None, client_factory=cloud.client)
    monkeypatch.setattr(restarted, "start", lambda: None)
    before = restarted.authorization_status("BE72")["verifiedAt"]
    status = restarted.authorization_status("BE72", verify=True)
    assert cloud.verifications == 1 and status["cloudVerified"] and status["routerVerified"]
    assert status["verifiedAt"] >= before
    again = OfficialGuardCoordinator(tmp_path, coordinator.commands, coordinator.identity,
        lambda: None, client_factory=cloud.client)
    assert again.authorization_status("BE72")["verifiedAt"] == status["verifiedAt"]


def test_expiry_is_reported_and_refresh_reverifies(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    cloud = Cloud()
    coordinator = OfficialGuardCoordinator(tmp_path, RouterCommandStore(tmp_path), lambda _: "SN72",
        lambda: None, client_factory=cloud.client)
    monkeypatch.setattr(coordinator, "start", lambda: None)
    coordinator.install_binding("BE72", {"serial": "SN72", "token": "old", "projectId": "p72",
        "account": "owner@example.com", "expireTime": int(time.time() * 1000) - 1})
    expired = coordinator.authorization_status("BE72")
    assert not expired["authorized"] and expired["errorCode"] == "official_token_expired"
    refreshed = coordinator.refresh("BE72")
    assert cloud.refreshes == 1 and cloud.verifications == 1
    assert refreshed["authorized"] and refreshed["expireTime"] > int(time.time() * 1000)
    assert coordinator._raw_binding("BE72")["token"] == "refreshed-secret-token"


def test_refresh_preserves_known_expiry_when_response_omits_it(monkeypatch, tmp_path):
    coordinator, cloud, _ = prepare(monkeypatch, tmp_path)
    before = coordinator._raw_binding("BE72")["expireTime"]
    original = cloud.client

    def factory(token="", binding=None):
        client = original(token, binding)
        client.refresh_token = lambda: (setattr(client, "token", "rotated-without-expiry") or {})
        return client

    coordinator.client_factory = factory
    status = coordinator.refresh("BE72")
    assert status["authorized"] and status["expireTime"] == before
    assert coordinator._raw_binding("BE72")["token"] == "rotated-without-expiry"


def test_delayed_verification_cannot_overwrite_newer_refreshed_token(monkeypatch, tmp_path):
    coordinator, cloud, _ = prepare(monkeypatch, tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = coordinator.client_factory

    def slow_factory(token="", binding=None):
        client = original(token, binding)
        verify = client.verify_binding

        def delayed(serial):
            entered.set()
            assert release.wait(2)
            return verify(serial)

        client.verify_binding = delayed
        return client

    coordinator.client_factory = slow_factory
    results = []

    def verify():
        results.append(coordinator.authorization_status("BE72", verify=True))

    thread = threading.Thread(target=verify)
    thread.start()
    assert entered.wait(2)
    binding = coordinator._raw_binding("BE72")
    coordinator._persist_binding("BE72", {**binding, "token": "refreshed-secret-token",
        "cloudVerified": False}, int(binding["authGeneration"]), expected_token=binding["token"])
    release.set()
    thread.join(3)
    assert results and results[0]["errorCode"] == "official_auth_changed"
    assert not results[0]["authorized"] and not results[0]["routerVerified"]
    assert coordinator._raw_binding("BE72")["token"] == "refreshed-secret-token"


def test_missing_expiry_is_rejected_instead_of_treated_as_non_expiring(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    coordinator = OfficialGuardCoordinator(tmp_path, RouterCommandStore(tmp_path), lambda _: "SN72",
        lambda: None, client_factory=Cloud().client)
    monkeypatch.setattr(coordinator, "start", lambda: None)
    with pytest.raises(OfficialGuardError) as error:
        coordinator.install_binding("BE72", {"serial": "SN72", "token": "token", "projectId": "p72"})
    assert error.value.code == "official_expiry_unknown"
    with pytest.raises(OfficialGuardError):
        coordinator._raw_binding("BE72")


@pytest.mark.parametrize("action", ["add_device", "remove_device"])
def test_logout_waits_for_blocked_cloud_mutation_before_completing(monkeypatch, tmp_path, action):
    coordinator, cloud, store = prepare(monkeypatch, tmp_path)
    if action == "remove_device":
        cloud.rows = [{"staId": UID, "mergeMacs": [mac_key(MAC)]}]
    entered, release, committed, logout_done = (threading.Event() for _ in range(4))
    original = cloud.client

    def factory(token="", binding=None):
        client = original(token, binding)
        if action == "add_device":
            def add(macs, *args):
                entered.set()
                assert release.wait(2)
                cloud.adds += 1
                cloud.rows.append({"staId": UID, "mergeMacs": sorted(macs)})
                committed.set()
            client.add = add
        else:
            def remove(uid):
                entered.set()
                assert release.wait(2)
                cloud.deletes += 1
                cloud.rows = [row for row in cloud.rows if row["staId"] != uid]
                committed.set()
            client.remove = remove
        return client

    coordinator.client_factory = factory
    payload = {"macs": [MAC]}
    if action == "remove_device":
        payload["uid"] = UID
    cid = coordinator.submit("BE72", action, payload)["commandId"]
    process_errors = []

    def run_process():
        try:
            coordinator.process(cid)
        except Exception as error:
            process_errors.append(error)

    def run_logout():
        coordinator.logout("BE72")
        logout_done.set()

    process_thread = threading.Thread(target=run_process)
    process_thread.start()
    assert entered.wait(2)
    logout_thread = threading.Thread(target=run_logout)
    logout_thread.start()
    assert not logout_done.wait(0.1), "logout crossed an in-flight cloud mutation"
    release.set()
    process_thread.join(3)
    logout_thread.join(3)
    assert committed.is_set() and logout_done.is_set()
    assert cloud.logouts == 1
    assert coordinator.status(cid)["errorCode"] == "official_logged_out"
    # The workflow may have queued its read-only confirmation before logout won
    # the barrier, but no native membership mutation may remain dispatchable.
    assert all(command["action"].startswith("get_") for command in store.take("BE72"))


def test_connect_refuses_install_when_logout_changes_generation_during_discovery(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    cloud = Cloud()
    coordinator = OfficialGuardCoordinator(tmp_path, RouterCommandStore(tmp_path), lambda _: "SN72",
        lambda: None, client_factory=cloud.client)
    monkeypatch.setattr(coordinator, "start", lambda: None)
    entered, release = threading.Event(), threading.Event()
    original = cloud.client

    def factory(token="", binding=None):
        client = original(token, binding)
        client.discover_binding = lambda serial: (entered.set(), release.wait(2),
            {"serial": serial, "projectId": "p72", "projectName": "Home",
             "createTime": "2026-01-01 00:00:00", "meshSerials": [serial]})[2]
        return client

    coordinator.client_factory = factory
    errors = []

    def connect():
        try:
            coordinator.connect("BE72", "owner@example.com", "password")
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=connect)
    thread.start()
    assert entered.wait(2)
    coordinator.logout("BE72")
    release.set()
    thread.join(3)
    assert errors and getattr(errors[0], "code", "") == "official_auth_changed"
    with pytest.raises(OfficialGuardError):
        coordinator._raw_binding("BE72")


def _advance_to_native_add(coordinator, store, cid, native):
    with pytest.raises(OfficialGuardError) as error:
        coordinator.process(cid)
    assert error.value.code == "router_confirmation_pending"
    command = store.take("BE72")[0]
    assert command["action"] == "get_users"
    store.acknowledge("BE72", [{"id": command["id"], "ok": True,
        "result": {"ok": True, "devices": copy.deepcopy(native)}}])


def test_logout_cancels_native_mutation_blocked_before_dispatch(monkeypatch, tmp_path):
    coordinator, _, store = prepare(monkeypatch, tmp_path)
    cid = coordinator.submit("BE72", "add_device", {"macs": [MAC]})["commandId"]
    _advance_to_native_add(coordinator, store, cid, [])
    entered, release, logout_done = threading.Event(), threading.Event(), threading.Event()
    original = store.enqueue

    def enqueue(router, action, payload=None):
        if action == "add_device":
            entered.set()
            assert release.wait(2)
        return original(router, action, payload)

    monkeypatch.setattr(store, "enqueue", enqueue)
    errors = []

    def process():
        try:
            coordinator.process(cid)
        except Exception as error:
            errors.append(error)

    def logout():
        coordinator.logout("BE72")
        logout_done.set()

    process_thread = threading.Thread(target=process)
    process_thread.start()
    assert entered.wait(2)
    logout_thread = threading.Thread(target=logout)
    logout_thread.start()
    assert not logout_done.wait(0.1)
    release.set()
    process_thread.join(3)
    logout_thread.join(3)
    assert logout_done.is_set() and errors
    assert store.take("BE72") == [], "native mutation survived logout"
    assert coordinator.status(cid)["errorCode"] == "official_logged_out"


def test_logout_waits_for_already_delivered_native_mutation(monkeypatch, tmp_path):
    coordinator, _, store = prepare(monkeypatch, tmp_path)
    cid = coordinator.submit("BE72", "add_device", {"macs": [MAC]})["commandId"]
    _advance_to_native_add(coordinator, store, cid, [])
    with pytest.raises(OfficialGuardError):
        coordinator.process(cid)
    command = store.take("BE72")[0]
    assert command["action"] == "add_device"
    logout_done = threading.Event()

    def logout():
        coordinator.logout("BE72")
        logout_done.set()

    thread = threading.Thread(target=logout)
    thread.start()
    assert not logout_done.wait(0.1), "logout ignored a delivered native mutation"
    store.acknowledge("BE72", [{"id": command["id"], "ok": True,
        "result": {"ok": True, "uid": UID, "macs": [MAC]}}])
    thread.join(3)
    assert logout_done.is_set() and store.take("BE72") == []
    assert coordinator.status(cid)["errorCode"] == "official_logged_out"


def test_logout_reports_pending_when_delivered_native_command_never_settles(monkeypatch, tmp_path):
    import official_child_guard
    coordinator, _, store = prepare(monkeypatch, tmp_path)
    cid = coordinator.submit("BE72", "add_device", {"macs": [MAC]})["commandId"]
    _advance_to_native_add(coordinator, store, cid, [])
    with pytest.raises(OfficialGuardError):
        coordinator.process(cid)
    assert store.take("BE72")[0]["action"] == "add_device"
    monkeypatch.setattr(official_child_guard, "OFFICIAL_LOGOUT_NATIVE_TIMEOUT_SEC", 0.01)
    with pytest.raises(OfficialGuardError) as error:
        coordinator.logout("BE72")
    assert error.value.code == "official_logout_pending"
    with pytest.raises(OfficialGuardError):
        coordinator.binding("BE72")


def test_cloud_logout_failure_still_clears_local_token_and_history(monkeypatch, tmp_path):
    coordinator, cloud, _ = prepare(monkeypatch, tmp_path)
    cid = coordinator.submit("BE72", "add_device", {"macs": [MAC]})["commandId"]
    cloud.fail_logout = True
    with pytest.raises(OfficialGuardError):
        coordinator.logout("BE72")
    with pytest.raises(OfficialGuardError):
        coordinator.binding("BE72")
    assert coordinator.status(cid)["errorCode"] == "official_logged_out"
    assert "secret-test-token" not in coordinator.auth_path.read_text(encoding="utf-8")


def test_failed_refresh_verification_invalidates_binding_and_blocks_writes(monkeypatch, tmp_path):
    coordinator, cloud, _ = prepare(monkeypatch, tmp_path)
    original = cloud.client

    def factory(token="", binding=None):
        client = original(token, binding)
        client.refresh_token = lambda: (setattr(client, "token", "rotated-unverified") or
            {"expireTime": int(time.time() * 1000) + 120000})
        client.verify_binding = lambda _serial: (_ for _ in ()).throw(
            OfficialGuardError("official_router_mismatch", "binding changed"))
        return client

    coordinator.client_factory = factory
    with pytest.raises(OfficialGuardError) as error:
        coordinator.refresh("BE72")
    assert error.value.code == "official_router_mismatch"
    assert not coordinator.authorization_status("BE72")["authorized"]
    with pytest.raises(OfficialGuardError):
        coordinator.submit("BE72", "add_device", {"macs": [MAC]})


def test_single_router_official_management_rejects_hook_token(monkeypatch):
    import hub
    monkeypatch.delenv("STRICT_TOKEN_SEPARATION", raising=False)
    monkeypatch.delenv("APP_TOKEN_PREVIOUS", raising=False)
    monkeypatch.setattr(hub, "get_app_token", lambda: "app-management")
    monkeypatch.setattr(hub, "get_hook_token", lambda: "device-hook")
    monkeypatch.setattr(hub, "_auth_tokens_from_request", lambda: ["device-hook"])
    assert not hub._official_account_management_auth()
    monkeypatch.setattr(hub, "_auth_tokens_from_request", lambda: ["app-management"])
    assert hub._official_account_management_auth()


def test_logout_api_distinguishes_local_clear_from_remote_unavailability(monkeypatch, tmp_path):
    import hub
    coordinator, cloud, _ = prepare(monkeypatch, tmp_path)
    monkeypatch.setattr(hub, "OFFICIAL_CHILD_GUARD", coordinator)
    monkeypatch.setattr(hub, "primary_router_name", lambda: "BE72")
    monkeypatch.setattr(hub, "_official_account_management_auth", lambda: True)
    cloud.fail_logout = True
    response = hub.app.test_client().delete("/api/official-account")
    body = response.get_json()
    assert response.status_code == 409 and not body["ok"]
    assert body["authorized"] is False and body["localCleared"] is True
    assert body["remoteRevocation"] == "unknown" and body["retrySafe"] is False
    assert body["errorCode"] == "official_logout_pending"


def test_global_root_alias_supports_login_verify_refresh_and_logout(monkeypatch, tmp_path):
    import hub
    monkeypatch.setenv("APP_TOKEN", "test-only-encryption-key")
    cloud = Cloud()
    coordinator = OfficialGuardCoordinator(tmp_path, RouterCommandStore(tmp_path), lambda _: "SN72",
        lambda: None, client_factory=cloud.client)
    monkeypatch.setattr(coordinator, "start", lambda: None)
    monkeypatch.setattr(hub, "OFFICIAL_CHILD_GUARD", coordinator)
    monkeypatch.setattr(hub, "primary_router_name", lambda: "BE72")
    monkeypatch.setattr(hub, "_official_account_management_auth", lambda: True)
    monkeypatch.setattr(hub, "check_read_token", lambda: True)
    client = hub.app.test_client()
    logged_in = client.post("/api/official-account", json={"account": "owner@example.com", "password": "password"})
    assert logged_in.status_code == 200 and logged_in.get_json()["account"] == "o***@example.com"
    assert logged_in.get_json()["state"] == "authorized"
    assert logged_in.get_json()["matchedRouterCount"] == 1
    assert logged_in.get_json()["routers"][0]["routerId"]
    verified = client.get("/api/official-account?verify=1")
    assert verified.status_code == 200 and verified.get_json()["cloudVerified"] and cloud.verifications == 1
    refreshed = client.post("/api/official-account", json={"action": "refresh"})
    assert refreshed.status_code == 200 and refreshed.get_json()["authorized"] and cloud.refreshes == 1
    logged_out = client.delete("/api/official-account")
    assert logged_out.status_code == 200 and not logged_out.get_json()["authorized"] and cloud.logouts == 1
    assert logged_out.get_json()["operationState"] == "complete"
    assert logged_out.get_json()["remoteRevocation"] == "confirmed"
    assert logged_out.get_json()["state"] == "unauthorized"
    assert logged_out.get_json()["routers"][0]["syncState"] == "unauthorized"
    assert all(secret not in logged_out.get_data(as_text=True) for secret in ("password", "token", "owner@example.com"))
