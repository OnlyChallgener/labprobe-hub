from flask import Flask

from shinya_compat import create_shinya_blueprint


class Router:
    def __init__(self):
        self.reads = 0

    def get_dashboard(self, force=False):
        self.reads += 1
        return {"online": True, "router": "BE72", "details": {
            "ap": {"serialNumber": "BE72-ONE", "model": "BE72-PRO", "hostName": "BE72"},
            "lan": {"mac": "10:5f:02:05:80:68", "ipv4": "192.168.5.1"}},
            "telemetry": {"temperatureC": 54.21, "cpuPercent": 14.6, "onlineDeviceCount": 2}}

    def get_devices(self, force=False):
        return [{"mac": "AA:BB:CC:DD:EE:01", "name": "Mate60", "devType": "phone", "online": True},
                {"mac": "AA:BB:CC:DD:EE:02", "name": "Mate60", "devType": "phone", "online": False}]


def client():
    app = Flask(__name__)
    router = Router()
    app.register_blueprint(create_shinya_blueprint(router, lambda: ["test-app-token"]))
    return app.test_client(), router


AUTH = {"Authorization": "Bearer test-app-token"}


def test_login_authentication_and_token_contract():
    api, router = client()
    path = "/api/v1/base/homeUser/accountPasswordLogin"
    assert api.post(path, json={"password": "wrong"}).json["code"] == 401
    result = api.post(path, json={"account": "http://hub:58443", "password": "test-app-token"}).json
    assert result["code"] == 0
    assert result["data"]["token"] == "test-app-token"
    assert result["data"]["expireTime"] > 1_000_000_000_000
    assert router.reads == 0
    assert api.get("/api/v1/base/homeUser/info").json["code"] == 401
    assert api.get("/api/v1/base/homeUser/info", headers=AUTH).json["data"]["accountId"] == "labprobe-hub"


def test_project_and_ap_identity_temperature():
    api, _ = client()
    project = api.post("/homewlan/apMonitor/getProjectList2", headers=AUTH).json["data"]["dataList"][0]
    assert project["buildingId"] == "hub:BE72-ONE"
    result = api.post("/homewlan/homeAp/getDeviceInfoList2", headers=AUTH,
                      json={"projectId": project["buildingId"]}).json
    assert result["data"]["mainAp"] == "BE72-ONE"
    assert result["data"]["apList"][0]["temperature"] == 54.21
    assert result["data"]["apList"][0]["gameTurbo"] == "0"


def test_router_selection_cannot_cross_worker_boundary():
    api, _ = client()
    path = "/homewlan/homeAp/getDeviceInfoList2"
    assert api.post(path, json={"buildingId": "hub:BE50-OTHER"}, headers=AUTH).json["code"] == 404
    assert api.post(path, json={"sn": "BE50-OTHER"}, headers=AUTH).json["code"] == 404
    assert api.post(path, headers={**AUTH, "projectId": "hub:BE50-OTHER"}).json["code"] == 404


def test_distinct_macs_and_offline_devices_are_retained():
    api, _ = client()
    devices = api.post("/homewlan/homeAp/getStaList2", headers=AUTH).json["data"]["sta_list"]
    assert len(devices) == 2
    assert devices[0]["mac"] != devices[1]["mac"]
    assert devices[0]["remark"] == devices[1]["remark"] == "Mate60"
    assert devices[1]["online"] is False


def test_unconnected_mutations_never_fake_success():
    api, router = client()
    for resource in ("homeAp/setWifiNameAndPasscode2", "childProtection/setStaBlackAndSendCmd2", "homeAp/deleteProject"):
        response = api.post("/homewlan/" + resource, json={"projectId": "hub:BE72-ONE"}, headers=AUTH)
        assert response.json["code"] == 501
        assert response.json["data"] is None
        assert response.headers["Cache-Control"] == "no-store"
    assert router.reads == 0
