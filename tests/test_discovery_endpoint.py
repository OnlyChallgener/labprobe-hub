"""`/.well-known/labprobe` 是 relay 无需凭据就能读的端点。

网关模式下每台路由器有自己的通道 /r/<routerId>；这个端点必须自己说清是哪台，
否则 relay 会把数据推到根 Hub，两台的路由器库就会互相接错。
"""

import hub


def _get(client=None):
    return (client or hub.app.test_client()).get("/.well-known/labprobe")


def test_discovery_names_the_channel_in_both_modes(monkeypatch):
    monkeypatch.delenv("ROUTER_ID", raising=False)
    body = _get().get_json()
    assert body["ok"] is True
    assert body["routerId"] == "default"
    # 单路由部署的通道就是根路径；install 脚本据此不改 HUB_URL。
    assert body["basePath"] == ""

    monkeypatch.setenv("ROUTER_ID", "be50")
    body = _get().get_json()
    assert body["routerId"] == "be50"
    assert body["basePath"] == "/r/be50"


def test_discovery_never_leaks_the_mqtt_password(monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "discovery-test-token")
    monkeypatch.delenv("APP_TOKEN_PREVIOUS", raising=False)
    monkeypatch.setattr(hub, "MQTT_PUBLIC_URL", "wss://broker.example:8884/mqtt")
    monkeypatch.setattr(hub, "MQTT_USERNAME", "hub-worker")
    monkeypatch.setattr(hub, "MQTT_PASSWORD", "s3cret-mqtt-password")
    body = _get().get_json()
    assert body["mqtt"]["enabled"] is True
    assert "password" not in body["mqtt"]
    assert "s3cret-mqtt-password" not in _get().get_data(as_text=True)
    # 需要凭据的那条路仍然给得出密码，说明这里只是 discovery 少给，不是功能坏了。
    response = hub.app.test_client().get(
        "/api/mqtt/config", headers={"Authorization": "Bearer discovery-test-token"})
    assert response.get_json()["mqtt"]["password"] == "s3cret-mqtt-password"
