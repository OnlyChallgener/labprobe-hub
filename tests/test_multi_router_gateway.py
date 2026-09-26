import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import yaml

import multi_router_gateway as gateway


SECRETS = {
    "HOME_APP": "A" * 32,
    "HOME_HOOK": "B" * 32,
    "OFFICE_APP": "C" * 32,
    "OFFICE_HOOK": "D" * 32,
}


def _config(tmp_path, *, entries=None):
    data = {
        "version": 1,
        "gateway": {
            "listenPort": 58443,
            "registryPort": 58444,
            "publicBaseUrl": "https://hub.example.test",
            "storageRoot": str(tmp_path / "multi"),
            "defaultRouterId": "home",
        },
        "routers": entries or [
            {"routerId": "home", "name": "Home", "site": "Home", "model": "Reyee",
             "platform": "reyee", "ewebUrl": "http://192.168.5.1", "workerPort": 58501,
             "appTokenEnv": "HOME_APP", "hookTokenEnv": "HOME_HOOK"},
            {"routerId": "office", "name": "Office", "site": "Office", "model": "Reyee",
             "platform": "reyee", "ewebUrl": "http://192.168.6.1", "workerPort": 58502,
             "appTokenEnv": "OFFICE_APP", "hookTokenEnv": "OFFICE_HOOK"},
        ],
    }
    path = tmp_path / "multi.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return path, data


def test_isolated_reyee_worker_paths_and_tokens(tmp_path):
    path, _ = _config(tmp_path)
    config = gateway.load_gateway_config(path, SECRETS)
    home, office = config["routers"]
    inherited = {**SECRETS, "ROUTER_PASSWORD": "stale", "APP_TOKEN_PREVIOUS": "old"}
    home_env = gateway.worker_environment(home, config, inherited)
    office_env = gateway.worker_environment(
        office, config, {**SECRETS, "ROUTER_EWEB_URL": "http://192.168.5.1"},
    )
    assert home_env["CONFIG_DIR"] != office_env["CONFIG_DIR"]
    assert home_env["DATABASE_PATH"] != office_env["DATABASE_PATH"]
    assert home_env["MQTT_TOPIC_PREFIX"] != office_env["MQTT_TOPIC_PREFIX"]
    assert home_env["APP_TOKEN"] != office_env["APP_TOKEN"]
    assert home_env["HOOK_TOKEN"] != office_env["HOOK_TOKEN"]
    assert home_env["HUB_BIND_HOST"] == office_env["HUB_BIND_HOST"] == "127.0.0.1"
    assert home_env["STRICT_TOKEN_SEPARATION"] == office_env["STRICT_TOKEN_SEPARATION"] == "1"
    assert home_env["MULTI_ROUTER_LOCK_EWEB"] == office_env["MULTI_ROUTER_LOCK_EWEB"] == "1"
    assert "ROUTER_PASSWORD" not in home_env
    assert "APP_TOKEN_PREVIOUS" not in home_env
    assert all(name not in home_env and name not in office_env for name in SECRETS)
    assert office_env["ROUTER_EWEB_URL"] == "http://192.168.6.1"
    assert office_env["ROUTER_RPC_PRIMARY"] == "true"
    assert office_env["HUB_ADVERTISE_URL"] == "https://hub.example.test/r/office"


def test_nginx_routes_http_and_websocket_to_isolated_workers(tmp_path):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    rendered = gateway.render_nginx_config(config, Path("/tmp/nginx.pid"))
    assert "location ^~ /r/home/" in rendered
    assert "location ^~ /r/office/" in rendered
    assert "proxy_pass http://127.0.0.1:58501/;" in rendered
    assert "proxy_pass http://127.0.0.1:58502/;" in rendered
    assert "location ^~ /r/ { return 404; }" in rendered
    assert "location / { proxy_pass http://127.0.0.1:58501; }" in rendered
    assert "proxy_set_header Upgrade $http_upgrade;" in rendered
    assert "proxy_set_header Connection $connection_upgrade;" in rendered
    assert "location = /api/routers" in rendered
    assert SECRETS["HOME_APP"] not in rendered


@pytest.mark.parametrize("change", [
    lambda data: data["routers"][1].update(routerId="home"),
    lambda data: data["routers"][1].update(workerPort=58501),
    lambda data: data["routers"][1].update(platform="agent_only"),
    lambda data: data["routers"][1].pop("ewebUrl"),
    lambda data: data["routers"][1].update(ewebUrl="http://192.168.5.1"),
    lambda data: data["routers"][1].update(ewebUrl="http://192.168.5.1:80"),
    lambda data: data["routers"][1].update(ewebUrl="http://192.168.6.1:0"),
    lambda data: data["routers"][1].pop("routerId"),
])
def test_invalid_router_config_is_rejected(tmp_path, change):
    path, data = _config(tmp_path)
    change(data)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValueError):
        gateway.load_gateway_config(path, SECRETS)


def test_duplicate_or_placeholder_secrets_are_rejected(tmp_path):
    path, _ = _config(tmp_path)
    with pytest.raises(ValueError):
        gateway.load_gateway_config(path, {**SECRETS, "OFFICE_APP": SECRETS["HOME_APP"]})
    with pytest.raises(ValueError):
        gateway.load_gateway_config(path, {**SECRETS, "OFFICE_APP": "replace-me"})


def test_registry_requires_default_app_token_and_never_exposes_worker_secrets(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    monkeypatch.setattr(gateway, "router_list", lambda _: {
        "ok": True, "defaultRouterId": "home",
        "routers": [{"routerId": "office", "basePath": "/r/office", "online": True}],
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.make_registry_handler(config))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/api/routers"
    try:
        for token in ("", SECRETS["OFFICE_APP"], SECRETS["HOME_HOOK"]):
            with pytest.raises(HTTPError) as error:
                urlopen(Request(url, headers={"Authorization": f"Bearer {token}"}), timeout=2)
            assert error.value.code == 401
        with urlopen(Request(url, headers={"Authorization": f"Bearer {SECRETS['HOME_APP']}"}), timeout=2) as response:
            body = response.read().decode("utf-8")
            assert response.headers["Cache-Control"] == "no-store"
        assert json.loads(body)["routers"][0]["basePath"] == "/r/office"
        assert all(secret not in body for secret in SECRETS.values())
    finally:
        server.shutdown()
        server.server_close()


def test_router_list_includes_count_only_when_known(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    home, office = config["routers"]
    (home["root"] / "data").mkdir(parents=True)
    (home["root"] / "data" / "devices.json").write_text('{"total":12,"onlineDeviceCount":5}', encoding="utf-8")
    monkeypatch.setattr(gateway, "urlopen", lambda *_args, **_kwargs: _HealthyResponse())
    monkeypatch.setattr(gateway, "eweb_reachable", lambda router: router["routerId"] == "home")
    rows = gateway.router_list(config)["routers"]
    assert rows[0]["deviceCount"] == 12
    assert rows[0]["onlineDeviceCount"] == 5
    assert "deviceCount" not in rows[1]
    assert "onlineDeviceCount" not in rows[1]
    assert rows[1]["platform"] == "reyee"
    assert rows[0]["online"] is True
    assert rows[1]["online"] is False
    assert rows[1]["hubOnline"] is True
    assert rows[1]["ewebReachable"] is False


def test_gateway_prefers_worker_device_counts_over_stale_file(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    home = config["routers"][0]
    (home["root"] / "data").mkdir(parents=True)
    (home["root"] / "data" / "devices.json").write_text(
        '{"total":10,"onlineDeviceCount":10}', encoding="utf-8"
    )

    class WorkerResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self):
            return b'{"routers":[{"deviceCount":25,"onlineDeviceCount":9}]}'

    def fake_urlopen(request, **_kwargs):
        assert request.get_header("Authorization") == f"Bearer {home['appToken']}"
        return WorkerResponse()

    monkeypatch.setattr(gateway, "urlopen", fake_urlopen)
    assert gateway._device_counts(home) == {"deviceCount": 25, "onlineDeviceCount": 9}


class _HealthyResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass


def test_optional_local_tunnel_requires_a_distinct_loopback_port(tmp_path):
    path, data = _config(tmp_path)
    data["routers"][1]["ewebTransport"] = "local_tunnel"
    data["routers"][1]["ewebUrl"] = "http://127.0.0.1:18082"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    configured = gateway.load_gateway_config(path, SECRETS)
    assert configured["routers"][1]["ewebHost"] == "127.0.0.1"
    assert configured["routers"][1]["ewebPort"] == 18082
    data["routers"][1]["ewebUrl"] = "http://192.168.6.1:18082"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValueError):
        gateway.load_gateway_config(path, SECRETS)


def test_managed_router_config_cannot_override_gateway_eweb(monkeypatch, tmp_path):
    from router_rpc import EncryptedRouterConfigStore

    monkeypatch.setenv("APP_TOKEN", "test-configuration-key")
    store = EncryptedRouterConfigStore(tmp_path)
    store.save("http://192.168.5.1", "router-secret", 3600)
    monkeypatch.setenv("MULTI_ROUTER_LOCK_EWEB", "1")
    monkeypatch.setenv("ROUTER_EWEB_URL", "http://192.168.6.1")
    assert store.load()["address"] == "http://192.168.6.1"


def test_default_switch_persists_and_requires_management_token(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    applied = []
    controller = gateway.DefaultRouterController(
        config, tmp_path / "default-router.json", lambda view: applied.append(view["defaultRouterId"]),
    )
    monkeypatch.setattr(gateway, "router_list", lambda view: {
        "ok": True, "defaultRouterId": view["defaultRouterId"], "routers": [],
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.make_registry_handler(config, controller))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    def change(token, router_id):
        return urlopen(Request(url + "/api/routers/default",
            data=json.dumps({"routerId": router_id}).encode(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}), timeout=2)
    try:
        with pytest.raises(HTTPError) as denied:
            change(SECRETS["OFFICE_APP"], "office")
        assert denied.value.code == 401
        with change(SECRETS["HOME_APP"], "office") as response:
            assert json.load(response)["defaultRouterId"] == "office"
        assert applied == ["office"]
        assert gateway.DefaultRouterController(config, tmp_path / "default-router.json").current_id == "office"
        with urlopen(Request(url + "/api/routers", headers={"Authorization": f"Bearer {SECRETS['HOME_APP']}"}), timeout=2) as response:
            assert json.load(response)["defaultRouterId"] == "office"
        with pytest.raises(HTTPError) as invalid:
            change(SECRETS["HOME_APP"], "unknown")
        assert invalid.value.code == 400
        assert controller.current_id == "office"
    finally:
        server.shutdown()
        server.server_close()


def test_failed_default_route_application_preserves_previous_default(tmp_path):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    def reject(_view):
        raise RuntimeError("nginx reload failed")
    controller = gateway.DefaultRouterController(config, tmp_path / "default-router.json", reject)
    with pytest.raises(RuntimeError):
        controller.set_default("office")
    assert controller.current_id == "home"
    assert not controller.state_path.exists()
    assert "location / { proxy_pass http://127.0.0.1:58502; }" in gateway.render_nginx_config(
        {**config, "defaultRouterId": "office"}, Path("/tmp/nginx.pid"))
