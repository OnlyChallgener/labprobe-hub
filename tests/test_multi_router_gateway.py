import json
import os
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
    assert 'log_format labprobe_without_query' in rendered
    assert '"$request_method $uri $server_protocol"' in rendered
    assert "access_log /dev/stdout labprobe_without_query;" in rendered
    assert '"$request "' not in rendered
    # A location that declares any proxy_set_header stops inheriting the server-level
    # ones, so the credential rewrite used to leave the WebSocket upgrade headers behind
    # and every /r/<id>/ channel answered the handshake with 400 while a direct worker
    # request returned 101. Assert them per location, not somewhere in the text.
    for router_id in ("home", "office"):
        block = rendered.split(f"location ^~ /r/{router_id}/ {{")[1].split("\n    }")[0]
        for header in ("Upgrade $http_upgrade", "Connection $connection_upgrade",
                       "Host $http_host", "X-Forwarded-Proto $scheme",
                       "X-Real-IP $remote_addr", "X-Forwarded-For"):
            assert header in block, (router_id, header)
    # G1 moves the worker credential into the rendered file on purpose: the front door
    # authenticates once and carries each worker's own credential inward. Hooks stay out.
    assert SECRETS["HOME_HOOK"] not in rendered
    assert SECRETS["OFFICE_HOOK"] not in rendered


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


def test_registry_accepts_any_worker_app_token_and_rejects_every_hook(tmp_path, monkeypatch):
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
        # A device credential must never reach the management surface, whichever router it
        # belongs to; only APP secrets do.
        for token in ("", SECRETS["HOME_HOOK"], SECRETS["OFFICE_HOOK"]):
            with pytest.raises(HTTPError) as error:
                urlopen(Request(url, headers={"Authorization": f"Bearer {token}"}), timeout=2)
            assert error.value.code == 401
        for token in (SECRETS["HOME_APP"], SECRETS["OFFICE_APP"]):
            with urlopen(Request(url, headers={"Authorization": f"Bearer {token}"}), timeout=2) as response:
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
        # A device credential must not move the global default, while any owner-level APP key
        # may - including one the user originally saved for the other router.
        with pytest.raises(HTTPError) as denied:
            change(SECRETS["OFFICE_HOOK"], "office")
        assert denied.value.code == 401
        with change(SECRETS["OFFICE_APP"], "office") as response:
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


def _router_block(rendered: str, router_id: str) -> str:
    return rendered.split(f"location ^~ /r/{router_id}/ {{")[1].split("    }")[0]


def _map_block(rendered: str, slug: str) -> str:
    return rendered.split(f"  map ${slug}_kind ${slug}_authorization {{")[1].split("  }")[0]


def test_front_door_gates_each_channel_and_rewrites_only_management_credentials(tmp_path):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    rendered = gateway.render_nginx_config(config, Path("/tmp/nginx.pid"))
    assert "location ^~ /_gateauth/ {" in rendered
    assert "internal;" in rendered
    assert "proxy_pass_request_body off;" in rendered
    assert 'proxy_set_header Content-Length "";' in rendered
    assert "proxy_set_header Authorization $http_authorization;" in rendered
    assert "proxy_set_header X-LabProbe-Token $http_x_labprobe_token;" in rendered
    assert "proxy_set_header X-LabProbe-Original-Args $args;" in rendered
    assert "proxy_set_header X-LabProbe-Original-URI $request_uri;" in rendered
    assert "location @denied {" in rendered
    for router_id, token in (("home", SECRETS["HOME_APP"]), ("office", SECRETS["OFFICE_APP"])):
        slug = "labprobe_" + router_id
        block = _router_block(rendered, router_id)
        assert f"auth_request /_gateauth/{router_id};" in block
        assert f"auth_request_set ${slug}_kind $upstream_http_x_labprobe_auth_kind;" in block
        assert "auth_request_set $labprobe_device_token $upstream_http_x_labprobe_token;" in block
        assert "error_page 401 = @denied;" in block
        # Both header names are rewritten because the realtime WebSocket presents both.
        assert f"proxy_set_header Authorization ${slug}_authorization;" in block
        assert f"proxy_set_header X-LabProbe-Token ${slug}_token;" in block
        assert f'    default "Bearer {token}";' in _map_block(rendered, slug)
        assert '"device" $labprobe_device_token;' in rendered
        assert '    "device" $http_authorization;' in _map_block(rendered, slug)
    assert SECRETS["OFFICE_APP"] not in _map_block(rendered, "labprobe_home")
    assert "Bearer" not in rendered.split("location / {")[1].split("}")[0]


def test_gate_opens_with_management_credential_anywhere_and_worker_credentials_only_themselves(tmp_path):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.make_registry_handler(config))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def outcome(router_id: str, headers: dict) -> tuple[int, str]:
        try:
            with urlopen(Request(f"{base}/_gateauth/{router_id}", headers=headers), timeout=2) as probe:
                return probe.status, probe.headers.get("X-LabProbe-Auth-Kind") or ""
        except HTTPError as error:
            return error.code, ""

    def bearer(token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    try:
        assert outcome("home", bearer(SECRETS["HOME_APP"])) == (200, "management")
        assert outcome("office", bearer(SECRETS["HOME_APP"])) == (200, "management")
        assert outcome("office", bearer(SECRETS["OFFICE_APP"])) == (200, "management")
        # The relay presents HOOK; it must pass through as a device credential so the
        # worker keeps validating it as HOOK instead of receiving an APP secret.
        assert outcome("home", {"X-LabProbe-Token": SECRETS["HOME_HOOK"]}) == (200, "device")
        # Any owner-level APP key opens any channel; a HOOK key only ever opens its own.
        assert outcome("home", bearer(SECRETS["OFFICE_APP"])) == (200, "management")
        assert outcome("office", {"X-LabProbe-Token": SECRETS["HOME_HOOK"]}) == (401, "")
        assert outcome("home", bearer("")) == (401, "")
        assert outcome("home", bearer(SECRETS["HOME_APP"] + "x")) == (401, "")
        assert outcome("ghost", bearer(SECRETS["HOME_APP"])) == (403, "")
    finally:
        server.shutdown()
        server.server_close()


def test_gate_accepts_only_matching_hook_token_from_webhook_query(tmp_path):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.make_registry_handler(config))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urlopen(f"{base}/_gateauth/home?token={SECRETS['HOME_HOOK']}", timeout=2) as response:
            assert response.headers["X-LabProbe-Auth-Kind"] == "device"
            assert response.headers["X-LabProbe-Token"] == SECRETS["HOME_HOOK"]
        with urlopen(Request(f"{base}/_gateauth/home", headers={
            "X-LabProbe-Original-Args": f"token={SECRETS['HOME_HOOK']}",
        }), timeout=2) as response:
            assert response.headers["X-LabProbe-Auth-Kind"] == "device"
        with pytest.raises(HTTPError) as denied:
            urlopen(f"{base}/_gateauth/office?token={SECRETS['HOME_HOOK']}", timeout=2)
        assert denied.value.code == 401
        with urlopen(f"{base}/_routeauth?hook_token={SECRETS['OFFICE_HOOK']}", timeout=2) as response:
            assert response.headers["X-LabProbe-Route"] == "office"
            assert response.headers["X-LabProbe-Token"] == SECRETS["OFFICE_HOOK"]
        with urlopen(Request(f"{base}/_routeauth", headers={
            "X-LabProbe-Original-URI": f"/api/router/status?hook_token={SECRETS['OFFICE_HOOK']}",
        }), timeout=2) as response:
            assert response.headers["X-LabProbe-Route"] == "office"
        with pytest.raises(HTTPError) as app_query:
            urlopen(f"{base}/_routeauth?token={SECRETS['HOME_APP']}", timeout=2)
        assert app_query.value.code == 401
    finally:
        server.shutdown()
        server.server_close()


def test_gate_never_echoes_a_secret_back_to_the_proxy(tmp_path):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.make_registry_handler(config))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/_gateauth/home"
    try:
        request = Request(url, headers={"Authorization": f"Bearer {SECRETS['HOME_APP']}"})
        with urlopen(request, timeout=2) as probe:
            headers = str(probe.headers).lower()
        assert all(secret.lower() not in headers for secret in SECRETS.values())
    finally:
        server.shutdown()
        server.server_close()


def test_secrets_that_could_escape_the_rendered_string_are_rejected(tmp_path):
    path, _ = _config(tmp_path)
    # Leading and trailing whitespace is stripped by the loader, so the hostile
    # character has to sit inside the value to reach the rendered configuration.
    for hostile in ('"', "$", "\\", "`", " ", "\t"):
        with pytest.raises(ValueError):
            gateway.load_gateway_config(path, {**SECRETS, "OFFICE_APP": "A" * 12 + hostile + "A" * 12})
    with pytest.raises(ValueError):
        gateway.load_gateway_config(path, {**SECRETS, "OFFICE_HOOK": "B" * 12 + '"' + "B" * 12})
    loaded = gateway.load_gateway_config(path, {**SECRETS, "OFFICE_APP": "A" * 24 + "_-."})
    assert loaded["routers"][1]["appToken"].endswith("_-.")


@pytest.mark.skipif(os.name != "posix", reason="only the Linux image can represent 0600; the gateway runs there")
def test_rendered_configuration_carries_no_group_or_other_bits(tmp_path):
    target = tmp_path / "nginx.conf"
    gateway.write_nginx_conf(target, "x")
    assert target.stat().st_mode & 0o077 == 0
def test_registry_probes_tolerate_a_cold_worker_but_route_checks_stay_fast(tmp_path, monkeypatch):
    """A worker that needs ~0.3s to boot must not be reported offline, while the eWeb probe
    stays quick because an unreachable router must not slow the whole list down."""
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    home = config["routers"][0]
    seen = []

    class _ColdWorker:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"routers":[{"deviceCount":3,"onlineDeviceCount":1}]}'

    def fake_urlopen(request, timeout=None):
        seen.append(timeout)
        return _ColdWorker()

    monkeypatch.setattr(gateway, "urlopen", fake_urlopen)
    row = gateway._router_row(home)
    assert row["hubOnline"] is True
    assert (row["deviceCount"], row["onlineDeviceCount"]) == (3, 1)
    # Measured worst case on a loaded worker was 1.14s, so the budget must clear it.
    assert seen and all(timeout >= 2.0 for timeout in seen), seen

    tcp = []

    def fake_connect(*_args, **kwargs):
        tcp.append(kwargs.get("timeout"))
        raise OSError("router away")

    monkeypatch.setattr(gateway.socket, "create_connection", fake_connect)
    assert gateway.eweb_reachable(home) is False
    assert tcp and tcp[0] <= 0.5, tcp


def test_registry_preserves_worker_physical_identity_for_phone_card_migration(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)

    class Reply:
        def __enter__(self): return self
        def __exit__(self, *_args): pass
        def read(self):
            return b'{"routers":[{"serialNumber":"g1tq88t702111","deviceCount":26,"onlineDeviceCount":8}]}'

    monkeypatch.setattr(gateway, "urlopen", lambda *args, **kwargs: Reply())
    assert gateway._device_counts(config["routers"][1]) == {
        "serialNumber": "G1TQ88T702111", "deviceCount": 26, "onlineDeviceCount": 8,
    }


def test_root_api_call_is_refused_instead_of_pinning_to_the_default_worker(tmp_path):
    """A root-path API request carrying an owner key cannot name a router, so it must be
    refused rather than forwarded to whichever worker happens to be the default."""
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    rendered = gateway.render_nginx_config(config, Path("/tmp/nginx.pid"))
    marker = "location ^~ /api/ {"
    assert marker in rendered
    block = rendered.split(marker, 1)[1].split("\n    }", 1)[0]
    # The refusal now lives in the named location the credential gate falls through to.
    assert "auth_request /_routeauth;" in block
    assert "error_page 401 = @root_refused;" in block
    refused = rendered.split("location @root_refused {", 1)[1].split("\n    }", 1)[0]
    assert "multi_router_path_required" in refused
    assert "proxy_pass http://127.0.0.1:58501" not in block, "no hard pin to the default worker"
    assert "location = /api/routers" in rendered, "the registry must still answer at the root"
    assert "location / { proxy_pass" in rendered, "/health must stay open for the healthcheck"
    assert rendered.index("location = /api/routers") < rendered.index(marker)


def test_root_api_forwards_a_device_credential_to_its_own_worker_only(tmp_path):
    """Relays keep pushing at the root path, and a HOOK key names exactly one router, so
    the root resolves it there - while an owner key stays refused (see the test above)."""
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    rendered = gateway.render_nginx_config(config, Path("/tmp/nginx.pid"))
    block = rendered.split("location ^~ /api/ {", 1)[1].split("\n    }", 1)[0]
    assert "proxy_pass $labprobe_root_worker;" in block
    # Reading $upstream_http_* straight from the map evaluates to ""; it must be copied
    # out with auth_request_set or nginx answers 500 "invalid URL prefix".
    assert "auth_request_set $labprobe_route $upstream_http_x_labprobe_route;" in block
    assert "auth_request_set $labprobe_device_token $upstream_http_x_labprobe_token;" in block
    assert "proxy_set_header X-LabProbe-Token $labprobe_device_token;" in block
    assert "map $labprobe_route $labprobe_root_worker {" in rendered
    # The credential must reach the worker untouched: each worker enforces its own HOOK,
    # and rewriting it here would hand the relay App-level access.
    assert "proxy_set_header Authorization" not in block
    # Same inheritance trap as /r/<id>/: declaring any header drops the server-level ones.
    for header in ("Host $http_host", "Upgrade $http_upgrade", "Connection $connection_upgrade"):
        assert f"proxy_set_header {header};" in block
    map_block = rendered.split(
        "map $labprobe_route $labprobe_root_worker {", 1,
    )[1].split("\n  }", 1)[0]
    assert "home http://127.0.0.1:58501;" in map_block
    assert "office http://127.0.0.1:58502;" in map_block
    assert '    default "";' in map_block
    for token in SECRETS.values():
        assert token not in map_block


def test_route_auth_names_the_hook_owner_and_never_an_owner_key(tmp_path):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.make_registry_handler(config))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def outcome(method: str, headers: dict) -> tuple[int, str]:
        request = Request(f"{base}/_routeauth", headers=headers, method=method)
        try:
            with urlopen(request, timeout=2) as probe:
                return probe.status, probe.headers.get("X-LabProbe-Route") or ""
        except HTTPError as error:
            return error.code, ""

    try:
        assert outcome("POST", {"Authorization": f"Bearer {SECRETS['HOME_HOOK']}"}) == (200, "home")
        assert outcome("GET", {"X-LabProbe-Token": SECRETS["OFFICE_HOOK"]}) == (200, "office")
        assert outcome("GET", {"X-LabProbe-Original-URI": f"/api/router/status?hook_token={SECRETS['OFFICE_HOOK']}"}) == (200, "office")
        assert outcome("DELETE", {"Authorization": f"Bearer {SECRETS['HOME_HOOK']}"}) == (200, "home")
        # An owner key at the root still cannot say which router the caller meant.
        assert outcome("POST", {"Authorization": f"Bearer {SECRETS['HOME_APP']}"}) == (401, "")
        assert outcome("POST", {"Authorization": f"Bearer {SECRETS['OFFICE_APP']}"}) == (401, "")
        assert outcome("POST", {}) == (401, "")
        assert outcome("POST", {"Authorization": f"Bearer {SECRETS['HOME_HOOK']}x"}) == (401, "")
    finally:
        server.shutdown()
        server.server_close()


def test_nginx_has_exact_global_official_account_location_before_generic_api(tmp_path):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    rendered = gateway.render_nginx_config(config, Path("/tmp/nginx.pid"))
    exact = f"location = {gateway.OFFICIAL_ACCOUNT_PATH} {{ proxy_pass http://127.0.0.1:{config['registryPort']}{gateway.OFFICIAL_ACCOUNT_PATH}; }}"
    generic = "location ^~ /api/ {"
    assert exact in rendered
    assert rendered.index(exact) < rendered.index(generic)


def test_gateway_fans_out_to_workers_concurrently(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    barrier = threading.Barrier(2)

    def reply(router, method, body=None):
        barrier.wait(timeout=2)
        return _official_reply(router, serial=router["routerId"].upper(), project=router["routerId"])

    monkeypatch.setattr(gateway, "_worker_official_call", reply)
    result = gateway.aggregate_official_account(config, "GET")
    assert result["state"] == "authorized" and result["matchedRouterCount"] == 2


def _official_reply(router, *, serial="SN1", project="p1", authorized=True, matched=True,
                    account="o***@example.com", fingerprint="fp1", expire=1893456000000):
    return True, {"ok": True, "authorized": authorized, "serial": serial, "projectId": project,
        "projectName": "Home", "cloudVerified": matched, "routerVerified": matched,
        "account": account, "accountFingerprint": fingerprint, "expireTime": expire}


def test_gateway_partial_offline_counts_only_unique_verified_projects_and_serials(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)

    def reply(router, method, body=None):
        if router["routerId"] == "office":
            return False, {"ok": False, "errorCode": "worker_offline"}
        return _official_reply(router)

    monkeypatch.setattr(gateway, "_worker_official_call", reply)
    result = gateway.aggregate_official_account(config, "POST", {
        "account": "owner@example.com", "password": "partial-login-password",
    })
    assert result["ok"] and result["state"] == "partial" and result["hubAuthorization"] == "partial"
    assert result["authorized"] and result["projectCount"] == result["matchedRouterCount"] == 1
    assert result["account"] == "o***@example.com" and result["expireTime"] == 1893456000000
    assert result["routers"][0]["matched"] and result["routers"][0]["syncState"] == "synced"
    assert result["routers"][1]["online"] is False and result["routers"][1]["syncState"] == "offline"
    assert not result["routers"][1]["matched"] and "error" in result["routers"][1]
    assert "password" not in json.dumps(result) and "token" not in json.dumps(result)


def test_gateway_logout_reports_local_clear_and_remote_partial_failure(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)

    def reply(router, method, body=None):
        if router["routerId"] == "home":
            return True, {"ok": True, "authorized": False, "serial": "SN1", "localCleared": True}
        return True, {"ok": False, "authorized": False, "serial": "SN2", "localCleared": True,
                      "errorCode": "official_logout_failed", "error": "cloud logout failed"}

    monkeypatch.setattr(gateway, "_worker_official_call", reply)
    result = gateway.aggregate_official_account(config, "DELETE")
    assert result["ok"] is False and result["state"] == "partial"
    assert result["localCleared"] is True and result["authorized"] is False
    assert result["remoteRevocation"] == "partial" and result["operationState"] == "partial_failure"
    assert result["retrySafe"] is False
    assert result["routers"][0]["remoteRevocation"] == "confirmed"
    assert result["routers"][1]["remoteRevocation"] == "failed"
    assert result["routers"][1]["localCleared"] is True
    assert result["errors"] == [{"routerId": "office", "errorCode": "official_logout_failed",
        "error": gateway._official_error_text("official_logout_failed"),
        "operationState": "failed", "retrySafe": False}]


def test_gateway_codeless_logout_failure_is_not_confirmed(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)

    def reply(router, method, body=None):
        return True, {"ok": False, "authorized": False, "serial": "SN1", "localCleared": True}

    monkeypatch.setattr(gateway, "_worker_official_call", reply)
    result = gateway.aggregate_official_account(config, "DELETE")
    assert result["ok"] is False and result["state"] == "failed"
    assert result["remoteRevocation"] == "failed" and result["retrySafe"] is False
    assert result["routers"][0]["remoteRevocation"] == "failed"
    assert result["routers"][0]["errorCode"] == "official_logout_failed"


def test_gateway_timeout_is_pending_unknown_and_not_safe_to_retry(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)

    def timeout(*_args, **_kwargs):
        raise TimeoutError("worker still mutating")

    monkeypatch.setattr(gateway, "urlopen", timeout)
    online, reply = gateway._worker_official_call(config["routers"][0], "DELETE")
    assert online and reply["errorCode"] == "worker_timeout"
    assert reply["operationState"] == "pending_unknown" and reply["retrySafe"] is False

    def mixed(router, method, body=None):
        if router["routerId"] == "home":
            return True, {"ok": True, "authorized": False, "serial": "SN1"}
        return online, reply

    monkeypatch.setattr(gateway, "_worker_official_call", mixed)
    result = gateway.aggregate_official_account(config, "DELETE")
    assert result["ok"] is False and result["state"] == "partial"
    assert result["localCleared"] is None  # The timed-out worker's local state is unknown.
    assert result["remoteRevocation"] == "unknown" and result["operationState"] == "pending_unknown"
    assert result["retrySafe"] is False
    assert result["routers"][1]["operationState"] == "pending_unknown"
    assert result["routers"][1]["errorCode"] == "worker_timeout"


def test_gateway_unknown_serial_is_pending_and_sn_mismatch_is_not_matched(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)

    def reply(router, method, body=None):
        if router["routerId"] == "home":
            return _official_reply(router, serial="", authorized=True, matched=True)
        return _official_reply(router, serial="DIFFERENT", project="p2", authorized=False, matched=False)

    monkeypatch.setattr(gateway, "_worker_official_call", reply)
    result = gateway.aggregate_official_account(config, "GET")
    assert result["state"] == "checking" and result["matchedRouterCount"] == result["projectCount"] == 0
    assert result["routers"][0]["syncState"] == "offline"
    assert result["routers"][1]["serialNumber"] == "DIFFERENT"
    assert result["routers"][1]["syncState"] == "failed" and not result["routers"][1]["matched"]


def test_gateway_conflicting_accounts_are_reported_and_counts_are_unique(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)

    def reply(router, method, body=None):
        if router["routerId"] == "home":
            return _official_reply(router, serial="SN1", project="p1", fingerprint="fp1")
        return _official_reply(router, serial="SN1", project="p1", account="a***@example.com", fingerprint="fp2")

    monkeypatch.setattr(gateway, "_worker_official_call", reply)
    result = gateway.aggregate_official_account(config, "GET")
    assert result["state"] == "conflict" and result["hubAuthorization"] == "partial"
    assert result["projectCount"] == result["matchedRouterCount"] == 1


def test_gateway_fanout_uses_each_worker_token_and_keeps_password_only_in_loopback_body(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    seen = []

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self, _amt=None):
            router_id = "home" if ":58501/" in self.url else "office"
            return json.dumps(_official_reply({"routerId": router_id})[1]).encode("utf-8")

    def fake_urlopen(request, timeout=None):
        seen.append((request.full_url, request.get_method(), request.get_header("Authorization"),
                     request.data, timeout))
        reply = Reply()
        reply.url = request.full_url
        return reply

    monkeypatch.setattr(gateway, "urlopen", fake_urlopen)
    password = "loopback-only-password"
    gateway.aggregate_official_account(config, "POST", {"account": "owner@example.com", "password": password})
    gateway.aggregate_official_account(config, "POST", {"action": "refresh"})
    gateway.aggregate_official_account(config, "GET")
    gateway.aggregate_official_account(config, "DELETE")
    assert len(seen) == 8
    for router in config["routers"]:
        calls = [row for row in seen if row[2] == f"Bearer {router['appToken']}"]
        assert len(calls) == 4
        assert all(row[4] == gateway.OFFICIAL_WORKER_TIMEOUT_SEC for row in calls)
        assert all(str(router["workerPort"]) in row[0] and row[0].startswith("http://127.0.0.1:") for row in calls)
    assert sum(password.encode() in (row[3] or b"") for row in seen) == 2
    assert all(b"password" not in (row[3] or b"") for row in seen if password.encode() not in (row[3] or b""))
    assert all(row[0].endswith("/api/official-account?verify=1") for row in seen if row[1] == "GET")
    assert all(row[3] is None for row in seen if row[1] == "DELETE")
    assert all(password.encode() not in path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())


def test_logout_registry_returns_multistatus_for_remote_failure(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    monkeypatch.setattr(gateway, "aggregate_official_account", lambda *_args, **_kwargs: {
        "ok": False, "localCleared": True, "remoteRevocation": "failed", "routers": [],
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.make_registry_handler(config))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    request = Request(f"http://127.0.0.1:{server.server_port}{gateway.OFFICIAL_ACCOUNT_PATH}",
        headers={"Authorization": f"Bearer {SECRETS['HOME_APP']}"}, method="DELETE")
    try:
        with urlopen(request, timeout=2) as response:
            assert response.status == 207
            body = json.load(response)
        assert body["ok"] is False and body["localCleared"] is True
        assert body["remoteRevocation"] == "failed"
    finally:
        server.shutdown()
        server.server_close()


def test_official_account_registry_accepts_any_app_and_rejects_hooks_for_every_method(tmp_path, monkeypatch):
    config = gateway.load_gateway_config(_config(tmp_path)[0], SECRETS)
    calls = []

    def aggregate(_config, method, body=None):
        calls.append((method, body))
        return {"ok": True, "account": "o***@example.com", "authorized": False, "state": "unauthorized",
                "projectCount": 0, "matchedRouterCount": 0, "hubAuthorization": "unauthorized", "routers": []}

    monkeypatch.setattr(gateway, "aggregate_official_account", aggregate)
    server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.make_registry_handler(config))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}{gateway.OFFICIAL_ACCOUNT_PATH}"

    def send(method, token, body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Authorization": f"Bearer {token}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        return urlopen(Request(url, data=data, headers=headers, method=method), timeout=2)

    try:
        for method in ("GET", "POST", "DELETE"):
            for token in ("", SECRETS["HOME_HOOK"], SECRETS["OFFICE_HOOK"]):
                with pytest.raises(HTTPError) as denied:
                    send(method, token, {"action": "refresh"} if method == "POST" else None)
                assert denied.value.code == 401
        assert calls == []
        for method in ("GET", "POST", "DELETE"):
            body = {"account": "owner@example.com", "password": "registry-memory-only"} if method == "POST" else None
            with send(method, SECRETS["OFFICE_APP"], body) as response:
                payload = response.read().decode("utf-8")
                assert response.status == 200 and response.headers["Cache-Control"] == "no-store"
                assert "registry-memory-only" not in payload and all(token not in payload for token in SECRETS.values())
        assert calls[0] == ("GET", None)
        assert calls[1][0] == "POST" and calls[1][1]["password"] == "registry-memory-only"
        assert calls[2] == ("DELETE", None)
    finally:
        server.shutdown()
        server.server_close()
