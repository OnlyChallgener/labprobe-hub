import base64
import json
from types import SimpleNamespace

from flask import Flask
import pytest

import https_service
from https_core import validate_certificate_bundle
from https_service import HttpsError, HttpsService, register_https_service


class FakeProcess:
    def __init__(self, returncode=None):
        self.returncode = returncode

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        self.returncode = 0


def make_service(tmp_path, **kwargs):
    options = {
        "hub_port": 58443,
        "mqtt_upstream": "http://127.0.0.1:9001",
    }
    options.update(kwargs)
    return HttpsService(tmp_path / "https", **options)


def allow_self_signed(monkeypatch):
    monkeypatch.setattr(
        https_service,
        "validate_certificate_bundle",
        lambda cert, key, domain: validate_certificate_bundle(cert, key, domain, verify_chain=False),
    )


def test_invalid_saved_config_does_not_prevent_service_construction(tmp_path):
    root = tmp_path / "https"
    root.mkdir()
    (root / "config.json").write_text('{"port":"invalid","enabled":false}', encoding="utf-8")

    service = make_service(tmp_path)

    assert service.status(include_process=False)["port"] == 58445
    assert "端口无效" in service.status(include_process=False)["lastError"]


def test_private_key_material_is_never_persisted_or_returned(tmp_path):
    service = make_service(tmp_path)
    service.config["certificate"] = {
        "fingerprint": "abc",
        "domains": ["hub.example.com"],
        "privateKey": "secret-private-key",
        "keyPem": "secret-key-pem",
    }
    service.config["privateKey"] = "top-secret"
    service._persist_config()

    status_text = json.dumps(service.status(include_process=False))
    config_text = service.config_path.read_text(encoding="utf-8")
    assert "secret-private-key" not in status_text
    assert "secret-key-pem" not in status_text
    assert "top-secret" not in config_text
    assert "secret-private-key" not in config_text


def test_configuration_rejects_port_conflicts_and_rolls_back(tmp_path):
    service = make_service(tmp_path)

    for port in (58443, 1883, 9001):
        with pytest.raises(HttpsError) as caught:
            service.configure({"domain": "hub.example.com", "port": port})
        assert caught.value.code == "https_port_conflict"
        assert service.config["port"] == 58445
        assert service.config["domain"] == ""
        assert service.config["enabled"] is False

    status = service.configure({"domain": "hub.example.com", "port": 58445, "source": "manual"})
    assert status["enabled"] is False
    assert status["domain"] == "hub.example.com"
    assert service.config_path.exists()


def test_enable_requires_domain_and_imported_certificate(tmp_path):
    service = make_service(tmp_path)
    with pytest.raises(HttpsError) as caught:
        service.set_enabled(True)
    assert caught.value.code == "https_domain_required"

    service.configure({"domain": "hub.example.com"})
    with pytest.raises(HttpsError) as caught:
        service.set_enabled(True)
    assert caught.value.code == "https_certificate_required"


def test_import_enable_disable_and_public_urls(tmp_path, monkeypatch, https_certificate):
    cert, key = https_certificate
    allow_self_signed(monkeypatch)
    service = make_service(tmp_path)
    service.configure({"domain": "hub.example.com", "source": "manual"})
    status = service.import_manual(cert.decode(), key.decode())
    fingerprint = status["certificate"]["fingerprint"]

    service.process = FakeProcess()
    monkeypatch.setattr(service, "_local_probe", lambda **kwargs: SimpleNamespace(peer_fingerprint=fingerprint))
    monkeypatch.setattr(service, "_apply_release_locked", lambda *args: None)

    enabled = service.set_enabled(True)
    assert enabled["running"] is True
    assert enabled["publicUrl"] == "https://hub.example.com:58445"
    assert enabled["realtimeUrl"] == "wss://hub.example.com:58445/api/realtime/ws"
    assert enabled["mqttUrl"] == "wss://hub.example.com:58445/mqtt"

    disabled = service.set_enabled(False)
    assert disabled["running"] is False
    assert disabled["publicUrl"] == ""


def test_failed_reload_keeps_previous_configuration(tmp_path, monkeypatch, https_certificate):
    cert, key = https_certificate
    allow_self_signed(monkeypatch)
    service = make_service(tmp_path)
    service.configure({"domain": "hub.example.com", "source": "manual"})
    service.import_manual(cert.decode(), key.decode())
    previous_release = service.config["release"]

    def fail_apply(*args):
        raise HttpsError("reload failed", 503, "https_reload_failed")

    monkeypatch.setattr(service, "_apply_release_locked", fail_apply)
    with pytest.raises(HttpsError):
        service.configure({"domain": "new.example.com", "enabled": True})

    assert service.config["domain"] == "hub.example.com"
    assert service.config["release"] == previous_release
    assert service.config["enabled"] is False


def test_nginx_reload_verification_failure_restores_previous_config(tmp_path, monkeypatch):
    service = make_service(tmp_path)
    service.nginx_bin = str(tmp_path / "nginx")
    https_service.Path(service.nginx_bin).write_text("fake", encoding="utf-8")
    config_path = service._nginx_config_path()
    config_path.write_bytes(b"old config")
    monkeypatch.setattr(service, "_validate_nginx_config", lambda text: None)
    monkeypatch.setattr(https_service.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(service, "_local_probe", lambda: SimpleNamespace(peer_fingerprint="old"))
    times = iter((0, 0, 9))
    monkeypatch.setattr(https_service.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(https_service.time, "sleep", lambda _: None)

    with pytest.raises(HttpsError) as caught:
        service._reload_nginx_locked(b"new config", "new")

    assert caught.value.code == "https_verify_failed"
    assert config_path.read_bytes() == b"old config"


def test_startup_probe_checks_tls_before_http_server_exists(tmp_path, monkeypatch):
    service = make_service(tmp_path)
    service.nginx_bin = str(tmp_path / "nginx")
    https_service.Path(service.nginx_bin).write_text("fake", encoding="utf-8")
    service.config["domain"] = "hub.example.com"
    process = FakeProcess()
    paths = []

    monkeypatch.setattr(service, "_validate_nginx_config", lambda text: None)
    monkeypatch.setattr(https_service.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        https_service,
        "probe_tls",
        lambda host, port, domain, **kwargs: paths.append(kwargs.get("path")) or SimpleNamespace(peer_fingerprint="abc"),
    )

    service._start_nginx_locked(b"config")

    assert paths == [""]
    assert service.process is process


def test_delete_certificate_disables_https_and_keeps_source_files(tmp_path, monkeypatch, https_certificate):
    cert, key = https_certificate
    allow_self_signed(monkeypatch)
    service = make_service(tmp_path)
    source_cert = service.import_root / "fullchain.pem"
    source_key = service.import_root / "privkey.pem"
    source_cert.write_bytes(cert)
    source_key.write_bytes(key)
    service.configure({"domain": "hub.example.com", "source": "local"})
    service.import_local("fullchain.pem", "privkey.pem")
    service.process = FakeProcess()
    monkeypatch.setattr(service, "_stop_nginx_locked", lambda: setattr(service, "process", None))

    status = service.delete_certificate()

    assert status["enabled"] is False
    assert status["certificate"] == {}
    assert status["release"] == ""
    assert source_cert.read_bytes() == cert
    assert source_key.read_bytes() == key
    assert not any(service.releases.iterdir())


class FakeHub:
    def __init__(self, admin_token):
        self.app = Flask(__name__)
        self.app.testing = True
        self.PORT = 58443
        self.MQTT_INTERNAL_HOST = "127.0.0.1"
        self.LOGGER = SimpleNamespace(warning=lambda *args: None)
        self.admin_token = admin_token

    def check_app_token(self):
        from flask import request
        return request.headers.get("Authorization") == "Bearer app-token"

    def cfg_get(self, key, default=""):
        return self.admin_token if key == "server.https_admin_token" else default


def test_management_api_requires_app_token_and_explicit_admin_authorization(tmp_path, monkeypatch):
    monkeypatch.delenv("HTTPS_ADMIN_TOKEN", raising=False)
    hub = FakeHub("admin-secret")
    service = register_https_service(hub, tmp_path / "https")
    client = hub.app.test_client()
    auth = {"Authorization": "Bearer app-token"}

    assert client.get("/api/https/status").status_code == 401
    assert client.get("/api/https/status", headers=auth).status_code == 200
    denied = client.post("/api/https/config", headers=auth, json={"domain": "hub.example.com"})
    assert denied.status_code == 403
    assert denied.get_json()["errorCode"] == "admin_token_required"
    wrong = client.post(
        "/api/https/config",
        headers={**auth, "X-LabProbe-Admin-Token": "wrong"},
        json={"domain": "hub.example.com"},
    )
    assert wrong.status_code == 403
    accepted = client.post(
        "/api/https/config",
        headers={**auth, "X-LabProbe-Admin-Token": "admin-secret"},
        json={"domain": "hub.example.com", "source": "manual"},
    )
    assert accepted.status_code == 200
    assert accepted.get_json()["enabled"] is False
    assert "privateKey" not in accepted.get_data(as_text=True)
    service.shutdown()


def test_management_api_uses_confirmation_header_without_stronger_token(tmp_path, monkeypatch):
    monkeypatch.delenv("HTTPS_ADMIN_TOKEN", raising=False)
    hub = FakeHub("")
    service = register_https_service(hub, tmp_path / "https")
    client = hub.app.test_client()
    auth = {"Authorization": "Bearer app-token"}

    assert client.post("/api/https/config", headers=auth, json={"domain": "hub.example.com"}).status_code == 403
    response = client.post(
        "/api/https/config",
        headers={**auth, "X-LabProbe-Confirm": "https-management"},
        json={"domain": "hub.example.com"},
    )
    assert response.status_code == 200
    service.shutdown()


def test_private_key_upload_requires_https_but_local_import_and_delete_work_over_http(tmp_path, monkeypatch, https_certificate):
    cert, key = https_certificate
    allow_self_signed(monkeypatch)
    monkeypatch.delenv("HTTPS_ADMIN_TOKEN", raising=False)
    hub = FakeHub("")
    service = register_https_service(hub, tmp_path / "https")
    client = hub.app.test_client()
    headers = {
        "Authorization": "Bearer app-token",
        "X-LabProbe-Confirm": "https-management",
    }
    body = {
        "domain": "hub.example.com",
        "certificateBase64": base64.b64encode(cert).decode(),
        "keyBase64": base64.b64encode(key).decode(),
    }

    rejected = client.post("/api/https/import/manual", headers=headers, json=body)
    assert rejected.status_code == 400
    assert rejected.get_json()["errorCode"] == "https_required_for_private_key"

    accepted = client.post(
        "/api/https/import/manual",
        headers={**headers, "X-Forwarded-Proto": "https"},
        json=body,
    )
    assert accepted.status_code == 200
    assert accepted.get_json()["certificate"]["fingerprint"]

    service.import_root.joinpath("fullchain.pem").write_bytes(cert)
    service.import_root.joinpath("privkey.pem").write_bytes(key)
    local = client.post("/api/https/import/local", headers=headers, json={
        "domain": "hub.example.com", "certPath": "fullchain.pem", "keyPath": "privkey.pem",
    })
    assert local.status_code == 200

    deleted = client.delete("/api/https/certificate", headers=headers)
    assert deleted.status_code == 200
    assert deleted.get_json()["certificate"] == {}
    assert deleted.get_json()["enabled"] is False
    service.shutdown()
