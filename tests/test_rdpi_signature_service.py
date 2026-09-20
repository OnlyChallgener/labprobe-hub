"""Tests for RDPI signature service: validation, template, and schema checks."""

import json
from pathlib import Path

import pytest
from rdpi_signature_service import (
    STANDARD_RDPI_TEMPLATE,
    delete_rdpi_signature,
    save_router_rdpi_db,
    validate_signature_object,
)
import rdpi_signature_service as service


def test_standard_template_validates_successfully():
    result = validate_signature_object(STANDARD_RDPI_TEMPLATE)
    assert result["index"] == "999-1-1-0"
    assert result["name"] == "自定义应用/新游戏"
    assert result["custom"] is True
    assert len(result["rules"]) == 3
    assert result["rules"][0]["protocol"] == "host"
    assert "*.customgame.com" in result["rules"][0]["hosts"]
    assert result["rules"][1]["protocol"] == "tcp"
    assert result["rules"][1]["payloads"][0]["payload"] == "47 41 4d 45"


def test_validation_rejects_invalid_index():
    invalid_template = {
        "app": {
            "index": "invalid_index_123",
            "name": "Test App",
            "rules": [{"protocol": "tcp", "hosts": ["test.com"]}]
        }
    }
    with pytest.raises(ValueError, match="Invalid RDPI index format"):
        validate_signature_object(invalid_template)


def test_validation_rejects_empty_rules():
    invalid_template = {
        "app": {
            "index": "999-2-1-0",
            "name": "Test App",
            "rules": []
        }
    }
    with pytest.raises(ValueError, match="at least one rule"):
        validate_signature_object(invalid_template)


def test_validation_normalizes_hex_payload():
    template = {
        "index": "950-1-1-0",
        "name": "Hex App",
        "rules": [
            {
                "protocol": "udp",
                "payloads": [
                    {
                        "pos": 0,
                        "payload": "0xAA,0xBB,0xCC"
                    }
                ]
            }
        ]
    }
    result = validate_signature_object(template)
    assert result["rules"][0]["payloads"][0]["payload"] == "aa bb cc"
    assert result["rules"][0]["payloads"][0]["length"] == 3


def test_official_host_protocol_and_optional_fields_are_preserved():
    payload = {
        "index": "999-1-1-0",
        "name": "官方形状",
        "note": "keep this",
        "rules": [{
            "protocol": "host",
            "hosts": ["example.com"],
            "note": "host rule",
        }, {
            "protocol": "tcp",
            "payloads": [{"stage": 0, "pos": 3, "length": 2, "payload": "AA bb"}],
        }],
    }
    result = validate_signature_object(payload)
    assert result["rules"][0]["protocol"] == "host"
    assert result["rules"][0]["note"] == "host rule"
    assert result["rules"][1]["payloads"][0]["stage"] == 0
    assert result["rules"][1]["payloads"][0]["payload"] == "aa bb"


def test_validation_rejects_unknown_protocol_instead_of_turning_it_into_any():
    payload = {
        "index": "999-1-1-0", "name": "bad", "rules": [
            {"protocol": "future-protocol", "hosts": ["example.com"]}
        ]
    }
    with pytest.raises(ValueError, match="Unsupported RDPI protocol"):
        validate_signature_object(payload)


def test_validation_rejects_unknown_fields_and_invalid_payload_length():
    unknown = {
        "index": "999-1-1-0", "name": "bad", "vendorMagic": True,
        "rules": [{"protocol": "tcp", "hosts": ["example.com"]}],
    }
    with pytest.raises(ValueError, match="Unsupported RDPI app fields"):
        validate_signature_object(unknown)

    bad_length = {
        "index": "999-1-1-0", "name": "bad", "rules": [{
            "protocol": "tcp", "payloads": [{"pos": 0, "length": -1, "payload": "aa bb"}]
        }],
    }
    with pytest.raises(ValueError, match="length must be non-negative"):
        validate_signature_object(bad_length)

    with pytest.raises(ValueError, match="payload pos must be non-negative"):
        validate_signature_object({
            "index": "999-1-1-0", "name": "bad", "rules": [{
                "protocol": "tcp", "payloads": [{"pos": 0.5, "payload": "aa"}]
            }],
        })

    with pytest.raises(ValueError, match="http-gets must be a list"):
        validate_signature_object({
            "index": "999-1-1-0", "name": "bad", "rules": [{
                "protocol": "http-gets", "http-gets": [None]
            }],
        })


def test_validation_preserves_official_legacy_declared_length():
    payload = {
        "index": "999-1-1-0", "name": "legacy", "rules": [{
            "protocol": "tcp", "payloads": [{"pos": 0, "length": 10, "payload": "aa bb"}]
        }],
    }
    result = validate_signature_object(payload)
    assert result["rules"][0]["payloads"][0]["length"] == 10


def test_supplied_official_883_rules_round_trip_except_14_empty_placeholders():
    official_db = Path(
        r"D:\Github\LabProbeApp\test\_analysis\extract\rootfs\usr\share\ndpi\db.default.json"
    )
    if not official_db.exists():
        pytest.skip("local official rootfs fixture is unavailable")
    data = json.loads(official_db.read_text(encoding="utf-8"))
    rules = [
        {"index": app["index"], "name": app["name"], "rules": [rule]}
        for app in data["apps"]
        for rule in app.get("rules", [])
    ]
    accepted = []
    rejected = []
    for signature in rules:
        try:
            validate_signature_object(signature)
            accepted.append(signature)
        except ValueError:
            rejected.append(signature)
    assert len(rules) == 883
    assert len(accepted) == 869
    assert len(rejected) == 14


class _FakeChannel:
    def shutdown_write(self):
        return None


class _FakeStdin:
    def __init__(self):
        self.channel = _FakeChannel()

    def write(self, _data):
        return None


class _FakeStream:
    def __init__(self, value=""):
        self.value = value

    def read(self):
        return self.value.encode()


class _FakeClient:
    def __init__(self, readback, reload_error=""):
        self.readback = readback
        self.reload_error = reload_error
        self.closed = False
        self.commands = []

    def exec_command(self, command):
        self.commands.append(command)
        return _FakeStdin(), _FakeStream(), _FakeStream()

    def close(self):
        self.closed = True


def _fake_remote_exec(client, command):
    client.commands.append(command)
    if command == f"cat {service.REMOTE_DB_PATH}":
        return client.readback, ""
    if command == "ubus -t 3 send 'rdpi_reinit'":
        return "", client.reload_error
    return "", ""


def test_save_reads_back_exact_json(monkeypatch):
    db = {"apps": [{"index": "999-1-1-0", "name": "x", "rules": []}], "version": "test"}
    client = _FakeClient(json.dumps(db))
    monkeypatch.setattr(service, "_remote_exec", _fake_remote_exec)
    assert "Saved successfully" in save_router_rdpi_db(db, client=client)
    assert any(f"cat {service.REMOTE_DB_PATH}" == c for c in client.commands)


def test_save_rolls_back_after_hot_reload_failure(monkeypatch):
    db = {"apps": [], "version": "test"}
    client = _FakeClient(json.dumps(db), reload_error="reinit failed")
    monkeypatch.setattr(service, "_remote_exec", _fake_remote_exec)
    with pytest.raises(RuntimeError, match="hot-reload failed"):
        save_router_rdpi_db(db, client=client)
    assert any("rollback" in c and "rdpi_reinit" in c for c in client.commands)


def test_save_rolls_back_after_readback_mismatch(monkeypatch):
    db = {"apps": [], "version": "test"}
    client = _FakeClient('{"apps": [], "version": "old"}')
    monkeypatch.setattr(service, "_remote_exec", _fake_remote_exec)
    with pytest.raises(RuntimeError, match="read-back mismatch"):
        save_router_rdpi_db(db, client=client)
    assert any("rollback" in c and "rdpi_reinit" in c for c in client.commands)


def test_delete_closes_client_without_undefined_close_client(monkeypatch):
    class Client:
        closed = False

        def close(self):
            self.closed = True

    client = Client()
    monkeypatch.setattr(service, "_get_ssh_client", lambda: client)
    monkeypatch.setattr(service, "load_router_rdpi_db", lambda _client: {
        "apps": [{"index": "999-1-1-0", "name": "x", "rules": []}]
    })
    monkeypatch.setattr(service, "save_router_rdpi_db", lambda *_args, **_kwargs: "saved")
    result = delete_rdpi_signature("999-1-1-0")
    assert result["ok"] is True
    assert client.closed is True
