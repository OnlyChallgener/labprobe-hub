from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest
from flask import Flask

from assistant.api import create_ai_blueprint
from assistant.provider import ProviderError, usage_from_chunk
from assistant.security import MasterKeyUnavailable, encrypt_secret
from assistant.storage import AIStore
from assistant.catalog import CATALOG_REVISION


def make_client(tmp_path, monkeypatch, authorized=True, hub_runtime=None):
    monkeypatch.setenv("LABPROBE_AI_MASTER_KEY", "test-master-key")
    app = Flask(__name__)
    app.register_blueprint(create_ai_blueprint(
        check_app_token=lambda: authorized,
        db_path=tmp_path / "ai.db",
        logger=None,
        hub_runtime=hub_runtime,
    ))
    return app.test_client()


def fake_hub(tmp_path):
    devices_file = tmp_path / "devices.json"
    portmap_status_file = tmp_path / "portmap-status.json"
    devices_file.write_text(json.dumps({
        "updatedAt": "2026-08-23 10:00:00",
        "online": [{"name": "Mate60", "mac": "AA:BB:CC:DD:EE:01", "ipv6List": ["240e::60"]}],
        "watched": [{"name": "ANS", "mac": "AA:BB:CC:DD:EE:02", "online": False}],
    }), encoding="utf-8")
    portmap_status_file.write_text("{}", encoding="utf-8")

    def load_json(path, default):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return default

    runtime = SimpleNamespace(
        DEVICES_FILE=devices_file,
        PORTMAP_ROUTER_STATUS_FILE=portmap_status_file,
        load_json=load_json,
        load_device_archive=lambda: {},
        normalize_ipv6_list=lambda value: value if isinstance(value, list) else [value],
        status_document=lambda: {"hub": {"name": "test"}},
        aggregate_daily=lambda day: {"date": day, "summary": {}},
        _load_portmap_rules_document=lambda: ({"rules": []}, True),
        send_wol=lambda mac: {"ok": True, "mac": mac, "sent": 3},
    )
    return runtime


def test_config_masks_key_and_never_echoes_it(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    secret = "sk-never-appear-in-response"
    response = client.put("/api/ai/config", json={"apiKey": secret})
    assert response.status_code == 200
    assert secret not in response.get_data(as_text=True)
    assert response.json["apiKey"] == "configured"
    assert secret.encode() not in (tmp_path / "ai.db").read_bytes()


def test_derives_credential_key_from_required_app_token(monkeypatch):
    monkeypatch.delenv("LABPROBE_AI_MASTER_KEY", raising=False)
    monkeypatch.setenv("APP_TOKEN", "long-app-token")
    assert encrypt_secret("sk-secret").startswith("v1:")


def test_rejects_persistent_plaintext_when_no_hub_secret_exists(monkeypatch):
    monkeypatch.delenv("LABPROBE_AI_MASTER_KEY", raising=False)
    monkeypatch.delenv("APP_TOKEN", raising=False)
    with pytest.raises(MasterKeyUnavailable):
        encrypt_secret("sk-secret")


def test_usage_parsing_handles_deepseek_stream_usage():
    assert usage_from_chunk({"usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}}) == {
        "prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7,
    }
    assert usage_from_chunk({"choices": []}) is None
    assert usage_from_chunk({"usage": {"total_tokens": 7}}) == {"total_tokens": 7}


def test_usage_returns_bounded_recent_task_details(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    for index in range(102):
        store.add_usage(
            f"conversation-{index}", "deepseek", "deepseek-v4-flash",
            {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        )
    response = client.get("/api/ai/usage?limit=1000")
    assert response.status_code == 200
    assert response.json["requests"] == 102
    assert len(response.json["recent"]) == 100
    newest = response.json["recent"][0]
    assert set(newest) == {
        "id", "conversation_id", "provider", "model", "prompt_tokens", "completion_tokens",
        "total_tokens", "status", "usage_known", "created_at",
    }
    assert newest["conversation_id"] == "conversation-101"


def test_chat_returns_configuration_error_status(monkeypatch, tmp_path):
    client = make_client(tmp_path, monkeypatch)
    assert client.post("/api/ai/chat", json={"message": "hello"}).status_code == 409


def test_config_requires_auth(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, authorized=False)
    assert client.get("/api/ai/config").status_code == 401


def test_config_rejects_non_local_http_and_accepts_localhost(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.put("/api/ai/config", json={"apiKey": "sk-a", "baseUrl": "http://provider.test"}).status_code == 400
    assert client.put("/api/ai/config", json={"apiKey": "sk-a", "baseUrl": "http://localhost:11434/v1"}).status_code == 200


def test_config_update_keeps_existing_secret_and_reports_enabled(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.put("/api/ai/config", json={"apiKey": "sk-a"}).status_code == 200
    response = client.put("/api/ai/config", json={"model": "deepseek-v4-pro", "enabled": False})
    assert response.status_code == 200
    assert response.json["enabled"] is False and response.json["apiKey"] == "configured"
    assert client.post("/api/ai/test").status_code == 409


def test_test_endpoint_returns_sanitized_provider_result(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.put("/api/ai/config", json={"apiKey": "sk-a"})

    class FakeProvider:
        def __init__(self, *args, **kwargs):
            pass

        def chat(self, messages):
            from assistant.provider import ChatResult
            return ChatResult("OK", {"total_tokens": 2})

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", FakeProvider)
    response = client.post("/api/ai/test")
    assert response.status_code == 200
    assert response.json == {"status": "ok", "usage": {"total_tokens": 2}}


def test_message_limits_are_enforced(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.post("/api/ai/chat", json={"messages": [{"role": "user", "content": "x" * 32001}]}).status_code == 413


def test_usage_summary_exposes_today_totals(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    response = client.get("/api/ai/usage")
    assert response.status_code == 200
    assert response.json["today_requests"] == 0
    assert response.json["today_total_tokens"] == 0


def test_conversation_history_and_date_usage_are_persisted(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    from assistant.storage import AIStore

    store = AIStore(tmp_path / "ai.db")
    store.create_conversation("conversation-1", "测试")
    store.add_message("conversation-1", "user", "你好")
    store.add_message("conversation-1", "assistant", "你好！")
    store.add_usage("conversation-1", "deepseek", "deepseek-v4-flash", {
        "prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5,
    })
    assert client.get("/api/ai/conversations").json["conversations"][0]["id"] == "conversation-1"
    assert client.get("/api/ai/conversations/conversation-1/messages").json["messages"][0]["content"] == "你好"
    shanghai = timezone(timedelta(hours=8))
    usage = store.usage_for_date(datetime.now(timezone.utc).astimezone(shanghai).date().isoformat())
    assert usage["total_tokens"] == 5


def test_catalog_is_authenticated_and_versioned(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    response = client.get("/api/ai/catalog")
    assert response.status_code == 200
    assert response.json["revision"] == CATALOG_REVISION
    wol = next(tool for tool in response.json["tools"] if tool["id"] == "device.wol")
    assert wol["risk"] == "write"
    assert wol["confirmation"] == "always"


def test_read_tool_resolves_device_ipv6_from_hub_cache(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, hub_runtime=fake_hub(tmp_path))
    response = client.post("/api/ai/tools/execute", json={
        "toolId": "device.ipv6", "arguments": {"device": "mate60"},
    })
    assert response.status_code == 200
    assert response.json["result"]["ipv6List"] == ["240e::60"]


def test_write_tool_requires_one_time_confirmation(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, hub_runtime=fake_hub(tmp_path))
    denied = client.post("/api/ai/tools/execute", json={
        "toolId": "device.wol", "arguments": {"device": "ANS"},
    })
    assert denied.status_code == 409
    prepared = client.post("/api/ai/tools/prepare", json={
        "toolId": "device.wol", "arguments": {"device": "ANS"},
    })
    assert prepared.status_code == 200
    confirmation_id = prepared.json["confirmationId"]
    confirmed = client.post("/api/ai/tools/confirm", json={"confirmationId": confirmation_id})
    assert confirmed.status_code == 200
    assert confirmed.json["result"]["mac"] == "AA:BB:CC:DD:EE:02"
    assert client.post("/api/ai/tools/confirm", json={"confirmationId": confirmation_id}).status_code == 409


def test_chat_executes_model_selected_read_tool_and_returns_final_answer(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, hub_runtime=fake_hub(tmp_path))
    assert client.put("/api/ai/config", json={"apiKey": "sk-test"}).status_code == 200

    class FakeToolProvider:
        calls = 0

        def __init__(self, *args, **kwargs):
            pass

        def chat(self, messages, tools=None):
            from assistant.provider import ChatResult
            self.__class__.calls += 1
            if self.__class__.calls == 1:
                assert tools and any(row["function"]["name"] == "device_ipv6" for row in tools)
                return ChatResult("", {"total_tokens": 4}, {
                    "role": "assistant", "content": None,
                    "tool_calls": [{
                        "id": "call-1", "type": "function",
                        "function": {"name": "device_ipv6", "arguments": '{"device":"Mate60"}'},
                    }],
                })
            assert messages[-1]["role"] == "tool"
            return ChatResult("Mate60 的 IPv6 地址是 240e::60。", {"total_tokens": 5}, {
                "role": "assistant", "content": "Mate60 的 IPv6 地址是 240e::60。",
            })

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", FakeToolProvider)
    response = client.post("/api/ai/chat", json={"message": "告诉我 Mate60 的 IPv6 地址"})
    assert response.status_code == 200
    assert "240e::60" in response.json["message"]["content"]
    assert response.json["usage"]["total_tokens"] == 9
    assert response.json["toolExecutions"] == [{"status": "completed", "toolId": "device.ipv6"}]


def test_app_context_is_sanitized_and_local_write_is_one_time_confirmed(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, hub_runtime=fake_hub(tmp_path))
    context = {
        "settings": {"privacyMode": False, "favoriteNetworkMode": "lan", "token": "must-not-pass"},
        "favorites": [{"id": "fav-1", "title": "Home Assistant", "localUrl": "http://192.168.1.2:8123"}],
    }
    settings = client.post("/api/ai/tools/execute", json={
        "toolId": "app.settings.get", "arguments": {}, "clientContext": context,
    })
    assert settings.status_code == 200
    assert settings.json["result"]["settings"] == {"privacyMode": False, "favoriteNetworkMode": "lan"}
    prepared = client.post("/api/ai/tools/prepare", json={
        "toolId": "app.favorite.remove", "arguments": {"favorite": "Home Assistant"}, "clientContext": context,
    })
    assert prepared.status_code == 200
    assert prepared.json["preview"]["executor"] == "app"
    confirmation_id = prepared.json["confirmationId"]
    confirmed = client.post("/api/ai/tools/confirm", json={"confirmationId": confirmation_id})
    assert confirmed.status_code == 200
    assert confirmed.json["clientAction"]["arguments"]["favorite"] == "fav-1"
    assert client.post("/api/ai/tools/confirm", json={"confirmationId": confirmation_id}).status_code == 409


def test_notification_inbox_deduplicates_watched_events_and_daily_summary(tmp_path):
    from assistant.notifications import AssistantNotificationService
    from assistant.storage import AIStore

    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    runtime = SimpleNamespace(
        cfg_get=lambda key, default: [{"name": "ANS", "mac": "AA:BB:CC:DD:EE:02"}],
        norm_mac=lambda value: str(value or "").upper(),
        now_str=lambda: "2026-08-23 22:30:00",
        aggregate_daily=lambda day: {
            "date": day,
            "summary": {"deviceChanges": 1, "deviceOnline": 1, "deviceOffline": 0, "networkChanges": 0},
            "aiUsage": {"requests": 2, "total_tokens": 30},
        },
    )
    service = AssistantNotificationService(runtime, store, logger=None)
    event = {"id": 7, "type": "device_online", "name": "ANS", "mac": "AA:BB:CC:DD:EE:02", "createdAt": "2026-08-23 21:00:00"}
    service.publish_event(event)
    service.publish_event(event)
    service.publish_daily("2026-08-23")
    service.publish_daily("2026-08-23")
    rows = store.list_notifications()
    assert [row["kind"] for row in rows] == ["device", "daily"]
    assert "30 Token" in rows[1]["content"]
