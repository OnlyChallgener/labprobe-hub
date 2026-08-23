from datetime import datetime, timedelta, timezone

import pytest
from flask import Flask

from assistant.api import create_ai_blueprint
from assistant.provider import ProviderError, usage_from_chunk
from assistant.security import MasterKeyUnavailable, encrypt_secret
from assistant.catalog import CATALOG_REVISION


def make_client(tmp_path, monkeypatch, authorized=True):
    monkeypatch.setenv("LABPROBE_AI_MASTER_KEY", "test-master-key")
    app = Flask(__name__)
    app.register_blueprint(create_ai_blueprint(check_app_token=lambda: authorized, db_path=tmp_path / "ai.db", logger=None))
    return app.test_client()


def test_config_masks_key_and_never_echoes_it(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    secret = "sk-never-appear-in-response"
    response = client.put("/api/ai/config", json={"apiKey": secret})
    assert response.status_code == 200
    assert secret not in response.get_data(as_text=True)
    assert response.json["apiKey"] == "configured"
    assert secret.encode() not in (tmp_path / "ai.db").read_bytes()


def test_rejects_persistent_plaintext_when_master_key_missing(monkeypatch):
    monkeypatch.delenv("LABPROBE_AI_MASTER_KEY", raising=False)
    with pytest.raises(MasterKeyUnavailable):
        encrypt_secret("sk-secret")


def test_usage_parsing_handles_deepseek_stream_usage():
    assert usage_from_chunk({"usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}}) == {
        "prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7,
    }
    assert usage_from_chunk({"choices": []}) is None
    assert usage_from_chunk({"usage": {"total_tokens": 7}}) == {"total_tokens": 7}


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
