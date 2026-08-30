import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from flask import Flask

from assistant.api import create_ai_blueprint
from assistant.provider import ChatResult, OpenAICompatibleProvider, ProviderError, parse_sse_line, usage_from_chunk
from assistant.security import decrypt_secret, encrypt_secret
from assistant.storage import AIStore
from assistant.tools import ToolError, ToolExecutor


def make_client(tmp_path, monkeypatch, *, master=True, hub_runtime=None):
    if master:
        monkeypatch.setenv("LABPROBE_AI_MASTER_KEY", "hardening-test-master")
    app = Flask(__name__)
    app.register_blueprint(create_ai_blueprint(
        check_app_token=lambda: True,
        db_path=tmp_path / "ai.db",
        logger=None,
        hub_runtime=hub_runtime,
    ))
    return app.test_client()


class FakeResponse:
    ok = True
    text = ""

    def __init__(self, lines):
        self.lines = lines
        self.closed = False

    def iter_lines(self, decode_unicode=True):
        yield from self.lines

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, lines):
        self.response = FakeResponse(lines)

    def post(self, *args, **kwargs):
        return self.response


def provider_for(lines):
    return OpenAICompatibleProvider("https://provider.example", "k", "m", session=FakeSession(lines))


def test_provider_normalizes_error_events_and_rejects_scalars_cleanly():
    with pytest.raises(ProviderError, match="quota exhausted") as error:
        list(provider_for(['data: {"error":{"message":"quota exhausted","code":429}}']).stream([]))
    assert error.value.status_code == 429
    with pytest.raises(ProviderError, match="non-object"):
        parse_sse_line('data: "not-an-object"')
    assert usage_from_chunk("scalar") is None
    with pytest.raises(ProviderError, match="malformed SSE"):
        list(provider_for(["data: 123"]).stream([]))
    with pytest.raises(ProviderError, match="gateway rejected"):
        list(provider_for(["event: error", 'data: {"message":"gateway rejected"}']).stream([]))


def test_provider_skips_bad_frame_when_a_later_frame_is_valid_and_reports_empty_stream():
    chunks = list(provider_for([
        "data: not-json", "",
        'data: {"choices":[{"delta":{"content":"ok"}}]}',
    ]).stream([]))
    assert chunks[0]["choices"][0]["delta"]["content"] == "ok"
    with pytest.raises(ProviderError, match="empty SSE stream"):
        list(provider_for([": ping", "data:"]).stream([]))


def test_chat_stream_starts_with_handshake_and_proxy_safe_headers(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.put("/api/ai/config", json={"apiKey": "sk"}).status_code == 200

    class StreamingProvider:
        def __init__(self, *args, **kwargs):
            pass

        def stream(self, messages, tools=None):
            yield {"choices": [{"delta": {"content": "ok"}}]}

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", StreamingProvider)
    response = client.post("/api/ai/chat", json={"message": "hello", "stream": True}, buffered=False)
    assert response.headers["Cache-Control"] == "no-cache, no-transform"
    assert response.headers["X-Accel-Buffering"] == "no"
    first = next(response.response).decode("utf-8")
    assert first == ": connected\n\n"
    response.close()


def test_closing_stream_stops_keepalive_producer(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.put("/api/ai/config", json={"apiKey": "sk"}).status_code == 200
    stopped = threading.Event()

    class EndlessProvider:
        def __init__(self, *args, **kwargs):
            pass

        def stream(self, messages, tools=None):
            try:
                while True:
                    yield {"choices": [{"delta": {"content": "x"}}]}
            finally:
                stopped.set()

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", EndlessProvider)
    response = client.post("/api/ai/chat", json={"message": "hello", "stream": True}, buffered=False)
    assert next(response.response).decode() == ": connected\n\n"
    assert "delta" in next(response.response).decode()
    response.close()
    assert stopped.wait(1.0)


def test_stream_failure_records_usage_received_before_disconnect(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    config = client.put("/api/ai/config", json={"apiKey": "sk"}).json

    class UsageThenFailureProvider:
        def __init__(self, *args, **kwargs):
            pass

        def stream(self, messages, tools=None):
            yield {"choices": [], "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}}
            raise ProviderError("connection reset")

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", UsageThenFailureProvider)
    response = client.post("/api/ai/chat", json={"message": "hello", "stream": True})
    events = [
        json.loads(line[6:]) for line in response.get_data(as_text=True).splitlines()
        if line.startswith("data: ")
    ]
    assert events[-1]["type"] == "error"
    store = AIStore(tmp_path / "ai.db")
    with store._connect() as conn:
        usage = conn.execute(
            "SELECT status,total_tokens FROM ai_usage WHERE config_id=? ORDER BY id DESC LIMIT 1",
            (config["id"],),
        ).fetchone()
    assert usage["status"] == "failed" and usage["total_tokens"] == 7


def test_stream_tool_round_echoes_tokenhub_reasoning_content(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, hub_runtime=SimpleNamespace())
    assert client.put("/api/ai/config", json={"apiKey": "sk"}).status_code == 200
    provider_messages = []

    class NoopExecutor:
        def __init__(self, hub):
            pass

        def register_handler(self, *args, **kwargs):
            pass

        def register_preview(self, *args, **kwargs):
            pass

        def execute(self, tool_id, arguments, **kwargs):
            return {"checked": True}

    class ThinkingToolProvider:
        def __init__(self, *args, **kwargs):
            self.round = 0

        def stream(self, messages, tools=None):
            provider_messages.append(json.loads(json.dumps(messages)))
            self.round += 1
            if self.round == 1:
                yield {"choices": [{"delta": {
                    "reasoning_content": "先检查网络，",
                    "tool_calls": [{"index": 0, "id": "call-1", "type": "function",
                                     "function": {"name": "network.self_check", "arguments": "{}"}}],
                }}]}
            else:
                yield {"choices": [{"delta": {"content": "检查完成"}}]}

    monkeypatch.setattr("assistant.api.ToolExecutor", NoopExecutor)
    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", ThinkingToolProvider)
    response = client.post("/api/ai/chat", json={"message": "请检查", "stream": True})
    assert response.status_code == 200
    events = _sse_events(response)
    assert events[-1]["type"] == "done"
    assert len(provider_messages) == 2
    assistant_tool = next(item for item in provider_messages[1] if item.get("role") == "assistant")
    assert assistant_tool["reasoning_content"] == "先检查网络，"


def test_daily_summary_uses_hub_beijing_today_instead_of_process_timezone():
    requested = []

    class DailyHub:
        def today_str(self):
            return "2026-08-30"

        def aggregate_daily(self, day):
            requested.append(day)
            return {"date": day, "summary": {}}

    result = ToolExecutor(DailyHub()).execute("daily.summary", {})
    assert requested == ["2026-08-30"]
    assert result["daily"]["date"] == "2026-08-30"


def test_daily_event_date_normalizes_utc_midnight_to_beijing_day():
    from hub import event_beijing_day, time_to_epoch

    assert event_beijing_day("2026-08-29T16:30:00Z") == "2026-08-30"
    assert event_beijing_day("2026-08-30 00:30:00") == "2026-08-30"
    assert time_to_epoch("2026-08-29T16:30:00Z") == time_to_epoch("2026-08-30 00:30:00")


def test_post_persist_chat_failure_keeps_identity_and_assistant_record(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    response = client.post("/api/ai/chat", json={"message": "hello"})
    assert response.status_code == 409
    assert response.json["conversationId"]
    assert response.json["userMessageId"] > 0 and response.json["messageId"] > 0
    store = AIStore(tmp_path / "ai.db")
    messages = store.get_messages(response.json["conversationId"])
    assert [row["role"] for row in messages] == ["user", "assistant"]
    assert messages[-1]["content"].startswith("〔请求失败〕")


def _sse_events(response):
    return [
        json.loads(line[6:]) for line in response.get_data(as_text=True).splitlines()
        if line.startswith("data: ")
    ]


def test_stream_without_enabled_config_returns_identified_persisted_failure(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    response = client.post("/api/ai/chat", json={"message": "hello", "stream": True})
    assert response.status_code == 200 and response.content_type.startswith("text/event-stream")
    error = _sse_events(response)[-1]
    assert error["type"] == "error"
    assert error["conversationId"] and error["userMessageId"] > 0 and error["messageId"] > 0
    messages = AIStore(tmp_path / "ai.db").get_messages(error["conversationId"])
    assert [row["role"] for row in messages] == ["user", "assistant"]
    assert messages[-1]["id"] == error["messageId"]


def test_stream_forced_self_check_tool_error_is_identified_and_persisted(tmp_path, monkeypatch):
    class FailingExecutor:
        def __init__(self, hub):
            pass

        def register_handler(self, *args, **kwargs):
            pass

        def register_preview(self, *args, **kwargs):
            pass

        def execute(self, *args, **kwargs):
            raise ToolError("self-check unavailable", "UNAVAILABLE", 503)

    monkeypatch.setattr("assistant.api.ToolExecutor", FailingExecutor)
    client = make_client(tmp_path, monkeypatch, hub_runtime=SimpleNamespace())
    response = client.post("/api/ai/chat", json={"message": "网络自检", "stream": True})
    assert response.status_code == 200
    error = _sse_events(response)[-1]
    assert error["type"] == "error" and "self-check unavailable" in error["error"]
    assert error["conversationId"] and error["userMessageId"] > 0 and error["messageId"] > 0
    messages = AIStore(tmp_path / "ai.db").get_messages(error["conversationId"])
    assert [row["role"] for row in messages] == ["user", "assistant"]
    assert messages[-1]["id"] == error["messageId"]


def test_app_token_rotation_reencrypts_config_before_previous_is_removed(tmp_path, monkeypatch):
    monkeypatch.delenv("LABPROBE_AI_MASTER_KEY", raising=False)
    monkeypatch.setenv("APP_TOKEN", "old-app-token")
    old_ciphertext = encrypt_secret("sk-rotating")
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    row = store.create_config("rotating", "deepseek", "https://api.example", "m", old_ciphertext, True)

    monkeypatch.setenv("APP_TOKEN", "new-app-token")
    monkeypatch.setenv("APP_TOKEN_PREVIOUS", "old-app-token")
    client = make_client(tmp_path, monkeypatch, master=False)
    config = client.get("/api/ai/config").json
    assert config["apiKeyStatus"] == "configured"
    migrated = store.get_config(row["id"])["api_key_ciphertext"]
    assert migrated != old_ciphertext

    monkeypatch.delenv("APP_TOKEN_PREVIOUS", raising=False)
    assert decrypt_secret(migrated) == "sk-rotating"


def test_config_view_does_not_claim_unreadable_ciphertext_is_usable(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    store.create_config("bad", "deepseek", "https://api.example", "m", "v1:not-valid", True)
    config = client.get("/api/ai/config").json
    assert config["configured"] is False
    assert config["apiKey"] is None
    assert config["apiKeyStatus"] == "invalid"


def test_base_url_rejects_credentials_query_and_fragment(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    for value in (
        "https://user:pass@api.example/v1",
        "https://api.example/v1?api_key=secret",
        "https://api.example/v1#secret",
    ):
        response = client.put("/api/ai/config", json={"apiKey": "sk", "baseUrl": value})
        assert response.status_code == 400
        assert "secret" not in response.get_data(as_text=True)


def test_legacy_secret_base_url_is_migrated_before_provider_use(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    row = store.create_config(
        "legacy", "deepseek", "https://user:password@api.example/v1?token=secret#fragment",
        "m", encrypt_secret("sk"), True,
    )
    outbound = []

    class CapturingProvider:
        def __init__(self, base_url, *_args):
            outbound.append(base_url)

        def chat(self, messages):
            return ChatResult("OK", {"total_tokens": 1})

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", CapturingProvider)
    assert client.post(f"/api/ai/config/{row['id']}/test").status_code == 200
    assert outbound == ["https://api.example/v1"]
    view = client.get("/api/ai/config")
    assert "password" not in view.get_data(as_text=True) and "secret" not in view.get_data(as_text=True)
    assert store.get_config(row["id"])["base_url"] == "https://api.example/v1"
    updated = client.put("/api/ai/config", json={"id": row["id"], "model": "m2", "enabled": False})
    assert updated.status_code == 200 and updated.json["model"] == "m2"


def test_legacy_hunyuan_endpoint_migrates_to_tokenhub_before_provider_use(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    row = store.create_config(
        "混元", "hunyuan", "https://api.hunyuan.cloud.tencent.com/v1", "deepseek-v4-flash-202605",
        encrypt_secret("sk"), True,
    )
    outbound = []

    class CapturingProvider:
        def __init__(self, base_url, *_args):
            outbound.append(base_url)

        def chat(self, messages, **_kwargs):
            return ChatResult("OK", {"total_tokens": 1})

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", CapturingProvider)
    response = client.post(f"/api/ai/config/{row['id']}/test")
    assert response.status_code == 200
    assert outbound == ["https://tokenhub.tencentmaas.com/v1"]
    assert store.get_config(row["id"])["base_url"] == "https://tokenhub.tencentmaas.com/v1"


def test_confirmation_cancel_and_recovery_endpoints_persist_cancel_note(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    store.create_conversation("conv", "test")
    store.create_confirmation(
        "conf", "device.wol", {"device": "ANS"}, {"title": "wake"},
        "2999-01-01T00:00:00+00:00", conversation_id="conv",
    )
    pending = client.get("/api/ai/conversations/conv/confirmations").json["confirmation"]
    assert pending["confirmationId"] == "conf" and pending["status"] == "pending"
    cancelled = client.post("/api/ai/tools/cancel", json={"confirmationId": "conf"})
    assert cancelled.status_code == 200
    status = client.get("/api/ai/tools/confirmations/conf").json["confirmation"]
    assert status["status"] == "cancelled" and status["result"]["ok"] is False
    assert client.get("/api/ai/conversations/conv/confirmations").json["confirmation"] is None
    assert "未执行" in store.get_messages("conv")[-1]["content"]
    assert client.post("/api/ai/tools/confirm", json={"confirmationId": "conf"}).status_code == 409


def test_usage_calibration_and_quota_are_atomic_and_not_counted_as_tasks(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    config = client.put("/api/ai/config", json={"apiKey": "sk", "tokenQuota": 1000}).json
    store = AIStore(tmp_path / "ai.db")
    store.add_usage("c", "deepseek", config["model"], {"total_tokens": 10}, config_id=config["id"])
    response = client.post("/api/ai/usage/adjust", json={
        "configId": config["id"], "totalTokens": 40, "tokenQuota": 2000,
    })
    assert response.status_code == 200
    assert response.json["adjustment"]["delta"] == 30
    assert response.json["config"]["tokenQuota"] == 2000
    usage = client.get("/api/ai/usage").json
    assert usage["requests"] == 1 and usage["total_tokens"] == 40
    assert usage["today_requests"] == 1 and usage["daily"][-1]["requests"] == 1
    assert all(row["status"] != "adjusted" for row in usage["recent"])

    same = client.post("/api/ai/usage/adjust", json={
        "configId": config["id"], "totalTokens": 40, "tokenQuota": None,
    }).json
    assert same["adjustment"]["id"] is None and same["adjustment"]["delta"] == 0
    assert same["config"]["tokenQuota"] is None


def test_manual_calibration_is_independent_from_conversation_deletion_and_future_tasks(tmp_path):
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    config = store.create_config("c", "p", "https://api.example", "m", "v1:x", True)
    store.create_conversation("old", "old")
    store.add_usage("old", "p", "m", {"total_tokens": 10}, config_id=config["id"])
    calibrated = store.record_usage_adjustment(config["id"], 100)
    assert calibrated["delta"] == 90
    assert store.delete_conversation("old")
    assert store.usage_by_config()[0]["total_tokens"] == 100
    from datetime import datetime, timedelta, timezone
    today = datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=8))).date().isoformat()
    assert store.usage_for_date(today)["total_tokens"] == 100
    store.add_usage("new", "p", "m", {"total_tokens": 7}, config_id=config["id"])
    assert store.usage_by_config()[0]["total_tokens"] == 107
    calibrated_day = store.usage_daily()[-1]
    assert calibrated_day["total_tokens"] == 107
    assert calibrated_day["models"]["m"] == 107
    assert store.record_usage_adjustment(config["id"], 100)["delta"] == -7
    assert store.usage_by_config()[0]["total_tokens"] == 100
    assert [row["total_tokens"] for row in store.list_usage()] == [7, 10]


def test_concurrent_same_target_calibration_creates_only_one_adjustment(tmp_path):
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    config = store.create_config("c", "p", "https://api.example", "m", "v1:x", True)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: store.record_usage_adjustment(config["id"], 100), range(8)))
    assert sum(1 for result in results if result["id"] is not None) == 1
    assert store.usage_by_config()[0]["total_tokens"] == 100
    assert store.usage_summary()["requests"] == 0


def test_connections_close_and_message_delete_repairs_empty_metadata(tmp_path):
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    with store._connect() as connection:
        connection.execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")

    store.create_conversation("conv", "only message")
    message_id = store.add_message("conv", "user", "only message")
    assert store.delete_message("conv", message_id)
    conversation = store.list_conversations()[0]
    assert conversation["title"] == "新对话"
    assert conversation["updated_at"] == conversation["created_at"]


def test_favorite_context_is_bounded_and_redacts_url_secrets():
    executor = ToolExecutor(SimpleNamespace())
    context = {
        "settings": {"privacyMode": False, "routerDisplayName": "r" * 30_000, "token": "no"},
        "favorites": [
            {
                "id": f"f-{index}", "title": "x" * 200,
                "localUrl": f"http://user:password@host{index}.local/path?token=secret#{index}",
            }
            for index in range(200)
        ],
    }
    safe = executor._client_context(context)
    encoded = json.dumps(safe, ensure_ascii=False).encode("utf-8")
    assert len(encoded) <= 16 * 1024
    assert len(safe["settings"]["routerDisplayName"]) == 256
    assert 0 < len(safe["favorites"]) < 100
    assert "password" not in encoded.decode() and "secret" not in encoded.decode()
    assert safe["favorites"][0]["localUrl"] == "http://host0.local/path"
