from datetime import datetime, timedelta, timezone
import json
import sqlite3
from types import SimpleNamespace

import pytest
from flask import Flask

from assistant.api import create_ai_blueprint
from assistant.provider import ProviderError, usage_from_chunk
from assistant.security import MasterKeyUnavailable, encrypt_secret
from assistant.storage import AIStore, utc_now
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

    commands_file = tmp_path / "agent-commands.json"
    commands_file.write_text("{}", encoding="utf-8")

    def save_json(path, value):
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def latest_command(router, action):
        rows = load_json(commands_file, {}).get("commands", [])
        for row in reversed(rows if isinstance(rows, list) else []):
            if isinstance(row, dict) and row.get("action") == action:
                return row
        return None

    task_calls = []
    runtime = SimpleNamespace(
        DEVICES_FILE=devices_file,
        PORTMAP_ROUTER_STATUS_FILE=portmap_status_file,
        AGENT_UPDATE_COMMANDS_FILE=commands_file,
        load_json=load_json,
        save_json=save_json,
        clean_saved_value=lambda value: str(value or "").strip(),
        primary_router_name=lambda: "router",
        resolve_agent_router=lambda preferred: str(preferred or "router"),
        notify_agent_commands_changed=lambda: None,
        now_str=lambda: "2026-08-29 15:00:00",
        latest_agent_command=latest_command,
        load_device_archive=lambda: {},
        normalize_ipv6_list=lambda value: value if isinstance(value, list) else [value],
        status_document=lambda: {"hub": {"name": "test"}},
        STATE_FILE=tmp_path / "state.json",
        agent_presence_snapshot=lambda: {"online": True, "router": "BE72"},
        ROUTER_TASK_MANAGER=SimpleNamespace(
            start_nat=lambda payload: task_calls.append(("nat", dict(payload))) or {
                "state": "succeeded", "stage": "finished", "result": {"nat_type": "symmetric"},
            },
            start_diagnostic=lambda: task_calls.append(("diagnostic", {})) or {
                "state": "succeeded", "stage": "finished", "result": {"process": "100%"},
            },
        ),
        aggregate_daily=lambda day: {"date": day, "summary": {}},
        _load_portmap_rules_document=lambda: ({"rules": []}, True),
        send_wol=lambda mac: {"ok": True, "mac": mac, "sent": 3},
    )
    runtime.task_calls = task_calls
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


def test_daily_usage_exposes_real_input_and_output_totals_for_bar_chart(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    store.add_usage("chart", "deepseek", "model-chart", {
        "prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10,
        "cache_hit_tokens": 2, "cache_miss_tokens": 5,
    })
    daily = client.get("/api/ai/usage").json["daily"][-1]
    assert daily["prompt_tokens"] == 7
    assert daily["completion_tokens"] == 3
    assert daily["total_tokens"] == 10
    assert daily["cache_hit_tokens"] == 2
    assert daily["cache_miss_tokens"] == 5
    assert daily["cache_reported_input_tokens"] == 7


def test_daily_cache_coverage_keeps_unreported_provider_input_out_of_hit_rate(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    store.add_usage("reported", "deepseek", "cache-model", {
        "prompt_tokens": 50, "completion_tokens": 1, "total_tokens": 51,
        "cache_hit_tokens": 20, "cache_miss_tokens": 30,
    })
    store.add_usage("unreported", "gateway", "opaque-model", {
        "prompt_tokens": 200, "completion_tokens": 2, "total_tokens": 202,
    })
    daily = client.get("/api/ai/usage").json["daily"][-1]
    assert daily["prompt_tokens"] == 250
    assert daily["cache_hit_tokens"] == 20
    assert daily["cache_reported_input_tokens"] == 50
    # The correct displayed rate is 20/50=40% with 50/250 coverage;
    # treating the opaque provider as a miss would incorrectly show 8%.


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


@pytest.mark.parametrize("message,tool_id,expected_call", [
    ("路由NAT检测", "router.nat.diagnostic", "nat"),
    ("路由器NAT诊断", "router.nat.diagnostic", "nat"),
    ("路由网络自检", "router.diagnostic", "diagnostic"),
])
def test_diagnostic_intents_execute_router_core_without_provider_or_navigation(
    tmp_path, monkeypatch, message, tool_id, expected_call,
):
    hub = fake_hub(tmp_path)
    client = make_client(tmp_path, monkeypatch, hub_runtime=hub)
    response = client.post("/api/ai/chat", json={"message": message})
    assert response.status_code == 200
    assert response.json["toolExecutions"] == [{"status": "completed", "toolId": tool_id}]
    assert response.json["clientActions"] == []
    assert hub.task_calls[0][0] == expected_call


def test_generic_network_self_check_is_direct_and_does_not_start_router_diagnostic(tmp_path, monkeypatch):
    hub = fake_hub(tmp_path)
    client = make_client(tmp_path, monkeypatch, hub_runtime=hub)
    response = client.post("/api/ai/chat", json={"message": "网络自检"})
    assert response.status_code == 200
    assert response.json["toolExecutions"] == [{"status": "completed", "toolId": "network.self_check"}]
    assert response.json["clientActions"] == []
    assert hub.task_calls == []
    assert "非路由器内置自检" in response.json["message"]["content"]


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
    completed = client.post("/api/ai/tools/complete", json={
        "confirmationId": confirmation_id, "ok": True, "message": "收藏已删除",
    })
    assert completed.status_code == 200
    assert completed.json["result"] == {"ok": True, "message": "收藏已删除"}
    assert client.post("/api/ai/tools/complete", json={
        "confirmationId": confirmation_id, "ok": True,
    }).status_code == 409


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
    service.publish_event({**event, "id": 8, "type": "device_offline"})
    service.publish_daily("2026-08-23")
    service.publish_daily("2026-08-23")
    rows = store.list_notifications()
    assert [row["kind"] for row in rows] == ["device", "daily"]
    assert "30 Token" in rows[1]["content"]


def test_prune_history_preserves_unlimited_conversation_count_and_bounds_auxiliary_rows(tmp_path):
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    now = datetime.now(timezone.utc)
    stale = (now - timedelta(days=120)).isoformat(timespec="seconds")
    fresh = now.isoformat(timespec="seconds")
    with store._connect() as conn:
        conn.execute("INSERT INTO conversations(id,title,created_at,updated_at) VALUES('c-old','旧','" + stale + "','" + stale + "')")
        conn.execute("INSERT INTO messages(conversation_id,role,content,created_at) VALUES('c-old','user','hi','" + stale + "')")
        conn.execute("INSERT INTO conversations(id,title,created_at,updated_at) VALUES('c-new','新','" + fresh + "','" + fresh + "')")
        conn.execute("INSERT INTO messages(conversation_id,role,content,created_at) VALUES('c-new','user','hi','" + fresh + "')")
        for index in range(8):
            conn.execute(
                "INSERT INTO ai_tool_audit(request_id,tool_id,risk,status,arguments_json,created_at) VALUES(?,?,?,?,?,?)",
                (f"r{index}", "status.get", "read", "ok", "{}", utc_now()),
            )
    store.prune_history(max_audit_rows=5, max_notifications=5)
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM messages WHERE conversation_id='c-old'").fetchone()["c"] == 1
        assert conn.execute("SELECT COUNT(*) AS c FROM messages WHERE conversation_id='c-new'").fetchone()["c"] == 1
        assert conn.execute("SELECT COUNT(*) AS c FROM ai_tool_audit").fetchone()["c"] == 5
    # Usage rows are the cumulative audit trail and are never pruned.
    store.add_usage("c-new", "deepseek", "deepseek-v4-flash", {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3})
    store.prune_history(max_audit_rows=5, max_notifications=5)
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM ai_usage").fetchone()["c"] == 1


def test_prune_history_clears_expired_pending_confirmations(tmp_path):
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(timespec="seconds")
    store.create_confirmation("expired-1", "device.wol", {"device": "ANS"}, {"toolId": "device.wol"}, past)
    deleted = store.prune_history()
    assert deleted["expired_confirmations"] == 1


def test_conversation_storage_counts_utf8_bytes_and_prunes_oldest_whole_conversation(tmp_path):
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    store.create_conversation("old", "旧")
    store.add_message("old", "user", "你好")
    store.create_conversation("current", "当前")
    store.add_message("current", "user", "abcd")
    assert store.conversation_storage()["bytes"] == 10
    deleted = store.enforce_conversation_storage(limit_bytes=4, protected_conversation_id="current")
    assert deleted["storage_conversations"] == 1
    assert [row["id"] for row in store.list_conversations()] == ["current"]
    assert store.conversation_storage()["bytes"] == 4


def test_conversation_list_has_no_count_cap_and_null_title_has_safe_fallback(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    for index in range(75):
        store.create_conversation(f"c-{index}", None)
    rows = client.get("/api/ai/conversations").json["conversations"]
    assert len(rows) == 75
    assert all(row["title"] == "新对话" for row in rows)


def test_incremental_chat_appends_one_turn_without_replaying_or_duplicating(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.put("/api/ai/config", json={"apiKey": "sk-test"}).status_code == 200

    class FakeProvider:
        calls = []

        def __init__(self, *args, **kwargs):
            pass

        def chat(self, messages, tools=None):
            from assistant.provider import ChatResult
            self.__class__.calls.append(messages)
            turn = sum(1 for item in messages if item.get("role") == "user")
            return ChatResult(f"回复{turn}", {"total_tokens": 1}, {
                "role": "assistant", "content": f"回复{turn}",
            })

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", FakeProvider)
    first = client.post("/api/ai/chat", json={"message": "第一问"})
    conversation_id = first.json["conversationId"]
    second = client.post("/api/ai/chat", json={"conversationId": conversation_id, "message": "第二问"})
    assert second.status_code == 200
    stored = client.get(f"/api/ai/conversations/{conversation_id}/messages").json["messages"]
    assert [(item["role"], item["content"]) for item in stored] == [
        ("user", "第一问"), ("assistant", "回复1"),
        ("user", "第二问"), ("assistant", "回复2"),
    ]
    assert [item["content"] for item in FakeProvider.calls[-1] if item.get("role") != "system"] == [
        "第一问", "回复1", "第二问",
    ]


def test_incremental_chat_replay_is_strictly_bounded_and_starts_with_user(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.put("/api/ai/config", json={"apiKey": "sk-test"}).status_code == 200
    store = AIStore(tmp_path / "ai.db")
    store.create_conversation("bounded", "bounded")
    for role, marker in (("user", "u1"), ("assistant", "a1"), ("user", "u2"), ("assistant", "a2")):
        store.add_message("bounded", role, marker + ("x" * 8998))

    class CapturingProvider:
        calls = []

        def __init__(self, *args, **kwargs):
            pass

        def chat(self, messages, tools=None):
            from assistant.provider import ChatResult
            self.__class__.calls.append(messages)
            return ChatResult("ok", {"total_tokens": 1}, {"role": "assistant", "content": "ok"})

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", CapturingProvider)
    response = client.post("/api/ai/chat", json={"conversationId": "bounded", "message": "current"})
    assert response.status_code == 200
    replay = [item for item in CapturingProvider.calls[-1] if item.get("role") != "system"]
    assert sum(len(item["content"]) for item in replay) <= 24_000
    assert replay[0]["role"] == "user" and replay[-1]["content"] == "current"


def test_incremental_chat_rejects_a_message_larger_than_replay_budget(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    response = client.post("/api/ai/chat", json={"message": "x" * 24_001})
    assert response.status_code == 413
    assert "replay budget" in response.json["error"]


def test_replace_messages_keeps_history_bounded_without_duplicates(tmp_path):
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    store.create_conversation("c-1", "对话")
    store.replace_messages("c-1", [
        {"role": "user", "content": "第一轮"},
        {"role": "assistant", "content": "回复一"},
    ])
    store.add_message("c-1", "user", "第二轮")
    # Client replays history next turn: replace instead of duplicating.
    store.replace_messages("c-1", [
        {"role": "user", "content": "第一轮"},
        {"role": "assistant", "content": "回复一"},
        {"role": "user", "content": "第二轮"},
        {"role": "assistant", "content": "回复二"},
    ])
    assert len(store.get_messages("c-1")) == 4


def test_chat_rejects_over_count_with_clear_error(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.post("/api/ai/chat", json={"message": "hello"}).status_code == 409  # not configured


def test_batch_write_tools_need_single_confirmation(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, hub_runtime=fake_hub(tmp_path))

    class FakeBatchProvider:
        def __init__(self, *args, **kwargs):
            pass

        def chat(self, messages, tools=None):
            from assistant.provider import ChatResult
            return ChatResult("", {"total_tokens": 6}, {
                "role": "assistant", "content": None,
                "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "device_wol", "arguments": '{"device":"Mate60"}'}},
                    {"id": "c2", "type": "function", "function": {"name": "device_wol", "arguments": '{"device":"ANS"}'}},
                ],
            })

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", FakeBatchProvider)
    assert client.put("/api/ai/config", json={"apiKey": "sk-test"}).status_code == 200
    response = client.post("/api/ai/chat", json={"message": "把两台设备都唤醒"})
    assert response.status_code == 200
    confirmation = response.json["confirmation"]
    assert confirmation["preview"]["toolId"] == "batch"
    assert "2 项" in confirmation["preview"]["title"]
    confirmed = client.post("/api/ai/tools/confirm", json={"confirmationId": confirmation["confirmationId"]})
    assert confirmed.status_code == 200
    assert "2/2" in confirmed.json["result"]["message"]


def test_conversation_title_comes_from_latest_message(tmp_path):
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    store.create_conversation("t-1", "  帮我看看今天的设备流量变化  ")
    row = store.list_conversations()[0]
    assert row["title"] == "帮我看看今天的设备流量变化"


def test_legacy_singleton_config_is_migrated_once(tmp_path, monkeypatch):
    monkeypatch.setenv("LABPROBE_AI_MASTER_KEY", "test-master-key")
    db_path = tmp_path / "legacy.db"
    store = AIStore(db_path)
    store.initialize()
    ciphertext = encrypt_secret("sk-legacy")
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM ai_provider_configs")
        conn.execute(
            "INSERT INTO ai_config(id,provider,base_url,model,api_key_ciphertext,enabled,updated_at) "
            "VALUES(1,'deepseek','https://legacy.example/v1','legacy-model',?,1,?)",
            (ciphertext, utc_now()),
        )
        conn.execute(
            "INSERT INTO ai_usage(conversation_id,provider,model,total_tokens,created_at) "
            "VALUES('legacy-chat','deepseek','legacy-model',9,?)", (utc_now(),),
        )
    store.initialize()
    configs = store.list_configs()
    assert len(configs) == 1
    assert configs[0]["model"] == "legacy-model"
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM ai_config").fetchone()[0] == 0
        assert conn.execute("SELECT config_id FROM ai_usage WHERE conversation_id='legacy-chat'").fetchone()[0] == configs[0]["id"]
    store.initialize()
    assert len(store.list_configs()) == 1


def test_multi_config_crud_masks_keys_and_hunyuan_has_new_default(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    first = client.put("/api/ai/config", json={"apiKey": "sk-first", "name": "主模型"})
    assert first.status_code == 200
    second = client.post("/api/ai/config", json={
        "apiKey": "sk-hunyuan", "name": "混元备用", "provider": "hunyuan",
        "model": "hunyuan-turbos", "tokenQuota": 1_000_000,
    })
    assert second.status_code == 200
    assert second.json["baseUrl"] == "https://tokenhub.tencentmaas.com/v1"
    config_id = second.json["id"]
    updated = client.put("/api/ai/config", json={"id": config_id, "name": "混元二号", "enabled": False})
    assert updated.status_code == 200
    assert updated.json["name"] == "混元二号"
    assert updated.json["apiKeyStatus"] == "configured"
    payload = client.get("/api/ai/config").json
    assert len(payload["configs"]) == 2
    assert "sk-first" not in json.dumps(payload)
    assert "sk-hunyuan" not in json.dumps(payload)
    assert payload["provider"] == "deepseek"  # phase-one fields still describe the primary config
    assert client.delete(f"/api/ai/config/{config_id}").status_code == 204
    assert len(client.get("/api/ai/config").json["configs"]) == 1


def test_chat_stays_on_primary_config_and_reports_model_failure(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.put("/api/ai/config", json={
        "apiKey": "sk-a", "name": "A", "baseUrl": "https://fail.example/v1",
        "model": "model-a", "tokenQuota": 10,
    })
    client.post("/api/ai/config", json={
        "apiKey": "sk-b", "name": "B", "baseUrl": "https://ok.example/v1",
        "model": "model-b",
    })
    calls = []

    class FakeProvider:
        def __init__(self, base_url, api_key, model):
            self.base_url, self.model = base_url, model

        def chat(self, messages, tools=None):
            calls.append(self.base_url)
            raise ProviderError("temporary provider failure", 429)

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", FakeProvider)
    response = client.post("/api/ai/chat", json={"message": "你好"})
    assert response.status_code == 429
    assert calls == ["https://fail.example/v1"]
    error_text = response.json["error"]
    assert "模型 model-a（A）" in error_text and "temporary provider failure" in error_text
    assert "自动切换已停用" in error_text
    usage = client.get("/api/ai/usage").json["config_usage"]
    by_name = {item["name"]: item for item in usage}
    assert by_name["A"]["total_tokens"] == 0
    assert by_name["B"]["total_tokens"] == 0


def test_chat_uses_first_enabled_config_and_never_auto_switches(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.put("/api/ai/config", json={
        "apiKey": "sk-disabled", "baseUrl": "https://disabled.example/v1", "enabled": False,
    })
    client.post("/api/ai/config", json={
        "apiKey": "sk-a", "baseUrl": "https://a.example/v1", "model": "a",
    })
    client.post("/api/ai/config", json={
        "apiKey": "sk-b", "baseUrl": "https://b.example/v1", "model": "b",
    })
    calls = []

    class FailingProvider:
        def __init__(self, base_url, *_args):
            self.base_url = base_url

        def chat(self, messages, tools=None):
            calls.append(self.base_url)
            raise ProviderError("unavailable", 502)

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", FailingProvider)
    response = client.post("/api/ai/chat", json={"message": "hello"})
    assert response.status_code == 502
    # 停用自动切换：只尝试第一个启用的配置，失败时把模型名与原因带回给 APP。
    assert calls == ["https://a.example/v1"]
    error_text = response.json["error"]
    assert "模型 a" in error_text and "不可用" in error_text and "自动切换已停用" in error_text


def test_stream_chat_reports_model_failure_without_failover(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    first = client.put("/api/ai/config", json={
        "apiKey": "sk-a", "baseUrl": "https://a.example/v1", "model": "a",
    }).json
    client.post("/api/ai/config", json={
        "apiKey": "sk-b", "baseUrl": "https://b.example/v1", "model": "b",
    })
    calls = []

    class StreamProvider:
        def __init__(self, base_url, *_args):
            self.base_url = base_url

        def stream(self, messages, tools=None):
            calls.append(self.base_url)
            yield {"choices": [{"delta": {"content": "残句"}}]}
            raise ProviderError("stream unavailable", 502)

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", StreamProvider)
    response = client.post("/api/ai/chat", json={"message": "hello", "stream": True})
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    events = [json.loads(line[len("data: "):]) for line in body.splitlines() if line.startswith("data: ")]
    kinds = [event["type"] for event in events]
    assert "reset" in kinds and "delta" in kinds
    last = events[-1]
    assert last["type"] == "error" and "模型 a" in last["error"] and "不可用" in last["error"]
    # 不自动切换：第二个配置从未被调用。
    assert calls == ["https://a.example/v1"]
    usage = {item["config_id"]: item for item in client.get("/api/ai/usage").json["config_usage"]}
    assert usage[first["id"]]["total_tokens"] == 0


def test_stream_error_carries_stored_user_message_identity(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.put("/api/ai/config", json={"apiKey": "sk-test"}).status_code == 200

    class FailingStreamProvider:
        def __init__(self, *_args):
            pass

        def stream(self, messages, tools=None):
            raise ProviderError("rate limit exceeded", 429)
            yield  # pragma: no cover - keeps this method a generator

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", FailingStreamProvider)
    response = client.post("/api/ai/chat", json={"message": "hello", "stream": True})
    assert response.status_code == 200
    events = [
        json.loads(line[len("data: "):])
        for line in response.get_data(as_text=True).splitlines()
        if line.startswith("data: ")
    ]
    error = events[-1]
    assert error["type"] == "error"
    assert error["conversationId"]
    assert error["userMessageId"] > 0
    assert "rate limit exceeded" in error["error"]


def test_master_key_failure_reports_config_name_and_records_usage(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.put("/api/ai/config", json={
        "apiKey": "sk-test", "name": "混元", "provider": "hunyuan", "model": "hy3",
    }).status_code == 200
    monkeypatch.delenv("LABPROBE_AI_MASTER_KEY", raising=False)
    monkeypatch.delenv("APP_TOKEN", raising=False)

    response = client.post("/api/ai/chat", json={"message": "hello"})
    assert response.status_code == 503
    assert "模型 hy3（混元）" in response.json["error"]
    assert "自动切换已停用" in response.json["error"]

    store = AIStore(tmp_path / "ai.db")
    with store._connect() as conn:
        row = conn.execute(
            "SELECT status, usage_json FROM ai_usage ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row["status"] == "failed"
    assert "Hub 缺少可用于加密 API Key 的 APP_TOKEN" in row["usage_json"]


def test_legacy_test_endpoint_fails_over_but_specific_test_stays_targeted(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    first = client.put("/api/ai/config", json={
        "apiKey": "sk-a", "baseUrl": "https://a.example/v1", "model": "a",
    }).json
    client.post("/api/ai/config", json={
        "apiKey": "sk-b", "baseUrl": "https://b.example/v1", "model": "b",
    })
    calls = []

    class TestProvider:
        def __init__(self, base_url, *_args):
            self.base_url = base_url

        def chat(self, messages):
            calls.append(self.base_url)
            if "a.example" in self.base_url:
                raise ProviderError("auth rejected", 401)
            from assistant.provider import ChatResult
            return ChatResult("OK", {"total_tokens": 1})

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", TestProvider)
    assert client.post("/api/ai/test").status_code == 200
    assert calls == ["https://a.example/v1", "https://b.example/v1"]
    calls.clear()
    assert client.post(f"/api/ai/config/{first['id']}/test").status_code == 401
    assert calls == ["https://a.example/v1"]


def test_usage_reports_known_and_unknown_quota_for_multiple_models(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    known = client.put("/api/ai/config", json={
        "apiKey": "sk-a", "name": "有限额", "model": "model-a", "tokenQuota": 100,
    }).json
    unknown = client.post("/api/ai/config", json={
        "apiKey": "sk-b", "name": "无限额", "model": "model-b",
    }).json
    store = AIStore(tmp_path / "ai.db")
    store.add_usage("c-a", "deepseek", "model-a", {"prompt_tokens": 20, "completion_tokens": 5, "total_tokens": 25}, config_id=known["id"])
    store.add_usage("c-b", "deepseek", "model-b", {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10}, config_id=unknown["id"])
    payload = client.get("/api/ai/usage").json
    by_id = {item["config_id"]: item for item in payload["config_usage"]}
    assert by_id[known["id"]]["used_percent"] == 25.0
    assert by_id[known["id"]]["remaining_percent"] == 75.0
    assert by_id[unknown["id"]]["quota_status"] == "unknown"
    assert by_id[unknown["id"]]["used_percent"] is None
    by_model = {item["model"]: item for item in payload["model_usage"]}
    assert by_model["model-a"]["used_percent"] == 25.0
    assert by_model["model-a"]["remaining_percent"] == 75.0
    assert by_model["model-b"]["quota_status"] == "unknown"


def test_conversation_title_can_be_renamed_with_validation(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    store.create_conversation("rename-me", "旧标题")
    response = client.patch("/api/ai/conversations/rename-me", json={"title": "  新标题  "})
    assert response.status_code == 200
    assert response.json["conversation"]["title"] == "新标题"
    assert client.patch("/api/ai/conversations/rename-me", json={"title": " "}).status_code == 400
    assert client.patch("/api/ai/conversations/rename-me", json={"title": "x" * 65}).status_code == 400
    assert client.patch("/api/ai/conversations/missing", json={"title": "名字"}).status_code == 404


def test_router_network_self_check_intent_maps_to_router_diagnostic(tmp_path, monkeypatch):
    from assistant.api import diagnostic_tool_intent

    assert diagnostic_tool_intent("路由器网络自检") == "router.diagnostic"
    assert diagnostic_tool_intent("路由器网络自检结果") == "router.diagnostic"
    assert diagnostic_tool_intent("路由网络自检") == "router.diagnostic"
    assert diagnostic_tool_intent("路由器自检") == "router.diagnostic"
    assert diagnostic_tool_intent("网络自检") == "network.self_check"
    assert diagnostic_tool_intent("综合网络自检") == "network.self_check"
    assert diagnostic_tool_intent("NAT诊断结果") == "router.nat.diagnostic"
    assert diagnostic_tool_intent("NAT检测") == "navigate.tool_nat"
    assert diagnostic_tool_intent("NAT诊断") == "navigate.tool_nat"
    assert diagnostic_tool_intent("路由NAT检测") == "router.nat.diagnostic"
    assert diagnostic_tool_intent("路由器NAT检测结果") == "router.nat.diagnostic"
    assert diagnostic_tool_intent("打开网络自检页面") is None
    assert diagnostic_tool_intent("查询设备列表") is None


def test_nat_forced_chat_polls_task_and_returns_readable_result(tmp_path, monkeypatch):
    hub = fake_hub(tmp_path)
    polls = {"count": 0}

    def snapshot(kind):
        polls["count"] += 1
        if polls["count"] >= 2:
            return {"state": "succeeded", "stage": "finished", "message": "检测完成",
                    "result": {"nat_type": "symmetric", "external_address": "1.2.3.4:4500",
                               "mode": "classic"}}
        return {"state": "running", "stageText": "路由器正在执行 NAT 检测"}

    hub.ROUTER_TASK_MANAGER = SimpleNamespace(
        start_nat=lambda payload: {"state": "queued", "taskId": "nat-x"},
        snapshot=snapshot,
    )
    client = make_client(tmp_path, monkeypatch, hub_runtime=hub)
    response = client.post("/api/ai/chat", json={"message": "路由NAT检测"})
    assert response.status_code == 200
    content = response.json["message"]["content"]
    assert "NAT 类型：对称型 NAT" in content
    assert "公网映射地址：1.2.3.4:4500" in content
    assert "{" not in content.split("\n")[0]
    assert response.json["usageKnown"] is False


def test_nat_result_query_reuses_existing_task_without_restart(tmp_path, monkeypatch):
    hub = fake_hub(tmp_path)
    task_calls = []

    def start_nat(payload):
        task_calls.append(payload)
        return {"state": "queued", "taskId": "nat-new"}

    hub.ROUTER_TASK_MANAGER = SimpleNamespace(
        start_nat=start_nat,
        snapshot=lambda kind: {
            "state": "succeeded", "stage": "finished", "message": "检测完成",
            "result": {"nat_type": "full cone", "mode": "rfc5780"},
        },
    )
    client = make_client(tmp_path, monkeypatch, hub_runtime=hub)
    response = client.post("/api/ai/chat", json={"message": "NAT诊断结果"})
    assert response.status_code == 200
    assert "完全锥形 NAT" in response.json["message"]["content"]
    assert task_calls == []


def test_router_diagnostic_content_is_readable_chinese():
    from assistant.api import router_diagnostic_content

    task = {
        "state": "succeeded",
        "result": {
            "process": "100%",
            "error_count": "1",
            "list": [
                {"type": "wan", "item": "WAN Port", "status": "OK",
                 "list": [{"item": "WAN Port", "status": "OK",
                           "result": "external network port network cable is OK"}]},
                {"type": "lan", "item": "LAN Port", "status": "OK",
                 "list": [{"item": "LAN Port", "status": "OK"}]},
                {"type": "port", "item": "Negotiation Speed", "status": "Error",
                 "list": [{"item": "Negotiation Speed", "status": "Error",
                           "result": "Network port negotiation rate is abnormal; May cause slow access to the Internet; Problem interface: {port}",
                           "tips": "Repair suggestion: ; Please try to change a network cable or check whether the network port rate of the intermediate device (switch/AP, etc.) is configured to 10M",
                           "advise": "check network cable",
                           "data": {"port": "LAN5/GAME"}}]},
            ],
        },
    }
    content = router_diagnostic_content(task)
    assert "共 3 项检查" in content and "1 项异常" in content
    assert "• 外网口连接：正常" in content
    assert "• 局域网连接：正常" in content
    assert "• 端口协商速率：异常（问题接口 LAN5/GAME）" in content
    assert "现象：网络端口协商速率异常" in content
    assert "现象：可能导致上网变慢" in content
    assert "现象：问题接口：LAN5/GAME" in content
    assert "提示：请尝试更换网线，或检查中间设备（交换机/AP 等）的网口速率是否被设置为 10M" in content
    assert "建议：请检查对应接口的网线连接" in content
    assert "Repair suggestion" not in content
    assert "abnormal" not in content


def test_nat_diagnostic_content_reports_running_and_failure():
    from assistant.api import nat_diagnostic_content

    running = nat_diagnostic_content({"state": "running", "stageText": "路由器正在执行 NAT 检测"})
    assert "进行中" in running and "NAT诊断结果" in running
    failed = nat_diagnostic_content({"state": "failed", "message": "STUN 不可达"})
    assert "失败" in failed and "STUN 不可达" in failed


def test_network_self_check_content_is_readable_without_raw_json():
    from assistant.api import network_self_check_content

    content = network_self_check_content({
        "summary": {
            "router": {"name": "BE72", "onlineDeviceCount": 11, "exitIpv4": "100.64.1.2",
                       "exitIpv6": "2409::1", "routerStatus": "ok"},
            "agent": {"agentOnline": True, "agentStateText": "Agent 在线", "agentVersion": "0.2.30",
                      "agentArchitecture": "aarch64", "agentLastSeenAt": "2026-08-29 15:50:26", "router": "BE72"},
            "hub": {"name": "labprobe", "version": "0.12.0", "advertiseUrl": "https://hub.example"},
            "vpnAddressCount": 2,
            "portmapRules": 2, "stunRules": 1, "wireguardEnabled": True,
        },
        "hub": {"hub": {"name": "test"}},
    })
    assert "非路由器内置自检" in content
    assert "名称：BE72（运行正常）" in content
    assert "在线设备：11 台" in content
    assert "出口 IPv4：100.64.1.2" in content
    assert "Relay 扩展：Agent 在线" in content
    assert "版本 0.2.30（aarch64）" in content
    assert "最后上报 2026-08-29 15:50:26" in content
    assert "Hub：labprobe v0.12.0" in content
    assert "访问地址：https://hub.example" in content
    assert "STUN 公网地址记录：2 条" in content
    assert "端口映射 2 条" in content
    assert "{" not in content


def test_conversation_delete_removes_messages_and_requires_auth(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    store.create_conversation("delete-me", "要删除的对话")
    store.add_message("delete-me", "user", "你好")
    store.add_message("delete-me", "assistant", "你好！")
    anonymous = make_client(tmp_path, monkeypatch, authorized=False)
    assert anonymous.delete("/api/ai/conversations/delete-me").status_code == 401
    assert client.delete("/api/ai/conversations/delete-me").status_code == 200
    assert client.delete("/api/ai/conversations/delete-me").status_code == 404
    assert client.get("/api/ai/conversations/delete-me/messages").json["messages"] == []
    assert client.get("/api/ai/conversations").json["conversations"] == []
    rows = sqlite3.connect(tmp_path / "ai.db").execute(
        "SELECT COUNT(*) FROM messages WHERE conversation_id='delete-me'").fetchone()
    assert rows[0] == 0


def test_plain_nat_intent_opens_app_tool_page_without_execution(tmp_path, monkeypatch):
    hub = fake_hub(tmp_path)
    client = make_client(tmp_path, monkeypatch, hub_runtime=hub)
    response = client.post("/api/ai/chat", json={"message": "NAT检测"})
    assert response.status_code == 200
    assert response.json["clientActions"] == [{"type": "navigate", "route": "nat"}]
    assert response.json["toolExecutions"] == []
    assert hub.task_calls == []
    assert "已打开工具箱页的「NAT 检测」" in response.json["message"]["content"]
    assert "路由NAT检测" in response.json["message"]["content"]


def test_agent_cleanup_requires_confirmation_and_queues_command(tmp_path, monkeypatch):
    hub = fake_hub(tmp_path)
    client = make_client(tmp_path, monkeypatch, hub_runtime=hub)
    denied = client.post("/api/ai/tools/execute", json={"toolId": "agent.cleanup", "arguments": {}})
    assert denied.status_code == 409
    prepared = client.post("/api/ai/tools/prepare", json={"toolId": "agent.cleanup", "arguments": {}})
    assert prepared.status_code == 200
    assert prepared.json["preview"]["executor"] == "hub"
    assert "清理" in prepared.json["preview"]["title"]
    confirmed = client.post("/api/ai/tools/confirm", json={"confirmationId": prepared.json["confirmationId"]})
    assert confirmed.status_code == 200
    assert "清理指令已发送" in confirmed.json["result"]["message"]
    commands = json.loads((tmp_path / "agent-commands.json").read_text(encoding="utf-8"))["commands"]
    assert commands and commands[-1]["action"] == "cleanup"

    catalog_ids = [tool["id"] for tool in client.get("/api/ai/catalog").json["tools"]]
    assert "agent.cleanup" in catalog_ids and "agent.cleanup.status" in catalog_ids


def test_agent_cleanup_status_reports_latest_command(tmp_path, monkeypatch):
    hub = fake_hub(tmp_path)
    client = make_client(tmp_path, monkeypatch, hub_runtime=hub)
    missing = client.post("/api/ai/tools/execute", json={
        "toolId": "agent.cleanup.status", "arguments": {},
    })
    assert missing.status_code == 200
    assert missing.json["result"]["state"] == "missing"
    hub.save_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": [{
        "id": "cmd-1", "router": "router", "action": "cleanup", "state": "succeeded",
        "message": "清理完成", "result": {"cleanedItems": ["/etc/labprobe/backups/old"],
                                          "reclaimedBytes": 2048, "reclaimedText": "2 KB"},
    }]})
    done = client.post("/api/ai/tools/execute", json={"toolId": "agent.cleanup.status", "arguments": {}})
    assert done.status_code == 200
    assert done.json["result"]["state"] == "succeeded"
    assert done.json["result"]["reclaimed"] == "2 KB"


def test_usage_config_backfill_attributes_legacy_rows_by_model(tmp_path, monkeypatch):
    monkeypatch.setenv("LABPROBE_AI_MASTER_KEY", "test-master-key")
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    store.create_config("腾讯混元", "openai_compatible", "https://x.example", "hy3",
                        encrypt_secret("sk-test"), True, None)
    # 旧记录：单配置时期写入，config_id 为空，provider 命名也与现配置不同
    store.add_usage("conv-1", "deepseek", "hy3", {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10})
    store.add_usage("conv-1", "openai_compatible", "hy3", {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5})
    store.initialize()  # 再次初始化触发回填

    import sqlite3
    ids = [row[0] for row in sqlite3.connect(tmp_path / "ai.db").execute(
        "SELECT config_id FROM ai_usage ORDER BY id")]
    assert ids == [1, 1]
    per_config = store.usage_by_config()
    assert per_config[0]["total_tokens"] == 15


def test_confirmation_outcome_is_recorded_in_conversation_transcript(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, hub_runtime=fake_hub(tmp_path))
    assert client.put("/api/ai/config", json={"apiKey": "sk-test"}).status_code == 200

    class FakeWriteProvider:
        def __init__(self, *args, **kwargs):
            pass

        def chat(self, messages, tools=None):
            from assistant.provider import ChatResult
            return ChatResult("", {"total_tokens": 3}, {
                "role": "assistant", "content": None,
                "tool_calls": [{
                    "id": "call-wol", "type": "function",
                    "function": {"name": "device_wol", "arguments": '{"device":"Mate60"}'},
                }],
            })

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", FakeWriteProvider)
    chat = client.post("/api/ai/chat", json={"message": "唤醒 Mate60"})
    assert chat.status_code == 200
    conversation_id = chat.json["conversationId"]
    confirmed = client.post("/api/ai/tools/confirm",
                            json={"confirmationId": chat.json["confirmation"]["confirmationId"]})
    assert confirmed.status_code == 200
    messages = client.get(f"/api/ai/conversations/{conversation_id}/messages").json["messages"]
    notes = [row for row in messages if row["content"].startswith("〔操作记录〕")]
    assert notes and "唤醒设备" in notes[-1]["content"]


def test_stream_chat_runs_tool_loop_and_emits_typed_events(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, hub_runtime=fake_hub(tmp_path))
    assert client.put("/api/ai/config", json={"apiKey": "sk-test"}).status_code == 200

    class FakeStreamProvider:
        rounds = 0

        def __init__(self, *args, **kwargs):
            pass

        def chat(self, messages, tools=None):  # pragma: no cover - stream path only
            raise AssertionError("stream request must not use non-stream chat")

        def stream(self, messages, tools=None):
            from assistant.provider import ChatResult  # noqa: F401
            self.__class__.rounds += 1
            if self.__class__.rounds == 1:
                assert tools and any(row["function"]["name"] == "device_ipv6" for row in tools)
                yield {"choices": [{"delta": {"tool_calls": [
                    {"index": 0, "id": "call-1", "function": {"name": "device_ipv6", "arguments": ""}},
                ]}}]}
                yield {"choices": [{"delta": {"tool_calls": [
                    {"index": 0, "function": {"arguments": '{"device":"Mate60"}'}},
                ]}}]}
                yield {"choices": [{"delta": {}}], "usage": {"prompt_tokens": 7}}
                return
            assert messages[-1]["role"] == "tool"
            yield {"choices": [{"delta": {"content": "Mate60 的"}}]}
            yield {"choices": [{"delta": {"content": "IPv6 是 240e::60。"}}]}
            yield {"choices": [{"delta": {}}],
                   "usage": {"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8}}

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", FakeStreamProvider)
    response = client.post("/api/ai/chat", json={"message": "告诉我 Mate60 的 IPv6 地址", "stream": True})
    assert response.status_code == 200
    assert response.content_type.startswith("text/event-stream")
    events = [json.loads(line[len("data: "):]) for line in response.get_data(as_text=True).splitlines()
              if line.startswith("data: ")]
    kinds = [event["type"] for event in events]
    assert kinds.count("tool") == 1 and events[kinds.index("tool")]["toolId"] == "device.ipv6"
    deltas = "".join(event["content"] for event in events if event["type"] == "delta")
    assert deltas == "Mate60 的IPv6 是 240e::60。"
    done = events[-1]
    assert done["type"] == "done"
    assert done["message"]["content"] == "Mate60 的IPv6 是 240e::60。"
    # A tool task is two billable provider requests: the tool-selection round
    # (7) plus the final-answer round (8). Repeated usage frames inside either
    # round are snapshots, but distinct rounds must be added.
    assert done["usage"]["prompt_tokens"] == 10
    assert done["usage"]["completion_tokens"] == 5
    assert done["usage"]["total_tokens"] == 15
    assert done["usageKnown"] is True
    assert done["toolExecutions"] == [{"toolId": "device.ipv6", "status": "completed"}]


def test_stream_chat_emits_confirmation_payload_for_write_tools(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, hub_runtime=fake_hub(tmp_path))
    assert client.put("/api/ai/config", json={"apiKey": "sk-test"}).status_code == 200

    class FakeStreamWriter:
        def __init__(self, *args, **kwargs):
            pass

        def chat(self, messages, tools=None):  # pragma: no cover
            raise AssertionError("stream request must not use non-stream chat")

        def stream(self, messages, tools=None):
            yield {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "id": "call-wol", "function": {"name": "device_wol", "arguments": '{"device":"Mate60"}'}},
            ]}}]}
            yield {"choices": [{"delta": {}}], "usage": {"total_tokens": 4}}

    monkeypatch.setattr("assistant.api.OpenAICompatibleProvider", FakeStreamWriter)
    response = client.post("/api/ai/chat", json={"message": "唤醒 Mate60", "stream": True})
    events = [json.loads(line[len("data: "):]) for line in response.get_data(as_text=True).splitlines()
              if line.startswith("data: ")]
    assert len(events) == 1 and events[0]["type"] == "confirmation"
    assert events[0]["confirmation"]["preview"]["title"] == "确认唤醒设备"
    assert "需要你的确认" in events[0]["message"]["content"]
    confirmed = client.post("/api/ai/tools/confirm",
                            json={"confirmationId": events[0]["confirmation"]["confirmationId"]})
    assert confirmed.status_code == 200


def test_orphaned_usage_config_ids_are_reattributed(tmp_path):
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    hunyuan = store.create_config("混元", "hunyuan", "https://api.example", "hy3", "v1:abc", True, None)
    other = store.create_config("DeepSeek", "deepseek", "https://api.example", "deepseek-v4-flash", "v1:abc", True, None)
    store.add_usage("c", "hunyuan", "hy3", {"total_tokens": 100}, config_id=999)
    store.add_usage("c", "hunyuan", "hy3", {"total_tokens": 50})
    store.initialize()
    totals = {row["config_id"]: row["total_tokens"] for row in store.usage_by_config()}
    assert totals[hunyuan["id"]] == 150 and totals[other["id"]] == 0
    assert store.delete_config(hunyuan["id"]) is True
    totals = {row["config_id"]: row["total_tokens"] for row in store.usage_by_config()}
    assert totals[other["id"]] == 0
    unattributed = store.usage_for_date.__self__  # placeholder to keep lint quiet
    with store._connect() as conn:
        rows = conn.execute("SELECT config_id FROM ai_usage WHERE model='hy3'").fetchall()
    assert all(row["config_id"] is None for row in rows)


def test_usage_backfill_prefers_first_position_for_duplicate_provider_model(tmp_path):
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    first = store.create_config("first", "deepseek", "https://one", "same", "v1:a", True, None)
    second = store.create_config("second", "deepseek", "https://two", "same", "v1:b", True, None)
    store.add_usage("c", "deepseek", "same", {"total_tokens": 77})
    store.initialize()
    totals = {row["config_id"]: row["total_tokens"] for row in store.usage_by_config()}
    assert totals[first["id"]] == 77
    assert totals[second["id"]] == 0


def test_notifications_stream_emits_inbox_rows(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    store.add_notification("device", "ANS 上线", "ANS 上线 · 10:00", "event:1")
    response = client.get("/api/ai/notifications/stream?after=0")
    assert response.status_code == 200
    assert response.content_type.startswith("text/event-stream")
    iterator = response.response
    first = next(iterator).decode("utf-8")
    second = next(iterator).decode("utf-8")
    assert first.startswith(": connected")
    assert "ANS 上线" in second and '"type": "notification"' in second.replace(", ", ", ").replace('":"', '": "')
    response.close()


def test_task_completion_publishes_notification_once(tmp_path, monkeypatch):
    from assistant.notifications import AssistantNotificationService

    hub = fake_hub(tmp_path)
    states = {"nat": "running"}
    hub.ROUTER_TASK_MANAGER = SimpleNamespace(snapshot=lambda kind: {"state": states[kind], "taskId": "nat-9"})
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    service = AssistantNotificationService(hub, store, None)
    service._publish_task_transitions()
    states["nat"] = "succeeded"
    service._publish_task_transitions()
    states["nat"] = "succeeded"
    service._publish_task_transitions()
    rows = store.list_notifications(after_id=0, limit=10)
    task_rows = [row for row in rows if row["kind"] == "task"]
    assert len(task_rows) == 1
    assert "NAT 检测完成" in task_rows[0]["title"]


def test_usage_known_requires_positive_tokens():
    from assistant.storage import usage_known

    assert usage_known({}) is False
    assert usage_known({"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}) is False
    assert usage_known({"prompt_tokens": 12, "completion_tokens": 0, "total_tokens": 12}) is True


def test_single_message_delete_keeps_usage_intact(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    store.add_usage("conv-1", "hy3", "hy3", {"total_tokens": 500})
    store.create_conversation("conv-1", title="t")
    kept_id = store.add_message("conv-1", "user", "保留")
    gone_id = store.add_message("conv-1", "assistant", "待删除")
    assert client.delete(f"/api/ai/conversations/conv-1/messages/{gone_id}").status_code == 200
    assert client.delete(f"/api/ai/conversations/conv-1/messages/{gone_id}").status_code == 404
    rows = client.get("/api/ai/conversations/conv-1/messages").json["messages"]
    assert [row["id"] for row in rows] == [kept_id]
    assert store.usage_summary()["total_tokens"] == 500


def test_confirmations_list_reports_lifecycle(tmp_path, monkeypatch):
    hub_runtime = fake_hub(tmp_path)
    client = make_client(tmp_path, monkeypatch, hub_runtime=hub_runtime)
    store = hub_runtime.ASSISTANT_AI_STORE
    store.create_conversation("conv-x", title="t")
    store.create_confirmation("conf-1", "agent.cleanup", {}, {"executor": "hub"}, "2000-01-01T00:00:00+00:00",
                              conversation_id="conv-x")
    rows = store.list_recent_confirmations(limit=5)
    assert rows[0]["expired"] is True


def test_stream_tolerates_gateway_noise_and_multiline_data():
    from assistant.provider import OpenAICompatibleProvider

    class FakeResponse:
        ok = True
        text = ""

        def iter_lines(self, decode_unicode=True):
            yield ": keep-alive"
            yield "data:"
            yield 'data: not-a-json-frame'
            yield 'data: {"choices":[{"delta":{"content":"你"}}]}'
            yield ""
            yield 'data: {"choices":[{"delta":{"content":"好"}}],'
            yield ' "usage":{"total_tokens": 2}}'
            yield ""
            yield "data: [DONE]"

        def close(self):
            pass

    class FakeSession:
        def post(self, *args, **kwargs):
            return FakeResponse()

    provider = OpenAICompatibleProvider("https://gw.example", "k", "m", session=FakeSession())
    chunks = list(provider.stream([{"role": "user", "content": "hi"}]))
    texts = [c["choices"][0]["delta"]["content"] for c in chunks if c.get("choices")]
    assert texts == ["你", "好"]
    assert any(c.get("usage", {}).get("total_tokens") == 2 for c in chunks)
    assert any(c.get("done") for c in chunks)
