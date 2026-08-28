"""Authenticated Flask blueprint for the first Hub AI surface."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List
from urllib.parse import urlparse

from flask import Blueprint, Response, jsonify, request, stream_with_context

from .provider import OpenAICompatibleProvider, ProviderError, usage_from_chunk
from .security import MasterKeyUnavailable, decrypt_secret, encrypt_secret, mask_secret
from .storage import AIStore
from .catalog import catalog, provider_tools, tool_id_from_function, tool_spec
from .domains import register_builtin
from .extend import drain_pending
from .notifications import AssistantNotificationService
from .tools import ToolError, ToolExecutor

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-flash"
MAX_MESSAGES = 80
MAX_MESSAGE_CHARS = 32_000
MAX_REQUEST_CHARS = 80_000
TOOL_SYSTEM_PROMPT = (
    "你是极客网探 Hub 助手，可以查看和控制整个网络：设备、事件、Agent/Relay、STUN 穿透、"
    "WireGuard、路由器端口映射、IPv6、每日记录、防火墙，以及让 APP 跳转页面或刷新数据。"
    "涉及查询时必须调用工具，不得猜测。只读工具可以直接调用；写入操作（新增/删除/启停端口映射"
    "或穿透规则、升级 Agent）只能生成确认请求，在收到工具执行成功结果前绝不能声称操作已经完成。"
    "回答使用简洁中文。"
)


def merge_usage(total: Dict[str, int], usage: Dict[str, int]) -> Dict[str, int]:
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        if key in usage:
            total[key] = int(total.get(key) or 0) + int(usage.get(key) or 0)
    return total


def create_ai_blueprint(*, check_app_token: Callable[[], bool], db_path, logger,
                        hub_runtime: Any = None, enable_notifications: bool = False) -> Blueprint:
    store = AIStore(db_path)
    store.initialize()
    executor = ToolExecutor(hub_runtime) if hub_runtime is not None else None
    if executor is not None:
        # Feature modules attach tool handlers via the hub runtime during
        # hub_entry install, before the first chat request arrives. Buffered
        # registrations are drained here, then the built-in domains bind.
        setattr(hub_runtime, "ASSISTANT_TOOL_EXECUTOR", executor)
        drain_pending(executor)
        register_builtin(executor)
    notification_service = None
    if hub_runtime is not None and enable_notifications:
        notification_service = AssistantNotificationService(hub_runtime, store, logger)
        notification_service.start()
    bp = Blueprint("hub_ai", __name__, url_prefix="/api/ai")

    def authorized():
        if not check_app_token():
            return jsonify({"error": "unauthorized"}), 401
        return None

    def config_view(row):
        key_configured = bool(row and row["api_key_ciphertext"])
        return {"configured": bool(row), "provider": row["provider"] if row else "deepseek",
                "baseUrl": row["base_url"] if row else DEFAULT_BASE_URL,
                "model": row["model"] if row else DEFAULT_MODEL,
                "enabled": bool(row["enabled"]) if row else False,
                "apiKey": mask_secret(row["api_key_ciphertext"]) if row else None,
                "apiKeyStatus": "configured" if key_configured else "not_configured"}

    @bp.get("/config")
    def get_config():
        denial = authorized()
        return denial or jsonify(config_view(store.get_config()))

    @bp.put("/config")
    def put_config():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        provider = str(body.get("provider", "deepseek")).lower()
        if provider != "deepseek":
            return jsonify({"error": "only the deepseek provider is supported"}), 400
        current = store.get_config()
        api_key = body.get("apiKey")
        if api_key is None and current:
            ciphertext = current["api_key_ciphertext"]
        elif isinstance(api_key, str) and api_key.strip():
            try:
                ciphertext = encrypt_secret(api_key.strip())
            except MasterKeyUnavailable as exc:
                return jsonify({"error": str(exc)}), 503
        else:
            return jsonify({"error": "apiKey is required for a new configuration"}), 400
        base_url = str(body.get("baseUrl") or (current["base_url"] if current else DEFAULT_BASE_URL)).rstrip("/")
        model = str(body.get("model") or (current["model"] if current else DEFAULT_MODEL))
        enabled = bool(body.get("enabled", bool(current["enabled"]) if current else True))
        parsed = urlparse(base_url)
        local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (parsed.scheme != "https" and not local_http) or not parsed.netloc or not model:
            return jsonify({"error": "baseUrl and model are invalid"}), 400
        store.save_config(provider, base_url, model, ciphertext, enabled)
        return jsonify(config_view(store.get_config()))

    @bp.delete("/config")
    def delete_config():
        denial = authorized()
        if denial:
            return denial
        store.delete_config()
        return "", 204

    @bp.get("/usage")
    def get_usage():
        denial = authorized()
        if denial:
            return denial
        try:
            limit = int(request.args.get("limit", 50))
        except (TypeError, ValueError):
            return jsonify({"error": "limit must be an integer"}), 400
        return jsonify({**store.usage_summary(), "recent": store.list_usage(limit),
                        "daily": store.usage_daily(14), "storage": store.conversation_storage()})

    @bp.get("/conversations")
    def list_conversations():
        denial = authorized()
        if denial:
            return denial
        try:
            limit = min(max(int(request.args.get("limit", "20")), 1), 50)
        except ValueError:
            limit = 20
        return jsonify({"conversations": store.list_conversations(limit)})

    @bp.get("/conversations/<conversation_id>/messages")
    def conversation_messages(conversation_id: str):
        denial = authorized()
        if denial:
            return denial
        messages = store.get_messages(conversation_id, limit=MAX_MESSAGES)
        return jsonify({"conversationId": conversation_id, "messages": messages})

    @bp.get("/catalog")
    def get_catalog():
        denial = authorized()
        return denial or jsonify(catalog())

    @bp.get("/notifications")
    def notifications():
        denial = authorized()
        if denial:
            return denial
        try:
            after = max(int(request.args.get("after", "0")), 0)
        except ValueError:
            after = 0
        rows = store.list_notifications(after_id=after, limit=100)
        return jsonify({"notifications": rows, "latestId": rows[-1]["id"] if rows else after})

    def require_executor():
        if executor is None:
            raise ToolError("Hub 工具运行时尚未就绪", "RUNTIME_UNAVAILABLE", 503)
        return executor

    def tool_error_response(exc: ToolError):
        return jsonify({"error": str(exc), "code": exc.code}), exc.status_code

    @bp.post("/tools/execute")
    def execute_tool():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        tool_id = str(body.get("toolId") or "")
        arguments = body.get("arguments") or {}
        client_context = body.get("clientContext") or {}
        request_id = str(uuid.uuid4())
        spec = tool_spec(tool_id) or {"risk": "unknown"}
        try:
            result = require_executor().execute(tool_id, arguments, client_context=client_context)
            store.add_tool_audit(request_id, tool_id, str(spec["risk"]), "completed", arguments, result)
            return jsonify({"requestId": request_id, "toolId": tool_id, "result": result})
        except ToolError as exc:
            store.add_tool_audit(request_id, tool_id, str(spec["risk"]), "rejected", arguments,
                                 {"code": exc.code, "error": str(exc)})
            return tool_error_response(exc)

    @bp.post("/tools/prepare")
    def prepare_tool():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        tool_id = str(body.get("toolId") or "")
        arguments = body.get("arguments") or {}
        client_context = body.get("clientContext") or {}
        try:
            preview = require_executor().preview(tool_id, arguments, client_context=client_context)
        except ToolError as exc:
            return tool_error_response(exc)
        confirmation_id = str(uuid.uuid4())
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds")
        store.create_confirmation(confirmation_id, tool_id, arguments, preview, expires_at)
        store.add_tool_audit(confirmation_id, tool_id, "write", "confirmation_required", arguments, preview)
        return jsonify({"confirmationId": confirmation_id, "expiresAt": expires_at, "preview": preview})

    @bp.post("/tools/confirm")
    def confirm_tool():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        confirmation_id = str(body.get("confirmationId") or "")
        pending = store.claim_confirmation(confirmation_id)
        if pending is None:
            return jsonify({"error": "确认已过期、已使用或不存在", "code": "CONFIRMATION_INVALID"}), 409
        if pending.get("preview", {}).get("executor") == "app":
            result = {"ok": True, "message": "用户已确认，交由 APP 本机执行"}
            store.finish_confirmation(confirmation_id, "client_confirmed", result)
            store.add_tool_audit(confirmation_id, pending["tool_id"], "write", "client_confirmed", pending["arguments"], result)
            return jsonify({
                "confirmationId": confirmation_id,
                "toolId": pending["tool_id"],
                "clientAction": pending["preview"],
                "result": result,
            })
        try:
            result = require_executor().execute(pending["tool_id"], pending["arguments"], allow_write=True)
            store.finish_confirmation(confirmation_id, "completed", result)
            store.add_tool_audit(confirmation_id, pending["tool_id"], "write", "completed", pending["arguments"], result)
            return jsonify({"confirmationId": confirmation_id, "toolId": pending["tool_id"], "result": result})
        except ToolError as exc:
            failure = {"code": exc.code, "error": str(exc)}
            store.finish_confirmation(confirmation_id, "failed", failure)
            store.add_tool_audit(confirmation_id, pending["tool_id"], "write", "failed", pending["arguments"], failure)
            return tool_error_response(exc)
        except Exception:
            failure = {"code": "TOOL_EXECUTION_FAILED", "error": "操作执行失败"}
            store.finish_confirmation(confirmation_id, "failed", failure)
            store.add_tool_audit(confirmation_id, pending["tool_id"], "write", "failed", pending["arguments"], failure)
            return jsonify(failure), 500

    @bp.post("/test")
    def test_config():
        denial = authorized()
        if denial:
            return denial
        row = store.get_config()
        if not row or not row["enabled"]:
            return jsonify({"error": "AI provider is not configured or disabled"}), 409
        try:
            key = decrypt_secret(row["api_key_ciphertext"])
            result = OpenAICompatibleProvider(row["base_url"], key, row["model"]).chat(
                [{"role": "user", "content": "Reply with OK."}]
            )
        except (MasterKeyUnavailable, ValueError) as exc:
            return jsonify({"error": str(exc)}), 503
        except ProviderError as exc:
            return jsonify({"error": str(exc), "status": "failed"}), exc.status_code
        return jsonify({"status": "ok", "usage": result.usage})

    @bp.post("/chat")
    def chat():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        client_context = body.get("clientContext") or {}
        if len(json.dumps(client_context, ensure_ascii=False)) > 32_000:
            return jsonify({"error": "clientContext exceeds the size limit"}), 413
        supplied = body.get("messages")
        if supplied is None and isinstance(body.get("message"), str):
            supplied = [{"role": "user", "content": body["message"]}]
        if not isinstance(supplied, list) or not supplied:
            return jsonify({"error": "messages must be a non-empty list"}), 400
        if len(supplied) > MAX_MESSAGES:
            return jsonify({"error": f"messages exceed the count limit (max {MAX_MESSAGES}); send only the latest turns"}), 400
        messages: List[Dict[str, str]] = []
        total_chars = 0
        for item in supplied:
            if not isinstance(item, dict) or item.get("role") not in {"system", "user", "assistant"} or not isinstance(item.get("content"), str):
                return jsonify({"error": "messages contain an invalid role or content"}), 400
            if len(item["content"]) > MAX_MESSAGE_CHARS:
                return jsonify({"error": "a message exceeds the size limit"}), 413
            total_chars += len(item["content"])
            messages.append({"role": item["role"], "content": item["content"]})
        if total_chars > MAX_REQUEST_CHARS:
            return jsonify({"error": "messages exceed the request size limit"}), 413
        row = store.get_config()
        if not row or not row["enabled"]:
            return jsonify({"error": "AI provider is not configured"}), 409
        try:
            key = decrypt_secret(row["api_key_ciphertext"])
        except (MasterKeyUnavailable, ValueError) as exc:
            return jsonify({"error": str(exc)}), 503
        conversation_id = str(body.get("conversationId") or uuid.uuid4())
        store.create_conversation(conversation_id)
        # The APP replays the visible history on every turn; replace stored
        # history instead of re-inserting it, or rows duplicate per request.
        store.replace_messages(conversation_id, messages)
        provider = OpenAICompatibleProvider(row["base_url"], key, row["model"])
        if body.get("stream"):
            def generate():
                parts, usage = [], {}
                try:
                    for chunk in provider.stream(messages):
                        delta = ((chunk.get("choices") or [{}])[0].get("delta") or {}).get("content", "")
                        if delta:
                            parts.append(delta)
                        usage.update(usage_from_chunk(chunk) or {})
                        yield "data: " + json.dumps(chunk, ensure_ascii=False) + "\n\n"
                    store.add_message(conversation_id, "assistant", "".join(parts))
                    store.add_usage(conversation_id, row["provider"], row["model"], usage)
                except ProviderError as exc:
                    store.add_usage(conversation_id, row["provider"], row["model"], usage, status="failed")
                    yield "event: error\ndata: " + json.dumps({"error": str(exc)}) + "\n\n"
            return Response(stream_with_context(generate()), content_type="text/event-stream")
        internal_messages: List[Dict[str, Any]] = list(messages)
        if not internal_messages or internal_messages[0].get("role") != "system":
            internal_messages.insert(0, {"role": "system", "content": TOOL_SYSTEM_PROMPT})
        accumulated_usage: Dict[str, int] = {}
        executions: List[Dict[str, Any]] = []
        client_actions: List[Dict[str, Any]] = []
        try:
            for _ in range(4):
                result = provider.chat(internal_messages, tools=provider_tools() if executor is not None else None)
                merge_usage(accumulated_usage, result.usage)
                assistant_message = result.message or {"role": "assistant", "content": result.content}
                assistant_message.setdefault("role", "assistant")
                tool_calls = assistant_message.get("tool_calls") or []
                if not isinstance(tool_calls, list) or not tool_calls:
                    if not result.content:
                        raise ProviderError("AI provider returned an empty response")
                    store.add_message(conversation_id, "assistant", result.content)
                    store.add_usage(conversation_id, row["provider"], row["model"], accumulated_usage)
                    return jsonify({
                        "conversationId": conversation_id,
                        "message": {"role": "assistant", "content": result.content},
                        "usage": accumulated_usage,
                        "toolExecutions": executions,
                        "clientActions": client_actions,
                    })
                internal_messages.append(assistant_message)
                for call in tool_calls[:4]:
                    call_id = str(call.get("id") or uuid.uuid4()) if isinstance(call, dict) else str(uuid.uuid4())
                    function = call.get("function") if isinstance(call, dict) else {}
                    function = function if isinstance(function, dict) else {}
                    tool_id = tool_id_from_function(str(function.get("name") or ""))
                    try:
                        arguments = json.loads(str(function.get("arguments") or "{}"))
                        if not isinstance(arguments, dict):
                            raise ValueError("arguments must be an object")
                    except (ValueError, json.JSONDecodeError):
                        arguments = {}
                        tool_payload = {"ok": False, "code": "INVALID_ARGUMENTS", "error": "工具参数不是有效 JSON"}
                    else:
                        tool_payload = {}
                    if tool_id is None:
                        tool_payload = {"ok": False, "code": "TOOL_NOT_FOUND", "error": "不支持该工具"}
                    elif not tool_payload:
                        spec = tool_spec(tool_id) or {"risk": "unknown"}
                        if spec["risk"] == "write":
                            try:
                                preview = require_executor().preview(tool_id, arguments, client_context=client_context)
                            except ToolError as exc:
                                tool_payload = {"ok": False, "code": exc.code, "error": str(exc)}
                                store.add_tool_audit(call_id, tool_id, "write", "rejected", arguments, tool_payload)
                            else:
                                confirmation_id = str(uuid.uuid4())
                                expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds")
                                store.create_confirmation(confirmation_id, tool_id, arguments, preview, expires_at)
                                store.add_tool_audit(confirmation_id, tool_id, "write", "confirmation_required", arguments, preview)
                                content = "需要你的确认：" + str(preview.get("summary") or preview.get("title") or tool_id)
                                store.add_message(conversation_id, "assistant", content)
                                store.add_usage(conversation_id, row["provider"], row["model"], accumulated_usage)
                                return jsonify({
                                    "conversationId": conversation_id,
                                    "message": {"role": "assistant", "content": content},
                                    "usage": accumulated_usage,
                                    "toolExecutions": executions,
                                    "clientActions": client_actions,
                                    "confirmation": {"confirmationId": confirmation_id, "expiresAt": expires_at, "preview": preview},
                                })
                        else:
                            try:
                                tool_result = require_executor().execute(tool_id, arguments, client_context=client_context)
                                tool_payload = {"ok": True, "result": tool_result}
                                if isinstance(tool_result, dict) and isinstance(tool_result.get("clientAction"), dict):
                                    client_actions.append(tool_result["clientAction"])
                                store.add_tool_audit(call_id, tool_id, str(spec["risk"]), "completed", arguments, tool_result)
                            except ToolError as exc:
                                tool_payload = {"ok": False, "code": exc.code, "error": str(exc)}
                                store.add_tool_audit(call_id, tool_id, str(spec["risk"]), "failed", arguments, tool_payload)
                    executions.append({"toolId": tool_id, "status": "completed" if tool_payload.get("ok") else "failed"})
                    internal_messages.append({
                        "role": "tool", "tool_call_id": call_id,
                        "content": json.dumps(tool_payload, ensure_ascii=False, separators=(",", ":")),
                    })
            raise ProviderError("AI tool call limit exceeded")
        except ProviderError as exc:
            store.add_usage(conversation_id, row["provider"], row["model"], accumulated_usage, status="failed")
            return jsonify({"error": str(exc)}), exc.status_code

    return bp
