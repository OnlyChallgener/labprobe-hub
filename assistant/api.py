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
TENCENT_HUNYUAN_BASE_URL = "https://tokenhub.tencentmaas.com/v1"
MAX_MESSAGES = 80
MAX_MESSAGE_CHARS = 32_000
MAX_REQUEST_CHARS = 80_000
TOOL_SYSTEM_PROMPT = (
    "你是极客网探 Hub 助手，可以查看和控制整个网络：设备、事件、Agent/Relay、STUN 穿透、"
    "WireGuard、路由器端口映射、IPv6、每日记录、防火墙，以及让 APP 跳转页面或刷新数据。"
    "涉及查询时必须调用工具，不得猜测。只读工具可以直接调用；写入操作（新增/删除/启停端口映射"
    "或穿透规则、升级 Agent）只能生成确认请求，在收到工具执行成功结果前绝不能声称操作已经完成。"
    "用户说‘网络自检’时调用 network.self_check；说‘路由网络自检/路由器自检’时调用 router.diagnostic；"
    "说‘NAT检测’时调用 router.nat.diagnostic。检测和自检绝不能调用 app.navigate，只有明确要求打开/进入/跳转页面时才允许导航。"
    "回答使用简洁中文。"
)


def merge_usage(total: Dict[str, int], usage: Dict[str, int]) -> Dict[str, int]:
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        if key in usage:
            total[key] = int(total.get(key) or 0) + int(usage.get(key) or 0)
    return total


def diagnostic_tool_intent(text: str) -> str | None:
    normalized = "".join(str(text or "").lower().split())
    if any(word in normalized for word in ("打开", "进入", "跳转", "页面")):
        return None
    if "nat" in normalized and any(word in normalized for word in ("检测", "诊断", "自检")):
        return "router.nat.diagnostic"
    if any(word in normalized for word in ("路由网络自检", "路由器自检", "路由设置-网络自检", "路由设置—网络自检")):
        return "router.diagnostic"
    if "网络自检" in normalized:
        return "network.self_check"
    return None


def diagnostic_result_content(tool_id: str, result: Dict[str, Any]) -> str:
    lines = [str(result.get("message") or "检测请求已执行")]
    task = result.get("task") if isinstance(result.get("task"), dict) else None
    if task:
        state = str(task.get("state") or "unknown")
        stage = str(task.get("stageText") or task.get("stage") or "").strip()
        lines.append(f"状态：{state}" + (f" · {stage}" if stage else ""))
        detail = task.get("result")
        if isinstance(detail, (dict, list)) and detail:
            lines.append("结果：" + json.dumps(detail, ensure_ascii=False, separators=(",", ":"))[:6000])
    elif isinstance(result.get("summary"), dict):
        lines.append("结果：" + json.dumps(result["summary"], ensure_ascii=False, separators=(",", ":"))[:6000])
    return "\n".join(lines)


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
        return {"id": int(row["id"]) if row else None,
                "name": row["name"] if row else "DeepSeek",
                "configured": bool(row), "provider": row["provider"] if row else "deepseek",
                "baseUrl": row["base_url"] if row else DEFAULT_BASE_URL,
                "model": row["model"] if row else DEFAULT_MODEL,
                "enabled": bool(row["enabled"]) if row else False,
                "tokenQuota": row["model_quota_tokens"] if row else None,
                "modelQuotaTokens": row["model_quota_tokens"] if row else None,
                "apiKey": mask_secret(row["api_key_ciphertext"]) if row else None,
                "apiKeyStatus": "configured" if key_configured else "not_configured"}

    def configs_response():
        rows = store.list_configs()
        primary = rows[0] if rows else None
        return {**config_view(primary), "configs": [config_view(row) for row in rows]}

    def default_base_url(provider: str) -> str:
        normalized = "".join(str(provider or "").lower().replace("-", "_").split())
        if normalized in {"hunyuan", "tencent", "tencent_hunyuan", "腾讯混元", "混元"}:
            return TENCENT_HUNYUAN_BASE_URL
        return DEFAULT_BASE_URL

    def parse_quota(body: Dict[str, Any], current: Any = None):
        supplied = "tokenQuota" in body or "modelQuotaTokens" in body
        if not supplied:
            return current["model_quota_tokens"] if current else None
        raw = body.get("tokenQuota") if "tokenQuota" in body else body.get("modelQuotaTokens")
        if raw is None or raw == "":
            return None
        if isinstance(raw, bool):
            raise ValueError("tokenQuota must be a positive integer or null")
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("tokenQuota must be a positive integer or null") from exc
        if value <= 0:
            raise ValueError("tokenQuota must be a positive integer or null")
        return value

    def save_config_request(*, create: bool):
        body = request.get_json(silent=True) or {}
        config_id = body.get("id")
        current = None
        if not create:
            try:
                current = store.get_config(int(config_id)) if config_id is not None else store.get_config()
            except (TypeError, ValueError):
                return jsonify({"error": "id must be an integer"}), 400
            if config_id is not None and current is None:
                return jsonify({"error": "AI configuration was not found"}), 404
        provider = str(body.get("provider") or (current["provider"] if current else "deepseek")).strip().lower()
        if not provider or len(provider) > 64:
            return jsonify({"error": "provider is invalid"}), 400
        model = str(body.get("model") or (current["model"] if current else DEFAULT_MODEL)).strip()
        if not model or len(model) > 200:
            return jsonify({"error": "model is invalid"}), 400
        name = str(body.get("name") or (current["name"] if current else model)).strip()
        if not name or len(name) > 64:
            return jsonify({"error": "name must contain 1 to 64 characters"}), 400
        provider_changed = bool(current and provider != str(current["provider"]).lower())
        fallback_url = default_base_url(provider) if provider_changed or not current else current["base_url"]
        base_url = str(body.get("baseUrl") or fallback_url).strip().rstrip("/")
        parsed = urlparse(base_url)
        local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (parsed.scheme != "https" and not local_http) or not parsed.netloc:
            return jsonify({"error": "baseUrl is invalid"}), 400
        api_key = body.get("apiKey")
        if current and (api_key is None or str(api_key).strip() in {"", "configured"}):
            ciphertext = current["api_key_ciphertext"]
        elif isinstance(api_key, str) and api_key.strip():
            try:
                ciphertext = encrypt_secret(api_key.strip())
            except MasterKeyUnavailable as exc:
                return jsonify({"error": str(exc)}), 503
        else:
            return jsonify({"error": "apiKey is required for a new configuration"}), 400
        try:
            quota = parse_quota(body, current)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        enabled = bool(body.get("enabled", bool(current["enabled"]) if current else True))
        if create or current is None:
            saved = store.create_config(name, provider, base_url, model, ciphertext, enabled, quota)
        else:
            saved = store.update_config(
                current["id"], name=name, provider=provider, base_url=base_url, model=model,
                ciphertext=ciphertext, enabled=enabled, model_quota_tokens=quota,
                position=int(current["position"]),
            )
        return jsonify(config_view(saved))

    @bp.get("/config")
    def get_config():
        denial = authorized()
        return denial or jsonify(configs_response())

    @bp.get("/configs")
    def get_configs_alias():
        denial = authorized()
        return denial or jsonify(configs_response())

    @bp.post("/config")
    def post_config():
        denial = authorized()
        return denial or save_config_request(create=True)

    @bp.put("/config")
    def put_config():
        denial = authorized()
        if denial:
            return denial
        return save_config_request(create=False)

    @bp.delete("/config")
    def delete_config():
        denial = authorized()
        if denial:
            return denial
        store.delete_config()
        return "", 204

    @bp.delete("/config/<int:config_id>")
    def delete_config_by_id(config_id: int):
        denial = authorized()
        if denial:
            return denial
        if not store.delete_config(config_id):
            return jsonify({"error": "AI configuration was not found"}), 404
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
                        "daily": store.usage_daily(14), "storage": store.conversation_storage(),
                        "config_usage": store.usage_by_config(),
                        "model_usage": store.usage_by_model()})

    @bp.get("/conversations")
    def list_conversations():
        denial = authorized()
        if denial:
            return denial
        raw_limit = request.args.get("limit")
        try:
            limit = max(int(raw_limit), 1) if raw_limit is not None else None
        except ValueError:
            limit = None
        return jsonify({"conversations": store.list_conversations(limit)})

    @bp.get("/conversations/<conversation_id>/messages")
    def conversation_messages(conversation_id: str):
        denial = authorized()
        if denial:
            return denial
        messages = store.get_messages(conversation_id, limit=MAX_MESSAGES)
        return jsonify({"conversationId": conversation_id, "messages": messages})

    @bp.patch("/conversations/<conversation_id>")
    def rename_conversation(conversation_id: str):
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        if not isinstance(body.get("title"), str):
            return jsonify({"error": "title is required"}), 400
        try:
            row = store.rename_conversation(conversation_id, body["title"])
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if row is None:
            return jsonify({"error": "conversation was not found"}), 404
        return jsonify({"conversation": row})

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
        normalized_arguments = preview.get("arguments") if isinstance(preview.get("arguments"), dict) else arguments
        store.create_confirmation(confirmation_id, tool_id, normalized_arguments, preview, expires_at)
        store.add_tool_audit(confirmation_id, tool_id, "write", "confirmation_required", normalized_arguments, preview)
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
            store.add_tool_audit(confirmation_id, pending["tool_id"], "write", "client_executing", pending["arguments"], result)
            return jsonify({
                "confirmationId": confirmation_id,
                "toolId": pending["tool_id"],
                "clientAction": pending["preview"],
                "result": result,
            })
        if pending["tool_id"] == "batch":
            items = pending["arguments"].get("tools") or []
            results = []
            failed = False
            for item in items:
                tool_id = str(item.get("toolId") or "")
                arguments = item.get("arguments") or {}
                try:
                    item_result = require_executor().execute(tool_id, arguments, allow_write=True)
                    results.append({"toolId": tool_id, "ok": True, "result": item_result})
                    store.add_tool_audit(f"{confirmation_id}:{tool_id}", tool_id, "write", "completed", arguments, item_result)
                except ToolError as exc:
                    results.append({"toolId": tool_id, "ok": False, "error": str(exc)})
                    store.add_tool_audit(f"{confirmation_id}:{tool_id}", tool_id, "write", "failed", arguments, {"code": exc.code, "error": str(exc)})
                    failed = True
                    break
                except Exception:
                    results.append({"toolId": tool_id, "ok": False, "error": "操作执行失败"})
                    store.add_tool_audit(f"{confirmation_id}:{tool_id}", tool_id, "write", "failed", arguments, {"code": "TOOL_EXECUTION_FAILED"})
                    failed = True
                    break
            summary_result = {"ok": not failed, "message": f"已完成 {sum(1 for r in results if r['ok'])}/{len(items)} 项操作", "items": results}
            store.finish_confirmation(confirmation_id, "failed" if failed else "completed", summary_result)
            return jsonify({"confirmationId": confirmation_id, "toolId": "batch", "result": summary_result})
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

    @bp.post("/tools/complete")
    def complete_client_tool():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        confirmation_id = str(body.get("confirmationId") or "")
        ok = body.get("ok") is True
        message = str(body.get("message") or ("APP 本机操作已完成" if ok else "APP 本机操作失败"))[:1000]
        result = {"ok": ok, "message": message}
        pending = store.complete_client_confirmation(
            confirmation_id, "completed" if ok else "failed", result,
        )
        if pending is None:
            return jsonify({"error": "确认未在执行中、已过期或已完成", "code": "CONFIRMATION_INVALID"}), 409
        store.add_tool_audit(
            confirmation_id, pending["tool_id"], "write", "completed" if ok else "failed",
            pending["arguments"], result,
        )
        return jsonify({"confirmationId": confirmation_id, "toolId": pending["tool_id"], "result": result})

    @bp.post("/test")
    @bp.post("/config/<int:config_id>/test")
    def test_config(config_id: int | None = None):
        denial = authorized()
        if denial:
            return denial
        path_config_id = config_id
        if config_id is None:
            try:
                query_id = request.args.get("id")
                config_id = int(query_id) if query_id is not None else None
            except (TypeError, ValueError):
                return jsonify({"error": "id must be an integer"}), 400
        if path_config_id is not None:
            selected = store.get_config(config_id)
            rows = [selected] if selected and selected["enabled"] else []
        else:
            rows = store.list_configs(enabled_only=True)
            if config_id is not None:
                rows.sort(key=lambda row: 0 if int(row["id"]) == config_id else 1)
        if not rows:
            return jsonify({"error": "AI provider is not configured or disabled"}), 409
        last_error: Exception | None = None
        last_status = 502
        for row in rows:
            try:
                key = decrypt_secret(row["api_key_ciphertext"])
                result = OpenAICompatibleProvider(row["base_url"], key, row["model"]).chat(
                    [{"role": "user", "content": "Reply with OK."}]
                )
            except MasterKeyUnavailable as exc:
                return jsonify({"error": str(exc)}), 503
            except ValueError as exc:
                last_error, last_status = exc, 503
                store.add_usage("", row["provider"], row["model"], {}, status="failed", config_id=row["id"])
                continue
            except ProviderError as exc:
                last_error, last_status = exc, exc.status_code
                store.add_usage("", row["provider"], row["model"], {}, status="failed", config_id=row["id"])
                continue
            store.add_usage("", row["provider"], row["model"], result.usage, config_id=row["id"])
            response = {"status": "ok", "usage": result.usage}
            if path_config_id is not None:
                response.update({"configId": row["id"], "provider": row["provider"], "model": row["model"]})
            return jsonify(response)
        return jsonify({"error": str(last_error or "AI provider is unavailable"), "status": "failed"}), last_status

    @bp.post("/chat")
    def chat():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        client_context = body.get("clientContext") or {}
        if len(json.dumps(client_context, ensure_ascii=False)) > 32_000:
            return jsonify({"error": "clientContext exceeds the size limit"}), 413
        incremental = isinstance(body.get("message"), str) and body.get("messages") is None
        supplied = [{"role": "user", "content": body["message"]}] if incremental else body.get("messages")
        if not isinstance(supplied, list) or not supplied:
            return jsonify({"error": "messages must be a non-empty list"}), 400
        if len(supplied) > MAX_MESSAGES:
            return jsonify({"error": f"messages exceed the count limit (max {MAX_MESSAGES}); send only the latest turns"}), 400
        messages: List[Dict[str, str]] = []
        total_chars = 0
        for item in supplied:
            if not isinstance(item, dict) or item.get("role") not in {"user", "assistant"} or not isinstance(item.get("content"), str):
                return jsonify({"error": "messages contain an invalid role or content"}), 400
            if len(item["content"]) > MAX_MESSAGE_CHARS:
                return jsonify({"error": "a message exceeds the size limit"}), 413
            total_chars += len(item["content"])
            messages.append({"role": item["role"], "content": item["content"]})
        if total_chars > MAX_REQUEST_CHARS:
            return jsonify({"error": "messages exceed the request size limit"}), 413
        conversation_id = str(body.get("conversationId") or uuid.uuid4())
        first_user_message = next((item["content"] for item in messages if item["role"] == "user"), None)
        store.create_conversation(conversation_id, title=first_user_message)
        if incremental:
            store.add_message(conversation_id, "user", messages[0]["content"])
            messages = [
                {"role": item["role"], "content": item["content"]}
                for item in store.get_messages(conversation_id, limit=MAX_MESSAGES)
            ]
        else:
            # Compatibility for older APP builds that still send a bounded transcript.
            store.replace_messages(conversation_id, messages)
        latest_user_text = next(
            (item["content"] for item in reversed(messages) if item["role"] == "user"), "",
        )
        forced_tool_id = diagnostic_tool_intent(latest_user_text)
        if forced_tool_id and executor is not None:
            try:
                tool_result = executor.execute(forced_tool_id, {})
            except ToolError as exc:
                return tool_error_response(exc)
            content = diagnostic_result_content(forced_tool_id, tool_result)
            store.add_message(conversation_id, "assistant", content)
            return jsonify({
                "conversationId": conversation_id,
                "message": {"role": "assistant", "content": content},
                "usage": {},
                "usageKnown": False,
                "toolExecutions": [{"toolId": forced_tool_id, "status": "completed"}],
                "clientActions": [],
            })
        config_rows = store.list_configs(enabled_only=True)
        if not config_rows:
            return jsonify({"error": "AI provider is not configured"}), 409
        if body.get("stream"):
            def generate():
                last_error: Exception | None = None
                for candidate in config_rows:
                    parts: List[str] = []
                    usage: Dict[str, int] = {}
                    chunks: List[Dict[str, Any]] = []
                    try:
                        key = decrypt_secret(candidate["api_key_ciphertext"])
                        provider = OpenAICompatibleProvider(candidate["base_url"], key, candidate["model"])
                        for chunk in provider.stream(messages):
                            chunks.append(chunk)
                            delta = ((chunk.get("choices") or [{}])[0].get("delta") or {}).get("content", "")
                            if delta:
                                parts.append(delta)
                            usage.update(usage_from_chunk(chunk) or {})
                    except MasterKeyUnavailable as exc:
                        last_error = exc
                        break
                    except (ValueError, ProviderError) as exc:
                        last_error = exc
                        store.add_usage(conversation_id, candidate["provider"], candidate["model"], usage,
                                        status="failed", config_id=candidate["id"])
                        continue
                    store.add_message(conversation_id, "assistant", "".join(parts))
                    store.add_usage(conversation_id, candidate["provider"], candidate["model"], usage,
                                    config_id=candidate["id"])
                    for chunk in chunks:
                        yield "data: " + json.dumps(chunk, ensure_ascii=False) + "\n\n"
                    return
                yield "event: error\ndata: " + json.dumps(
                    {"error": str(last_error or "AI provider is unavailable")}, ensure_ascii=False,
                ) + "\n\n"
            return Response(stream_with_context(generate()), content_type="text/event-stream")
        internal_messages: List[Dict[str, Any]] = list(messages)
        if not internal_messages or internal_messages[0].get("role") != "system":
            internal_messages.insert(0, {"role": "system", "content": TOOL_SYSTEM_PROMPT})
        accumulated_usage: Dict[str, int] = {}
        config_index = -1
        active_row: Dict[str, Any] | None = None
        active_provider: Any = None

        def provider_chat(chat_messages, tools=None):
            nonlocal config_index, active_row, active_provider, accumulated_usage
            last_error: ProviderError | None = None
            while True:
                if active_provider is None:
                    config_index += 1
                    if config_index >= len(config_rows):
                        raise last_error or ProviderError("AI provider is unavailable")
                    active_row = config_rows[config_index]
                    try:
                        key = decrypt_secret(active_row["api_key_ciphertext"])
                    except MasterKeyUnavailable as exc:
                        raise ProviderError(str(exc), 503) from exc
                    except ValueError as exc:
                        store.add_usage(conversation_id, active_row["provider"], active_row["model"], {},
                                        status="failed", config_id=active_row["id"])
                        active_row = None
                        last_error = ProviderError(str(exc), 503)
                        continue
                    active_provider = OpenAICompatibleProvider(
                        active_row["base_url"], key, active_row["model"],
                    )
                try:
                    result = active_provider.chat(chat_messages, tools=tools)
                except ProviderError as exc:
                    last_error = exc
                    if active_row is not None:
                        store.add_usage(
                            conversation_id, active_row["provider"], active_row["model"], accumulated_usage,
                            status="failed", config_id=active_row["id"],
                        )
                    accumulated_usage = {}
                    active_row = None
                    active_provider = None
                    continue
                merge_usage(accumulated_usage, result.usage)
                return result
        executions: List[Dict[str, Any]] = []
        client_actions: List[Dict[str, Any]] = []
        pending_writes: List[Dict[str, Any]] = []
        try:
            for _ in range(4):
                result = provider_chat(internal_messages, tools=provider_tools() if executor is not None else None)
                assistant_message = result.message or {"role": "assistant", "content": result.content}
                assistant_message.setdefault("role", "assistant")
                tool_calls = assistant_message.get("tool_calls") or []
                if not isinstance(tool_calls, list) or not tool_calls:
                    if not result.content:
                        raise ProviderError("AI provider returned an empty response")
                    store.add_message(conversation_id, "assistant", result.content)
                    if not accumulated_usage and logger is not None:
                        logger.warning("ai: provider returned no usage tokens (model=%s)", active_row["model"])
                    store.add_usage(conversation_id, active_row["provider"], active_row["model"],
                                    accumulated_usage, config_id=active_row["id"])
                    return jsonify({
                        "conversationId": conversation_id,
                        "message": {"role": "assistant", "content": result.content},
                        "usage": accumulated_usage,
                        "usageKnown": bool(accumulated_usage),
                        "configId": active_row["id"],
                        "provider": active_row["provider"],
                        "model": active_row["model"],
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
                        guarded_tool_id = diagnostic_tool_intent(latest_user_text)
                        if tool_id == "app.navigate" and guarded_tool_id:
                            tool_id = guarded_tool_id
                            arguments = {}
                        spec = tool_spec(tool_id) or {"risk": "unknown"}
                        if spec["risk"] == "write":
                            try:
                                preview = require_executor().preview(tool_id, arguments, client_context=client_context)
                            except ToolError as exc:
                                tool_payload = {"ok": False, "code": exc.code, "error": str(exc)}
                                store.add_tool_audit(call_id, tool_id, "write", "rejected", arguments, tool_payload)
                            else:
                                normalized_arguments = preview.get("arguments") if isinstance(preview.get("arguments"), dict) else arguments
                                signature = tool_id + "|" + json.dumps(normalized_arguments, sort_keys=True, ensure_ascii=False)
                                if signature not in {p["signature"] for p in pending_writes}:
                                    pending_writes.append({
                                        "signature": signature, "toolId": tool_id,
                                        "arguments": normalized_arguments, "preview": preview,
                                    })
                                continue
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
                if pending_writes:
                    confirmation_id = str(uuid.uuid4())
                    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds")
                    if len(pending_writes) == 1:
                        first = pending_writes[0]
                        preview = dict(first["preview"])
                        confirm_tool_id = first["toolId"]
                        confirm_arguments = first["arguments"]
                    else:
                        confirm_tool_id = "batch"
                        confirm_arguments = {"tools": [{"toolId": p["toolId"], "arguments": p["arguments"]} for p in pending_writes]}
                        preview = {
                            "toolId": "batch",
                            "title": f"确认执行 {len(pending_writes)} 项操作",
                            "summary": "；".join(
                                str(p["preview"].get("summary") or p["preview"].get("title") or p["toolId"])
                                for p in pending_writes
                            ),
                            "arguments": confirm_arguments,
                            "executor": "hub",
                        }
                    store.create_confirmation(confirmation_id, confirm_tool_id, confirm_arguments, preview, expires_at)
                    for item in pending_writes:
                        store.add_tool_audit(confirmation_id, item["toolId"], "write", "confirmation_required", item["arguments"], item["preview"])
                    content = "需要你的确认：" + str(preview.get("summary") or preview.get("title") or confirm_tool_id)
                    store.add_message(conversation_id, "assistant", content)
                    store.add_usage(conversation_id, active_row["provider"], active_row["model"],
                                    accumulated_usage, config_id=active_row["id"])
                    return jsonify({
                        "conversationId": conversation_id,
                        "message": {"role": "assistant", "content": content},
                        "usage": accumulated_usage,
                        "usageKnown": bool(accumulated_usage),
                        "configId": active_row["id"],
                        "provider": active_row["provider"],
                        "model": active_row["model"],
                        "toolExecutions": executions,
                        "clientActions": client_actions,
                        "confirmation": {"confirmationId": confirmation_id, "expiresAt": expires_at, "preview": preview},
                    })
            raise ProviderError("AI tool call limit exceeded")
        except ProviderError as exc:
            if active_row is not None:
                store.add_usage(conversation_id, active_row["provider"], active_row["model"],
                                accumulated_usage, status="failed", config_id=active_row["id"])
            return jsonify({"error": str(exc)}), exc.status_code

    return bp
