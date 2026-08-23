"""Authenticated Flask blueprint for the first Hub AI surface."""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Dict, List
from urllib.parse import urlparse

from flask import Blueprint, Response, jsonify, request, stream_with_context

from .provider import OpenAICompatibleProvider, ProviderError, usage_from_chunk
from .security import MasterKeyUnavailable, decrypt_secret, encrypt_secret, mask_secret
from .storage import AIStore
from .catalog import catalog

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-flash"
MAX_MESSAGES = 40
MAX_MESSAGE_CHARS = 32_000
MAX_REQUEST_CHARS = 80_000


def create_ai_blueprint(*, check_app_token: Callable[[], bool], db_path, logger) -> Blueprint:
    store = AIStore(db_path)
    store.initialize()
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
        return denial or jsonify(store.usage_summary())

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
        supplied = body.get("messages")
        if supplied is None and isinstance(body.get("message"), str):
            supplied = [{"role": "user", "content": body["message"]}]
        if not isinstance(supplied, list) or not supplied or len(supplied) > MAX_MESSAGES:
            return jsonify({"error": "messages must be a non-empty list"}), 400
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
        for message in messages:
            store.add_message(conversation_id, message["role"], message["content"])
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
        try:
            result = provider.chat(messages)
        except ProviderError as exc:
            store.add_usage(conversation_id, row["provider"], row["model"], {}, status="failed")
            return jsonify({"error": str(exc)}), exc.status_code
        store.add_message(conversation_id, "assistant", result.content)
        store.add_usage(conversation_id, row["provider"], row["model"], result.usage)
        return jsonify({"conversationId": conversation_id, "message": {"role": "assistant", "content": result.content}, "usage": result.usage})

    return bp
