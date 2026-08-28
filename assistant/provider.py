"""OpenAI-compatible provider transport, including DeepSeek SSE usage frames."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Protocol

import requests


class ProviderError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def parse_sse_line(line: str) -> Optional[Dict[str, Any]]:
    if not line or not line.startswith("data:"):
        return None
    data = line[5:].strip()
    if data == "[DONE]":
        return {"done": True}
    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        raise ProviderError("provider returned invalid SSE JSON") from exc


def usage_from_chunk(chunk: Dict[str, Any]) -> Optional[Dict[str, int]]:
    usage = chunk.get("usage")
    if not isinstance(usage, dict):
        return None
    values: Dict[str, int] = {key: int(usage[key]) for key in ("prompt_tokens", "completion_tokens", "total_tokens")
                              if key in usage and usage[key] is not None}
    # Cache-hit reporting: DeepSeek names them prompt_cache_*; Anthropic-style
    # providers use cache_read/cache_creation. Normalise into hit/miss pairs.
    hit = usage.get("prompt_cache_hit_tokens", usage.get("cache_read_input_tokens"))
    miss = usage.get("prompt_cache_miss_tokens", usage.get("cache_creation_input_tokens"))
    try:
        if hit is not None:
            values["cache_hit_tokens"] = int(hit)
        if miss is not None:
            values["cache_miss_tokens"] = int(miss)
    except (TypeError, ValueError):
        pass
    return values or None


@dataclass
class ChatResult:
    content: str
    usage: Dict[str, int]
    message: Optional[Dict[str, Any]] = None


class ChatProvider(Protocol):
    """Provider boundary; additional vendors need only implement these calls."""
    def chat(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> ChatResult: ...
    def stream(self, messages: List[Dict[str, Any]]) -> Iterator[Dict[str, Any]]: ...


class OpenAICompatibleProvider:
    def __init__(self, base_url: str, api_key: str, model: str, session: Any = requests):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.session = session

    def _request(self, messages: List[Dict[str, Any]], stream: bool,
                 tools: Optional[List[Dict[str, Any]]] = None):
        payload: Dict[str, Any] = {"model": self.model, "messages": messages, "stream": stream}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if stream:
            payload["stream_options"] = {"include_usage": True}
        try:
            endpoint = self.base_url if self.base_url.endswith("/chat/completions") else self.base_url + "/chat/completions"
            response = self.session.post(endpoint, json=payload,
                headers={"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json"},
                timeout=(5, 90), stream=stream)
        except requests.RequestException as exc:
            raise ProviderError("AI provider is unavailable") from exc
        if not response.ok:
            status_code = response.status_code if response.status_code < 500 else 502
            response.close()
            raise ProviderError("AI provider rejected the request", status_code)
        return response

    def chat(self, messages: List[Dict[str, Any]],
             tools: Optional[List[Dict[str, Any]]] = None) -> ChatResult:
        response = self._request(messages, False, tools)
        try:
            body = response.json()
            choice = body["choices"][0]["message"]
            message = {
                key: choice[key]
                for key in ("role", "content", "reasoning_content", "tool_calls")
                if key in choice
            }
            return ChatResult(str(choice.get("content") or ""), usage_from_chunk(body) or {}, message)
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise ProviderError("AI provider returned an invalid response") from exc
        finally:
            response.close()

    def stream(self, messages: List[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
        response = self._request(messages, True)
        try:
            for raw in response.iter_lines(decode_unicode=True):
                chunk = parse_sse_line(raw)
                if chunk is not None:
                    yield chunk
        except requests.RequestException as exc:
            raise ProviderError("AI provider stream was interrupted") from exc
        finally:
            response.close()
