"""OpenAI-compatible provider transport, including robust SSE parsing."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Protocol

import requests


class ProviderError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def _json_object(data: str) -> Dict[str, Any]:
    try:
        value = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ProviderError("AI 服务商返回的 SSE 数据格式错误") from exc
    if not isinstance(value, dict):
        raise ProviderError("AI 服务商返回的 SSE 事件不是对象")
    return value


def parse_sse_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a complete one-line SSE data field and reject JSON scalars."""
    if not line or not line.startswith("data:"):
        return None
    data = line[5:].strip()
    if not data:
        return None
    if data == "[DONE]":
        return {"done": True}
    return _json_object(data)


def usage_from_chunk(chunk: Any) -> Optional[Dict[str, int]]:
    if not isinstance(chunk, dict):
        return None
    usage = chunk.get("usage")
    if not isinstance(usage, dict):
        return None
    values: Dict[str, int] = {}

    def first_int(*candidates: Any) -> Optional[int]:
        for candidate in candidates:
            if candidate is None or isinstance(candidate, bool):
                continue
            try:
                return max(0, int(candidate))
            except (TypeError, ValueError):
                continue
        return None

    anthropic_read = first_int(usage.get("cache_read_input_tokens"))
    anthropic_creation = first_int(usage.get("cache_creation_input_tokens"))
    anthropic_cache_usage = anthropic_read is not None or anthropic_creation is not None
    prompt = first_int(usage.get("prompt_tokens"))
    if prompt is None and anthropic_cache_usage:
        # Anthropic reports uncached input, cache writes and cache reads as
        # separate billing buckets. Their complete logical prompt is the sum.
        uncached_input = first_int(usage.get("input_tokens")) or 0
        prompt = uncached_input + int(anthropic_read or 0) + int(anthropic_creation or 0)
    elif prompt is None:
        prompt = first_int(usage.get("input_tokens"))
    completion = first_int(usage.get("completion_tokens"), usage.get("output_tokens"))
    total = first_int(usage.get("total_tokens"))
    if prompt is not None:
        values["prompt_tokens"] = prompt
    if completion is not None:
        values["completion_tokens"] = completion
    if total is not None:
        values["total_tokens"] = total
    elif prompt is not None or completion is not None:
        values["total_tokens"] = int(prompt or 0) + int(completion or 0)

    prompt_details = usage.get("prompt_tokens_details")
    prompt_details = prompt_details if isinstance(prompt_details, dict) else {}
    input_details = usage.get("input_tokens_details")
    input_details = input_details if isinstance(input_details, dict) else {}
    if anthropic_cache_usage and usage.get("prompt_cache_hit_tokens") is None:
        explicit_hit = int(anthropic_read or 0)
        explicit_miss = (
            (first_int(usage.get("input_tokens")) or 0)
            + int(anthropic_creation or 0)
        )
    else:
        explicit_hit = first_int(
            usage.get("prompt_cache_hit_tokens"),
            prompt_details.get("cached_tokens"),
            input_details.get("cached_tokens"),
        )
        explicit_miss = first_int(usage.get("prompt_cache_miss_tokens"))
    if explicit_hit is not None or explicit_miss is not None:
        hit = int(explicit_hit or 0)
        miss = int(explicit_miss or 0)
        # OpenAI's nested cached_tokens is a complete split against prompt
        # tokens; several OpenAI-compatible providers instead expose only a
        # partial hit/miss pair. Preserve the reported coverage so the APP can
        # distinguish "not cached" from "provider did not report it".
        nested_cached = (
            prompt_details.get("cached_tokens") is not None
            or input_details.get("cached_tokens") is not None
        )
        if nested_cached and explicit_miss is None and prompt is not None:
            miss = max(0, prompt - hit)
        values["cache_hit_tokens"] = hit
        values["cache_miss_tokens"] = miss
        values["cache_reported_input_tokens"] = hit + miss
    return values or None


def accumulate_tool_call_fragment(acc: Dict[str, Dict[str, str]], delta_tool_calls: Any) -> None:
    """Merge one chunk's delta.tool_calls into {index: {"id","name","arguments"}}."""
    if not isinstance(delta_tool_calls, list):
        return
    for fragment in delta_tool_calls:
        if not isinstance(fragment, dict):
            continue
        try:
            index = int(fragment.get("index") or 0)
        except (TypeError, ValueError):
            index = 0
        slot = acc.setdefault(index, {"id": "", "name": "", "arguments": ""})
        slot["id"] += str(fragment.get("id") or "")
        function = fragment.get("function") if isinstance(fragment.get("function"), dict) else {}
        slot["name"] += str(function.get("name") or "")
        slot["arguments"] += str(function.get("arguments") or "")


def tool_calls_from_accumulated(acc: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
    return [{
        "id": slot["id"] or f"call_{index}",
        "type": "function",
        "function": {"name": slot["name"], "arguments": slot["arguments"] or "{}"},
    } for index, slot in sorted(acc.items())]


@dataclass
class ChatResult:
    content: str
    usage: Dict[str, int]
    message: Optional[Dict[str, Any]] = None


class ChatProvider(Protocol):
    def chat(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> ChatResult: ...
    def stream(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> Iterator[Dict[str, Any]]: ...


def _provider_detail(response: Any) -> str:
    """Extract a short upstream error without reflecting HTML or credentials."""
    try:
        body = (response.text or "").strip().replace("\n", " ")
    except Exception:
        return ""
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            message = parsed.get("error") or parsed.get("message") or ""
            if isinstance(message, dict):
                message = message.get("message") or message.get("detail") or ""
            if message:
                return str(message)[:200]
    except (ValueError, AttributeError):
        pass
    if body.lower().startswith(("<!doctype", "<html")):
        return ""
    return body[:200]


def _event_error(chunk: Dict[str, Any]) -> Optional[ProviderError]:
    """Turn OpenAI- and gateway-style JSON error events into one error type."""
    if "error" not in chunk and str(chunk.get("type") or "").lower() != "error":
        return None
    error = chunk.get("error", chunk.get("message"))
    code: Any = chunk.get("status") or chunk.get("status_code")
    if isinstance(error, dict):
        message = error.get("message") or error.get("detail") or error.get("error")
        code = code or error.get("status") or error.get("status_code") or error.get("code")
    else:
        message = error
    message = str(message or "AI 服务商返回错误事件")[:300]
    try:
        numeric_code = int(code)
    except (TypeError, ValueError):
        numeric_code = 502
    if numeric_code < 400 or numeric_code > 599:
        numeric_code = 502
    return ProviderError(f"AI 服务商错误：{message}", numeric_code if numeric_code < 500 else 502)


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
            response = self.session.post(
                endpoint, json=payload,
                headers={"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json"},
                timeout=(5, 90), stream=stream,
            )
        except requests.RequestException as exc:
            raise ProviderError(f"AI 服务商暂不可用：{str(exc)[:150]}") from exc
        if not response.ok:
            status_code = response.status_code if response.status_code < 500 else 502
            detail = _provider_detail(response)
            response.close()
            message = "AI 服务商拒绝了请求" if not detail else \
                f"AI 服务商 HTTP {response.status_code}：{detail}"
            raise ProviderError(message, status_code)
        return response

    def chat(self, messages: List[Dict[str, Any]],
             tools: Optional[List[Dict[str, Any]]] = None) -> ChatResult:
        response = self._request(messages, False, tools)
        try:
            body = response.json()
            if not isinstance(body, dict):
                raise TypeError("response is not an object")
            event_error = _event_error(body)
            if event_error is not None:
                raise event_error
            choice = body["choices"][0]["message"]
            if not isinstance(choice, dict):
                raise TypeError("message is not an object")
            message = {
                key: choice[key]
                for key in ("role", "content", "reasoning_content", "tool_calls")
                if key in choice
            }
            return ChatResult(str(choice.get("content") or ""), usage_from_chunk(body) or {}, message)
        except ProviderError:
            raise
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise ProviderError("AI 服务商返回了无效响应") from exc
        finally:
            response.close()

    @staticmethod
    def _validated_event(value: Any) -> Dict[str, Any]:
        if not isinstance(value, dict):
            raise ProviderError("AI 服务商返回的 SSE 事件不是对象")
        event_error = _event_error(value)
        if event_error is not None:
            raise event_error
        return value

    def stream(self, messages: List[Dict[str, Any]],
               tools: Optional[List[Dict[str, Any]]] = None) -> Iterator[Dict[str, Any]]:
        response = self._request(messages, True, tools)
        pending: List[str] = []
        saw_payload = False
        saw_valid = False
        malformed = False
        event_name = ""

        def decode_pending() -> Optional[Dict[str, Any]]:
            nonlocal malformed, event_name
            if not pending:
                event_name = ""
                return None
            joined = "\n".join(pending)
            pending.clear()
            if joined == "[DONE]":
                event_name = ""
                return {"done": True}
            try:
                value = json.loads(joined)
            except json.JSONDecodeError:
                malformed = True
                event_name = ""
                return None
            if event_name == "error":
                value = {"error": value.get("error", value.get("message", value))} if isinstance(value, dict) else {"error": value}
            event_name = ""
            return self._validated_event(value)

        try:
            # SSE and JSON are UTF-8 on the wire.  Do not let ``requests``
            # choose ISO-8859-1 for ``text/event-stream`` responses which omit
            # an explicit charset (Tencent TokenHub currently does this), or
            # valid Chinese text is irreversibly turned into mojibake before it
            # reaches the Hub transcript.
            for raw in response.iter_lines(decode_unicode=False):
                if raw is None:
                    continue
                if isinstance(raw, bytes):
                    try:
                        raw = raw.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise ProviderError("AI 服务商返回的 SSE 数据不是有效 UTF-8") from exc
                elif not isinstance(raw, str):
                    raw = str(raw)
                raw = raw.lstrip("\ufeff")
                if not raw:
                    event = decode_pending()
                    if event is not None:
                        saw_valid = True
                        yield event
                    continue
                line = raw.strip()
                if not line or line.startswith(":") or line.startswith(("id:", "retry:")):
                    continue
                if line.startswith("event:"):
                    event_name = line[6:].strip().lower()
                    continue
                if not line.startswith("data:"):
                    if pending:
                        pending.append(line)
                    continue
                payload = line[5:].strip()
                if not payload:
                    continue
                saw_payload = True
                if payload == "[DONE]":
                    pending.clear()
                    event_name = ""
                    saw_valid = True
                    yield {"done": True}
                    continue
                try:
                    value = json.loads(payload)
                except json.JSONDecodeError:
                    pending.append(payload)
                    continue
                if event_name == "error":
                    value = {"error": value.get("error", value.get("message", value))} if isinstance(value, dict) else {"error": value}
                event_name = ""
                try:
                    event = self._validated_event(value)
                except ProviderError:
                    if isinstance(value, dict) and _event_error(value) is not None:
                        raise
                    malformed = True
                    continue
                pending.clear()
                saw_valid = True
                yield event
            event = decode_pending()
            if event is not None:
                saw_valid = True
                yield event
            if not saw_valid:
                if malformed or saw_payload:
                    raise ProviderError("AI 服务商返回的 SSE 数据格式错误")
                raise ProviderError("AI 服务商返回了空 SSE 数据流")
        except ProviderError:
            raise
        except requests.RequestException as exc:
            raise ProviderError(f"AI 服务数据流已中断：{str(exc)[:150]}") from exc
        finally:
            response.close()
