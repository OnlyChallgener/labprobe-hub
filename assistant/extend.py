"""Assistant capability extension interface.

Feature modules publish tools without importing the AI stack internals:

    from assistant.extend import register_domain

    register_domain(hub, SPECS, HANDLERS, PREVIEWS)

- ``SPECS`` follow the same shape as the built-in entries in assistant.catalog.
- ``HANDLERS`` map tool id to ``fn(executor, args, client_context) -> dict``.
- ``PREVIEWS`` map write-tool id to a confirmation-card builder with the same
  signature; the card decides what the user confirms in the APP.

Registration is order-independent: calls made before the AI blueprint creates
the ToolExecutor are buffered and drained by assistant.api. Duplicate ids are
ignored on re-registration, so calling register_domain twice is safe.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

_PENDING: List[Dict[str, Any]] = []


def _apply(catalog, executor, specs, handlers, previews) -> None:
    for spec in specs:
        if catalog.tool_spec(spec["id"]) is None:
            catalog.register_tool(spec)
    for tool_id, handler in handlers.items():
        executor.register_handler(tool_id, handler)
    for tool_id, preview in previews.items():
        executor.register_preview(tool_id, preview)


def register_domain(hub: Any, specs: List[Dict[str, Any]], handlers: Dict[str, Callable],
                    previews: Dict[str, Callable] | None = None) -> None:
    executor = getattr(hub, "ASSISTANT_TOOL_EXECUTOR", None)
    if executor is None:
        _PENDING.append({"specs": list(specs), "handlers": dict(handlers), "previews": dict(previews or {})})
        return
    from . import catalog
    _apply(catalog, executor, list(specs), dict(handlers), dict(previews or {}))


def drain_pending(executor) -> int:
    """Bind every registration buffered before the executor existed."""
    from . import catalog

    applied = 0
    while _PENDING:
        item = _PENDING.pop(0)
        _apply(catalog, executor, item["specs"], item["handlers"], item["previews"])
        applied += 1
    return applied
