"""Bounded stale-while-revalidate cache for slow router-control reads.

The APP should receive the last successful DDNS/firewall/UPnP/port-mapping
snapshot immediately. Once its short freshness TTL expires, Hub refreshes the
router in one background worker and atomically replaces the cached value. A
transient router/login failure never replaces usable data with an empty value.

This cache is process memory only. It does not write periodic snapshots to disk.
Old entries are pruned opportunistically and the cache is hard bounded.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Dict, Set

import router_rpc


SLOW_CACHE_TTLS: Dict[str, float] = {
    "native-portmap": float(os.environ.get("ROUTER_PORT_MAPPING_CACHE_TTL_SEC", "30")),
    "upnp": float(os.environ.get("ROUTER_UPNP_CACHE_TTL_SEC", "30")),
    "firewall": float(os.environ.get("ROUTER_FIREWALL_CACHE_TTL_SEC", "60")),
    "ddns": float(os.environ.get("ROUTER_DDNS_CACHE_TTL_SEC", "60")),
}
CACHE_PRUNE_INTERVAL_SEC = max(
    60.0,
    float(os.environ.get("ROUTER_CACHE_PRUNE_INTERVAL_SEC", "300")),
)
CACHE_MAX_STALE_SEC = max(
    600.0,
    float(os.environ.get("ROUTER_CACHE_MAX_STALE_SEC", "86400")),
)
CACHE_MAX_ENTRIES = max(
    8,
    int(os.environ.get("ROUTER_CACHE_MAX_ENTRIES", "64")),
)


def _logger_call(client: Any, level: str, message: str, *args: Any) -> None:
    logger = getattr(client, "logger", None)
    fn = getattr(logger, level, None)
    if callable(fn):
        fn(message, *args)


def _ensure_runtime(client: Any) -> None:
    if not hasattr(client, "_slow_cache_state_lock"):
        client._slow_cache_state_lock = threading.RLock()
        client._slow_cache_refreshing = set()
        client._slow_cache_scope = None
        client._slow_cache_last_prune = 0.0


def _ensure_scope(client: Any) -> None:
    _ensure_runtime(client)
    try:
        scope = client._session_cache_key()
    except Exception:
        scope = ""
    with client._slow_cache_state_lock:
        previous = client._slow_cache_scope
        if previous is None:
            client._slow_cache_scope = scope
            return
        if previous == scope:
            return
        # Router address/password changed. Never serve the previous router's data.
        client.cache.clear()
        client._slow_cache_refreshing.clear()
        client._slow_cache_scope = scope
        client._slow_cache_last_prune = time.time()


def _prune(client: Any, now: float) -> None:
    _ensure_runtime(client)
    with client._slow_cache_state_lock:
        if now - client._slow_cache_last_prune < CACHE_PRUNE_INTERVAL_SEC:
            return
        client._slow_cache_last_prune = now

    cache = client.cache
    with cache._lock:
        expired = [
            key for key, row in cache._data.items()
            if not row or now - float(row[0]) > CACHE_MAX_STALE_SEC
        ]
        for key in expired:
            cache._data.pop(key, None)

        overflow = len(cache._data) - CACHE_MAX_ENTRIES
        if overflow > 0:
            oldest = sorted(cache._data.items(), key=lambda item: float(item[1][0]))[:overflow]
            for key, _ in oldest:
                cache._data.pop(key, None)


def _peek(cache: Any, key: str) -> Any:
    with cache._lock:
        return cache._data.get(key)


def _finish_refresh(client: Any, key: str) -> None:
    with client._slow_cache_state_lock:
        client._slow_cache_refreshing.discard(key)


def _start_refresh(client: Any, key: str, loader: Callable[[], Any]) -> None:
    _ensure_runtime(client)
    with client._slow_cache_state_lock:
        refreshing: Set[str] = client._slow_cache_refreshing
        if key in refreshing:
            return
        refreshing.add(key)

    def worker() -> None:
        try:
            latest = loader()
            client.cache.put(key, latest)
            _logger_call(client, "debug", "router slow cache refreshed key=%s", key)
        except Exception as exc:
            # Keep the last successful value. The next request may schedule a retry.
            _logger_call(client, "debug", "router slow cache refresh deferred key=%s error=%s", key, exc)
        finally:
            _finish_refresh(client, key)

    threading.Thread(
        target=worker,
        name=f"router-cache-refresh-{key}",
        daemon=True,
    ).start()


def install_router_slow_cache_patch() -> None:
    """Install the bounded SWR policy before the router client is constructed."""
    if getattr(router_rpc, "_labprobe_slow_cache_patch", False):
        return

    original_cached = router_rpc.RuijieRouterClient.cached

    def cached(
        self: Any,
        key: str,
        ttl: float,
        loader: Callable[[], Any],
        force: bool = False,
    ) -> Any:
        _ensure_scope(self)
        now = time.time()
        _prune(self, now)

        effective_ttl = max(1.0, SLOW_CACHE_TTLS.get(key, float(ttl)))
        if key not in SLOW_CACHE_TTLS:
            # Real-time/fallback reads keep their existing synchronous semantics.
            return original_cached(self, key, ttl, loader, force)

        if force:
            latest = loader()
            return self.cache.put(key, latest)

        row = _peek(self.cache, key)
        if row is None:
            # First request has no usable value, so one synchronous read is required.
            latest = loader()
            return self.cache.put(key, latest)

        saved_at, value = row
        if now - float(saved_at) <= effective_ttl:
            return value

        # Return stale data immediately and refresh once in the background.
        _start_refresh(self, key, loader)
        return value

    router_rpc.RuijieRouterClient.cached = cached
    router_rpc._labprobe_slow_cache_patch = True
