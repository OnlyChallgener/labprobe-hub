"""Router Core Unified SWR Cache and Lock Manager.

Provides thread-safe Stale-While-Revalidate caching to eliminate duplicate RPCs
and prevent request pileups on slow router firmware.
"""

import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple


class CacheEntry:
    """Represents a cached item with expiration and freshness timestamps."""

    def __init__(self, value: Any, ttl: float):
        self.value = value
        self.created_at = time.time()
        self.ttl = ttl

    @property
    def is_fresh(self) -> bool:
        return (time.time() - self.created_at) < self.ttl

    @property
    def is_stale(self) -> bool:
        return not self.is_fresh


class RouterCache:
    """Thread-safe SWR Cache with Single-Flight Fetching."""

    def __init__(self, default_ttl: float = 2.0, max_entries: int = 256):
        self.default_ttl = default_ttl
        self.max_entries = max_entries
        self._store: Dict[str, CacheEntry] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._global_lock = threading.Lock()

    def _get_key_lock(self, key: str) -> threading.Lock:
        with self._global_lock:
            if key not in self._locks:
                self._locks[key] = threading.Lock()
            return self._locks[key]

    def get(self, key: str) -> Optional[Any]:
        """Returns the cached value if fresh, otherwise None."""
        with self._global_lock:
            entry = self._store.get(key)
            if entry and entry.is_fresh:
                return entry.value
        return None

    def peek(self, key: str) -> Optional[Any]:
        """Returns the cached value even if stale (for SWR fast return)."""
        with self._global_lock:
            entry = self._store.get(key)
            return entry.value if entry else None

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Saves a value in cache with the specified TTL."""
        entry_ttl = ttl if ttl is not None else self.default_ttl
        with self._global_lock:
            if len(self._store) >= self.max_entries and key not in self._store:
                # Evict oldest entries
                oldest_key = min(self._store.keys(), key=lambda k: self._store[k].created_at)
                del self._store[oldest_key]
            self._store[key] = CacheEntry(value, entry_ttl)

    def invalidate(self, key_or_prefix: str = "") -> None:
        """Invalidates keys matching prefix or all keys if empty."""
        with self._global_lock:
            if not key_or_prefix:
                self._store.clear()
            else:
                to_delete = [k for k in self._store if k.startswith(key_or_prefix)]
                for k in to_delete:
                    del self._store[k]

    def get_or_fetch(
        self,
        key: str,
        fetcher: Callable[[], Any],
        ttl: Optional[float] = None,
        force: bool = False,
    ) -> Any:
        """Thread-safe acquisition with single-flight locking to collapse concurrent requests."""
        if not force:
            cached = self.get(key)
            if cached is not None:
                return cached

        # Single-Flight execution under per-key lock
        key_lock = self._get_key_lock(key)
        with key_lock:
            # Re-check cache under lock
            if not force:
                cached = self.get(key)
                if cached is not None:
                    return cached

            # Execute fetcher
            value = fetcher()
            self.set(key, value, ttl=ttl)
            return value
