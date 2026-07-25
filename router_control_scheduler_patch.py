"""Keep slow router-control refreshes away from the realtime WSS path.

The APP build158 preloads settings sequentially. This Hub guard also serializes
stale-while-revalidate background loaders, so separate HTTP pages cannot fan out
multiple slow router RPC refreshes at the same time. It does not touch the
router-native realtime WebSocket, its collector, or APP WSS delivery.
"""
from __future__ import annotations

import threading
from typing import Any, Callable

import router_slow_cache_patch


_background_refresh_gate = threading.Lock()


def install_router_control_scheduler_patch() -> None:
    if getattr(router_slow_cache_patch, "_labprobe_control_scheduler_patch", False):
        return

    original_start_refresh = router_slow_cache_patch._start_refresh

    def serialized_start_refresh(client: Any, key: str, loader: Callable[[], Any]) -> None:
        def serialized_loader() -> Any:
            with _background_refresh_gate:
                return loader()

        original_start_refresh(client, key, serialized_loader)

    router_slow_cache_patch._start_refresh = serialized_start_refresh
    router_slow_cache_patch._labprobe_control_scheduler_patch = True
