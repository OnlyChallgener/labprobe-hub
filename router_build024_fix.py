"""Hub 0.9.24 final realtime/detail fixes.

Keeps router native ``type=fast`` independent while restoring the fields and
low-frequency detail refresh needed by the Android router status page.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any

import router_compat
import router_lite_realtime_patch
import router_ws_patch

DETAIL_REFRESH_SECONDS = 60.0


def _refresh_interval() -> float:
    try:
        return max(30.0, float(os.environ.get("ROUTER_DETAILS_REFRESH_SEC", str(DETAIL_REFRESH_SECONDS))))
    except (TypeError, ValueError):
        return DETAIL_REFRESH_SECONDS


def _details_refresh_loop(sync: Any) -> None:
    """Refresh static network/AP/storage details without blocking native fast."""
    interval = _refresh_interval()
    while not sync._stop.is_set():
        if not sync.configured():
            sync._stop.wait(2.0)
            continue
        try:
            # This runs on its own worker. Even a slow eWeb HTTP/RPC response can
            # never block router /ws fast reception or APP WSS fan-out.
            sync.sync_dashboard(force=True)
            sync._last_dashboard = time.monotonic()
        except Exception as exc:
            sync.logger.debug("router detail background refresh deferred: %s", exc)
        sync._stop.wait(interval)


def _start_details_worker(self: Any) -> None:
    if not self.primary or self._thread is not None:
        return
    self._thread = threading.Thread(
        target=_details_refresh_loop,
        args=(self,),
        name="router-details-refresh",
        daemon=True,
    )
    self._thread.start()
    self.logger.info(
        "router details refresh worker started interval=%ss; native fast remains independent",
        _refresh_interval(),
    )


def install_router_build024_fix() -> None:
    # BE72 native fast already carries these two radio temperatures. Some
    # firmwares also expose diskutil in fast; otherwise the independent detail
    # worker obtains storage from slow/static dashboard data.
    router_ws_patch._FAST_ROOT_NUMBER_FIELDS.update({
        "temperature2gC": ("temp_2g", "temperature2gC", "temperature_2g"),
        "temperature5gC": ("temp_5g", "temperature5gC", "temperature_5g"),
        "storagePercent": ("diskutil", "storagePercent", "disk_usage", "overlay_usage"),
    })
    router_lite_realtime_patch._ROUTER_FIELDS.update({
        "temperature2gC",
        "temperature5gC",
        "storagePercent",
    })

    cls = router_compat.RouterRpcCompatibilitySync
    cls.start = _start_details_worker
    cls._labprobe_build024_fix = True
