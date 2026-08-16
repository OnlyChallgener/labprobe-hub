"""Persistent router configuration snapshots and compact WSS change delivery.

Firewall, DDNS, UPnP and native port-mapping are durable configuration data,
not page requests. Hub owns their latest confirmed snapshot, verifies one resource
at a time at low frequency, and only publishes a WSS frame when the value changes.
User commands keep their existing write+readback verification and immediately feed
that confirmed result into this store.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Tuple

import router_rpc

STEP_SECONDS = max(3.0, float(os.environ.get("ROUTER_CONFIG_SYNC_STEP_SEC", "5")))
START_DELAY_SECONDS = max(1.0, float(os.environ.get("ROUTER_CONFIG_SYNC_START_DELAY_SEC", "3")))

RESOURCE_BY_CACHE_KEY = {
    "firewall": "firewall",
    "ddns": "ddns",
    "upnp": "upnp",
    "native-portmap": "portMappings",
}


def _now() -> int:
    return int(time.time())


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _comparison_value(resource: str, value: Any) -> Any:
    """Remove transport/runtime fields that are not configuration changes."""
    normalized = _jsonable(value)
    if not isinstance(normalized, dict):
        return normalized
    result = dict(normalized)
    for key in ("updatedAt", "checkedAt", "receivedAt", "receivedEpoch"):
        result.pop(key, None)
    if resource == "firewall":
        rows = result.get("list")
        if isinstance(rows, list):
            clean_rows = []
            for row in rows:
                if isinstance(row, dict):
                    clean = dict(row)
                    clean.pop("stats", None)
                    clean_rows.append(clean)
                else:
                    clean_rows.append(row)
            result["list"] = clean_rows
    return result


def _digest(resource: str, value: Any) -> str:
    wire = json.dumps(_comparison_value(resource, value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(wire.encode("utf-8")).hexdigest()


class RouterConfigSync:
    def __init__(self, hub: Any, client: Any, logger: Any):
        self.hub = hub
        self.client = client
        self.logger = logger
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        data_dir = Path(os.environ.get("DATA_DIR", "./data")).resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "router_config_snapshots.json"
        self.rows: Dict[str, Dict[str, Any]] = {}
        self.revision = 0
        self._load()
        self.loaders: Tuple[Tuple[str, Callable[[], Any]], ...] = (
            ("firewall", lambda: self.client.firewall(True)),
            ("ddns", lambda: self.client.ddns(True)),
            ("upnp", lambda: self.client.upnp(True)),
            ("portMappings", lambda: self.client.native_port_mapping(True)),
        )
        self.thread = threading.Thread(target=self._run, name="router-config-sync", daemon=True)

    def _load(self) -> None:
        try:
            root = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
            if not isinstance(root, dict):
                return
            rows = root.get("resources")
            if isinstance(rows, dict):
                self.rows = {
                    str(key): dict(value)
                    for key, value in rows.items()
                    if isinstance(value, dict) and isinstance(value.get("data"), (dict, list))
                }
            self.revision = max(int(root.get("revision") or 0), *(int(row.get("revision") or 0) for row in self.rows.values()), 0)
        except Exception as exc:
            self.logger.warning("router config snapshot load failed: %s", exc)

    def _save_locked(self) -> None:
        try:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps({"revision": self.revision, "resources": self.rows}, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )
            tmp.replace(self.path)
        except Exception as exc:
            self.logger.debug("router config snapshot save deferred: %s", exc)

    def start(self) -> None:
        if not self.thread.is_alive():
            self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def snapshot(self, resource: str) -> Dict[str, Any]:
        with self.lock:
            row = self.rows.get(resource)
            return dict(row) if isinstance(row, dict) else {}

    def frames(self) -> Iterable[Dict[str, Any]]:
        with self.lock:
            return [dict(row) for row in self.rows.values() if isinstance(row, dict) and row.get("data") is not None]

    def _publish(self, frame: Dict[str, Any]) -> None:
        ws = getattr(self.hub, "HUB_REALTIME_WEBSOCKET", None)
        publish = getattr(ws, "_publish", None)
        if callable(publish):
            try:
                publish("config", frame)
            except Exception:
                self.logger.debug("router config WSS publish deferred", exc_info=True)

    def accept(self, resource: str, data: Any, source: str = "sync") -> Dict[str, Any]:
        if resource not in {"firewall", "ddns", "upnp", "portMappings"}:
            return {}
        normalized = _jsonable(data)
        fingerprint = _digest(resource, normalized)
        with self.lock:
            previous = self.rows.get(resource) or {}
            if previous.get("digest") == fingerprint:
                # A command confirmation is still useful to a mutating APP even when
                # the value equals the previous snapshot, so publish it with the same revision.
                frame = {
                    **previous,
                    "resource": resource,
                    "source": source,
                    "checkedAt": _now(),
                }
                if source != "command":
                    return frame
            else:
                self.revision += 1
                frame = {
                    "resource": resource,
                    "revision": self.revision,
                    "updatedAt": _now(),
                    "checkedAt": _now(),
                    "source": source,
                    "digest": fingerprint,
                    "data": normalized,
                }
                self.rows[resource] = dict(frame)
                self._save_locked()
        self._publish(frame)
        return frame

    def accept_verified(self, cache_prefix: str, data: Any) -> None:
        resource = RESOURCE_BY_CACHE_KEY.get(str(cache_prefix or ""))
        if resource:
            self.accept(resource, data, source="command")

    def refresh(self, resource: str, loader: Callable[[], Any]) -> None:
        try:
            latest = loader()
            self.accept(resource, latest, source="sync")
        except router_rpc.RouterRpcError as exc:
            if getattr(exc, "code", "") not in {"BACKGROUND_DEFERRED", "CONTROL_QUEUE_BUSY"}:
                self.logger.debug("router config sync deferred resource=%s error=%s", resource, exc)
        except Exception as exc:
            self.logger.debug("router config sync deferred resource=%s error=%s", resource, exc)

    def _run(self) -> None:
        if self.stop_event.wait(START_DELAY_SECONDS):
            return
        index = 0
        while not self.stop_event.is_set():
            resource, loader = self.loaders[index % len(self.loaders)]
            index += 1
            self.refresh(resource, loader)
            self.stop_event.wait(STEP_SECONDS)


def install_router_config_sync_patch(hub: Any, client: Any) -> RouterConfigSync:
    existing = getattr(hub, "ROUTER_CONFIG_SYNC", None)
    if existing is not None:
        return existing

    sync = RouterConfigSync(hub, client, hub.LOGGER)
    hub.ROUTER_CONFIG_SYNC = sync

    original_write_and_verify = router_rpc.RouterController.write_and_verify
    if not getattr(router_rpc.RouterController, "_labprobe_config_sync_wrapped", False):
        def write_and_verify(self: Any, cache_prefix: str, write: Callable[[], Any], read: Callable[[], Any]) -> Dict[str, Any]:
            result = original_write_and_verify(self, cache_prefix, write, read)
            active = getattr(hub, "ROUTER_CONFIG_SYNC", None)
            if active is not None and isinstance(result, dict):
                active.accept_verified(cache_prefix, result.get("data"))
            return result

        router_rpc.RouterController.write_and_verify = write_and_verify
        router_rpc.RouterController._labprobe_config_sync_wrapped = True

    sync.start()
    return sync
