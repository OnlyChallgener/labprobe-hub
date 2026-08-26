import json
import inspect
import threading
import time
from datetime import datetime
from types import SimpleNamespace

from device_history_patch import DurableDeviceHistory
from hub0935_sync_fix import (
    _run_router_connection_without_app_keepalive,
)


class FakeSocket:
    def __init__(self):
        self.closed = False
        self.timeout = None
        self.frames = [json.dumps({"type": "fast", "data": {"up": 1}})]

    def settimeout(self, value):
        self.timeout = value

    def recv(self):
        return self.frames.pop(0)

    def close(self):
        self.closed = True


class FakeMonitor:
    def __init__(self):
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._last_fast_at = 0.0
        self.connected = []
        self.messages = []

    def _set_connected(self, connected, url="", error=""):
        self.connected.append((connected, url, error))

    def _dispatch_message(self, message):
        self.messages.append(message)
        self._last_fast_at = time.time()
        self._stop.set()


def test_router_native_ws_is_passive_and_sends_no_application_keepalive(monkeypatch):
    socket = FakeSocket()
    monkeypatch.setattr(
        "hub0935_sync_fix.websocket.create_connection",
        lambda *args, **kwargs: socket,
    )
    monitor = FakeMonitor()

    _run_router_connection_without_app_keepalive(
        monitor,
        "ws://192.168.5.1/ws?auth=test",
        "http://192.168.5.1",
        "sid=test",
        False,
        "192.168.5.1",
    )

    assert monitor.connected[0][0] is True
    assert monitor.messages == [{"type": "fast", "data": {"up": 1}}]
    assert socket.closed is True
    # FakeSocket deliberately has no send()/ping() method.  Reaching this line
    # proves the receiver did not emit the old {"action":"keepalive"} frame.


class FakeHub(SimpleNamespace):
    def now_str(self):
        return "2026-08-02 21:00:00"

    def clean_saved_value(self, value):
        return str(value or "").strip()


def test_relay_device_snapshot_is_enrichment_only_and_keeps_core_count():
    merged = []
    hub = FakeHub(
        DEVICES_FILE="devices.json",
        parse_ipv6_neighbors=lambda payload: payload.get("ipv6Neighbors", []),
        normalize_ipv6_prefixes=lambda rows: list(rows or []),
        merge_ipv6_neighbors_to_archive=lambda rows, prefixes: merged.extend(rows) or len(rows),
        load_json=lambda _path, _default: {
            "source": "router_core_user_list",
            "onlineDeviceCount": 2,
            "online": [{"mac": "aa"}, {"mac": "bb"}],
            "watched": [{"mac": "aa"}],
        },
    )
    history = object.__new__(DurableDeviceHistory)
    history.hub = hub
    history.lock = threading.RLock()

    result = history.ingest_enrichment({
        "list": [{"mac": "relay-only-device"}],
        "ipv6Neighbors": [{"mac": "aa", "ip": "2409::1"}],
    })

    assert result["accepted"] is True
    assert result["enrichmentOnly"] is True
    assert result["persisted"] is False
    assert result["source"] == "relay_device_enrichment"
    assert result["ipv6Changed"] is True
    assert result["onlineDeviceCount"] == 2
    assert result["watchedCount"] == 1
    assert merged == [{"mac": "aa", "ip": "2409::1"}]


def test_router_push_enrichment_accepts_source_and_prefixes():
    received = []
    hub = FakeHub(
        DEVICES_FILE="devices.json",
        parse_ipv6_neighbors=lambda payload: payload.get("ipv6Neighbors", []),
        normalize_ipv6_prefixes=lambda rows: [str(value) for value in (rows or [])],
        merge_ipv6_neighbors_to_archive=lambda rows, prefixes: received.append((rows, prefixes)) or 1,
        load_json=lambda _path, _default: {"online": [], "watched": [], "onlineDeviceCount": 0},
        clean_saved_value=lambda value: str(value or "").strip(),
    )
    history = object.__new__(DurableDeviceHistory)
    history.hub = hub
    history.lock = threading.RLock()

    result = history.ingest_enrichment(
        {"ipv6Neighbors": [{"mac": "aa", "ip": "2409::1"}], "lanIpv6Prefixes": ["2409::/64"]},
        source="router_push_snapshot",
    )

    assert result["source"] == "router_push_snapshot"
    assert result["ipv6Changed"] is True
    assert received == [([{"mac": "aa", "ip": "2409::1"}], ["2409::/64"])]


def test_core_transition_deduplicates_recent_relay_event():
    saved = []
    stamp = "2026-08-02 21:00:00"
    hub = FakeHub(
        EVENTS_FILE="events.json",
        clean_saved_value=lambda value: str(value or "").strip(),
        norm_mac=lambda value: str(value or "").lower(),
        parse_time_safe=lambda value: datetime.strptime(value, "%Y-%m-%d %H:%M:%S"),
        load_json=lambda _path, _default: [{
            "type": "device_online",
            "mac": "aa:bb",
            "createdAt": stamp,
            "source": "ruijie_agent",
        }],
        duration_between=lambda *_args: "",
        add_event=lambda event: saved.append(event),
    )
    history = object.__new__(DurableDeviceHistory)
    history.hub = hub
    history.logger = SimpleNamespace(debug=lambda *_args, **_kwargs: None)

    history._add_transition_event("device_online", {"mac": "AA:BB", "name": "Phone"}, stamp)

    assert saved == []


def test_relay_event_check_and_write_are_serialized_with_core_history():
    stamp = "2026-08-02 21:00:00"
    events = [{"type": "device_online", "mac": "aa:bb", "createdAt": stamp}]
    archived = []
    hub = FakeHub(
        EVENTS_FILE="events.json",
        norm_mac=lambda value: str(value or "").lower(),
        parse_time_safe=lambda value: datetime.strptime(value, "%Y-%m-%d %H:%M:%S"),
        load_json=lambda _path, _default: events,
        add_event=lambda event: events.append(event) or event,
        archive_device_snapshot=lambda row: archived.append(row),
    )
    history = object.__new__(DurableDeviceHistory)
    history.hub = hub
    history.lock = threading.RLock()

    duplicate = history.record_event_enrichment(
        {"type": "device_online", "mac": "AA:BB", "createdAt": stamp},
        {"mac": "AA:BB"},
        online=True,
        event_time=stamp,
        dedup_seconds=10,
    )
    transition = history.record_event_enrichment(
        {"type": "device_offline", "mac": "AA:BB", "createdAt": stamp},
        {"mac": "AA:BB", "ip": "192.168.5.20"},
        online=False,
        event_time=stamp,
        dedup_seconds=10,
    )

    assert duplicate["dedup"] is True
    assert transition["dedup"] is False
    assert events[-1]["type"] == "device_offline"
    assert len(archived) == 2


def test_core_history_disables_legacy_watched_transition_emission():
    source = inspect.getsource(DurableDeviceHistory.ingest)
    assert "build_watched_devices(hydrated, emit_events=False)" in source
