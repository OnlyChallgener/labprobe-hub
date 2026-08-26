import inspect
from types import SimpleNamespace

from router_compat import RouterRpcCompatibilitySync
from router_device_live_sync_patch import RouterDeviceLiveSync
from router_core.service.router_service import RouterService


class _Logger:
    def info(self, *_args, **_kwargs):
        pass

    def warning(self, *_args, **_kwargs):
        pass

    def debug(self, *_args, **_kwargs):
        pass


class _History:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = list(responses or [])

    def ingest(self, payload, **kwargs):
        self.calls.append((payload, kwargs))
        if self.responses:
            return self.responses.pop(0)
        return {"accepted": True}


class _Realtime:
    def __init__(self):
        self.frames = []

    def accept_devices_snapshot(self, frame):
        self.frames.append(frame)


def _normalized_device(raw):
    return {
        "name": raw.get("deviceAliasName") or raw["mac"],
        "mac": raw["mac"].lower(),
        "ip": raw.get("userIp", ""),
        "raw": dict(raw),
        "todayOnlineDurationSec": 1,
    }


def test_router_device_live_sync_is_the_only_native_user_list_reader():
    history = _History()
    realtime = _Realtime()
    raw = {
        "mac": "AA:BB:CC:DD:EE:FF",
        "userIp": "192.168.5.20",
        "flowUp": 10,
        "flowDown": 20,
        "flow_cnt": 3,
    }
    client = SimpleNamespace(calls=[])

    def rpc(*args, **kwargs):
        client.calls.append((args, kwargs))
        return {"list": [raw], "total": 1}

    client.rpc = rpc
    hub = SimpleNamespace(
        LOGGER=_Logger(),
        DURABLE_DEVICE_HISTORY=history,
        ROUTER_REALTIME=realtime,
        parse_ruijie_devices=lambda payload: (
            [_normalized_device(row) for row in payload.get("list", [])],
            int(payload.get("total", 0)),
        ),
        load_device_archive=lambda: {},
        hydrate_device_with_archive=lambda row, _archive: dict(row),
        attach_hub_local_ipv6_to_nas_devices=lambda rows: rows,
        norm_mac=lambda value: str(value or "").lower(),
        now_str=lambda: "2026-08-26 12:00:00",
        human_duration=lambda seconds: f"{seconds}s",
    )
    service = RouterDeviceLiveSync(hub, client, start=False)

    frame = service.poll_once()

    assert len(client.calls) == 1
    assert client.calls[0][0] == (
        "devSta.get",
        "user_list",
        {"devType": "all", "dataType": "timely"},
    )
    assert client.calls[0][1] == {"no_parse": True}
    assert frame["onlineDeviceCount"] == 1
    assert realtime.frames[-1]["devices"][0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert history.calls[0][1]["source"] == "router_core_user_list"


def test_compat_device_projection_consumes_live_snapshot_without_router_rpc():
    stored = {
        "devices": {
            "source": "router_core_user_list",
            "online": [_normalized_device({
                "mac": "AA:BB:CC:DD:EE:FF",
                "userIp": "192.168.5.20",
                "flowUp": 10,
                "flowDown": 20,
                "flow_cnt": 3,
            })],
            "watched": [],
            "onlineDeviceCount": 1,
        },
        "state": {},
    }
    raw = {
        "mac": "AA:BB:CC:DD:EE:FF",
        "userIp": "192.168.5.20",
        "flowUp": 10,
        "flowDown": 20,
        "flow_cnt": 3,
    }

    class Live:
        polls = 0

        def snapshot(self):
            return {"sampleEpochMs": 1, "devices": [_normalized_device(raw)]}

        def poll_once(self):
            self.polls += 1
            return self.snapshot()

    live = Live()

    def load_json(path, default):
        return stored.get(path, default)

    hub = SimpleNamespace(
        LOGGER=_Logger(),
        ROUTER_DEVICE_LIVE_SYNC=live,
        DEVICES_FILE="devices",
        load_json=load_json,
    )
    client = SimpleNamespace(config={"address": "http://router", "password": "secret"})
    sync = RouterRpcCompatibilitySync(hub, client)

    document = sync.sync_devices(force=False)

    assert live.polls == 0
    assert document["source"] == "router_core_user_list"
    assert document["onlineDeviceCount"] == 1
    source = inspect.getsource(RouterRpcCompatibilitySync.sync_devices)
    assert "client.devices" not in source
    assert "save_json" not in source
    assert "archive_device_snapshot" not in source

    sync.sync_devices(force=True)
    assert live.polls == 1


def test_live_sync_retries_persistence_when_history_defers_snapshot():
    history = _History([{"accepted": False}, {"accepted": True}])
    raw = {"mac": "AA:BB:CC:DD:EE:FF", "flowUp": 1, "flowDown": 2}
    client = SimpleNamespace(rpc=lambda *_args, **_kwargs: {"list": [raw], "total": 1})
    hub = SimpleNamespace(
        LOGGER=_Logger(),
        DURABLE_DEVICE_HISTORY=history,
        ROUTER_REALTIME=_Realtime(),
        parse_ruijie_devices=lambda payload: (
            [_normalized_device(row) for row in payload.get("list", [])],
            int(payload.get("total", 0)),
        ),
        load_device_archive=lambda: {},
        hydrate_device_with_archive=lambda row, _archive: dict(row),
        attach_hub_local_ipv6_to_nas_devices=lambda rows: rows,
        norm_mac=lambda value: str(value or "").lower(),
        now_str=lambda: "2026-08-26 12:00:00",
        human_duration=lambda seconds: f"{seconds}s",
    )
    service = RouterDeviceLiveSync(hub, client, start=False)

    service.poll_once()
    assert service.last_persist_at == 0
    service.poll_once()
    assert service.last_persist_at > 0
    assert len(history.calls) == 2


def test_live_sync_first_empty_uses_durable_membership_confirmation():
    history = _History()
    realtime = _Realtime()
    client = SimpleNamespace(rpc=lambda *_args, **_kwargs: {"list": [], "total": 0})
    hub = SimpleNamespace(
        LOGGER=_Logger(),
        DURABLE_DEVICE_HISTORY=history,
        ROUTER_REALTIME=realtime,
        DEVICES_FILE="devices.json",
        load_json=lambda _path, _default: {"online": [{"mac": "aa:bb"}]},
        parse_ruijie_devices=lambda _payload: ([], 0),
        load_device_archive=lambda: {},
        hydrate_device_with_archive=lambda row, _archive: dict(row),
        attach_hub_local_ipv6_to_nas_devices=lambda rows: rows,
        norm_mac=lambda value: str(value or "").lower(),
        now_str=lambda: "2026-08-26 12:00:00",
        human_duration=lambda seconds: f"{seconds}s",
    )
    service = RouterDeviceLiveSync(hub, client, start=False)

    first = service.poll_once()
    second = service.poll_once()

    assert first["accepted"] is False
    assert first["deferredEmpty"] is True
    assert realtime.frames[-1]["onlineDeviceCount"] == 0
    assert second["confirmedEmpty"] is True
    assert len(realtime.frames) == 1


def test_router_service_devices_use_core_snapshot_loader_not_driver():
    driver = SimpleNamespace(
        get_devices=lambda **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected driver poll"))
    )
    rows = [{"mac": "aa:bb:cc:dd:ee:ff"}]
    service = RouterService(driver=driver, devices_loader=lambda force: rows if force else rows)

    assert service.get_devices(force=False) == rows


def test_dashboard_background_interval_has_native_ws_safe_floor(monkeypatch):
    monkeypatch.delenv("ROUTER_DASHBOARD_POLL_SEC", raising=False)
    hub = SimpleNamespace(LOGGER=_Logger())
    sync = RouterRpcCompatibilitySync(hub, SimpleNamespace())
    assert sync.dashboard_interval == 30.0

    monkeypatch.setenv("ROUTER_DASHBOARD_POLL_SEC", "3")
    sync = RouterRpcCompatibilitySync(hub, SimpleNamespace())
    assert sync.dashboard_interval == 10.0
