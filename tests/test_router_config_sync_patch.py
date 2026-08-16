import logging
from pathlib import Path
from types import SimpleNamespace

from router_config_sync_patch import RouterConfigSync


def test_firewall_config_diff_ignores_runtime_counters(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    published = []
    ws = SimpleNamespace(_publish=lambda kind, payload: published.append((kind, payload)))
    hub = SimpleNamespace(HUB_REALTIME_WEBSOCKET=ws, LOGGER=logging.getLogger("config-test"))
    sync = RouterConfigSync(hub, SimpleNamespace(), hub.LOGGER)

    first = {
        "updatedAt": 100,
        "list": [{"uuid": "r1", "enable": "1", "stats": {"packets": 1, "bytes": 20}}],
    }
    second = {
        "updatedAt": 101,
        "list": [{"uuid": "r1", "enable": "1", "stats": {"packets": 9, "bytes": 500}}],
    }
    changed = {
        "updatedAt": 102,
        "list": [{"uuid": "r1", "enable": "0", "stats": {"packets": 9, "bytes": 500}}],
    }

    sync.accept("firewall", first, source="sync")
    assert len(published) == 1
    sync.accept("firewall", second, source="sync")
    assert len(published) == 1
    sync.accept("firewall", changed, source="sync")
    assert len(published) == 2
    assert published[-1][1]["data"]["list"][0]["enable"] == "0"
    assert Path(tmp_path, "router_config_snapshots.json").exists()


def test_equal_command_result_is_republished_for_confirmation(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    published = []
    ws = SimpleNamespace(_publish=lambda kind, payload: published.append((kind, payload)))
    hub = SimpleNamespace(HUB_REALTIME_WEBSOCKET=ws, LOGGER=logging.getLogger("config-command-test"))
    sync = RouterConfigSync(hub, SimpleNamespace(), hub.LOGGER)

    data = {"enable_upnp": "true", "wan": "AUTO", "upnpds": []}
    sync.accept("upnp", data, source="sync")
    before = len(published)
    sync.accept("upnp", data, source="command")
    assert len(published) == before + 1
    assert published[-1][1]["source"] == "command"
