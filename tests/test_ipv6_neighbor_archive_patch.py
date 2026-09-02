from types import SimpleNamespace

from ipv6_neighbor_archive_patch import install_ipv6_neighbor_archive_patch


def _fake_hub():
    saved = {}

    def save_device_archive(value):
        saved.clear()
        saved.update(value)

    hub = SimpleNamespace(
        load_device_archive=lambda: {},
        save_device_archive=save_device_archive,
        configured_nas_macs=lambda: set(),
        local_hub_ipv6_records=lambda: [],
        get_local_lan_ipv4=lambda: "",
        norm_mac=lambda value: str(value or "").lower(),
        clean_saved_value=lambda value: str(value or "").strip(),
        normalize_ipv6_records=lambda records, _prefixes=None: list(records),
        ipv6_in_prefixes=lambda _ip, prefixes: bool(prefixes),
        is_temporary_ipv6=lambda _ip, _source="": False,
        is_ula_ipv6=lambda _ip: False,
        pick_primary_ipv6=lambda records: records[0]["ip"] if records else "",
        score_ipv6_record=lambda _record: 1,
        normalize_ipv6_list=lambda values: [value for value in values if value],
        now_str=lambda: "2026-09-02 20:30:00",
    )
    return hub, saved


def test_patch_restores_missing_merge_helper_and_persists_neighbor():
    hub, saved = _fake_hub()
    merge = install_ipv6_neighbor_archive_patch(hub)

    changed = merge(
        [
            {
                "mac": "AA:BB:CC:DD:EE:FF",
                "ip": "2409::1234",
                "state": "REACHABLE",
                "dev": "br-lan",
                "source": "router_ndp",
                "seenAt": "2026-09-02 20:29:00",
            }
        ],
        ["2409::/64"],
    )

    assert changed == 1
    assert hub.merge_ipv6_neighbors_to_archive is merge
    row = saved["aa:bb:cc:dd:ee:ff"]
    assert row["ipv6"] == "2409::1234"
    assert row["ipv6List"] == ["2409::1234"]
    assert row["ndpState"] == "REACHABLE"
    assert row["ndpDev"] == "br-lan"


def test_patch_does_not_override_native_helper():
    native = lambda _neighbors, _prefixes=None: 7
    hub = SimpleNamespace(merge_ipv6_neighbors_to_archive=native)

    installed = install_ipv6_neighbor_archive_patch(hub)

    assert installed is native
    assert hub.merge_ipv6_neighbors_to_archive([], []) == 7
