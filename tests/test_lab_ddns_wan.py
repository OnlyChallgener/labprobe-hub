import json
import logging

import pytest
from flask import Flask

import lab_ddns
from lab_ddns import LabDdnsStore, install_lab_ddns


def sample(wan_id, ipv4, ipv6, detected_at, *, ipv4_state="public", ipv6_state="public"):
    return {
        "wanId": wan_id,
        "detectedIpv4": ipv4,
        "detectedIpv6": ipv6,
        "ipv4State": ipv4_state,
        "ipv6State": ipv6_state,
        "ipv4Source": f"{wan_id}:v4",
        "ipv6Source": f"{wan_id}:v6",
        "detectedAt": detected_at,
    }


def new_store(tmp_path):
    return LabDdnsStore(tmp_path / "lab_ddns.json")


def add_record(store, wan_id, hostname="home.example.com", record_types=None):
    return store.save_record({
        "provider": "cloudflare",
        "hostname": hostname,
        "wanId": wan_id,
        "recordTypes": record_types or ["A", "AAAA"],
    })


def records_by_wan(store):
    return {record["wanId"]: record for record in store.snapshot()["records"]}


class FakeProvider:
    provider_id = "cloudflare"

    def __init__(self, outcomes=()):
        self.outcomes = list(outcomes)
        self.calls = []

    def supports_record_type(self, record_type):
        return record_type in {"A", "AAAA", "CNAME", "TXT"}

    def sync_record(self, hostname, record_type, value, ttl, credentials):
        self.calls.append((hostname, record_type, value, ttl))
        return self.outcomes.pop(0)


def success(record_type, record_id):
    return lab_ddns.ProviderResult(
        True,
        "success",
        provider="cloudflare",
        record_type=record_type,
        record_id=record_id,
        changed=True,
    )


def test_wan_id_is_optional_normalized_bounded_and_persisted(tmp_path):
    store = new_store(tmp_path)
    record = add_record(store, "  WAN_1  ")
    legacy = add_record(store, "", hostname="legacy.example.com")
    assert record["wanId"] == "wan_1"
    assert legacy["wanId"] == ""
    assert store.snapshot()["addresses"] == {}

    with pytest.raises(ValueError, match="wanId"):
        add_record(store, "wan 1", hostname="invalid.example.com")
    with pytest.raises(ValueError, match="wanId"):
        add_record(store, "a" * 65, hostname="too-long.example.com")

    loaded = LabDdnsStore(store.path).snapshot()
    assert [item["wanId"] for item in loaded["records"]] == ["wan_1", ""]


def test_two_wans_keep_independent_samples_stability_and_publications(tmp_path, monkeypatch):
    store = new_store(tmp_path)
    store.accept_address({"detectedIpv4": "203.0.113.99", "ipv4State": "public", "detectedAt": 90})
    first = add_record(store, "wan1")
    second = add_record(store, "wan2")
    assert records_by_wan(store)["wan1"]["detectedIpv4"] == ""
    assert records_by_wan(store)["wan2"]["detectedIpv6"] == ""

    assert store.accept_address({"wans": [
        sample("WAN1", "198.51.100.10", "2001:db8::10", 101),
        sample("wan2", "198.51.100.20", "2001:db8::20", 101),
    ]})
    snapshot = store.snapshot()
    assert snapshot["address"]["detectedIpv4"] == "203.0.113.99"
    assert snapshot["addresses"]["wan1"]["detectedIpv4"] == "198.51.100.10"
    assert snapshot["addresses"]["wan2"]["detectedIpv6"] == "2001:db8::20"
    assert records_by_wan(store)["wan1"]["stability"]["A"]["stableCount"] == 1
    assert records_by_wan(store)["wan2"]["stability"]["AAAA"]["stableCount"] == 1

    provider = FakeProvider([
        success("A", "wan1-a"), success("AAAA", "wan1-aaaa"),
        success("A", "wan2-a"), success("AAAA", "wan2-aaaa"),
    ])
    monkeypatch.setitem(lab_ddns.PROVIDERS, "cloudflare", provider)
    store.accept_address({"wans": [
        sample("wan1", "198.51.100.10", "2001:db8::10", 102),
        sample("wan2", "198.51.100.20", "2001:db8::20", 102),
    ]})
    assert store.run_update(first["id"])["ok"]
    assert store.run_update(second["id"])["ok"]
    assert provider.calls == [
        ("home.example.com", "A", "198.51.100.10", 600),
        ("home.example.com", "AAAA", "2001:db8::10", 600),
        ("home.example.com", "A", "198.51.100.20", 600),
        ("home.example.com", "AAAA", "2001:db8::20", 600),
    ]
    by_wan = records_by_wan(store)
    assert by_wan["wan1"]["publishedIpv4"] == "198.51.100.10"
    assert by_wan["wan1"]["publishedIpv6"] == "2001:db8::10"
    assert by_wan["wan2"]["publishedIpv4"] == "198.51.100.20"
    assert by_wan["wan2"]["publishedIpv6"] == "2001:db8::20"


def test_legacy_scalar_and_single_wan_samples_update_only_their_own_scope(tmp_path):
    store = new_store(tmp_path)
    store.accept_address({"wans": [sample("wan1", "198.51.100.10", "2001:db8::10", 100)]})
    bound = add_record(store, "wan1")
    legacy = add_record(store, "")

    store.accept_address({"detectedIpv4": "192.0.2.10", "ipv4State": "public", "detectedAt": 101})
    snapshot = store.snapshot()
    assert snapshot["addresses"]["wan1"]["detectedIpv4"] == "198.51.100.10"
    assert records_by_wan(store)["wan1"]["detectedIpv4"] == "198.51.100.10"
    assert records_by_wan(store)[""]["detectedIpv4"] == "192.0.2.10"
    assert legacy["id"] != bound["id"]
    assert legacy["wanId"] == ""
    assert bound["wanId"] == "wan1"

    store.accept_address(sample("WAN1", "198.51.100.11", "2001:db8::11", 102))
    snapshot = store.snapshot()
    assert snapshot["address"]["detectedIpv4"] == "192.0.2.10"
    assert snapshot["addresses"]["wan1"]["detectedIpv4"] == "198.51.100.11"
    assert records_by_wan(store)[""]["detectedIpv4"] == "192.0.2.10"
    assert records_by_wan(store)["wan1"]["detectedIpv4"] == "198.51.100.11"


def test_missing_or_offline_wan_preserves_last_success_without_fallback(tmp_path, monkeypatch):
    store = new_store(tmp_path)
    store.accept_address({"detectedIpv4": "192.0.2.99", "ipv4State": "public", "detectedAt": 90})
    first = add_record(store, "wan1")
    second = add_record(store, "wan2")
    provider = FakeProvider([
        success("A", "first-a"), success("AAAA", "first-aaaa"),
        success("A", "second-a"), success("AAAA", "second-aaaa"),
    ])
    monkeypatch.setitem(lab_ddns.PROVIDERS, "cloudflare", provider)
    for detected_at in (100, 101):
        store.accept_address({"wans": [
            sample("wan1", "198.51.100.10", "2001:db8::10", detected_at),
            sample("wan2", "198.51.100.20", "2001:db8::20", detected_at),
        ]})
    assert store.run_update(first["id"])["ok"]
    assert store.run_update(second["id"])["ok"]
    published = records_by_wan(store)["wan1"]
    calls_before = list(provider.calls)

    store.accept_address({"wans": [sample("wan2", "198.51.100.21", "2001:db8::21", 102)]})
    assert records_by_wan(store)["wan1"] == published

    store.accept_address({"wans": [sample(
        "wan1", "", "", 103, ipv4_state="unavailable", ipv6_state="unavailable"
    )]})
    offline = records_by_wan(store)["wan1"]
    assert offline["wanId"] == "wan1"
    assert offline["detectedIpv4"] == published["detectedIpv4"]
    assert offline["detectedIpv6"] == published["detectedIpv6"]
    assert offline["publishedIpv4"] == published["publishedIpv4"]
    assert offline["publishedIpv6"] == published["publishedIpv6"]
    assert offline["lastDetectedAt"] == published["lastDetectedAt"]
    assert offline["lastUpdatedAt"] == published["lastUpdatedAt"]
    assert offline["lastRecordResults"] == published["lastRecordResults"]
    assert offline["ipv4State"] == offline["ipv6State"] == "unavailable"
    assert offline["status"] == "published"
    assert store.run_pending_updates() == 0
    assert provider.calls == calls_before
    assert records_by_wan(store)["wan2"]["detectedIpv4"] == "198.51.100.21"
    assert store.snapshot()["address"]["detectedIpv4"] == "192.0.2.99"


def test_retry_backoff_and_errors_are_isolated_between_wans(tmp_path, monkeypatch):
    store = new_store(tmp_path)
    first = add_record(store, "wan1", hostname="shared.example.com", record_types=["A"])
    second = add_record(store, "wan2", hostname="shared.example.com", record_types=["A"])
    provider = FakeProvider([
        lab_ddns.ProviderResult(
            False, "error", provider="cloudflare", record_type="A",
            error_code="rate_limited", error_message="wan1 throttled",
        ),
        success("A", "wan2-a"),
    ])
    monkeypatch.setitem(lab_ddns.PROVIDERS, "cloudflare", provider)
    for detected_at in (100, 101):
        store.accept_address({"wans": [
            sample("wan1", "198.51.100.10", "", detected_at, ipv6_state="unavailable"),
            sample("wan2", "198.51.100.20", "", detected_at, ipv6_state="unavailable"),
        ]})
    assert not store.run_update(first["id"])["ok"]
    assert store.run_update(second["id"])["ok"]
    by_wan = records_by_wan(store)
    assert by_wan["wan1"]["status"] == "error"
    assert by_wan["wan1"]["lastError"] == "wan1 throttled"
    assert by_wan["wan1"]["stability"]["A"]["retryAttempt"] == 1
    assert by_wan["wan1"]["stability"]["A"]["nextRetryAt"] > 0
    assert by_wan["wan2"]["status"] == "published"
    assert by_wan["wan2"]["publishedIpv4"] == "198.51.100.20"
    assert by_wan["wan2"]["lastError"] is None
    assert by_wan["wan2"]["stability"]["A"]["retryAttempt"] == 0

    deferred = store.run_update(first["id"])
    assert deferred["results"]["A"]["status"] == "retry_backoff"
    assert len(provider.calls) == 2


def test_auto_ready_is_line_isolated(tmp_path, monkeypatch):
    store = new_store(tmp_path)
    first = add_record(store, "wan1", record_types=["A"])
    second = add_record(store, "wan2", record_types=["A"])
    provider = FakeProvider([success("A", "wan2-a"), success("A", "wan1-a")])
    monkeypatch.setitem(lab_ddns.PROVIDERS, "cloudflare", provider)

    store.auto_event.clear()
    store.accept_address({"wans": [sample("wan1", "198.51.100.10", "", 100, ipv6_state="unavailable")]})
    assert not store.auto_event.is_set()
    assert store.run_pending_updates() == 0
    store.accept_address({"wans": [sample("wan2", "198.51.100.20", "", 100, ipv6_state="unavailable")]})
    assert not store.auto_event.is_set()
    store.accept_address({"wans": [sample("wan2", "198.51.100.20", "", 101, ipv6_state="unavailable")]})
    assert store.auto_event.is_set()
    assert store.run_pending_updates() == 1
    assert provider.calls == [("home.example.com", "A", "198.51.100.20", 600)]
    assert records_by_wan(store)["wan1"]["publishedIpv4"] is None

    store.auto_event.clear()
    store.accept_address({"wans": [sample("wan1", "198.51.100.10", "", 101, ipv6_state="unavailable")]})
    assert store.auto_event.is_set()
    assert store.run_pending_updates() == 1


def test_freshness_and_auto_due_are_isolated_per_wan(tmp_path, monkeypatch):
    store = new_store(tmp_path)
    first = add_record(store, "wan1", record_types=["A"])
    second = add_record(store, "wan2", record_types=["A"])
    provider = FakeProvider([success("A", "wan2-a")])
    monkeypatch.setitem(lab_ddns.PROVIDERS, "cloudflare", provider)
    now = 1_700_000_000
    monkeypatch.setattr(lab_ddns, "_now", lambda: now)
    for detected_at in (now, now + 1):
        store.accept_address({"wans": [
            sample("wan1", "198.51.100.10", "", detected_at, ipv6_state="unavailable"),
            sample("wan2", "198.51.100.20", "", detected_at, ipv6_state="unavailable"),
        ]})

    now += lab_ddns.ADDRESS_STALE_SECONDS + 2
    store.accept_address({"wans": [
        sample("wan2", "198.51.100.20", "", now, ipv6_state="unavailable"),
    ]})
    assert store._auto_due()[0] == [second["id"]]
    assert store.run_pending_updates() == 1
    assert provider.calls == [("home.example.com", "A", "198.51.100.20", 600)]
    assert records_by_wan(store)["wan1"]["publishedIpv4"] is None
    assert records_by_wan(store)["wan1"]["lastDetectedAt"] == now - lab_ddns.ADDRESS_STALE_SECONDS - 1
    assert store.run_update(first["id"])["results"]["A"]["status"] == "stale_address"


def test_rebind_resets_new_line_detection_and_preserves_success_history(tmp_path, monkeypatch):
    store = new_store(tmp_path)
    record = add_record(store, "wan1")
    provider = FakeProvider([success("A", "a1"), success("AAAA", "aaaa1")])
    monkeypatch.setitem(lab_ddns.PROVIDERS, "cloudflare", provider)
    for detected_at in (100, 101):
        store.accept_address({"wans": [
            sample("wan1", "198.51.100.10", "2001:db8::10", detected_at),
            sample("wan2", "198.51.100.20", "2001:db8::20", detected_at),
        ]})
    assert store.run_update(record["id"])["ok"]
    with store.lock:
        old = store.root["records"][0]
        old["stability"]["A"].update({"retryAttempt": 2, "nextRetryAt": 999, "authError": True})
        old["lastError"] = "previous provider warning"
        store._save_locked()
        history = {
            "publishedIpv4": old["publishedIpv4"],
            "publishedIpv6": old["publishedIpv6"],
            "lastUpdatedAt": old["lastUpdatedAt"],
            "lastRecordResults": json.loads(json.dumps(old["lastRecordResults"])),
        }

    rebound = store.save_record({
        "provider": "cloudflare",
        "hostname": "home.example.com",
        "recordTypes": ["A", "AAAA"],
        "wanId": " WAN2 ",
    }, record["id"])
    assert rebound["wanId"] == "wan2"
    assert rebound["detectedIpv4"] == "198.51.100.20"
    assert rebound["detectedIpv6"] == "2001:db8::20"
    assert rebound["lastDetectedAt"] == 101
    assert rebound["source"] == "wan2:v4,wan2:v6"
    assert rebound["stability"]["A"] == lab_ddns._empty_tracker()["A"]
    assert rebound["stability"]["AAAA"] == lab_ddns._empty_tracker()["AAAA"]
    for key, value in history.items():
        assert rebound[key] == value
    assert rebound["lastError"] == "previous provider warning"

    before = store.snapshot()["records"][0]
    store.accept_address({"wans": [sample("wan1", "198.51.100.11", "2001:db8::11", 102)]})
    assert store.snapshot()["records"][0] == before
    store.accept_address({"wans": [sample("wan2", "198.51.100.21", "2001:db8::21", 102)]})
    assert store.snapshot()["records"][0]["stability"]["A"]["stableCount"] == 1
    waiting = store.run_update(record["id"])
    assert waiting["results"]["A"]["status"] == "waiting_for_stability"
    assert waiting["results"]["AAAA"]["status"] == "waiting_for_stability"
    assert len(provider.calls) == 2


def test_edit_omitted_wan_preserves_binding_and_explicit_blank_switches_to_legacy(tmp_path):
    store = new_store(tmp_path)
    record = add_record(store, "wan1")
    for detected_at in (100, 101):
        store.accept_address({"wans": [
            sample("wan1", "198.51.100.10", "2001:db8::10", detected_at),
        ]})
        store.accept_address({"detectedIpv4": "192.0.2.10", "ipv4State": "public", "detectedAt": detected_at})
    with store.lock:
        stored = store.root["records"][0]
        stored["publishedIpv4"] = "198.51.100.9"
        stored["lastUpdatedAt"] = 77
        store._save_locked()
    before = store.snapshot()["records"][0]

    omitted = store.save_record({
        "provider": "cloudflare",
        "hostname": "renamed.example.com",
        "recordTypes": ["A", "AAAA"],
    }, record["id"])
    assert omitted["wanId"] == "wan1"
    assert omitted["detectedIpv4"] == before["detectedIpv4"]
    assert omitted["lastDetectedAt"] == before["lastDetectedAt"]
    assert omitted["stability"] == before["stability"]

    blank = store.save_record({
        "provider": "cloudflare",
        "hostname": "renamed.example.com",
        "recordTypes": ["A", "AAAA"],
        "wanId": "",
    }, record["id"])
    assert blank["wanId"] == ""
    assert blank["detectedIpv4"] == "192.0.2.10"
    assert blank["detectedIpv6"] == ""
    assert blank["lastDetectedAt"] == 101
    assert blank["stability"]["A"]["candidate"] == ""
    assert blank["stability"]["A"]["stableCount"] == 0
    assert blank["publishedIpv4"] == "198.51.100.9"
    assert blank["lastUpdatedAt"] == 77

    store.accept_address({"wans": [sample("wan1", "198.51.100.11", "2001:db8::11", 102)]})
    assert store.snapshot()["records"][0]["detectedIpv4"] == "192.0.2.10"
    store.accept_address({"detectedIpv4": "192.0.2.11", "ipv4State": "public", "detectedAt": 102})
    assert store.snapshot()["records"][0]["detectedIpv4"] == "192.0.2.11"


def test_duplicate_hostname_on_different_wans_is_allowed(tmp_path, monkeypatch):
    store = new_store(tmp_path)
    first = add_record(store, "wan1", hostname="shared.example.com", record_types=["A"])
    second = add_record(store, "wan2", hostname="shared.example.com", record_types=["A"])
    assert first["id"] != second["id"]
    provider = FakeProvider([success("A", "first"), success("A", "second")])
    monkeypatch.setitem(lab_ddns.PROVIDERS, "cloudflare", provider)
    for detected_at in (100, 101):
        store.accept_address({"wans": [
            sample("wan1", "198.51.100.10", "", detected_at, ipv6_state="unavailable"),
            sample("wan2", "198.51.100.20", "", detected_at, ipv6_state="unavailable"),
        ]})
    assert store.run_update(first["id"])["ok"]
    assert store.run_update(second["id"])["ok"]
    assert [call[2] for call in provider.calls] == ["198.51.100.10", "198.51.100.20"]
    assert len(store.snapshot()["records"]) == 2


def test_restart_preserves_wan_addresses_bindings_and_success_history(tmp_path, monkeypatch):
    store = new_store(tmp_path)
    first = add_record(store, "wan1")
    second = add_record(store, "wan2")
    provider = FakeProvider([success("A", "first-a"), success("AAAA", "first-aaaa")])
    monkeypatch.setitem(lab_ddns.PROVIDERS, "cloudflare", provider)
    store.accept_address({"detectedIpv4": "192.0.2.99", "ipv4State": "public", "detectedAt": 99})
    for detected_at in (100, 101):
        store.accept_address({"wans": [
            sample("wan1", "198.51.100.10", "2001:db8::10", detected_at),
            sample("wan2", "198.51.100.20", "2001:db8::20", detected_at),
        ]})
    assert store.run_update(first["id"])["ok"]
    persisted = store.snapshot()
    raw = json.loads(store.path.read_text(encoding="utf-8"))
    assert raw["addresses"]["wan1"]["detectedIpv4"] == "198.51.100.10"
    assert raw["addresses"]["wan2"]["detectedIpv6"] == "2001:db8::20"
    assert [item["wanId"] for item in raw["records"]] == ["wan1", "wan2"]

    restarted = LabDdnsStore(store.path)
    loaded = restarted.snapshot()
    assert loaded["address"] == persisted["address"]
    assert loaded["addresses"] == persisted["addresses"]
    by_wan = records_by_wan(restarted)
    assert by_wan["wan1"]["publishedIpv4"] == "198.51.100.10"
    assert by_wan["wan1"]["publishedIpv6"] == "2001:db8::10"
    assert by_wan["wan1"]["lastUpdatedAt"] == persisted["records"][0]["lastUpdatedAt"]
    assert by_wan["wan1"]["lastRecordResults"] == persisted["records"][0]["lastRecordResults"]
    assert by_wan["wan1"]["stability"]["A"]["stableCount"] == 0
    assert by_wan["wan2"]["detectedIpv4"] == "198.51.100.20"

    second_before = by_wan["wan2"]
    restarted.accept_address({"wans": [sample("wan1", "198.51.100.11", "2001:db8::11", 102)]})
    by_wan = records_by_wan(restarted)
    assert by_wan["wan1"]["stability"]["A"]["stableCount"] == 1
    assert by_wan["wan2"] == second_before
    assert restarted.snapshot()["address"] == persisted["address"]
    restarted.accept_address({"wans": [sample("wan1", "198.51.100.11", "2001:db8::11", 102)]})
    assert records_by_wan(restarted)["wan1"]["stability"]["A"]["stableCount"] == 1
    restarted.accept_address({"wans": [sample("wan1", "198.51.100.11", "2001:db8::11", 103)]})
    assert records_by_wan(restarted)["wan1"]["stability"]["A"]["stableCount"] == 2


def test_api_crud_automatically_carries_wan_id(tmp_path):
    class Hub:
        def __init__(self):
            self.app = Flask("lab-ddns-wan-route-test")
            self.DATA_DIR = tmp_path
            self.LOGGER = logging.getLogger("lab-ddns-wan-route-test")

        def check_app_token(self):
            return True

    hub = Hub()
    store = install_lab_ddns(hub)
    client = hub.app.test_client()
    created = client.post("/api/ddns", json={
        "provider": "cloudflare",
        "hostname": "home.example.com",
        "recordTypes": ["A"],
        "wanId": " WAN1 ",
    })
    assert created.status_code == 200
    record = created.get_json()["record"]
    assert record["wanId"] == "wan1"
    record_id = record["id"]

    listed = client.get("/api/ddns").get_json()
    assert listed["records"][0]["wanId"] == "wan1"
    assert listed["addresses"] == {}

    omitted = client.put(f"/api/ddns/{record_id}", json={
        "provider": "cloudflare",
        "hostname": "renamed.example.com",
        "recordTypes": ["A"],
    })
    assert omitted.status_code == 200
    assert omitted.get_json()["record"]["wanId"] == "wan1"
    assert store.snapshot()["records"][0]["wanId"] == "wan1"

    blank = client.put(f"/api/ddns/{record_id}", json={
        "provider": "cloudflare",
        "hostname": "renamed.example.com",
        "recordTypes": ["A"],
        "wanId": "",
    })
    assert blank.status_code == 200
    assert blank.get_json()["record"]["wanId"] == ""
    assert client.delete(f"/api/ddns/{record_id}").status_code == 200
    assert store.snapshot()["records"] == []
