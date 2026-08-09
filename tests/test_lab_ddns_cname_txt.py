import json
from pathlib import Path

import pytest

import lab_ddns
from lab_ddns import LabDdnsStore, install_lab_ddns
from lab_ddns_providers import AliDnsProvider, CloudflareProvider, DnsPodProvider, DuckDnsProvider


class FakeResponse:
    def __init__(self, payload, status_code=200, text=None):
        self.payload = payload
        self.status_code = status_code
        self.text = text

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


class FakeProvider:
    provider_id = "cloudflare"

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def supports_record_type(self, record_type):
        return record_type in {"A", "AAAA", "CNAME", "TXT"}

    def sync_record(self, hostname, record_type, value, ttl, credentials):
        self.calls.append((hostname, record_type, value, ttl, dict(credentials)))
        return self.outcomes.pop(0)


def new_store(tmp_path: Path):
    return LabDdnsStore(tmp_path / "lab_ddns.json")


@pytest.mark.parametrize("provider_cls, record_type, existing, action", [
    (AliDnsProvider, "CNAME", {"RecordId": "c1", "RR": "home", "Type": "CNAME", "Value": "old.example.net"}, "UpdateDomainRecord"),
    (AliDnsProvider, "TXT", {"RecordId": "t1", "RR": "home", "Type": "TXT", "Value": "old"}, "UpdateDomainRecord"),
])
def test_alidns_cname_and_txt_use_record_type_and_value(provider_cls, record_type, existing, action):
    session = FakeSession([
        FakeResponse({"DomainRecords": {"Record": [existing]}}),
        FakeResponse({"RecordId": existing["RecordId"]}),
    ])
    result = provider_cls(session).sync_record("home.example.com", record_type, "new-value", 600, {"AccessKeyId": "id", "AccessKeySecret": "secret", "zone": "example.com"})
    assert result.ok and result.changed
    assert session.calls[1][2]["params"]["Action"] == action
    assert session.calls[1][2]["params"]["Type"] == record_type
    assert session.calls[1][2]["params"]["Value"] == "new-value"


@pytest.mark.parametrize("record_type", ["CNAME", "TXT"])
def test_dnspod_cname_and_txt_use_independent_record_type(record_type):
    session = FakeSession([
        FakeResponse({"Response": {"RecordList": [{"RecordId": "r1", "Name": "home", "Type": record_type, "Value": "old"}]}}),
        FakeResponse({"Response": {}}),
    ])
    result = DnsPodProvider(session).sync_record("home.example.com", record_type, "new-value", 600, {"SecretId": "sid", "SecretKey": "skey", "zone": "example.com"})
    assert result.ok and result.changed
    body = session.calls[1][2]["json"]
    assert body["RecordType"] == record_type
    assert body["Value"] == "new-value"


@pytest.mark.parametrize("provider_cls, record_type, expected_action", [
    (AliDnsProvider, "CNAME", "AddDomainRecord"),
    (AliDnsProvider, "TXT", "AddDomainRecord"),
    (DnsPodProvider, "CNAME", "CreateRecord"),
    (DnsPodProvider, "TXT", "CreateRecord"),
])
def test_alidns_dnspod_cname_txt_create(provider_cls, record_type, expected_action):
    if provider_cls is AliDnsProvider:
        session = FakeSession([
            FakeResponse({"DomainRecords": {"Record": []}}),
            FakeResponse({"RecordId": "new"}),
        ])
        credentials = {"AccessKeyId": "id", "AccessKeySecret": "secret", "zone": "example.com"}
    else:
        session = FakeSession([
            FakeResponse({"Response": {"RecordList": []}}),
            FakeResponse({"Response": {"RecordId": "new"}}),
        ])
        credentials = {"SecretId": "sid", "SecretKey": "skey", "zone": "example.com"}
    result = provider_cls(session).sync_record("home.example.com", record_type, "target.example.net" if record_type == "CNAME" else "verification", 600, credentials)
    assert result.ok and result.changed
    if provider_cls is AliDnsProvider:
        assert session.calls[1][2]["params"]["Action"] == expected_action
        assert session.calls[1][2]["params"]["Type"] == record_type
    else:
        assert session.calls[1][2]["headers"]["X-TC-Action"] == expected_action
        assert session.calls[1][2]["json"]["RecordType"] == record_type


@pytest.mark.parametrize("record_type", ["CNAME", "TXT"])
def test_cloudflare_cname_txt_create_update_and_noop(record_type):
    credentials = {"apiToken": "secret", "zoneId": "zone-1"}
    create = FakeSession([FakeResponse({"success": True, "result": []}), FakeResponse({"success": True, "result": {"id": "new"}})])
    created = CloudflareProvider(create).sync_record("home.example.com", record_type, "target.example.net" if record_type == "CNAME" else "verification", 600, credentials)
    assert created.ok and created.changed
    create_body = create.calls[1][2]["json"]
    assert create_body["type"] == record_type
    assert create_body["content"]
    if record_type == "CNAME":
        assert create_body["proxied"] is False
    else:
        assert "proxied" not in create_body

    existing = {"id": "r1", "name": "home.example.com", "type": record_type, "content": "old", "ttl": 600, "data": {"keep": True}}
    update = FakeSession([FakeResponse({"success": True, "result": [existing]}), FakeResponse({"success": True, "result": {"id": "r1"}})])
    changed = CloudflareProvider(update).sync_record("home.example.com", record_type, "new", 600, credentials)
    assert changed.ok and changed.changed
    assert update.calls[1][2]["json"]["content"] == "new"
    assert update.calls[1][2]["json"]["data"] == {"keep": True}

    noop = FakeSession([FakeResponse({"success": True, "result": [{**existing, "content": "same"}]})])
    same = CloudflareProvider(noop).sync_record("home.example.com", record_type, "same", 600, credentials)
    assert same.ok and not same.changed
    assert len(noop.calls) == 1


def test_duckdns_txt_uses_txt_parameter_and_cname_is_rejected():
    session = FakeSession([FakeResponse({}, text="OK")])
    result = DuckDnsProvider(session).sync_record("home.duckdns.org", "TXT", "verification", 600, {"token": "secret"})
    assert result.ok
    assert session.calls[0][2]["params"] == {"domains": "home", "token": "secret", "txt": "verification"}

    rejected_session = FakeSession([])
    rejected = DuckDnsProvider(rejected_session).sync_record("home.duckdns.org", "CNAME", "target.example.net", 600, {"token": "secret"})
    assert not rejected.ok
    assert rejected.error_code == "unsupported_record_type"
    assert rejected_session.calls == []


def test_provider_capabilities_expose_cname_txt_matrix():
    specs = {item["id"]: item for item in lab_ddns.provider_specs()}
    assert specs["alidns"]["recordTypes"] == ["A", "AAAA", "CNAME", "TXT"]
    assert specs["dnspod"]["recordTypes"] == ["A", "AAAA", "CNAME", "TXT"]
    assert specs["cloudflare"]["recordTypes"] == ["A", "AAAA", "CNAME", "TXT"]
    assert specs["duckdns"]["recordTypes"] == ["A", "AAAA", "TXT"]
    for provider in ("dynv6", "desec", "dynu", "ipv64"):
        assert specs[provider]["recordTypes"] == ["A", "AAAA"]


def test_cname_and_txt_update_without_detected_addresses(tmp_path):
    store = new_store(tmp_path)
    cname = store.save_record({"provider": "cloudflare", "hostname": "alias.example.com", "recordTypes": ["CNAME"], "recordValues": {"CNAME": "target.example.net"}})
    txt = store.save_record({"provider": "cloudflare", "hostname": "_verify.example.com", "recordTypes": ["TXT"], "recordValues": {"TXT": "verification"}})
    provider = FakeProvider([
        lab_ddns.ProviderResult(True, "success", provider="cloudflare", record_type="CNAME", changed=True),
        lab_ddns.ProviderResult(True, "success", provider="cloudflare", record_type="TXT", changed=True),
    ])
    old = lab_ddns.PROVIDERS["cloudflare"]
    lab_ddns.PROVIDERS["cloudflare"] = provider
    try:
        assert store.run_update(cname["id"])["ok"]
        assert store.run_update(txt["id"])["ok"]
    finally:
        lab_ddns.PROVIDERS["cloudflare"] = old
    records = {item["id"]: item for item in store.snapshot()["records"]}
    assert records[cname["id"]]["publishedValues"] == {"CNAME": "target.example.net"}
    assert records[txt["id"]]["publishedValues"] == {"TXT": "verification"}
    assert records[cname["id"]]["publishedIpv4"] is None
    assert records[cname["id"]]["publishedIpv6"] is None
    assert [call[1] for call in provider.calls] == ["CNAME", "TXT"]


def test_txt_value_preserves_user_whitespace(tmp_path):
    store = new_store(tmp_path)
    value = "  v=spf1 include:example.test  "
    record = store.save_record({"provider": "cloudflare", "hostname": "_verify.example.com", "recordTypes": ["TXT"], "recordValues": {"TXT": value}})
    assert record["recordValues"]["TXT"] == value
    provider = FakeProvider([lab_ddns.ProviderResult(True, "success", provider="cloudflare", record_type="TXT", changed=True)])
    old = lab_ddns.PROVIDERS["cloudflare"]
    lab_ddns.PROVIDERS["cloudflare"] = provider
    try:
        assert store.run_update(record["id"])["ok"]
    finally:
        lab_ddns.PROVIDERS["cloudflare"] = old
    assert provider.calls[0][2] == value


def test_editing_direct_value_keeps_published_value_separate(tmp_path):
    store = new_store(tmp_path)
    record = store.save_record({"provider": "cloudflare", "hostname": "alias.example.com", "recordTypes": ["CNAME"], "recordValues": {"CNAME": "old.example.net"}})
    with store.lock:
        store.root["records"][0]["publishedValues"] = {"CNAME": "old.example.net"}
        store._save_locked()
    updated = store.save_record({"provider": "cloudflare", "hostname": "alias.example.com", "recordTypes": ["CNAME"], "recordValues": {"CNAME": "new.example.net"}}, record["id"])
    assert updated["recordValues"] == {"CNAME": "new.example.net"}
    assert updated["publishedValues"] == {"CNAME": "old.example.net"}


def test_a_aaaa_txt_published_values_stay_independent(tmp_path):
    store = new_store(tmp_path)
    record = store.save_record({"provider": "cloudflare", "hostname": "home.example.com", "recordTypes": ["A", "AAAA", "TXT"], "recordValues": {"TXT": "verify"}})
    provider = FakeProvider([lab_ddns.ProviderResult(True, "success", provider="cloudflare", record_type="TXT", changed=True)])
    old = lab_ddns.PROVIDERS["cloudflare"]
    lab_ddns.PROVIDERS["cloudflare"] = provider
    try:
        result = store.run_update(record["id"])
    finally:
        lab_ddns.PROVIDERS["cloudflare"] = old
    saved = store.snapshot()["records"][0]
    assert result["ok"]
    assert saved["publishedValues"] == {"TXT": "verify"}
    assert saved["publishedIpv4"] is None and saved["publishedIpv6"] is None


def test_txt_success_does_not_turn_waiting_a_into_provider_error(tmp_path):
    store = new_store(tmp_path)
    record = store.save_record({"provider": "cloudflare", "hostname": "home.example.com", "recordTypes": ["A", "TXT"], "recordValues": {"TXT": "verify"}})
    store.accept_address({"detectedIpv4": "198.51.100.20", "ipv4State": "public", "detectedAt": 1})
    provider = FakeProvider([lab_ddns.ProviderResult(True, "success", provider="cloudflare", record_type="TXT", changed=True)])
    old = lab_ddns.PROVIDERS["cloudflare"]
    lab_ddns.PROVIDERS["cloudflare"] = provider
    try:
        result = store.run_update(record["id"])
    finally:
        lab_ddns.PROVIDERS["cloudflare"] = old
    saved = store.snapshot()["records"][0]
    assert result["ok"]
    assert saved["status"] == "detected"
    assert saved["publishedValues"] == {"TXT": "verify"}
    assert saved["stability"]["A"]["retryAttempt"] == 0


def test_txt_updates_when_either_ip_family_is_unavailable(tmp_path):
    store = new_store(tmp_path)
    ipv4_record = store.save_record({"provider": "cloudflare", "hostname": "v4.example.com", "recordTypes": ["A", "TXT"], "recordValues": {"TXT": "google-site-verification=abc123"}})
    ipv6_record = store.save_record({"provider": "cloudflare", "hostname": "v6.example.com", "recordTypes": ["AAAA", "TXT"], "recordValues": {"TXT": "v=spf1 include:example.com ~all"}})
    provider = FakeProvider([
        lab_ddns.ProviderResult(True, "success", provider="cloudflare", record_type="TXT", changed=True),
        lab_ddns.ProviderResult(True, "success", provider="cloudflare", record_type="TXT", changed=True),
    ])
    old = lab_ddns.PROVIDERS["cloudflare"]
    lab_ddns.PROVIDERS["cloudflare"] = provider
    try:
        assert store.run_update(ipv4_record["id"])["ok"]
        assert store.run_update(ipv6_record["id"])["ok"]
    finally:
        lab_ddns.PROVIDERS["cloudflare"] = old
    records = {item["id"]: item for item in store.snapshot()["records"]}
    assert records[ipv4_record["id"]]["publishedValues"] == {"TXT": "google-site-verification=abc123"}
    assert records[ipv6_record["id"]]["publishedValues"] == {"TXT": "v=spf1 include:example.com ~all"}
    assert [call[1] for call in provider.calls] == ["TXT", "TXT"]


def test_cname_conflict_and_provider_unsupported_type_are_rejected(tmp_path):
    store = new_store(tmp_path)
    with pytest.raises(ValueError, match="CNAME"):
        store.save_record({"provider": "cloudflare", "hostname": "alias.example.com", "recordTypes": ["CNAME", "A"], "recordValues": {"CNAME": "target.example.net"}})
    with pytest.raises(ValueError, match="does not support"):
        store.save_record({"provider": "duckdns", "hostname": "home.duckdns.org", "recordTypes": ["CNAME"], "recordValues": {"CNAME": "target.example.net"}})


@pytest.mark.parametrize("target", [
    "https://target.example.com",
    "http://target.example.com",
    "target.example.com/path",
    "alias.example.com",
])
def test_cname_url_path_and_self_reference_are_rejected_by_hub(tmp_path, target):
    store = new_store(tmp_path)
    with pytest.raises(ValueError, match="CNAME"):
        store.save_record({"provider": "cloudflare", "hostname": "alias.example.com", "recordTypes": ["CNAME"], "recordValues": {"CNAME": target}})


def test_cname_trailing_dot_is_normalized_without_changing_target(tmp_path):
    store = new_store(tmp_path)
    record = store.save_record({"provider": "cloudflare", "hostname": "alias.example.com", "recordTypes": ["CNAME"], "recordValues": {"CNAME": "target.example.com."}})
    assert record["recordValues"] == {"CNAME": "target.example.com"}


def test_old_json_without_record_values_remains_readable(tmp_path):
    path = tmp_path / "lab_ddns.json"
    path.write_text(json.dumps({"version": 1, "address": {}, "records": [{"id": "old", "provider": "cloudflare", "hostname": "home.example.com", "recordTypes": ["A"]}]}), encoding="utf-8")
    store = LabDdnsStore(path)
    record = store.snapshot()["records"][0]
    assert record["recordValues"] == {}
    assert record["publishedValues"] == {}


def test_save_route_publishes_direct_value_without_address_sample(tmp_path):
    import logging
    from flask import Flask

    class Hub:
        def __init__(self):
            self.app = Flask("lab-ddns-cname-route-test")
            self.DATA_DIR = tmp_path
            self.LOGGER = logging.getLogger("lab-ddns-cname-route-test")

        def check_app_token(self):
            return True

    hub = Hub()
    install_lab_ddns(hub)
    provider = FakeProvider([lab_ddns.ProviderResult(True, "success", provider="cloudflare", record_type="TXT", changed=True)])
    old = lab_ddns.PROVIDERS["cloudflare"]
    lab_ddns.PROVIDERS["cloudflare"] = provider
    try:
        response = hub.app.test_client().post("/api/ddns", json={
            "provider": "cloudflare",
            "hostname": "_verify.example.com",
            "recordTypes": ["TXT"],
            "recordValues": {"TXT": "verification"},
        })
    finally:
        lab_ddns.PROVIDERS["cloudflare"] = old
    assert response.status_code == 200
    body = response.get_json()["record"]
    assert body["publishedValues"] == {"TXT": "verification"}
    assert provider.calls[0][1:3] == ("TXT", "verification")
