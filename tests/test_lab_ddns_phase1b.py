import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask

import lab_ddns
import lab_ddns_providers as providers
from lab_ddns import LabDdnsStore, install_lab_ddns
from lab_ddns_providers import AliDnsProvider, CloudflareProvider, DnsPodProvider


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

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
    provider_id = "fake"

    def __init__(self, outcomes, observer=None):
        self.outcomes = list(outcomes)
        self.calls = []
        self.observer = observer

    def sync_record(self, hostname, record_type, value, ttl, credentials):
        if self.observer is not None:
            self.observer()
        self.calls.append((hostname, record_type, value, ttl, dict(credentials)))
        return self.outcomes.pop(0)


class FakeHub:
    def __init__(self, allowed):
        self.app = Flask("lab-ddns-phase1b-route-test")
        self.DATA_DIR = Path(tempfile.mkdtemp(prefix="labprobe-ddns-route-"))
        self.LOGGER = logging.getLogger("lab-ddns-phase1b-route-test")
        self.allowed = allowed

    def check_app_token(self):
        return self.allowed


class LabDdnsPhase1BTests(unittest.TestCase):
    def new_store(self):
        return LabDdnsStore(Path(tempfile.mkdtemp(prefix="labprobe-ddns-1b-")) / "lab_ddns.json")

    def test_update_and_read_routes_require_app_auth_and_never_return_secret(self):
        denied_hub = FakeHub(False)
        denied_store = install_lab_ddns(denied_hub)
        denied_record = denied_store.save_record({"provider": "cloudflare", "hostname": "home.example.com"})
        denied_response = denied_hub.app.test_client().post(f"/api/ddns/{denied_record['id']}/update", json={})
        self.assertEqual(denied_response.status_code, 401)
        self.assertEqual(denied_hub.app.test_client().get("/api/ddns").status_code, 401)

        allowed_hub = FakeHub(True)
        allowed_store = install_lab_ddns(allowed_hub)
        record = allowed_store.save_record({"provider": "cloudflare", "hostname": "home.example.com"})
        allowed_store.save_credentials(record["id"], {"apiToken": "never-return-this", "zoneId": "zone-1"})
        response = allowed_hub.app.test_client().get("/api/ddns")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        encoded = json.dumps(body, ensure_ascii=False)
        self.assertTrue(body["records"][0]["credentialsConfigured"])
        self.assertNotIn("never-return-this", encoded)
        self.assertNotIn("AccessKeySecret", encoded)
        self.assertNotIn("SecretKey", encoded)
        self.assertNotIn("Authorization", encoded)

    def test_stability_then_explicit_provider_success(self):
        store = self.new_store()
        record = store.save_record({"provider": "cloudflare", "hostname": "home.example.com", "recordTypes": ["AAAA"]})
        store.save_credentials(record["id"], {"apiToken": "secret-token", "zoneId": "zone-1"})
        provider = FakeProvider(
            [lab_ddns.ProviderResult(True, "success", provider="fake", record_type="AAAA", record_id="r1", changed=True)],
            observer=lambda: self.assertEqual(store.snapshot()["records"][0]["status"], "updating"),
        )
        old = lab_ddns.PROVIDERS["cloudflare"]
        lab_ddns.PROVIDERS["cloudflare"] = provider
        try:
            address = {"detectedIpv6": "2409:db8::10", "ipv6State": "public", "ipv6Source": "default-route:wan6"}
            store.accept_address({**address, "detectedAt": 100})
            self.assertEqual(store.snapshot()["records"][0]["status"], "detected")
            self.assertIsNone(store.snapshot()["records"][0]["publishedIpv6"])
            self.assertEqual(store.snapshot()["records"][0]["stability"]["AAAA"]["stableCount"], 1)
            self.assertEqual(len(provider.calls), 0)
            store.accept_address({**address, "detectedAt": 100})
            self.assertEqual(store.snapshot()["records"][0]["stability"]["AAAA"]["stableCount"], 1)
            store.accept_address({**address, "detectedAt": 101})
            self.assertEqual(store.snapshot()["records"][0]["stability"]["AAAA"]["stableCount"], 2)
            result = store.run_update(record["id"])
            self.assertTrue(result["ok"])
            saved = store.snapshot()["records"][0]
            self.assertEqual(saved["status"], "published")
            self.assertEqual(saved["publishedIpv6"], "2409:db8::10")
            self.assertEqual(saved["lastRecordResults"]["AAAA"]["status"], "published")
            self.assertEqual(len(provider.calls), 1)
        finally:
            lab_ddns.PROVIDERS["cloudflare"] = old

    def test_error_keeps_old_published_and_a_aaaa_are_independent(self):
        store = self.new_store()
        record = store.save_record({"provider": "cloudflare", "hostname": "home.example.com", "recordTypes": ["A", "AAAA"]})
        store.save_credentials(record["id"], {"apiToken": "secret-token", "zoneId": "zone-1"})
        with store.lock:
            store.root["records"][0]["publishedIpv4"] = "198.51.100.1"
            store.root["records"][0]["publishedIpv6"] = "2001:db8::1"
            store._save_locked()
        provider = FakeProvider([
            lab_ddns.ProviderResult(True, "success", provider="fake", record_type="A", record_id="a1", changed=True),
            lab_ddns.ProviderResult(False, "error", "provider failed secret-token", provider="fake", record_type="AAAA", error_code="rate_limited", error_message="provider failed secret-token"),
        ])
        old = lab_ddns.PROVIDERS["cloudflare"]
        lab_ddns.PROVIDERS["cloudflare"] = provider
        try:
            for detected_at in (200, 201):
                store.accept_address({
                    "detectedIpv4": "198.51.100.2",
                    "detectedIpv6": "2409:db8::2",
                    "ipv4State": "public",
                    "ipv6State": "public",
                    "detectedAt": detected_at,
                })
            result = store.run_update(record["id"])
            self.assertFalse(result["ok"])
            saved = store.snapshot()["records"][0]
            self.assertEqual(saved["status"], "error")
            self.assertEqual(saved["publishedIpv4"], "198.51.100.2")
            self.assertEqual(saved["publishedIpv6"], "2001:db8::1")
            self.assertTrue(saved["lastRecordResults"]["A"]["success"])
            self.assertFalse(saved["lastRecordResults"]["AAAA"]["success"])
            self.assertNotIn("secret-token", json.dumps(saved, ensure_ascii=False))
            self.assertNotIn("secret-token", json.dumps(result, ensure_ascii=False))
        finally:
            lab_ddns.PROVIDERS["cloudflare"] = old

    def test_same_address_is_noop_and_auth_failure_is_not_retried(self):
        store = self.new_store()
        record = store.save_record({"provider": "cloudflare", "hostname": "home.example.com", "recordTypes": ["A"]})
        provider = FakeProvider([
            lab_ddns.ProviderResult(False, "error", provider="fake", record_type="A", error_code="AuthFailure", error_message="authentication failed"),
        ])
        old = lab_ddns.PROVIDERS["cloudflare"]
        lab_ddns.PROVIDERS["cloudflare"] = provider
        try:
            address = {"detectedIpv4": "198.51.100.2", "ipv4State": "public", "detectedAt": 300}
            store.accept_address(address)
            store.accept_address({**address, "detectedAt": 301})
            first = store.run_update(record["id"])
            self.assertFalse(first["ok"])
            second = store.run_update(record["id"])
            self.assertTrue(second["ok"])
            self.assertEqual(second["results"]["A"]["status"], "credential_error")
            self.assertEqual(len(provider.calls), 1)
            with store.lock:
                store.root["records"][0]["publishedIpv4"] = "198.51.100.2"
                store._save_locked()
            noop = store.run_update(record["id"])
            self.assertEqual(noop["results"]["A"]["status"], "noop")
            self.assertEqual(len(provider.calls), 1)
        finally:
            lab_ddns.PROVIDERS["cloudflare"] = old

    def test_transient_failure_uses_backoff(self):
        store = self.new_store()
        record = store.save_record({"provider": "cloudflare", "hostname": "home.example.com", "recordTypes": ["A"]})
        provider = FakeProvider([lab_ddns.ProviderResult(False, "error", provider="fake", record_type="A", error_code="rate_limited", error_message="try later")])
        old = lab_ddns.PROVIDERS["cloudflare"]
        lab_ddns.PROVIDERS["cloudflare"] = provider
        try:
            store.accept_address({"detectedIpv4": "198.51.100.5", "ipv4State": "public", "detectedAt": 500})
            store.accept_address({"detectedIpv4": "198.51.100.5", "ipv4State": "public", "detectedAt": 501})
            self.assertFalse(store.run_update(record["id"])["ok"])
            deferred = store.run_update(record["id"])
            self.assertEqual(deferred["results"]["A"]["status"], "retry_backoff")
            self.assertEqual(len(provider.calls), 1)
        finally:
            lab_ddns.PROVIDERS["cloudflare"] = old

    def test_stale_detected_address_is_never_sent_to_provider(self):
        store = self.new_store()
        record = store.save_record({"provider": "cloudflare", "hostname": "home.example.com", "recordTypes": ["AAAA"]})
        store.save_credentials(record["id"], {"apiToken": "secret-token", "zoneId": "zone-1"})
        provider = FakeProvider([])
        old = lab_ddns.PROVIDERS["cloudflare"]
        lab_ddns.PROVIDERS["cloudflare"] = provider
        try:
            stale_at = 1_786_325_000
            address = {"detectedIpv6": "2409:db8::7", "ipv6State": "public", "detectedAt": stale_at}
            store.accept_address(address)
            store.accept_address({**address, "detectedAt": stale_at + 1})
            with patch("lab_ddns._now", return_value=stale_at + lab_ddns.ADDRESS_STALE_SECONDS + 2):
                result = store.run_update(record["id"])
            saved = store.snapshot()["records"][0]
            self.assertFalse(result["ok"])
            self.assertEqual(result["results"]["AAAA"]["status"], "stale_address")
            self.assertEqual(saved["status"], "detected")
            self.assertIsNone(saved["publishedIpv6"])
            self.assertEqual(len(provider.calls), 0)
        finally:
            lab_ddns.PROVIDERS["cloudflare"] = old

    def test_restart_restores_stability_and_secrets_stay_private(self):
        store = self.new_store()
        record = store.save_record({"provider": "cloudflare", "hostname": "home.example.com", "recordTypes": ["AAAA"]})
        store.save_credentials(record["id"], {"apiToken": "secret-token", "zoneId": "zone-1"})
        store.accept_address({"detectedIpv6": "2409:db8::3", "ipv6State": "public", "detectedAt": 400})
        restarted = LabDdnsStore(store.path)
        self.assertEqual(restarted.snapshot()["records"][0]["stability"]["AAAA"]["stableCount"], 0)
        restarted.accept_address({"detectedIpv6": "2409:db8::3", "ipv6State": "public", "detectedAt": 400})
        self.assertEqual(restarted.snapshot()["records"][0]["stability"]["AAAA"]["stableCount"], 0)
        restarted.accept_address({"detectedIpv6": "2409:db8::3", "ipv6State": "public", "detectedAt": 401})
        self.assertEqual(restarted.snapshot()["records"][0]["stability"]["AAAA"]["stableCount"], 1)
        public = restarted.public_snapshot()
        encoded = json.dumps(public, ensure_ascii=False)
        self.assertNotIn("secret-token", encoded)
        self.assertTrue(public["records"][0]["credentialsConfigured"])

    def test_alidns_noop_update_add_and_error_redaction(self):
        credentials = {"AccessKeyId": "id", "AccessKeySecret": "secret", "zone": "example.com"}
        same = FakeSession([FakeResponse({"DomainRecords": {"Record": [{"RecordId": "1", "RR": "home", "Type": "A", "Value": "198.51.100.2"}]}})])
        self.assertFalse(AliDnsProvider(same).sync_record("home.example.com", "A", "198.51.100.2", 600, credentials).changed)
        different = FakeSession([
            FakeResponse({"DomainRecords": {"Record": [{"RecordId": "1", "RR": "home", "Type": "A", "Value": "198.51.100.2"}]}}),
            FakeResponse({"RecordId": "1"}),
        ])
        changed = AliDnsProvider(different).sync_record("home.example.com", "A", "198.51.100.3", 600, credentials)
        self.assertTrue(changed.changed)
        self.assertEqual(different.calls[1][2]["params"]["Action"], "UpdateDomainRecord")
        added = FakeSession([FakeResponse({"DomainRecords": {"Record": []}}), FakeResponse({"RecordId": "2"})])
        self.assertTrue(AliDnsProvider(added).sync_record("home.example.com", "AAAA", "2409:db8::2", 600, credentials).changed)
        self.assertEqual(added.calls[1][2]["params"]["Action"], "AddDomainRecord")
        error = FakeSession([FakeResponse({"Code": "InvalidAccessKeyId", "Message": "bad secret"})])
        failed = AliDnsProvider(error).sync_record("home.example.com", "A", "198.51.100.3", 600, credentials)
        self.assertFalse(failed.ok)
        self.assertNotIn("secret", failed.error_message.lower())

    def test_alidns_signature_fixture_is_sorted_and_encoded(self):
        class FixedDateTime:
            @classmethod
            def now(cls, tz=None):
                from datetime import datetime, timezone
                return datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

        credentials = {"AccessKeyId": "id", "AccessKeySecret": "secret"}
        provider = AliDnsProvider(FakeSession([]))
        with patch.object(providers.uuid, "uuid4", return_value=type("Uuid", (), {"hex": "nonce"})()), patch.object(providers, "datetime", FixedDateTime):
            params = provider._signed_params("DescribeDomainRecords", {"Value": "a b", "ActionOrder": "z"}, credentials)
        self.assertEqual(params["Timestamp"], "2024-01-02T03:04:05Z")
        self.assertEqual(params["SignatureNonce"], "nonce")
        self.assertEqual(params["Signature"], "2SJTkOfZ/TZn99xNX27zSPj/p5I=")
        self.assertNotIn("AccessKeySecret", json.dumps(params))

    def test_dnspod_tc3_signature_fixture(self):
        credentials = {"SecretId": "sid", "SecretKey": "skey"}
        provider = DnsPodProvider(FakeSession([]))
        body = {"Domain": "example.com", "Subdomain": "home", "RecordType": "A", "RecordLine": "默认"}
        with patch.object(providers.time, "time", return_value=1704164645):
            headers = provider._headers("DescribeRecordList", body, credentials)
        self.assertEqual(headers["X-TC-Version"], "2021-03-23")
        self.assertEqual(headers["X-TC-Timestamp"], "1704164645")
        self.assertEqual(headers["Authorization"], "TC3-HMAC-SHA256 Credential=sid/2024-01-02/dnspod/tc3_request, SignedHeaders=content-type;host, Signature=54c9782cd9924cbd1603a6e1356b92cb4574cdfb9ca8cb3f5016b1ed82a35cd8")
        self.assertNotIn("skey", headers["Authorization"])

    def test_dnspod_create_modify_and_tc3_redaction(self):
        credentials = {"SecretId": "sid", "SecretKey": "skey", "zone": "example.com"}
        session = FakeSession([
            FakeResponse({"Response": {"RecordList": [{"RecordId": "7", "Name": "home", "Type": "A", "Value": "198.51.100.2"}]}}),
            FakeResponse({"Response": {}}),
        ])
        result = DnsPodProvider(session).sync_record("home.example.com", "A", "198.51.100.3", 600, credentials)
        self.assertTrue(result.ok)
        self.assertEqual(session.calls[1][2]["headers"]["X-TC-Action"], "ModifyRecord")
        added = FakeSession([FakeResponse({"Response": {"RecordList": []}}), FakeResponse({"Response": {"RecordId": "8"}})])
        self.assertTrue(DnsPodProvider(added).sync_record("home.example.com", "AAAA", "2409:db8::3", 600, credentials).ok)
        self.assertEqual(added.calls[1][2]["headers"]["X-TC-Action"], "CreateRecord")
        self.assertNotIn("skey", result.error_message)

    def test_cloudflare_create_patch_noop_and_proxied_default(self):
        credentials = {"apiToken": "cf-secret", "zoneId": "zone-1"}
        created = FakeSession([FakeResponse({"success": True, "result": []}), FakeResponse({"success": True, "result": {"id": "cf1"}})])
        result = CloudflareProvider(created).sync_record("home.example.com", "A", "198.51.100.4", 600, credentials)
        self.assertTrue(result.changed)
        self.assertFalse(created.calls[1][2]["json"]["proxied"])
        patched = FakeSession([
            FakeResponse({"success": True, "result": [{"id": "cf2", "name": "home.example.com", "type": "AAAA", "content": "2001:db8::1", "ttl": 600, "proxied": True, "data": {"keep": True}}]}),
            FakeResponse({"success": True, "result": {"id": "cf2"}}),
        ])
        result = CloudflareProvider(patched).sync_record("home.example.com", "AAAA", "2001:db8::2", 600, credentials)
        self.assertTrue(result.changed)
        self.assertTrue(patched.calls[1][2]["json"]["proxied"])
        noop = FakeSession([FakeResponse({"success": True, "result": [{"id": "cf3", "name": "home.example.com", "type": "A", "content": "198.51.100.4"}]})])
        self.assertFalse(CloudflareProvider(noop).sync_record("home.example.com", "A", "198.51.100.4", 600, credentials).changed)


if __name__ == "__main__":
    unittest.main()
