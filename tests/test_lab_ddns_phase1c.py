import json
import tempfile
import unittest
from pathlib import Path

import lab_ddns
import lab_ddns_providers as providers
from lab_ddns import LabDdnsStore
from lab_ddns_providers import DeSecProvider, DuckDnsProvider, DynuProvider, Dynv6Provider, IPv64Provider


class FakeResponse:
    def __init__(self, text="OK", status_code=200, payload=None):
        self.text = text
        self.status_code = status_code
        self.payload = payload

    def json(self):
        if self.payload is not None:
            return self.payload
        return json.loads(self.text)


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


class LabDdnsPhase1CTests(unittest.TestCase):
    def assert_no_secret(self, result, secret):
        self.assertNotIn(secret, result.error)
        self.assertNotIn(secret, result.error_message)
        self.assertNotIn(secret, json.dumps(result.__dict__, ensure_ascii=False))

    def test_registry_and_capabilities(self):
        expected = {"dynv6", "duckdns", "desec", "dynu", "ipv64"}
        self.assertTrue(expected.issubset(lab_ddns.PROVIDERS))
        specs = {item["id"]: item for item in lab_ddns.provider_specs()}
        for provider_id in expected:
            self.assertTrue(specs[provider_id]["supportsA"])
            self.assertTrue(specs[provider_id]["supportsAAAA"])

    def test_dynv6_ipv4_ipv6_and_auth_redaction(self):
        ipv4_session = FakeSession([FakeResponse("good 198.51.100.10")])
        result = Dynv6Provider(ipv4_session).sync_record("home.dynv6.net", "A", "198.51.100.10", 600, {"token": "dynv6-secret"})
        self.assertTrue(result.ok)
        self.assertEqual(ipv4_session.calls[0][2]["params"]["ipv4"], "198.51.100.10")
        self.assertNotIn("ipv6", ipv4_session.calls[0][2]["params"])

        ipv6_session = FakeSession([FakeResponse("good 2001:db8::10")])
        result = Dynv6Provider(ipv6_session).sync_record("home.dynv6.net", "AAAA", "2001:db8::10", 600, {"token": "dynv6-secret"})
        self.assertTrue(result.ok)
        self.assertEqual(ipv6_session.calls[0][2]["params"]["ipv6"], "2001:db8::10")
        self.assertNotIn("ipv4", ipv6_session.calls[0][2]["params"])

        failed = Dynv6Provider(FakeSession([FakeResponse("forbidden dynv6-secret", 403)])).sync_record(
            "home.dynv6.net", "A", "198.51.100.10", 600, {"token": "dynv6-secret"}
        )
        self.assertFalse(failed.ok)
        self.assert_no_secret(failed, "dynv6-secret")

    def test_duckdns_ipv4_ipv6_dual_stack_and_error(self):
        credentials = {"token": "duck-secret"}
        ipv4 = FakeSession([FakeResponse("OK")])
        self.assertTrue(DuckDnsProvider(ipv4).sync_record("home.duckdns.org", "A", "198.51.100.11", 600, credentials).ok)
        self.assertEqual(ipv4.calls[0][2]["params"]["domains"], "home")
        self.assertEqual(ipv4.calls[0][2]["params"]["ip"], "198.51.100.11")
        self.assertNotIn("ipv6", ipv4.calls[0][2]["params"])

        ipv6 = FakeSession([FakeResponse("OK")])
        self.assertTrue(DuckDnsProvider(ipv6).sync_record("home.duckdns.org", "AAAA", "2001:db8::11", 600, credentials).ok)
        self.assertEqual(ipv6.calls[0][2]["params"]["ipv6"], "2001:db8::11")
        self.assertNotIn("ip", ipv6.calls[0][2]["params"])

        dual = FakeSession([FakeResponse("OK"), FakeResponse("OK")])
        provider = DuckDnsProvider(dual)
        self.assertTrue(provider.sync_record("home.duckdns.org", "A", "198.51.100.11", 600, credentials).ok)
        self.assertTrue(provider.sync_record("home.duckdns.org", "AAAA", "2001:db8::11", 600, credentials).ok)
        self.assertEqual(len(dual.calls), 2)

        failed = DuckDnsProvider(FakeSession([FakeResponse("KO")])).sync_record("home.duckdns.org", "A", "198.51.100.11", 600, credentials)
        self.assertFalse(failed.ok)
        self.assert_no_secret(failed, "duck-secret")

    def test_duckdns_published_values_stay_record_type_isolated(self):
        store = LabDdnsStore(Path(tempfile.mkdtemp(prefix="labprobe-ddns-1c-duck-")) / "lab_ddns.json")
        record = store.save_record({"provider": "duckdns", "hostname": "home.duckdns.org", "recordTypes": ["A", "AAAA"]})

        class RecordingDuckDns:
            provider_id = "duckdns"

            def __init__(self):
                self.calls = []

            def sync_record(self, hostname, record_type, value, ttl, credentials):
                self.calls.append(record_type)
                return lab_ddns.ProviderResult(
                    record_type == "A",
                    "success" if record_type == "A" else "error",
                    provider="duckdns",
                    record_type=record_type,
                    changed=record_type == "A",
                    error_code="" if record_type == "A" else "provider_error",
                    error_message="" if record_type == "A" else "AAAA failed",
                )

        provider = RecordingDuckDns()
        previous = lab_ddns.PROVIDERS["duckdns"]
        lab_ddns.PROVIDERS["duckdns"] = provider
        try:
            for detected_at in (100, 101):
                store.accept_address({
                    "detectedIpv4": "198.51.100.21",
                    "detectedIpv6": "2001:db8::21",
                    "ipv4State": "public",
                    "ipv6State": "public",
                    "detectedAt": detected_at,
                })
            result = store.run_update(record["id"])
            saved = store.snapshot()["records"][0]
            self.assertFalse(result["ok"])
            self.assertEqual(provider.calls, ["A", "AAAA"])
            self.assertEqual(saved["publishedIpv4"], "198.51.100.21")
            self.assertIsNone(saved["publishedIpv6"])
            self.assertEqual(saved["lastRecordResults"]["A"]["status"], "published")
            self.assertEqual(saved["lastRecordResults"]["AAAA"]["status"], "error")
        finally:
            lab_ddns.PROVIDERS["duckdns"] = previous

    def test_desec_a_aaaa_auth_and_token_redaction(self):
        credentials = {"token": "desec-secret"}
        a = FakeSession([FakeResponse("good")])
        self.assertTrue(DeSecProvider(a).sync_record("home.dedyn.io", "A", "198.51.100.12", 600, credentials).ok)
        self.assertEqual(a.calls[0][2]["params"]["myipv4"], "198.51.100.12")
        self.assertEqual(a.calls[0][2]["params"]["myipv6"], "preserve")
        self.assertEqual(a.calls[0][2]["headers"]["Authorization"], "Token desec-secret")

        aaaa = FakeSession([FakeResponse("good")])
        self.assertTrue(DeSecProvider(aaaa).sync_record("home.dedyn.io", "AAAA", "2001:db8::12", 600, credentials).ok)
        self.assertEqual(aaaa.calls[0][2]["params"]["myipv4"], "preserve")
        self.assertEqual(aaaa.calls[0][2]["params"]["myipv6"], "2001:db8::12")

        failed = DeSecProvider(FakeSession([FakeResponse("forbidden", 403)])).sync_record("home.dedyn.io", "AAAA", "2001:db8::12", 600, credentials)
        self.assertFalse(failed.ok)
        self.assert_no_secret(failed, "desec-secret")

    def test_dynu_ipv4_ipv6_provider_error_and_secret_redaction(self):
        credentials = {"username": "dynu-user", "password": "dynu-secret"}
        ipv4 = FakeSession([FakeResponse("good 198.51.100.13")])
        self.assertTrue(DynuProvider(ipv4).sync_record("home.example.com", "A", "198.51.100.13", 600, credentials).ok)
        self.assertEqual(ipv4.calls[0][2]["params"]["myip"], "198.51.100.13")
        self.assertEqual(ipv4.calls[0][2]["params"]["myipv6"], "no")
        self.assertEqual(ipv4.calls[0][2]["auth"], ("dynu-user", "dynu-secret"))

        ipv6 = FakeSession([FakeResponse("good 2001:db8::13")])
        self.assertTrue(DynuProvider(ipv6).sync_record("home.example.com", "AAAA", "2001:db8::13", 600, credentials).ok)
        self.assertEqual(ipv6.calls[0][2]["params"]["myip"], "no")
        self.assertEqual(ipv6.calls[0][2]["params"]["myipv6"], "2001:db8::13")

        failed = DynuProvider(FakeSession([FakeResponse("provider failure dynu-secret", 500)])).sync_record("home.example.com", "A", "198.51.100.13", 600, credentials)
        self.assertFalse(failed.ok)
        self.assert_no_secret(failed, "dynu-secret")

    def test_ipv64_ipv4_ipv6_auth_and_token_redaction(self):
        credentials = {"token": "ipv64-secret"}
        ipv4 = FakeSession([FakeResponse('{"status":"success","IP":["198.51.100.14"]}')])
        self.assertTrue(IPv64Provider(ipv4).sync_record("home.ipv64.net", "A", "198.51.100.14", 600, credentials).ok)
        self.assertEqual(ipv4.calls[0][2]["params"]["ip"], "198.51.100.14")
        self.assertEqual(ipv4.calls[0][2]["headers"]["Authorization"], "Bearer ipv64-secret")

        ipv6 = FakeSession([FakeResponse('{"Status":"good","IP":["2001:db8::14"]}')])
        self.assertTrue(IPv64Provider(ipv6).sync_record("home.ipv64.net", "AAAA", "2001:db8::14", 600, credentials).ok)
        self.assertEqual(ipv6.calls[0][2]["params"]["ip6"], "2001:db8::14")

        failed = IPv64Provider(FakeSession([FakeResponse("unauthorized", 401)])).sync_record("home.ipv64.net", "AAAA", "2001:db8::14", 600, credentials)
        self.assertFalse(failed.ok)
        self.assert_no_secret(failed, "ipv64-secret")

    def test_ipv64_429_uses_existing_retry_backoff(self):
        store = LabDdnsStore(Path(tempfile.mkdtemp(prefix="labprobe-ddns-1c-429-")) / "lab_ddns.json")
        record = store.save_record({"provider": "ipv64", "hostname": "home.ipv64.net", "recordTypes": ["A"]})
        store.save_credentials(record["id"], {"token": "ipv64-secret"})
        session = FakeSession([FakeResponse("rate limited", 429)])
        previous = lab_ddns.PROVIDERS["ipv64"]
        lab_ddns.PROVIDERS["ipv64"] = IPv64Provider(session)
        try:
            store.accept_address({"detectedIpv4": "198.51.100.22", "ipv4State": "public", "detectedAt": 200})
            store.accept_address({"detectedIpv4": "198.51.100.22", "ipv4State": "public", "detectedAt": 201})
            first = store.run_update(record["id"])
            self.assertFalse(first["ok"])
            self.assertEqual(first["results"]["A"]["errorCode"], "http_429")
            second = store.run_update(record["id"])
            self.assertTrue(second["ok"])
            self.assertEqual(second["results"]["A"]["status"], "retry_backoff")
            self.assertEqual(len(session.calls), 1)
        finally:
            lab_ddns.PROVIDERS["ipv64"] = previous

    def test_phase1b_provider_tests_remain_in_full_suite(self):
        self.assertIsInstance(lab_ddns.PROVIDERS["alidns"], providers.AliDnsProvider)
        self.assertIsInstance(lab_ddns.PROVIDERS["dnspod"], providers.DnsPodProvider)
        self.assertIsInstance(lab_ddns.PROVIDERS["cloudflare"], providers.CloudflareProvider)


if __name__ == "__main__":
    unittest.main()
