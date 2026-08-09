import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


TEST_ROOT = tempfile.mkdtemp(prefix="labprobe-ddns-test-")
os.environ.setdefault("DATA_DIR", str(Path(TEST_ROOT) / "data"))
os.environ.setdefault("CONFIG_DIR", str(Path(TEST_ROOT) / "config"))
os.environ.setdefault("BACKUPS_DIR", str(Path(TEST_ROOT) / "backups"))
os.environ.setdefault("LOGS_DIR", str(Path(TEST_ROOT) / "logs"))
os.environ.setdefault("APP_TOKEN", "test-app-token")
os.environ.setdefault("HOOK_TOKEN", "test-hook-token")

import hub  # noqa: E402
from lab_ddns import LabDdnsStore, PROVIDERS, PROVIDER_IDS, provider_specs  # noqa: E402
from router_compat import RouterRpcCompatibilitySync  # noqa: E402


class LabDdnsPhase1ATests(unittest.TestCase):
    def new_store(self):
        return LabDdnsStore(Path(tempfile.mkdtemp(prefix="labprobe-ddns-state-")) / "lab_ddns.json")

    def test_provider_registry_is_local_and_complete(self):
        self.assertEqual(set(PROVIDERS), set(PROVIDER_IDS))
        self.assertEqual({item["id"] for item in provider_specs()}, set(PROVIDER_IDS))
        self.assertTrue(all("credentialSchema" not in item for item in provider_specs()))
        result = PROVIDERS["cloudflare"].update("router.example", "", "", {})
        self.assertFalse(result.ok)
        self.assertEqual(result.status, "not_implemented")

    def test_detected_and_published_addresses_are_separate_and_persistent(self):
        store = self.new_store()
        record = store.save_record({
            "provider": "alidns",
            "hostname": "router.example",
            "recordTypes": ["A"],
            "credentials": {"token": "secret-value"},
        })
        self.assertTrue(store.accept_address({
            "detectedIpv4": "198.51.100.10",
            "detectedIpv6": "2001:db8::10",
            "ipv4State": "public",
            "ipv6State": "public",
            "ipv4Source": "default-route:pppoe0",
            "ipv6Source": "default-route:pppoe0",
            "detectedAt": 100,
        }))
        address = store.snapshot()["address"]
        self.assertEqual(address["detectedIpv6"], "2001:db8::10")
        self.assertEqual(address["ipv6State"], "public")
        self.assertEqual(address["ipv6Source"], "default-route:pppoe0")
        detected = store.snapshot()["records"][0]
        self.assertEqual(detected["status"], "detected")
        self.assertEqual(detected["publishedIpv6"], None)
        self.assertEqual(detected["lastUpdatedAt"], None)
        self.assertEqual(detected["lastError"], None)
        self.assertEqual(detected["source"], "default-route:pppoe0,default-route:pppoe0")
        with store.lock:
            store.root["records"][0]["publishedIpv4"] = "198.51.100.9"
            store.root["records"][0]["publishedIpv6"] = "2001:db8::9"
            store.root["records"][0]["lastUpdatedAt"] = 90
            store._save_locked()
        store.accept_address({
            "detectedIpv4": "198.51.100.11",
            "detectedIpv4State": "public",
            "detectedAt": 110,
        })
        loaded = LabDdnsStore(store.path).snapshot()
        saved = loaded["records"][0]
        self.assertEqual(saved["id"], record["id"])
        self.assertEqual(saved["detectedIpv4"], "198.51.100.11")
        self.assertEqual(saved["publishedIpv4"], "198.51.100.9")
        self.assertEqual(saved["publishedIpv6"], "2001:db8::9")
        self.assertEqual(saved["lastUpdatedAt"], 90)
        self.assertNotIn("secret-value", json.dumps(loaded))

    def test_error_status_keeps_last_published_address(self):
        store = self.new_store()
        record = store.save_record({"provider": "dnspod", "hostname": "router.example"})
        with store.lock:
            stored = store.root["records"][0]
            stored.update({
                "publishedIpv6": "2001:db8::1",
                "status": "error",
                "lastError": "provider timeout",
                "lastUpdatedAt": 200,
            })
            store._save_locked()
        store.accept_address({
            "detectedIpv6": "2409:db8::2",
            "ipv6State": "public",
            "ipv6Source": "default-route:wan6",
            "detectedAt": 210,
        })
        saved = LabDdnsStore(store.path).snapshot()["records"][0]
        self.assertEqual(saved["id"], record["id"])
        self.assertEqual(saved["detectedIpv6"], "2409:db8::2")
        self.assertEqual(saved["status"], "error")
        self.assertEqual(saved["publishedIpv6"], "2001:db8::1")
        self.assertEqual(saved["lastUpdatedAt"], 200)
        self.assertEqual(saved["lastError"], "provider timeout")

    def test_record_edit_cannot_change_published_without_provider_result(self):
        store = self.new_store()
        record = store.save_record({"provider": "cloudflare", "hostname": "router.example"})
        with store.lock:
            store.root["records"][0]["publishedIpv4"] = "198.51.100.40"
            store.root["records"][0]["lastUpdatedAt"] = 300
            store._save_locked()
        updated = store.save_record({"provider": "cloudflare", "hostname": "new.example", "publishedIpv4": "198.51.100.41"}, record["id"])
        self.assertEqual(updated["publishedIpv4"], "198.51.100.40")
        self.assertEqual(updated["lastUpdatedAt"], 300)

    def test_old_dashboard_without_ddns_is_compatible(self):
        store = self.new_store()
        self.assertFalse(store.accept_address(None))
        self.assertEqual(store.snapshot()["address"], {})

    def test_repeated_dashboard_payload_does_not_rewrite_state(self):
        store = self.new_store()
        payload = {"detectedIpv4": "198.51.100.30", "ipv4State": "public", "detectedAt": 140}
        with mock.patch.object(store, "_save_locked", wraps=store._save_locked) as save:
            self.assertTrue(store.accept_address(payload))
            self.assertTrue(store.accept_address(payload))
        self.assertEqual(save.call_count, 1)

    def test_normal_dashboard_push_accepts_ddns_address(self):
        store = self.new_store()
        with mock.patch.object(hub, "LAB_DDNS", store, create=True), \
             mock.patch.object(hub, "_cached_hub_exit_ipv4", return_value=""), \
             mock.patch.object(hub, "_schedule_dashboard_operator_probe", return_value=None):
            response = hub.app.test_client().post(
                "/api/router/dashboard/push",
                headers={"X-LabProbe-Token": "test-hook-token"},
                json={"router": "BE72", "ddnsAddress": {
                    "detectedIpv4": "198.51.100.20",
                    "ipv4State": "public",
                    "detectedAt": 120,
                }},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(store.snapshot()["address"]["detectedIpv4"], "198.51.100.20")

    def test_router_rpc_primary_ignored_push_still_accepts_ddns(self):
        store = self.new_store()
        fake_hub = SimpleNamespace(
            check_hook_token=lambda: True,
            LAB_DDNS=store,
            now_str=lambda: "now",
        )
        sync = object.__new__(RouterRpcCompatibilitySync)
        sync.hub = fake_hub
        with hub.app.test_request_context(
            "/api/router/dashboard/push",
            method="POST",
            json={"ddnsAddress": {"detectedIpv6": "2001:db8::20", "ipv6State": "public", "detectedAt": 130}},
        ):
            response = sync.ignored_relay_dashboard_push()
        status_code = response.status_code if hasattr(response, "status_code") else response[1]
        self.assertEqual(status_code, 200)
        self.assertEqual(store.snapshot()["address"]["detectedIpv6"], "2001:db8::20")


if __name__ == "__main__":
    unittest.main()
