import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


TEST_ROOT = tempfile.mkdtemp(prefix="labprobe-hub-test-")
os.environ["DATA_DIR"] = str(Path(TEST_ROOT) / "data")
os.environ["CONFIG_DIR"] = str(Path(TEST_ROOT) / "config")
os.environ["BACKUPS_DIR"] = str(Path(TEST_ROOT) / "backups")
os.environ["LOGS_DIR"] = str(Path(TEST_ROOT) / "logs")
os.environ["CONFIG_PATH"] = str(Path(TEST_ROOT) / "config" / "config.yaml")
os.environ["APP_TOKEN"] = "test-app-token"
os.environ["HOOK_TOKEN"] = "test-hook-token"
os.environ["HUB_ADVERTISE_URL"] = "http://192.168.1.20:58443"

import hub  # noqa: E402


class HubSyncApiTests(unittest.TestCase):
    def setUp(self):
        self.client = hub.app.test_client()
        self.headers = {"Authorization": "Bearer test-app-token"}

    def test_snapshot_delta_and_revision(self):
        hub.save_json(hub.STATE_FILE, {"router": {"name": "Ruijie"}})
        hub.save_json(hub.DEVICES_FILE, {
            "updatedAt": "2026-07-17 10:00:00",
            "online": [{"mac": "02:00:00:00:00:01", "name": "Phone", "online": True}],
            "watched": [{"mac": "02:00:00:00:00:01", "name": "Phone", "online": True}],
        })
        hub.add_event({"type": "device_online", "name": "Phone", "mac": "02:00:00:00:00:01"})

        snapshot = self.client.get("/api/sync/snapshot", headers=self.headers)
        self.assertEqual(snapshot.status_code, 200)
        body = snapshot.get_json()
        revision = body["revision"]
        self.assertEqual(len(body["devices"]["online"]), 1)
        self.assertEqual(len(body["events"]), 1)

        hub.save_json(hub.DEVICES_FILE, {
            "updatedAt": "2026-07-17 10:01:00",
            "online": [],
            "watched": [{"mac": "02:00:00:00:00:01", "name": "Phone", "online": False}],
        })
        delta = self.client.get(f"/api/sync/changes?since={revision}", headers=self.headers)
        self.assertEqual(delta.status_code, 200)
        changes = delta.get_json()["changes"]
        self.assertTrue(any(x["entity"] == "online_device" and x["operation"] == "delete" for x in changes))
        self.assertTrue(any(x["entity"] == "device" and x["operation"] == "upsert" for x in changes))

    def test_portmap_list_exposes_document_revision_and_command_sync_state(self):
        rule = {"id": "map-1", "name": "Web", "enabled": True, "listenPort": 20000}
        hub.save_json(hub.PORTMAP_RULES_FILE, {"version": 1, "revision": 7, "updatedAt": "2026-08-10 10:00:00", "rules": [rule]})
        hub.save_json(hub.PORTMAP_COMMANDS_FILE, {"commands": [{
            "id": "cmd-1", "router": hub._portmap_router_name(), "action": "upsert",
            "payload": {"rule": rule}, "status": "pending",
        }]})
        response = self.client.get("/api/portmaps", headers=self.headers)
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["rulesLoaded"])
        self.assertEqual(body["rulesRevision"], 7)
        self.assertEqual(body["rulesUpdatedAt"], "2026-08-10 10:00:00")
        self.assertEqual(body["rules"][0]["syncState"], "syncing")

    def test_portmap_service_type_is_preserved_by_the_hub_model(self):
        payload = {
            "id": "map-service-type",
            "name": "NAS HTTPS",
            "enabled": True,
            "mode": "6to4",
            "listenPort": 20000,
            "targetMode": "ipv4",
            "targetIpv4": "192.168.5.46",
            "targetIpv6": "",
            "targetIpv6Suffix": "",
            "targetMac": "",
            "targetPort": 443,
            "serviceType": "HTTPS",
            "expiresAt": None,
            "leaseSeconds": 0,
            "maxConnections": 32,
            "idleTimeoutSec": 300,
        }
        created = hub._clean_portmap_rule(payload)
        updated = hub._clean_portmap_rule({"name": "NAS Web"}, created)
        self.assertEqual(created["serviceType"], "HTTPS")
        self.assertEqual(updated["serviceType"], "HTTPS")

    def test_portmap_transport_defaults_to_tcp_and_retains_ipv6_snapshot(self):
        payload = {
            "id": "map-ipv6-snapshot",
            "name": "NAS HTTPS",
            "enabled": True,
            "mode": "6to6",
            "listenPort": 20000,
            "targetMode": "ipv6_suffix",
            "targetIpv4": "",
            "targetIpv6": "2409:8a50:2e40:8dc0:a9e5:169d:a7c8:9bfe",
            "targetIpv6Snapshot": "2409:8a50:2e40:8dc0:a9e5:169d:a7c8:9bfe",
            "targetIpv6Suffix": "::a9e5:169d:a7c8:9bfe",
            "targetMac": "aa:bb:cc:dd:ee:ff",
            "targetPort": 443,
            "serviceType": "HTTPS",
            "leaseSeconds": 0,
            "maxConnections": 32,
            "idleTimeoutSec": 300,
        }
        cleaned = hub._clean_portmap_rule(payload)
        self.assertEqual(cleaned["transportProtocol"], "TCP")
        self.assertEqual(cleaned["targetIpv6Snapshot"], payload["targetIpv6Snapshot"])

    def test_portmap_udp_is_persisted_and_shares_port_only_with_tcp(self):
        udp = hub._clean_portmap_rule({
            "id": "map-udp", "name": "UDP", "enabled": True, "mode": "6to4",
            "listenPort": 20000, "targetMode": "ipv4", "targetIpv4": "192.168.5.46",
            "targetPort": 53, "transportProtocol": "UDP",
        })
        tcp = hub._clean_portmap_rule({
            "id": "map-tcp", "name": "TCP", "enabled": True, "mode": "6to4",
            "listenPort": 20000, "targetMode": "ipv4", "targetIpv4": "192.168.5.46",
            "targetPort": 53, "transportProtocol": "TCP",
        })
        self.assertEqual(udp["transportProtocol"], "UDP")
        hub._portmap_check_conflict([udp], tcp)
        with self.assertRaises(ValueError):
            hub._portmap_check_conflict([udp], {**udp, "id": "map-udp-2"})

    def test_portmap_udp_rule_survives_hub_document_reload(self):
        udp = hub._clean_portmap_rule({
            "id": "map-udp-reload", "name": "UDP reload", "enabled": True, "mode": "6to6",
            "listenPort": 20000, "targetMode": "ipv6_full", "targetIpv6": "2001:db8::53",
            "targetPort": 53, "transportProtocol": "UDP",
        })
        # The storage layer intentionally permits documents only below DATA_DIR.
        path = hub.DATA_DIR / "udp-portmaps-reload.json"
        with patch.object(hub, "PORTMAP_RULES_FILE", path):
            hub._save_portmap_rules([udp])
            document, loaded = hub._load_portmap_rules_document()
        self.assertTrue(loaded)
        self.assertEqual(document["rules"][0]["transportProtocol"], "UDP")

    def test_malformed_portmap_document_is_not_an_authoritative_empty_set(self):
        original = hub.PORTMAP_RULES_FILE.read_bytes() if hub.PORTMAP_RULES_FILE.exists() else None
        try:
            hub.PORTMAP_RULES_FILE.write_text("{malformed", encoding="utf-8")
            document, loaded = hub._load_portmap_rules_document()
            self.assertFalse(loaded)
            self.assertEqual(document["rules"], [])
        finally:
            if original is None:
                hub.PORTMAP_RULES_FILE.unlink(missing_ok=True)
            else:
                hub.PORTMAP_RULES_FILE.write_bytes(original)

    def test_malformed_portmap_document_never_queues_router_rule_deletion(self):
        original = hub.PORTMAP_RULES_FILE.read_bytes() if hub.PORTMAP_RULES_FILE.exists() else None
        queued = []
        try:
            hub.PORTMAP_RULES_FILE.write_text("{malformed", encoding="utf-8")
            with patch.object(hub, "check_hook_token", return_value=True), patch.object(
                hub, "_queue_portmap_command", side_effect=lambda *args, **kwargs: queued.append((args, kwargs))
            ):
                with hub.app.test_request_context(
                    "/api/router/portmaps/status",
                    method="POST",
                    json={"rules": [{"rule": {"id": "router-only"}, "runtime": {"id": "router-only"}}]},
                ):
                    response = hub.api_router_portmap_status()
            self.assertEqual(response.status_code, 200)
            self.assertEqual(queued, [])
        finally:
            if original is None:
                hub.PORTMAP_RULES_FILE.unlink(missing_ok=True)
            else:
                hub.PORTMAP_RULES_FILE.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
