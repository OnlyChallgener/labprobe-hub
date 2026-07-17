import os
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
