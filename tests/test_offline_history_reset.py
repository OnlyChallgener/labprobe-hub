import tempfile
import unittest
from pathlib import Path

from labprobe_storage import SQLiteStore


class OfflineHistoryResetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name) / "data"
        self.store = SQLiteStore(self.data, Path(self.temp.name) / "backups")
        self.store.initialize()

    def test_archive_repair_requires_full_snapshot_for_cached_clients(self):
        archive = self.data / "device_archive.json"
        native = {"mac": "00:00:00:00:00:01", "lastIp": "192.168.5.2"}
        foreign = {"mac": "00:00:00:00:00:02", "lastIp": "192.168.110.2"}
        self.store.save(archive, {native["mac"]: native, foreign["mac"]: foreign})
        cursor = self.store.revision_info()["revision"]
        self.store.save(archive, {native["mac"]: native})
        result = self.store.changes_since(cursor)
        self.assertTrue(result["fullRequired"])
        self.assertEqual(result["changes"], [])
        self.assertEqual(self.store.load(archive, {}), {native["mac"]: native})
        # The new snapshot acknowledges the boundary; later edits use deltas.
        current = self.store.revision_info()["revision"]
        self.store.save(self.data / "settings.json", {"updated": True})
        delta = self.store.changes_since(current)
        self.assertFalse(delta["fullRequired"])
        self.assertEqual(len(delta["changes"]), 1)

    def test_reset_beyond_first_page_still_requires_full_snapshot(self):
        archive = self.data / "device_archive.json"
        self.store.save(archive, {"old": {"mac": "old"}})
        cursor = self.store.revision_info()["revision"]
        for value in range(4):
            self.store.save(self.data / "settings.json", {"value": value})
        self.store.save(archive, {})
        self.assertTrue(self.store.changes_since(cursor, limit=1)["fullRequired"])

    def test_metrics_and_new_members_do_not_trigger_full_snapshots(self):
        archive = self.data / "device_archive.json"
        cursor = self.store.revision_info()["revision"]
        self.store.save(archive, {"mac": {"rssi": -40, "lastSeenAt": "first"}})
        self.store.save(archive, {"mac": {"rssi": -70, "lastSeenAt": "second"}, "new": {"rssi": -30}})
        self.assertEqual(self.store.revision_info()["revision"], cursor)
        self.assertFalse(self.store.changes_since(cursor)["fullRequired"])


if __name__ == "__main__":
    unittest.main()
