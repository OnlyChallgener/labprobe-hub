import tempfile
import unittest
from pathlib import Path

from labprobe_storage import SQLiteStore
from tools.repair_device_history import repair


class DeviceHistoryRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.store = SQLiteStore(root / "be72", root / "backups")
        self.store.initialize()
        self.native = {"mac": "01:02:03:04:05:06", "lastIp": "192.168.5.20", "lastSeenAt": "2026-09-28 10:00:00"}
        self.foreign = {"mac": self.native["mac"], "lastIp": "192.168.110.20", "lastSeenAt": "2026-09-28 09:00:00"}
        self.plan = {"routerSerial": "be72-sn", "observations": [{"mac": self.native["mac"], "address": "192.168.110.20", "day": "2026-09-28"}]}
        self.store.save(self.store.data_dir / "router_dashboard.json", {"details": {"identity": {"serialNumber": "be72-sn"}}})
        self.store.save(self.store.data_dir / "device_archive.json", {self.native["mac"]: self.foreign, "other": {"mac": "other", "lastIp": "192.168.5.3"}})
        self.store.save(self.store.data_dir / "events.json", [
            {"id": 1, **self.foreign, "time": "2026-09-28 09:00:00"},
            {"id": 2, **self.native, "time": "2026-09-28 10:00:00"},
            {"id": 3, **self.foreign, "time": "2026-09-29 10:00:00"},
        ])
        self.store.save(self.store.data_dir / "daily.json", {"days": {"2026-09-28": {"devices": {self.native["mac"]: self.foreign}}, "2026-09-29": {"devices": {self.native["mac"]: self.foreign}}}})

    def test_dry_run_preserves_documents(self):
        before = self.store.load(self.store.data_dir / "events.json", [])
        self.assertEqual(repair(self.store, self.plan), {"applied": False, "archive": 1, "events": 1, "dailyRows": 1})
        self.assertEqual(self.store.load(self.store.data_dir / "events.json", []), before)

    def test_repair_is_scoped_backed_up_and_invalidates_cached_clients(self):
        cursor = self.store.revision_info()["revision"]
        result = repair(self.store, self.plan, apply=True)
        self.assertTrue(result["applied"])
        self.assertEqual((result["archive"], result["events"], result["dailyRows"]), (1, 1, 1))
        self.assertTrue((Path(result["backup"]) / "labprobe-before.db").is_file())
        self.assertTrue((Path(result["backup"]) / "quarantine.json").is_file())
        events = self.store.load(self.store.data_dir / "events.json", [])
        self.assertEqual([row["id"] for row in events], [2, 3])
        self.assertTrue(self.store.changes_since(cursor)["fullRequired"])
        self.assertFalse(repair(self.store, self.plan, apply=True)["applied"])

    def test_another_router_serial_is_rejected_without_changes(self):
        before = self.store.revision_info()["revision"]
        with self.assertRaisesRegex(ValueError, "serial"):
            repair(self.store, {**self.plan, "routerSerial": "be50-sn"}, apply=True)
        self.assertEqual(self.store.revision_info()["revision"], before)

    def test_reconnection_with_same_mac_preserves_native_archive(self):
        self.store.save(self.store.data_dir / "device_archive.json", {self.native["mac"]: self.native})
        result = repair(self.store, self.plan, apply=True)
        self.assertEqual(result["archive"], 0)
        self.assertEqual(self.store.load(self.store.data_dir / "device_archive.json", {})[self.native["mac"]], self.native)

    def test_still_online_observation_is_not_deleted(self):
        self.store.save(self.store.data_dir / "devices.json", {"online": [self.foreign]})
        with self.assertRaisesRegex(ValueError, "still online"):
            repair(self.store, self.plan, apply=True)


if __name__ == "__main__":
    unittest.main()
