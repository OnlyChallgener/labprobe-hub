import tempfile
import unittest
from pathlib import Path

import labprobe_storage
from labprobe_storage import SQLiteStore


class SQLiteRetentionTests(unittest.TestCase):
    def make_store(self):
        temp = tempfile.TemporaryDirectory()
        base = Path(temp.name)
        store = SQLiteStore(base / "data", base / "backups")
        store.initialize()
        return temp, store, base / "data"

    def revision_count(self, store):
        with store.connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM revisions").fetchone()[0])

    def test_runtime_documents_do_not_create_revisions(self):
        temp, store, data = self.make_store()
        self.addCleanup(temp.cleanup)
        baseline = self.revision_count(store)
        for idx in range(5):
            store.save(data / "device_archive.json", {"mac": {"rssi": -40 - idx}})
            store.save(data / "portmap_history.json", {"rule": [{"time": idx}]})
            store.save(data / "router_dashboard.json", {"cpu": idx})
        self.assertEqual(self.revision_count(store), baseline)
        self.assertEqual(store.load(data / "router_dashboard.json", {}), {"cpu": 4})

    def test_device_metrics_do_not_create_revisions_but_identity_changes_do(self):
        temp, store, data = self.make_store()
        self.addCleanup(temp.cleanup)
        first = {
            "onlineDeviceCount": 1,
            "total": 1,
            "online": [{"mac": "02:00:00:00:00:01", "ip": "192.168.1.2", "rssi": -40, "dailyDown": 100}],
            "watched": [],
        }
        store.save(data / "devices.json", first)
        after_first = self.revision_count(store)
        metrics_only = {
            **first,
            "online": [{"mac": "02:00:00:00:00:01", "ip": "192.168.1.2", "rssi": -65, "dailyDown": 9999}],
        }
        store.save(data / "devices.json", metrics_only)
        self.assertEqual(self.revision_count(store), after_first)
        changed_ip = {
            **metrics_only,
            "online": [{"mac": "02:00:00:00:00:01", "ip": "192.168.1.3", "rssi": -65, "dailyDown": 9999}],
        }
        store.save(data / "devices.json", changed_ip)
        self.assertEqual(self.revision_count(store), after_first + 1)

    def test_status_timestamps_and_embedded_device_metrics_do_not_create_revisions(self):
        temp, store, data = self.make_store()
        self.addCleanup(temp.cleanup)
        first = {
            "updatedAt": "2026-07-20 10:00:00",
            "router": {"wanIpv6": "2400::1", "devicesUpdatedAt": "2026-07-20 10:00:00"},
            "devices": [{"mac": "02:00:00:00:00:01", "rssi": -40, "dailyDown": 100}],
        }
        store.save(data / "state.json", first)
        after_first = self.revision_count(store)
        metrics_only = {
            "updatedAt": "2026-07-20 10:01:00",
            "router": {"wanIpv6": "2400::1", "devicesUpdatedAt": "2026-07-20 10:01:00"},
            "devices": [{"mac": "02:00:00:00:00:01", "rssi": -70, "dailyDown": 10000}],
        }
        store.save(data / "state.json", metrics_only)
        self.assertEqual(self.revision_count(store), after_first)
        changed_address = {
            **metrics_only,
            "router": {"wanIpv6": "2400::2", "devicesUpdatedAt": "2026-07-20 10:02:00"},
        }
        store.save(data / "state.json", changed_address)
        self.assertEqual(self.revision_count(store), after_first + 1)

    def test_revision_row_cap_requests_full_sync_for_old_cursor(self):
        temp, store, data = self.make_store()
        self.addCleanup(temp.cleanup)
        old_max = labprobe_storage.REVISION_MAX_ROWS
        old_interval = labprobe_storage.REVISION_PRUNE_INTERVAL_SEC
        labprobe_storage.REVISION_MAX_ROWS = 500
        labprobe_storage.REVISION_PRUNE_INTERVAL_SEC = 30
        try:
            for idx in range(620):
                store.save(data / "settings.json", {"value": idx})
            with store.connect() as conn:
                store._prune_revisions(conn, force=True)
            info = store.revision_info()
            self.assertLessEqual(info["revision"] - info["oldestRevision"] + 1, 500)
            self.assertTrue(store.changes_since(0)["fullRequired"])
            self.assertFalse(store.changes_since(info["oldestRevision"] - 1)["fullRequired"])
        finally:
            labprobe_storage.REVISION_MAX_ROWS = old_max
            labprobe_storage.REVISION_PRUNE_INTERVAL_SEC = old_interval


if __name__ == "__main__":
    unittest.main()
