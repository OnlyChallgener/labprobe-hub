import json
import tempfile
import unittest
from pathlib import Path

from labprobe_storage import SQLiteStore


class SQLiteMigrationTests(unittest.TestCase):
    def test_json_migration_backup_revision_and_pairing(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            data = base / "data"
            backups = base / "backups"
            (data / "notes").mkdir(parents=True)
            fixtures = {
                "devices.json": {"online": [{"mac": "02:00:00:00:00:01", "online": True}], "watched": []},
                "events.json": [{"id": 1, "type": "device_online"}],
                "portmaps.json": {"rules": [{"id": "web", "listenPort": 20001}]},
                "settings.json": {"keep": True},
                "notes/2026-07-17.json": {"date": "2026-07-17", "note": "保留备注"},
            }
            for name, value in fixtures.items():
                path = data / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

            store = SQLiteStore(data, backups)
            result = store.initialize()
            self.assertEqual(result["status"], "migrated")
            self.assertEqual(result["documents"], len(fixtures))
            for name, value in fixtures.items():
                self.assertEqual(store.load(data / name, None), value)
                self.assertTrue((Path(result["backup"]) / name).exists())

            updated = {"online": [], "watched": [{"mac": "02:00:00:00:00:01", "online": False}]}
            revision = store.save(data / "devices.json", updated)
            self.assertGreater(revision, 0)
            delta = store.changes_since(0)
            self.assertFalse(delta["fullRequired"])
            self.assertTrue(any(change["entity"] == "device" for change in delta["changes"]))

            code = store.create_pairing_code("app", 600)
            paired = store.exchange_pairing_code(code, "app", "test phone", "127.0.0.1")
            self.assertTrue(paired["clientToken"].startswith("lp_"))
            self.assertTrue(store.authenticate(paired["clientToken"], {"app"}))
            with self.assertRaises(PermissionError):
                store.exchange_pairing_code(code, "app", "second phone", "127.0.0.2")


if __name__ == "__main__":
    unittest.main()
