import os
import tempfile
import unittest
from pathlib import Path


TEST_ROOT = tempfile.mkdtemp(prefix="labprobe-dashboard-test-")
os.environ["DATA_DIR"] = str(Path(TEST_ROOT) / "data")
os.environ["CONFIG_DIR"] = str(Path(TEST_ROOT) / "config")
os.environ["BACKUPS_DIR"] = str(Path(TEST_ROOT) / "backups")
os.environ["LOGS_DIR"] = str(Path(TEST_ROOT) / "logs")
os.environ["CONFIG_PATH"] = str(Path(TEST_ROOT) / "config" / "config.yaml")
os.environ["APP_TOKEN"] = "test-app-token"
os.environ["HOOK_TOKEN"] = "test-hook-token"
os.environ.pop("MQTT_PASSWORD", None)

import hub  # noqa: E402


class RouterDashboardApiTests(unittest.TestCase):
    def setUp(self):
        self.client = hub.app.test_client()
        with hub.ROUTER_DASHBOARD_LOCK:
            hub.ROUTER_DASHBOARD_CACHE.clear()
            hub.ROUTER_DASHBOARD_REFRESH_NONCE = 0

    def test_push_read_and_refresh(self):
        pushed = self.client.post(
            "/api/router/dashboard/push",
            headers={"X-LabProbe-Token": "test-hook-token"},
            json={
                "router": "BE72",
                "telemetry": {"cpuPercent": 4, "onlineDeviceCount": 9},
                "details": {"wan": {"ipv4": "10.0.0.2"}, "ports": []},
            },
        )
        self.assertEqual(pushed.status_code, 200)

        read = self.client.get(
            "/api/router/dashboard",
            headers={"Authorization": "Bearer test-app-token"},
        )
        self.assertEqual(read.status_code, 200)
        body = read.get_json()
        self.assertEqual(body["router"], "BE72")
        self.assertEqual(body["telemetry"]["onlineDeviceCount"], 9)
        self.assertEqual(body["details"]["wan"]["ipv4"], "10.0.0.2")

        refresh = self.client.post(
            "/api/router/dashboard/refresh",
            headers={"Authorization": "Bearer test-app-token"},
            json={},
        )
        self.assertEqual(refresh.status_code, 200)
        self.assertEqual(refresh.get_json()["refreshNonce"], 1)

        ack = self.client.post(
            "/api/router/dashboard/push",
            headers={"X-LabProbe-Token": "test-hook-token"},
            json={"router": "BE72", "telemetry": {"cpuPercent": 5}, "refreshNonce": 1},
        )
        self.assertEqual(ack.status_code, 200)
        body = self.client.get(
            "/api/router/dashboard",
            headers={"Authorization": "Bearer test-app-token"},
        ).get_json()
        self.assertEqual(body["refreshCompletedNonce"], 1)

    def test_wrong_token_rejected(self):
        response = self.client.post(
            "/api/router/dashboard/push",
            headers={"X-LabProbe-Token": "wrong"},
            json={"telemetry": {}},
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
