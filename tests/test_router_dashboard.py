import os
import tempfile
import unittest
from unittest import mock
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
        with hub.ROUTER_CREDENTIALS_LOCK:
            hub.ROUTER_CREDENTIALS_CACHE.clear()
            hub.ROUTER_CREDENTIALS_REFRESH_NONCE = 1000

    def test_push_read_and_refresh(self):
        with mock.patch.object(hub, "_cached_hub_exit_ipv4", return_value=""), \
             mock.patch.object(hub, "_schedule_dashboard_operator_probe", return_value=None):
            pushed = self.client.post(
                "/api/router/dashboard/push",
                headers={"X-LabProbe-Token": "test-hook-token"},
                json={
                    "router": "BE72",
                    "telemetry": {
                        "cpuPercent": 4,
                        "storagePercent": 37.5,
                        "onlineDeviceCount": 9,
                        "wan": {
                            "uploadBps": 8442450,
                            "downloadBps": 5016360,
                            "totalUploadBytes": 30749142999,
                            "totalDownloadBytes": 78239897230,
                        },
                        "connections": {"ipv4": 151, "ipv6": 60},
                    },
                    "details": {
                        "wan": {"ipv4": "10.0.0.2", "dnsServers": ["111.8.14.18", "211.142.211.124"]},
                        "ap": {
                            "workMode": "ROUTER",
                            "relayMode": "none",
                            "channelUtilization": ["56", "8"],
                        },
                        "ports": [],
                    },
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
        self.assertEqual(body["telemetry"]["storagePercent"], 37.5)
        self.assertEqual(body["telemetry"]["connections"]["ipv4"], 151)
        self.assertEqual(body["telemetry"]["connections"]["ipv6"], 60)
        self.assertEqual(body["telemetry"]["wan"]["totalUploadBytes"], 30749142999)
        self.assertEqual(body["telemetry"]["wan"]["totalDownloadBytes"], 78239897230)
        self.assertEqual(body["details"]["wan"]["ipv4"], "10.0.0.2")
        self.assertEqual(body["details"]["wan"]["dnsServers"], ["111.8.14.18", "211.142.211.124"])
        self.assertEqual(body["details"]["ap"]["workMode"], "ROUTER")
        self.assertEqual(body["details"]["ap"]["channelUtilization"], ["56", "8"])

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



    def test_operator_uses_hub_public_ipv4(self):
        with mock.patch.object(hub, "_cached_hub_exit_ipv4", return_value="8.8.8.8"), \
             mock.patch.object(hub, "_operator_for_dashboard_ip", return_value="测试运营商"):
            pushed = self.client.post(
                "/api/router/dashboard/push",
                headers={"X-LabProbe-Token": "test-hook-token"},
                json={
                    "router": "BE72",
                    "details": {"wan": {"ipv4": "10.87.180.102", "operator": "路由器上报值"}},
                },
            )
        self.assertEqual(pushed.status_code, 200)
        body = self.client.get(
            "/api/router/dashboard",
            headers={"Authorization": "Bearer test-app-token"},
        ).get_json()
        wan = body["details"]["wan"]
        self.assertEqual(wan["ipv4"], "10.87.180.102")
        self.assertEqual(wan["publicIpv4"], "8.8.8.8")
        self.assertEqual(wan["operatorCheckedIp"], "8.8.8.8")
        self.assertEqual(wan["operator"], "测试运营商")

    def test_credentials_are_memory_only_and_expire(self):
        refresh = self.client.post(
            "/api/router/dashboard/credentials/refresh",
            headers={"Authorization": "Bearer test-app-token"},
            json={},
        )
        self.assertEqual(refresh.status_code, 200)
        self.assertEqual(refresh.get_json()["refreshNonce"], 1001)

        push = self.client.post(
            "/api/router/dashboard/credentials/push",
            headers={"X-LabProbe-Token": "test-hook-token"},
            json={
                "router": "BE72",
                "lanMac": "00:11:22:33:44:55",
                "username": "pppoe-user",
                "password": "pppoe-pass",
                "refreshNonce": 1001,
            },
        )
        self.assertEqual(push.status_code, 200)

        read = self.client.get(
            "/api/router/dashboard/credentials",
            headers={"Authorization": "Bearer test-app-token"},
        )
        body = read.get_json()
        self.assertFalse(body["stale"])
        self.assertEqual(body["username"], "pppoe-user")
        self.assertEqual(body["password"], "pppoe-pass")
        self.assertEqual(body["refreshCompletedNonce"], 1001)
        self.assertNotIn("username", hub.ROUTER_DASHBOARD_CACHE)


    def test_agent_cleanup_command_round_trip(self):
        hub.save_json(hub.AGENT_UPDATE_COMMANDS_FILE, {"commands": []})
        created = self.client.post(
            "/api/agent/cleanup",
            headers={"Authorization": "Bearer test-app-token"},
            json={},
        )
        self.assertEqual(created.status_code, 200)
        created_body = created.get_json()
        command_id = created_body["commandId"]
        router = created_body["router"]

        pending = self.client.get(
            f"/api/router/agent/commands?router={router}",
            headers={"X-LabProbe-Token": "test-hook-token"},
        )
        self.assertEqual(pending.status_code, 200)
        self.assertEqual(pending.get_json()["commands"][0]["action"], "cleanup")

        acknowledged = self.client.post(
            "/api/router/agent/ack",
            headers={"X-LabProbe-Token": "test-hook-token"},
            json={
                "id": command_id,
                "state": "completed",
                "message": "清理完成，回收 12.0 KB",
                "result": {
                    "cleanedItems": [{"name": "Agent 备份", "count": 2, "bytes": 12288}],
                    "reclaimedBytes": 12288,
                    "reclaimedText": "12.0 KB",
                    "errors": [],
                },
            },
        )
        self.assertEqual(acknowledged.status_code, 200)
        self.assertTrue(acknowledged.get_json()["acknowledged"])

        status = self.client.get(
            f"/api/agent/cleanup/status?commandId={command_id}",
            headers={"Authorization": "Bearer test-app-token"},
        )
        self.assertEqual(status.status_code, 200)
        status_body = status.get_json()
        self.assertEqual(status_body["state"], "completed")
        self.assertEqual(status_body["reclaimedBytes"], 12288)
        self.assertEqual(status_body["cleanedItems"][0]["name"], "Agent 备份")

    def test_wrong_token_rejected(self):
        response = self.client.post(
            "/api/router/dashboard/push",
            headers={"X-LabProbe-Token": "wrong"},
            json={"telemetry": {}},
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
