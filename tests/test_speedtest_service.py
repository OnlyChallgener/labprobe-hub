"""Speed test transport contract tests.

Every firmware payload used here was copied verbatim from a live EW7200 (BE72)
`devSta.get` call on 2026-09-17, so the normalizers are pinned to real wire
data rather than to an imagined schema.

Run:  python -m pytest tests/test_speedtest_service.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import speedtest_service as st  # noqa: E402


# --------------------------------------------------------------------------- #
# verbatim live payloads
# --------------------------------------------------------------------------- #

PORT_STATUS = {
    "count": "9",
    "List": [
        {"duplex": "half", "portId": "1", "ipaddr": "192.168.5.1", "port_type": "NORMAL",
         "poe_direct": "none", "name": "LAN", "status": "off", "panel_name": "LAN6/IPTV",
         "poe_enable": "0", "speed": "0"},
        {"duplex": "full", "portId": "5", "ipaddr": "192.168.1.2", "port_type": "NORMAL",
         "poe_direct": "none", "name": "WAN", "status": "on", "panel_name": "WAN",
         "poe_enable": "0", "speed": "2500"},
        {"duplex": "full", "portId": "6", "ipaddr": "192.168.5.1", "port_type": "NORMAL",
         "poe_direct": "none", "name": "LAN", "status": "on", "panel_name": "LAN2/WAN1",
         "poe_enable": "0", "speed": "2500"},
        {"duplex": "full", "portId": "7", "ipaddr": "192.168.5.1", "port_type": "NORMAL",
         "poe_direct": "none", "name": "LAN", "status": "on", "panel_name": "LAN3",
         "poe_enable": "0", "speed": "100"},
    ],
}

CUR_INTF_RST = {
    "intf": ["wan"],
    "stat": "running",
    "error_code": "0",
    "tmp_rst": {
        "wan": {
            "latency": "1.68", "jitter": "0.23", "loss": "0.00",
            "downspeed": ["1559.21", "912.84", "585.47", "577.03"],
            "upspeed": ["116.49", "81.90", "95.55", "83.66"],
        }
    },
}

HIS_RST = {
    "his_rst": [
        {"timestamp": "1789637285", "intf": ["wan"],
         "tmp_rst": {"wan": {"latency": "1.68", "jitter": "0.23", "downspeed": "587.07",
                             "upspeed": "49.23", "loss": "0.00", "result": ""}}},
        {"timestamp": "1783818657", "intf": ["wan"],
         "tmp_rst": {"wan": {"latency": "1.68", "jitter": "0.11", "downspeed": "580.69",
                             "upspeed": "48.91", "loss": "0.00", "result": ""}}},
    ]
}

SERVERS = {
    "error_code": "0", "msg": "success",
    "servers": [{"id": "308000101", "name": "衡阳移动"}, {"id": "301000101", "name": "长沙移动"}],
}

PROC_STAT = {"get_proc_stat": "0"}


# --------------------------------------------------------------------------- #
# normalizers
# --------------------------------------------------------------------------- #

def test_ports_marks_only_live_wan_testable():
    data = st.normalize_ports(PORT_STATUS)
    assert data["total"] == 4
    assert data["testable"] == ["wan"]
    wan = next(p for p in data["ports"] if p["name"] == "WAN")
    assert wan["up"] is True and wan["speedMbps"] == 2500
    assert wan["panelName"] == "WAN" and wan["ipAddress"] == "192.168.1.2"
    lan = next(p for p in data["ports"] if p["portId"] == "6")
    # A 2.5G live LAN port must stay untestable - only WAN rows feed set_nodes.
    assert lan["up"] is True and lan["testable"] is False


def test_progress_keeps_sample_arrays_and_reads_last_value():
    data = st.normalize_progress(CUR_INTF_RST)
    assert data["stat"] == "running" and data["running"] is True and data["finished"] is False
    primary = data["primary"]
    assert primary["intf"] == "wan"
    assert primary["latency"] == 1.68 and primary["jitter"] == 0.23 and primary["loss"] == 0.0
    assert primary["downspeed"] == [1559.21, 912.84, 585.47, 577.03]
    assert primary["currentDown"] == 577.03
    assert primary["peakDown"] == 1559.21
    assert primary["currentUp"] == 83.66


def test_progress_end_state_is_recognized():
    payload = dict(CUR_INTF_RST)
    payload["stat"] = "end"
    data = st.normalize_progress(payload)
    assert data["finished"] is True and data["running"] is False


def test_progress_unknown_stat_degrades_to_idle():
    payload = dict(CUR_INTF_RST)
    payload["stat"] = ""
    assert st.normalize_progress(payload)["stat"] == "idle"


def test_history_scalar_speeds_do_not_leak_array_semantics():
    data = st.normalize_history(HIS_RST)
    assert data["total"] == 2
    first = data["records"][0]
    # newest-first ordering by epoch
    assert first["epoch"] == 1789637285
    primary = first["primary"]
    assert primary["downspeed"] == [] and primary["upspeed"] == []
    assert primary["currentDown"] == 587.07 and primary["currentUp"] == 49.23
    assert primary["peakDown"] is None


def test_history_rejects_bogus_timestamps():
    payload = {"his_rst": [{"timestamp": "12", "intf": ["wan"],
                            "tmp_rst": {"wan": {"downspeed": "1.00", "upspeed": "1.00"}}}]}
    data = st.normalize_history(payload)
    assert data["records"][0]["epoch"] == 0


def test_servers_and_state():
    servers = st.normalize_servers(SERVERS)
    assert servers["total"] == 2
    assert servers["servers"][0] == {"id": "308000101", "name": "衡阳移动"}
    assert st.normalize_state(PROC_STAT) == {"procState": "0", "running": False}
    assert st.normalize_state({"get_proc_stat": "1"})["running"] is True


def test_numeric_noise_becomes_none_instead_of_crashing():
    payload = {"intf": ["wan"], "stat": "running", "error_code": "0",
               "tmp_rst": {"wan": {"latency": "nan", "jitter": "inf", "loss": "--",
                                   "downspeed": ["3.5", "bad", "", None], "upspeed": []}}}
    primary = st.normalize_progress(payload)["primary"]
    assert primary["latency"] is None and primary["jitter"] is None and primary["loss"] is None
    assert primary["downspeed"] == [3.5]


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #

def test_clean_interfaces_defaults_and_validates():
    assert st.clean_interfaces(None) == ["wan"]
    assert st.clean_interfaces(["WAN"]) == ["wan"]
    assert st.clean_interfaces(["wan", "wan", "wan1"]) == ["wan", "wan1"]
    with pytest.raises(st.SpeedTestError) as error:
        st.clean_interfaces(["eth0"])
    assert error.value.status == 400
    with pytest.raises(st.SpeedTestError):
        st.clean_interfaces([])


def test_clean_nodes_defaults_to_auto_and_rejects_unknown_intf():
    assert st.clean_nodes(None, ["wan"]) == {}
    assert st.clean_nodes({"wan": "308000101"}, ["wan"]) == {"wan": ["308000101"]}
    assert st.clean_nodes({"wan": "308000101", "wan1": "1"}, ["wan"]) == {"wan": ["308000101"]}
    assert st.clean_nodes({"wan": ""}, ["wan"]) == {"wan": ["0"]}
    with pytest.raises(st.SpeedTestError):
        st.clean_nodes({"wan": "../etc/passwd"}, ["wan"])


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #

class FakeDriver:
    """Records the exact RPC the blueprint issues."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def rpc(self, method, module="", data=None, no_parse=False, params=None, **kwargs):
        self.calls.append({"method": method, "module": module, "data": data})
        if isinstance(data, dict) and data.get("type") in self.responses:
            return self.responses[data["type"]]
        if "port_status" in self.responses and (data is None):
            return self.responses["port_status"]
        return {"error_code": "0"}


class FakeHub:
    LOGGER = None

    def __init__(self, driver):
        self.ROUTER_DRIVER = driver
        self.app = Flask(__name__)

    @staticmethod
    def check_app_token():
        return True


def build_client(responses):
    driver = FakeDriver(responses)
    hub = FakeHub(driver)
    st.install_speedtest_service(hub)
    return hub.app.test_client(), driver


def test_ports_route_passes_port_status_with_no_data():
    client, driver = build_client({"port_status": PORT_STATUS})
    body = client.get("/api/router/speedtest/ports").get_json()
    assert body["ok"] is True and body["data"]["testable"] == ["wan"]
    # Regression guard: port_status lives in its own dev_sta module. Sending it
    # under `speedtest` makes the firmware answer without a `List` key, which
    # silently produced an empty port list on the live device.
    assert driver.calls[0]["module"] == "port_status"
    assert driver.calls[0]["data"] is None


def test_start_route_builds_firmware_set_nodes_shape():
    client, driver = build_client({})
    response = client.post("/api/router/speedtest/start",
                           json={"intf": ["wan"], "nodes": {"wan": "308000101"}})
    assert response.status_code == 202
    assert response.get_json()["ok"] is True
    sent = driver.calls[-1]["data"]
    assert sent == {"type": "start_test", "intf": ["wan"],
                    "set_nodes": {"wan": ["308000101"]}}


def test_start_route_defaults_to_auto_node():
    client, driver = build_client({})
    client.post("/api/router/speedtest/start", json={"intf": ["wan"]})
    assert driver.calls[-1]["data"]["set_nodes"] == {"wan": ["0"]}


def test_start_route_reports_router_rejection_as_409():
    client, _ = build_client({"start_test": {"error_code": "1"}})
    response = client.post("/api/router/speedtest/start", json={"intf": ["wan"]})
    assert response.status_code == 409
    assert response.get_json()["error"] == "router_rejected"


def test_a_second_start_while_testing_is_not_reported_as_a_failure():
    """重复点「开始测速」时固件会拒第二次（error_code != 0）。路由器本来就在测，
    界面不该弹「未能启动测速」—— 实测 2026-09-22 09:14:15 同一秒 202 + 409。"""
    client, driver = build_client({"get_proc_stat": {"get_proc_stat": "1"},
                                   "start_test": {"error_code": "1"}})
    response = client.post("/api/router/speedtest/start", json={"intf": ["wan"]})
    assert response.status_code == 202
    body = response.get_json()
    assert body["ok"] is True and body["data"]["alreadyRunning"] is True
    assert [call["data"] for call in driver.calls] == [{"type": "get_proc_stat"}], \
        "路由器已经在测，就不该再发 start_test"


def test_start_route_rejects_bad_intf_without_touching_router():
    client, driver = build_client({})
    response = client.post("/api/router/speedtest/start", json={"intf": ["eth0"]})
    assert response.status_code == 400
    assert driver.calls == []


def test_progress_and_history_routes():
    client, _ = build_client({"get_cur_intf_rst": CUR_INTF_RST, "get_his_rst": HIS_RST})
    progress = client.get("/api/router/speedtest/progress").get_json()["data"]
    assert progress["primary"]["currentDown"] == 577.03
    history = client.get("/api/router/speedtest/history").get_json()["data"]
    assert history["records"][0]["primary"]["currentDown"] == 587.07


def test_missing_driver_returns_503():
    hub = FakeHub(None)
    st.install_speedtest_service(hub)
    response = hub.app.test_client().get("/api/router/speedtest/ports")
    assert response.status_code == 503
    assert response.get_json()["error"] == "router_unavailable"


def test_unauthorized_is_rejected():
    driver = FakeDriver({})
    hub = FakeHub(driver)
    hub.check_app_token = staticmethod(lambda: False)
    st.install_speedtest_service(hub)
    assert hub.app.test_client().get("/api/router/speedtest/ports").status_code == 401
