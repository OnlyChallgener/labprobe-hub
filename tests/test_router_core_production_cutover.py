import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import hub
import hub_entry

from router_core.driver.reyee import ReyeeEWebDriver
from router_core.driver.reyee_rpc import ReyeeRpcClient
from router_ws_patch import RouterWebSocketMonitor


def test_production_url_map_is_owned_by_router_core():
    adapter = hub.app.url_map.bind("localhost")
    expected = {
        ("GET", "/api/router/dashboard"): "router_core_api.get_dashboard",
        ("POST", "/api/router/dashboard/refresh"): "router_core_api.refresh_dashboard",
        ("GET", "/api/router/realtime"): "router_core_api.get_realtime_calibration",
        ("GET", "/api/router/status"): "router_core_api.get_status",
        ("GET", "/api/router/ipv6/status"): "router_core_api.get_ipv6_status",
        ("GET", "/api/router/port-mapping"): "router_core_api.get_port_mapping",
        ("GET", "/api/router/tasks/nat"): "router_core_api.get_task",
    }
    for (method, path), endpoint in expected.items():
        assert adapter.match(path, method=method)[0] == endpoint

    assert hub.ROUTER_RPC_COMPAT_SYNC.client is hub.ROUTER_DRIVER
    assert hub.ROUTER_RPC_COMPAT_SYNC.primary is True
    assert hub.ROUTER_TASK_MANAGER.client is hub.ROUTER_DRIVER


def test_be72_monitor_to_core_to_hub_wss_first_frame():
    websocket = hub.HUB_REALTIME_WEBSOCKET
    client = websocket._register()
    try:
        monitor = RouterWebSocketMonitor(
            hub.ROUTER_DRIVER,
            SimpleNamespace(
                info=lambda *_args, **_kwargs: None,
                warning=lambda *_args, **_kwargs: None,
                debug=lambda *_args, **_kwargs: None,
            ),
        )
        monitor.set_fast_handler(hub.ROUTER_REALTIME.accept_router_fast)
        epoch_before = int(time.time() * 1000)
        monitor._dispatch_message({
            "type": "fast",
            "data": {
                "cpu_usage": 11.5,
                "memutil": 22,
                "wan_stat": {"wans": {"up": 1234, "down": 5678}},
            },
        })

        frame = json.loads(client.frames.get(timeout=0.5))
        assert frame["type"] == "router"
        assert frame["data"]["uploadBps"] == 1234
        assert frame["data"]["downloadBps"] == 5678
        assert frame["data"]["cpuPercent"] == 11.5
        assert frame["data"]["sampleEpochMs"] >= epoch_before
        assert frame["data"]["source"] == "router_eweb_ws_fast"
    finally:
        websocket._unregister(client)


def test_native_driver_uses_production_module_envelopes():
    rpc = MagicMock(spec=ReyeeRpcClient)
    rpc.session_manager = MagicMock()
    rpc.session_manager.address = "http://192.168.5.1"
    rpc.session_manager.password = "secret"
    rpc.session_manager.is_valid.return_value = True

    def rpc_result(*, method, module, data=None, no_parse=False, params=None, **_kwargs):
        if (method, module) == ("devSta.get", "user_list"):
            return {"list": [{"mac": "AA-BB", "userIp": "192.168.5.20", "flowUp": 1, "flowDown": 2}]}
        if (method, module) == ("devConfig.get", "port_mapping"):
            return {"portMapping": [{"ruleName": "ssh"}]}
        if (method, module) == ("devSta.get", "upnp"):
            return {"upnpds": [], "upnp_line": "1", "wan": "AUTO"}
        if (method, module) == ("devSta.get", "ddnsCfg"):
            return {"list": []}
        return {}

    rpc.rpc.side_effect = rpc_result
    rpc.batch.return_value = [{"list": []}, {"list": []}]
    driver = ReyeeEWebDriver(rpc_client=rpc)

    devices = driver.get_devices(force=True)
    assert devices[0]["mac"] == "aa-bb"
    driver.add_port_mapping({"ruleName": "web"})
    driver.set_upnp(True, "WAN")
    driver.add_firewall_rule({"name": "allow-test"})
    driver.add_ddns({"service": "test"}, "password")

    rpc.rpc.assert_any_call(
        method="devSta.get",
        module="user_list",
        data={"devType": "all", "dataType": "timely"},
        no_parse=True,
        params=None,
    )
    rpc.rpc.assert_any_call(
        method="devConfig.add",
        module="port_mapping",
        data={"list": [{"ruleName": "web"}]},
        no_parse=False,
        params=None,
    )
    rpc.rpc.assert_any_call(
        method="devSta.set",
        module="upnp",
        data={"enable_upnp": "true", "upnpds": [], "upnp_line": "1", "wan": "WAN"},
        no_parse=False,
        params=None,
    )
    rpc.rpc.assert_any_call(
        method="devConfig.add",
        module="ip_firewall",
        data={"list": [{"name": "allow-test"}]},
        no_parse=False,
        params=None,
    )
    rpc.rpc.assert_any_call(
        method="devSta.add",
        module="ddnsCfg",
        data={"service": "test", "password": "password"},
        no_parse=False,
        params=None,
    )


def test_relay_realtime_endpoint_is_control_only():
    service = hub.ROUTER_LITE_REALTIME
    demand = service.demand_payload()
    assert demand["routerActive"] is False
    assert demand["devicesActive"] is False

    result = service.accept_push({
        "sampleEpochMs": int(time.time() * 1000),
        "routerSample": {"uploadBps": 999},
        "devices": [{"mac": "AA-BB", "uploadBps": 999}],
    })
    assert result["acceptedRouter"] is False
    assert result["acceptedDevices"] is False
    assert result["source"] == "router_core"
