from types import SimpleNamespace

import pytest

from router_core.driver.reyee import ReyeeEWebDriver
from router_core.errors import RouterValidationError


class FakeRpc:
    def __init__(self):
        self.state = {"enable_upnp": "false", "wan": "auto", "upnp_line": "1", "upnpds": []}
        self.calls = []

    def rpc(self, method, module="", data=None, **kwargs):
        self.calls.append((method, module, data))
        if method == "devSta.get":
            return dict(self.state)
        if method == "devSta.set":
            self.state = {**self.state, **data}
            return {"rcode": "0"}
        return {"rcode": "0"}


def driver(rpc):
    cache = SimpleNamespace(get_or_fetch=lambda key, loader, ttl=0, force=False: loader(), invalidate=lambda *a, **k: None)
    return ReyeeEWebDriver(rpc_client=rpc, cache=cache)


def test_upnp_read_adds_wan_id_and_keeps_legacy_wan_field():
    result = driver(FakeRpc()).get_upnp(force=True)
    assert result["wan"] == "AUTO"
    assert result["wanId"] == "auto"


def test_upnp_wan1_write_uses_firmware_external_interface_contract():
    rpc = FakeRpc()
    result = driver(rpc).set_upnp(True, "WAN1")
    payload = next(data for method, module, data in rpc.calls if method == "devSta.set")
    assert payload["wan"] == "wan1"
    assert result["wan"] == "WAN1"
    assert result["wanId"] == "wan1"


def test_upnp_rejects_unsafe_interface_before_write():
    rpc = FakeRpc()
    with pytest.raises(RouterValidationError) as raised:
        driver(rpc).set_upnp(True, "../bad")
    assert raised.value.code == "UPNP_WAN_UNSUPPORTED"
    assert not rpc.calls


def test_upnp_preserves_existing_native_interface_name():
    rpc = FakeRpc()
    rpc.state["wan"] = "br-wan"
    result = driver(rpc).get_upnp(force=True)
    assert result["wan"] == "BR-WAN"
    assert result["wanId"] == "br-wan"


def test_firewall_interfaces_come_from_native_network_config():
    network = {
        "wan": [{"proto": "dhcp"}, {"proto": "pppoe"}],
        "lan": [{"vlanid": "233"}, {"vlanid": "234"}, {"vlanid": "235"}],
    }
    assert ReyeeEWebDriver._firewall_interfaces(network) == ["wan", "wan1", "lan", "lan_234", "lan_235"]


@pytest.mark.parametrize("ui_wan", ["AUTO", "WAN", "WAN1"])
def test_upnp_keeps_display_name_separate_from_wire_id(ui_wan):
    rpc = FakeRpc()
    result = driver(rpc).set_upnp(True, ui_wan)
    payload = next(data for method, module, data in rpc.calls if method == "devSta.set")
    assert payload["wan"] == ui_wan.lower()
    assert result["wan"] == ui_wan
    assert result["wanId"] == ui_wan.lower()
