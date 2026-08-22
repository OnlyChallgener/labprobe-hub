from __future__ import annotations

import copy
import logging
import threading

import pytest
from flask import Flask

from router.ipv6 import create_ipv6_blueprint
from router.ipv6.models import Ipv6ValidationError
from router.ipv6.service import Ipv6Service


class FakeRouterClient:
    def __init__(self):
        self.write_lock = threading.RLock()
        self.calls = []
        self.network6 = {
            "wan6Num": "1",
            "lan": [
                {
                    "ip6addr": "",
                    "ip6assign": "64",
                    "ip6hint": "0",
                    "ip6class": "keep-lan-class",
                    "dhcpv6": "server",
                    "dhcpv6Type": "DHCPv6+SLAAC",
                    "ra": "server",
                    "ra_management": "1",
                    "leasetime6": "120",
                    "dns": "",
                    "relay": "1",
                    "unknownLan": "keep-lan",
                }
            ],
            "wan6": [
                {
                    "proto": "dhcpv6",
                    "ifname": "@wan",
                    "dns": "",
                    "dnsType": "auto",
                    "relay": "0",
                    "masq6": "0",
                    "metric": "7",
                    "unknownWan": "keep-wan",
                }
            ],
            "version": "1.0.0",
            "lanNum": "1",
            "wanNum": "0",
            "unknownTop": {"preserve": True},
            "configTime": "123",
            "currentTime": "123",
            "configId": "123",
        }

    def rpc(self, method, module, data=None, no_parse=False):
        self.calls.append((method, module, copy.deepcopy(data)))
        if method == "devSta.get" and module == "ipinfo6":
            return {
                "wan_v6": {
                    "proto": "dhcpv6",
                    "ip6": "2409:8a50::20/64",
                    "prefix": "2409:8a50:10::/60",
                    "gateway6": "fe80::1",
                    "dns6List": "2400:3200::1,2400:3200:baba::1",
                }
            }
        if method == "devSta.get" and module == "dhcp_lease6":
            assert data == {"index": 1, "size": 100, "macaddr": ""}
            return {
                "total": "1",
                "List": [
                    {
                        "hostname": "fnos",
                        "ipv6": "2409:8a50:10::1c3b",
                        "leasetime": "88",
                        "duid": "00:04:c9:8b",
                    }
                ],
            }
        if method == "devConfig.get" and module == "network6":
            return copy.deepcopy(self.network6)
        if method == "devConfig.set" and module == "network6":
            self.network6 = copy.deepcopy(data)
            return {"rcode": "00000000", "message": ""}
        raise AssertionError(f"unexpected RPC {method} {module}")


def test_status_and_dhcpv6_clients_are_normalized():
    service = Ipv6Service(FakeRouterClient())

    status = service.status().to_dict()
    clients = [item.to_dict() for item in service.clients()]

    assert status == {
        "connected": True,
        "proto": "dhcpv6",
        "address": "2409:8a50::20/64",
        "prefix": "2409:8a50:10::/60",
        "gateway": "fe80::1",
        "dns": ["2400:3200::1", "2400:3200:baba::1"],
    }
    assert clients == [
        {
            "hostname": "fnos",
            "ipv6": "2409:8a50:10::1c3b",
            "leasetime": 88,
            "duid": "00:04:c9:8b",
        }
    ]


def test_save_reads_merges_writes_full_config_and_verifies():
    client = FakeRouterClient()
    service = Ipv6Service(client)

    result = service.update_config(
        {
            "wan": {
                "proto": "relay",
                "relay": True,
                "dnsType": "manual",
                "dns": ["2400:3200::1"],
            },
            "lan": {
                "dhcpv6Server": False,
                "slaac": True,
                "ra": True,
                "ip6assign": 60,
                "leasetime6": 240,
            },
        }
    )

    assert [(method, module) for method, module, _ in client.calls] == [
        ("devConfig.get", "network6"),
        ("devConfig.set", "network6"),
        ("devConfig.get", "network6"),
    ]
    written = client.calls[1][2]
    assert written["unknownTop"] == {"preserve": True}
    assert written["wan6"][0]["unknownWan"] == "keep-wan"
    assert written["wan6"][0]["masq6"] == "0"
    assert written["wan6"][0]["metric"] == "7"
    assert written["wan6"][0]["ifname"] == "@wan"
    assert written["lan"][0]["unknownLan"] == "keep-lan"
    assert written["lan"][0]["ip6hint"] == "0"
    assert written["lan"][0]["ip6class"] == "keep-lan-class"
    assert {"configTime", "currentTime", "configId"}.isdisjoint(written)
    assert written["wan6"][0]["proto"] == "relay"
    assert written["wan6"][0]["dns"] == "2400:3200::1"
    assert written["wan6"][0]["dnsType"] == "admin"
    assert written["wan6"][0]["relay"] == "1"
    assert written["lan"][0]["ip6assign"] == "60"
    assert written["lan"][0]["dhcpv6"] == "disabled"
    assert written["lan"][0]["dhcpv6Type"] == "SLAAC"
    assert written["lan"][0]["ra"] == "server"
    assert written["lan"][0]["leasetime6"] == "240"
    assert result["config"].wan.dns == ["2400:3200::1"]


def test_invalid_manual_dns_is_rejected_before_write():
    client = FakeRouterClient()
    service = Ipv6Service(client)

    with pytest.raises(Ipv6ValidationError, match="DNS 地址无效"):
        service.update_config(
            {
                "wan": {"proto": "dhcpv6", "dnsType": "manual", "dns": ["not-an-ip"]},
                "lan": {"dhcpv6Server": True, "slaac": True, "ra": True, "ip6assign": 64, "leasetime6": 120},
            }
        )

    assert all(method != "devConfig.set" for method, _, _ in client.calls)


def test_ipv6_blueprint_uses_existing_app_token_guard():
    router = FakeRouterClient()
    denied = Flask("ipv6-denied")
    denied.register_blueprint(create_ipv6_blueprint(lambda: False, logging.getLogger("test"), router))
    allowed = Flask("ipv6-allowed")
    allowed.register_blueprint(create_ipv6_blueprint(lambda: True, logging.getLogger("test"), router))

    denied_response = denied.test_client().get("/api/router/ipv6/status")
    allowed_response = allowed.test_client().get("/api/router/ipv6/status")

    assert denied_response.status_code == 401
    assert denied_response.get_json() == {"ok": False, "error": "unauthorized"}
    assert allowed_response.status_code == 200
    assert allowed_response.get_json()["data"]["connected"] is True
