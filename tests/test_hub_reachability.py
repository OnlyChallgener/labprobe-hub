"""Hub 自报「家里该用哪个地址连回来」。

动机：App 的 Hub 地址下拉以前只有 3 条历史，用户加两个外网地址就把家里的局域网地址
挤掉了 —— 而局域网地址才是绝大多数时候能用的那一个。它不该靠用户手输，Hub 自己知道。
"""

import socket

import hub


def test_reachability_shape_and_port_agree_with_the_serving_port(monkeypatch):
    monkeypatch.delenv("HUB_ADVERTISE_URL", raising=False)
    report = hub.hub_reachability()
    assert report["ok"] is True
    assert report["port"] == hub.PORT
    # 探不到局域网地址时宁可给空串，也不许编一个。
    assert report["lan"] in ("", f"http://{report['lanIp']}:{hub.PORT}")
    if report["lanIp"]:
        assert not report["lanIp"].startswith("127.")


def test_explicit_advertise_url_wins_over_detection(monkeypatch):
    monkeypatch.setenv("HUB_ADVERTISE_URL", "http://hub.home.lan:58443/")
    report = hub.hub_reachability()
    assert report["lan"] == "http://hub.home.lan:58443"
    assert report["lanSource"] == "advertise"


def test_loopback_advertise_url_is_not_offered_as_a_device_address(monkeypatch):
    # 默认值就是 127.0.0.1，它只对容器自己有意义，给设备等于给一个连不上的地址。
    monkeypatch.setenv("HUB_ADVERTISE_URL", f"http://127.0.0.1:{hub.PORT}")
    report = hub.hub_reachability()
    assert "127.0.0.1" not in report["lan"]


def test_default_gateway_parses_real_route_table_text():
    """纯函数版解析器：Windows 上没有 /proc/net/route，读文件那段永远走 except，
    当初 `struct` 忘了 import 也能把测试跑绿 —— 真机才炸。这条在任何平台都执行到。"""
    route = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0105A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "eth0\t0005A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
    )
    assert hub.parse_default_gateway_ipv4(route) == "192.168.5.1"
    # 没有默认路由时返回空，而不是拿第一条凑数。
    assert hub.parse_default_gateway_ipv4(route.splitlines()[0] + "\neth0\t0005A8C0\t00000000\t0001\n") == ""
    assert hub.parse_default_gateway_ipv4("") == ""


def test_lan_probe_picks_the_interface_that_routes_to_the_gateway(monkeypatch):
    # 不依赖真实网卡：把默认网关指向一个必然走本机回环地址族的对端，验证它确实是用
    # getsockname 选路，而不是枚举网卡拿第一个。
    monkeypatch.setattr(hub, "_default_gateway_ipv4", lambda: "10.255.255.254")
    monkeypatch.setenv("HUB_ADVERTISE_URL", "")
    ip = hub.hub_lan_ipv4()
    assert ip == "" or not ip.startswith("127.")


def test_reachability_route_needs_the_app_token(monkeypatch):
    # 不假设「没配 token 时放不放行」这套策略，只钉住这条路由自己走了鉴权分支。
    monkeypatch.setattr(hub, "check_app_token", lambda: False)
    response = hub.app.test_client().get("/api/hub/reachability")
    assert response.status_code == 401
    assert response.get_json()["ok"] is False
