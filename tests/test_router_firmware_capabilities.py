from router_capabilities import firmware_features
from router_core.service.router_service import RouterService


def test_be50_does_not_advertise_be72_firmware_features():
    features = firmware_features("BE50", True)
    assert firmware_features("BE5100", True)["wireguard"] is False
    for name in ("firewall", "ddns", "wireguard", "ipv6Bridge", "nativeNatDiagnostic",
                 "nativeFirmwareUpgrade", "ipv6ConnectionCount", "routerEwebWss"):
        assert features[name] is False
    assert features["nativePortMapping"] is True
    assert features["upnp"] is True


def test_be72_keeps_full_firmware_capabilities():
    features = firmware_features("BE72", True)
    assert all(features.values())


def test_be50_firmware_identity_survives_display_name_change(monkeypatch):
    monkeypatch.setenv("PRIMARY_ROUTER_NAME", "BE50")
    assert firmware_features("书房", True)["wireguard"] is False


def test_be50_status_uses_only_fresh_agent_sample(monkeypatch):
    monkeypatch.setenv("PRIMARY_ROUTER_NAME", "BE50")

    class Driver:
        def get_status(self):
            return {"connected": False, "sessionConnected": False, "dataAvailable": False}

    class Realtime:
        sample = {"source": "agent_dashboard_push", "sampleEpochMs": 1234,
                  "sampleAgeMs": 1000, "stale": False}

        def get_router_calibration_snapshot(self):
            return self.sample

    realtime = Realtime()
    service = RouterService(Driver(), realtime=realtime)
    status = service.get_status()
    assert status["connected"] is True
    assert status["sessionConnected"] is False
    assert status["source"] == "agent_dashboard_push"

    realtime.sample = {**realtime.sample, "sampleAgeMs": 30_000, "stale": True}
    assert service.get_status()["connected"] is False
