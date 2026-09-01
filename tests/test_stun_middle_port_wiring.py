from pathlib import Path

import stun_port_config_patch as patch


def test_stun_middle_port_patch_is_installed_in_runtime_order():
    text = Path("hub_entry.py").read_text(encoding="utf-8")
    assert "from stun_port_config_patch import install_stun_port_config_patch" in text
    service = text.index("install_stun_service(hub, router_driver)")
    port_patch = text.index("install_stun_port_config_patch(hub)")
    legacy_sync = text.index("install_labrelay_sync_patch(hub)")
    assert service < port_patch < legacy_sync


def test_stun_middle_port_policy_matches_app_contract():
    assert patch.STUN_USER_PORT_MIN == 1024
    assert patch.STUN_USER_PORT_MAX == 65535
    assert patch.STUN_AUTO_PORT_MIN == 30000
    assert patch.STUN_AUTO_PORT_MAX == 32767
