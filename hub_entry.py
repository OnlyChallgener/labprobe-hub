"""LabProbe Hub entrypoint with direct Ruijie router control enabled."""
from pathlib import Path

import hub
from agent_presence_patch import install_agent_presence_patch
from device_history_patch import install_device_history_patch
from final_stability_patch import install_final_stability_patch
from followup_stability_patch import install_followup_stability_patch
from hub0934_fixes import install_hub0934_fixes
from hub0935_sync_fix import (
    install_hub0935_device_sync_fix,
    install_router_ws_passive_fix,
)
from hub_realtime_ws import install_hub_realtime_ws
from labrelay_sync_patch import install_labrelay_sync_patch
from lab_ddns import install_lab_ddns
from portmap_persistence_patch import install_portmap_persistence_patch
from router_be72_auth_patch import install_router_be72_auth_patch
from router_be72_sid_wire_patch import install_router_be72_sid_wire_patch
from router_build024_fix import install_router_build024_fix
from router_compat import install_router_rpc_compat
from router_config_sync_patch import install_router_config_sync_patch
from router_control_actor_patch import install_router_control_actor_patch
from router_control_scheduler_patch import install_router_control_scheduler_patch
from router_device_live_sync_patch import install_router_device_live_sync_patch
from router_developer_flow_patch import install_router_developer_flow_patch
from router_fast_watchdog_patch import install_router_fast_watchdog_patch
from router.firewall_automation import install_firewall_automation
from router_http_developer_transport_patch import install_router_http_developer_transport_patch
from router_lite_realtime_patch import install_router_lite_realtime_patch
from router_native_features_patch import install_router_native_features_patch
from router_realtime_stability_patch import (
    install_router_realtime_stability_patch,
    install_router_status_localization,
)
from router_relay_credentials_patch import install_router_relay_credentials_patch
from router_rpc_v010 import create_router_blueprint_v010
from router_slow_cache_patch import install_router_slow_cache_patch
from router_task_manager_patch import install_router_task_manager_patch
from router_ws_patch import install_router_ws_patch
from router.ipv6 import create_ipv6_blueprint
from stun_service import install_stun_service
from wireguard_service import install_wireguard_service

PREVIOUS_HUB_VERSION = "0.9.35"
HUB_VERSION = "0.10.9"
hub.APP_VERSION = HUB_VERSION
install_router_http_developer_transport_patch()
install_router_developer_flow_patch()
install_router_be72_auth_patch()
install_router_be72_sid_wire_patch()
install_router_native_features_patch()
install_router_ws_patch()
install_router_fast_watchdog_patch()
install_router_ws_passive_fix()
install_router_realtime_stability_patch()
install_router_build024_fix()
install_router_relay_credentials_patch()
install_router_slow_cache_patch()
install_router_control_scheduler_patch()
install_router_control_actor_patch()
install_router_task_manager_patch(hub)
hub.app.register_blueprint(
    create_router_blueprint_v010(
        check_app_token=hub.check_app_token,
        logger=hub.LOGGER,
        config_dir=Path(hub.CONFIG_DIR),
    )
)
hub.app.register_blueprint(
    create_ipv6_blueprint(
        check_app_token=hub.check_app_token,
        logger=hub.LOGGER,
        client=hub.ROUTER_TASK_MANAGER.client,
    )
)
router_sync = install_router_rpc_compat(hub)
install_router_status_localization(hub, router_sync)
router_lite_realtime = install_router_lite_realtime_patch(hub, router_sync)
install_hub_realtime_ws(hub, router_lite_realtime)
install_router_config_sync_patch(hub, hub.ROUTER_TASK_MANAGER.client)
install_firewall_automation(hub, hub.ROUTER_TASK_MANAGER.client)
install_stun_service(hub, hub.ROUTER_TASK_MANAGER.client)
install_wireguard_service(hub)
install_lab_ddns(hub)
install_agent_presence_patch(hub)
install_device_history_patch(hub)
install_hub0935_device_sync_fix(hub)
install_portmap_persistence_patch(hub)
install_router_device_live_sync_patch(hub, hub.ROUTER_TASK_MANAGER.client)
install_followup_stability_patch(hub, router_lite_realtime)
install_final_stability_patch(hub)
install_labrelay_sync_patch(hub)
install_hub0934_fixes(hub)

if __name__ == "__main__":
    raise SystemExit(hub.command_line())
