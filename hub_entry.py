"""LabProbe Hub entrypoint with direct Router Core v1 architecture enabled."""
from pathlib import Path
import hub

# Core Extensions (KEEP)
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
from router_build024_fix import install_router_build024_fix
from router_compat import install_router_rpc_compat
from router_config_sync_patch import install_router_config_sync_patch
from router_control_actor_patch import install_router_control_actor_patch
from router_control_scheduler_patch import install_router_control_scheduler_patch
from router_device_live_sync_patch import install_router_device_live_sync_patch
from router.firewall_automation import install_firewall_automation
from router_lite_realtime_patch import install_router_lite_realtime_patch
from router_native_features_patch import install_router_native_features_patch
from router_realtime_stability_patch import (
    install_router_realtime_stability_patch,
    install_router_status_localization,
)
from router_relay_credentials_patch import install_router_relay_credentials_patch
from router_task_manager_patch import install_router_task_manager_patch
from stun_service import install_stun_service
from wireguard_service import install_wireguard_service

# Router Core v1 Architecture
from router_core.driver.reyee_session import ReyeeSessionManager
from router_core.driver.reyee_rpc import ReyeeRpcClient
from router_core.driver.reyee import ReyeeEWebDriver
from router_core.cache.router_cache import RouterCache
from router_core.realtime.router_realtime import RouterRealtimeEngine, RealtimeFrame
from router_core.service.router_service import RouterService
from router_core.service.blueprint import create_router_blueprint_v1

PREVIOUS_HUB_VERSION = "0.11.0"
HUB_VERSION = "0.11.0"
hub.APP_VERSION = HUB_VERSION

# Initialize Router Core Single-Source-of-Truth
router_host = (
    hub.cfg_get("router.host")
    or hub.cfg_get("router.address")
    or hub.cfg_get("router.ip")
    or os.environ.get("ROUTER_HOST")
    or os.environ.get("ROUTER_IP")
    or os.environ.get("ROUTER_ADDRESS")
    or "192.168.110.1"
)
router_password = (
    hub.cfg_get("router.password")
    or os.environ.get("ROUTER_PASSWORD")
    or ""
)
router_username = (
    hub.cfg_get("router.username")
    or os.environ.get("ROUTER_USERNAME")
    or "admin"
)

router_session_mgr = ReyeeSessionManager(
    host=str(router_host).strip(),
    password=str(router_password).strip(),
    username=str(router_username).strip(),
    timeout=8.0,
)
router_rpc_client = ReyeeRpcClient(session_mgr=router_session_mgr)
router_driver = ReyeeEWebDriver(rpc_client=router_rpc_client)
router_cache = RouterCache(default_ttl=2.0)
router_realtime = RouterRealtimeEngine()

router_service = RouterService(
    driver=router_driver,
    cache=router_cache,
    realtime=router_realtime,
    notify_config_change=lambda res, act, data: router_realtime.broadcast(RealtimeFrame.config(res, act, data)),
)

hub.ROUTER_SESSION_MANAGER = router_session_mgr
hub.ROUTER_RPC_CLIENT = router_rpc_client
hub.ROUTER_DRIVER = router_driver
hub.ROUTER_CACHE = router_cache
hub.ROUTER_REALTIME = router_realtime
hub.ROUTER_SERVICE = router_service

# Initialize task manager for async router tasks
install_router_task_manager_patch(hub)

# Register Router Core Blueprint v1 as official production API
hub.app.register_blueprint(
    create_router_blueprint_v1(
        service=router_service,
        check_app_token=hub.check_app_token,
        logger=hub.LOGGER,
        task_manager=getattr(hub, "ROUTER_TASK_MANAGER", None),
    )
)

# Compatibility bridge & extension services
router_sync = install_router_rpc_compat(hub)
install_router_status_localization(hub, router_sync)
router_lite_realtime = install_router_lite_realtime_patch(hub, router_sync)
install_hub_realtime_ws(hub, router_lite_realtime)

# Retained LabRelay & Product Extensions
install_router_config_sync_patch(hub, router_driver)
install_firewall_automation(hub, router_driver)
install_stun_service(hub, router_driver)
install_wireguard_service(hub)
install_lab_ddns(hub)
install_agent_presence_patch(hub)
install_device_history_patch(hub)
install_hub0935_device_sync_fix(hub)
install_portmap_persistence_patch(hub)
install_router_device_live_sync_patch(hub, router_driver)
install_followup_stability_patch(hub, router_lite_realtime)
install_final_stability_patch(hub)
install_labrelay_sync_patch(hub)
install_hub0934_fixes(hub)

if __name__ == "__main__":
    raise SystemExit(hub.command_line())
