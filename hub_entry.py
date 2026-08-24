"""LabProbe Hub entrypoint with direct Router Core v1 architecture enabled."""
import os
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
from router_rpc import EncryptedRouterConfigStore
from router_task_manager_patch import RouterTaskManager
from router_ws_patch import RouterWebSocketMonitor
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

PREVIOUS_HUB_VERSION = "0.11.1-rc1"
HUB_VERSION = "0.11.1"
hub.APP_VERSION = HUB_VERSION

# Initialize Router Core Single-Source-of-Truth
def _resolve_router_settings():
    legacy = EncryptedRouterConfigStore(Path(hub.CONFIG_DIR)).load()
    host = (
        hub.cfg_get("router.host")
        or hub.cfg_get("router.address")
        or hub.cfg_get("router.ip")
        or os.environ.get("ROUTER_HOST")
        or os.environ.get("ROUTER_IP")
        or os.environ.get("ROUTER_ADDRESS")
        or legacy.get("address")
        or "http://192.168.5.1"
    )
    password = (
        hub.cfg_get("router.password")
        or os.environ.get("ROUTER_PASSWORD")
        or legacy.get("password")
        or ""
    )
    username = (
        hub.cfg_get("router.username")
        or os.environ.get("ROUTER_USERNAME")
        or "admin"
    )
    try:
        session_seconds = int(
            hub.cfg_get("router.session_seconds")
            or hub.cfg_get("router.sessionSeconds")
            or legacy.get("sessionSeconds")
            or 3600
        )
    except (TypeError, ValueError):
        session_seconds = 3600
    verify_tls_value = hub.cfg_get(
        "router.verify_tls",
        hub.cfg_get("router.verifyTls", None),
    )
    verify_tls = (
        bool(legacy.get("verifyTls", False))
        if verify_tls_value is None
        else str(verify_tls_value).strip().lower() in {"1", "true", "yes", "on"}
    )
    return {
        "host": str(host).strip(),
        "password": str(password).strip(),
        "username": str(username).strip(),
        "session_seconds": max(600, min(7200, session_seconds)),
        "verify_tls": verify_tls,
    }


router_settings = _resolve_router_settings()

router_session_mgr = ReyeeSessionManager(
    host=router_settings["host"],
    password=router_settings["password"],
    username=router_settings["username"],
    timeout=8.0,
    verify_tls=router_settings["verify_tls"],
    session_seconds=router_settings["session_seconds"],
)
router_rpc_client = ReyeeRpcClient(session_mgr=router_session_mgr)
router_cache = RouterCache(default_ttl=2.0)
router_driver = ReyeeEWebDriver(rpc_client=router_rpc_client, cache=router_cache)
router_realtime = RouterRealtimeEngine()

hub.ROUTER_SESSION_MANAGER = router_session_mgr
hub.ROUTER_RPC_CLIENT = router_rpc_client
hub.ROUTER_DRIVER = router_driver
hub.ROUTER_CACHE = router_cache
hub.ROUTER_REALTIME = router_realtime

# Existing App dashboard projection remains the public contract, but every
# refresh now reads exclusively through the Router Core driver.
router_sync = install_router_rpc_compat(hub)
router_task_manager = RouterTaskManager(hub, router_driver, hub.LOGGER)
hub.ROUTER_TASK_MANAGER = router_task_manager

router_service = RouterService(
    driver=router_driver,
    cache=router_cache,
    realtime=router_realtime,
    notify_config_change=lambda res, act, data: router_realtime.broadcast(RealtimeFrame.config(res, act, data)),
    dashboard_loader=router_sync.dashboard_snapshot,
    dashboard_refresher=router_sync.refresh_dashboard,
)
hub.ROUTER_SERVICE = router_service

# Register Router Core Blueprint v1 as official production API
hub.app.register_blueprint(
    create_router_blueprint_v1(
        service=router_service,
        check_app_token=hub.check_app_token,
        logger=hub.LOGGER,
        task_manager=router_task_manager,
    )
)

install_router_status_localization(hub, router_sync)
router_lite_realtime = install_router_lite_realtime_patch(hub, router_sync, router_realtime)
install_hub_realtime_ws(hub, router_realtime, router_lite_realtime)

# The authenticated BE72 fast stream feeds Router Core directly.  RouterLite is
# retained only for the existing Relay demand/ack endpoints.
router_ws_monitor = RouterWebSocketMonitor(router_driver, hub.LOGGER)
router_driver.router_ws_monitor = router_ws_monitor
router_ws_monitor.set_fast_handler(router_realtime.accept_router_fast)
router_ws_monitor.start()

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
install_followup_stability_patch(hub, None)
install_final_stability_patch(hub)
install_labrelay_sync_patch(hub)
install_hub0934_fixes(hub)

if __name__ == "__main__":
    raise SystemExit(hub.command_line())
