"""LabProbe Hub entrypoint with direct Ruijie router control enabled."""
from pathlib import Path

import hub
from hub_realtime_ws import install_hub_realtime_ws
from router_be72_auth_patch import install_router_be72_auth_patch
from router_be72_sid_wire_patch import install_router_be72_sid_wire_patch
from router_compat import install_router_rpc_compat
from router_developer_flow_patch import install_router_developer_flow_patch
from router_http_developer_transport_patch import install_router_http_developer_transport_patch
from router_lite_realtime_patch import install_router_lite_realtime_patch
from router_native_features_patch import install_router_native_features_patch
from router_realtime_stability_patch import (
    install_router_realtime_stability_patch,
    install_router_status_localization,
)
from router_relay_credentials_patch import install_router_relay_credentials_patch
from router_rpc_v010 import create_router_blueprint_v010
from router_ws_patch import install_router_ws_patch

HUB_VERSION = "0.9.21"
hub.APP_VERSION = HUB_VERSION
install_router_http_developer_transport_patch()
install_router_developer_flow_patch()
install_router_be72_auth_patch()
install_router_be72_sid_wire_patch()
install_router_native_features_patch()
install_router_ws_patch()
install_router_realtime_stability_patch()
install_router_relay_credentials_patch()
hub.app.register_blueprint(
    create_router_blueprint_v010(
        check_app_token=hub.check_app_token,
        logger=hub.LOGGER,
        config_dir=Path(hub.CONFIG_DIR),
    )
)
router_sync = install_router_rpc_compat(hub)
install_router_status_localization(hub, router_sync)
router_lite_realtime = install_router_lite_realtime_patch(hub, router_sync)
install_hub_realtime_ws(hub, router_lite_realtime)

if __name__ == "__main__":
    raise SystemExit(hub.command_line())
