"""LabProbe Hub entrypoint with direct Ruijie router control enabled."""
from pathlib import Path

import hub
from router_be72_auth_patch import install_router_be72_auth_patch
from router_be72_sid_wire_patch import install_router_be72_sid_wire_patch
from router_compat import install_router_rpc_compat
from router_developer_flow_patch import install_router_developer_flow_patch
from router_http_developer_transport_patch import install_router_http_developer_transport_patch
from router_native_features_patch import install_router_native_features_patch
from router_rpc_v010 import create_router_blueprint_v010
from router_ws_patch import install_router_ws_patch

HUB_VERSION = "0.9.14"
hub.APP_VERSION = HUB_VERSION
install_router_http_developer_transport_patch()
install_router_developer_flow_patch()
install_router_be72_auth_patch()
install_router_be72_sid_wire_patch()
install_router_native_features_patch()
install_router_ws_patch()
hub.app.register_blueprint(
    create_router_blueprint_v010(
        check_app_token=hub.check_app_token,
        logger=hub.LOGGER,
        config_dir=Path(hub.CONFIG_DIR),
    )
)
install_router_rpc_compat(hub)

if __name__ == "__main__":
    raise SystemExit(hub.command_line())
