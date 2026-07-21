"""LabProbe Hub entrypoint with direct Ruijie router control enabled."""
from pathlib import Path

import hub
from router_compat import install_router_rpc_compat
from router_rpc_v010 import create_router_blueprint_v010

HUB_VERSION = "0.9.10"
hub.APP_VERSION = HUB_VERSION
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
