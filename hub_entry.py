"""LabProbe Hub entrypoint with direct Ruijie router control enabled."""
from pathlib import Path

import hub
from router_compat import install_router_rpc_compat
from router_rpc_v010 import create_router_blueprint_v010
from router_browser_timeout_patch import install_browser_timeout_patch
from router_browser_locator_patch import install_browser_locator_patch

HUB_VERSION = "0.9.12"
hub.APP_VERSION = HUB_VERSION
install_browser_timeout_patch()
install_browser_locator_patch(hub.LOGGER)
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
