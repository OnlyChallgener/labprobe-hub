"""LabProbe Hub entrypoint with the Ruijie router-control blueprint enabled."""
from pathlib import Path

import hub
from router_rpc import create_router_blueprint

HUB_VERSION = "0.9.8"
hub.APP_VERSION = HUB_VERSION
hub.app.register_blueprint(
    create_router_blueprint(
        check_app_token=hub.check_app_token,
        logger=hub.LOGGER,
        config_dir=Path(hub.CONFIG_DIR),
    )
)

if __name__ == "__main__":
    raise SystemExit(hub.command_line())
