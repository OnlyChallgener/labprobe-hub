"""Make APP-owned IPv6 mapping rules explicitly authoritative and durable.

Agent presence only describes execution capability.  The desired rule document is
stored by Hub and must be returned even when the Agent has never connected, is
restarting, or has lost its local runtime configuration.
"""
from __future__ import annotations

from typing import Any, Dict, List

from flask import jsonify, request


def install_portmap_persistence_patch(hub: Any) -> None:
    if getattr(hub, "_labprobe_portmap_persistence_patch", False):
        return

    original_save = hub._save_portmap_rules

    def save_rules(rows: List[Dict[str, Any]]) -> None:
        previous = hub.load_json(hub.PORTMAP_RULES_FILE, {})
        revision = hub.to_int(previous.get("revision"), 0) + 1 if isinstance(previous, dict) else 1
        rows = sorted(
            rows[-100:],
            key=lambda item: (
                hub.to_int(item.get("listenPort"), 0),
                hub.clean_saved_value(item.get("name")),
            ),
        )
        hub.save_json(hub.PORTMAP_RULES_FILE, {
            "version": 2,
            "revision": revision,
            "updatedAt": hub.now_str(),
            "rules": rows,
        })

    hub._save_portmap_rules = save_rules

    endpoint = "api_portmaps"
    original_view = hub.app.view_functions.get(endpoint)
    if original_view is None:
        # Keep startup safe if a future Hub renames the route; saves are still durable.
        hub.LOGGER.warning("portmap persistence response marker not installed: endpoint missing")
        hub._labprobe_portmap_persistence_patch = True
        return

    def api_portmaps_with_revision(*args: Any, **kwargs: Any):
        result = original_view(*args, **kwargs)
        if request.method != "GET":
            return result
        response = hub.app.make_response(result)
        if response.status_code != 200:
            return response
        root = response.get_json(silent=True)
        if not isinstance(root, dict):
            return response
        document = hub.load_json(hub.PORTMAP_RULES_FILE, {})
        if not isinstance(document, dict):
            document = {}
        root.update({
            "rulesLoaded": True,
            "rulesRevision": hub.to_int(document.get("revision"), 0),
            "rulesUpdatedAt": hub.clean_saved_value(document.get("updatedAt")),
            "rulesSource": "hub_persistent_desired_state",
        })
        return jsonify(root)

    hub.app.view_functions[endpoint] = api_portmaps_with_revision
    hub._labprobe_portmap_persistence_patch = True
