"""Router Core Hub API Blueprint v1.

Provides Flask REST route handlers powered by RouterService.
Guarantees 100% contract compliance with docs/contracts/app-hub-contract-v1.json.
"""

from typing import Any, Callable, Optional
from flask import Blueprint, jsonify, request

from router_core.errors import RouterCoreError, from_legacy_error
from router_core.service.router_service import RouterService


def create_router_blueprint_v1(
    service: RouterService,
    check_app_token: Callable[[], bool],
    logger: Optional[Any] = None,
    name: str = "router_core_api",
    url_prefix: str = "/api/router",
) -> Blueprint:
    """Creates a Flask Blueprint exposing official Router endpoints via RouterService."""
    bp = Blueprint(name, __name__, url_prefix=url_prefix)

    @bp.before_request
    def _authorize():
        if not check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401

    @bp.errorhandler(Exception)
    def _handle_error(error: Exception):
        if logger:
            logger.error("Router API error: %s", error, exc_info=True)
        core_err = from_legacy_error(error)
        return jsonify(core_err.to_response_dict()), core_err.status_code

    # --- Capabilities & Status ---

    @bp.get("/capabilities")
    def get_capabilities():
        return jsonify(service.get_capabilities())

    @bp.get("/status")
    def get_status():
        return jsonify(service.get_status())

    @bp.get("/dashboard")
    def get_dashboard():
        force = request.args.get("force", "").lower() in ("1", "true")
        return jsonify(service.get_dashboard(force=force))

    @bp.post("/dashboard/refresh")
    def refresh_dashboard():
        return jsonify(service.get_dashboard(force=True))

    @bp.get("/devices")
    def get_devices():
        force = request.args.get("force", "").lower() in ("1", "true")
        return jsonify(service.get_devices(force=force))

    # --- Native Port Mapping ---

    @bp.get("/port-mapping")
    def get_port_mapping():
        force = request.args.get("force", "").lower() in ("1", "true")
        return jsonify(service.get_port_mappings(force=force))

    @bp.post("/port-mapping")
    def add_port_mapping():
        body = request.get_json(silent=True) or {}
        return jsonify(service.add_port_mapping(body))

    @bp.put("/port-mapping/<path:rule_name>")
    def update_port_mapping(rule_name: str):
        body = request.get_json(silent=True) or {}
        return jsonify(service.update_port_mapping(rule_name, body))

    @bp.delete("/port-mapping/<path:rule_name>")
    def delete_port_mapping(rule_name: str):
        return jsonify(service.delete_port_mapping(rule_name))

    # --- UPnP ---

    @bp.get("/upnp")
    def get_upnp():
        force = request.args.get("force", "").lower() in ("1", "true")
        return jsonify(service.get_upnp(force=force))

    @bp.put("/upnp")
    def set_upnp():
        body = request.get_json(silent=True) or {}
        enabled = bool(body.get("enabled", False))
        wan = str(body.get("wan", "WAN"))
        return jsonify(service.set_upnp(enabled, wan))

    # --- Firewall ---

    @bp.get("/firewall")
    def get_firewall():
        force = request.args.get("force", "").lower() in ("1", "true")
        return jsonify(service.get_firewall(force=force))

    @bp.post("/firewall/rules")
    def add_firewall_rule():
        body = request.get_json(silent=True) or {}
        return jsonify(service.add_firewall_rule(body))

    @bp.put("/firewall/rules/<uuid>")
    def update_firewall_rule(uuid: str):
        body = request.get_json(silent=True) or {}
        return jsonify(service.update_firewall_rule(uuid, body))

    @bp.patch("/firewall/rules/<uuid>/enabled")
    def set_firewall_rule_enabled(uuid: str):
        body = request.get_json(silent=True) or {}
        enabled = bool(body.get("enabled", False))
        return jsonify(service.set_firewall_rule_enabled(uuid, enabled))

    @bp.delete("/firewall/rules/<uuid>")
    def delete_firewall_rule(uuid: str):
        return jsonify(service.delete_firewall_rule(uuid))

    @bp.post("/firewall/reorder")
    def reorder_firewall_rules():
        body = request.get_json(silent=True) or {}
        scope = str(body.get("scope", "wan"))
        uuids = body.get("uuids", [])
        return jsonify(service.reorder_firewall_rules(scope, uuids))

    # --- DDNS ---

    @bp.get("/ddns")
    def get_ddns():
        force = request.args.get("force", "").lower() in ("1", "true")
        return jsonify(service.get_ddns(force=force))

    @bp.post("/ddns")
    def add_ddns():
        body = request.get_json(silent=True) or {}
        password = str(body.get("password", ""))
        return jsonify(service.add_ddns(body, password))

    @bp.put("/ddns/<service_id>")
    def update_ddns(service_id: str):
        body = request.get_json(silent=True) or {}
        password = body.get("password")
        return jsonify(service.update_ddns(service_id, body, password))

    @bp.delete("/ddns/<service_id>")
    def delete_ddns(service_id: str):
        return jsonify(service.delete_ddns(service_id))

    # --- IPv6 ---

    @bp.get("/ipv6/status")
    def get_ipv6_status():
        return jsonify(service.get_ipv6_status())

    @bp.get("/ipv6/config")
    def get_ipv6_config():
        return jsonify(service.get_ipv6_config())

    @bp.get("/ipv6/clients")
    def get_dhcpv6_clients():
        return jsonify(service.get_dhcpv6_clients())

    @bp.put("/ipv6/config")
    def save_ipv6_config():
        body = request.get_json(silent=True) or {}
        return jsonify(service.save_ipv6_config(body))

    # --- Diagnostic ---

    @bp.get("/diagnostic")
    def get_diagnostic():
        return jsonify(service.get_diagnostic())

    @bp.post("/diagnostic")
    def start_diagnostic():
        return jsonify(service.start_diagnostic())

    return bp
