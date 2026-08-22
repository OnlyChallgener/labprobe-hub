"""Authenticated Hub API for Router IPv6 management."""
from __future__ import annotations

import time
from typing import Any, Callable

from flask import Blueprint, jsonify, request

from router_rpc import RouterRpcError

from .models import Ipv6ValidationError
from .service import Ipv6Service


def create_ipv6_blueprint(check_app_token: Callable[[], bool], logger: Any, client: Any) -> Blueprint:
    service = Ipv6Service(client)
    bp = Blueprint("router_ipv6", __name__, url_prefix="/api/router/ipv6")

    @bp.before_request
    def _authorize():
        if not check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return None

    @bp.errorhandler(Exception)
    def _handle(error: Exception):
        logger.warning(
            "router ipv6 api error path=%s type=%s message=%s",
            request.path,
            type(error).__name__,
            error,
        )
        if isinstance(error, Ipv6ValidationError):
            return jsonify({"ok": False, "error": "INVALID_IPV6_CONFIG", "message": str(error)}), 400
        if isinstance(error, RouterRpcError):
            return jsonify({"ok": False, "error": error.code, "message": str(error)}), error.http_status
        return jsonify({"ok": False, "error": "INTERNAL_ERROR", "message": "IPv6 操作失败"}), 500

    @bp.get("/status")
    def get_status():
        return jsonify({"ok": True, "data": service.status().to_dict(), "updatedAt": int(time.time())})

    @bp.get("/config")
    def get_config():
        return jsonify({"ok": True, "data": service.config().to_dict()})

    @bp.get("/clients")
    def get_clients():
        clients = [client_row.to_dict() for client_row in service.clients()]
        return jsonify({"ok": True, "data": {"clients": clients, "total": len(clients)}})

    @bp.put("/config")
    def put_config():
        result = service.update_config(request.get_json(silent=True) or {})
        return jsonify(
            {
                "ok": True,
                "data": result["config"].to_dict(),
                "verifiedAt": result["verifiedAt"],
                "message": "IPv6 设置已保存并校验",
            }
        )

    return bp
