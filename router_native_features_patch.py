"""Add router-native NAT diagnostics and Beta update checks to the v0.10 API.

This patch wraps the existing blueprint factory so the new routes reuse the
same authenticated router client, cookie jar and session cache. No second
router login or WebSocket connection is created.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict

from flask import Blueprint, jsonify, request

import router_rpc_v099 as v099
from router_rpc import RouterRpcError


DEFAULT_STUN_HOST = "stun.hot-chilli.net"
ALLOWED_NAT_MODES = {"classic", "5780"}
ALLOWED_WAN_INTERFACES = {"wan", "wan1"}


def normalize_nat_request(body: Dict[str, Any]) -> Dict[str, Any]:
    host = str(body.get("host") or DEFAULT_STUN_HOST).strip()
    if not host or len(host) > 253 or any(ch.isspace() for ch in host):
        raise RouterRpcError("STUN服务器地址无效", "INVALID_STUN_HOST", 400)
    raw_port = body.get("port", 3478)
    if raw_port is None or str(raw_port).strip() == "":
        raw_port = 3478
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise RouterRpcError("STUN端口无效", "INVALID_STUN_PORT", 400) from exc
    if not 1 <= port <= 65535:
        raise RouterRpcError("STUN端口必须在1到65535之间", "INVALID_STUN_PORT", 400)
    interface = str(body.get("interface") or "wan").strip().lower()
    if interface not in ALLOWED_WAN_INTERFACES:
        raise RouterRpcError("WAN接口无效", "INVALID_WAN_INTERFACE", 400)
    mode = str(body.get("mode") or "classic").strip().lower()
    if mode not in ALLOWED_NAT_MODES:
        raise RouterRpcError("NAT检测模式无效", "INVALID_NAT_MODE", 400)
    return {
        "host": host,
        "port": port,
        "interface": interface,
        "mode": mode,
    }


def install_router_native_features_patch() -> None:
    if getattr(v099, "_labprobe_native_features_patch", False):
        return

    original_factory = v099.create_router_blueprint_v099

    def wrapped_factory(
        check_app_token: Callable[[], bool],
        logger: Any,
        config_dir: Any,
    ) -> Blueprint:
        captured: Dict[str, Any] = {}
        original_client_constructor = v099.ReliableRuijieRouterClient

        def capture_client(*args: Any, **kwargs: Any) -> Any:
            client = original_client_constructor(*args, **kwargs)
            captured["client"] = client
            return client

        v099.ReliableRuijieRouterClient = capture_client
        try:
            bp = original_factory(check_app_token, logger, config_dir)
        finally:
            v099.ReliableRuijieRouterClient = original_client_constructor

        client = captured.get("client")
        if client is None:
            raise RuntimeError("router client capture failed")

        @bp.get("/nat-diagnostic")
        def nat_diagnostic_get():
            return jsonify({"ok": True, "data": client.rpc("devSta.get", "nat_detector")})

        @bp.post("/nat-diagnostic")
        def nat_diagnostic_start():
            payload = normalize_nat_request(request.get_json(silent=True) or {})
            client.rpc("devSta.set", "nat_detector", payload)
            return jsonify({
                "ok": True,
                "message": "路由NAT诊断已启动",
                "startedAt": int(time.time()),
                "request": payload,
            })

        @bp.get("/beta-upgrade")
        def beta_upgrade_get():
            data = client.rpc("devSta.get", "ehr_beta_upgrade", {"action": "version"})
            return jsonify({"ok": True, "data": data})

        @bp.after_request
        def advertise_native_features(response: Any):
            if request.path.endswith("/api/router/capabilities") and response.is_json:
                root = response.get_json(silent=True)
                if isinstance(root, dict):
                    features = root.setdefault("features", {})
                    if isinstance(features, dict):
                        features["natDiagnostic"] = True
                        features["betaUpgrade"] = True
                    response.set_data(jsonify(root).get_data())
                    response.content_type = "application/json"
            return response

        return bp

    v099.create_router_blueprint_v099 = wrapped_factory
    v099._labprobe_native_features_patch = True
