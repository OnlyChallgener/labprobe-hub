"""Add router-native NAT diagnostics and Beta update checks to the v0.10 API.

NAT detection is intentionally asynchronous. Reyee's ``nat_detector`` RPC can
block for the whole STUN procedure, so Flask requests must never wait on it.
The APP starts a job, then polls the in-memory result while a Hub worker talks
to the router in the background.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable, Dict

from flask import Blueprint, jsonify, request

import router_rpc_v099 as v099
from router_rpc import RouterRpcError


DEFAULT_STUN_HOST = "stun.voip.aebc.com"
ALLOWED_NAT_MODES = {"classic", "5780"}
ALLOWED_WAN_INTERFACES = {"wan", "wan1"}
NAT_POLL_SECONDS = 1.0
NAT_TIMEOUT_SECONDS = 75.0


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


def _nat_result_with_request(data: Any, requested: Dict[str, Any]) -> Any:
    """Attach the requested parameters without changing router result fields."""
    parsed = data
    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except Exception:
            return data
    if not isinstance(parsed, dict):
        return parsed
    result = dict(parsed)
    result["requested_host"] = requested.get("host", DEFAULT_STUN_HOST)
    result["requested_port"] = int(requested.get("port") or 3478)
    result["requested_interface"] = requested.get("interface", "wan")
    result["requested_mode"] = requested.get("mode", "classic")
    return result


def _nat_terminal(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    status = str(data.get("status") or "").strip().lower()
    if status in {"completed", "success", "failed", "error", "timeout", "cancelled", "canceled"}:
        return True
    return bool(str(data.get("nat_type") or data.get("natType") or "").strip())


def _nat_error_message(exc: Exception) -> str:
    raw = str(exc or "").strip()
    lower = raw.lower()
    if "timeout" in lower or "timed out" in lower:
        return "路由器 NAT 检测请求超时"
    if "unauthorized" in lower or "forbidden" in lower or "401" in lower or "403" in lower:
        return "路由器认证失效，请重新连接"
    if "resolve" in lower or "dns" in lower:
        return "STUN 服务器域名解析失败"
    return f"路由器 NAT 检测失败：{raw}" if raw else "路由器 NAT 检测失败"


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

        nat_lock = threading.RLock()
        nat_generation = 0
        last_nat_request: Dict[str, Any] = {
            "host": DEFAULT_STUN_HOST,
            "port": 3478,
            "interface": "wan",
            "mode": "classic",
        }
        nat_result: Dict[str, Any] = _nat_result_with_request(
            {"status": "idle", "message": "等待检测"},
            last_nat_request,
        )

        def store_nat_result(generation: int, value: Any, requested: Dict[str, Any]) -> bool:
            nonlocal nat_result
            normalized = _nat_result_with_request(value, requested)
            if not isinstance(normalized, dict):
                normalized = _nat_result_with_request(
                    {"status": "running", "message": "检测进行中"},
                    requested,
                )
            if not str(normalized.get("status") or "").strip() and str(
                normalized.get("nat_type") or normalized.get("natType") or ""
            ).strip():
                normalized["status"] = "completed"
            normalized["updatedAt"] = int(time.time())
            with nat_lock:
                if generation != nat_generation:
                    return False
                nat_result = dict(normalized)
            return _nat_terminal(normalized)

        def run_nat_detection(generation: int, requested: Dict[str, Any]) -> None:
            try:
                start_data = client.rpc("devSta.set", "nat_detector", requested)
                if store_nat_result(generation, start_data, requested):
                    return
                deadline = time.monotonic() + NAT_TIMEOUT_SECONDS
                while time.monotonic() < deadline:
                    with nat_lock:
                        if generation != nat_generation:
                            return
                    try:
                        latest = client.rpc("devSta.get", "nat_detector")
                        if store_nat_result(generation, latest, requested):
                            return
                    except Exception as poll_error:
                        logger.debug("router NAT result poll deferred: %s", poll_error)
                    time.sleep(NAT_POLL_SECONDS)
                store_nat_result(
                    generation,
                    {
                        "status": "timeout",
                        "message": "检测超时，请更换 STUN 服务器或 WAN 接口后重试",
                        "log": "检测超时：在规定时间内未收到路由器最终结果",
                    },
                    requested,
                )
            except Exception as exc:
                message = _nat_error_message(exc)
                logger.warning("router NAT diagnostic failed: %s", exc)
                store_nat_result(
                    generation,
                    {"status": "error", "message": message, "log": message},
                    requested,
                )

        @bp.get("/nat-diagnostic")
        def nat_diagnostic_get():
            with nat_lock:
                data = dict(nat_result)
            return jsonify({"ok": True, "data": data})

        @bp.post("/nat-diagnostic")
        def nat_diagnostic_start():
            nonlocal nat_generation, nat_result
            payload = normalize_nat_request(request.get_json(silent=True) or {})
            with nat_lock:
                nat_generation += 1
                generation = nat_generation
                last_nat_request.clear()
                last_nat_request.update(payload)
                nat_result = _nat_result_with_request(
                    {
                        "status": "running",
                        "message": "检测已启动",
                        "startedAt": int(time.time()),
                    },
                    payload,
                )
            threading.Thread(
                target=run_nat_detection,
                args=(generation, dict(payload)),
                name=f"router-nat-diagnostic-{generation}",
                daemon=True,
            ).start()
            return jsonify({
                "ok": True,
                "message": "路由 NAT 诊断已在后台启动",
                "startedAt": int(time.time()),
                "request": payload,
            }), 202

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
