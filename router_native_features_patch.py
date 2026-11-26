"""Add router-native NAT diagnostics and Beta update checks to the v0.10 API.

NAT detection is asynchronous. Reyee's ``nat_detector`` RPC can run for several
minutes, so Flask requests never wait on the whole procedure. The APP starts a
job and polls the in-memory result while one Hub worker follows the router.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
import uuid
from typing import Any, Callable, Dict

from flask import Blueprint, jsonify, request

import router_rpc_v099 as v099
from router_rpc import RouterRpcError


DEFAULT_STUN_HOST = "stun.voip.aebc.com"
ALLOWED_NAT_MODES = {"classic", "5780"}
ALLOWED_WAN_INTERFACES = {"wan", "wan1"}
NAT_POLL_SECONDS = 1.0
# Do not synthesize a Hub timeout while the router may still be running. The old
# 75-second limit regularly raced the router's own RFC5780 retries.
NAT_MAX_RUNTIME_SECONDS = max(
    180.0,
    float(os.environ.get("ROUTER_NAT_MAX_RUNTIME_SEC", "600")),
)
BETA_CACHE_TTL_SECONDS = max(
    60.0,
    float(os.environ.get("ROUTER_BETA_CACHE_TTL_SEC", "21600")),
)


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


def _first_text(data: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() not in {"none", "null", "--"}:
            return text
    return ""


def _normalize_nat_payload(value: Any) -> Any:
    parsed = value
    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except Exception:
            return value
    if not isinstance(parsed, dict):
        return parsed

    result = dict(parsed)
    mapping = _first_text(result, "mapping_behavior", "mappingBehavior", "mapping")
    filtering = _first_text(result, "filtering_behavior", "filteringBehavior", "filtering")
    nat_type = _first_text(result, "nat_type", "natType", "classic_type", "classicType")
    external_address = _first_text(
        result,
        "external_address",
        "externalAddress",
        "mapped_address",
        "mappedAddress",
    )
    other_address = _first_text(result, "other_address", "otherAddress")

    if mapping:
        result["mapping_behavior"] = mapping
    if filtering:
        result["filtering_behavior"] = filtering
    if nat_type:
        result["nat_type"] = nat_type
    if external_address:
        result["external_address"] = external_address
    if other_address:
        result["other_address"] = other_address

    status = _first_text(result, "status").lower()
    terminal_statuses = {"completed", "success", "failed", "error", "timeout", "cancelled", "canceled"}
    if mapping and filtering and status not in {"cancelled", "canceled", "failed", "error", "timeout"}:
        result["status"] = "completed"
    elif nat_type and status not in terminal_statuses:
        result["status"] = "completed"
    return result


def _epoch_seconds(value: Any) -> int:
    if value is None or isinstance(value, bool):
        return 0
    try:
        number = float(str(value).strip())
        if number <= 0:
            return 0
        if number >= 10_000_000_000:
            number /= 1000.0
        return int(number)
    except (TypeError, ValueError, OverflowError):
        return 0


def _nat_result_timestamp(data: Any) -> int:
    if not isinstance(data, dict):
        return 0
    for key in ("timestamp", "result_timestamp", "resultTimestamp"):
        timestamp = _epoch_seconds(data.get(key))
        if timestamp:
            return timestamp
    return 0


def _nat_result_is_stale(
    data: Any,
    request_started_at: int,
    last_firmware_timestamp: int = 0,
) -> bool:
    """Only timestamped firmware output can prove that a result is current."""
    timestamp = _nat_result_timestamp(data)
    if not timestamp:
        # Older firmware did not always return a timestamp. Keep that payload
        # compatible while still rejecting every stale result that can be dated.
        return False
    started_at = _epoch_seconds(request_started_at)
    previous = _epoch_seconds(last_firmware_timestamp)
    return bool((started_at and timestamp < started_at) or (previous and timestamp < previous))


def _valid_ipv4(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.IPv4Address(text))
    except ipaddress.AddressValueError:
        return ""


def _nat_source_ipv4(data: Dict[str, Any]) -> str:
    for key in (
        "source_ipv4",
        "sourceIPv4",
        "sourceIpv4",
        "source_ip",
        "sourceIp",
        "src_ipv4",
        "srcIpv4",
        "src_ip",
        "srcIp",
        "local_ipv4",
        "localIpv4",
        "local_ip",
        "localIp",
    ):
        address = _valid_ipv4(data.get(key))
        if address:
            return address
    raw_log = data.get("log")
    if isinstance(raw_log, (list, tuple)):
        raw_log = "\n".join(str(line) for line in raw_log)
    match = re.search(r"(?im)^\s*(?:\[[^\]]+\]\s*)?Source\s*IP(?:v4)?\s*:\s*([^\s,;]+)", str(raw_log or ""))
    return _valid_ipv4(match.group(1)) if match else ""


def _nat_detected_interface(data: Dict[str, Any]) -> str:
    for key in (
        "detected_interface",
        "detectedInterface",
        "external_iface",
        "externalIface",
        "wan_id",
        "wanId",
        "interface",
        "wan",
        "line",
    ):
        value = _first_text(data, key).lower()
        if value in ALLOWED_WAN_INTERFACES:
            return value
    raw_log = data.get("log")
    if isinstance(raw_log, (list, tuple)):
        raw_log = "\n".join(str(line) for line in raw_log)
    match = re.search(r"(?im)^\s*(?:\[[^\]]+\]\s*)?Interface\s*:\s*(wan1|wan)\s*$", str(raw_log or ""))
    return match.group(1).lower() if match else ""


def _nat_result_with_request(
    data: Any,
    requested: Dict[str, Any],
    *,
    request_id: str = "",
    task_id: str = "",
    request_started_at: int = 0,
    result_timestamp: int | None = None,
) -> Any:
    """Normalize firmware output and bind it to one accepted Hub request."""
    parsed = _normalize_nat_payload(data)
    if not isinstance(parsed, dict):
        return parsed
    result = dict(parsed)
    requested_host = requested.get("host", DEFAULT_STUN_HOST)
    requested_port = int(requested.get("port") or 3478)
    requested_interface = str(requested.get("interface") or "wan").strip().lower()
    requested_mode = str(requested.get("mode") or "classic").strip().lower()
    result["requested_host"] = requested_host
    result["requested_port"] = requested_port
    result["requested_interface"] = requested_interface
    result["requested_mode"] = requested_mode
    result["requestedInterface"] = requested_interface
    detected_interface = _nat_detected_interface(result)
    actual_interface = detected_interface or requested_interface
    result["wan_id"] = actual_interface
    result["wanId"] = actual_interface
    result.setdefault("mode", requested_mode)

    if detected_interface:
        result["detected_interface"] = detected_interface
        result["detectedInterface"] = detected_interface
    # ``interface`` was historically ambiguous. Keep it usable for old history
    # readers, but never let firmware output replace the requested line.
    result["interface"] = actual_interface
    status = str(result.get("status") or "").strip().lower()
    if status in {"completed", "success", "failed", "error", "timeout", "cancelled", "canceled"} and (
        (detected_interface and detected_interface != requested_interface)
        or (not detected_interface and requested_interface != "wan")
    ):
        result["status"] = "failed"
        result["error"] = "固件未确认请求线路的实际出口，结果不能归因到该 WAN"
        result["errorCode"] = "wan_mismatch"

    source_ipv4 = _nat_source_ipv4(result)
    if source_ipv4:
        result["source_ip"] = source_ipv4
        result["source_ipv4"] = source_ipv4
        result["sourceIp"] = source_ipv4
        result["sourceIpv4"] = source_ipv4
        result["sourceIPv4"] = source_ipv4

    started_at = _epoch_seconds(request_started_at)
    if started_at:
        result["request_started_at"] = started_at
        result["requestStartedAt"] = started_at
    if request_id:
        result["request_id"] = request_id
        result["requestId"] = request_id
    if task_id:
        result["task_id"] = task_id
        result["taskId"] = task_id

    timestamp = _nat_result_timestamp(result) if result_timestamp is None else _epoch_seconds(result_timestamp)
    if timestamp:
        result["timestamp"] = timestamp
        result["result_timestamp"] = timestamp
        result["resultTimestamp"] = timestamp
    return result


def _nat_terminal(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    normalized = _normalize_nat_payload(data)
    if not isinstance(normalized, dict):
        return False
    status = str(normalized.get("status") or "").strip().lower()
    if status in {"completed", "success", "failed", "error", "timeout", "cancelled", "canceled"}:
        return True
    if _first_text(normalized, "nat_type", "natType"):
        return True
    return bool(
        _first_text(normalized, "mapping_behavior", "mappingBehavior", "mapping")
        and _first_text(normalized, "filtering_behavior", "filteringBehavior", "filtering")
    )


def _nat_error_message(exc: Exception) -> str:
    raw = str(exc or "").strip()
    lower = raw.lower()
    if "timeout" in lower or "timed out" in lower:
        return "路由器 NAT 检测请求暂时无响应"
    if "unauthorized" in lower or "forbidden" in lower or "401" in lower or "403" in lower:
        return "路由器认证失效，请重新连接"
    if "resolve" in lower or "dns" in lower:
        return "STUN 服务器域名解析失败"
    return f"路由器 NAT 检测失败：{raw}" if raw else "路由器 NAT 检测失败"


def _beta_snapshot(data: Any, checked_at: int) -> Dict[str, Any]:
    if isinstance(data, dict):
        result = dict(data)
    else:
        result = {"raw": data}
    result["checkedAt"] = int(checked_at)
    return result


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
        nat_active = False
        nat_last_firmware_timestamp = 0
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

        beta_lock = threading.RLock()
        beta_result: Dict[str, Any] = {}
        beta_updated_at = 0.0

        def store_nat_result(
            generation: int,
            value: Any,
            requested: Dict[str, Any],
            correlation: Dict[str, Any],
        ) -> bool:
            nonlocal nat_result, nat_active, nat_last_firmware_timestamp
            with nat_lock:
                if generation != nat_generation:
                    return False
                if _nat_result_is_stale(
                    value,
                    int(correlation.get("requestStartedAt") or 0),
                    nat_last_firmware_timestamp,
                ):
                    logger.debug("router NAT stale firmware result ignored: %s", value)
                    return False
                firmware_timestamp = _nat_result_timestamp(value)
                normalized = _nat_result_with_request(
                    value,
                    requested,
                    request_id=str(correlation.get("requestId") or ""),
                    task_id=str(correlation.get("taskId") or ""),
                    request_started_at=int(correlation.get("requestStartedAt") or 0),
                    result_timestamp=firmware_timestamp or int(time.time()),
                )
                if not isinstance(normalized, dict):
                    normalized = _nat_result_with_request(
                        {"status": "running", "message": "检测进行中"},
                        requested,
                        request_id=str(correlation.get("requestId") or ""),
                        task_id=str(correlation.get("taskId") or ""),
                        request_started_at=int(correlation.get("requestStartedAt") or 0),
                        result_timestamp=int(time.time()),
                    )
                if _nat_terminal(normalized):
                    status = str(normalized.get("status") or "").strip().lower()
                    if status not in {"failed", "error", "timeout", "cancelled", "canceled"}:
                        normalized["status"] = "completed"
                normalized["updatedAt"] = int(time.time())
                if firmware_timestamp:
                    nat_last_firmware_timestamp = firmware_timestamp
                terminal = _nat_terminal(normalized)
                if terminal:
                    nat_active = False
                nat_result = dict(normalized)
                return terminal

        def run_nat_detection(
            generation: int,
            requested: Dict[str, Any],
            correlation: Dict[str, Any],
        ) -> None:
            try:
                start_data = client.rpc("devSta.set", "nat_detector", requested)
                if store_nat_result(generation, start_data, requested, correlation):
                    return
                deadline = time.monotonic() + NAT_MAX_RUNTIME_SECONDS
                while time.monotonic() < deadline:
                    with nat_lock:
                        if generation != nat_generation:
                            return
                    try:
                        latest = client.rpc("devSta.get", "nat_detector")
                        if store_nat_result(generation, latest, requested, correlation):
                            return
                    except Exception as poll_error:
                        # A single control-RPC timeout must not become the final NAT
                        # result. The router may still be retrying a STUN sub-test.
                        logger.debug("router NAT result poll deferred: %s", poll_error)
                    time.sleep(NAT_POLL_SECONDS)

                # One final router read before declaring the Hub-side maximum runtime.
                try:
                    latest = client.rpc("devSta.get", "nat_detector")
                    if store_nat_result(generation, latest, requested, correlation):
                        return
                except Exception as poll_error:
                    logger.debug("router NAT final poll deferred: %s", poll_error)

                store_nat_result(
                    generation,
                    {
                        "status": "error",
                        "message": "路由器长时间未返回最终检测结果",
                        "log": f"Hub 已等待 {int(NAT_MAX_RUNTIME_SECONDS)} 秒，路由器仍未返回最终状态",
                        "timeoutSource": "hub_max_runtime",
                    },
                    requested,
                    correlation,
                )
            except Exception as exc:
                message = _nat_error_message(exc)
                logger.warning("router NAT diagnostic failed: %s", exc)
                store_nat_result(
                    generation,
                    {"status": "error", "message": message, "log": message},
                    requested,
                    correlation,
                )

        @bp.get("/nat-diagnostic")
        def nat_diagnostic_get():
            with nat_lock:
                data = dict(nat_result)
            return jsonify({"ok": True, "data": data})

        @bp.post("/nat-diagnostic")
        def nat_diagnostic_start():
            nonlocal nat_generation, nat_active, nat_last_firmware_timestamp
            payload = normalize_nat_request(request.get_json(silent=True) or {})
            with nat_lock:
                if nat_active:
                    raise RouterRpcError(
                        "路由器 NAT 检测正在运行，请等待当前检测完成",
                        "NAT_DIAGNOSTIC_BUSY",
                        409,
                    )
                nat_generation += 1
                generation = nat_generation
                request_started_at = int(time.time())
                request_id = f"nat-request-{uuid.uuid4().hex[:12]}"
                task_id = f"nat-{generation}-{uuid.uuid4().hex[:12]}"
                correlation = {
                    "requestId": request_id,
                    "taskId": task_id,
                    "requestStartedAt": request_started_at,
                }
                nat_active = True
                nat_last_firmware_timestamp = 0
                last_nat_request.clear()
                last_nat_request.update(payload)
                nat_result = _nat_result_with_request(
                    {
                        "status": "running",
                        "message": "检测已启动",
                        "startedAt": request_started_at,
                    },
                    payload,
                    request_id=request_id,
                    task_id=task_id,
                    request_started_at=request_started_at,
                    result_timestamp=request_started_at,
                )
            threading.Thread(
                target=run_nat_detection,
                args=(generation, dict(payload), correlation),
                name=f"router-nat-diagnostic-{generation}",
                daemon=True,
            ).start()
            return jsonify({
                "ok": True,
                "message": "路由 NAT 诊断已在后台启动",
                "taskId": task_id,
                "requestId": request_id,
                "startedAt": request_started_at,
                "requestStartedAt": request_started_at,
                "requestedInterface": payload["interface"],
                "request": payload,
            }), 202

        @bp.get("/beta-upgrade")
        def beta_upgrade_get():
            nonlocal beta_result, beta_updated_at
            now = time.time()
            force = request.args.get("force") == "1"
            with beta_lock:
                if beta_result and not force and now - beta_updated_at <= BETA_CACHE_TTL_SECONDS:
                    return jsonify({"ok": True, "data": dict(beta_result), "cached": True})

            data = client.rpc("devSta.get", "ehr_beta_upgrade", {"action": "version"})
            snapshot = _beta_snapshot(data, int(time.time()))
            with beta_lock:
                beta_result = dict(snapshot)
                beta_updated_at = time.time()
            return jsonify({"ok": True, "data": snapshot, "cached": False})

        @bp.after_request
        def advertise_native_features(response: Any):
            if request.path.endswith("/api/router/capabilities") and response.is_json:
                root = response.get_json(silent=True)
                if isinstance(root, dict):
                    features = root.setdefault("features", {})
                    if isinstance(features, dict):
                        features["natDiagnostic"] = True
                        features.pop("natDiagnosticCancel", None)
                        features["betaUpgrade"] = True
                    response.set_data(jsonify(root).get_data())
                    response.content_type = "application/json"
            return response

        return bp

    v099.create_router_blueprint_v099 = wrapped_factory
    v099._labprobe_native_features_patch = True
