"""Read-only protocol adapter for the independently signed Shinya Hub client.

Each worker exposes only its own RouterService. Project identifiers and device
serial numbers are checked before reading, so a request cannot select another
router accidentally. Unsupported mutations never return a success envelope.
"""
from __future__ import annotations

import hmac
import time
from typing import Callable

from flask import Blueprint, jsonify, request


def project_snapshot(dashboard: dict) -> tuple[dict, dict]:
    details = dashboard.get("details") or {}
    ap = details.get("ap") or {}
    identity = details.get("identity") or {}
    telemetry = dashboard.get("telemetry") or {}
    sn = str(ap.get("serialNumber") or identity.get("serialNumber") or "").strip()
    if not sn:
        raise ValueError("router_identity_unavailable")
    project_id = "hub:" + sn
    name = str(dashboard.get("router") or ap.get("hostName") or identity.get("hostname") or sn)
    online = bool(dashboard.get("online"))
    project = {
        "buildingId": project_id, "projectId": project_id, "name": name,
        "projectName": name, "role": "OWNER", "online": online,
        "deviceCount": 1, "mainAp": sn, "accountId": "labprobe-hub",
    }
    router = {
        "sn": sn, "serialNumber": sn, "buildingId": project_id,
        "projectId": project_id, "name": name, "aliasName": name,
        "model": ap.get("model") or identity.get("model") or "",
        "productType": ap.get("model") or identity.get("model") or "",
        "hardware": ap.get("hardware") or "",
        "software": ap.get("software") or "", "version": ap.get("software") or "",
        "mac": (details.get("lan") or {}).get("mac") or "",
        "ip": ap.get("managementIp") or (details.get("lan") or {}).get("ipv4") or "",
        "status": "ON" if online else "OFF", "online": online, "isOnline": online,
        "forwardMode": ap.get("forwardMode") or "ROUTER",
        "workMode": ap.get("workMode") or "ROUTER",
        "staCount": telemetry.get("onlineDeviceCount"),
        "staNum": telemetry.get("onlineDeviceCount"),
        "temperature": telemetry.get("temperatureC"),
        "cpuUsage": telemetry.get("cpuPercent"),
        "memoryUsage": telemetry.get("memoryPercent"),
        "uptime": telemetry.get("uptimeSeconds"),
        "remotectrl": "0", "supportLanInfo": "0", "childGuardVer": "0",
        "gameTurbo": "0", "syAi": "0", "capabilities": {},
    }
    return project, router


def station_snapshot(device: dict, router: dict) -> dict:
    # Preserve the raw RouterService fields and MAC identity. The original
    # client's local rename/icon overlays continue to operate on the same MAC.
    item = dict(device)
    item.update({
        "mac": str(device.get("mac") or "").lower(),
        "ip": device.get("ipv4") or device.get("userIp") or "",
        "type": device.get("devType") or "others",
        "remark": device.get("name") or device.get("deviceAliasName") or "",
        "recommend": device.get("devRecommend") or "",
        "apSn": router["sn"], "sn": router["sn"],
        "buildingId": router["buildingId"], "projectId": router["projectId"],
        "online": bool(device.get("online")),
        "connectType": device.get("connectType") or "",
        "firstOnlineTime": device.get("firstOnlineTime") or "",
        "activetime": device.get("activeTime") or device.get("onlinetime") or "",
        "inactivetime": device.get("inactiveTime") or "",
    })
    return item


def create_shinya_blueprint(service, tokens: Callable[[], list[str]], logger=None):
    bp = Blueprint("shinya_hub_compat", __name__)
    login_path = "base/homeUser/accountPasswordLogin"
    user = {"accountId": "labprobe-hub", "userName": "Hub 管理员", "name": "Hub 管理员",
            "phone": "", "email": "", "gender": "", "externalId": ""}

    def envelope(data=None, code=0, message=""):
        response = jsonify({"code": code, "data": data, "msg": message})
        response.headers["Cache-Control"] = "no-store"
        return response

    def accepted(token):
        if not isinstance(token, str) or not token:
            return False
        return any(hmac.compare_digest(token.encode("utf-8"), value.encode("utf-8"))
                   for value in tokens() if value)

    def bearer():
        scheme, _, token = request.headers.get("Authorization", "").partition(" ")
        return token if scheme.lower() == "bearer" else ""

    def token_result(token):
        # Hub APP Tokens remain governed by Hub configuration/rotation. The
        # compatibility expiry only schedules the original client's refresh.
        return {"token": token, "expireTime": int((time.time() + 86400) * 1000)}

    @bp.route("/api/v1/<path:resource>", methods=["GET", "POST", "PUT", "DELETE"])
    @bp.route("/homewlan/<path:resource>", methods=["GET", "POST", "PUT", "DELETE"])
    def dispatch(resource):
        raw = request.get_json(silent=True) or {}
        if not isinstance(raw, dict):
            return envelope(code=400, message="请求参数无效")
        if request.path.startswith("/api/v1/") and resource == login_path:
            if request.method != "POST":
                return envelope(code=405, message="登录请求方式无效")
            token = raw.get("password", "")
            if not accepted(token):
                return envelope(code=401, message="APP Token 不正确")
            return envelope(token_result(token))
        if not accepted(bearer()):
            return envelope(code=401, message="请重新登录 Hub")
        if resource == "base/homeUser/info":
            return envelope(user)
        if resource == "base/homeUser/refreshToken":
            return envelope(token_result(bearer()))
        if resource == "base/homeUser/logout":
            return envelope({"loggedOut": True})
        if request.method not in {"GET", "POST"}:
            return envelope(code=501, message="此操作尚未接入 Hub")

        reads = {
            "apMonitor/getProjectList2", "homeAp/getDeviceInfoList2",
            "homeAp/getStaList2", "homeDetail/getStaList2",
            "experienceVisual/getApOverview",
        }
        if resource not in reads:
            return envelope(code=501, message="此功能尚未接入 Hub")
        try:
            dashboard = service.get_dashboard(force=False)
            project, router = project_snapshot(dashboard)
            for field in ("projectId", "buildingId"):
                selected = raw.get(field) or request.headers.get("projectId")
                if selected and str(selected) != project["projectId"]:
                    return envelope(code=404, message="当前 Hub 中没有这台路由器")
            for field in ("sn", "apSn", "deviceSn"):
                if raw.get(field) and str(raw[field]) != router["sn"]:
                    return envelope(code=404, message="当前 Hub 中没有这台路由器")
            if resource == "apMonitor/getProjectList2":
                return envelope({"dataList": [project], "total": 1})
            if resource == "homeAp/getDeviceInfoList2":
                return envelope({"apList": [router], "mainAp": router["sn"]})
            if resource in {"homeAp/getStaList2", "homeDetail/getStaList2"}:
                stations = [station_snapshot(d, router) for d in service.get_devices(force=False)]
                return envelope({"sta_list": stations})
            telemetry = dashboard.get("telemetry") or {}
            return envelope({
                **router, "apList": [router],
                "staCount": telemetry.get("onlineDeviceCount"),
                "wan": telemetry.get("wan") or {},
                "cpuUsage": telemetry.get("cpuPercent"),
                "memoryUsage": telemetry.get("memoryPercent"),
                "temperature": telemetry.get("temperatureC"),
            })
        except Exception as error:
            if logger:
                # Do not log request bodies: login bodies contain the APP Token.
                logger.warning("Shinya Hub read failed path=%s type=%s", resource, type(error).__name__)
            return envelope(code=503, message="路由器数据暂不可用，请刷新")

    return bp


def install_shinya_compat(hub):
    if "shinya_hub_compat" in hub.app.blueprints:
        return
    hub.app.register_blueprint(create_shinya_blueprint(hub.ROUTER_SERVICE, hub.get_app_tokens, hub.LOGGER))
    # Router Core owns its narrow locks. These reads must not block unrelated
    # Hub synchronization behind the global state lock.
    hub.DATA_LOCK_BYPASS_PREFIXES = tuple(hub.DATA_LOCK_BYPASS_PREFIXES) + ("/homewlan", "/api/v1")
