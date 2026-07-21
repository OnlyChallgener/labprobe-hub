"""Reliable Ruijie/Reyee router RPC runtime for LabProbe Hub 0.9.9.

Adds token-authenticated RPC, persistent connection status, background
session keepalive, and an APP-facing config response that can restore the
user-entered password for masked/eye-toggle display.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict

import requests
from flask import Blueprint, jsonify, request

from router_rpc import (
    DEFAULT_ROUTER_URL,
    HUB_ROUTER_API_VERSION,
    EncryptedRouterConfigStore,
    GLOBAL_ROUTER_SESSION_CACHE,
    RouterAuthExpired,
    RouterController,
    RouterNotConfigured,
    RouterRpcError,
    RuijieRouterClient,
    _json_error,
    _safe_int,
    _wire_json,
)


class ReliableRuijieRouterClient(RuijieRouterClient):
    """Router client with firmware-compatible API paths and health state."""

    def __init__(self, store: EncryptedRouterConfigStore, logger: Any):
        super().__init__(store, logger)
        self.http.headers["User-Agent"] = "LabProbe-Hub/0.9.9"
        self._status_lock = threading.RLock()
        self.last_success_at = 0.0
        self.last_error = ""
        self.last_error_code = ""

    def _mark_success(self) -> None:
        with self._status_lock:
            self.last_success_at = time.time()
            self.last_error = ""
            self.last_error_code = ""

    def _mark_failure(self, exc: Exception) -> None:
        with self._status_lock:
            self.last_error = str(exc)
            self.last_error_code = getattr(exc, "code", type(exc).__name__)

    def login(self, force: bool = False):
        try:
            session = super().login(force=force)
            self._mark_success()
            return session
        except Exception as exc:
            self._mark_failure(exc)
            raise

    def _post_api(self, api_path: str, payload: Dict[str, Any], retry_auth: bool = True) -> Any:
        session = self.login()
        cfg = self.config
        wire = _wire_json(payload)
        auth_token = session.auth
        url = cfg["address"] + f"/cgi-bin/luci/api/{api_path}?auth={auth_token}"
        safe_url = cfg["address"] + f"/cgi-bin/luci/api/{api_path}?auth=<redacted>"
        self.logger.debug(
            "router eweb rpc request method=POST url=%s auth_present=%s",
            safe_url,
            bool(auth_token),
        )

        try:
            response = self.http.post(
                url,
                data=wire.encode("utf-8"),
                headers=self._headers_for(payload, session),
                timeout=(4, 15),
                verify=cfg["verifyTls"],
                allow_redirects=True,
            )
        except requests.Timeout as exc:
            error = RouterRpcError("Router RPC timed out", "RPC_TIMEOUT", 504)
            self._mark_failure(error)
            raise error from exc
        except requests.RequestException as exc:
            error = RouterRpcError(f"Router RPC request failed: {exc}", "ROUTER_UNREACHABLE", 502)
            self._mark_failure(error)
            raise error from exc

        if response.status_code in {401, 403}:
            config_key = self._session_cache_key(cfg)
            self.logger.warning(
                "router eweb rpc auth rejected api=%s final_status=%s request_url=%s cookie_names=%s auth_present=%s",
                api_path,
                response.status_code,
                safe_url,
                sorted({cookie.name for cookie in self.http.cookies}),
                bool(auth_token),
            )
            with self.login_lock:
                current_session_failed = self.session is session
                if current_session_failed:
                    self.clear_session()
                    if retry_auth:
                        self.login(force=True)
                    else:
                        GLOBAL_ROUTER_SESSION_CACHE.block_login(config_key)
            if retry_auth:
                return self._post_api(api_path, payload, retry_auth=False)
            error = RouterAuthExpired()
            self._mark_failure(error)
            raise error

        if response.status_code >= 400:
            error = RouterRpcError(
                f"Router returned HTTP {response.status_code}",
                "RPC_HTTP_ERROR",
                502,
            )
            self._mark_failure(error)
            raise error
        try:
            root = response.json()
        except ValueError as exc:
            error = RouterRpcError(
                "Router returned a login page without HTTP 401/403"
                if self._looks_like_login_page(response.text)
                else "Router returned an invalid RPC response",
                "RPC_INVALID_RESPONSE",
                502,
            )
            self._mark_failure(error)
            raise error from exc
        if isinstance(root, dict) and root.get("error"):
            message = root["error"].get("message") if isinstance(root["error"], dict) else str(root["error"])
            error = RouterRpcError(message or "Router rejected the RPC operation", "RPC_REJECTED", 409)
            self._mark_failure(error)
            raise error
        self._mark_success()
        return root.get("data") if isinstance(root, dict) and "data" in root else root

    def status(self, probe: bool = False) -> Dict[str, Any]:
        cfg = self.config
        configured = bool(cfg.get("address") and cfg.get("password"))
        if probe and configured:
            try:
                self.rpc("acConfig.get", "network_group", no_parse=True)
            except Exception:
                pass
        now = time.time()
        remaining = 0
        if self.session.sid:
            remaining = max(0, int(self.session.session_seconds - (now - self.session.obtained_at)))
        with self._status_lock:
            connected = bool(configured and self.session.valid_locally and not self.last_error)
            return {
                "configured": configured,
                "connected": connected,
                "sessionActive": self.session.valid_locally,
                "sessionRemainingSeconds": remaining,
                "lastSuccessAt": int(self.last_success_at),
                "lastError": self.last_error,
                "lastErrorCode": self.last_error_code,
                "statusText": "已连接" if connected else ("连接异常" if configured else "未配置"),
                "serialNumber": self.session.serial_number,
            }


def _start_keepalive(client: ReliableRuijieRouterClient, logger: Any) -> None:
    def worker() -> None:
        while True:
            cfg = client.config
            sleep_seconds = max(30, min(180, int(cfg.get("sessionSeconds", 3600)) // 4))
            if cfg.get("address") and cfg.get("password"):
                try:
                    client.rpc("acConfig.get", "network_group", no_parse=True)
                except RouterNotConfigured:
                    pass
                except Exception as exc:
                    logger.debug("router keepalive failed: %s", exc)
            time.sleep(sleep_seconds)

    threading.Thread(target=worker, name="router-eweb-keepalive", daemon=True).start()


def create_router_blueprint_v099(check_app_token: Callable[[], bool], logger: Any, config_dir: Path) -> Blueprint:
    store = EncryptedRouterConfigStore(config_dir)
    client = ReliableRuijieRouterClient(store, logger)
    controller = RouterController(client)
    bp = Blueprint("router_rpc", __name__, url_prefix="/api/router")
    _start_keepalive(client, logger)

    @bp.before_request
    def _authorize():
        if not check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return None

    @bp.errorhandler(Exception)
    def _handle(error: Exception):
        logger.warning("router api error path=%s type=%s message=%s", request.path, type(error).__name__, error)
        return _json_error(error)

    def config_response(include_secret: bool = False, probe: bool = False):
        cfg = client.config
        state = client.status(probe=probe)
        body = {
            "ok": True,
            "address": cfg.get("address", ""),
            "passwordConfigured": bool(cfg.get("password")),
            "sessionSeconds": cfg.get("sessionSeconds", 3600),
            "verifyTls": cfg.get("verifyTls", False),
            **state,
        }
        if include_secret:
            body["password"] = cfg.get("password", "")
        return body

    @bp.get("/config")
    def get_config():
        return jsonify(config_response(request.args.get("includeSecret") == "1", request.args.get("probe") == "1"))
    @bp.get("/status")
    def get_status():
        """Return an App-safe Hub status without exposing eWeb session details."""
        state = client.status(probe=False)
        configured = bool(state.get("configured"))
        connected = bool(state.get("connected"))
        error_code = str(state.get("lastErrorCode") or "")
        error_message = str(state.get("lastError") or "")
        if connected:
            status = "ready"
            message = "Hub is connected to the router"
        elif not configured:
            status = "no_router_data"
            error_code = "HUB_NO_ROUTER_DATA"
            message = "Hub is online, but router data has not been configured"
        elif error_code:
            status = "router_login_failed"
            message = error_message or "Hub could not log in to the router"
        else:
            status = "no_router_data"
            error_code = "HUB_NO_ROUTER_DATA"
            message = "Hub is online and waiting for router data"
        return jsonify({
            "ok": True,
            "state": status,
            "connected": connected,
            "message": message,
            "errorCode": error_code,
            "lastSuccessAt": int(state.get("lastSuccessAt") or 0),
        })

    @bp.put("/config")
    def put_config():
        body = request.get_json(silent=True) or {}
        address = body.get("address") or client.config.get("address") or DEFAULT_ROUTER_URL
        password = body.get("password") if "password" in body else None
        seconds = _safe_int(body.get("sessionSeconds"), client.config.get("sessionSeconds", 3600), 600, 7200)
        store.save(address, password, seconds, bool(body.get("verifyTls", False)))
        client.clear_session()
        if bool(body.get("test", True)):
            client.login()
            client.rpc("acConfig.get", "network_group", no_parse=True)
        return jsonify(config_response(include_secret=True, probe=False))

    @bp.post("/session/test")
    def test_session():
        client.login()
        client.rpc("acConfig.get", "network_group", no_parse=True)
        return jsonify(config_response(False, False))

    @bp.post("/session/logout")
    def logout_session():
        client.logout()
        return jsonify({"ok": True})

    @bp.get("/capabilities")
    def capabilities():
        return jsonify({
            "ok": True,
            "apiVersion": HUB_ROUTER_API_VERSION,
            "configured": bool(client.config.get("password")),
            "features": {
                "dashboard": True,
                "devices": True,
                "firewall": True,
                "nativePortMapping": True,
                "upnp": True,
                "ddns": True,
                "diagnostic": True,
            },
        })

    @bp.get("/dashboard")
    def dashboard():
        return jsonify({"ok": True, "data": client.dashboard(request.args.get("force") == "1")})

    @bp.get("/devices")
    def devices():
        return jsonify({"ok": True, "data": client.devices(request.args.get("force") == "1")})

    @bp.get("/firewall")
    def firewall_get():
        return jsonify({"ok": True, "data": client.firewall(request.args.get("force") == "1")})

    @bp.post("/firewall/rules")
    def firewall_add():
        body = request.get_json(silent=True) or {}
        return jsonify(controller.write_and_verify("firewall", lambda: client.rpc("devConfig.add", "ip_firewall", {"list": [body]}), lambda: client.firewall(True)))

    @bp.put("/firewall/rules/<uuid>")
    def firewall_update(uuid: str):
        body = request.get_json(silent=True) or {}
        body["uuid"] = uuid
        return jsonify(controller.write_and_verify("firewall", lambda: client.rpc("devConfig.update", "ip_firewall", {"list": [body]}), lambda: client.firewall(True)))

    @bp.patch("/firewall/rules/<uuid>/enabled")
    def firewall_enabled(uuid: str):
        enabled = "1" if bool((request.get_json(silent=True) or {}).get("enabled")) else "0"
        return jsonify(controller.write_and_verify("firewall", lambda: client.rpc("devConfig.update", "ip_firewall", {"list": [{"uuid": uuid, "enable": enabled}]}), lambda: client.firewall(True)))

    @bp.delete("/firewall/rules/<uuid>")
    def firewall_delete(uuid: str):
        return jsonify(controller.write_and_verify("firewall", lambda: client.rpc("devConfig.del", "ip_firewall", {"uuid": [uuid]}), lambda: client.firewall(True)))

    @bp.post("/firewall/reorder")
    def firewall_reorder():
        body = request.get_json(silent=True) or {}
        scope = str(body.get("scope") or "")
        allowed = {"inbound_ipv4", "inbound_ipv6", "outbound_ipv4", "outbound_ipv6", "forward_ipv4", "forward_ipv6"}
        if scope not in allowed:
            raise RouterRpcError("防火墙排序范围无效", "INVALID_SCOPE", 400)
        uuids = [str(v) for v in body.get("uuids", []) if str(v)]
        return jsonify(controller.write_and_verify("firewall", lambda: client.rpc("devConfig.update", "ip_firewall", {"op": "reorder", "scope": scope, "uuids": uuids}), lambda: client.firewall(True)))

    @bp.get("/port-mapping")
    def port_mapping_get():
        return jsonify({"ok": True, "data": client.native_port_mapping(request.args.get("force") == "1")})

    @bp.post("/port-mapping")
    def port_mapping_add():
        body = request.get_json(silent=True) or {}
        return jsonify(controller.write_and_verify("native-portmap", lambda: client.rpc("devConfig.add", "port_mapping", {"list": [body]}), lambda: client.native_port_mapping(True)))

    @bp.put("/port-mapping/<path:rule_name>")
    def port_mapping_update(rule_name: str):
        body = request.get_json(silent=True) or {}
        latest = client.native_port_mapping(True)
        rows = latest.get("portMapping") or latest.get("list") or []
        old = next((row for row in rows if isinstance(row, dict) and str(row.get("ruleName")) == rule_name), None)
        if old is None:
            raise RouterRpcError("端口映射规则不存在", "RULE_NOT_FOUND", 404)
        return jsonify(controller.write_and_verify("native-portmap", lambda: client.rpc("devConfig.update", "port_mapping", {"old": old, "new": body}), lambda: client.native_port_mapping(True)))

    @bp.delete("/port-mapping/<path:rule_name>")
    def port_mapping_delete(rule_name: str):
        return jsonify(controller.write_and_verify("native-portmap", lambda: client.rpc("devConfig.del", "port_mapping", {"ruleName": [rule_name]}), lambda: client.native_port_mapping(True)))

    @bp.get("/upnp")
    def upnp_get():
        return jsonify({"ok": True, "data": client.upnp(request.args.get("force") == "1")})

    @bp.put("/upnp")
    def upnp_put():
        body = request.get_json(silent=True) or {}
        latest = client.upnp(True)
        payload = {
            "enable_upnp": "true" if bool(body.get("enabled")) else "false",
            "upnpds": latest.get("upnpds") or [],
            "upnp_line": str(latest.get("upnp_line") or "1"),
            "wan": str(body.get("wan") or latest.get("wan") or "AUTO").upper(),
        }
        return jsonify(controller.write_and_verify("upnp", lambda: client.rpc("devSta.set", "upnp", payload), lambda: client.upnp(True)))

    @bp.get("/ddns")
    def ddns_get():
        return jsonify({"ok": True, "data": client.ddns(request.args.get("force") == "1")})

    @bp.post("/ddns")
    def ddns_add():
        body = request.get_json(silent=True) or {}
        return jsonify(controller.write_and_verify("ddns", lambda: client.rpc("devSta.add", "ddnsCfg", body), lambda: client.ddns(True)))

    @bp.put("/ddns/<service_id>")
    def ddns_update(service_id: str):
        body = request.get_json(silent=True) or {}
        current = client.rpc("devSta.get", "ddnsCfg")
        rows = (current.get("list") or current.get("data") or []) if isinstance(current, dict) else []
        old = next((row for row in rows if isinstance(row, dict) and str(row.get("service")) == service_id), {})
        merged = {**old, **body, "service": service_id}
        merged.pop("status", None)
        merged.pop("ip", None)
        if not body.get("password"):
            merged["password"] = old.get("password", "")
        return jsonify(controller.write_and_verify("ddns", lambda: client.rpc("devSta.update", "ddnsCfg", {"data": [merged]}), lambda: client.ddns(True)))

    @bp.delete("/ddns/<service_id>")
    def ddns_delete(service_id: str):
        return jsonify(controller.write_and_verify("ddns", lambda: client.rpc("devSta.del", "ddnsCfg", {"data": [service_id]}), lambda: client.ddns(True)))

    @bp.get("/diagnostic")
    def diagnostic_get():
        return jsonify({"ok": True, "data": client.rpc("devSta.get", "dev_diag")})

    @bp.post("/diagnostic")
    def diagnostic_start():
        client.rpc("devSta.set", "dev_diag", {"user": "eweb", "action": "start"})
        return jsonify({"ok": True, "message": "诊断已启动", "startedAt": int(time.time())})

    return bp
