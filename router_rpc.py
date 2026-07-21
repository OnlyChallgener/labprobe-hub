"""Ruijie eWeb RPC adapter for LabProbe Hub.

Only exposes a strict product-level whitelist. The Android client never sees
router credentials, sid/stok, or arbitrary RPC method names.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Blueprint, jsonify, request

HUB_ROUTER_API_VERSION = "1.0"
DEFAULT_ROUTER_URL = "http://192.168.5.1"
LOGIN_AES_PASSWORD = "RjYkhwzx$2018!"
REQUEST_SIGN_SECRET = "Web@Rj$2020!"


class RouterRpcError(RuntimeError):
    def __init__(self, message: str, code: str = "ROUTER_RPC_FAILED", http_status: int = 502):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


class RouterAuthExpired(RouterRpcError):
    def __init__(self, message: str = "路由器登录会话已失效"):
        super().__init__(message, "AUTH_EXPIRED", 401)


class RouterNotConfigured(RouterRpcError):
    def __init__(self):
        super().__init__("尚未配置路由器管理地址和密码", "ROUTER_NOT_CONFIGURED", 409)


def _clean_url(value: Any) -> str:
    raw = str(value or "").strip().rstrip("/")
    if not raw:
        return ""
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError("路由器地址无效")
    return raw


def _safe_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16) -> Tuple[bytes, bytes]:
    material = b""
    previous = b""
    while len(material) < key_len + iv_len:
        previous = hashlib.md5(previous + password + salt).digest()
        material += previous
    return material[:key_len], material[key_len:key_len + iv_len]


def gibberish_aes_encrypt(plain_text: str, password: str = LOGIN_AES_PASSWORD) -> str:
    """Compatible with GibberishAES.enc/OpenSSL salted AES-256-CBC."""
    salt = secrets.token_bytes(8)
    key, iv = _evp_bytes_to_key(password.encode("utf-8"), salt)
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plain_text.encode("utf-8"), AES.block_size))
    return base64.b64encode(b"Salted__" + salt + encrypted).decode("ascii")


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _wire_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _deep_strip_runtime_fields(value: Any) -> Any:
    if isinstance(value, list):
        return [_deep_strip_runtime_fields(v) for v in value]
    if isinstance(value, dict):
        return {
            k: _deep_strip_runtime_fields(v)
            for k, v in value.items()
            if k not in {"configId", "configTime", "currentTime"}
        }
    return value.strip() if isinstance(value, str) else value


class EncryptedRouterConfigStore:
    """Persist the router password encrypted at rest with AES-GCM."""

    def __init__(self, config_dir: Path):
        self.path = config_dir / "router_eweb.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        source = (os.environ.get("ROUTER_CONFIG_KEY") or os.environ.get("APP_TOKEN") or "labprobe-router-config").encode("utf-8")
        self.key = hashlib.sha256(source).digest()
        self._lock = threading.RLock()

    def _encrypt(self, plain: str) -> Dict[str, str]:
        cipher = AES.new(self.key, AES.MODE_GCM)
        encrypted, tag = cipher.encrypt_and_digest(plain.encode("utf-8"))
        return {
            "nonce": base64.b64encode(cipher.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(encrypted).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
        }

    def _decrypt(self, payload: Dict[str, Any]) -> str:
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=base64.b64decode(payload["nonce"]))
        return cipher.decrypt_and_verify(base64.b64decode(payload["ciphertext"]), base64.b64decode(payload["tag"])).decode("utf-8")

    def load(self) -> Dict[str, Any]:
        with self._lock:
            saved: Dict[str, Any] = {}
            if self.path.exists():
                try:
                    saved = json.loads(self.path.read_text(encoding="utf-8"))
                except Exception:
                    saved = {}
            address = _clean_url(os.environ.get("ROUTER_EWEB_URL") or saved.get("address") or DEFAULT_ROUTER_URL)
            session_seconds = _safe_int(os.environ.get("ROUTER_SESSION_TIME") or saved.get("sessionSeconds"), 3600, 600, 7200)
            password = os.environ.get("ROUTER_EWEB_PASSWORD", "")
            if not password and isinstance(saved.get("passwordEncrypted"), dict):
                try:
                    password = self._decrypt(saved["passwordEncrypted"])
                except Exception:
                    password = ""
            return {
                "address": address,
                "password": password,
                "sessionSeconds": session_seconds,
                "verifyTls": str(os.environ.get("ROUTER_VERIFY_TLS") or saved.get("verifyTls") or "false").lower() == "true",
            }

    def save(self, address: str, password: Optional[str], session_seconds: int, verify_tls: bool = False) -> Dict[str, Any]:
        with self._lock:
            old = self.load()
            actual_password = old.get("password", "") if password is None else password
            payload = {
                "address": _clean_url(address),
                "sessionSeconds": _safe_int(session_seconds, 3600, 600, 7200),
                "verifyTls": bool(verify_tls),
                "updatedAt": int(time.time()),
                "passwordEncrypted": self._encrypt(actual_password) if actual_password else None,
            }
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            os.chmod(tmp, 0o600)
            tmp.replace(self.path)
            os.chmod(self.path, 0o600)
            return self.load()


@dataclass
class RouterSession:
    sid: str = ""
    stok: str = ""
    serial_number: str = ""
    obtained_at: float = 0.0
    session_seconds: int = 3600

    @property
    def valid_locally(self) -> bool:
        # The Hub owns the browser session. Renew it before fewer than five
        # minutes remain, rather than letting a dashboard request race an
        # expiring BE72 eWeb SID.
        return bool(self.sid) and time.time() - self.obtained_at < max(60, self.session_seconds - 300)


class TinyTtlCache:
    def __init__(self):
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.RLock()

    def get(self, key: str, ttl: float) -> Any:
        with self._lock:
            row = self._data.get(key)
            if not row or time.time() - row[0] > ttl:
                return None
            return row[1]

    def put(self, key: str, value: Any) -> Any:
        with self._lock:
            self._data[key] = (time.time(), value)
        return value

    def clear(self, prefix: str = "") -> None:
        with self._lock:
            if not prefix:
                self._data.clear()
            else:
                for key in list(self._data):
                    if key.startswith(prefix):
                        self._data.pop(key, None)


class RuijieRouterClient:
    def __init__(self, store: EncryptedRouterConfigStore, logger: Any):
        self.store = store
        self.logger = logger
        self.http = requests.Session()
        self.http.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "LabProbe-Hub/0.9.8",
        })
        self.session = RouterSession()
        self.login_lock = threading.RLock()
        self.write_lock = threading.RLock()
        self.cache = TinyTtlCache()

    @property
    def config(self) -> Dict[str, Any]:
        return self.store.load()

    def clear_session(self) -> None:
        with self.login_lock:
            self.session = RouterSession()
            self.http.cookies.clear()

    @staticmethod
    def _extract_token(text: str, name: str) -> str:
        patterns = [
            rf"\bvar\s+{re.escape(name)}\s*=\s*['\"]([^'\"]+)['\"]",
            rf"\b{name}\s*[:=]\s*['\"]([^'\"]+)['\"]",
            rf";{re.escape(name)}=([A-Za-z0-9]+)",
        ]
        for pattern in patterns:
            found = re.search(pattern, text or "", re.I)
            if found:
                return found.group(1).strip()
        return ""

    @staticmethod
    def _looks_like_login_page(text: str) -> bool:
        low = (text or "").lower()
        return 'id="password"' in low and 'id="login"' in low and "api/auth" in low

    def login(self, force: bool = False) -> RouterSession:
        with self.login_lock:
            if not force and self.session.valid_locally:
                return self.session
            cfg = self.config
            if not cfg.get("address") or not cfg.get("password"):
                raise RouterNotConfigured()
            self.http.cookies.clear()
            body = {
                "method": "login",
                "params": {
                    "password": gibberish_aes_encrypt(str(cfg["password"])),
                    "time": str(int(time.time())),
                    "encry": True,
                    "limit": False,
                    "setInit": False,
                },
            }
            try:
                response = self.http.post(
                    cfg["address"] + "/cgi-bin/luci/api/auth",
                    data=_wire_json(body).encode("utf-8"),
                    timeout=(4, 10),
                    verify=cfg["verifyTls"],
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                raise RouterRpcError(f"无法连接路由器：{exc}", "ROUTER_UNREACHABLE", 502) from exc

            auth_data: Dict[str, Any] = {}
            try:
                auth_root = response.json()
                if isinstance(auth_root, dict):
                    nested = auth_root.get("data")
                    auth_data = nested if isinstance(nested, dict) else auth_root
            except ValueError:
                pass

            candidates: List[requests.Response] = list(response.history) + [response]
            page_text = response.text or ""
            sid = str(auth_data.get("sid") or "").strip()
            stok = str(auth_data.get("token") or auth_data.get("stok") or "").strip()
            serial = str(auth_data.get("sn") or auth_data.get("serialNumber") or "").strip()
            session_seconds = _safe_int(
                auth_data.get("sessiontime") or auth_data.get("sessionTime"),
                cfg["sessionSeconds"],
                600,
                7200,
            )
            for item in candidates:
                stok = stok or self._extract_token(item.url, "stok")
                stok = stok or self._extract_token(item.headers.get("Location", ""), "stok")
                stok = stok or self._extract_token(item.text or "", "stok")

            root_urls = []
            if stok:
                root_urls.append(cfg["address"] + f"/cgi-bin/luci/;stok={stok}")
            root_urls.append(cfg["address"] + "/cgi-bin/luci/")
            for url in root_urls:
                try:
                    page = self.http.get(url, timeout=(4, 10), verify=cfg["verifyTls"], allow_redirects=True)
                except requests.RequestException:
                    continue
                page_text = page.text or ""
                if self._looks_like_login_page(page_text):
                    continue
                stok = stok or self._extract_token(page.url, "stok") or self._extract_token(page_text, "stok")
                sid = sid or self._extract_token(page_text, "sid")
                serial = serial or self._extract_token(page_text, "sn")
                session_seconds = _safe_int(self._extract_token(page_text, "sessiontime"), session_seconds, 600, 7200)
                if sid:
                    break

            if not sid:
                self.clear_session()
                raise RouterRpcError("路由器登录失败，请检查管理密码", "LOGIN_FAILED", 401)

            self.session = RouterSession(
                sid=sid,
                stok=stok,
                serial_number=serial,
                obtained_at=time.time(),
                session_seconds=session_seconds,
            )
            self._set_session_time(cfg["sessionSeconds"])
            self.logger.info("router eweb login ok address=%s sn=%s session=%ss", cfg["address"], serial or "unknown", cfg["sessionSeconds"])
            return self.session

    def _headers_for(self, payload: Dict[str, Any], session: Optional[RouterSession] = None) -> Dict[str, str]:
        stable = _stable_json(payload)
        wire = _wire_json(payload)
        return {
            "Content-Accept": hashlib.md5((REQUEST_SIGN_SECRET + stable).encode("utf-8")).hexdigest(),
            "Contents-Accept": hashlib.md5((REQUEST_SIGN_SECRET + wire).encode("utf-8")).hexdigest(),
        }

    def _post_api(self, api_path: str, payload: Dict[str, Any], retry_auth: bool = True) -> Any:
        session = self.login()
        cfg = self.config
        auth_token = session.stok or session.sid
        url = cfg["address"] + f"/cgi-bin/luci/api/{api_path}?auth={auth_token}"
        wire = _wire_json(payload)
        try:
            response = self.http.post(
                url,
                data=wire.encode("utf-8"),
                headers=self._headers_for(payload),
                timeout=(4, 15),
                verify=cfg["verifyTls"],
            )
        except requests.Timeout as exc:
            raise RouterRpcError("路由器响应超时", "RPC_TIMEOUT", 504) from exc
        except requests.RequestException as exc:
            raise RouterRpcError(f"路由器请求失败：{exc}", "ROUTER_UNREACHABLE", 502) from exc
        if response.status_code in {401, 403}:
            self.clear_session()
            if retry_auth:
                self.login(force=True)
                return self._post_api(api_path, payload, retry_auth=False)
            raise RouterAuthExpired()
        if response.status_code >= 400:
            raise RouterRpcError(f"路由器返回 HTTP {response.status_code}", "RPC_HTTP_ERROR", 502)
        try:
            root = response.json()
        except ValueError as exc:
            if self._looks_like_login_page(response.text):
                self.clear_session()
                raise RouterAuthExpired() from exc
            raise RouterRpcError("路由器返回了无法解析的数据", "RPC_INVALID_RESPONSE", 502) from exc
        if isinstance(root, dict) and root.get("error"):
            message = root["error"].get("message") if isinstance(root["error"], dict) else str(root["error"])
            raise RouterRpcError(message or "路由器拒绝了操作", "RPC_REJECTED", 409)
        return root.get("data") if isinstance(root, dict) and "data" in root else root

    def _set_session_time(self, seconds: int) -> None:
        seconds = _safe_int(seconds, 3600, 600, 7200)
        try:
            self._post_api("common", {"method": "setSessionTime", "params": {"sessiontime": str(seconds)}}, retry_auth=False)
            self.session.session_seconds = seconds
            self.session.obtained_at = time.time()
        except Exception as exc:
            self.logger.warning("router setSessionTime failed: %s", exc)

    def logout(self) -> None:
        if self.session.sid:
            try:
                self._post_api("common", {"method": "logout", "params": {}}, retry_auth=False)
            except Exception:
                pass
        self.clear_session()

    def rpc(self, method: str, module: str, data: Any = None, no_parse: bool = False) -> Any:
        params: Dict[str, Any] = {
            "module": module,
            "noParse": bool(no_parse),
            "async": None,
            "remoteIp": False,
            "device": "pc",
        }
        if data is not None:
            params["data"] = _deep_strip_runtime_fields(data)
        return self._post_api("cmd", {"method": method, "params": params})

    def batch(self, calls: Iterable[Dict[str, Any]]) -> Any:
        rows = []
        for call in calls:
            params: Dict[str, Any] = {
                "module": call["module"],
                "noParse": bool(call.get("noParse", False)),
                "async": None,
                "remoteIp": False,
            }
            if "data" in call:
                params["data"] = _deep_strip_runtime_fields(call["data"])
            rows.append({"method": call["method"], "params": params})
        return self._post_api("cmd", {"method": "cmdArr", "params": {"device": "pc", "params": rows}})

    def cached(self, key: str, ttl: float, loader: Callable[[], Any], force: bool = False) -> Any:
        if not force:
            cached = self.cache.get(key, ttl)
            if cached is not None:
                return cached
        return self.cache.put(key, loader())

    def devices(self, force: bool = False) -> Dict[str, Any]:
        def load() -> Dict[str, Any]:
            raw = self.rpc("devSta.get", "user_list", {"devType": "all", "dataType": "timely"}, no_parse=True)
            if isinstance(raw, str):
                raw = json.loads(raw)
            rows = raw.get("list", []) if isinstance(raw, dict) else []
            normalized = []
            for item in rows:
                if not isinstance(item, dict):
                    continue
                normalized.append({
                    **item,
                    "mac": str(item.get("mac") or "").lower(),
                    "ipv4": item.get("userIp") or "",
                    "online": True,
                    "realtimeUpBytes": int(item.get("flowUp") or 0),
                    "realtimeDownBytes": int(item.get("flowDown") or 0),
                    "connectionCount": int(item.get("flow_cnt") or 0),
                })
            return {"items": normalized, "total": int(raw.get("total") or len(normalized)), "updatedAt": int(time.time())}
        return self.cached("devices", 3.0, load, force)

    def dashboard(self, force: bool = False) -> Dict[str, Any]:
        def load() -> Dict[str, Any]:
            result = self.batch([
                {"method": "devSta.get", "module": "ws_sysinfo", "data": {"get": "static"}},
                {"method": "devSta.get", "module": "ws_sysinfo", "data": {"get": "slow"}},
                {"method": "devSta.get", "module": "ws_sysinfo", "data": {"get": "fast"}},
                {"method": "devSta.get", "module": "ipinfo"},
                {"method": "devConfig.get", "module": "network"},
                {"method": "devSta.get", "module": "ap_list"},
                {"method": "devSta.get", "module": "port_status"},
            ])
            values = result if isinstance(result, list) else []
            keys = ["static", "slow", "fast", "ipinfo", "network", "apList", "portStatus"]
            return {**{key: values[i] if i < len(values) else None for i, key in enumerate(keys)}, "updatedAt": int(time.time())}
        return self.cached("dashboard", 3.0, load, force)

    def firewall(self, force: bool = False) -> Dict[str, Any]:
        def load() -> Dict[str, Any]:
            data = self.batch([
                {"method": "devConfig.get", "module": "ip_firewall"},
                {"method": "devSta.get", "module": "ip_firewall"},
            ])
            config = data[0] if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict) else {}
            stats = data[1] if isinstance(data, list) and len(data) > 1 and isinstance(data[1], dict) else {}
            stat_map = {str(row.get("uuid")): row for row in stats.get("list", []) if isinstance(row, dict)}
            rules = []
            for rule in config.get("list", []) if isinstance(config.get("list"), list) else []:
                if isinstance(rule, dict):
                    rules.append({**rule, "stats": stat_map.get(str(rule.get("uuid")), {"packets": 0, "bytes": 0})})
            return {**config, "list": rules, "updatedAt": int(time.time())}
        return self.cached("firewall", 5.0, load, force)

    def native_port_mapping(self, force: bool = False) -> Dict[str, Any]:
        def load() -> Dict[str, Any]:
            raw = self.rpc("devConfig.get", "port_mapping")
            return raw if isinstance(raw, dict) else {"portMapping": raw if isinstance(raw, list) else []}
        return self.cached("native-portmap", 15.0, load, force)

    def upnp(self, force: bool = False) -> Dict[str, Any]:
        def load() -> Dict[str, Any]:
            raw = self.rpc("devSta.get", "upnp")
            return raw if isinstance(raw, dict) else {}
        return self.cached("upnp", 10.0, load, force)

    def ddns(self, force: bool = False) -> Dict[str, Any]:
        def load() -> Dict[str, Any]:
            raw = self.rpc("devSta.get", "ddnsCfg")
            if isinstance(raw, dict):
                rows = raw.get("list") or raw.get("data") or []
                if isinstance(rows, list):
                    clean = []
                    for row in rows:
                        if isinstance(row, dict):
                            clean.append({**row, "password": "", "passwordConfigured": bool(row.get("password"))})
                    raw = {**raw, "list": clean}
                return raw
            return {"list": []}
        return self.cached("ddns", 15.0, load, force)


class RouterController:
    def __init__(self, client: RuijieRouterClient):
        self.client = client

    def write_and_verify(self, cache_prefix: str, write: Callable[[], Any], read: Callable[[], Any]) -> Dict[str, Any]:
        with self.client.write_lock:
            write_result = write()
            self.client.cache.clear(cache_prefix)
            current = read()
            return {"ok": True, "writeResult": write_result, "data": current, "verifiedAt": int(time.time())}


def _json_error(exc: Exception):
    if isinstance(exc, RouterRpcError):
        return jsonify({"ok": False, "error": exc.code, "message": str(exc)}), exc.http_status
    return jsonify({"ok": False, "error": "INTERNAL_ERROR", "message": str(exc)}), 500


def create_router_blueprint(check_app_token: Callable[[], bool], logger: Any, config_dir: Path) -> Blueprint:
    store = EncryptedRouterConfigStore(config_dir)
    client = RuijieRouterClient(store, logger)
    controller = RouterController(client)
    bp = Blueprint("router_rpc", __name__, url_prefix="/api/router")

    @bp.before_request
    def _authorize():
        if not check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return None

    @bp.errorhandler(Exception)
    def _handle(error: Exception):
        logger.warning("router api error path=%s type=%s message=%s", request.path, type(error).__name__, error)
        return _json_error(error)

    @bp.get("/config")
    def get_config():
        cfg = client.config
        return jsonify({
            "ok": True,
            "address": cfg.get("address", ""),
            "passwordConfigured": bool(cfg.get("password")),
            "sessionSeconds": cfg.get("sessionSeconds", 3600),
            "verifyTls": cfg.get("verifyTls", False),
            "sessionActive": client.session.valid_locally,
            "serialNumber": client.session.serial_number,
        })

    @bp.put("/config")
    def put_config():
        body = request.get_json(silent=True) or {}
        address = body.get("address") or client.config.get("address") or DEFAULT_ROUTER_URL
        password = body.get("password") if "password" in body else None
        seconds = _safe_int(body.get("sessionSeconds"), client.config.get("sessionSeconds", 3600), 600, 7200)
        cfg = store.save(address, password, seconds, bool(body.get("verifyTls", False)))
        client.clear_session()
        if bool(body.get("test", True)):
            client.login(force=True)
        return jsonify({
            "ok": True,
            "address": cfg["address"],
            "passwordConfigured": bool(cfg["password"]),
            "sessionSeconds": cfg["sessionSeconds"],
            "sessionActive": client.session.valid_locally,
            "serialNumber": client.session.serial_number,
        })

    @bp.post("/session/test")
    def test_session():
        session = client.login(force=True)
        return jsonify({"ok": True, "serialNumber": session.serial_number, "sessionSeconds": session.session_seconds})

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
        return jsonify(controller.write_and_verify(
            "firewall",
            lambda: client.rpc("devConfig.add", "ip_firewall", {"list": [body]}),
            lambda: client.firewall(True),
        ))

    @bp.put("/firewall/rules/<uuid>")
    def firewall_update(uuid: str):
        body = request.get_json(silent=True) or {}
        body["uuid"] = uuid
        return jsonify(controller.write_and_verify(
            "firewall",
            lambda: client.rpc("devConfig.update", "ip_firewall", {"list": [body]}),
            lambda: client.firewall(True),
        ))

    @bp.patch("/firewall/rules/<uuid>/enabled")
    def firewall_enabled(uuid: str):
        enabled = "1" if bool((request.get_json(silent=True) or {}).get("enabled")) else "0"
        return jsonify(controller.write_and_verify(
            "firewall",
            lambda: client.rpc("devConfig.update", "ip_firewall", {"list": [{"uuid": uuid, "enable": enabled}]}),
            lambda: client.firewall(True),
        ))

    @bp.delete("/firewall/rules/<uuid>")
    def firewall_delete(uuid: str):
        return jsonify(controller.write_and_verify(
            "firewall",
            lambda: client.rpc("devConfig.del", "ip_firewall", {"uuid": [uuid]}),
            lambda: client.firewall(True),
        ))

    @bp.post("/firewall/reorder")
    def firewall_reorder():
        body = request.get_json(silent=True) or {}
        scope = str(body.get("scope") or "")
        allowed = {"inbound_ipv4", "inbound_ipv6", "outbound_ipv4", "outbound_ipv6", "forward_ipv4", "forward_ipv6"}
        if scope not in allowed:
            raise RouterRpcError("防火墙排序范围无效", "INVALID_SCOPE", 400)
        uuids = [str(v) for v in body.get("uuids", []) if str(v)]
        return jsonify(controller.write_and_verify(
            "firewall",
            lambda: client.rpc("devConfig.update", "ip_firewall", {"op": "reorder", "scope": scope, "uuids": uuids}),
            lambda: client.firewall(True),
        ))

    @bp.get("/port-mapping")
    def port_mapping_get():
        return jsonify({"ok": True, "data": client.native_port_mapping(request.args.get("force") == "1")})

    @bp.post("/port-mapping")
    def port_mapping_add():
        body = request.get_json(silent=True) or {}
        return jsonify(controller.write_and_verify(
            "native-portmap",
            lambda: client.rpc("devConfig.add", "port_mapping", {"list": [body]}),
            lambda: client.native_port_mapping(True),
        ))

    @bp.put("/port-mapping/<path:rule_name>")
    def port_mapping_update(rule_name: str):
        body = request.get_json(silent=True) or {}
        latest = client.native_port_mapping(True)
        rows = latest.get("portMapping") or latest.get("list") or []
        old = next((row for row in rows if isinstance(row, dict) and str(row.get("ruleName")) == rule_name), None)
        if old is None:
            raise RouterRpcError("端口映射规则不存在", "RULE_NOT_FOUND", 404)
        return jsonify(controller.write_and_verify(
            "native-portmap",
            lambda: client.rpc("devConfig.update", "port_mapping", {"old": old, "new": body}),
            lambda: client.native_port_mapping(True),
        ))

    @bp.delete("/port-mapping/<path:rule_name>")
    def port_mapping_delete(rule_name: str):
        return jsonify(controller.write_and_verify(
            "native-portmap",
            lambda: client.rpc("devConfig.del", "port_mapping", {"ruleName": [rule_name]}),
            lambda: client.native_port_mapping(True),
        ))

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
        return jsonify(controller.write_and_verify(
            "upnp",
            lambda: client.rpc("devSta.set", "upnp", payload),
            lambda: client.upnp(True),
        ))

    @bp.get("/ddns")
    def ddns_get():
        return jsonify({"ok": True, "data": client.ddns(request.args.get("force") == "1")})

    @bp.post("/ddns")
    def ddns_add():
        body = request.get_json(silent=True) or {}
        return jsonify(controller.write_and_verify(
            "ddns",
            lambda: client.rpc("devSta.add", "ddnsCfg", body),
            lambda: client.ddns(True),
        ))

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
        return jsonify(controller.write_and_verify(
            "ddns",
            lambda: client.rpc("devSta.update", "ddnsCfg", {"data": [merged]}),
            lambda: client.ddns(True),
        ))

    @bp.delete("/ddns/<service_id>")
    def ddns_delete(service_id: str):
        return jsonify(controller.write_and_verify(
            "ddns",
            lambda: client.rpc("devSta.del", "ddnsCfg", {"data": [service_id]}),
            lambda: client.ddns(True),
        ))

    @bp.get("/diagnostic")
    def diagnostic_get():
        return jsonify({"ok": True, "data": client.rpc("devSta.get", "dev_diag")})

    @bp.post("/diagnostic")
    def diagnostic_start():
        client.rpc("devSta.set", "dev_diag", {"user": "eweb", "action": "start"})
        return jsonify({"ok": True, "message": "诊断已启动", "startedAt": int(time.time())})

    return bp
