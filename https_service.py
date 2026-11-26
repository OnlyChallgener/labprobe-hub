"""Optional HTTPS termination managed inside the Hub container."""
from __future__ import annotations

import atexit
import base64
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from typing import Any, Callable

from flask import Blueprint, jsonify, request

from https_core import (
    DEFAULT_PORT,
    CertificateDetails,
    atomic_write,
    load_https_config,
    probe_tls,
    read_certificate_pair,
    render_nginx_conf,
    validate_certificate_bundle,
    validate_domain,
    validate_http_upstream,
    validate_port,
)

_CERTIFICATE_FIELDS = {
    "domains", "notBefore", "notAfter", "fingerprint", "chainLength",
    "subject", "issuer", "source", "importedAt",
}


class HttpsError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "https_error"):
        super().__init__(message)
        self.status = status
        self.code = code


def _text(value: Any) -> str:
    return str(value or "").strip()


def _now() -> int:
    return int(time.time())


class HttpsService:
    def __init__(
        self,
        root: Path,
        *,
        hub_port: int,
        mqtt_upstream: str,
        nginx_bin: str | None = None,
        admin_token: str = "",
        logger: Any = None,
        local_cert_root: Path | None = None,
    ):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.config_path = self.root / "config.json"
        self.runtime = self.root / "runtime"
        self.releases = self.root / "releases"
        self.import_root = Path(local_cert_root) if local_cert_root else self.root / "import"
        for path in (self.runtime, self.releases, self.import_root):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(path, 0o700)
        self.hub_port = validate_port(hub_port)
        self.mqtt_upstream = validate_http_upstream(mqtt_upstream, "MQTT upstream")
        self.nginx_bin = nginx_bin or shutil.which("nginx") or "/usr/sbin/nginx"
        self.admin_token = _text(admin_token)
        self.logger = logger
        self.lock = threading.RLock()
        self.process: subprocess.Popen[bytes] | None = None
        self._last_error = ""
        self._last_probe_at = 0
        self.config = self._load_config()
        self._persist_config()

    def _default_config(self) -> dict[str, Any]:
        return {
            "enabled": False,
            "port": DEFAULT_PORT,
            "domain": "",
            "source": "manual",
            "localCertPath": "",
            "localKeyPath": "",
            "certificate": {},
            "release": "",
            "lastError": "",
            "updatedAt": _now(),
        }

    @staticmethod
    def _public_certificate(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        return {key: value[key] for key in _CERTIFICATE_FIELDS if key in value}

    def _load_config(self) -> dict[str, Any]:
        config = self._default_config()
        try:
            saved = load_https_config(self.config_path)
        except Exception as error:
            self._last_error = f"HTTPS 配置读取失败：{error}"
            return config
        if isinstance(saved, dict):
            config.update({key: value for key, value in saved.items() if key in config})
        config["certificate"] = self._public_certificate(config.get("certificate"))
        try:
            config["port"] = validate_port(config.get("port") or DEFAULT_PORT)
        except ValueError:
            config["port"] = DEFAULT_PORT
            self._last_error = "HTTPS 配置端口无效，已恢复默认端口"
        config["enabled"] = bool(config.get("enabled"))
        config["source"] = _text(config.get("source")).lower()
        if config["source"] not in {"manual", "local"}:
            config["source"] = "manual"
        return config

    def _persist_config(self) -> None:
        public = {key: value for key, value in self.config.items() if key not in {"privateKey", "key", "keyPem"}}
        public["certificate"] = self._public_certificate(public.get("certificate"))
        public["lastError"] = _text(public.get("lastError"))
        atomic_write(self.config_path, (json.dumps(public, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(), 0o600)

    @staticmethod
    def _release_id(details: CertificateDetails) -> str:
        return details.fingerprint[:32]

    def _write_release(self, cert: bytes, key: bytes, details: CertificateDetails) -> Path:
        release = self.releases / self._release_id(details)
        release.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(release, 0o700)
        atomic_write(release / "fullchain.pem", cert, 0o644)
        atomic_write(release / "privkey.pem", key, 0o600)
        meta = {"certificate": details.public_dict(), "createdAt": _now()}
        atomic_write(release / "meta.json", (json.dumps(meta, ensure_ascii=False, sort_keys=True) + "\n").encode(), 0o600)
        self._prune_releases(release.name)
        return release

    def _prune_releases(self, keep: str) -> None:
        try:
            directories = sorted((path for path in self.releases.iterdir() if path.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True)
        except OSError:
            return
        active = {keep, _text(self.config.get("release"))}
        for index, path in enumerate(directories):
            if path.name in active or index < 6:
                continue
            shutil.rmtree(path, ignore_errors=True)

    def _release_dir(self) -> Path | None:
        release = _text(self.config.get("release"))
        if not release or "/" in release or "\\" in release:
            return None
        path = self.releases / release
        return path if path.is_dir() else None

    def _certificate(self) -> dict[str, Any]:
        return self._public_certificate(self.config.get("certificate"))

    def _nginx_available(self) -> bool:
        return bool(self.nginx_bin and Path(self.nginx_bin).exists())

    def _nginx_config_path(self) -> Path:
        return self.runtime / "nginx.conf"

    def _render_config(self, release: Path, port: int, domain: str) -> bytes:
        return render_nginx_conf(
            port,
            f"http://127.0.0.1:{self.hub_port}",
            self.mqtt_upstream,
            server_name=domain,
            cert_dir=str(release),
            ipv6=True,
        ).encode()

    def _validate_nginx_config(self, text: bytes) -> None:
        if not self._nginx_available():
            raise HttpsError("Hub 镜像缺少 nginx，无法启用 HTTPS", 503, "https_unavailable")
        candidate = self.runtime / "nginx.next.conf"
        atomic_write(candidate, text, 0o600)
        try:
            result = subprocess.run(
                [self.nginx_bin, "-t", "-c", str(candidate)],
                text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=20,
            )
        except Exception as error:
            raise HttpsError(f"nginx 配置检查失败：{error}", 503, "https_config_invalid")
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip().splitlines()
            summary = detail[-1][:240] if detail else "unknown error"
            if "privkey" in summary.lower() or "private" in summary.lower():
                summary = "证书或私钥加载失败"
            raise HttpsError(f"nginx 配置检查失败：{summary}", 400, "https_config_invalid")

    def _start_nginx_locked(self, config_text: bytes) -> None:
        if not self._nginx_available():
            raise HttpsError("Hub 镜像缺少 nginx，无法启用 HTTPS", 503, "https_unavailable")
        self._validate_nginx_config(config_text)
        config_path = self._nginx_config_path()
        atomic_write(config_path, config_text, 0o600)
        log_path = self.runtime / "nginx.log"
        try:
            handle = log_path.open("ab", buffering=0)
        except OSError:
            handle = subprocess.DEVNULL  # type: ignore[assignment]
        try:
            self.process = subprocess.Popen(
                [self.nginx_bin, "-c", str(config_path), "-g", "daemon off;"],
                cwd=str(self.runtime), stdin=subprocess.DEVNULL, stdout=handle, stderr=subprocess.STDOUT,
            )
        finally:
            if handle is not subprocess.DEVNULL:
                handle.close()
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise HttpsError("HTTPS 服务启动失败，58443 HTTP 服务未受影响", 503, "https_start_failed")
            if self._local_probe(http=False):
                return
            time.sleep(0.3)
        self._stop_nginx_locked()
        raise HttpsError("HTTPS 服务启动后未通过 TLS 检查", 503, "https_start_failed")

    def _reload_nginx_locked(self, config_text: bytes, expected_fingerprint: str) -> None:
        if not self._nginx_available():
            raise HttpsError("Hub 镜像缺少 nginx，无法启用 HTTPS", 503, "https_unavailable")
        self._validate_nginx_config(config_text)
        config_path = self._nginx_config_path()
        previous = config_path.read_bytes() if config_path.exists() else b""
        atomic_write(config_path, config_text, 0o600)
        try:
            reload = subprocess.run(
                [self.nginx_bin, "-s", "reload", "-c", str(config_path)],
                text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=20,
            )
            if reload.returncode != 0:
                raise HttpsError("HTTPS 证书热加载失败，旧证书继续生效", 503, "https_reload_failed")
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                active = self._local_probe()
                if active and active.peer_fingerprint == expected_fingerprint:
                    return
                time.sleep(0.25)
            raise HttpsError("新证书未通过实际 TLS 校验，旧证书继续生效", 503, "https_verify_failed")
        except HttpsError:
            if previous:
                try:
                    atomic_write(config_path, previous, 0o600)
                    subprocess.run(
                        [self.nginx_bin, "-s", "reload", "-c", str(config_path)],
                        text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=20,
                    )
                except Exception:
                    pass
            raise

    def _stop_nginx_locked(self) -> None:
        process = self.process
        if process is None:
            return
        try:
            config = self._nginx_config_path()
            if config.exists():
                subprocess.run(
                    [self.nginx_bin, "-s", "quit", "-c", str(config)],
                    text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=10,
                )
            process.wait(timeout=5)
        except Exception:
            try:
                process.terminate()
                process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        finally:
            self.process = None

    def _local_probe(self, *, http: bool = True):
        domain = _text(self.config.get("domain"))
        port = int(self.config.get("port") or DEFAULT_PORT)
        if not domain:
            return None
        for host in ("127.0.0.1", "::1"):
            try:
                return probe_tls(host, port, domain, path="/health" if http else "", timeout=2.5)
            except Exception:
                continue
        return None

    def _apply_release_locked(self, release: Path, domain: str, port: int, fingerprint: str) -> None:
        config_text = self._render_config(release, port, domain)
        if self.process is not None and self.process.poll() is None:
            self._reload_nginx_locked(config_text, fingerprint)
        else:
            self._start_nginx_locked(config_text)
            active = self._local_probe(http=False)
            if active is None or active.peer_fingerprint != fingerprint:
                self._stop_nginx_locked()
                raise HttpsError("HTTPS 服务未加载新证书", 503, "https_verify_failed")

    def _public_url_locked(self) -> str:
        if not self.config.get("enabled"):
            return ""
        if self.process is None or self.process.poll() is not None:
            return ""
        domain = _text(self.config.get("domain"))
        port = int(self.config.get("port") or DEFAULT_PORT)
        return f"https://{domain}:{port}" if domain else ""

    def public_url(self) -> str:
        with self.lock:
            return self._public_url_locked()

    def realtime_url(self) -> str:
        public = self.public_url()
        return f"wss://{public[8:]}/api/realtime/ws" if public else ""

    def mqtt_url(self) -> str:
        public = self.public_url()
        return f"wss://{public[8:]}/mqtt" if public else ""

    def status(self, *, include_process: bool = True) -> dict[str, Any]:
        with self.lock:
            running = bool(include_process and self.process is not None and self.process.poll() is None)
            if include_process and running:
                active = self._local_probe()
                if active is not None:
                    self._last_probe_at = _now()
                else:
                    running = False
            public = self._public_url_locked() if running else ""
            return {
                "ok": True,
                "enabled": bool(self.config.get("enabled")),
                "running": running,
                "supported": self._nginx_available(),
                "port": int(self.config.get("port") or DEFAULT_PORT),
                "domain": _text(self.config.get("domain")),
                "source": _text(self.config.get("source")) or "manual",
                "localCertPath": _text(self.config.get("localCertPath")),
                "localKeyPath": _text(self.config.get("localKeyPath")),
                "certificate": self._certificate(),
                "release": _text(self.config.get("release")),
                "publicUrl": public,
                "realtimeUrl": f"wss://{public[8:]}/api/realtime/ws" if public else "",
                "mqttUrl": f"wss://{public[8:]}/mqtt" if public else "",
                "adminTokenRequired": bool(self.admin_token),
                "lastError": _text(self._last_error or self.config.get("lastError")),
                "lastProbeAt": self._last_probe_at,
                "updatedAt": int(self.config.get("updatedAt") or 0),
            }

    def _save_error(self, error: Exception | str) -> None:
        self._last_error = _text(str(error))[:300]
        self.config["lastError"] = self._last_error
        self._persist_config()

    def configure(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            previous = dict(self.config)
            try:
                port = validate_port(payload.get("port", self.config.get("port") or DEFAULT_PORT))
                domain_raw = payload.get("domain", self.config.get("domain") or "")
                domain = validate_domain(domain_raw) if _text(domain_raw) else ""
                source = _text(payload.get("source", self.config.get("source") or "manual")).lower()
                if source not in {"manual", "local"}:
                    raise HttpsError("证书来源无效", 400, "invalid_source")
                if port == self.hub_port:
                    raise HttpsError("HTTPS 端口不能与 Hub HTTP 端口相同", 400, "https_port_conflict")
                if port in {1883, 9001}:
                    raise HttpsError("HTTPS 端口不能占用 MQTT 内部端口", 400, "https_port_conflict")
                incoming_enabled = payload.get("enabled")
                enabled = bool(self.config.get("enabled")) if incoming_enabled is None else bool(incoming_enabled)
                self.config.update({
                    "port": port,
                    "domain": domain,
                    "source": source,
                    "enabled": enabled,
                    "localCertPath": _text(payload.get("localCertPath", self.config.get("localCertPath"))),
                    "localKeyPath": _text(payload.get("localKeyPath", self.config.get("localKeyPath"))),
                    "updatedAt": _now(),
                    "lastError": "",
                })
                if enabled:
                    self._enable_locked()
                else:
                    self._stop_nginx_locked()
                self._persist_config()
                return self.status()
            except Exception as error:
                self._last_error = _text(str(error))[:300]
                self.config = previous
                self.config["lastError"] = self._last_error
                self._persist_config()
                raise

    def set_enabled(self, enabled: bool) -> dict[str, Any]:
        with self.lock:
            previous = dict(self.config)
            self.config["enabled"] = bool(enabled)
            self.config["updatedAt"] = _now()
            try:
                if enabled:
                    self._enable_locked()
                else:
                    self._stop_nginx_locked()
                    self.config["lastError"] = ""
                self._persist_config()
                return self.status()
            except Exception as error:
                self._last_error = _text(str(error))[:300]
                self.config = previous
                self.config["lastError"] = self._last_error
                self._persist_config()
                raise

    def _enable_locked(self) -> None:
        domain = _text(self.config.get("domain"))
        if not domain:
            raise HttpsError("请先填写 HTTPS 访问域名", 400, "https_domain_required")
        release = self._release_dir()
        fingerprint = _text(self._certificate().get("fingerprint"))
        if release is None or not fingerprint:
            raise HttpsError("请先导入并校验证书", 400, "https_certificate_required")
        self.config["port"] = validate_port(self.config.get("port") or DEFAULT_PORT)
        self._apply_release_locked(release, domain, int(self.config["port"]), fingerprint)
        self._last_error = ""
        self.config["lastError"] = ""

    def import_manual(self, cert_pem: str | bytes, key_pem: str | bytes, domain: str | None = None) -> dict[str, Any]:
        cert = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
        key = key_pem.encode() if isinstance(key_pem, str) else key_pem
        return self._import_bundle(cert, key, domain, "manual")

    def import_local(self, cert_path: str, key_path: str, domain: str | None = None) -> dict[str, Any]:
        cert, key = read_certificate_pair(self.import_root, cert_path, key_path)
        return self._import_bundle(cert, key, domain, "local", local_cert_path=cert_path, local_key_path=key_path)

    def _import_bundle(
        self,
        cert: bytes,
        key: bytes,
        domain: str | None,
        source: str,
        *,
        local_cert_path: str = "",
        local_key_path: str = "",
    ) -> dict[str, Any]:
        with self.lock:
            previous = dict(self.config)
            try:
                target = validate_domain(domain or self.config.get("domain") or "")
                details = validate_certificate_bundle(cert, key, target)
                release = self._write_release(cert, key, details)
                if self.config.get("enabled"):
                    self.config["domain"] = target
                    self.config["port"] = validate_port(self.config.get("port") or DEFAULT_PORT)
                    self._apply_release_locked(release, target, int(self.config["port"]), details.fingerprint)
                self.config.update({
                    "domain": target,
                    "source": source,
                    "release": release.name,
                    "certificate": {**details.public_dict(), "source": source, "importedAt": _now()},
                    "localCertPath": local_cert_path,
                    "localKeyPath": local_key_path,
                    "lastError": "",
                    "updatedAt": _now(),
                })
                self._persist_config()
                return self.status()
            except Exception:
                self.config = previous
                self._persist_config()
                raise

    def delete_certificate(self) -> dict[str, Any]:
        with self.lock:
            self._stop_nginx_locked()
            for release in self.releases.iterdir():
                if release.is_dir():
                    shutil.rmtree(release, ignore_errors=True)
            self.config.update({
                "enabled": False,
                "source": "manual",
                "release": "",
                "certificate": {},
                "localCertPath": "",
                "localKeyPath": "",
                "lastError": "",
                "updatedAt": _now(),
            })
            self._last_error = ""
            self._persist_config()
            return self.status()

    def start_if_enabled(self) -> None:
        with self.lock:
            if not self.config.get("enabled"):
                return
            try:
                self._enable_locked()
                self._persist_config()
            except Exception as error:
                self._save_error(error)

    def shutdown(self) -> None:
        with self.lock:
            self._stop_nginx_locked()

    def _require_admin(self, check_app_token: Callable[[], bool]) -> Any:
        if not check_app_token():
            return jsonify(ok=False, error="unauthorized", errorCode="unauthorized"), 401
        if not self.admin_token:
            if request.headers.get("X-LabProbe-Confirm", "") != "https-management":
                return jsonify(ok=False, error="需要确认管理员操作", errorCode="confirmation_required"), 403
        else:
            provided = request.headers.get("X-LabProbe-Admin-Token", "")
            if not hmac.compare_digest(provided.encode(), self.admin_token.encode()):
                return jsonify(ok=False, error="管理员授权失败", errorCode="admin_token_required"), 403
        return None

    @staticmethod
    def _body() -> dict[str, Any]:
        if request.content_length and request.content_length > 2 * 1024 * 1024:
            raise HttpsError("请求内容过大", 413, "payload_too_large")
        value = request.get_json(silent=True) or {}
        if not isinstance(value, dict):
            raise HttpsError("请求格式无效", 400, "invalid_request")
        return value

    @staticmethod
    def _secure_request() -> bool:
        forwarded = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
        return request.is_secure or forwarded == "https"


def _decode_material(value: Any, label: str) -> bytes:
    try:
        return base64.b64decode(str(value or ""), validate=True)
    except Exception:
        raise HttpsError(f"{label}格式无效", 400, "invalid_certificate_material")


def register_https_service(hub: Any, root: Path) -> HttpsService:
    mqtt_host = _text(os.environ.get("HTTPS_MQTT_HOST") or getattr(hub, "MQTT_INTERNAL_HOST", "127.0.0.1"))
    try:
        mqtt_ws_port = validate_port(os.environ.get("MQTT_WS_PORT", "9001"))
    except ValueError:
        mqtt_ws_port = 9001
    if ":" in mqtt_host and not mqtt_host.startswith("["):
        mqtt_host = f"[{mqtt_host}]"
    service = HttpsService(
        root,
        hub_port=int(getattr(hub, "PORT", DEFAULT_PORT + 2)),
        mqtt_upstream=_text(os.environ.get("HTTPS_MQTT_UPSTREAM")) or f"http://{mqtt_host}:{mqtt_ws_port}",
        nginx_bin=os.environ.get("HTTPS_NGINX_BIN") or None,
        admin_token=_text(os.environ.get("HTTPS_ADMIN_TOKEN") or hub.cfg_get("server.https_admin_token", "")),
        logger=getattr(hub, "LOGGER", None),
        local_cert_root=Path(os.environ.get("HTTPS_LOCAL_CERT_ROOT", str(root / "import"))),
    )
    hub.HTTPS_SERVICE = service
    bp = Blueprint("labprobe_https", __name__, url_prefix="/api/https")

    @bp.errorhandler(HttpsError)
    def https_error(error: HttpsError):
        return jsonify(ok=False, error=str(error), errorCode=error.code), error.status

    @bp.route("/status", methods=["GET"])
    def status():
        if not hub.check_app_token():
            return jsonify(ok=False, error="unauthorized", errorCode="unauthorized"), 401
        return jsonify(service.status())

    @bp.route("/config", methods=["POST"])
    def config():
        denied = service._require_admin(hub.check_app_token)
        if denied:
            return denied
        return jsonify(service.configure(service._body()))

    @bp.route("/enable", methods=["POST"])
    def enable():
        denied = service._require_admin(hub.check_app_token)
        if denied:
            return denied
        body = service._body()
        return jsonify(service.set_enabled(bool(body.get("enabled", True))))

    @bp.route("/import/manual", methods=["POST"])
    def import_manual():
        denied = service._require_admin(hub.check_app_token)
        if denied:
            return denied
        if not service._secure_request():
            raise HttpsError("私钥只能通过 HTTPS 上传；首次配置请使用 NAS 本地证书文件", 400, "https_required_for_private_key")
        body = service._body()
        cert = _decode_material(body.get("certificateBase64") or body.get("certificatePem"), "证书")
        key = _decode_material(body.get("keyBase64") or body.get("privateKeyPem"), "私钥")
        chain = _decode_material(body.get("issuerCertificateBase64"), "证书链") if body.get("issuerCertificateBase64") else b""
        if chain:
            cert = cert.rstrip() + b"\n" + chain
        return jsonify(service.import_manual(cert, key, _text(body.get("domain")) or None))

    @bp.route("/import/local", methods=["POST"])
    def import_local():
        denied = service._require_admin(hub.check_app_token)
        if denied:
            return denied
        body = service._body()
        return jsonify(service.import_local(
            _text(body.get("certPath")), _text(body.get("keyPath")), _text(body.get("domain")) or None,
        ))

    @bp.route("/certificate", methods=["DELETE"])
    def delete_certificate():
        denied = service._require_admin(hub.check_app_token)
        if denied:
            return denied
        return jsonify(service.delete_certificate())

    hub.app.register_blueprint(bp)
    atexit.register(service.shutdown)
    return service
