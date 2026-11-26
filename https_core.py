"""Certificate and nginx helpers shared by the Hub HTTPS service and CLI."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit


DEFAULT_PORT = 58445
DEFAULT_UPSTREAM = "http://127.0.0.1:58443"
DEFAULT_MQTT_UPSTREAM = "http://127.0.0.1:9001"
DEFAULT_SERVER_NAME = "_"
DEFAULT_CERT_DIR = "/tls"

MAX_CERTIFICATE_BYTES = 256 * 1024
MAX_PRIVATE_KEY_BYTES = 128 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024

_PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
_PEM_PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----", re.S)
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class CertificateDetails:
    domains: frozenset[str]
    not_before: int
    not_after: int
    fingerprint: str
    chain_length: int
    subject: str
    issuer: str

    def public_dict(self) -> dict[str, Any]:
        return {
            "domains": sorted(self.domains),
            "notBefore": self.not_before,
            "notAfter": self.not_after,
            "fingerprint": self.fingerprint,
            "chainLength": self.chain_length,
            "subject": self.subject,
            "issuer": self.issuer,
        }


@dataclass(frozen=True)
class TlsProbe:
    address: str
    status: int
    peer_fingerprint: str
    certificate: CertificateDetails


def validate_port(port: int) -> int:
    try:
        value = int(port)
    except (TypeError, ValueError):
        raise ValueError("HTTPS 端口须为 1–65535")
    if not 1 <= value <= 65535:
        raise ValueError("HTTPS 端口须为 1–65535")
    return value


def validate_domain(domain: str) -> str:
    value = str(domain or "").strip().lower().rstrip(".")
    if not value or len(value) > 253 or "." not in value or "*" in value:
        raise ValueError("请输入用于访问的完整域名，例如 hub.example.com")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in value.split(".")):
        raise ValueError("访问域名格式无效")
    return value


def validate_http_upstream(value: str, label: str = "upstream") -> str:
    raw = str(value or "").strip()
    parsed = urlsplit(raw)
    if (parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
        raise ValueError(f"{label} 必须是 http://host:port")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError(f"{label} 端口无效")
    if port is None:
        port = 80
    if not 1 <= port <= 65535:
        raise ValueError(f"{label} 端口无效")
    return raw.rstrip("/")


def _upstream_authority(value: str, label: str) -> str:
    parsed = urlsplit(validate_http_upstream(value, label))
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{parsed.port or 80}"


def render_nginx_conf(
    port: int,
    upstream: str,
    mqtt_upstream: str = DEFAULT_MQTT_UPSTREAM,
    server_name: str = DEFAULT_SERVER_NAME,
    cert_dir: str = DEFAULT_CERT_DIR,
    ipv6: bool = True,
) -> str:
    port = validate_port(port)
    upstream_authority = _upstream_authority(upstream, "Hub upstream")
    mqtt_authority = _upstream_authority(mqtt_upstream, "MQTT upstream")
    name = str(server_name or DEFAULT_SERVER_NAME).strip()
    if name != DEFAULT_SERVER_NAME:
        name = validate_domain(name)
    cert_root = str(cert_dir or DEFAULT_CERT_DIR).rstrip("/")
    if any(character in cert_root for character in "\r\n\";{}"):
        raise ValueError("nginx 证书目录无效")
    listen_v4 = f"        listen {port} ssl;\n"
    listen_v6 = f"        listen [::]:{port} ssl ipv6only=on;\n" if ipv6 else ""
    return f"""worker_processes auto;
error_log /dev/stderr warn;
pid /tmp/labprobe-https.pid;
events {{ worker_connections 2048; }}
http {{
    access_log off;
    server_tokens off;
    client_max_body_size 2m;
    client_body_timeout 15s;
    keepalive_timeout 75s;
    map $http_upgrade $connection_upgrade {{
        default upgrade;
        '' close;
    }}
    server {{
{listen_v4}{listen_v6}        server_name {name};
        ssl_certificate "{cert_root}/fullchain.pem";
        ssl_certificate_key "{cert_root}/privkey.pem";
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:labprobe_https:4m;
        ssl_session_tickets off;
        add_header X-Content-Type-Options nosniff always;
        location = /mqtt {{
            proxy_pass http://{mqtt_authority};
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Port $server_port;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_buffering off;
            proxy_connect_timeout 5s;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
        }}
        location / {{
            proxy_pass http://{upstream_authority};
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Port $server_port;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_buffering off;
            proxy_connect_timeout 5s;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
        }}
    }}
}}
"""


def _pem_block(block: bytes) -> bytes:
    return block if block.endswith(b"\n") else block + b"\n"


def _first_pem_certificate(cert_pem: bytes) -> bytes:
    match = _PEM_CERT.search(cert_pem)
    if not match:
        raise ValueError("证书文件不是有效的 PEM 证书")
    return _pem_block(match.group(0))


def _pem_certificates(cert_pem: bytes) -> list[bytes]:
    return [_pem_block(block) for block in _PEM_CERT.findall(cert_pem)]


def _decode_certificate(cert_pem: bytes) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="labprobe-cert-") as directory:
        path = Path(directory) / "cert.pem"
        path.write_bytes(_first_pem_certificate(cert_pem))
        return ssl._ssl._test_decode_cert(str(path))


def _name_text(value: Any) -> str:
    if not isinstance(value, (list, tuple)):
        return str(value or "")
    parts = []
    for rdn in value:
        if not isinstance(rdn, (list, tuple)):
            continue
        for pair in rdn:
            if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                parts.append(f"{pair[0]}={pair[1]}")
    return ", ".join(parts)


def certificate_domains(cert_pem: bytes) -> set[str]:
    decoded = _decode_certificate(cert_pem)
    domains = {str(value[1]).lower().rstrip(".") for value in decoded.get("subjectAltName", ()) if value and str(value[0]).lower() == "dns"}
    for field in decoded.get("subject", ()):
        if field[0][0].lower() == "commonname":
            domains.add(str(field[0][1]).lower().rstrip("."))
    return {domain for domain in domains if domain}


def certificate_covers_domain(domains: Iterable[str], domain: str) -> bool:
    wanted = domain.lower().rstrip(".")
    for pattern in domains:
        candidate = str(pattern).lower().rstrip(".")
        if candidate == wanted:
            return True
        if candidate.startswith("*.") and wanted.endswith(candidate[1:]) and wanted.count(".") == candidate.count("."):
            return True
    return False


def certificate_details(cert_pem: bytes) -> CertificateDetails:
    if not cert_pem or len(cert_pem) > MAX_CERTIFICATE_BYTES:
        raise ValueError("证书内容为空或过大")
    decoded = _decode_certificate(cert_pem)
    domains = certificate_domains(cert_pem)
    try:
        not_before = int(ssl.cert_time_to_seconds(decoded["notBefore"]))
        not_after = int(ssl.cert_time_to_seconds(decoded["notAfter"]))
    except Exception:
        raise ValueError("证书有效期无法解析")
    leaf_pem = _first_pem_certificate(cert_pem)
    leaf = base64.b64decode(b"".join(line.strip() for line in leaf_pem.splitlines() if not line.startswith(b"-----")))
    return CertificateDetails(
        domains=frozenset(domains),
        not_before=not_before,
        not_after=not_after,
        fingerprint=hashlib.sha256(leaf).hexdigest(),
        chain_length=len(_pem_certificates(cert_pem)),
        subject=_name_text(decoded.get("subject")),
        issuer=_name_text(decoded.get("issuer")),
    )


def _openssl_chain_verify(cert_pem: bytes) -> None:
    openssl = shutil.which("openssl")
    if not openssl:
        raise ValueError("当前环境缺少 openssl，无法校验证书链")
    blocks = _pem_certificates(cert_pem)
    if not blocks:
        raise ValueError("证书文件不是有效的 PEM 证书")
    with tempfile.TemporaryDirectory(prefix="labprobe-chain-") as directory:
        root = Path(directory)
        leaf = root / "leaf.pem"
        leaf.write_bytes(blocks[0])
        command = [openssl, "verify"]
        if len(blocks) > 1:
            intermediates = root / "intermediates.pem"
            intermediates.write_bytes(b"".join(blocks[1:]))
            command.extend(["-untrusted", str(intermediates)])
        if Path("/etc/ssl/certs").is_dir():
            command.extend(["-CApath", "/etc/ssl/certs"])
        command.append(str(leaf))
        result = subprocess.run(command, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=20)
    if result.returncode != 0:
        raise ValueError("证书链校验失败，请导入包含中间证书的完整链")


def validate_certificate_bundle(
    cert_pem: bytes,
    key_pem: bytes,
    domain: str,
    *,
    verify_chain: bool = True,
    now: int | None = None,
) -> CertificateDetails:
    if not key_pem or len(key_pem) > MAX_PRIVATE_KEY_BYTES:
        raise ValueError("私钥内容为空或过大")
    domain = validate_domain(domain)
    details = certificate_details(cert_pem)
    if not certificate_covers_domain(details.domains, domain):
        raise ValueError(f"证书不包含访问域名 {domain}")
    current = int(time.time()) if now is None else int(now)
    if details.not_after <= current:
        raise ValueError("证书已过期")
    if details.not_before > current + 300:
        raise ValueError("证书尚未生效")
    with tempfile.TemporaryDirectory(prefix="labprobe-key-") as directory:
        cert_path = Path(directory) / "fullchain.pem"
        key_path = Path(directory) / "privkey.pem"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
        except Exception:
            raise ValueError("证书与私钥不匹配")
    if verify_chain:
        _openssl_chain_verify(cert_pem)
    return details


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_certificate_pair(directory: Path, cert_path: str, key_path: str) -> tuple[bytes, bytes]:
    root = directory.resolve()
    try:
        cert_file = (root / cert_path).resolve() if not Path(cert_path).is_absolute() else Path(cert_path).resolve()
        key_file = (root / key_path).resolve() if not Path(key_path).is_absolute() else Path(key_path).resolve()
        cert_file.relative_to(root)
        key_file.relative_to(root)
    except (ValueError, OSError):
        raise ValueError("证书路径必须位于 Hub HTTPS 导入目录内")
    if not cert_file.is_file() or not key_file.is_file():
        raise ValueError("证书或私钥文件不存在")
    if cert_file.stat().st_size > MAX_CERTIFICATE_BYTES or key_file.stat().st_size > MAX_PRIVATE_KEY_BYTES:
        raise ValueError("证书或私钥文件过大")
    return cert_file.read_bytes(), key_file.read_bytes()


def _peer_fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def probe_tls(
    connect_host: str,
    port: int,
    server_name: str,
    *,
    path: str = "/health",
    timeout: float = 8.0,
    verify: bool = True,
) -> TlsProbe:
    domain = validate_domain(server_name)
    context = ssl.create_default_context() if verify else ssl._create_unverified_context()
    raw = socket.create_connection((connect_host, validate_port(port)), timeout=timeout)
    try:
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            peer = tls.getpeercert()
            der = tls.getpeercert(binary_form=True)
            if verify and not peer:
                raise ValueError("TLS 服务未返回可验证证书")
            status = 0
            if path:
                request = (
                    f"GET {path} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
                ).encode()
                tls.sendall(request)
                chunks = []
                total = 0
                while True:
                    chunk = tls.recv(8192)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > 64 * 1024:
                        break
                    chunks.append(chunk)
                response = b"".join(chunks)
                first = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
                match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", first)
                if match:
                    status = int(match.group(1))
            if verify:
                details = certificate_details(ssl.DER_cert_to_PEM_cert(der).encode())
            else:
                details = CertificateDetails(frozenset(), 0, 0, _peer_fingerprint(der), 0, "", "")
            return TlsProbe(connect_host, status, _peer_fingerprint(der), details)
    finally:
        raw.close()


def load_https_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("HTTPS 配置格式无效")
    return data