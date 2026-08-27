"""Reyee Session Manager.

Implements the official Reference Oracle authentication specification:
1. Dynamic key extraction from GET /cgi-bin/luci/.
2. OpenSSL EVP_BytesToKey(MD5) compatible AES-256-CBC encryption.
3. POST /cgi-bin/luci/api/auth login with sid, token, and CookieJar capture.
4. Idle Timeout lifecycle (never force-relogins based on wall-clock minutes).
5. Single-flight mutual exclusion locking to prevent concurrent login storms.
6. Max 1 retry on session expiration with infinite loop backoff circuit breaker.
7. Router credentials / SID / Cookie stay strictly inside Hub backend.
"""

import base64
import hashlib
import json
import os
import re
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from router_core.errors import (
    RouterAuthError,
    RouterAuthExpiredError,
    RouterNotConfiguredError,
    RouterUnreachableError,
)
from router_core.session.interface import RouterSessionProtocol

_KEY_PATTERNS = (
    re.compile(r'GibberishAES\.enc\(passwordEl\.value,\s*["\']([A-Fa-f0-9]+)["\']\)', re.I),
    re.compile(r"GibberishAES\s*\.\s*enc\s*\(\s*[^,]+,\s*['\"]([A-Fa-f0-9]{16,128})['\"]\s*\)", re.I),
    re.compile(r"(?:encrypt(?:ion)?Key|aesKey|loginKey)\s*[:=]\s*['\"]([A-Fa-f0-9]{16,128})['\"]", re.I),
    re.compile(r"['\"]([A-Fa-f0-9]{16,64})['\"]\s*\)\s*;\s*//\s*aes", re.I),
)
AUTH_RETRY_BACKOFF_SECONDS = 15
BE72_AES_PASSWORD = "RjYkhwzx$2018!"


def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16) -> Tuple[bytes, bytes]:
    """OpenSSL EVP_BytesToKey KDF using iterative MD5 hashing."""
    data = b""
    last = b""
    while len(data) < (key_len + iv_len):
        h = hashlib.md5()
        if last:
            h.update(last)
        h.update(password)
        h.update(salt)
        last = h.digest()
        data += last
    return data[:key_len], data[key_len : key_len + iv_len]


def gibberish_aes_encrypt(plain_text: str, encryption_key: str, custom_salt: Optional[bytes] = None) -> str:
    """Encrypts plain_text using OpenSSL / GibberishAES compatible AES-256-CBC.
    
    Format: 'Salted__' + 8-byte salt + ciphertext (PKCS#7 padded) -> Base64 without whitespace.
    """
    salt = custom_salt if custom_salt is not None else os.urandom(8)
    if len(salt) != 8:
        raise ValueError("Salt must be exactly 8 bytes")
    
    key, iv = _evp_bytes_to_key(encryption_key.encode("utf-8"), salt, key_len=32, iv_len=16)
    padded_data = pad(plain_text.encode("utf-8"), AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_data)
    
    raw = b"Salted__" + salt + ciphertext
    b64_str = base64.b64encode(raw).decode("ascii")
    return re.sub(r"\s+", "", b64_str)


def gibberish_aes_decrypt(b64_cipher: str, encryption_key: str) -> str:
    """Decrypts OpenSSL / GibberishAES compatible Base64 ciphertext."""
    clean_b64 = re.sub(r"\s+", "", b64_cipher)
    raw = base64.b64decode(clean_b64)
    if len(raw) < 16 or raw[:8] != b"Salted__":
        raise ValueError("Invalid OpenSSL Salted__ ciphertext header")
    
    salt = raw[8:16]
    ciphertext = raw[16:]
    key, iv = _evp_bytes_to_key(encryption_key.encode("utf-8"), salt, key_len=32, iv_len=16)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    plain_bytes = unpad(padded_data, AES.block_size)
    return plain_bytes.decode("utf-8")


class ReyeeSession:
    """Represents an active authenticated session with a Reyee router."""

    def __init__(
        self,
        sid: str,
        token: str,
        cookie_header: str,
        serial_number: str = "",
        session_seconds: int = 3600,
        obtained_at: Optional[float] = None,
    ):
        self.sid = sid
        self.token = token
        self.cookie_header = cookie_header
        self.serial_number = serial_number
        self.session_seconds = max(1, min(7200, session_seconds))
        self.obtained_at = obtained_at if obtained_at is not None else time.time()
        self.last_activity_at = self.obtained_at

    @property
    def is_valid_locally(self) -> bool:
        if not self.sid or not self.cookie_header:
            return False
        # Idle timeout check (session_seconds is an idle expiration window)
        idle_elapsed = time.time() - self.last_activity_at
        return idle_elapsed < self.session_seconds

    def touch(self) -> None:
        """Refreshes the idle activity timestamp upon successful authenticated RPC."""
        self.last_activity_at = time.time()


def _clean_address(raw: str) -> str:
    addr = str(raw or "").strip()
    if not addr:
        return ""
    if not re.match(r"^https?://", addr, re.I):
        addr = f"http://{addr}"
    return addr.rstrip("/")


def _normalize_endpoint_url(base: str, path: str) -> str:
    base = str(base or "").strip().rstrip("/")
    path = "/" + str(path or "").strip().lstrip("/")
    if base.endswith("/cgi-bin/luci") and path.startswith("/cgi-bin/luci/"):
        path = path[len("/cgi-bin/luci"):]
    return base + path


class ReyeeSessionManager(RouterSessionProtocol):
    """Production Session Manager managing authenticated Reyee router sessions."""

    def __init__(
        self,
        *,
        address: Optional[str] = None,
        host: Optional[str] = None,
        password: str = "",
        username: str = "admin",
        verify_tls: bool = False,
        session_seconds: int = 3600,
        http_timeout: Tuple[int, int] = (4, 10),
        timeout: Optional[Any] = None,
        session_factory: Optional[Callable[[], requests.Session]] = None,
    ):
        self.address = _clean_address(address or host)
        self.password = str(password or "")
        self.username = str(username or "admin").strip() or "admin"
        self.verify_tls = bool(verify_tls)
        self.session_seconds = max(600, min(7200, int(session_seconds or 3600)))
        if isinstance(timeout, (int, float)):
            self.http_timeout = (int(timeout), int(timeout))
        elif isinstance(timeout, (tuple, list)) and len(timeout) >= 2:
            self.http_timeout = (int(timeout[0]), int(timeout[1]))
        else:
            self.http_timeout = http_timeout
        self._http = session_factory() if session_factory else requests.Session()
        
        self._session: Optional[ReyeeSession] = None
        self._lock = threading.Lock()
        self._blocked_until: float = 0.0
        self._consecutive_failures: int = 0

    @property
    def http_session(self) -> requests.Session:
        return self._http

    def is_valid(self) -> bool:
        session = self._session
        return bool(session and session.is_valid_locally)

    def invalidate_session(self) -> None:
        with self._lock:
            self._session = None

    def record_activity(self) -> None:
        session = self._session
        if session:
            session.touch()

    def reconfigure(
        self,
        *,
        address: str,
        password: str,
        username: str = "admin",
        verify_tls: bool = False,
        session_seconds: int = 3600,
    ) -> None:
        """Atomically apply a Hub-owned router connection configuration."""
        with self._lock:
            self.address = _clean_address(address)
            self.password = str(password or "")
            self.username = str(username or "admin").strip() or "admin"
            self.verify_tls = bool(verify_tls)
            self.session_seconds = max(600, min(7200, int(session_seconds or 3600)))
            self._session = None
            self._http.cookies.clear()
            self._blocked_until = 0.0
            self._consecutive_failures = 0

    def get_session(self, force: bool = False) -> ReyeeSession:
        """Thread-safe acquisition of a valid ReyeeSession using Single-Flight execution."""
        # Fast path: locally valid session
        if not force:
            current = self._session
            if current and current.is_valid_locally:
                return current

        with self._lock:
            # Re-check under lock (Single-Flight double-checked locking)
            if not force:
                current = self._session
                if current and current.is_valid_locally:
                    return current

            # Check circuit breaker backoff
            now = time.time()
            if now < self._blocked_until:
                remaining = int(self._blocked_until - now)
                raise RouterAuthError(f"Router login retry paused for {remaining}s due to consecutive failures")

            if not self.address or not self.password:
                raise RouterNotConfiguredError("Router address or password not configured")

            try:
                new_session = self._perform_login()
                self._session = new_session
                self._consecutive_failures = 0
                self._blocked_until = 0.0
                return new_session
            except Exception as exc:
                self._session = None
                self._consecutive_failures += 1
                if self._consecutive_failures >= 3:
                    self._blocked_until = time.time() + AUTH_RETRY_BACKOFF_SECONDS
                raise

    def _fetch_encryption_key(self) -> str:
        root_addr = re.sub(r"/cgi-bin/luci.*$", "", self.address, flags=re.I)
        candidates = [
            _normalize_endpoint_url(self.address, "/cgi-bin/luci/"),
            self.address + "/",
            root_addr + "/",
            root_addr + "/index.html",
            _normalize_endpoint_url(self.address, "/index.html"),
        ]
        last_error = None
        fetched_login_page = False
        for url in candidates:
            try:
                resp = self._http.get(
                    url,
                    timeout=self.http_timeout,
                    verify=self.verify_tls,
                    allow_redirects=True,
                    headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
                )
                if resp.status_code < 400:
                    fetched_login_page = True
                    for pat in _KEY_PATTERNS:
                        match = pat.search(resp.text or "")
                        if match:
                            return match.group(1)
            except requests.RequestException as exc:
                last_error = exc
                continue

        if fetched_login_page:
            # BE72 firmware builds that keep the key outside the returned HTML use
            # the same fixed key as the browser bundle on the exact auth endpoint.
            return BE72_AES_PASSWORD
        if last_error:
            raise RouterUnreachableError(f"Unable to connect to router login page: {last_error}") from last_error
        raise RouterAuthError("Router login page was unavailable")

    @staticmethod
    def _wire_json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    def _validate_session(self, session: ReyeeSession) -> None:
        payload = {"method": "getDeviceInfo", "params": None}
        wire = self._wire_json(payload)
        url = _normalize_endpoint_url(self.address, f"/cgi-bin/luci/api/overview?auth={session.sid}")
        try:
            response = self._http.post(
                url,
                data=wire.encode("utf-8"),
                timeout=self.http_timeout,
                verify=self.verify_tls,
                allow_redirects=False,
                headers={
                    "Content-Type": "application/json;charset=UTF-8",
                    "Cookie": session.cookie_header,
                },
            )
            # Only treat explicit 401/403 as auth failure
            if response.status_code in (401, 403):
                raise RouterAuthExpiredError(
                    f"BE72 login session validation returned HTTP {response.status_code}"
                )
            if response.status_code < 400:
                try:
                    root = response.json()
                    if isinstance(root, dict):
                        err_text = str(root.get("error") or "").lower()
                        if "auth" in err_text or "token" in err_text or "permission" in err_text:
                            raise RouterAuthExpiredError(f"Router validation error: {root.get('error')}")
                except (ValueError, TypeError):
                    pass
        except (RouterAuthExpiredError, RouterUnreachableError):
            raise
        except Exception:
            # Tolerant: do not drop session on benign network probe timeout or non-standard overview responses
            pass

    def _perform_login(self) -> ReyeeSession:
        encryption_key = self._fetch_encryption_key()
        encrypted_pwd = gibberish_aes_encrypt(self.password, encryption_key)
        timestamp = str(round(time.time()))

        payload = {
            "method": "login",
            "params": {
                "password": encrypted_pwd,
                "time": timestamp,
                "encry": True,
                "limit": False,
                "setInit": False,
            },
        }
        wire = self._wire_json(payload)

        url = _normalize_endpoint_url(self.address, "/cgi-bin/luci/api/auth")
        try:
            resp = self._http.post(
                url,
                data=wire.encode("utf-8"),
                timeout=self.http_timeout,
                verify=self.verify_tls,
                allow_redirects=False,
                headers={"Content-Type": "application/json;charset=UTF-8"},
            )
        except requests.RequestException as exc:
            raise RouterUnreachableError(f"Unable to reach router authentication endpoint: {exc}") from exc

        if resp.status_code >= 400:
            raise RouterAuthError(f"Router authentication endpoint returned HTTP {resp.status_code}")

        try:
            root = resp.json()
        except Exception as exc:
            raise RouterAuthError(f"Invalid JSON returned by router login endpoint: {exc}") from exc

        if not isinstance(root, dict):
            raise RouterAuthError("Router login response was not a JSON object")
        data = root.get("data") if isinstance(root.get("data"), dict) else {}
        token = str(data.get("token") or data.get("auth_token") or data.get("auth") or "").strip()
        sid = str(data.get("sid") or data.get("sessionId") or data.get("session_id") or "").strip()
        serial = str(data.get("sn") or data.get("serialNumber") or data.get("devSn") or "").strip()

        # If serial is not in data, check cookies from response
        if not serial:
            for cookie in self._http.cookies:
                if cookie.name.upper() == "SN" and cookie.value:
                    serial = cookie.value.strip()
                    break

        # If sid is present but token is missing, token = sid, and vice-versa
        if not token and sid:
            token = sid
        if not sid and token:
            sid = token

        try:
            sessiontime = int(data.get("sessiontime") or data.get("sessionTime") or self.session_seconds)
        except (TypeError, ValueError):
            sessiontime = self.session_seconds
        sessiontime = max(600, min(7200, sessiontime))

        try:
            code = int(root.get("code") or 0)
        except (TypeError, ValueError):
            code = -1
        if code != 0 or not sid:
            code = root.get("code")
            msg = root.get("message") or root.get("msg") or "Login credentials rejected"
            raise RouterAuthError(f"Router login failed: {msg} (code={code})")

        # Captured BE72 browser traffic uses SN cookie and/or sysauth cookie
        self._http.cookies.clear()
        if serial:
            self._http.cookies.set(serial, sid, path="/")
            cookie_header = f"{serial}={sid}"
        else:
            cookie_header = f"sysauth={sid}"
        self._http.cookies.set("sysauth", sid, path="/")

        session = ReyeeSession(
            sid=sid,
            token=token,
            cookie_header=cookie_header,
            serial_number=serial,
            session_seconds=sessiontime,
            obtained_at=time.time(),
        )
        self._validate_session(session)
        return session
