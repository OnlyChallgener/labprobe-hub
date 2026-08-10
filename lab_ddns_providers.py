"""Hub-side DDNS provider adapters for Phase 1B.

The adapters are intentionally request-session based so tests can inject a
fake transport. They never log credentials or request bodies.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import quote

import requests

from lab_ddns import DdnsProvider, ProviderResult, ProviderSpec


@dataclass
class ProviderRecord:
    record_id: str
    name: str
    record_type: str
    value: str
    ttl: int = 600
    raw: Dict[str, Any] = field(default_factory=dict)


def _clean_error(value: Any, secret_values: Any = ()) -> str:
    text = str(value or "")
    for secret in secret_values or ():
        secret_text = str(secret or "")
        if len(secret_text) >= 3:
            text = text.replace(secret_text, "[REDACTED]")
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)(accesskeysecret|secretkey|token|signature|authorization)=?[^\s&,;]+", r"\1=[REDACTED]", text)
    return text[:240]


def _failure(provider: str, record_type: str, code: str, message: str, record_id: str = "", secret_values: Any = ()) -> ProviderResult:
    safe_code = _clean_error(code, secret_values) or "provider_error"
    safe_message = _clean_error(message, secret_values) or "provider request failed"
    return ProviderResult(
        False,
        "error",
        safe_message,
        provider=provider,
        record_type=record_type,
        record_id=record_id,
        changed=False,
        error_code=safe_code,
        error_message=safe_message,
    )


def _success(provider: str, record_type: str, changed: bool, record_id: str = "") -> ProviderResult:
    return ProviderResult(
        True,
        "success",
        provider=provider,
        record_type=record_type,
        record_id=record_id,
        changed=changed,
    )


def _required(credentials: Mapping[str, str], keys: Tuple[str, ...], provider: str, record_type: str) -> Optional[ProviderResult]:
    missing = [key for key in keys if not str(credentials.get(key) or "").strip()]
    if missing:
        return _failure(provider, record_type, "credential_error", "provider credentials are not configured")
    return None


def _zone_rr(hostname: str, credentials: Mapping[str, str], provider: str, record_type: str) -> Tuple[Optional[Tuple[str, str]], Optional[ProviderResult]]:
    hostname = str(hostname or "").strip().rstrip(".").lower()
    zone = str(credentials.get("zone") or credentials.get("domain") or "").strip().rstrip(".").lower()
    if not zone:
        return None, _failure(provider, record_type, "zone_required", "provider zone/domain is required")
    if hostname != zone and not hostname.endswith("." + zone):
        return None, _failure(provider, record_type, "zone_mismatch", "hostname is outside the configured zone")
    rr = "@" if hostname == zone else hostname[: -(len(zone) + 1)]
    return (zone, rr), None


class _HttpProvider(DdnsProvider):
    def __init__(self, spec: ProviderSpec, session: Optional[requests.Session] = None):
        super().__init__(spec)
        self.session = session or requests.Session()

    def _request_json(self, method: str, url: str, record_type: str, **kwargs: Any) -> Tuple[Optional[Dict[str, Any]], Optional[ProviderResult]]:
        try:
            response = self.session.request(method, url, timeout=(4, 8), **kwargs)
        except requests.RequestException:
            return None, _failure(self.provider_id, record_type, "network_error", "provider request failed")
        try:
            payload = response.json()
        except (ValueError, TypeError):
            return None, _failure(self.provider_id, record_type, f"http_{response.status_code}", "provider returned invalid JSON")
        if not isinstance(payload, dict):
            return None, _failure(self.provider_id, record_type, f"http_{response.status_code}", "provider returned invalid JSON")
        if response.status_code in (401, 403):
            return None, _failure(self.provider_id, record_type, f"http_{response.status_code}", "provider authentication failed")
        if response.status_code == 429:
            return None, _failure(self.provider_id, record_type, "http_429", "provider rate limited")
        return payload, None

    def _request_text(self, method: str, url: str, record_type: str, **kwargs: Any) -> Tuple[Optional[str], Optional[ProviderResult]]:
        try:
            response = self.session.request(method, url, timeout=(4, 8), **kwargs)
        except requests.RequestException:
            return None, _failure(self.provider_id, record_type, "network_error", "provider request failed")
        if response.status_code in (401, 403):
            return None, _failure(self.provider_id, record_type, f"http_{response.status_code}", "provider authentication failed")
        if response.status_code == 429:
            return None, _failure(self.provider_id, record_type, "http_429", "provider rate limited")
        text = getattr(response, "text", None)
        if text is None:
            try:
                text = json.dumps(response.json(), ensure_ascii=False)
            except (ValueError, TypeError):
                text = ""
        return str(text or "").strip(), None


def _text_update_result(
    provider: str,
    record_type: str,
    body: str,
    status_code: int,
    credentials: Mapping[str, str],
    success_words: Tuple[str, ...] = ("good", "ok", "success", "updated", "nochg"),
) -> ProviderResult:
    """Normalize the small text responses used by DynDNS-compatible APIs."""
    normalized = (body or "").strip().splitlines()[0].strip().lower() if body else ""
    if status_code in (401, 403):
        return _failure(provider, record_type, f"http_{status_code}", "provider authentication failed", secret_values=credentials.values())
    if normalized in {word.lower() for word in success_words} or any(normalized.startswith(f"{word.lower()} ") for word in success_words):
        return _success(provider, record_type, normalized not in {"ok", "nochg"})
    auth_words = {"badauth", "unauthorized", "forbidden", "invalid token", "invalid_token", "authentication failed"}
    code = "authentication_failed" if normalized in auth_words else f"http_{status_code}" if status_code >= 400 else "provider_error"
    message = "provider authentication failed" if code == "authentication_failed" else "provider update failed"
    return _failure(provider, record_type, code, message, secret_values=credentials.values())


class AliDnsProvider(_HttpProvider):
    ENDPOINT = "https://alidns.aliyuncs.com/"
    MIN_TTL = 600
    MAX_TTL = 86400

    def __init__(self, session: Optional[requests.Session] = None):
        super().__init__(ProviderSpec("alidns", ("AccessKeyId", "AccessKeySecret", "zone"), supports_cname=True, supports_txt=True), session)

    def validate_credentials(self, credentials: Mapping[str, str]) -> ProviderResult:
        error = _required(credentials, ("AccessKeyId", "AccessKeySecret"), self.provider_id, "")
        if error:
            return error
        if not str(credentials.get("zone") or credentials.get("domain") or "").strip():
            return _failure(self.provider_id, "", "zone_required", "provider zone/domain is required")
        return ProviderResult(True, "valid", provider=self.provider_id)

    @staticmethod
    def _encode(value: Any) -> str:
        return quote(str(value), safe="~-_.")

    @classmethod
    def _normalize_ttl(cls, ttl: int) -> int:
        try:
            return min(cls.MAX_TTL, max(cls.MIN_TTL, int(ttl)))
        except (TypeError, ValueError):
            return cls.MIN_TTL

    def _signed_params(self, action: str, extra: Mapping[str, Any], credentials: Mapping[str, str]) -> Dict[str, str]:
        params = {
            "AccessKeyId": str(credentials.get("AccessKeyId", "")),
            "Action": action,
            "Format": "JSON",
            "SignatureMethod": "HMAC-SHA1",
            "SignatureNonce": uuid.uuid4().hex,
            "SignatureVersion": "1.0",
            "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Version": "2015-01-09",
        }
        params.update({str(key): str(value) for key, value in extra.items() if value is not None})
        canonical = "&".join(f"{self._encode(key)}={self._encode(params[key])}" for key in sorted(params))
        string_to_sign = "GET&%2F&" + self._encode(canonical)
        digest = hmac.new((str(credentials.get("AccessKeySecret", "")) + "&").encode(), string_to_sign.encode(), hashlib.sha1).digest()
        params["Signature"] = base64.b64encode(digest).decode("ascii")
        return params

    def _rpc(self, action: str, extra: Mapping[str, Any], credentials: Mapping[str, str], record_type: str) -> Tuple[Optional[Dict[str, Any]], Optional[ProviderResult]]:
        payload, error = self._request_json("GET", self.ENDPOINT, record_type, params=self._signed_params(action, extra, credentials), headers={"User-Agent": "LabProbe-Hub-DDNS"})
        if error:
            return None, error
        if payload.get("Code"):
            return None, _failure(self.provider_id, record_type, payload.get("Code", "provider_error"), payload.get("Message", "provider request failed"), secret_values=credentials.values())
        return payload, None

    def sync_record(self, hostname: str, record_type: str, value: str, ttl: int, credentials: Mapping[str, str]) -> ProviderResult:
        if not self.supports_record_type(record_type):
            return self.unsupported_result(record_type)
        ttl = self._normalize_ttl(ttl)
        error = _required(credentials, ("AccessKeyId", "AccessKeySecret"), self.provider_id, record_type)
        if error:
            return error
        zone_rr, error = _zone_rr(hostname, credentials, self.provider_id, record_type)
        if error:
            return error
        zone, rr = zone_rr
        payload, error = self._rpc("DescribeDomainRecords", {"DomainName": zone, "RRKeyWord": rr, "TypeKeyWord": record_type, "PageNumber": 1, "PageSize": 100}, credentials, record_type)
        if error:
            return error
        records = ((payload or {}).get("DomainRecords") or {}).get("Record") or []
        found = next((item for item in records if str(item.get("Type", "")).upper() == record_type and str(item.get("RR", "@")) == rr), None)
        if found is None:
            created, error = self._rpc("AddDomainRecord", {"DomainName": zone, "RR": rr, "Type": record_type, "Value": value, "TTL": ttl}, credentials, record_type)
            if error:
                return error
            return _success(self.provider_id, record_type, True, str((created or {}).get("RecordId", "")))
        record_id = str(found.get("RecordId", ""))
        if str(found.get("Value", "")) == value:
            return _success(self.provider_id, record_type, False, record_id)
        updated, error = self._rpc("UpdateDomainRecord", {"RecordId": record_id, "RR": rr, "Type": record_type, "Value": value, "TTL": ttl}, credentials, record_type)
        if error:
            return error
        return _success(self.provider_id, record_type, True, str((updated or {}).get("RecordId", record_id)))


class DnsPodProvider(_HttpProvider):
    ENDPOINT = "https://dnspod.tencentcloudapi.com"

    def __init__(self, session: Optional[requests.Session] = None):
        super().__init__(ProviderSpec("dnspod", ("SecretId", "SecretKey", "zone"), supports_cname=True, supports_txt=True), session)

    def validate_credentials(self, credentials: Mapping[str, str]) -> ProviderResult:
        error = _required(credentials, ("SecretId", "SecretKey"), self.provider_id, "")
        if error:
            return error
        if not str(credentials.get("zone") or credentials.get("domain") or "").strip():
            return _failure(self.provider_id, "", "zone_required", "provider zone/domain is required")
        return ProviderResult(True, "valid", provider=self.provider_id)

    def _headers(self, action: str, body: Mapping[str, Any], credentials: Mapping[str, str]) -> Dict[str, str]:
        host = "dnspod.tencentcloudapi.com"
        service = "dnspod"
        timestamp = int(time.time())
        date = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d")
        body_text = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
        hashed = hashlib.sha256(body_text.encode()).hexdigest()
        canonical_headers = f"content-type:application/json; charset=utf-8\nhost:{host}\n"
        signed_headers = "content-type;host"
        canonical_request = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{hashed}"
        credential_scope = f"{date}/{service}/tc3_request"
        string_to_sign = f"TC3-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        secret_date = hmac.new(("TC3" + str(credentials.get("SecretKey", ""))).encode(), date.encode(), hashlib.sha256).digest()
        secret_service = hmac.new(secret_date, service.encode(), hashlib.sha256).digest()
        secret_signing = hmac.new(secret_service, b"tc3_request", hashlib.sha256).digest()
        signature = hmac.new(secret_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
        return {
            "Content-Type": "application/json; charset=utf-8",
            "Host": host,
            "X-TC-Action": action,
            "X-TC-Version": "2021-03-23",
            "X-TC-Timestamp": str(timestamp),
            "Authorization": f"TC3-HMAC-SHA256 Credential={credentials.get('SecretId', '')}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        }

    def _rpc(self, action: str, body: Mapping[str, Any], credentials: Mapping[str, str], record_type: str) -> Tuple[Optional[Dict[str, Any]], Optional[ProviderResult]]:
        payload, error = self._request_json("POST", self.ENDPOINT, record_type, json=body, headers=self._headers(action, body, credentials))
        if error:
            return None, error
        response = (payload or {}).get("Response") or {}
        api_error = response.get("Error") or {}
        if api_error:
            return None, _failure(self.provider_id, record_type, api_error.get("Code", "provider_error"), api_error.get("Message", "provider request failed"), secret_values=credentials.values())
        return response, None

    def sync_record(self, hostname: str, record_type: str, value: str, ttl: int, credentials: Mapping[str, str]) -> ProviderResult:
        if not self.supports_record_type(record_type):
            return self.unsupported_result(record_type)
        error = _required(credentials, ("SecretId", "SecretKey"), self.provider_id, record_type)
        if error:
            return error
        zone_rr, error = _zone_rr(hostname, credentials, self.provider_id, record_type)
        if error:
            return error
        zone, rr = zone_rr
        body = {"Domain": zone, "Subdomain": rr, "RecordType": record_type, "RecordLine": "默认"}
        response, error = self._rpc("DescribeRecordList", body, credentials, record_type)
        if error:
            return error
        records = (response or {}).get("RecordList") or []
        found = next((item for item in records if str(item.get("Type", "")).upper() == record_type and str(item.get("Name", rr)) == rr), None)
        if found is None:
            # DNSPod's minimum TTL varies by domain plan. TTL is optional for
            # record writes, so let DNSPod apply its plan-valid default.
            created, error = self._rpc("CreateRecord", {**body, "Value": value}, credentials, record_type)
            if error:
                return error
            return _success(self.provider_id, record_type, True, str((created or {}).get("RecordId", "")))
        record_id = str(found.get("RecordId", ""))
        if str(found.get("Value", "")) == value:
            return _success(self.provider_id, record_type, False, record_id)
        updated, error = self._rpc("ModifyRecord", {**body, "RecordId": record_id, "Value": value}, credentials, record_type)
        if error:
            return error
        return _success(self.provider_id, record_type, True, record_id)


class CloudflareProvider(_HttpProvider):
    BASE = "https://api.cloudflare.com/client/v4"

    def __init__(self, session: Optional[requests.Session] = None):
        super().__init__(ProviderSpec("cloudflare", ("apiToken", "zoneId"), supports_cname=True, supports_txt=True), session)

    def validate_credentials(self, credentials: Mapping[str, str]) -> ProviderResult:
        if not str(credentials.get("apiToken") or credentials.get("token") or "").strip() or not str(credentials.get("zoneId") or "").strip():
            return _failure(self.provider_id, "", "credential_error", "provider credentials are not configured")
        return ProviderResult(True, "valid", provider=self.provider_id)

    def _headers(self, credentials: Mapping[str, str]) -> Dict[str, str]:
        return {"Authorization": f"Bearer {credentials.get('apiToken') or credentials.get('token') or ''}", "Content-Type": "application/json", "User-Agent": "LabProbe-Hub-DDNS"}

    def _api(self, method: str, path: str, record_type: str, credentials: Mapping[str, str], **kwargs: Any) -> Tuple[Optional[Dict[str, Any]], Optional[ProviderResult]]:
        payload, error = self._request_json(method, self.BASE + path, record_type, headers=self._headers(credentials), **kwargs)
        if error:
            return None, error
        if not payload.get("success", False):
            errors = payload.get("errors") or [{}]
            first = errors[0] if isinstance(errors, list) and errors else {}
            return None, _failure(self.provider_id, record_type, first.get("code", "provider_error"), first.get("message", "provider request failed"), secret_values=credentials.values())
        return payload, None

    def sync_record(self, hostname: str, record_type: str, value: str, ttl: int, credentials: Mapping[str, str]) -> ProviderResult:
        if not self.supports_record_type(record_type):
            return self.unsupported_result(record_type)
        if not str(credentials.get("apiToken") or credentials.get("token") or "").strip() or not str(credentials.get("zoneId") or "").strip():
            return _failure(self.provider_id, record_type, "credential_error", "provider credentials are not configured")
        zone_id = str(credentials.get("zoneId"))
        payload, error = self._api("GET", f"/zones/{quote(zone_id, safe='')}/dns_records", record_type, credentials, params={"name": hostname.rstrip("."), "type": record_type, "per_page": 100})
        if error:
            return error
        records = (payload or {}).get("result") or []
        found = next((item for item in records if str(item.get("name", "")).rstrip(".").lower() == hostname.rstrip(".").lower() and str(item.get("type", "")).upper() == record_type), None)
        if found is None:
            body = {"type": record_type, "name": hostname.rstrip("."), "content": value, "ttl": ttl}
            if record_type in {"A", "AAAA", "CNAME"}:
                body["proxied"] = False
            created, error = self._api("POST", f"/zones/{quote(zone_id, safe='')}/dns_records", record_type, credentials, json=body)
            if error:
                return error
            return _success(self.provider_id, record_type, True, str(((created or {}).get("result") or {}).get("id", "")))
        record_id = str(found.get("id", ""))
        if str(found.get("content", "")) == value:
            return _success(self.provider_id, record_type, False, record_id)
        body = {key: item for key, item in found.items() if key not in {"id", "zone_id", "zone_name", "created_on", "modified_on", "meta"}}
        body.update({"type": record_type, "name": hostname.rstrip("."), "content": value, "ttl": ttl})
        body.setdefault("proxied", False)
        updated, error = self._api("PATCH", f"/zones/{quote(zone_id, safe='')}/dns_records/{quote(record_id, safe='')}", record_type, credentials, json=body)
        if error:
            return error
        return _success(self.provider_id, record_type, True, str(((updated or {}).get("result") or {}).get("id", record_id)))


class Dynv6Provider(_HttpProvider):
    """dynv6 single-host A/AAAA update endpoint."""

    ENDPOINT = "https://dynv6.com/api/update"

    def __init__(self, session: Optional[requests.Session] = None):
        super().__init__(ProviderSpec("dynv6", ("token",)), session)

    def validate_credentials(self, credentials: Mapping[str, str]) -> ProviderResult:
        return ProviderResult(True, "valid", provider=self.provider_id) if str(credentials.get("token") or "").strip() else _failure(self.provider_id, "", "credential_error", "provider credentials are not configured")

    def sync_record(self, hostname: str, record_type: str, value: str, ttl: int, credentials: Mapping[str, str]) -> ProviderResult:
        if not self.supports_record_type(record_type):
            return self.unsupported_result(record_type)
        token = str(credentials.get("token") or "").strip()
        if not token:
            return _failure(self.provider_id, record_type, "credential_error", "provider credentials are not configured")
        params = {"zone": hostname.rstrip("."), "token": token, "ipv4" if record_type == "A" else "ipv6": value}
        body, error = self._request_text("GET", self.ENDPOINT, record_type, params=params)
        if error:
            return error
        return _text_update_result(self.provider_id, record_type, body or "", 200, credentials)


class DuckDnsProvider(_HttpProvider):
    """DuckDNS update endpoint; A and AAAA are issued as separate calls."""

    ENDPOINT = "https://www.duckdns.org/update"

    def __init__(self, session: Optional[requests.Session] = None):
        super().__init__(ProviderSpec("duckdns", ("token",), supports_txt=True), session)

    def validate_credentials(self, credentials: Mapping[str, str]) -> ProviderResult:
        return ProviderResult(True, "valid", provider=self.provider_id) if str(credentials.get("token") or "").strip() else _failure(self.provider_id, "", "credential_error", "provider credentials are not configured")

    @staticmethod
    def _domain(hostname: str) -> str:
        value = hostname.rstrip(".")
        suffix = ".duckdns.org"
        return value[:-len(suffix)] if value.lower().endswith(suffix) else value

    def sync_record(self, hostname: str, record_type: str, value: str, ttl: int, credentials: Mapping[str, str]) -> ProviderResult:
        if not self.supports_record_type(record_type):
            return self.unsupported_result(record_type)
        token = str(credentials.get("token") or "").strip()
        if not token:
            return _failure(self.provider_id, record_type, "credential_error", "provider credentials are not configured")
        params = {"domains": self._domain(hostname), "token": token}
        if record_type == "TXT":
            params["txt"] = value
        elif record_type == "AAAA":
            params["ipv6"] = value
        else:
            params["ip"] = value
        body, error = self._request_text("GET", self.ENDPOINT, record_type, params=params)
        if error:
            return error
        return _text_update_result(self.provider_id, record_type, body or "", 200, credentials, ("OK", "nochg"))


class DeSecProvider(_HttpProvider):
    """deSEC/dedyn.io dynDNS update endpoint."""

    ENDPOINT = "https://update.dedyn.io/"

    def __init__(self, session: Optional[requests.Session] = None):
        super().__init__(ProviderSpec("desec", ("token",)), session)

    def validate_credentials(self, credentials: Mapping[str, str]) -> ProviderResult:
        return ProviderResult(True, "valid", provider=self.provider_id) if str(credentials.get("token") or "").strip() else _failure(self.provider_id, "", "credential_error", "provider credentials are not configured")

    def sync_record(self, hostname: str, record_type: str, value: str, ttl: int, credentials: Mapping[str, str]) -> ProviderResult:
        if not self.supports_record_type(record_type):
            return self.unsupported_result(record_type)
        token = str(credentials.get("token") or "").strip()
        if not token:
            return _failure(self.provider_id, record_type, "credential_error", "provider credentials are not configured")
        params = {"hostname": hostname.rstrip("."), "myipv4": value if record_type == "A" else "preserve", "myipv6": value if record_type == "AAAA" else "preserve"}
        body, error = self._request_text("GET", self.ENDPOINT, record_type, params=params, headers={"Authorization": f"Token {token}"})
        if error:
            return error
        return _text_update_result(self.provider_id, record_type, body or "", 200, credentials)


class DynuProvider(_HttpProvider):
    """Dynu official DynDNS IP update protocol."""

    ENDPOINT = "https://api.dynu.com/nic/update"

    def __init__(self, session: Optional[requests.Session] = None):
        super().__init__(ProviderSpec("dynu", ("username", "password")), session)

    def validate_credentials(self, credentials: Mapping[str, str]) -> ProviderResult:
        missing = _required(credentials, ("username", "password"), self.provider_id, "")
        return missing or ProviderResult(True, "valid", provider=self.provider_id)

    def sync_record(self, hostname: str, record_type: str, value: str, ttl: int, credentials: Mapping[str, str]) -> ProviderResult:
        if not self.supports_record_type(record_type):
            return self.unsupported_result(record_type)
        missing = _required(credentials, ("username", "password"), self.provider_id, record_type)
        if missing:
            return missing
        params = {"hostname": hostname.rstrip("."), "myip": value if record_type == "A" else "no", "myipv6": value if record_type == "AAAA" else "no"}
        body, error = self._request_text(
            "GET",
            self.ENDPOINT,
            record_type,
            params=params,
            auth=(str(credentials["username"]), str(credentials["password"])),
            headers={"User-Agent": "LabProbe-Hub-DDNS"},
        )
        if error:
            return error
        return _text_update_result(self.provider_id, record_type, body or "", 200, credentials)


class IPv64Provider(_HttpProvider):
    """IPv64.net DynDNS2 updater with Bearer token authentication."""

    ENDPOINT = "https://ipv64.net/nic/update"

    def __init__(self, session: Optional[requests.Session] = None):
        super().__init__(ProviderSpec("ipv64", ("token",)), session)

    def validate_credentials(self, credentials: Mapping[str, str]) -> ProviderResult:
        return ProviderResult(True, "valid", provider=self.provider_id) if str(credentials.get("token") or "").strip() else _failure(self.provider_id, "", "credential_error", "provider credentials are not configured")

    def sync_record(self, hostname: str, record_type: str, value: str, ttl: int, credentials: Mapping[str, str]) -> ProviderResult:
        if not self.supports_record_type(record_type):
            return self.unsupported_result(record_type)
        token = str(credentials.get("token") or "").strip()
        if not token:
            return _failure(self.provider_id, record_type, "credential_error", "provider credentials are not configured")
        params = {"host": hostname.rstrip("."), "ip" if record_type == "A" else "ip6": value}
        body, error = self._request_text("GET", self.ENDPOINT, record_type, params=params, headers={"Authorization": f"Bearer {token}"})
        if error:
            return error
        raw = (body or "").strip()
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError):
            payload = None
        if isinstance(payload, dict):
            status = str(payload.get("status") or payload.get("Status") or payload.get("info") or "").lower()
            if status in {"success", "good", "ok", "updated", "nochg"}:
                return _success(self.provider_id, record_type, status not in {"ok", "nochg"})
            if status in {"401", "403", "unauthorized", "forbidden"}:
                return _failure(self.provider_id, record_type, "authentication_failed", "provider authentication failed", secret_values=credentials.values())
            return _failure(self.provider_id, record_type, f"http_{200}", "provider update failed", secret_values=credentials.values())
        return _text_update_result(self.provider_id, record_type, raw, 200, credentials)
