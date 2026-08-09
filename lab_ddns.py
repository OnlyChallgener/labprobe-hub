"""Phase 1A LabProbe DDNS state and provider abstraction.

This module intentionally does not make provider network calls. It stores the
Relay's detected address separately from the address last published by a
future provider adapter.
"""
from __future__ import annotations

import json
import ipaddress
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from flask import Blueprint, jsonify, request


PROVIDER_IDS = (
    "alidns",
    "dnspod",
    "cloudflare",
    "dynv6",
    "duckdns",
    "desec",
    "dynu",
    "ipv64",
)

FLOW_STATUSES = {"disabled", "waiting", "detected", "updating", "published", "error"}
IPV4_STATES = {"public", "cgnat", "unavailable", "ambiguous"}
IPV6_STATES = {"public", "unavailable", "ambiguous"}
RECORD_TYPES = ("A", "AAAA")
RETRY_DELAYS = (30, 120, 600, 1800)


@dataclass(frozen=True)
class ProviderSpec:
    provider_id: str
    credential_schema: tuple[str, ...]
    supports_a: bool = True
    supports_aaaa: bool = True


@dataclass(frozen=True)
class ProviderResult:
    ok: bool
    status: str
    error: str = ""
    provider: str = ""
    record_type: str = ""
    record_id: str = ""
    changed: bool = False
    error_code: str = ""
    error_message: str = ""


class DdnsProvider:
    """Small adapter contract; Phase 1A deliberately performs no I/O."""

    def __init__(self, spec: ProviderSpec):
        self.spec = spec

    @property
    def provider_id(self) -> str:
        return self.spec.provider_id

    def validate_credentials(self, credentials: Mapping[str, str]) -> ProviderResult:
        return ProviderResult(True, "valid", provider=self.provider_id)

    def find_record(self, hostname: str, record_type: str, credentials: Mapping[str, str]):
        raise NotImplementedError

    def create_record(self, hostname: str, record_type: str, value: str, ttl: int, credentials: Mapping[str, str]) -> ProviderResult:
        return ProviderResult(False, "not_implemented", "Provider API is disabled in Phase 1A", provider=self.provider_id, record_type=record_type, error_code="not_implemented", error_message="Provider API is disabled in Phase 1A")

    def update_record(self, record: Any, hostname: str, record_type: str, value: str, ttl: int, credentials: Mapping[str, str]) -> ProviderResult:
        return ProviderResult(False, "not_implemented", "Provider API is disabled in Phase 1A", provider=self.provider_id, record_type=record_type, error_code="not_implemented", error_message="Provider API is disabled in Phase 1A")

    def sync_record(self, hostname: str, record_type: str, value: str, ttl: int, credentials: Mapping[str, str]) -> ProviderResult:
        return self.update(hostname, value, "", credentials)

    def update(self, hostname: str, ipv4: str, ipv6: str, credentials: Mapping[str, str]) -> ProviderResult:
        return ProviderResult(False, "not_implemented", "Provider API is disabled in Phase 1A", provider=self.provider_id, error_code="not_implemented", error_message="Provider API is disabled in Phase 1A")


PROVIDERS: Dict[str, DdnsProvider] = {
    provider_id: DdnsProvider(ProviderSpec(provider_id, ("token",)))
    for provider_id in PROVIDER_IDS
}


def _install_provider_adapters() -> None:
    from lab_ddns_providers import (
        AliDnsProvider,
        CloudflareProvider,
        DeSecProvider,
        DnsPodProvider,
        DuckDnsProvider,
        DynuProvider,
        Dynv6Provider,
        IPv64Provider,
    )

    PROVIDERS.update({
        "alidns": AliDnsProvider(),
        "dnspod": DnsPodProvider(),
        "cloudflare": CloudflareProvider(),
        "dynv6": Dynv6Provider(),
        "duckdns": DuckDnsProvider(),
        "desec": DeSecProvider(),
        "dynu": DynuProvider(),
        "ipv64": IPv64Provider(),
    })


_install_provider_adapters()


def provider_specs() -> List[Dict[str, Any]]:
    # Credential schemas stay an internal adapter concern in Phase 1A.  Do not
    # expose even field names through APP-facing responses before credentials
    # have a dedicated secret store.
    return [
        {
            "id": provider.spec.provider_id,
            "supportsA": provider.spec.supports_a,
            "supportsAAAA": provider.spec.supports_aaaa,
        }
        for provider in PROVIDERS.values()
    ]


def _now() -> int:
    return int(time.time())


def _text(value: Any) -> str:
    return str(value or "").strip()


def _redact_error(value: Any, credentials: Mapping[str, Any]) -> str:
    """Keep adapter failures safe even if an adapter returns raw provider text."""
    text = _text(value)
    for secret in credentials.values():
        secret_text = _text(secret)
        if len(secret_text) >= 3:
            text = text.replace(secret_text, "[REDACTED]")
    return text[:240]


def _ip_text(value: Any, version: int) -> str:
    text = _text(value)
    if not text:
        return ""
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return ""
    return text if parsed.version == version else ""


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _optional_int(value: Any) -> Optional[int]:
    parsed = _safe_int(value)
    return parsed or None


def _bool(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"false", "0", "no", "off"}:
            return False
        if lowered in {"true", "1", "yes", "on"}:
            return True
    return default


def _empty_root() -> Dict[str, Any]:
    return {"version": 1, "address": {}, "records": []}


def _empty_tracker() -> Dict[str, Dict[str, Any]]:
    return {
        record_type: {"candidate": "", "stableCount": 0, "retryAttempt": 0, "nextRetryAt": 0, "authError": False}
        for record_type in RECORD_TYPES
    }


def _normal_tracker(value: Any) -> Dict[str, Dict[str, Any]]:
    result = _empty_tracker()
    if not isinstance(value, dict):
        return result
    for record_type in RECORD_TYPES:
        item = value.get(record_type)
        if not isinstance(item, dict):
            continue
        result[record_type] = {
            "candidate": _ip_text(item.get("candidate"), 4 if record_type == "A" else 6),
            "stableCount": min(2, _safe_int(item.get("stableCount"))),
            "retryAttempt": min(len(RETRY_DELAYS), _safe_int(item.get("retryAttempt"))),
            "nextRetryAt": _safe_int(item.get("nextRetryAt")),
            "authError": _bool(item.get("authError"), False),
        }
    return result


def _normal_results(value: Any) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    if not isinstance(value, dict):
        return result
    for record_type in RECORD_TYPES:
        item = value.get(record_type)
        if isinstance(item, dict):
            result[record_type] = {
                "success": bool(item.get("success")),
                "provider": _text(item.get("provider")),
                "recordType": record_type,
                "recordId": _text(item.get("recordId")),
                "changed": bool(item.get("changed")),
                "status": _text(item.get("status")),
                "errorCode": _text(item.get("errorCode")),
                "errorMessage": _text(item.get("errorMessage"))[:240],
            }
    return result


def _normal_address(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    detected_ipv4 = _ip_text(value.get("detectedIpv4"), 4)
    detected_ipv6 = _ip_text(value.get("detectedIpv6"), 6)
    ipv4_state = _text(value.get("ipv4State"))
    ipv6_state = _text(value.get("ipv6State"))
    if ipv4_state == "public" and not detected_ipv4:
        ipv4_state = "unavailable"
    if ipv6_state == "public" and not detected_ipv6:
        ipv6_state = "unavailable"
    return {
        "detectedIpv4": detected_ipv4,
        "detectedIpv6": detected_ipv6,
        "ipv4State": ipv4_state if ipv4_state in IPV4_STATES else "unavailable",
        "ipv6State": ipv6_state if ipv6_state in IPV6_STATES else "unavailable",
        "ipv4Source": _text(value.get("ipv4Source")),
        "ipv6Source": _text(value.get("ipv6Source")),
        "detectedAt": _safe_int(value.get("detectedAt")),
    }


def _normal_record(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    provider = _text(value.get("provider")).lower()
    if provider not in PROVIDERS:
        return None
    record_types = value.get("recordTypes")
    if isinstance(record_types, str):
        record_types = [record_types]
    if not isinstance(record_types, list):
        record_types = ["A", "AAAA"]
    record_types = [item for item in (_text(item).upper() for item in record_types) if item in set(RECORD_TYPES)]
    if not record_types:
        record_types = ["A", "AAAA"]
    record_id = _text(value.get("id")) or uuid.uuid4().hex
    enabled = _bool(value.get("enabled", True))
    status = _text(value.get("status"))
    if not enabled:
        status = "disabled"
    elif status not in FLOW_STATUSES:
        status = "waiting"
    return {
        "id": record_id,
        "provider": provider,
        "hostname": _text(value.get("hostname")),
        "recordTypes": list(dict.fromkeys(record_types)),
        "ttl": min(86400, max(60, _safe_int(value.get("ttl"), 600))),
        "enabled": enabled,
        "detectedIpv4": _ip_text(value.get("detectedIpv4"), 4),
        "detectedIpv6": _ip_text(value.get("detectedIpv6"), 6),
        "ipv4State": _text(value.get("ipv4State")) if _text(value.get("ipv4State")) in IPV4_STATES else "unavailable",
        "ipv6State": _text(value.get("ipv6State")) if _text(value.get("ipv6State")) in IPV6_STATES else "unavailable",
        "publishedIpv4": _ip_text(value.get("publishedIpv4"), 4) or None,
        "publishedIpv6": _ip_text(value.get("publishedIpv6"), 6) or None,
        "source": _text(value.get("source")),
        "status": status,
        "lastDetectedAt": _safe_int(value.get("lastDetectedAt")),
        "lastUpdatedAt": _optional_int(value.get("lastUpdatedAt")),
        "lastError": _text(value.get("lastError")) or None,
        "stability": _normal_tracker(value.get("stability")),
        "lastRecordResults": _normal_results(value.get("lastRecordResults")),
    }


class LabDdnsSecretsStore:
    """Private, atomic credential storage kept out of public DDNS state."""

    def __init__(self, path: Path, logger: Any = None):
        self.path = path
        self.logger = logger
        self.lock = threading.RLock()
        self.root: Dict[str, Any] = {"version": 1, "records": {}}
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                records = raw.get("records") if isinstance(raw, dict) else None
                if isinstance(records, dict):
                    self.root["records"] = {
                        str(record_id): {
                            str(key): _text(value)
                            for key, value in values.items()
                            if isinstance(values, dict) and _text(value)
                        }
                        for record_id, values in records.items()
                        if isinstance(values, dict)
                    }
        except Exception as exc:
            if self.logger:
                self.logger.warning("LabProbe DDNS secret load failed: %s", type(exc).__name__)

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.root, ensure_ascii=False, indent=2)
        fd, temp_name = tempfile.mkstemp(prefix="lab-ddns-secret-", suffix=".tmp", dir=str(self.path.parent))
        try:
            try:
                os.chmod(temp_name, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def save(self, record_id: str, credentials: Mapping[str, Any]) -> bool:
        safe = {str(key): _text(value) for key, value in credentials.items() if _text(value)}
        if not safe:
            return False
        with self.lock:
            self.root["records"][str(record_id)] = safe
            self._save_locked()
        return True

    def get(self, record_id: str) -> Dict[str, str]:
        with self.lock:
            values = self.root["records"].get(str(record_id), {})
            return dict(values) if isinstance(values, dict) else {}

    def configured(self, record_id: str) -> bool:
        return bool(self.get(record_id))

    def delete(self, record_id: str) -> None:
        with self.lock:
            if str(record_id) in self.root["records"]:
                del self.root["records"][str(record_id)]
                self._save_locked()


class LabDdnsStore:
    def __init__(self, path: Path, logger: Any = None, secrets: Optional[LabDdnsSecretsStore] = None):
        self.path = path
        self.logger = logger
        self.secrets = secrets or LabDdnsSecretsStore(path.parent / "lab_ddns_secrets.json", logger)
        self.lock = threading.RLock()
        self.root = _empty_root()
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self.root["address"] = _normal_address(raw.get("address"))
                    records = []
                    for item in raw.get("records", []):
                        record = _normal_record(item)
                        if record is None:
                            continue
                        # A restart must wait for a fresh Relay sample before
                        # satisfying the two-sample stability gate.
                        for tracker in record["stability"].values():
                            tracker.update({"candidate": "", "stableCount": 0})
                        records.append(record)
                    self.root["records"] = records
        except Exception as exc:
            if self.logger:
                self.logger.warning("LabProbe DDNS state load failed: %s", type(exc).__name__)

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.root, ensure_ascii=False, indent=2)
        fd, temp_name = tempfile.mkstemp(prefix="lab-ddns-", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self.root, ensure_ascii=False))

    def public_snapshot(self) -> Dict[str, Any]:
        snapshot = self.snapshot()
        for record in snapshot.get("records", []):
            record["credentialsConfigured"] = self.secrets.configured(record.get("id", ""))
        return snapshot

    def accept_address(self, value: Any) -> bool:
        address = _normal_address(value)
        if not address:
            return False
        with self.lock:
            if not address["detectedAt"]:
                address["detectedAt"] = (
                    _safe_int(self.root.get("address", {}).get("detectedAt")) or _now()
                )
            previous_address = self.root.get("address", {})
            sample_changed = previous_address.get("detectedAt") != address.get("detectedAt")
            changed = previous_address != address
            self.root["address"] = address
            for record in self.root["records"]:
                source = ",".join(filter(None, [address["ipv4Source"], address["ipv6Source"]]))
                values = {
                    "detectedIpv4": address["detectedIpv4"],
                    "detectedIpv6": address["detectedIpv6"],
                    "ipv4State": address["ipv4State"],
                    "ipv6State": address["ipv6State"],
                    "source": source,
                    "lastDetectedAt": address["detectedAt"],
                }
                if any(record.get(key) != item for key, item in values.items()):
                    changed = True
                    record.update(values)
                for record_type, state_key, detected_key, published_key in (
                    ("A", "ipv4State", "detectedIpv4", "publishedIpv4"),
                    ("AAAA", "ipv6State", "detectedIpv6", "publishedIpv6"),
                ):
                    tracker = record.setdefault("stability", _empty_tracker()).setdefault(record_type, _empty_tracker()[record_type])
                    tracker_before = dict(tracker)
                    detected = address[detected_key]
                    published = record.get(published_key) or ""
                    if not sample_changed:
                        pass
                    elif record_type not in record.get("recordTypes", RECORD_TYPES):
                        tracker.update({"candidate": "", "stableCount": 0})
                    elif address[state_key] == "public" and detected and detected != published:
                        if tracker.get("candidate") == detected:
                            tracker["stableCount"] = min(2, _safe_int(tracker.get("stableCount")) + 1)
                        else:
                            tracker.update({"candidate": detected, "stableCount": 1, "retryAttempt": 0, "nextRetryAt": 0, "authError": False})
                            changed = True
                    else:
                        if tracker.get("candidate") or tracker.get("stableCount"):
                            changed = True
                        tracker.update({"candidate": "", "stableCount": 0})
                        if detected == published:
                            tracker.update({"retryAttempt": 0, "nextRetryAt": 0, "authError": False})
                    if tracker != tracker_before:
                        changed = True
                pending = any(
                    record_type in record.get("recordTypes", RECORD_TYPES)
                    and address[state_key] == "public"
                    and address[detected_key]
                    and address[detected_key] != (record.get(published_key) or "")
                    for record_type, state_key, detected_key, published_key in (
                        ("A", "ipv4State", "detectedIpv4", "publishedIpv4"),
                        ("AAAA", "ipv6State", "detectedIpv6", "publishedIpv6"),
                    )
                )
                has_published = any(record.get(key) for key in ("publishedIpv4", "publishedIpv6"))
                if not record.get("enabled", True):
                    new_status, new_error = "disabled", record.get("lastError")
                elif record.get("status") in {"error", "updating"}:
                    new_status, new_error = record.get("status"), record.get("lastError")
                elif pending:
                    new_status, new_error = "detected", None
                elif has_published:
                    new_status, new_error = "published", None
                else:
                    new_status, new_error = "waiting", None
                if record.get("status") != new_status or record.get("lastError") != new_error:
                    changed = True
                    record["status"], record["lastError"] = new_status, new_error
            if changed:
                self._save_locked()
        return True

    def save_record(self, value: Mapping[str, Any], record_id: str = "") -> Dict[str, Any]:
        record = _normal_record(dict(value))
        if record is None or not record["hostname"]:
            raise ValueError("provider and hostname are required")
        with self.lock:
            if record_id:
                for index, old in enumerate(self.root["records"]):
                    if old["id"] == record_id:
                        record["id"] = record_id
                        for key in ("detectedIpv4", "detectedIpv6", "ipv4State", "ipv6State", "publishedIpv4", "publishedIpv6", "source", "status", "lastDetectedAt", "lastUpdatedAt", "lastError", "stability", "lastRecordResults"):
                            record[key] = old.get(key, record[key])
                        record["ttl"] = record["ttl"] if "ttl" in value else old.get("ttl", record["ttl"])
                        record["enabled"] = _bool(value.get("enabled", old.get("enabled", True)))
                        if not record["enabled"]:
                            record["status"] = "disabled"
                        elif old.get("status") == "disabled":
                            record["status"] = "detected" if record["detectedIpv4"] or record["detectedIpv6"] else "waiting"
                        self.root["records"][index] = record
                        self._save_locked()
                        return dict(record)
                raise KeyError(record_id)
            address = self.root.get("address", {})
            record["detectedIpv4"] = address.get("detectedIpv4", "")
            record["detectedIpv6"] = address.get("detectedIpv6", "")
            record["ipv4State"] = address.get("ipv4State", "unavailable")
            record["ipv6State"] = address.get("ipv6State", "unavailable")
            record["lastDetectedAt"] = _safe_int(address.get("detectedAt"))
            record["source"] = ",".join(filter(None, [address.get("ipv4Source", ""), address.get("ipv6Source", "")]))
            if not record["enabled"]:
                record["status"] = "disabled"
            else:
                record["status"] = "detected" if record["detectedIpv4"] or record["detectedIpv6"] else "waiting"
            self.root["records"].append(record)
            self._save_locked()
            return dict(record)

    def save_credentials(self, record_id: str, credentials: Mapping[str, Any]) -> bool:
        return self.secrets.save(record_id, credentials)

    def run_update(self, record_id: str, force: bool = False) -> Dict[str, Any]:
        """Explicit execution path; dashboard ingestion never calls providers."""
        with self.lock:
            record = next((item for item in self.root["records"] if item["id"] == record_id), None)
            if record is None:
                raise KeyError(record_id)
            if not record.get("enabled", True):
                record["status"] = "disabled"
                self._save_locked()
                return {"ok": True, "status": "disabled", "results": {}}
            provider = PROVIDERS.get(record.get("provider", ""))
            credentials = self.secrets.get(record_id)
            if provider is None:
                raise ValueError("unknown provider")
            now = _now()
            work = []
            results: Dict[str, Dict[str, Any]] = {}
            for record_type, state_key, detected_key, published_key in (
                ("A", "ipv4State", "detectedIpv4", "publishedIpv4"),
                ("AAAA", "ipv6State", "detectedIpv6", "publishedIpv6"),
            ):
                if record_type not in record.get("recordTypes", RECORD_TYPES):
                    continue
                detected = record.get(detected_key) or ""
                published = record.get(published_key) or ""
                tracker = record["stability"][record_type]
                if record.get(state_key) == "public" and detected and detected != published:
                    if _safe_int(tracker.get("stableCount")) < 2:
                        results[record_type] = {"success": False, "status": "waiting_for_stability", "provider": provider.provider_id, "recordType": record_type, "recordId": "", "changed": False, "errorCode": "", "errorMessage": ""}
                    elif tracker.get("authError") and not force:
                        results[record_type] = {"success": False, "status": "credential_error", "provider": provider.provider_id, "recordType": record_type, "recordId": "", "changed": False, "errorCode": "credential_error", "errorMessage": "credentials require correction"}
                    elif _safe_int(tracker.get("nextRetryAt")) > now and not force:
                        results[record_type] = {"success": False, "status": "retry_backoff", "provider": provider.provider_id, "recordType": record_type, "recordId": "", "changed": False, "errorCode": "retry_backoff", "errorMessage": "retry is deferred"}
                    else:
                        work.append((record_type, detected, tracker))
                else:
                    results[record_type] = {"success": True, "status": "noop", "provider": provider.provider_id, "recordType": record_type, "recordId": "", "changed": False, "errorCode": "", "errorMessage": ""}
            if not work:
                record["lastRecordResults"] = results
                if any(item.get("status") in {"waiting_for_stability", "retry_backoff", "credential_error"} for item in results.values()):
                    record["status"] = "detected" if record.get("status") != "error" else "error"
                elif any(record.get(key) for key in ("publishedIpv4", "publishedIpv6")):
                    record["status"] = "published"
                    record["lastError"] = None
                self._save_locked()
                return {"ok": True, "status": record["status"], "results": results}
            record["status"] = "updating"
            self._save_locked()
        for record_type, detected, _tracker in work:
            try:
                result = provider.sync_record(record["hostname"], record_type, detected, record["ttl"], credentials)
            except Exception:
                result = ProviderResult(False, "error", "provider request failed", provider=provider.provider_id, record_type=record_type, error_code="provider_error", error_message="provider request failed")
            results[record_type] = {
                "success": bool(result.ok),
                "status": "published" if result.ok else "error",
                "provider": result.provider or provider.provider_id,
                "recordType": record_type,
                "recordId": result.record_id,
                "changed": bool(result.changed),
                "errorCode": result.error_code,
                "errorMessage": _redact_error(result.error_message or result.error, credentials),
            }
        with self.lock:
            current = next(item for item in self.root["records"] if item["id"] == record_id)
            now = _now()
            any_error = False
            for record_type, result in results.items():
                if result.get("success"):
                    detected_key = "detectedIpv4" if record_type == "A" else "detectedIpv6"
                    published_key = "publishedIpv4" if record_type == "A" else "publishedIpv6"
                    current[published_key] = current.get(detected_key) or None
                    current["lastUpdatedAt"] = now
                    tracker = current["stability"][record_type]
                    tracker.update({"candidate": "", "stableCount": 0, "retryAttempt": 0, "nextRetryAt": 0, "authError": False})
                else:
                    any_error = True
                    tracker = current["stability"][record_type]
                    code = _text(result.get("errorCode"))
                    auth_error = code in {"401", "403", "http_401", "http_403", "InvalidAccessKey", "InvalidAccessKeyId", "AuthFailure", "credential_error", "authentication_failed"}
                    attempt = min(len(RETRY_DELAYS), _safe_int(tracker.get("retryAttempt")) + 1)
                    tracker["retryAttempt"] = attempt
                    tracker["authError"] = auth_error
                    tracker["nextRetryAt"] = 0 if auth_error else now + RETRY_DELAYS[min(attempt - 1, len(RETRY_DELAYS) - 1)]
                    current["lastError"] = _redact_error(result.get("errorMessage"), credentials) or code or "provider update failed"
            current["lastRecordResults"] = results
            current["status"] = "error" if any_error else "published"
            if not any_error:
                current["lastError"] = None
            self._save_locked()
            return {"ok": not any_error, "status": current["status"], "results": results}

    def delete_record(self, record_id: str) -> bool:
        with self.lock:
            before = len(self.root["records"])
            self.root["records"] = [record for record in self.root["records"] if record["id"] != record_id]
            if len(self.root["records"]) == before:
                return False
            self._save_locked()
            return True


def install_lab_ddns(hub: Any) -> LabDdnsStore:
    existing = getattr(hub, "LAB_DDNS", None)
    if existing is not None:
        return existing
    secrets = LabDdnsSecretsStore(Path(hub.DATA_DIR) / "lab_ddns_secrets.json", hub.LOGGER)
    store = LabDdnsStore(Path(hub.DATA_DIR) / "lab_ddns.json", hub.LOGGER, secrets)
    hub.LAB_DDNS = store
    blueprint = Blueprint("lab_ddns", __name__, url_prefix="/api/ddns")

    @blueprint.get("")
    def get_ddns():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return jsonify({"ok": True, **store.public_snapshot(), "providers": provider_specs()})

    @blueprint.get("/providers")
    def get_providers():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return jsonify({"ok": True, "providers": provider_specs()})

    @blueprint.post("")
    def add_ddns():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            body = {}
        credentials = body.get("credentials", {}) if isinstance(body, dict) else {}
        try:
            record = store.save_record({key: value for key, value in body.items() if key != "credentials"})
        except ValueError as exc:
            return jsonify({"ok": False, "error": "invalid_record", "message": str(exc)}), 400
        if isinstance(credentials, dict):
            store.save_credentials(record["id"], credentials)
        record["credentialsConfigured"] = store.secrets.configured(record["id"])
        return jsonify({"ok": True, "record": record})

    @blueprint.put("/<record_id>")
    def update_ddns(record_id: str):
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            body = {}
        credentials = body.get("credentials", {}) if isinstance(body, dict) else {}
        try:
            record = store.save_record({key: value for key, value in body.items() if key != "credentials"}, record_id)
        except KeyError:
            return jsonify({"ok": False, "error": "not_found"}), 404
        except ValueError as exc:
            return jsonify({"ok": False, "error": "invalid_record", "message": str(exc)}), 400
        if isinstance(credentials, dict):
            store.save_credentials(record_id, credentials)
        record["credentialsConfigured"] = store.secrets.configured(record_id)
        return jsonify({"ok": True, "record": record})

    @blueprint.post("/<record_id>/update")
    def update_now(record_id: str):
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        try:
            result = store.run_update(record_id, force=_bool(body.get("force"), False) if isinstance(body, dict) else False)
        except KeyError:
            return jsonify({"ok": False, "error": "not_found"}), 404
        except ValueError as exc:
            return jsonify({"ok": False, "error": "invalid_record", "message": str(exc)}), 400
        return jsonify({"ok": True, **result})

    @blueprint.delete("/<record_id>")
    def delete_ddns(record_id: str):
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        if not store.delete_record(record_id):
            return jsonify({"ok": False, "error": "not_found"}), 404
        store.secrets.delete(record_id)
        return jsonify({"ok": True})

    hub.app.register_blueprint(blueprint)
    return store
