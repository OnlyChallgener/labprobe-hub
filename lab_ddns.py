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


class DdnsProvider:
    """Small adapter contract; Phase 1A deliberately performs no I/O."""

    def __init__(self, spec: ProviderSpec):
        self.spec = spec

    def update(self, hostname: str, ipv4: str, ipv6: str, credentials: Mapping[str, str]) -> ProviderResult:
        return ProviderResult(False, "not_implemented", "Provider API is disabled in Phase 1A")


PROVIDERS: Dict[str, DdnsProvider] = {
    provider_id: DdnsProvider(ProviderSpec(provider_id, ("token",)))
    for provider_id in PROVIDER_IDS
}


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
    record_types = [item for item in (_text(item).upper() for item in record_types) if item in {"A", "AAAA"}]
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
        "enabled": enabled,
        "detectedIpv4": _ip_text(value.get("detectedIpv4"), 4),
        "detectedIpv6": _ip_text(value.get("detectedIpv6"), 6),
        "publishedIpv4": _ip_text(value.get("publishedIpv4"), 4) or None,
        "publishedIpv6": _ip_text(value.get("publishedIpv6"), 6) or None,
        "source": _text(value.get("source")),
        "status": status,
        "lastDetectedAt": _safe_int(value.get("lastDetectedAt")),
        "lastUpdatedAt": _optional_int(value.get("lastUpdatedAt")),
        "lastError": _text(value.get("lastError")) or None,
    }


class LabDdnsStore:
    def __init__(self, path: Path, logger: Any = None):
        self.path = path
        self.logger = logger
        self.lock = threading.RLock()
        self.root = _empty_root()
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self.root["address"] = _normal_address(raw.get("address"))
                    self.root["records"] = [
                        record for item in raw.get("records", [])
                        if (record := _normal_record(item)) is not None
                    ]
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

    def accept_address(self, value: Any) -> bool:
        address = _normal_address(value)
        if not address:
            return False
        with self.lock:
            if not address["detectedAt"]:
                address["detectedAt"] = (
                    _safe_int(self.root.get("address", {}).get("detectedAt")) or _now()
                )
            changed = self.root.get("address") != address
            self.root["address"] = address
            for record in self.root["records"]:
                source = ",".join(filter(None, [address["ipv4Source"], address["ipv6Source"]]))
                values = {
                    "detectedIpv4": address["detectedIpv4"],
                    "detectedIpv6": address["detectedIpv6"],
                    "source": source,
                    "lastDetectedAt": address["detectedAt"],
                }
                if any(record.get(key) != item for key, item in values.items()):
                    changed = True
                    record.update(values)
                if not record.get("enabled", True):
                    new_status, new_error = "disabled", record.get("lastError")
                elif record.get("status") in {"error", "updating"}:
                    new_status, new_error = record.get("status"), record.get("lastError")
                elif address["detectedIpv4"] or address["detectedIpv6"]:
                    new_status, new_error = "detected", None
                else:
                    new_status, new_error = "waiting", record.get("lastError")
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
                        for key in ("detectedIpv4", "detectedIpv6", "publishedIpv4", "publishedIpv6", "source", "status", "lastDetectedAt", "lastUpdatedAt", "lastError"):
                            record[key] = old.get(key, record[key])
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
            record["lastDetectedAt"] = _safe_int(address.get("detectedAt"))
            record["source"] = ",".join(filter(None, [address.get("ipv4Source", ""), address.get("ipv6Source", "")]))
            if not record["enabled"]:
                record["status"] = "disabled"
            else:
                record["status"] = "detected" if record["detectedIpv4"] or record["detectedIpv6"] else "waiting"
            self.root["records"].append(record)
            self._save_locked()
            return dict(record)

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
    store = LabDdnsStore(Path(hub.DATA_DIR) / "lab_ddns.json", hub.LOGGER)
    hub.LAB_DDNS = store
    blueprint = Blueprint("lab_ddns", __name__, url_prefix="/api/ddns")

    @blueprint.get("")
    def get_ddns():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return jsonify({"ok": True, **store.snapshot(), "providers": provider_specs()})

    @blueprint.get("/providers")
    def get_providers():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return jsonify({"ok": True, "providers": provider_specs()})

    @blueprint.post("")
    def add_ddns():
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        try:
            record = store.save_record(request.get_json(silent=True) or {})
        except ValueError as exc:
            return jsonify({"ok": False, "error": "invalid_record", "message": str(exc)}), 400
        return jsonify({"ok": True, "record": record})

    @blueprint.put("/<record_id>")
    def update_ddns(record_id: str):
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        try:
            record = store.save_record(request.get_json(silent=True) or {}, record_id)
        except KeyError:
            return jsonify({"ok": False, "error": "not_found"}), 404
        except ValueError as exc:
            return jsonify({"ok": False, "error": "invalid_record", "message": str(exc)}), 400
        return jsonify({"ok": True, "record": record})

    @blueprint.delete("/<record_id>")
    def delete_ddns(record_id: str):
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        if not store.delete_record(record_id):
            return jsonify({"ok": False, "error": "not_found"}), 404
        return jsonify({"ok": True})

    hub.app.register_blueprint(blueprint)
    return store
