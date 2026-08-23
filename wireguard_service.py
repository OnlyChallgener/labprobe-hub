"""WireGuard server control plane for LabProbe Agent.

The Hub stores public desired state only.  The server private key is generated
and retained by Agent on the router.  DDNS and STUN endpoint profiles have
independent endpoint revisions, so their updaters can never overwrite each
other or mutate the WireGuard kernel configuration revision.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from flask import Blueprint, jsonify, request


def _text(value: Any) -> str:
    return str(value or "").strip()


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _now() -> int:
    return int(time.time())


def _now_text() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _has_secret(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            if normalized in {"privatekey", "presharedkey", "secret", "password"}:
                return True
            if _has_secret(item):
                return True
    elif isinstance(value, list):
        return any(_has_secret(item) for item in value)
    return False


def _public_key(value: Any) -> str:
    text = _text(value)
    try:
        decoded = base64.b64decode(text, validate=True)
    except Exception as error:
        raise ValueError("Peer 公钥格式无效") from error
    if len(decoded) != 32:
        raise ValueError("Peer 公钥必须是 32 字节 WireGuard 公钥")
    return text


class WireGuardService:
    def __init__(self, hub: Any):
        self.hub = hub
        self.lock = threading.RLock()
        root = Path(hub.DATA_DIR)
        self.document_path = root / "wireguard_server.json"
        self.commands_path = root / "wireguard_commands.json"
        self.status_path = root / "wireguard_agent_status.json"

    def _router_name(self) -> str:
        resolver = getattr(self.hub, "_portmap_router_name", None)
        return _text(resolver()) if callable(resolver) else "router"

    def document(self) -> Dict[str, Any]:
        raw = self.hub.load_json(self.document_path, {})
        raw = raw if isinstance(raw, dict) else {}
        return {
            "version": 1,
            "revision": max(0, _int(raw.get("revision"))),
            "endpointRevision": max(0, _int(raw.get("endpointRevision"))),
            "updatedAt": _text(raw.get("updatedAt")),
            "server": dict(raw["server"]) if isinstance(raw.get("server"), dict) else None,
            "tombstone": dict(raw["tombstone"]) if isinstance(raw.get("tombstone"), dict) else None,
        }

    def _save_document(self, document: Dict[str, Any]) -> None:
        if _has_secret(document):
            raise ValueError("Hub 不允许保存 WireGuard 私钥或预共享密钥")
        self.hub.save_json(self.document_path, document)

    def clean_server(self, payload: Dict[str, Any], old: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if _has_secret(payload):
            raise ValueError("私钥只能保存在路由器 Agent 本地")
        old = dict(old or {})
        interface_name = _text(payload.get("interfaceName") or old.get("interfaceName") or "labwg0")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface_name) or interface_name == "lo":
            raise ValueError("WireGuard 接口名称无效")
        address = _text(payload.get("address") or old.get("address") or "10.77.0.1/24")
        try:
            network_address = ipaddress.ip_interface(address)
        except ValueError as error:
            raise ValueError("WireGuard 服务端地址无效") from error
        if network_address.version != 4 or not network_address.ip.is_private:
            raise ValueError("WireGuard 服务端必须使用私有 IPv4 地址段")
        listen_port = _int(payload.get("listenPort"), _int(old.get("listenPort"), 51820))
        if not 1 <= listen_port <= 65535:
            raise ValueError("WireGuard UDP 监听端口无效")

        peers = []
        peer_ids, peer_keys = set(), set()
        for raw in payload.get("peers", old.get("peers", [])) or []:
            if not isinstance(raw, dict):
                raise ValueError("Peer 配置无效")
            peer_id = _text(raw.get("id")) or f"peer-{uuid.uuid4().hex[:10]}"
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", peer_id) or peer_id in peer_ids:
                raise ValueError("Peer ID 无效或重复")
            key = _public_key(raw.get("publicKey"))
            if key in peer_keys:
                raise ValueError("Peer 公钥重复")
            allowed = []
            for value in raw.get("allowedIps", []) or []:
                try:
                    allowed.append(str(ipaddress.ip_network(_text(value), strict=False)))
                except ValueError as error:
                    raise ValueError("Peer AllowedIPs 无效") from error
            if not allowed:
                raise ValueError("Peer 至少需要一个 AllowedIPs")
            keepalive = _int(raw.get("persistentKeepaliveSeconds"), 25)
            if not 0 <= keepalive <= 600:
                raise ValueError("Peer Keepalive 必须在 0–600 秒")
            peer_ids.add(peer_id)
            peer_keys.add(key)
            peers.append({
                "id": peer_id,
                "name": _text(raw.get("name"))[:64] or peer_id,
                "publicKey": key,
                "allowedIps": allowed,
                "persistentKeepaliveSeconds": keepalive,
            })
        if len(peers) > 64:
            raise ValueError("MVP 最多支持 64 个 Peer")

        profiles = []
        profile_ids = set()
        for raw in payload.get("endpointProfiles", old.get("endpointProfiles", [])) or []:
            if not isinstance(raw, dict):
                raise ValueError("Endpoint Profile 无效")
            profile_id = _text(raw.get("id")) or f"endpoint-{uuid.uuid4().hex[:8]}"
            source = _text(raw.get("endpointSource")).lower()
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", profile_id) or profile_id in profile_ids:
                raise ValueError("Endpoint Profile ID 无效或重复")
            if source not in {"manual", "ddns", "stun"}:
                raise ValueError("Endpoint Source 只能是 manual、ddns 或 stun")
            profile = {
                "id": profile_id,
                "name": _text(raw.get("name"))[:64] or ({"manual": "手动地址", "ddns": "DDNS 直连", "stun": "STUN 穿透"}[source]),
                "endpointSource": source,
                "enabled": bool(raw.get("enabled", True)),
                "port": _int(raw.get("port"), listen_port),
                "endpointRevision": max(0, _int(raw.get("endpointRevision"))),
                "resolvedEndpoint": _text(raw.get("resolvedEndpoint")),
            }
            if not 1 <= profile["port"] <= 65535:
                raise ValueError("Endpoint 端口无效")
            if source == "manual":
                endpoint = _text(raw.get("resolvedEndpoint"))
                if not endpoint:
                    raise ValueError("Manual Profile 需要固定 Endpoint")
                profile.update({
                    "hostname": "",
                    "stunRuleId": "",
                    "bindingMode": "manual",
                    "owner": "",
                    "resolvedEndpoint": endpoint,
                })
            elif source == "ddns":
                hostname = _text(raw.get("hostname")).lower().rstrip(".")
                if not hostname or len(hostname) > 253 or ":" in hostname:
                    raise ValueError("DDNS Profile 需要独立域名")
                profile.update({"hostname": hostname, "stunRuleId": "", "bindingMode": "fixed-port", "owner": f"ddns:{profile_id}"})
            else:
                if _text(raw.get("hostname")):
                    raise ValueError("STUN Profile 不能复用 DDNS 域名字段")
                stun_rule_id = _text(raw.get("stunRuleId"))
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", stun_rule_id):
                    raise ValueError("STUN Profile 需要独立的 UDP 穿透规则")
                # The sidecar owns the STUN channel port and forwards UDP to
                # the local fixed WG port. It must never bind WG to that same
                # dynamic/public STUN port.
                profile.update({
                    "hostname": "",
                    "stunRuleId": stun_rule_id,
                    "bindingMode": "udp-sidecar",
                    "transportProtocol": "UDP",
                    "localTargetPort": listen_port,
                    "owner": f"stun:{stun_rule_id}",
                })
            profile_ids.add(profile_id)
            profiles.append(profile)
        return {
            "interfaceName": interface_name,
            "address": str(network_address),
            "listenPort": listen_port,
            "enabled": bool(payload.get("enabled", old.get("enabled", True))),
            "peers": peers,
            "endpointProfiles": profiles,
        }

    def commands(self) -> List[Dict[str, Any]]:
        raw = self.hub.load_json(self.commands_path, {"commands": []})
        return [dict(row) for row in raw.get("commands", []) if isinstance(row, dict)] if isinstance(raw, dict) else []

    def _save_commands(self, rows: Iterable[Dict[str, Any]]) -> None:
        self.hub.save_json(self.commands_path, {"commands": list(rows)})

    def queue(self, action: str, revision: int, payload: Dict[str, Any], router: str = "", revision_scope: str = "server") -> Dict[str, Any]:
        router = router or self._router_name() or "router"
        with self.lock:
            rows = self.commands()
            rows = [row for row in rows if not (
                row.get("router") == router
                and _text(row.get("revisionScope")) in {"", revision_scope}
                and _int(row.get("revision")) <= revision
                and row.get("status") in {"pending", "delivered"}
            )]
            command = {
                "id": f"wg-cmd-{uuid.uuid4().hex[:12]}",
                "router": router,
                "action": action,
                "revision": revision,
                "revisionScope": revision_scope,
                "payload": {**payload, "revision": revision},
                "status": "pending",
                "attempts": 0,
                "createdAt": _now_text(),
            }
            rows.append(command)
            self._save_commands(rows[-500:])
            return command

    def put(self, payload: Dict[str, Any], expected_revision: Optional[int]) -> Dict[str, Any]:
        with self.lock:
            document = self.document()
            if expected_revision is not None and expected_revision != document["revision"]:
                raise RuntimeError("revision conflict")
            server = self.clean_server(payload, document.get("server"))
            revision = document["revision"] + 1
            server["revision"] = revision
            saved = {
                **document,
                "revision": revision,
                "updatedAt": _now_text(),
                "server": server,
                "tombstone": None,
            }
            self._save_document(saved)
            self.queue("apply", revision, {"server": server})
            return saved

    def delete(self, expected_revision: Optional[int]) -> Dict[str, Any]:
        with self.lock:
            document = self.document()
            if expected_revision is not None and expected_revision != document["revision"]:
                raise RuntimeError("revision conflict")
            old = document.get("server") or {}
            revision = document["revision"] + 1
            tombstone = {"revision": revision, "deletedAt": _now_text(), "interfaceName": _text(old.get("interfaceName")) or "labwg0"}
            saved = {**document, "revision": revision, "updatedAt": tombstone["deletedAt"], "server": None, "tombstone": tombstone}
            self._save_document(saved)
            self.queue("delete", revision, {"interfaceName": tombstone["interfaceName"], "tombstone": True})
            return saved

    def update_endpoint(self, profile_id: str, source: str, owner: str, endpoint: str, expected_revision: Optional[int]) -> Dict[str, Any]:
        with self.lock:
            document = self.document()
            server = dict(document.get("server") or {})
            profiles = [dict(row) for row in server.get("endpointProfiles", []) if isinstance(row, dict)]
            profile = next((row for row in profiles if _text(row.get("id")) == profile_id), None)
            if profile is None:
                raise ValueError("endpoint profile not found")
            if _text(profile.get("endpointSource")) == "manual":
                raise ValueError("manual endpoint profile cannot be changed by an automatic updater")
            if _text(profile.get("endpointSource")) != _text(source).lower():
                raise ValueError("endpoint updater does not own this profile")
            if not owner or _text(profile.get("owner")) != _text(owner):
                raise ValueError("endpoint owner does not match this profile")
            current = _int(profile.get("endpointRevision"))
            if expected_revision is None:
                raise ValueError("expectedEndpointRevision is required")
            if expected_revision != current:
                raise RuntimeError("endpoint revision conflict")
            if source == "stun":
                try:
                    host, port = endpoint.rsplit(":", 1)
                    ipaddress.ip_address(host.strip("[]"))
                    if not 1 <= int(port) <= 65535:
                        raise ValueError
                except Exception as error:
                    raise ValueError("STUN endpoint 必须包含公网 IP 和端口") from error
            elif source == "ddns" and endpoint and ":" not in endpoint:
                endpoint = f"{endpoint}:{profile['port']}"
            profile["resolvedEndpoint"] = endpoint
            profile["endpointRevision"] = current + 1
            profile["endpointUpdatedAt"] = _now_text()
            server["endpointProfiles"] = profiles
            document["server"] = server
            document["endpointRevision"] += 1
            document["updatedAt"] = _now_text()
            self._save_document(document)
            self.queue(
                "endpoint",
                profile["endpointRevision"],
                {
                    "profileId": profile_id,
                    "endpointSource": source,
                    "owner": owner,
                    "endpoint": endpoint,
                    "expectedEndpointRevision": current,
                    "endpointRevision": profile["endpointRevision"],
                },
                revision_scope=f"endpoint:{profile_id}",
            )
            return profile


def create_wireguard_blueprint(hub: Any, service: WireGuardService) -> Blueprint:
    bp = Blueprint("wireguard_service", __name__, url_prefix="/api")

    @bp.route("/wireguard/server", methods=["GET", "PUT", "DELETE"])
    def server():
        if request.method == "GET":
            if not hub.check_read_token():
                return jsonify({"ok": False, "error": "unauthorized"}), 401
            document = service.document()
            status = hub.load_json(service.status_path, {})
            return jsonify({"ok": True, **document, "agentStatus": status if isinstance(status, dict) else {}})
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        payload = request.get_json(silent=True) or {}
        expected = payload.get("expectedRevision")
        expected_revision = _int(expected) if expected is not None else None
        try:
            document = service.delete(expected_revision) if request.method == "DELETE" else service.put(payload, expected_revision)
            return jsonify({"ok": True, **document})
        except RuntimeError as error:
            return jsonify({"ok": False, "error": str(error), "currentRevision": service.document()["revision"]}), 409
        except Exception as error:
            return jsonify({"ok": False, "error": str(error)}), 400

    @bp.patch("/wireguard/endpoints/<profile_id>")
    def endpoint(profile_id: str):
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        payload = request.get_json(silent=True) or {}
        expected = payload.get("expectedEndpointRevision")
        try:
            profile = service.update_endpoint(
                profile_id,
                _text(payload.get("endpointSource")),
                _text(payload.get("owner")),
                _text(payload.get("endpoint")),
                _int(expected) if expected is not None else None,
            )
            return jsonify({"ok": True, "profile": profile, "endpointRevision": service.document()["endpointRevision"]})
        except RuntimeError as error:
            return jsonify({"ok": False, "error": str(error)}), 409
        except Exception as error:
            return jsonify({"ok": False, "error": str(error)}), 400

    @bp.get("/router/wireguard/commands")
    def agent_commands():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad hook token"}), 401
        router = _text(request.args.get("router")) or service._router_name()
        limit = max(1, min(20, _int(request.args.get("limit"), 10)))
        rows = service.commands()
        selected, changed, now = [], False, _now()
        for row in rows:
            retry = row.get("status") == "delivered" and now - _int(row.get("deliveredEpoch")) >= 15 and _int(row.get("attempts")) < 5
            if row.get("router") == router and (row.get("status") == "pending" or retry):
                row.update({"status": "delivered", "deliveredEpoch": now, "deliveredAt": _now_text(), "attempts": _int(row.get("attempts")) + 1})
                selected.append({key: row.get(key) for key in ("id", "action", "revision", "payload", "createdAt")})
                changed = True
                if len(selected) >= limit:
                    break
        if changed:
            service._save_commands(rows)
        return jsonify({"ok": True, "commands": selected})

    @bp.post("/router/wireguard/ack")
    def agent_ack():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad hook token"}), 401
        values = {_text(row.get("id")): row for row in (request.get_json(silent=True) or {}).get("acks", []) if isinstance(row, dict)}
        rows, changed = service.commands(), 0
        for row in rows:
            ack = values.get(_text(row.get("id")))
            if ack:
                row.update({"status": "done" if ack.get("ok") else "failed", "result": ack.get("result"), "finishedAt": _now_text()})
                changed += 1
        if changed:
            service._save_commands(rows)
        return jsonify({"ok": True, "acknowledged": changed})

    @bp.post("/router/wireguard/status")
    def agent_status():
        if not hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad hook token"}), 401
        router = _text(request.args.get("router")) or service._router_name()
        payload = request.get_json(silent=True) or {}
        # Defensive second barrier: never persist a status object containing a
        # private or preshared key, even if a future Agent regresses.
        if _has_secret(payload):
            return jsonify({"ok": False, "error": "secret material rejected"}), 400
        record = {"router": router, "receivedAt": _now_text(), "receivedEpoch": _now(), **payload}
        hub.save_json(service.status_path, record)
        document = service.document()
        agent_revision = _int(payload.get("revision"))
        if agent_revision < document["revision"]:
            if document.get("server"):
                service.queue("apply", document["revision"], {"server": document["server"]}, router)
            elif document.get("tombstone"):
                service.queue("delete", document["revision"], {**document["tombstone"], "tombstone": True}, router)
        return jsonify({"ok": True, "receivedAt": record["receivedAt"], "desiredRevision": document["revision"]})

    return bp


def install_wireguard_service(hub: Any) -> WireGuardService:
    existing = getattr(hub, "WIREGUARD_SERVICE", None)
    if existing is not None:
        return existing
    service = WireGuardService(hub)
    hub.WIREGUARD_SERVICE = service
    hub.app.register_blueprint(create_wireguard_blueprint(hub, service))
    return service
