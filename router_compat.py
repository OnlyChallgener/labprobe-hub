"""Compatibility bridge from direct eWeb RPC data to LabProbe's existing status/device APIs.

The Android router-status and terminal pages keep their current API contracts:
- GET /api/router/dashboard
- GET /api/devices / sync snapshot

This module refreshes the existing Hub caches from the router directly. Relay
continues to contribute IPv6-neighbour data and 6to6 runtime only.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from flask import jsonify, request

from router_rpc import RuijieRouterClient, RouterRpcError


def _clean(value: Any) -> str:
    text = str(value or "").strip()
    return "" if text.lower() in {"none", "null"} else text


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip().rstrip("%"))
    except (TypeError, ValueError):
        return default


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip().rstrip("%")))
    except (TypeError, ValueError):
        return default


def _unwrap(value: Any) -> Any:
    current = value
    for _ in range(5):
        if not isinstance(current, dict) or "data" not in current:
            break
        keys = set(current)
        if keys.issubset({"data", "code", "id", "error", "rcode", "message", "msg"}):
            current = current.get("data")
        else:
            break
    if isinstance(current, str):
        text = current.strip()
        if text.startswith(("{", "[")):
            try:
                return _unwrap(json.loads(text))
            except Exception:
                pass
    return current


def _walk(value: Any) -> Iterable[Tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _first(value: Any, *keys: str, default: Any = "") -> Any:
    wanted = {key.lower() for key in keys}
    for key, child in _walk(value):
        if key.lower() in wanted and child not in (None, "", [], {}):
            return child
    return default


def _dict(value: Any, *keys: str) -> Dict[str, Any]:
    if isinstance(value, dict):
        for key in keys:
            child = value.get(key)
            if isinstance(child, dict):
                return child
    wanted = {key.lower() for key in keys}
    for key, child in _walk(value):
        if key.lower() in wanted and isinstance(child, dict):
            return child
    return {}


def _list(value: Any, *keys: str) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in keys:
            child = value.get(key)
            if isinstance(child, list):
                return child
        child = value.get("list")
        if isinstance(child, list):
            return child
    wanted = {key.lower() for key in keys}
    for key, child in _walk(value):
        if key.lower() in wanted and isinstance(child, list):
            return child
    return []


def _split(value: Any) -> List[str]:
    if isinstance(value, list):
        rows = [_clean(item) for item in value]
    else:
        rows = _clean(value).replace(";", ",").split(",")
    return list(dict.fromkeys(row.strip() for row in rows if row.strip()))


def _select_network_row(network: Any, kind: str) -> Dict[str, Any]:
    if not isinstance(network, dict):
        return {}
    direct = network.get(kind)
    if isinstance(direct, dict):
        return direct
    if isinstance(direct, list):
        return next((row for row in direct if isinstance(row, dict)), {})
    for row in _list(network, "list", "interfaces", "networks"):
        if not isinstance(row, dict):
            continue
        marker = " ".join(_clean(row.get(k)).lower() for k in ("type", "name", "ifname", "interface", "role"))
        if kind in marker:
            return row
    return {}


def _find_client(app: Any) -> RuijieRouterClient:
    for endpoint, function in app.view_functions.items():
        if not endpoint.startswith("router_rpc."):
            continue
        for cell in function.__closure__ or ():
            try:
                value = cell.cell_contents
            except ValueError:
                continue
            if isinstance(value, RuijieRouterClient):
                return value
    raise RuntimeError("router RPC client was not found in registered blueprint")


class RouterRpcCompatibilitySync:
    def __init__(self, hub: Any, client: RuijieRouterClient):
        self.hub = hub
        self.client = client
        self.logger = hub.LOGGER
        self.dashboard_interval = max(2.0, float(os.environ.get("ROUTER_DASHBOARD_POLL_SEC", "3")))
        self.device_interval = max(3.0, float(os.environ.get("ROUTER_DEVICE_POLL_SEC", "5")))
        self.primary = str(os.environ.get("ROUTER_RPC_PRIMARY", "true")).lower() not in {"0", "false", "no"}
        self._stop = threading.Event()
        self._refresh_lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._last_dashboard = 0.0
        self._last_devices = 0.0
        self._device_total = 0
        self._last_error = ""

    def configured(self) -> bool:
        try:
            cfg = self.client.config
            return bool(cfg.get("address") and cfg.get("password"))
        except Exception:
            return False

    def start(self) -> None:
        if not self.primary or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="router-rpc-sync", daemon=True)
        self._thread.start()
        self.logger.info(
            "router RPC compatibility sync started dashboard=%ss devices=%ss",
            self.dashboard_interval,
            self.device_interval,
        )

    def _loop(self) -> None:
        while not self._stop.wait(0.5):
            if not self.configured():
                continue
            now = time.monotonic()
            try:
                if now - self._last_devices >= self.device_interval:
                    self.sync_devices(force=True)
                    self._last_devices = now
                if now - self._last_dashboard >= self.dashboard_interval:
                    self.sync_dashboard(force=True)
                    self._last_dashboard = now
                self._last_error = ""
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                if message != self._last_error:
                    self.logger.warning("router direct sync failed: %s", message)
                    self._last_error = message
                self._stop.wait(2.0)

    def sync_once(self, force: bool = True) -> Dict[str, Any]:
        with self._refresh_lock:
            devices = self.sync_devices(force=force)
            dashboard = self.sync_dashboard(force=force)
            return {"dashboard": dashboard, "devices": devices}

    def sync_devices(self, force: bool = True) -> Dict[str, Any]:
        raw = self.client.devices(force=force)
        raw_rows = raw.get("items", []) if isinstance(raw, dict) else []
        payload = {"list": raw_rows, "total": raw.get("total", len(raw_rows)) if isinstance(raw, dict) else len(raw_rows)}
        online, total = self.hub.parse_ruijie_devices(payload)
        realtime_by_mac: Dict[str, Dict[str, int]] = {}
        for item in raw_rows:
            if not isinstance(item, dict):
                continue
            mac = self.hub.norm_mac(item.get("mac"))
            if not mac:
                continue
            realtime_by_mac[mac] = {
                "realtimeUpload": _integer(item.get("realtimeUpBytes", item.get("flowUp"))),
                "realtimeDownload": _integer(item.get("realtimeDownBytes", item.get("flowDown"))),
                "connectionCount": _integer(item.get("connectionCount", item.get("flow_cnt"))),
            }

        archive = self.hub.load_device_archive()
        normalized: List[Dict[str, Any]] = []
        for device in online:
            mac = self.hub.norm_mac(device.get("mac"))
            device.update(realtime_by_mac.get(mac, {}))
            device = self.hub.hydrate_device_with_archive(device, archive)
            device["online"] = True
            device["lastSeenAt"] = self.hub.now_str()
            self.hub.archive_device_snapshot(device)
            normalized.append(device)
        normalized = self.hub.attach_hub_local_ipv6_to_nas_devices(normalized)
        watched = self.hub.build_watched_devices(normalized)
        updated_at = self.hub.now_str()
        document = {
            "online": normalized,
            "watched": watched,
            "onlineDeviceCount": total,
            "updatedAt": updated_at,
            "source": "router_rpc",
        }
        with self.hub.DATA_LOCK:
            self.hub.save_json(self.hub.DEVICES_FILE, document)
            state = self.hub.load_json(self.hub.STATE_FILE, {})
            state["devices"] = watched
            state["devicesUpdatedAt"] = updated_at
            state["updatedAt"] = updated_at
            self.hub.save_json(self.hub.STATE_FILE, state)
        self._device_total = total
        return document

    def _normalize_dashboard(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        static = _unwrap(raw.get("static")) or {}
        slow = _unwrap(raw.get("slow")) or {}
        fast = _unwrap(raw.get("fast")) or {}
        ipinfo = _unwrap(raw.get("ipinfo")) or {}
        network = _unwrap(raw.get("network")) or {}
        network_group = _unwrap(raw.get("networkGroup")) or {}
        network_connect = _unwrap(raw.get("networkConnect")) or {}
        wireless_config = _unwrap(raw.get("wireless")) or {}
        rcgame = _unwrap(raw.get("rcgame")) or {}
        ap_raw = _unwrap(raw.get("apList")) or {}
        port_raw = _unwrap(raw.get("portStatus")) or {}

        wan_stat = _dict(fast, "wan_stat", "wanStat") or _dict(network_connect, "wan_stat", "wanStat")
        aggregate = _dict(wan_stat, "wans") or _dict(wan_stat, "wan") or wan_stat
        wan_info = (
            _dict(ipinfo, "wan", "WAN")
            or (_list(ipinfo, "list") or [{}])[0]
            or _dict(network_connect, "wan", "WAN")
            or (network_connect if isinstance(network_connect, dict) else {})
        )
        if not isinstance(wan_info, dict):
            wan_info = {}
        network_lan = _select_network_row(network, "lan") or _select_network_row(network_group, "lan")
        network_wan = _select_network_row(network, "wan") or _select_network_row(network_group, "wan")

        ap_rows = _list(ap_raw, "list", "apList", "aps")
        ap = next((row for row in ap_rows if isinstance(row, dict)), ap_raw if isinstance(ap_raw, dict) else {})
        if not isinstance(ap, dict):
            ap = {}
        port_rows = [row for row in _list(port_raw, "list", "ports", "portList") if isinstance(row, dict)]

        identity_source = {
            **(static if isinstance(static, dict) else {}),
            **(slow if isinstance(slow, dict) else {}),
            **(network_group if isinstance(network_group, dict) else {}),
            **(wireless_config if isinstance(wireless_config, dict) else {}),
            **(rcgame if isinstance(rcgame, dict) else {}),
            **ap,
        }
        hostname = _clean(ap.get("hostName") or _first(identity_source, "hostname", "hostName", "deviceAliasName"))
        model = _clean(ap.get("devModel") or ap.get("deviceType") or ap.get("product") or _first(identity_source, "model", "devModel", "deviceType"))
        serial = _clean(ap.get("serialNumber") or _first(identity_source, "serialNumber", "sn"))

        cpu = _number(_first(fast, "cpu_usage", "cpuUsage", "cpuutil"), _number(_first(slow, "cpu_usage", "cpuUsage", "cpuutil")))
        memory = _number(_first(fast, "memutil", "memoryPercent", "memory_usage"), _number(_first(slow, "memutil", "memoryPercent", "memory_usage")))
        storage_value = _first(slow, "diskutil", "storagePercent", "disk_usage", "overlay_usage", default=None)
        temperature = _number(_first(fast, "temp", "temperature", "temperatureC"), _number(_first(slow, "temp", "temperature", "temperatureC")))
        temperature2g = _number(_first(fast, "temp_2g", "temperature2gC"), _number(_first(slow, "temp_2g", "temperature2gC")))
        temperature5g = _number(_first(fast, "temp_5g", "temperature5gC"), _number(_first(slow, "temp_5g", "temperature5gC")))
        uptime = _integer(_first(fast, "runtime", "uptime", "uptimeSeconds"), _integer(_first(slow, "runtime", "uptime", "uptimeSeconds")))

        upload = _integer(aggregate.get("up") if isinstance(aggregate, dict) else 0)
        download = _integer(aggregate.get("down") if isinstance(aggregate, dict) else 0)
        total_upload = _integer(aggregate.get("total_up") if isinstance(aggregate, dict) else 0)
        total_download = _integer(aggregate.get("total_down") if isinstance(aggregate, dict) else 0)
        ipv4_connections = _integer(aggregate.get("ipv4_connection_count") if isinstance(aggregate, dict) else 0)
        ipv6_connections = _integer(aggregate.get("ipv6_connection_count") if isinstance(aggregate, dict) else 0)

        dns = _split(wan_info.get("dnsList") or wan_info.get("dns") or network_wan.get("dns"))
        for key in ("dns1", "dns2", "primaryDns", "secondaryDns"):
            value = _clean(wan_info.get(key) or network_wan.get(key))
            if value and value not in dns:
                dns.append(value)

        channel_values = _split(ap.get("channel") or ap.get("channels"))
        channel_util = _split(ap.get("chutil") or ap.get("channelUtilization"))
        bands = _split(ap.get("band") or ap.get("bands"))
        if not bands and channel_values:
            bands = ["2.4G", "5G"][: len(channel_values)]

        previous = {}
        with self.hub.ROUTER_DASHBOARD_LOCK:
            previous = json.loads(json.dumps(self.hub.ROUTER_DASHBOARD_CACHE, ensure_ascii=False)) if self.hub.ROUTER_DASHBOARD_CACHE else {}
        previous_details = previous.get("details") if isinstance(previous.get("details"), dict) else {}
        previous_wan = previous_details.get("wan") if isinstance(previous_details.get("wan"), dict) else {}
        previous_wireless = previous_details.get("wireless") if isinstance(previous_details.get("wireless"), dict) else {}

        wan = {
            "ipv4": _clean(wan_info.get("ip") or wan_info.get("ipv4") or network_wan.get("ipaddr")),
            "gateway": _clean(wan_info.get("gateway") or network_wan.get("gateway")),
            "netmask": _clean(wan_info.get("mask") or wan_info.get("netmask") or network_wan.get("netmask")),
            "proto": _clean(wan_info.get("proto") or network_wan.get("proto")),
            "mtu": _clean(wan_info.get("mtu") or network_wan.get("mtu")),
            "dnsServers": dns[:3],
            "interfaceDisplay": _clean(wan_info.get("interfaceDisplay") or wan_info.get("ifname") or "WAN").upper(),
            "operator": _clean(previous_wan.get("operator")),
            "publicIpv4": _clean(previous_wan.get("publicIpv4")),
            "operatorCheckedIp": _clean(previous_wan.get("operatorCheckedIp")),
            "operatorCheckedEpoch": previous_wan.get("operatorCheckedEpoch", 0),
            "operatorSource": _clean(previous_wan.get("operatorSource")),
        }
        lan = {
            "ipv4": _clean(network_lan.get("ipaddr") or network_lan.get("ip") or _first(network, "lanIp", "lan_ip")),
            "mac": _clean(network_lan.get("macaddr") or network_lan.get("mac") or ap.get("mac")),
            "broadbandRemark": _clean(network_wan.get("service") or network_wan.get("serviceName")),
            "netmask": _clean(network_lan.get("netmask") or network_lan.get("mask")),
            "vlanId": _clean(network_lan.get("vlanid") or network_lan.get("vlanId") or network_lan.get("vid")),
            "dhcpLease": _clean(network_lan.get("leasetime") or network_lan.get("leaseTime")),
            "uplink": _clean(network_wan.get("ifname") or network_wan.get("interface") or "wan"),
        }
        ap_details = {
            "model": model,
            "hostName": hostname,
            "networkName": _clean(ap.get("networkName") or ap.get("ssid") or hostname),
            "managementIp": _clean(ap.get("ip") or lan.get("ipv4")),
            "software": _clean(ap.get("software") or _first(static, "firmware", "software")),
            "hardware": _clean(ap.get("hardware") or _first(static, "hardware")),
            "serialNumber": serial,
            "workMode": _clean(ap.get("workMode") or ap.get("forwardMode")),
            "forwardMode": _clean(ap.get("forwardMode")),
            "relayMode": _clean(ap.get("relayMode")),
            "channelUtilization": channel_util,
            "stationCount": _clean(ap.get("staNum") or ap.get("stationCount") or self._device_total),
            "bands": bands,
            "channels": channel_values,
            "status": _clean(ap.get("status") or "ON"),
        }

        now = self.hub.now_str()
        now_epoch = time.time()
        return {
            "router": hostname or model or _clean(previous.get("router")) or "router",
            "receivedAt": now,
            "receivedEpoch": now_epoch,
            "telemetryAt": now,
            "telemetryEpoch": now_epoch,
            "detailsAt": now,
            "detailsEpoch": now_epoch,
            "source": "router_rpc",
            "telemetry": {
                "temperatureC": temperature,
                "temperature2gC": temperature2g,
                "temperature5gC": temperature5g,
                "cpuPercent": cpu,
                "memoryPercent": memory,
                "storagePercent": None if storage_value in (None, "") else _number(storage_value),
                "uptimeSeconds": uptime,
                "onlineDeviceCount": self._device_total,
                "wan": {
                    "uploadBps": upload,
                    "downloadBps": download,
                    "totalUploadBytes": total_upload,
                    "totalDownloadBytes": total_download,
                    "dailyUploadBytes": _integer(aggregate.get("daily_up") if isinstance(aggregate, dict) else 0),
                    "dailyDownloadBytes": _integer(aggregate.get("daily_down") if isinstance(aggregate, dict) else 0),
                },
                "connections": {
                    "ipv4": ipv4_connections,
                    "ipv6": ipv6_connections,
                    "ipv4Half": _integer(aggregate.get("ipv4_half_connection_count") if isinstance(aggregate, dict) else 0),
                    "ipv6Half": _integer(aggregate.get("ipv6_half_connection_count") if isinstance(aggregate, dict) else 0),
                    "ipv4Local": _integer(aggregate.get("ipv4_local_connection_count") if isinstance(aggregate, dict) else 0),
                    "ipv6Local": _integer(aggregate.get("ipv6_local_connection_count") if isinstance(aggregate, dict) else 0),
                    "flowCount": _integer(aggregate.get("flow_cnt") if isinstance(aggregate, dict) else 0),
                    "cps": _integer(aggregate.get("cps") if isinstance(aggregate, dict) else 0),
                    "max": _integer(_first(fast, "conntrack_max", "maxConnections")),
                },
            },
            "details": {
                "identity": {"hostname": hostname, "model": model, "serialNumber": serial},
                "wan": wan,
                "lan": lan,
                "ap": ap_details,
                "wireless": previous_wireless,
                "network": network,
                "networkGroup": network_group,
                "networkConnect": network_connect,
                "wirelessConfig": wireless_config,
                "rcgame": rcgame,
                "ports": port_rows,
            },
        }

    def sync_dashboard(self, force: bool = True) -> Dict[str, Any]:
        raw = self.client.dashboard(force=force)
        normalized = self._normalize_dashboard(raw if isinstance(raw, dict) else {})
        with self.hub.ROUTER_DASHBOARD_LOCK:
            refresh_nonce = self.hub.ROUTER_DASHBOARD_REFRESH_NONCE
            normalized["refreshNonce"] = refresh_nonce
            normalized["refreshCompletedNonce"] = refresh_nonce
            normalized["refreshCompletedAt"] = self.hub.now_str()
            self.hub.ROUTER_DASHBOARD_CACHE.clear()
            self.hub.ROUTER_DASHBOARD_CACHE.update(normalized)
            public = self.hub._router_dashboard_public()
        self.hub._persist_router_dashboard_if_due(force=False)
        self.hub.MQTT_PUBLISHER.publish_dashboard(public)
        return public

    def refresh_view(self):
        if not self.hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        global_nonce = 0
        with self.hub.ROUTER_DASHBOARD_LOCK:
            self.hub.ROUTER_DASHBOARD_REFRESH_NONCE += 1
            global_nonce = self.hub.ROUTER_DASHBOARD_REFRESH_NONCE
        try:
            result = self.sync_once(force=True)
            return jsonify({
                "ok": True,
                "refreshNonce": global_nonce,
                "refreshCompletedNonce": global_nonce,
                "message": "router RPC refresh completed",
                "dashboard": result["dashboard"],
                "time": self.hub.now_str(),
            })
        except RouterRpcError as exc:
            return jsonify({"ok": False, "error": exc.code, "message": str(exc)}), exc.http_status
        except Exception as exc:
            self.logger.warning("router direct manual refresh failed: %s", exc)
            return jsonify({"ok": False, "error": "ROUTER_REFRESH_FAILED", "message": str(exc)}), 502

    def ignored_relay_dashboard_push(self):
        if not self.hub.check_hook_token():
            return jsonify({"ok": False, "error": "bad agent token"}), 401
        return jsonify({
            "ok": True,
            "ignored": True,
            "source": "router_rpc",
            "message": "dashboard telemetry is supplied directly by Hub; Relay push is no longer authoritative",
            "time": self.hub.now_str(),
        })


def install_router_rpc_compat(hub: Any) -> RouterRpcCompatibilitySync:
    client = _find_client(hub.app)
    sync = RouterRpcCompatibilitySync(hub, client)
    if sync.primary:
        if "api_router_dashboard_refresh" in hub.app.view_functions:
            hub.app.view_functions["api_router_dashboard_refresh"] = sync.refresh_view
        if "api_router_dashboard_push" in hub.app.view_functions:
            hub.app.view_functions["api_router_dashboard_push"] = sync.ignored_relay_dashboard_push
    sync.start()
    hub.ROUTER_RPC_COMPAT_SYNC = sync
    return sync
