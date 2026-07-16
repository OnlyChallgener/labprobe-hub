import os
import json
import socket
import subprocess
import ipaddress
import re
import time
import threading
import secrets
from datetime import datetime, date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
import requests
import dns.resolver
from flask import Flask, request, jsonify

APP_VERSION = "0.8.3"
PORT = int(os.environ.get("PORT", "58443"))
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/app/config/config.yaml"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

EVENTS_FILE = DATA_DIR / "events.json"
STATE_FILE = DATA_DIR / "state.json"
VPN_STATE_FILE = DATA_DIR / "vpn_stun_addresses.json"
DEVICES_FILE = DATA_DIR / "devices.json"
DEVICE_ARCHIVE_FILE = DATA_DIR / "device_archive.json"
DAILY_FILE = DATA_DIR / "daily.json"
DAILY_ONLINE_FILE = DATA_DIR / "daily_online.json"
GEO_CACHE_FILE = DATA_DIR / "geo_cache.json"
PORTMAP_RULES_FILE = DATA_DIR / "portmaps.json"
PORTMAP_COMMANDS_FILE = DATA_DIR / "portmap_commands.json"
PORTMAP_ROUTER_STATUS_FILE = DATA_DIR / "portmap_router_status.json"
PORTMAP_HISTORY_FILE = DATA_DIR / "portmap_history.json"
NOTES_DIR = DATA_DIR / "notes"
NOTES_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

DATA_LOCK = threading.RLock()
REFRESH_LOCK = threading.RLock()
REFRESH_RUNNING = False
STATUS_REFRESH_TTL_SEC = int(os.environ.get("STATUS_REFRESH_TTL_SEC", "180"))



def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_str() -> str:
    return date.today().isoformat()


def time_to_epoch(v: Any) -> float:
    if not v:
        return 0.0
    text = str(v).strip()
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
        try:
            return datetime.strptime(text[:19], fmt).timestamp()
        except Exception:
            pass
    return 0.0


def load_json(path: Path, default: Any) -> Any:
    with DATA_LOCK:
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return default


def save_json(path: Path, data: Any) -> None:
    # v0.7.3：原子写入，避免 APP 刷新和路由器推送同时读写时出现半截 JSON / 覆盖。
    with DATA_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)


def load_config() -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    if CONFIG_PATH.exists():
        try:
            cfg = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
        except Exception as e:
            print(f"[LabProbe] config load failed: {e}", flush=True)
            cfg = {}
    return cfg


def cfg_get(path: str, default: Any = None) -> Any:
    cfg = load_config()
    cur: Any = cfg
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def get_app_token() -> str:
    return os.environ.get("APP_TOKEN") or cfg_get("server.app_token", "change-app-token")


def get_hook_token() -> str:
    return os.environ.get("HOOK_TOKEN") or cfg_get("server.hook_token", "change-hook-token")


def _auth_tokens_from_request() -> List[str]:
    """Collect all supported auth token locations.

    APP pages normally use Authorization: Bearer <APP_TOKEN>.
    Router scripts use X-LabProbe-Token / URL token with HOOK_TOKEN.
    Debugging from router shell is easier when GET APIs accept the same token
    headers as /api/router/push, so read-only APIs can accept either app or hook
    token without weakening POST/WOL behavior.
    """
    tokens: List[str] = []

    auth = request.headers.get("Authorization", "").strip()
    if auth.lower().startswith("bearer "):
        tokens.append(auth[7:].strip())
    elif auth:
        tokens.append(auth)

    for header in [
        "X-LabProbe-Token",
        "X-Labprobe-Token",
        "X-Hook-Token",
        "X-Api-Token",
        "X-API-Key",
        "X-LabProbe-Hook-Token",
    ]:
        v = request.headers.get(header, "").strip()
        if v:
            tokens.append(v)

    for arg in ["token", "app_token", "appToken", "hook_token", "hookToken", "key"]:
        v = request.args.get(arg, "").strip()
        if v:
            tokens.append(v)

    return [t for t in tokens if t]


def check_app_token() -> bool:
    app_token = get_app_token()
    return any(t == app_token for t in _auth_tokens_from_request())


def check_hook_token() -> bool:
    hook_token = get_hook_token()
    return any(t == hook_token for t in _auth_tokens_from_request())


def check_read_token() -> bool:
    allowed = {get_app_token(), get_hook_token()}
    return any(t in allowed for t in _auth_tokens_from_request())


def add_event(event: Dict[str, Any]) -> Dict[str, Any]:
    events: List[Dict[str, Any]] = load_json(EVENTS_FILE, [])
    next_id = int(events[-1].get("id", 0)) + 1 if events else 1
    event["id"] = next_id
    event.setdefault("createdAt", now_str())
    event.setdefault("level", "normal")
    events.append(event)
    events = events[-1000:]
    save_json(EVENTS_FILE, events)
    return event


def norm_mac(mac: Optional[str]) -> str:
    if not mac:
        return ""
    m = str(mac).lower().replace("-", ":").replace(".", "").strip()
    if ":" not in m and len(m) == 12:
        m = ":".join([m[i:i+2] for i in range(0, 12, 2)])
    return m


def prefer_name(item: Dict[str, Any]) -> str:
    for key in ["devUserDefine", "devRecommend", "hostName", "name", "manufacture", "mac"]:
        v = item.get(key)
        if v not in [None, ""]:
            return str(v)
    return "未知设备"


def to_int(v: Any, default: int = 0) -> int:
    try:
        return int(str(v))
    except Exception:
        return default


def human_bytes(v: Any) -> str:
    n = to_int(v, 0)
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return str(n)


TRAFFIC_UNIT_BYTES = {
    "": 1,
    "B": 1,
    "K": 1024,
    "KB": 1024,
    "KIB": 1024,
    "M": 1024 ** 2,
    "MB": 1024 ** 2,
    "MIB": 1024 ** 2,
    "G": 1024 ** 3,
    "GB": 1024 ** 3,
    "GIB": 1024 ** 3,
    "T": 1024 ** 4,
    "TB": 1024 ** 4,
    "TIB": 1024 ** 4,
}


def traffic_bytes(v: Any) -> Optional[int]:
    """Convert Ruijie traffic values to bytes without turning missing data into zero."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return max(0, int(v))
    text = str(v).strip().replace(",", "")
    if not text:
        return None
    match = re.search(r"(?i)([0-9]+(?:\.[0-9]+)?)\s*(TIB|TB|T|GIB|GB|G|MIB|MB|M|KIB|KB|K|B)?", text)
    if not match:
        return None
    number = float(match.group(1))
    unit = (match.group(2) or "").upper()
    return max(0, int(number * TRAFFIC_UNIT_BYTES.get(unit, 1)))


def first_traffic_value(item: Dict[str, Any], keys: List[str]) -> Any:
    containers = [item]
    for container_key in ["traffic", "flow", "trafficStats", "flowStats", "statistics", "stats"]:
        container = item.get(container_key)
        if isinstance(container, dict):
            containers.append(container)
    for container in containers:
        for key in keys:
            if key in container and container.get(key) not in [None, ""]:
                return container.get(key)
    return None


def normalize_device_traffic(item: Dict[str, Any]) -> Dict[str, Any]:
    """Expose stable traffic keys consumed by LabProbeApp.

    Ruijie user_list uses dailyUp/dailyDown for today's counters and up/down
    for the current router-uptime counters. Extra aliases keep this compatible
    with firmware variants without changing the raw payload.
    """
    today_upload = traffic_bytes(first_traffic_value(item, [
        "dailyUp", "todayUp", "dayUp", "dailyUpload", "todayUpload",
        "daily_up", "today_up", "todayTx", "todayTxBytes",
    ]))
    today_download = traffic_bytes(first_traffic_value(item, [
        "dailyDown", "todayDown", "dayDown", "dailyDownload", "todayDownload",
        "daily_down", "today_down", "todayRx", "todayRxBytes",
    ]))
    total_upload = traffic_bytes(first_traffic_value(item, [
        "up", "totalUp", "realtimeUp", "realTimeUp", "totalUpload",
        "total_up", "realtime_up", "totalTx", "totalTxBytes",
    ]))
    total_download = traffic_bytes(first_traffic_value(item, [
        "down", "totalDown", "realtimeDown", "realTimeDown", "totalDownload",
        "total_down", "realtime_down", "totalRx", "totalRxBytes",
    ]))

    out: Dict[str, Any] = {}
    today_group: Dict[str, int] = {}
    total_group: Dict[str, int] = {}
    if today_upload is not None:
        out["todayUpload"] = today_upload
        out["dailyUpBytes"] = today_upload
        today_group["upload"] = today_upload
    if today_download is not None:
        out["todayDownload"] = today_download
        out["dailyDownBytes"] = today_download
        today_group["download"] = today_download
    if total_upload is not None:
        out["totalUpload"] = total_upload
        out["upBytes"] = total_upload
        total_group["upload"] = total_upload
    if total_download is not None:
        out["totalDownload"] = total_download
        out["downBytes"] = total_download
        total_group["download"] = total_download
    if today_group:
        out["todayTraffic"] = today_group
        out["trafficDate"] = today_str()
    if total_group:
        out["realtimeTraffic"] = total_group
    if today_group or total_group:
        out["trafficUpdatedAt"] = now_str()
    return out



def human_duration(seconds: Any) -> str:
    sec = to_int(seconds, 0)
    if sec <= 0:
        return ""
    h = sec // 3600
    m = (sec % 3600) // 60
    if h > 0:
        return f"{h}小时{m:02d}分"
    return f"{m}分"


def human_duration_precise(seconds: Any) -> str:
    sec = to_int(seconds, 0)
    if sec <= 0:
        return ""
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    if h > 0:
        return f"{h}小时{m:02d}分{s:02d}秒"
    if m > 0:
        return f"{m}分{s:02d}秒"
    return f"{s}秒"


def today_online_seconds_from_item(item: Dict[str, Any], now: Optional[datetime] = None) -> int:
    """Return a safe same-day seed from one Ruijie user_list record.

    Wireless clients usually expose onlinetime/activeTime. Wired clients often
    leave both empty, so their real daily duration is maintained separately by
    update_daily_online_durations().
    """
    now = now or datetime.now()
    midnight = datetime.combine(now.date(), datetime.min.time())
    seconds_since_midnight = max(0, int((now - midnight).total_seconds()))

    active = to_int(item.get("activeTime") or item.get("onlineDurationSec") or item.get("durationSec"), 0)
    start = parse_time_safe(item.get("onlinetime") or item.get("onlineSince") or item.get("startTime"))
    if start:
        window_start = max(start, midnight)
        return max(0, min(seconds_since_midnight, int((now - window_start).total_seconds())))
    if active > 0:
        return min(active, seconds_since_midnight)
    return 0


def update_daily_online_durations(devices: List[Dict[str, Any]], now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Persist per-MAC online seconds for the current local calendar day.

    The router snapshot arrives about once per minute. We accumulate only while
    the same MAC is present in consecutive snapshots. A small gap cap prevents a
    long Hub outage from being counted as confirmed online time. Wireless
    onlinetime/activeTime remains a useful lower-bound seed; wired devices are
    tracked entirely by Hub snapshots.
    """
    now = now or datetime.now()
    day = now.date().isoformat()
    now_epoch = int(now.timestamp())
    state = load_json(DAILY_ONLINE_FILE, {})
    if not isinstance(state, dict) or state.get("date") != day:
        state = {"date": day, "devices": {}, "updatedAt": now_str()}
    entries = state.get("devices") if isinstance(state.get("devices"), dict) else {}

    by_mac: Dict[str, Dict[str, Any]] = {}
    for dev in devices or []:
        mac = norm_mac(dev.get("mac"))
        if mac:
            by_mac[mac] = dev

    # Close devices absent from this authoritative online snapshot.
    for mac, entry in list(entries.items()):
        if not isinstance(entry, dict):
            entries[mac] = {"seconds": 0, "online": False, "lastSampleEpoch": now_epoch}
            continue
        if mac not in by_mac:
            entry["online"] = False
            entry["lastSampleEpoch"] = now_epoch

    for mac, dev in by_mac.items():
        raw = dev.get("raw") if isinstance(dev.get("raw"), dict) else dev
        seed = today_online_seconds_from_item(raw, now)
        entry = entries.get(mac) if isinstance(entries.get(mac), dict) else {}
        seconds = max(0, to_int(entry.get("seconds"), 0))
        last_epoch = to_int(entry.get("lastSampleEpoch"), 0)
        if bool(entry.get("online")) and last_epoch > 0:
            delta = max(0, now_epoch - last_epoch)
            # Normal cadence is 60 s. Count short restart/network gaps, but do
            # not claim hours of unobserved wired-device uptime.
            seconds += min(delta, 300)
        if seed > seconds:
            seconds = seed

        first_seen = clean_saved_value(entry.get("firstSeenAt")) or now.strftime("%Y-%m-%d %H:%M:%S")
        entries[mac] = {
            "seconds": seconds,
            "online": True,
            "firstSeenAt": first_seen,
            "lastSeenAt": now.strftime("%Y-%m-%d %H:%M:%S"),
            "lastSampleEpoch": now_epoch,
        }
        dev["todayOnlineDurationSec"] = seconds
        dev["todayOnlineDurationText"] = human_duration(seconds)
        dev["todayOnlineDate"] = day

    state["date"] = day
    state["devices"] = entries
    state["updatedAt"] = now.strftime("%Y-%m-%d %H:%M:%S")
    save_json(DAILY_ONLINE_FILE, state)
    return devices


def clean_saved_value(v: Any) -> str:
    text = "" if v is None else str(v).strip()
    if text.lower() in ["", "null", "none", "nan"] or text == "-":
        return ""
    return text


def strip_ip_prefix(v: Any) -> str:
    text = clean_saved_value(v)
    if not text:
        return ""
    # 允许手动配置 2409:.../64，展示和 WireGuard 只需要纯地址。
    if "/" in text and not text.startswith("http"):
        text = text.split("/", 1)[0].strip()
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")].strip()
    return text


def is_public_ip_text(v: Any, ipv6: bool = False) -> bool:
    text = strip_ip_prefix(v)
    if not text:
        return False
    try:
        ip = ipaddress.ip_address(text)
        if ipv6 and ip.version != 6:
            return False
        if not ipv6 and ip.version != 4:
            return False
        return ip.is_global
    except Exception:
        return False


def get_manual_nas_ip(ipv6: bool = False) -> str:
    # 最高优先级：显式手动配置。用于 Docker bridge 无法直接 curl 出 NAS IPv6 的情况。
    # docker-compose 可写：NAS_IPV6=2409:...:2a79 或 NAS_IPV6=2409:...:2a79/64
    keys = ["NAS_IPV6", "LABPROBE_NAS_IPV6", "EXIT_IPV6"] if ipv6 else ["NAS_IPV4", "LABPROBE_NAS_IPV4", "EXIT_IPV4"]
    for k in keys:
        v = strip_ip_prefix(os.environ.get(k))
        if v and is_public_ip_text(v, ipv6=ipv6):
            return v
    cfg_keys = [
        "nas.exit_ipv6", "nas.exitIpv6", "nas.ipv6", "exit_ip.manual_ipv6", "exit_ip.ipv6_manual"
    ] if ipv6 else [
        "nas.exit_ipv4", "nas.exitIpv4", "nas.ipv4", "exit_ip.manual_ipv4", "exit_ip.ipv4_manual"
    ]
    for k in cfg_keys:
        v = strip_ip_prefix(cfg_get(k, ""))
        if v and is_public_ip_text(v, ipv6=ipv6):
            return v
    return ""


def get_route_source_ipv6() -> str:
    """Return the IPv6 source address the NAS kernel would actually use."""
    for target in ["2606:4700:4700::1111", "2001:4860:4860::8888"]:
        try:
            out = subprocess.check_output(["ip", "-6", "route", "get", target], text=True, timeout=3)
        except Exception:
            continue
        match = re.search(r"(?:^|\s)src\s+([0-9a-fA-F:]+)(?:\s|$)", out)
        ip = strip_ip_prefix(match.group(1)) if match else ""
        if ip and is_public_ip_text(ip, ipv6=True):
            return ip
    return ""


def get_local_lan_ipv4() -> str:
    """Return the host LAN IPv4, including RFC1918 addresses."""
    for target in ["1.1.1.1", "8.8.8.8"]:
        try:
            out = subprocess.check_output(["ip", "-4", "route", "get", target], text=True, timeout=3)
        except Exception:
            continue
        match = re.search(r"(?:^|\s)src\s+(\d+(?:\.\d+){3})(?:\s|$)", out)
        if not match:
            continue
        try:
            addr = ipaddress.ip_address(match.group(1))
            if addr.version == 4 and not addr.is_loopback and not addr.is_unspecified:
                return str(addr)
        except Exception:
            pass
    return ""


def get_local_global_ip(ipv6: bool = False) -> str:
    # For IPv6, route-source selection is authoritative. It avoids choosing an
    # arbitrary first address (often the old EUI-64) from a multi-address NIC.
    if ipv6:
        route_src = get_route_source_ipv6()
        if route_src:
            return route_src

    cmd = ["ip", "-6" if ipv6 else "-4", "addr", "show", "scope", "global"]
    try:
        out = subprocess.check_output(cmd, text=True, timeout=3)
    except Exception:
        return ""
    candidates = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("inet6 " if ipv6 else "inet "):
            continue
        if any(x in line for x in ["tentative", "deprecated"]):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = strip_ip_prefix(parts[1])
        if is_public_ip_text(ip, ipv6=ipv6):
            score = 10 if "temporary" in line.lower() else 0
            candidates.append((score, ip))
    candidates.sort(key=lambda x: x[0])
    return candidates[0][1] if candidates else ""


def clean_vpn_address(v: Any) -> str:
    text = clean_saved_value(v)
    if not text:
        return ""
    low = text.lower()
    bad_parts = ["#{", "{stun_", "token=", "bearer ", "authorization"]
    if any(b in low for b in bad_parts):
        return ""
    return text


def vpn_service_key(name: Any) -> str:
    raw = clean_saved_value(name) or "STUN"
    key = raw.lower().strip().replace(" ", "_").replace("/", "_")
    key = re.sub(r"[^a-z0-9_一-鿿-]+", "_", key)
    return key.strip("_") or "stun"


def load_vpn_addresses() -> Dict[str, Dict[str, Any]]:
    raw = load_json(VPN_STATE_FILE, {})
    return raw if isinstance(raw, dict) else {}


def save_vpn_addresses(data: Dict[str, Dict[str, Any]]) -> None:
    clean: Dict[str, Dict[str, Any]] = {}
    for k, item in (data or {}).items():
        if not isinstance(item, dict):
            continue
        name = clean_saved_value(item.get("name")) or k
        address = clean_vpn_address(item.get("address") or item.get("stun"))
        if not address:
            continue
        clean[vpn_service_key(name)] = {
            "name": name,
            "address": address,
            "stun": address,
            "source": clean_saved_value(item.get("source")) or "webhook",
            "updatedAt": clean_saved_value(item.get("updatedAt")) or now_str(),
        }
    save_json(VPN_STATE_FILE, clean)


def upsert_vpn_address(name: Any, address: Any, source: str = "webhook") -> Tuple[Dict[str, Any], str]:
    service = clean_saved_value(name) or "STUN"
    addr = clean_vpn_address(address)
    if not addr:
        return {}, ""
    key = vpn_service_key(service)
    data = load_vpn_addresses()
    old = clean_vpn_address((data.get(key) or {}).get("address"))
    item = {
        "name": service,
        "address": addr,
        "stun": addr,
        "source": source,
        "updatedAt": now_str(),
    }
    data[key] = item
    save_vpn_addresses(data)
    return item, old


def vpn_addresses_list(state: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    if isinstance(state, dict):
        vpn = state.get("vpn")
        if isinstance(vpn, dict):
            for k, item in vpn.items():
                if isinstance(item, dict):
                    name = clean_saved_value(item.get("name")) or k
                    addr = clean_vpn_address(item.get("address") or item.get("stun"))
                    if addr:
                        merged[vpn_service_key(name)] = {"name": name, "address": addr, "stun": addr, "source": clean_saved_value(item.get("source")) or "state", "updatedAt": clean_saved_value(item.get("updatedAt"))}
        for legacy_key, default_name in [("luckyStun", "Lucky"), ("stun", "STUN")]:
            item = state.get(legacy_key)
            if isinstance(item, dict):
                name = clean_saved_value(item.get("name")) or default_name
                addr = clean_vpn_address(item.get("address") or item.get("stun") or item.get("publicAddress"))
                if addr:
                    merged.setdefault(vpn_service_key(name), {"name": name, "address": addr, "stun": addr, "source": clean_saved_value(item.get("source")) or "legacy", "updatedAt": clean_saved_value(item.get("updatedAt"))})
    for k, item in load_vpn_addresses().items():
        name = clean_saved_value(item.get("name")) or k
        addr = clean_vpn_address(item.get("address") or item.get("stun"))
        if addr:
            merged[vpn_service_key(name)] = {"name": name, "address": addr, "stun": addr, "source": clean_saved_value(item.get("source")) or "webhook", "updatedAt": clean_saved_value(item.get("updatedAt"))}
    preferred = {"wireguard": 0, "openvpn": 1, "lucky": 2, "easytier": 3, "stun": 4}
    return sorted(merged.values(), key=lambda x: (preferred.get(vpn_service_key(x.get("name")), 50), str(x.get("name", ""))))


def parse_vpn_text_content(text: Any) -> Tuple[str, str]:
    raw = str(text or "").strip().replace("\r", " ").replace("\n", " ")
    if not raw:
        return "", ""
    m = re.search(r"^\s*([^:：]{1,32})\s*[:：]\s*(.+?)\s*$", raw)
    if m:
        return clean_saved_value(m.group(1)), clean_vpn_address(m.group(2))
    return "", clean_vpn_address(raw)


def vpn_address_from_event(event: Dict[str, Any]) -> Tuple[str, str]:
    if not isinstance(event, dict):
        return "", ""
    typ = str(event.get("type") or "")
    title = str(event.get("title") or "")
    content = event.get("content") or event.get("text") or ""
    name = clean_saved_value(event.get("name") or event.get("service"))
    addr = clean_vpn_address(event.get("address") or event.get("newValue") or event.get("value") or event.get("stun"))
    parsed_name, parsed_addr = parse_vpn_text_content(content)
    if not name:
        name = parsed_name
    if not addr:
        addr = parsed_addr
    if not name and title:
        # 兼容“OpenVPN STUN 地址变化”这类标题。
        name = clean_saved_value(title.replace("STUN 地址变化", "").replace("地址变化", "").strip())
    if not name:
        return "", ""
    low_name = name.lower()
    low_type = typ.lower()
    known = ["wireguard", "openvpn", "open_vpn", "lucky", "easytier", "easy_tier", "stun"]
    if not any(k in low_name.replace(" ", "_") for k in known) and "stun" not in low_type and "vpn" not in low_type and "lucky" not in low_type:
        return "", ""
    return name, addr


def ensure_vpn_addresses_from_events(state: Dict[str, Any]) -> Dict[str, Any]:
    """Repair current VPN/STUN state from recent event history.

    首页读的是 /api/status 当前状态；记录页/每日总结读的是 events。
    如果老版本只保存了事件、或同地址 webhook 没有新增变化事件，这里会把最近事件补进 current state。
    """
    current = {vpn_service_key(x.get("name")): x for x in vpn_addresses_list(state)}
    changed = False
    events = load_json(EVENTS_FILE, [])
    for e in reversed(events[-300:]):
        name, addr = vpn_address_from_event(e)
        if not name or not addr:
            continue
        key = vpn_service_key(name)
        if key not in current or not clean_vpn_address(current.get(key, {}).get("address")):
            item, _ = upsert_vpn_address(name, addr, clean_saved_value(e.get("source")) or "event_repair")
            if item:
                current[key] = item
                state.setdefault("vpn", {})[key] = item
                changed = True
    if changed:
        state["vpnStunAddresses"] = vpn_addresses_list(state)
        state["vpnAddresses"] = state["vpnStunAddresses"]
        state["updatedAt"] = now_str()
        save_json(STATE_FILE, state)
    return state



def merge_non_empty(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base or {})
    for k, v in (overlay or {}).items():
        if clean_saved_value(v):
            out[k] = v
        elif k not in out:
            out[k] = v
    return out


def load_device_archive() -> Dict[str, Dict[str, Any]]:
    raw = load_json(DEVICE_ARCHIVE_FILE, {})
    return raw if isinstance(raw, dict) else {}


def save_device_archive(data: Dict[str, Dict[str, Any]]) -> None:
    # MAC 数量很少，但仍然限制一下，避免无限增长。
    items = list(data.items())[-500:]
    save_json(DEVICE_ARCHIVE_FILE, dict(items))


def archive_device_snapshot(dev: Dict[str, Any]) -> None:
    mac = norm_mac(dev.get("mac"))
    if not mac:
        return
    archive = load_device_archive()
    old = archive.get(mac, {})
    keep_keys = [
        "name", "mac", "ip", "lastIp", "ssid", "band", "rssi", "rxrate", "channel",
        "connectType", "onlineSince", "onlineDurationText", "lastSeenAt", "offlineAt",
        "todayOnlineDurationSec", "todayOnlineDurationText", "todayOnlineDate",
        "hostName", "devType", "osType", "manufacture", "devRecommend", "ipv6", "ipv6Address", "globalIpv6",
        "ipv6List", "ipv6Records", "ipv6UpdatedAt", "ndpState", "ndpDev", "wolMode",
        "todayUpload", "todayDownload", "totalUpload", "totalDownload", "todayTraffic", "realtimeTraffic",
        "dailyUpBytes", "dailyDownBytes", "upBytes", "downBytes", "trafficDate", "trafficUpdatedAt", "trafficText"
    ]
    snap = {k: dev.get(k) for k in keep_keys if k in dev}
    if clean_saved_value(snap.get("trafficDate")) and snap.get("trafficDate") != old.get("trafficDate"):
        old = dict(old)
        for key in ["todayUpload", "todayDownload", "todayTraffic", "dailyUpBytes", "dailyDownBytes"]:
            old.pop(key, None)
    # 在线时把 ip 同步成 lastIp；离线时保留旧 lastIp，不被 None 覆盖。
    if clean_saved_value(snap.get("ip")):
        snap["lastIp"] = snap.get("ip")
    merged = merge_non_empty(old, snap)
    merged["mac"] = mac
    merged["archivedAt"] = now_str()
    archive[mac] = merged
    save_device_archive(archive)


def hydrate_device_with_archive(dev: Dict[str, Any], archive: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    mac = norm_mac(dev.get("mac"))
    if not mac:
        return dev
    archive = archive if archive is not None else load_device_archive()
    old = archive.get(mac, {})
    if not old:
        return dev
    out = dict(dev)
    # 离线设备长期保留最后一次有效信息；在线设备只补缺失字段。
    hydrate_keys = [
        "name", "lastIp", "ssid", "band", "rssi", "rxrate", "channel", "connectType", "onlineSince",
        "onlineDurationText", "lastSeenAt",
        "hostName", "devType", "osType", "manufacture", "devRecommend",
        "ipv6", "ipv6Address", "globalIpv6", "ipv6List", "ipv6Records", "ipv6UpdatedAt", "ndpState", "ndpDev", "wolMode",
        "totalUpload", "totalDownload", "realtimeTraffic", "upBytes", "downBytes", "trafficUpdatedAt", "trafficText",
    ]
    if old.get("trafficDate") == today_str():
        hydrate_keys.extend(["todayUpload", "todayDownload", "todayTraffic", "dailyUpBytes", "dailyDownBytes", "trafficDate"])
    if old.get("todayOnlineDate") == today_str():
        hydrate_keys.extend(["todayOnlineDurationSec", "todayOnlineDurationText", "todayOnlineDate"])
    for k in hydrate_keys:
        if not clean_saved_value(out.get(k)) and clean_saved_value(old.get(k)):
            out[k] = old.get(k)

    # v0.7.9: expose the preferred global IPv6 as flat fields too, because
    # older/newer APP builds may read either ipv6 or ipv6List.
    current_prefixes = normalize_ipv6_prefixes((load_json(STATE_FILE, {}).get("router") or {}).get("lanIpv6Prefixes") or [])
    ipv6_records = normalize_ipv6_records(out.get("ipv6Records") or old.get("ipv6Records") or [], current_prefixes)
    if ipv6_records:
        best = pick_primary_ipv6(ipv6_records)
        ordered = [best] + [r["ip"] for r in sorted(ipv6_records, key=score_ipv6_record, reverse=True) if r.get("ip") != best]
        out["ipv6Records"] = ipv6_records
        out["ipv6List"] = normalize_ipv6_list(ordered)
        if best:
            out["ipv6"] = best
            out["ipv6Address"] = best
            out["globalIpv6"] = best

    ipv6_list = normalize_ipv6_list(out.get("ipv6List") or old.get("ipv6List") or [])
    if ipv6_list:
        out["ipv6List"] = ipv6_list
        if not clean_saved_value(out.get("ipv6")):
            out["ipv6"] = ipv6_list[0]
        if not clean_saved_value(out.get("ipv6Address")):
            out["ipv6Address"] = ipv6_list[0]
        if not clean_saved_value(out.get("globalIpv6")):
            out["globalIpv6"] = ipv6_list[0]
    if not bool(out.get("online")):
        if not clean_saved_value(out.get("ip")) and clean_saved_value(old.get("lastIp") or old.get("ip")):
            out["lastIp"] = old.get("lastIp") or old.get("ip")
        if not clean_saved_value(out.get("offlineAt")) and clean_saved_value(old.get("offlineAt")):
            out["offlineAt"] = old.get("offlineAt")
    return out


def hydrate_watched_list(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    archive = load_device_archive()
    return [hydrate_device_with_archive(d, archive) for d in (items or [])]


def parse_time_safe(v: Any) -> Optional[datetime]:
    if not v:
        return None
    text = str(v).strip()
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
        try:
            return datetime.strptime(text[:19], fmt)
        except Exception:
            pass
    return None


def duration_between(start: Any, end: Any) -> str:
    st = parse_time_safe(start)
    et = parse_time_safe(end)
    if not st or not et:
        return ""
    sec = int((et - st).total_seconds())
    return human_duration_precise(sec)


def is_public_ipv6(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("/")[0].strip())
        return ip.version == 6 and ip.is_global and not ip.is_link_local and not ip.is_multicast and not ip.is_loopback
    except Exception:
        return False


def extract_public_ipv6(text: str) -> Optional[str]:
    # 优先从 `inet6 xxxx/64 scope global` 中提取，过滤 fe80/fd/fc/ff 等非公网地址。
    candidates: List[Tuple[int, str]] = []
    for line in text.splitlines():
        if "inet6" not in line:
            continue
        m = re.search(r"inet6\s+([0-9a-fA-F:]+)(?:/\d+)?", line)
        if not m:
            continue
        addr = m.group(1)
        if not is_public_ipv6(addr):
            continue
        score = 0
        low = line.lower()
        if "scope global" in low:
            score += 10
        if "temporary" in low:
            score -= 3
        if "deprecated" in low:
            score -= 5
        candidates.append((score, addr))
    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]
    # 兜底：从任意文本里找公网 v6。
    for token in re.findall(r"[0-9a-fA-F:]{3,}", text):
        if ":" in token and is_public_ipv6(token):
            return token
    return None



def normalize_ip(ip: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(str(ip).split("/")[0].strip())
    except Exception:
        return None


def local_geo_match(ip: str) -> Optional[Dict[str, Any]]:
    addr = normalize_ip(ip)
    if not addr:
        return None
    for item in (cfg_get("geo.local_prefixes", []) or []):
        try:
            net = ipaddress.ip_network(str(item.get("prefix")), strict=False)
            if addr in net:
                return {
                    "localLabel": item.get("label") or item.get("name") or "本地标记",
                    "operator": item.get("operator") or item.get("isp") or "",
                    "source": "local_prefix",
                    "confidence": "本地标记最高",
                }
        except Exception:
            continue
    return None


def operator_from_text(asn: Any = None, org: str = "") -> str:
    org_l = str(org or "").lower()
    asn_s = str(asn or "")
    if any(k in org_l for k in ["unicom", "联通", "china169"]) or asn_s in {"4837", "9929", "10099", "136958"}:
        return "中国联通"
    if any(k in org_l for k in ["telecom", "chinanet", "电信"]) or asn_s in {"4134", "4812", "58466", "4809"}:
        return "中国电信"
    if any(k in org_l for k in ["mobile", "cmcc", "移动"]) or asn_s in {"9808", "56040", "56046", "56048", "24400"}:
        return "中国移动"
    if "cernet" in org_l or "教育" in org_l:
        return "教育网"
    return str(org or "")


def lookup_geo(ip: str) -> Dict[str, Any]:
    # v0.6.1：只返回本地标记、运营商与 ASN，不再返回城市 Geo，避免家宽/IPv6 城市漂移误导。
    cache = load_json(GEO_CACHE_FILE, {})
    cached = cache.get(ip)
    if cached and cached.get("cachedAt"):
        # 兼容旧缓存：去掉城市字段。
        cached.pop("geoText", None)
        cached.pop("location", None)
        return cached

    local = local_geo_match(ip)
    if local:
        result = {
            "ip": ip,
            "localLabel": local.get("localLabel", ""),
            "operator": local.get("operator", ""),
            "asn": "",
            "source": local.get("source", "local_prefix"),
            "confidence": "本地标记最高",
            "note": "命中 config.yaml 的 geo.local_prefixes；仅显示运营商/本地标记，不显示城市 Geo。",
            "cachedAt": now_str(),
        }
        cache[ip] = result
        save_json(GEO_CACHE_FILE, cache)
        return result

    operator = ""
    asn = ""
    source = "ipwho.is_connection"
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=4)
        data = r.json()
        if data.get("success"):
            conn = data.get("connection") or {}
            asn = str(conn.get("asn") or "")
            org = conn.get("org") or data.get("org") or ""
            operator = operator_from_text(asn, org)
    except Exception:
        pass

    result = {
        "ip": ip,
        "localLabel": "",
        "operator": operator,
        "asn": asn,
        "source": source,
        "confidence": "运营商识别" if operator else "运营商未知",
        "note": "已移除城市 Geo，仅返回运营商/ASN，避免城市漂移误导。",
        "cachedAt": now_str(),
    }
    cache[ip] = result
    cache = dict(list(cache.items())[-1000:])
    save_json(GEO_CACHE_FILE, cache)
    return result

def normalize_ipv6_list(values: Any) -> List[str]:
    raw: List[str] = []
    if isinstance(values, list):
        raw = [str(x or "") for x in values]
    elif isinstance(values, str):
        raw = re.split(r"[\s,]+", values)
    out: List[str] = []
    for v in raw:
        ip = str(v or "").strip().split("/")[0]
        if not ip or ":" not in ip or ip.lower().startswith("fe80:"):
            continue
        try:
            addr = ipaddress.ip_address(ip)
            if (
                addr.version == 6
                and not addr.is_link_local
                and not addr.is_multicast
                and not addr.is_loopback
                and not addr.ipv4_mapped
            ):
                out.append(str(addr))
        except Exception:
            continue
    return list(dict.fromkeys(out))[:8]


def normalize_ipv6_prefixes(values: Any) -> List[str]:
    raw: List[str] = []
    if isinstance(values, list):
        raw = [str(x.get("prefix") if isinstance(x, dict) else x) for x in values]
    elif isinstance(values, str):
        raw = re.split(r"[\s,]+", values)
    out: List[str] = []
    for v in raw:
        text = clean_saved_value(v)
        if not text or ":" not in text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
            if net.version == 6 and not net.is_link_local and not net.is_multicast and not net.is_loopback:
                out.append(str(net))
        except Exception:
            continue
    return list(dict.fromkeys(out))[:16]


def normalize_ipv6_items(values: Any, default_name: str = "IPv6") -> List[Dict[str, Any]]:
    items: List[Any] = values if isinstance(values, list) else []
    out: List[Dict[str, Any]] = []
    seen = set()
    for i, item in enumerate(items):
        if isinstance(item, str):
            item = {"ip": item}
        if not isinstance(item, dict):
            continue
        ips = normalize_ipv6_list([item.get("ip") or item.get("address") or item.get("ipv6") or item.get("value")])
        if not ips or ips[0] in seen:
            continue
        seen.add(ips[0])
        name = clean_saved_value(item.get("name")) or (default_name if i == 0 else f"{default_name} {i + 1}")
        out.append({
            "name": name,
            "ip": ips[0],
            "dev": clean_saved_value(item.get("dev") or item.get("iface") or item.get("ifname")),
            "primary": bool(item.get("primary")) or (i == 0),
        })
    if out and not any(x.get("primary") for x in out):
        out[0]["primary"] = True
    return out[:16]


def ipv6_in_prefixes(ip: str, prefixes: List[str]) -> bool:
    if not ip or not prefixes:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(p, strict=False) for p in prefixes)
    except Exception:
        return False


def is_ula_ipv6(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == 6 and addr.is_private and str(addr).lower().startswith(("fc", "fd"))
    except Exception:
        return False


def is_temporary_ipv6(ip: str, source: str = "") -> bool:
    # A random-looking IID can be a stable RFC 7217 address. Only explicit
    # metadata may classify an address as temporary/privacy.
    source_l = str(source or "").lower()
    return any(token in source_l for token in ["temporary", "privacy", " temp", "临时", "隐私"])


def ipv6_reachability_score(state: Any) -> int:
    s = clean_saved_value(state).upper()
    if s == "REACHABLE":
        return 20
    if s in ["DELAY", "PROBE"]:
        return 12
    if s == "STALE":
        return 4
    if s == "FAILED":
        return -30
    return 0


def score_ipv6_record(rec: Dict[str, Any]) -> int:
    ip = clean_saved_value(rec.get("ip"))
    if not ip:
        return -9999
    score = 0
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 6 or addr.is_link_local or addr.is_multicast or addr.is_loopback or addr.ipv4_mapped:
            return -9999
        if addr.is_global:
            score += 100
        elif is_ula_ipv6(ip):
            score += 40
    except Exception:
        return -9999
    if rec.get("currentPrefix"):
        score += 25
    if rec.get("historical"):
        score -= 35
    score += ipv6_reachability_score(rec.get("state") or rec.get("ndState"))
    source = str(rec.get("source") or "")
    if "hub_local" in source:
        score += 160
    if rec.get("primary"):
        score += 120
    if "crosscheck" in source.lower():
        score -= 80
    if "dhcp" in source.lower():
        score += 10
    if not is_temporary_ipv6(ip, source):
        score += 8
    else:
        score -= 10
    score += min(5, int(time_to_epoch(rec.get("lastSeen") or rec.get("lastSeenAt")) // 86400) % 6)
    return score


def pick_primary_ipv6(records: List[Dict[str, Any]]) -> str:
    valid = [r for r in records if score_ipv6_record(r) > -9999]
    if not valid:
        return ""
    valid.sort(key=lambda r: (score_ipv6_record(r), time_to_epoch(r.get("lastReachable") or r.get("lastSeen"))), reverse=True)
    return clean_saved_value(valid[0].get("ip"))


def normalize_ipv6_records(records: Any, current_prefixes: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    current_prefixes = current_prefixes or []
    out: List[Dict[str, Any]] = []
    if isinstance(records, dict):
        records = list(records.values())
    if not isinstance(records, list):
        records = []
    for item in records:
        if isinstance(item, str):
            item = {"ip": item}
        if not isinstance(item, dict):
            continue
        ips = normalize_ipv6_list([item.get("ip") or item.get("ipv6") or item.get("address") or item.get("addr")])
        if not ips:
            continue
        ip = ips[0]
        state = clean_saved_value(item.get("state") or item.get("ndState"))
        source = clean_saved_value(item.get("source")) or "unknown"
        current_prefix = ipv6_in_prefixes(ip, current_prefixes) if current_prefixes else bool(item.get("currentPrefix"))
        rec = {
            "ip": ip,
            "firstSeen": clean_saved_value(item.get("firstSeen") or item.get("seenAt") or item.get("lastSeen")) or now_str(),
            "lastSeen": clean_saved_value(item.get("lastSeen") or item.get("seenAt")) or now_str(),
            "lastReachable": clean_saved_value(item.get("lastReachable")),
            "source": source,
            "state": state,
            "dev": clean_saved_value(item.get("dev") or item.get("iface") or item.get("ifname")),
            "currentPrefix": current_prefix,
            "temporary": bool(item.get("temporary")) or is_temporary_ipv6(ip, source),
            "primary": bool(item.get("primary")),
        }
        if not rec["lastReachable"] and state.upper() in ["REACHABLE", "DELAY", "PROBE"]:
            rec["lastReachable"] = rec["lastSeen"]
        rec["historical"] = (
            bool(not rec["currentPrefix"] and not is_ula_ipv6(ip))
            if current_prefixes else bool(item.get("historical"))
        )
        out.append(rec)
    dedup: Dict[str, Dict[str, Any]] = {}
    for rec in out:
        dedup[rec["ip"]] = rec
    return list(dedup.values())[:24]


def local_hub_ipv6_records() -> List[Dict[str, Any]]:
    out = []
    for ip in normalize_ipv6_list([get_local_global_ip(True)]):
        out.append({
            "ip": ip,
            "firstSeen": now_str(),
            "lastSeen": now_str(),
            "lastReachable": now_str(),
            "source": "hub_local_probe",
            "state": "REACHABLE",
            "dev": "hub",
            "currentPrefix": True,
            "temporary": is_temporary_ipv6(ip, "hub_local_probe"),
            "historical": False,
            "primary": True,
        })
    return out


def configured_nas_macs() -> set:
    vals: List[str] = []
    env_raw = os.environ.get("NAS_MAC") or os.environ.get("LABPROBE_NAS_MAC") or ""
    if env_raw:
        vals.extend(re.split(r"[\s,;]+", env_raw))
    for key in ["nas.mac", "nas.macs", "nas.device_mac"]:
        raw = cfg_get(key, None)
        if isinstance(raw, list):
            vals.extend(str(x) for x in raw)
        elif raw:
            vals.extend(re.split(r"[\s,;]+", str(raw)))

    # Backward-compatible inference for existing configs that only list a
    # watched device named NAS/绿联 NAS.
    for item in cfg_get("watched_devices", []) or []:
        if not isinstance(item, dict):
            continue
        label = " ".join(str(item.get(k) or "") for k in ["name", "remark", "devType", "type"]).lower()
        if "nas" in label or "绿联" in label or "ugreen" in label:
            vals.append(str(item.get("mac") or ""))
    return {norm_mac(x) for x in vals if norm_mac(x)}



def parse_ipv6_neighbor_text(text: str) -> List[Dict[str, Any]]:
    """Parse `ip -6 neigh show` text lines from router agent.
    Example: 2409:... dev br-lan lladdr 6c:1f:f7:76:71:04 REACHABLE
    """
    out: List[Dict[str, Any]] = []
    for line in str(text or "").splitlines():
        raw = line.strip()
        if not raw:
            continue
        m = re.search(r"(?P<ip>[0-9a-fA-F:]{3,})(?:/\d+)?\s+dev\s+(?P<dev>\S+).*?lladdr\s+(?P<mac>[0-9a-fA-F:]{2}(?::[0-9a-fA-F:]{2}){5})(?:\s+(?P<state>[A-Z_]+))?", raw)
        if not m:
            continue
        mac = norm_mac(m.group("mac"))
        ips = normalize_ipv6_list([m.group("ip")])
        if mac and ips:
            out.append({"mac": mac, "ip": ips[0], "state": clean_saved_value(m.group("state")), "dev": clean_saved_value(m.group("dev")), "seenAt": now_str(), "source": "router_ndp"})
    return out

def parse_ipv6_neighbors(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    items = payload.get("ipv6_neighbors") or payload.get("ipv6Neighbors") or payload.get("ndp") or payload.get("neighbors")
    leases = payload.get("dhcpv6_leases") or payload.get("dhcpv6Leases") or payload.get("leases") or []
    text = payload.get("ipv6_neighbors_text") or payload.get("ipv6NeighborsText") or payload.get("ip6_neigh") or payload.get("ip6Neigh") or payload.get("ndpText")

    out: List[Dict[str, Any]] = []
    if isinstance(items, str):
        out += parse_ipv6_neighbor_text(items)
        items = []
    if isinstance(text, str):
        out += parse_ipv6_neighbor_text(text)
    if not isinstance(items, list):
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        mac = norm_mac(item.get("mac") or item.get("lladdr") or item.get("linkLayerAddress"))
        ip = clean_saved_value(item.get("ip") or item.get("ipv6") or item.get("address") or item.get("addr"))
        ips = normalize_ipv6_list([ip])
        if mac and ips:
            out.append({
                "mac": mac,
                "ip": ips[0],
                "state": clean_saved_value(item.get("state")),
                "dev": clean_saved_value(item.get("dev") or item.get("iface") or item.get("ifname")),
                "seenAt": clean_saved_value(item.get("seenAt") or item.get("collectedAt")) or now_str(),
                "source": clean_saved_value(item.get("source")) or "router_ndp",
            })

    if isinstance(leases, list):
        for item in leases:
            if not isinstance(item, dict):
                continue
            mac = norm_mac(item.get("mac") or item.get("duidMac") or item.get("lladdr"))
            ip = clean_saved_value(item.get("ip") or item.get("ipv6") or item.get("address") or item.get("addr"))
            ips = normalize_ipv6_list([ip])
            if mac and ips:
                out.append({
                    "mac": mac,
                    "ip": ips[0],
                    "state": clean_saved_value(item.get("state")) or "LEASED",
                    "dev": clean_saved_value(item.get("dev") or item.get("iface") or item.get("ifname")) or "dhcpv6",
                    "seenAt": clean_saved_value(item.get("seenAt") or item.get("collectedAt")) or now_str(),
                    "source": "dhcpv6_lease",
                })

    # 去重：同一个 MAC + IPv6 只保留一次。
    dedup: Dict[str, Dict[str, Any]] = {}
    for n in out:
        key = f"{norm_mac(n.get('mac'))}|{clean_saved_value(n.get('ip'))}"
        if key.strip("|"):
            dedup[key] = n
    return list(dedup.values())


def merge_ipv6_neighbors_to_archive(neighbors: List[Dict[str, Any]], current_prefixes: Optional[List[str]] = None) -> int:
    if not neighbors:
        return 0
    current_prefixes = current_prefixes or []
    archive = load_device_archive()
    changed = 0
    nas_macs = configured_nas_macs()
    local_records = local_hub_ipv6_records()
    local_lan_ipv4 = get_local_lan_ipv4()
    for n in neighbors:
        mac = norm_mac(n.get("mac"))
        ip = clean_saved_value(n.get("ip"))
        if not mac or not ip:
            continue
        old = archive.get(mac, {})
        is_nas = mac in nas_macs or bool(
            local_lan_ipv4 and clean_saved_value(old.get("ip") or old.get("lastIp")) == local_lan_ipv4
        )
        old_records = normalize_ipv6_records(old.get("ipv6Records") or old.get("ipv6List") or [], current_prefixes)
        by_ip = {r.get("ip"): r for r in old_records if r.get("ip")}

        source = clean_saved_value(n.get("source")) or "router_ndp"
        if is_nas:
            # Router NDP for the Hub/NAS is only cross-check data. The Hub's
            # own local probe has higher authority and must not be overwritten.
            source = "router_ndp_crosscheck"
        seen_at = clean_saved_value(n.get("seenAt")) or now_str()
        rec = by_ip.get(ip, {"ip": ip, "firstSeen": seen_at})
        rec["lastSeen"] = seen_at
        rec["source"] = source
        rec["state"] = clean_saved_value(n.get("state"))
        rec["dev"] = clean_saved_value(n.get("dev"))
        rec["currentPrefix"] = ipv6_in_prefixes(ip, current_prefixes)
        rec["temporary"] = is_temporary_ipv6(ip, source)
        rec["primary"] = False
        if rec["state"].upper() in ["REACHABLE", "DELAY", "PROBE", "LEASED"]:
            rec["lastReachable"] = seen_at
        rec["historical"] = bool(current_prefixes and not rec["currentPrefix"] and not is_ula_ipv6(ip))
        by_ip[ip] = rec

        if is_nas:
            for local_rec in local_records:
                local_ip = local_rec.get("ip")
                if local_ip:
                    existing = by_ip.get(local_ip, {"ip": local_ip, "firstSeen": local_rec.get("firstSeen")})
                    existing.update(local_rec)
                    by_ip[local_ip] = existing

        # Re-evaluate existing records after a router mode/prefix change. Old
        # GUA from the previous prefix stays as history, but no longer wins.
        merged_records = normalize_ipv6_records(list(by_ip.values()), current_prefixes)
        best = pick_primary_ipv6(merged_records)
        for record in merged_records:
            record["primary"] = bool(best and record.get("ip") == best)
        ipv6_list = [best] + [r["ip"] for r in sorted(merged_records, key=score_ipv6_record, reverse=True) if r.get("ip") != best]
        ipv6_list = normalize_ipv6_list(ipv6_list)
        if merged_records != old.get("ipv6Records") or ipv6_list != old.get("ipv6List") or best != old.get("ipv6"):
            old["ipv6Records"] = merged_records
            old["ipv6List"] = ipv6_list
            if best:
                old["ipv6"] = best
                old["ipv6Address"] = best
                old["globalIpv6"] = best
            old["ipv6UpdatedAt"] = now_str()
            changed += 1
        old["mac"] = mac
        old["ndpState"] = n.get("state")
        old["ndpDev"] = n.get("dev")
        old["archivedAt"] = now_str()
        archive[mac] = old
    save_device_archive(archive)
    return changed


def attach_hub_local_ipv6_to_nas_devices(devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach Hub-host IPv6 as the authoritative primary on the NAS device."""
    if not devices:
        return devices
    local_records = local_hub_ipv6_records()
    if not local_records:
        return devices
    nas_macs = configured_nas_macs()
    local_lan_ipv4 = get_local_lan_ipv4()
    state = load_json(STATE_FILE, {})
    current_prefixes = normalize_ipv6_prefixes((state.get("router") or {}).get("lanIpv6Prefixes") or [])
    archive = load_device_archive()

    for dev in devices:
        mac = norm_mac(dev.get("mac"))
        is_nas = mac in nas_macs or bool(local_lan_ipv4 and clean_saved_value(dev.get("ip")) == local_lan_ipv4)
        if not is_nas:
            continue
        old = archive.get(mac, {}) if mac else {}
        records = normalize_ipv6_records(
            dev.get("ipv6Records") or old.get("ipv6Records") or dev.get("ipv6List") or old.get("ipv6List") or [],
            current_prefixes,
        )
        by_ip = {r.get("ip"): r for r in records if r.get("ip")}
        for local_rec in local_records:
            local_ip = local_rec.get("ip")
            if not local_ip:
                continue
            existing = by_ip.get(local_ip, {"ip": local_ip, "firstSeen": local_rec.get("firstSeen")})
            existing.update(local_rec)
            by_ip[local_ip] = existing
        merged = normalize_ipv6_records(list(by_ip.values()), current_prefixes)
        best = pick_primary_ipv6(merged)
        for record in merged:
            record["primary"] = bool(best and record.get("ip") == best)
        ordered = [best] + [r["ip"] for r in sorted(merged, key=score_ipv6_record, reverse=True) if r.get("ip") != best]
        dev["ipv6Records"] = merged
        dev["ipv6List"] = normalize_ipv6_list(ordered)
        if best:
            dev["ipv6"] = best
            dev["ipv6Address"] = best
            dev["globalIpv6"] = best
            dev["ipv6UpdatedAt"] = now_str()
    return devices


def parse_ruijie_devices(payload: Any) -> Tuple[List[Dict[str, Any]], int]:
    if isinstance(payload, str):
        payload = json.loads(payload)
    raw_list = payload.get("list", []) if isinstance(payload, dict) else []
    devices: List[Dict[str, Any]] = []
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        mac = norm_mac(item.get("mac"))
        if not mac:
            continue
        traffic = normalize_device_traffic(item)
        today_online_sec = today_online_seconds_from_item(item)
        device = {
            "name": prefer_name(item),
            "mac": mac,
            "online": True,
            "ip": item.get("userIp"),
            "ipv6List": normalize_ipv6_list(item.get("ipv6") or item.get("ipv6List") or item.get("userIpv6") or item.get("userIPv6") or []),
            "connectType": item.get("connectType"),
            "ssid": item.get("ssid"),
            "band": item.get("band"),
            "rssi": item.get("rssi"),
            "rxrate": item.get("rxrate"),
            "channel": item.get("channel"),
            "onlinetime": item.get("onlinetime"),
            "onlineSince": item.get("onlinetime"),
            "activeTimeSec": to_int(item.get("activeTime"), 0),
            "onlineDurationText": human_duration(item.get("activeTime")),
            "todayOnlineDurationSec": today_online_sec,
            "todayOnlineDurationText": human_duration(today_online_sec),
            "todayOnlineDate": today_str(),
            "lastSeenAt": now_str(),
            "hostName": item.get("hostName"),
            "manufacture": item.get("manufacture"),
            "osType": item.get("osType"),
            "devType": item.get("devType"),
            "devRecommend": item.get("devRecommend"),
            "deviceAliasName": item.get("deviceAliasName"),
            "trafficText": f"↑{human_bytes(traffic.get('totalUpload'))} ↓{human_bytes(traffic.get('totalDownload'))}",
            "raw": item,
        }
        device.update(traffic)
        devices.append(device)
    total = to_int(payload.get("total"), len(devices)) if isinstance(payload, dict) else len(devices)
    return devices, total


def build_watched_devices(online_devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    watched = cfg_get("watched_devices", []) or []
    by_mac = {norm_mac(d.get("mac")): d for d in online_devices}
    result: List[Dict[str, Any]] = []
    previous_state = load_json(DEVICES_FILE, {})
    previous = previous_state.get("watched", [])
    previous_by_mac = {norm_mac(d.get("mac")): d for d in previous}
    archive = load_device_archive()
    now = now_str()

    for w in watched:
        wmac = norm_mac(w.get("mac"))
        # 历史归档作为底座，devices.json 当前状态作为覆盖。避免离线半小时后锐捷快照缺字段导致 APP 丢失最后 IP / 信号。
        old = merge_non_empty(archive.get(wmac, {}), previous_by_mac.get(wmac, {}))
        match = by_mac.get(wmac)
        old_online = old.get("online")

        if match:
            dev = dict(match)
            dev.update({
                "name": w.get("name") or match.get("name"),
                "online": True,
                "lastSeenAt": now,
                "offlineAt": None,
                "onlineSince": match.get("onlineSince") or old.get("onlineSince") or now,
                "onlineDurationText": match.get("onlineDurationText") or human_duration(match.get("activeTimeSec")),
                "lastChangedAt": old.get("lastChangedAt") or now,
            })
            archive_device_snapshot(dev)
            if old_online is not None and old_online is False:
                dev["lastChangedAt"] = now
                add_event({
                    "type": "device_online",
                    "title": f"{dev.get('name')} 上线",
                    "name": dev.get("name"),
                    "mac": wmac,
                    "oldValue": "offline",
                    "newValue": "online",
                    "ip": dev.get("ip"),
                    "rssi": dev.get("rssi"),
                    "band": dev.get("band"),
                    "rxrate": dev.get("rxrate"),
                    "ssid": dev.get("ssid"),
                    "connectType": dev.get("connectType"),
                    "onlineSince": dev.get("onlineSince"),
                    "onlineDurationText": "0分",
                    "device": {k: dev.get(k) for k in ["name", "mac", "ip", "rssi", "band", "rxrate", "ssid", "connectType", "onlineSince", "hostName", "devType"]},
                })
        else:
            was_online = bool(old.get("online")) if old_online is not None else False
            offline_at = now if was_online else old.get("offlineAt")
            dev = {
                "name": w.get("name") or old.get("name") or wmac,
                "mac": wmac,
                "online": False,
                "ip": None,
                "lastIp": old.get("ip") or old.get("lastIp"),
                "ssid": old.get("ssid"),
                "band": old.get("band"),
                "rssi": old.get("rssi"),
                "rxrate": old.get("rxrate"),
                "onlineSince": old.get("onlineSince"),
                "onlineDurationText": old.get("onlineDurationText"),
                "lastSeenAt": old.get("lastSeenAt"),
                "offlineAt": offline_at,
                "lastChangedAt": now if was_online else old.get("lastChangedAt") or now,
            }
            dev = hydrate_device_with_archive(dev, archive)
            archive_device_snapshot(dev)
            if was_online:
                duration_text = duration_between(old.get("onlineSince"), offline_at) or old.get("onlineDurationText") or ""
                add_event({
                    "type": "device_offline",
                    "title": f"{dev.get('name')} 离线",
                    "name": dev.get("name"),
                    "mac": wmac,
                    "oldValue": "online",
                    "newValue": "offline",
                    "ip": old.get("ip") or old.get("lastIp"),
                    "lastIp": old.get("ip") or old.get("lastIp"),
                    "rssi": old.get("rssi"),
                    "band": old.get("band"),
                    "rxrate": old.get("rxrate"),
                    "ssid": old.get("ssid"),
                    "connectType": old.get("connectType"),
                    "onlineSince": old.get("onlineSince"),
                    "offlineAt": offline_at,
                    "onlineDurationText": duration_text,
                    "device": {k: old.get(k) for k in ["name", "mac", "ip", "rssi", "band", "rxrate", "ssid", "connectType", "onlineSince", "hostName", "devType"]},
                })
        result.append(dev)
    return result



def device_snapshot_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize ruijie agent device_event payload into the same field names used by /api/devices."""
    mac = norm_mac(payload.get("mac"))
    name = payload.get("name") or payload.get("devRecommend") or payload.get("hostName") or mac or "未知设备"
    ip = payload.get("ip") or payload.get("userIp") or payload.get("lastIp") or ""
    rssi = payload.get("rssi") or ""
    band = payload.get("band") or ""
    rxrate = payload.get("rxrate") or payload.get("rate") or ""
    ssid = payload.get("ssid") or ""
    connect_type = payload.get("connectType") or payload.get("connect_type") or ""
    now = payload.get("time") or now_str()
    online_since = payload.get("onlineSince") or payload.get("onlinetime") or payload.get("startTime") or now
    offline_at = payload.get("offlineAt") or (now if str(payload.get("type", "")).endswith("offline") else "")
    duration_text = payload.get("onlineDurationText") or ""
    duration_sec = payload.get("onlineDurationSec") or payload.get("durationSec") or ""
    if not duration_text and duration_sec not in [None, ""]:
        duration_text = human_duration_precise(duration_sec)
    if not duration_text and offline_at:
        duration_text = duration_between(online_since, offline_at)
    snapshot = {
        "name": str(name),
        "mac": mac,
        "ip": str(ip) if ip else "",
        "lastIp": str(ip) if ip else "",
        "rssi": str(rssi) if rssi else "",
        "band": str(band) if band else "",
        "rxrate": str(rxrate) if rxrate else "",
        "ssid": str(ssid) if ssid else "",
        "connectType": str(connect_type) if connect_type else "",
        "onlineSince": str(online_since) if online_since else "",
        "offlineAt": str(offline_at) if offline_at else "",
        "onlineDurationText": str(duration_text) if duration_text else "",
        "lastSeenAt": str(payload.get("lastSeenAt") or now),
        "hostName": str(payload.get("hostName") or ""),
        "devType": str(payload.get("devType") or ""),
        "raw": payload,
    }
    snapshot.update(normalize_device_traffic(payload))
    return snapshot


def upsert_watched_device_from_event(snapshot: Dict[str, Any], online: bool, event_time: str) -> None:
    devices_state = load_json(DEVICES_FILE, {"online": [], "watched": [], "updatedAt": None})
    watched = devices_state.get("watched", []) or []
    mac = norm_mac(snapshot.get("mac"))
    archive = load_device_archive()
    found = False
    next_watched = []
    for d in watched:
        if norm_mac(d.get("mac")) == mac:
            nd = merge_non_empty(archive.get(mac, {}), d)
            nd.update({k: v for k, v in snapshot.items() if clean_saved_value(v)})
            nd["online"] = online
            nd["lastChangedAt"] = event_time
            if online:
                nd["ip"] = snapshot.get("ip") or snapshot.get("lastIp") or d.get("ip")
                nd["offlineAt"] = None
                nd["onlineSince"] = snapshot.get("onlineSince") or event_time
                nd["lastSeenAt"] = event_time
            else:
                nd["lastIp"] = snapshot.get("lastIp") or snapshot.get("ip") or d.get("ip") or d.get("lastIp") or archive.get(mac, {}).get("lastIp")
                nd["ip"] = None
                nd["offlineAt"] = snapshot.get("offlineAt") or event_time
                nd["lastSeenAt"] = snapshot.get("lastSeenAt") or d.get("lastSeenAt") or event_time
                nd = hydrate_device_with_archive(nd, archive)
            archive_device_snapshot(nd)
            next_watched.append(nd)
            found = True
        else:
            next_watched.append(d)
    if not found and mac:
        nd = dict(snapshot)
        nd["online"] = online
        nd["lastChangedAt"] = event_time
        if online:
            nd["offlineAt"] = None
            nd["onlineSince"] = snapshot.get("onlineSince") or event_time
        else:
            nd["ip"] = None
            nd["offlineAt"] = snapshot.get("offlineAt") or event_time
            nd = hydrate_device_with_archive(nd, archive)
        archive_device_snapshot(nd)
        next_watched.append(nd)
    devices_state["watched"] = next_watched
    devices_state["updatedAt"] = now_str()
    save_json(DEVICES_FILE, devices_state)

    state = load_json(STATE_FILE, {})
    state["devices"] = next_watched
    state["updatedAt"] = now_str()
    save_json(STATE_FILE, state)


def get_exit_ip(ipv6: bool = False) -> Optional[str]:
    # NAS 出口地址只能由 Hub/NAS 自己获取或手动配置，绝不从 router_wan6 兜底。
    # 优先级：手动配置 > curl 外网出口 > 本机全局地址。
    manual = get_manual_nas_ip(ipv6)
    if manual:
        return manual

    cfg_url = cfg_get("exit_ip.ipv6_url" if ipv6 else "exit_ip.ipv4_url", None)
    urls = []
    if cfg_url:
        urls.append(cfg_url)
    if ipv6:
        urls += ["https://api6.ipify.org", "https://api64.ipify.org", "https://ipv6.icanhazip.com", "https://v6.ident.me", "https://6.ipw.cn"]
    else:
        urls += ["https://api.ipify.org", "https://ipv4.icanhazip.com", "https://v4.ident.me", "https://4.ipw.cn"]
    seen = set()
    for url in urls:
        if not url or url in seen:
            continue
        seen.add(url)
        cmd = ["curl", "-6" if ipv6 else "-4", "-s", "--max-time", "6", url]
        try:
            out = strip_ip_prefix(subprocess.check_output(cmd, text=True, timeout=8))
            if out and is_public_ip_text(out, ipv6=ipv6):
                return out
        except Exception:
            pass

    local_ip = get_local_global_ip(ipv6)
    if local_ip:
        return local_ip
    return None


def resolve_records(domain: str, record_type: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=4)
        return [str(a).rstrip(".") for a in answers]
    except Exception:
        return []


def refresh_ddns_and_exit(state: Dict[str, Any]) -> Dict[str, Any]:
    nas_ipv4 = get_exit_ip(False)
    nas_ipv6 = get_exit_ip(True)
    state.setdefault("nas", {})

    # v0.7.6：NAS IPv4 / IPv6 只由 Hub/NAS 自己获取或手动配置。
    # 检测失败时保留旧值，不清空，避免 APP 里 NAS IPv6 / WireGuard 突然消失。
    nas_update = {"updatedAt": now_str()}
    if nas_ipv4:
        nas_update["exitIpv4"] = nas_ipv4
        nas_update["exitIpv4Source"] = "manual_or_hub"
    else:
        nas_update["exitIpv4LastError"] = "detect_failed_keep_previous"
    if nas_ipv6:
        nas_update["exitIpv6"] = nas_ipv6
        nas_update["localIpv6List"] = normalize_ipv6_list([nas_ipv6])
        nas_update["exitIpv6Source"] = "manual_or_hub"
    else:
        nas_update["exitIpv6LastError"] = "detect_failed_keep_previous"
    state["nas"].update(nas_update)

    # 路由器 WAN6 由路由脚本推送；只保留 router.*，不参与 NAS 字段。
    state.setdefault("router", {})
    state["router"].setdefault("exitIpv4", None)
    state["router"].setdefault("exitIpv6", state["router"].get("wanIpv6"))

    ddns_cfg = cfg_get("ddns", []) or []
    ddns_list = []
    for item in ddns_cfg:
        domain = item.get("domain")
        if not domain:
            continue
        a = resolve_records(domain, "A") if "A" in (item.get("record_types") or ["A", "AAAA"]) else []
        aaaa = resolve_records(domain, "AAAA") if "AAAA" in (item.get("record_types") or ["A", "AAAA"]) else []
        expect = item.get("expect")
        expected_value = None
        if expect == "nas_ipv6":
            expected_value = nas_ipv6
        elif expect == "nas_ipv4":
            expected_value = nas_ipv4
        elif expect == "router_ipv6":
            expected_value = state.get("router", {}).get("exitIpv6")
        elif expect == "router_ipv4":
            expected_value = state.get("router", {}).get("exitIpv4")
        matched = None
        if expected_value:
            matched = expected_value in a or expected_value in aaaa
        ddns_list.append({
            "name": item.get("name") or domain,
            "domain": domain,
            "a": a,
            "aaaa": aaaa,
            "expect": expect,
            "expectedValue": expected_value,
            "matched": matched,
            "updatedAt": now_str(),
        })
    state["ddnsResolved"] = ddns_list
    return state


def check_push_token() -> bool:
    token = request.headers.get("X-LabProbe-Token", "").strip()
    if token and token in {get_hook_token(), get_app_token()}:
        return True
    return check_hook_token()


@app.route("/api/router/push", methods=["POST"])
def api_router_push():
    # 极简路由脚本入口：路由器只 POST snapshot / device_event，Hub 负责保存和去重。
    if not check_push_token():
        return jsonify({"ok": False, "error": "bad token"}), 401
    payload = request.get_json(silent=True) or {}
    typ = str(payload.get("type") or "snapshot").strip()
    ts = payload.get("ts")
    event_time = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S") if ts else now_str()

    if typ == "snapshot":
        state = load_json(STATE_FILE, {})
        state.setdefault("router", {})
        state.setdefault("nas", {})
        router_name = clean_saved_value(payload.get("router")) or cfg_get("router.name", "Ruijie")
        wan_items = normalize_ipv6_items(
            payload.get("wan_ipv6_list") or payload.get("wanIpv6List") or payload.get("router_wan6_list") or payload.get("routerWan6List") or payload.get("wan6List"),
            "WAN IPv6",
        )
        has_new_ipv6_snapshot = any(k in payload for k in ["ipv6_mode", "ipv6Mode", "wan_ipv6_list", "wanIpv6List", "lan_ipv6_prefixes", "lanIpv6Prefixes"])
        router_items = normalize_ipv6_items(payload.get("router_ipv6_list") or payload.get("routerIpv6List"), "Router IPv6")
        lan_items = normalize_ipv6_items(payload.get("lan_ipv6_list") or payload.get("lanIpv6List"), "LAN IPv6")
        lan_prefixes = normalize_ipv6_prefixes(payload.get("lan_ipv6_prefixes") or payload.get("lanIpv6Prefixes"))
        router_wan6 = (
            clean_saved_value(payload.get("router_wan6") or payload.get("routerWanIpv6") or payload.get("wanIpv6"))
            or next((x.get("ip") for x in wan_items if x.get("primary")), "")
            or (wan_items[0].get("ip") if wan_items else "")
            or ("" if has_new_ipv6_snapshot else state.get("router", {}).get("wanIpv6"))
        )

        # v0.7.4：路由器脚本只允许更新“路由 WAN6”类字段。
        # 注意：wan_ipv4 / wan_ipv6 是路由器侧外网探测结果，不能写入 nas.exitIpv4/exitIpv6，
        # 否则会把 NAS IPv6 错显示成路由 WAN6。
        router_update = {
            "name": router_name,
            "lanIp": clean_saved_value(payload.get("lan_ip")),
            "ipv6Mode": clean_saved_value(payload.get("ipv6_mode") or payload.get("ipv6Mode")) or "unknown",
            "ipv6DefaultIf": clean_saved_value(payload.get("ipv6_default_if") or payload.get("ipv6DefaultIf")),
            "wanIpv6": router_wan6,
            "routerUpdatedAt": event_time,
            "routerStatus": "ok",
        }
        if router_items or ("router_ipv6_list" in payload or "routerIpv6List" in payload):
            router_update["routerIpv6List"] = router_items
        if wan_items or ("wan_ipv6_list" in payload or "wanIpv6List" in payload):
            router_update["wanIpv6List"] = wan_items
            router_update["wan6List"] = [{"name": x.get("name"), "ip": x.get("ip"), "primary": x.get("primary")} for x in wan_items]
        if lan_items or ("lan_ipv6_list" in payload or "lanIpv6List" in payload):
            router_update["lanIpv6List"] = lan_items
        if lan_prefixes or ("lan_ipv6_prefixes" in payload or "lanIpv6Prefixes" in payload):
            router_update["lanIpv6Prefixes"] = lan_prefixes
        wan6_list = payload.get("router_wan6_list") or payload.get("routerWan6List") or payload.get("wan6List")
        if isinstance(wan6_list, list) and not wan_items:
            cleaned = []
            seen = set()
            for i, item in enumerate(wan6_list):
                if not isinstance(item, dict):
                    continue
                ip = clean_saved_value(item.get("ip") or item.get("address") or item.get("value"))
                if not ip or ip in seen:
                    continue
                seen.add(ip)
                name = clean_saved_value(item.get("name")) or ("主用 WAN" if item.get("primary") or i == 0 else "备用 WAN")
                cleaned.append({"name": name, "ip": ip, "primary": bool(item.get("primary") or (not cleaned and ip == router_wan6))})
            if cleaned:
                if not any(x.get("primary") for x in cleaned):
                    cleaned[0]["primary"] = True
                router_update["wan6List"] = cleaned
        state["router"].update(router_update)

        # v0.7.7：路由脚本可附带 IPv6 邻居表；Hub 只按 MAC 合并到设备归档。
        neighbors = parse_ipv6_neighbors(payload)
        ipv6_changed = merge_ipv6_neighbors_to_archive(neighbors, lan_prefixes or state.get("router", {}).get("lanIpv6Prefixes") or [])
        if neighbors:
            devices_state = load_json(DEVICES_FILE, {"online": [], "watched": [], "updatedAt": None})
            archive = load_device_archive()
            devices_state["online"] = [hydrate_device_with_archive(d, archive) for d in (devices_state.get("online") or [])]
            devices_state["watched"] = [hydrate_device_with_archive(d, archive) for d in (devices_state.get("watched") or [])]
            devices_state["updatedAt"] = event_time
            save_json(DEVICES_FILE, devices_state)

        # v0.7.5：/api/router/push 只允许更新 router.*。
        # NAS IPv4 / NAS IPv6 是 Hub/NAS 本机出口，不能由路由脚本清空，也不能因为和路由 WAN6 相同就隐藏。
        # 某些桥接场景下 NAS 出口 IPv6 与路由 WAN6 可能相同，这仍然是有效的 NAS IPv6。

        state["updatedAt"] = event_time
        save_json(STATE_FILE, state)

        nas_state = state.get("nas") if isinstance(state.get("nas"), dict) else {}
        if not clean_saved_value(nas_state.get("exitIpv4")) or not clean_saved_value(nas_state.get("exitIpv6")):
            try:
                trigger_status_refresh_if_needed(state, force=True)
            except Exception:
                pass

        return jsonify({"ok": True, "message": "snapshot saved", "ipv6NeighborCount": len(neighbors), "ipv6Changed": ipv6_changed, "time": now_str()})

    if typ in ["device_event", "device"]:
        event_name = clean_saved_value(payload.get("event"))
        mapped = "device_online" if event_name == "online" else "device_offline" if event_name == "offline" else event_name
        if mapped not in ["device_online", "device_offline"]:
            return jsonify({"ok": False, "error": "event must be online/offline"}), 400
        fake_payload = dict(payload)
        fake_payload["type"] = mapped
        fake_payload["time"] = event_time
        fake_payload["lastIp"] = payload.get("ip")
        # 复用同一套设备事件逻辑。
        with app.test_request_context(json=fake_payload, headers={"X-LabProbe-Token": request.headers.get("X-LabProbe-Token", "")}):
            # 不能直接复用 token 校验上下文，改为内联最小保存逻辑。
            pass
        snap = device_snapshot_from_payload(fake_payload)
        online = mapped == "device_online"
        name = snap.get("name") or snap.get("mac") or "未知设备"
        event = {
            "type": mapped, "source": "router_push", "title": f"{name} {'上线' if online else '离线'}",
            "name": name, "mac": snap.get("mac"), "time": event_time, "createdAt": event_time,
            "ip": snap.get("ip") if online else (snap.get("lastIp") or snap.get("ip")),
            "lastIp": snap.get("lastIp") or snap.get("ip"),
            "rssi": snap.get("rssi"), "band": snap.get("band"), "rxrate": snap.get("rxrate"), "ssid": snap.get("ssid"),
            "onlineSince": snap.get("onlineSince"), "offlineAt": snap.get("offlineAt") or (event_time if not online else ""),
            "onlineDurationText": snap.get("onlineDurationText"), "oldValue": "offline" if online else "online", "newValue": "online" if online else "offline",
            "device": snap,
        }
        if not online and not event.get("onlineDurationText"):
            event["onlineDurationText"] = duration_between(event.get("onlineSince"), event.get("offlineAt"))
        events = load_json(EVENTS_FILE, [])
        last = next((e for e in reversed(events) if norm_mac(e.get("mac")) == norm_mac(event.get("mac")) and e.get("type") == event.get("type")), None)
        if last:
            lt = parse_time_safe(last.get("createdAt") or last.get("time")); nt = parse_time_safe(event_time)
            if lt and nt and abs((nt - lt).total_seconds()) <= 300 and mapped == "device_offline":
                upsert_watched_device_from_event(snap, online, event_time)
                return jsonify({"ok": True, "dedup": True, "message": "duplicate offline ignored", "time": now_str()})
        saved = add_event(event)
        upsert_watched_device_from_event(snap, online, event_time)
        return jsonify({"ok": True, "message": "device event saved", "event": saved, "time": now_str()})

    return jsonify({"ok": False, "error": "unknown type"}), 400


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "name": "LabProbe Hub", "version": APP_VERSION, "time": now_str()})


@app.route("/hook/lucky", methods=["POST", "GET"])
def hook_lucky():
    """Lucky Webhook：兼容简单钉钉文本格式。

    推荐 Lucky 请求体：
    {
      "msgtype": "text",
      "text": {"content": "Lucky：#{ipAddr}"}
    }

    其中 #{ipAddr} 已经是 Lucky 输出的公网地址+端口，Hub 不拆分，原样保存；content 冒号前缀作为 APP 显示名，例如 OpenVPN：#{ipAddr}。
    """
    if not check_hook_token():
        return jsonify({"ok": False, "error": "bad hook token"}), 401

    if request.is_json:
        payload = request.get_json(silent=True) or {}
    else:
        payload = dict(request.form) or dict(request.args)

    def clean_addr(v: Any) -> str:
        text = str(v or "").strip()
        if not text:
            return ""
        bad = ["null", "none", "-", "#{", "{STUN_", "token=", "Bearer "]
        low = text.lower()
        if any(b.lower() in low for b in bad):
            return ""
        return text

    def parse_lucky_content(text: str) -> Tuple[str, str]:
        raw = str(text or "").strip().replace("\r", " ").replace("\n", " ")
        if not raw:
            return "Lucky", ""
        # 兼容：Lucky：公网地址:端口 / Lucky:公网地址:端口
        m = re.search(r"^\s*([^:：]{1,32})\s*[:：]\s*(.+?)\s*$", raw)
        if m:
            return (m.group(1).strip() or "Lucky"), clean_addr(m.group(2))
        # 没有前缀时也接受整段，方便手动测试。
        return "Lucky", clean_addr(raw)

    # 兼容钉钉文本格式：{"msgtype":"text","text":{"content":"Lucky：#{ipAddr}"}}
    text_obj = payload.get("text") if isinstance(payload, dict) else None
    text_content = ""
    if isinstance(text_obj, dict):
        text_content = str(text_obj.get("content") or "")
    elif isinstance(payload.get("content"), str):
        text_content = str(payload.get("content") or "")

    parsed_name, parsed_addr = parse_lucky_content(text_content)

    event_type = str(payload.get("type") or "lucky_webhook")
    name = str(payload.get("name") or parsed_name or "Lucky")
    address = clean_addr(
        payload.get("address")
        or payload.get("ipAddr")
        or payload.get("newValue")
        or payload.get("value")
        or parsed_addr
    )

    # 只收到 URL token 的空 webhook 属于测试粘贴错误，不记录事件。
    if not address:
        safe_payload = {k: v for k, v in payload.items() if str(k).lower() not in ["token", "password", "secret"]}
        return jsonify({
            "ok": True,
            "ignored": True,
            "reason": "empty or invalid lucky address",
            "received": safe_payload,
            "time": now_str(),
        })

    state = load_json(STATE_FILE, {})
    state["updatedAt"] = now_str()

    # 简单稳定：#{ipAddr} 已经是完整公网地址+端口，不拆 ip / port，按 content 前缀作为服务名保存。
    service = str(payload.get("service") or name or "Lucky").strip() or "Lucky"
    item, old = upsert_vpn_address(service, address, "Lucky Webhook")
    service_key = vpn_service_key(service)

    state.setdefault("vpn", {})
    state["vpn"][service_key] = item
    # /api/status 直接返回动态列表，APP 首页不再只认 WireGuard。
    state["vpnStunAddresses"] = vpn_addresses_list(state)

    # 只有真正的 Lucky/STUN 推送才写入 luckyStun / stun 兼容字段。
    if service_key in ["lucky", "lucky_stun", "stun"] or "lucky" in service_key or "stun" in service_key:
        state["luckyStun"] = item
        state["stun"] = {"name": service, "publicAddress": address, "address": address, "source": "Lucky Webhook", "updatedAt": now_str()}

    if address != old:
        add_event({
            "type": "stun_changed",
            "title": f"{service} STUN 地址变化",
            "name": service,
            "oldValue": old,
            "newValue": address,
            "source": "lucky",
            "content": text_content,
        })

    save_json(STATE_FILE, state)
    return jsonify({
        "ok": True,
        "message": "lucky address saved",
        "name": service,
        "address": address,
        "time": now_str(),
    })

@app.route("/hook/ruijie/devices", methods=["POST"])
def hook_ruijie_devices():
    if not check_hook_token():
        return jsonify({"ok": False, "error": "bad hook token"}), 401
    raw = request.get_data(as_text=True)
    try:
        payload = json.loads(raw)
        online, total = parse_ruijie_devices(payload)
        online = update_daily_online_durations(online)
        merge_ipv6_neighbors_to_archive(parse_ipv6_neighbors(payload))
        archive = load_device_archive()
        online = [hydrate_device_with_archive(dev, archive) for dev in online]
        online = attach_hub_local_ipv6_to_nas_devices(online)
        for dev in online:
            archive_device_snapshot(dev)
    except Exception as e:
        return jsonify({"ok": False, "error": f"parse failed: {e}"}), 400

    watched = build_watched_devices(online)
    devices_state = {
        "source": "ruijie_push",
        "updatedAt": now_str(),
        "onlineDeviceCount": len(online),
        "total": total,
        "online": online,
        "watched": watched,
    }
    save_json(DEVICES_FILE, devices_state)

    state = load_json(STATE_FILE, {})
    state.setdefault("router", {})
    state["router"].update({
        "name": cfg_get("router.name", "Ruijie"),
        "mode": "push",
        "onlineDeviceCount": len(online),
        "total": total,
        "devicesUpdatedAt": now_str(),
    })
    state["devices"] = watched
    state["updatedAt"] = now_str()
    save_json(STATE_FILE, state)

    return jsonify({"ok": True, "message": "ruijie devices saved", "onlineDeviceCount": len(online), "watchedCount": len(watched), "time": now_str()})



@app.route("/hook/ruijie/device_event", methods=["POST"])
def hook_ruijie_device_event():
    if not check_hook_token():
        return jsonify({"ok": False, "error": "bad hook token"}), 401
    payload = request.get_json(silent=True) or {}
    if not payload:
        return jsonify({"ok": False, "error": "empty json"}), 400
    typ = str(payload.get("type") or "").strip()
    if typ not in ["device_online", "device_offline"]:
        return jsonify({"ok": False, "error": "type must be device_online/device_offline"}), 400

    event_time = str(payload.get("time") or now_str())
    snap = device_snapshot_from_payload(payload)
    name = snap.get("name") or payload.get("name") or snap.get("mac") or "未知设备"
    online = typ == "device_online"

    # 事件由锐捷 Agent 主动上报，字段优先级高于 Hub 的快照推断。
    event = {
        "type": typ,
        "source": "ruijie_agent",
        "title": f"{name} {'上线' if online else '离线'}",
        "name": name,
        "mac": snap.get("mac"),
        "time": event_time,
        "createdAt": event_time,
        "ip": snap.get("ip") if online else (snap.get("lastIp") or snap.get("ip")),
        "lastIp": snap.get("lastIp") or snap.get("ip"),
        "rssi": snap.get("rssi"),
        "band": snap.get("band"),
        "rxrate": snap.get("rxrate"),
        "ssid": snap.get("ssid"),
        "connectType": snap.get("connectType"),
        "onlineSince": snap.get("onlineSince"),
        "offlineAt": snap.get("offlineAt") or (event_time if not online else ""),
        "onlineDurationText": snap.get("onlineDurationText"),
        "oldValue": "offline" if online else "online",
        "newValue": "online" if online else "offline",
        "device": snap,
    }
    if not online and not event.get("onlineDurationText"):
        event["onlineDurationText"] = duration_between(event.get("onlineSince"), event.get("offlineAt"))

    # 简单去重：同一 MAC 同类型 10 秒内不重复保存。
    events = load_json(EVENTS_FILE, [])
    if events:
        last = events[-1]
        if norm_mac(last.get("mac")) == norm_mac(event.get("mac")) and last.get("type") == event.get("type"):
            lt = parse_time_safe(last.get("createdAt") or last.get("time"))
            nt = parse_time_safe(event_time)
            if lt and nt and abs((nt - lt).total_seconds()) <= 10:
                upsert_watched_device_from_event(snap, online, event_time)
                return jsonify({"ok": True, "dedup": True, "message": "duplicate device event ignored", "time": now_str()})

    saved = add_event(event)
    upsert_watched_device_from_event(snap, online, event_time)
    return jsonify({"ok": True, "message": "device event saved", "event": saved, "time": now_str()})


@app.route("/hook/ruijie/router", methods=["POST", "GET"])
def hook_ruijie_router():
    if not check_hook_token():
        return jsonify({"ok": False, "error": "bad hook token"}), 401

    payload: Dict[str, Any] = {}
    raw = request.get_data(as_text=True) or ""
    if request.is_json:
        payload = request.get_json(silent=True) or {}
    elif request.args:
        payload = dict(request.args)

    wan_if = payload.get("wanIf") or payload.get("interface") or "pppoe-wan"
    wan_v6 = payload.get("routerWanIpv6") or payload.get("wanIpv6") or payload.get("ipv6")
    if not wan_v6:
        wan_v6 = extract_public_ipv6(raw or json.dumps(payload, ensure_ascii=False))

    state = load_json(STATE_FILE, {})
    state.setdefault("router", {})
    old = state["router"].get("wanIpv6")
    state["router"]["wanIf"] = wan_if
    state["router"]["routerLastCheckAt"] = now_str()

    if wan_v6 and is_public_ipv6(str(wan_v6)):
        state["router"].update({
            "name": cfg_get("router.name", "Ruijie"),
            "wanIpv6": wan_v6,
            "exitIpv6": wan_v6,
            "routerUpdatedAt": now_str(),
            "routerStatus": "ok",
        })
        state["updatedAt"] = now_str()
        save_json(STATE_FILE, state)
        if old and old != wan_v6:
            add_event({
                "type": "router_wan_ipv6_changed",
                "title": "路由 WAN IPv6 变化",
                "name": wan_if,
                "oldValue": old,
                "newValue": wan_v6,
            })
        return jsonify({"ok": True, "message": "router status saved", "wanIpv6": wan_v6, "wanIf": wan_if, "time": now_str()})

    # 空值或非公网地址不覆盖旧值，避免 APP 首页忽隐忽现。
    state["router"]["routerStatus"] = "check_failed"
    state["router"]["routerLastError"] = "no public IPv6 found" if not wan_v6 else f"not public IPv6: {wan_v6}"
    state["updatedAt"] = now_str()
    save_json(STATE_FILE, state)
    return jsonify({"ok": True, "message": "router check failed, keep previous value", "wanIpv6": old, "wanIf": wan_if, "time": now_str(), "status": "stale"})


def _refresh_status_cache_worker(force: bool = False) -> None:
    global REFRESH_RUNNING
    with REFRESH_LOCK:
        if REFRESH_RUNNING:
            return
        REFRESH_RUNNING = True
    try:
        state = load_json(STATE_FILE, {})
        # 慢任务放后台：公网出口 curl、DDNS 解析、事件修复，不阻塞 /api/status。
        state = refresh_ddns_and_exit(state)
        state = ensure_vpn_addresses_from_events(state)
        state.setdefault("hub", {})
        state["hub"].update({"backgroundRefreshedAt": now_str()})
        state["updatedAt"] = now_str()
        save_json(STATE_FILE, state)
    except Exception as e:
        print(f"[LabProbe] background refresh failed: {e}", flush=True)
    finally:
        with REFRESH_LOCK:
            REFRESH_RUNNING = False


def trigger_status_refresh_if_needed(state: Dict[str, Any], force: bool = False) -> None:
    hub = state.get("hub") if isinstance(state.get("hub"), dict) else {}
    nas = state.get("nas") if isinstance(state.get("nas"), dict) else {}
    last = time_to_epoch(hub.get("backgroundRefreshedAt") or state.get("updatedAt"))
    missing_nas_exit = not clean_saved_value(nas.get("exitIpv4")) or not clean_saved_value(nas.get("exitIpv6"))
    stale = force or missing_nas_exit or not last or (time.time() - last > STATUS_REFRESH_TTL_SEC)
    if stale:
        threading.Thread(target=_refresh_status_cache_worker, kwargs={"force": force or missing_nas_exit}, daemon=True).start()



# ---------------------------------------------------------------------------
# LabRelay / Port Mapping (Hub v0.8.3)
# APP manages structured rules; router agent polls commands with HOOK_TOKEN.
# No endpoint accepts arbitrary shell commands and Hub never edits firewall.
# ---------------------------------------------------------------------------

def _portmap_router_name() -> str:
    # Use a stable agent identifier, not router.name (which is a display label and
    # may contain spaces such as "Ruijie BE72"). The router installer defaults to
    # BE72Pro, so both sides work without changing existing display-name config.
    return (
        clean_saved_value(os.environ.get("PORTMAP_ROUTER_NAME"))
        or clean_saved_value(cfg_get("router.portmap_id", ""))
        or clean_saved_value(cfg_get("router.agent_name", ""))
        or "BE72Pro"
    )


def _portmap_rule_id(value: Any = None) -> str:
    raw = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(value or "").strip()).strip("-").lower()
    return raw[:48] or f"pm-{int(time.time())}-{secrets.token_hex(3)}"


def _normalize_ipv6_suffix(value: Any) -> str:
    text = clean_saved_value(value).lower().strip("[]")
    if not text:
        return ""
    candidate = text if "::" in text else "::" + text.lstrip(":")
    addr = ipaddress.ip_address(candidate)
    if addr.version != 6:
        raise ValueError("IPv6 后缀无效")
    iid = int(addr) & ((1 << 64) - 1)
    if iid == 0:
        raise ValueError("IPv6 后缀不能全部为 0")
    return str(ipaddress.IPv6Address(iid))


def _portmap_epoch(value: Any) -> Optional[int]:
    if value in [None, "", 0, "0"]:
        return None
    try:
        n = int(float(str(value)))
        if n > 10_000_000_000:
            n //= 1000
        return n if n > 0 else None
    except Exception:
        return None


def _portmap_time_epoch(value: Any) -> Optional[int]:
    raw = clean_saved_value(value)
    if not raw:
        return None
    try:
        return int(datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").timestamp())
    except Exception:
        return None


def _portmap_lease_seconds(src: Dict[str, Any], old: Dict[str, Any], expires_at: Optional[int]) -> int:
    """Return the repeatable duration for a timed rule.

    leaseSeconds is persisted independently from expiresAt so an expired rule can
    be started again with its previous duration. Legacy v0.8.2 rules are migrated
    by deriving the original duration from createdAt/updatedAt when possible.
    """
    raw = src.get("leaseSeconds", old.get("leaseSeconds"))
    lease = max(0, min(7 * 86400, to_int(raw, 0)))
    if lease > 0 or expires_at is None:
        return lease

    base = _portmap_time_epoch(old.get("createdAt") or src.get("createdAt"))
    if base and expires_at > base:
        return max(60, min(7 * 86400, expires_at - base))

    updated = _portmap_time_epoch(old.get("updatedAt") or src.get("updatedAt"))
    if updated and expires_at > updated:
        return max(60, min(7 * 86400, expires_at - updated))
    return 0


def _clean_portmap_rule(payload: Dict[str, Any], existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    old = existing or {}
    src = {**old, **(payload or {})}
    rule_id = _portmap_rule_id(src.get("id") or old.get("id"))
    mode = clean_saved_value(src.get("mode") or "6to4").lower()
    if mode not in ["6to4", "6to6"]:
        raise ValueError("映射类型只能是 6to4 或 6to6")
    listen_port = to_int(src.get("listenPort"), 0)
    target_port = to_int(src.get("targetPort"), 0)
    if not 20000 <= listen_port <= 20020:
        raise ValueError("监听端口必须在 20000-20020")
    if not 1 <= target_port <= 65535:
        raise ValueError("目标端口无效")
    name = clean_saved_value(src.get("name"))[:64]
    if not name:
        raise ValueError("规则名称不能为空")

    target_mode = clean_saved_value(src.get("targetMode")).lower()
    target_ipv4 = clean_saved_value(src.get("targetIpv4"))
    target_ipv6 = clean_saved_value(src.get("targetIpv6")).strip("[]")
    target_suffix = clean_saved_value(src.get("targetIpv6Suffix")).lower()
    target_mac = norm_mac(src.get("targetMac"))
    if target_mac and not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", target_mac):
        raise ValueError("目标 MAC 格式无效")
    if mode == "6to4":
        target_mode = "ipv4"
        ip = ipaddress.ip_address(target_ipv4)
        if ip.version != 4 or not (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise ValueError("6to4 目标必须是内网 IPv4")
        target_ipv6 = ""
        target_suffix = ""
    else:
        if target_mode not in ["ipv6_full", "ipv6_suffix"]:
            target_mode = "ipv6_suffix"
        target_ipv4 = ""
        if target_mode == "ipv6_full":
            ip = ipaddress.ip_address(target_ipv6)
            if ip.version != 6 or ip.is_link_local or ip.is_multicast or ip.is_loopback or ip.is_unspecified:
                raise ValueError("目标 IPv6 无效")
            target_ipv6 = str(ip)
            target_suffix = ""
        else:
            target_suffix = _normalize_ipv6_suffix(target_suffix)
            target_ipv6 = ""
            if not target_suffix:
                raise ValueError("请输入目标 IPv6 后缀")

    max_connections = max(1, min(256, to_int(src.get("maxConnections"), 32) or 32))
    idle_timeout = max(30, min(3600, to_int(src.get("idleTimeoutSec"), 300) or 300))
    expires_at = _portmap_epoch(src.get("expiresAt"))
    lease_seconds = _portmap_lease_seconds(src, old, expires_at)
    if expires_at is None:
        lease_seconds = 0
    now = now_str()
    return {
        "id": rule_id,
        "name": name,
        "enabled": bool(src.get("enabled", False)),
        "mode": mode,
        "listenPort": listen_port,
        "targetMode": target_mode,
        "targetIpv4": target_ipv4,
        "targetIpv6": target_ipv6,
        "targetIpv6Suffix": target_suffix,
        "targetMac": target_mac,
        "targetPort": target_port,
        "preferCurrentPrefix": bool(src.get("preferCurrentPrefix", True)),
        "expiresAt": expires_at,
        "leaseSeconds": lease_seconds,
        "maxConnections": max_connections,
        "idleTimeoutSec": idle_timeout,
        "createdAt": old.get("createdAt") or now,
        "updatedAt": now,
    }


def _load_portmap_rules() -> List[Dict[str, Any]]:
    raw = load_json(PORTMAP_RULES_FILE, {"rules": []})
    rows = raw.get("rules", []) if isinstance(raw, dict) else raw if isinstance(raw, list) else []
    return [x for x in rows if isinstance(x, dict) and clean_saved_value(x.get("id"))]


def _save_portmap_rules(rows: List[Dict[str, Any]]) -> None:
    rows = sorted(rows[-100:], key=lambda x: (to_int(x.get("listenPort"), 0), clean_saved_value(x.get("name"))))
    save_json(PORTMAP_RULES_FILE, {"version": 1, "updatedAt": now_str(), "rules": rows})


def _portmap_check_conflict(rows: List[Dict[str, Any]], rule: Dict[str, Any]) -> None:
    for item in rows:
        if item.get("id") != rule.get("id") and to_int(item.get("listenPort"), 0) == to_int(rule.get("listenPort"), 0):
            raise ValueError(f"监听端口 {rule.get('listenPort')} 已被规则 {item.get('name')} 使用")


def _portmap_command_rule_id(action: str, payload: Dict[str, Any]) -> str:
    if action == "upsert" and isinstance(payload.get("rule"), dict):
        return clean_saved_value(payload.get("rule", {}).get("id"))
    return clean_saved_value(payload.get("id"))


def _queue_portmap_command(action: str, payload: Dict[str, Any], router: Optional[str] = None) -> Dict[str, Any]:
    data = load_json(PORTMAP_COMMANDS_FILE, {"commands": []})
    commands = data.get("commands", []) if isinstance(data, dict) else []
    now_epoch = int(time.time())
    commands = [c for c in commands if isinstance(c, dict) and not (
        c.get("status") in ["done", "failed"] and now_epoch - to_int(c.get("finishedEpoch"), now_epoch) > 86400
    )][-500:]
    target_router = router or _portmap_router_name()
    rule_id = _portmap_command_rule_id(action, payload)
    for existing in reversed(commands):
        if existing.get("router") != target_router or existing.get("status") not in ["pending", "delivered"]:
            continue
        if existing.get("action") == action and _portmap_command_rule_id(action, existing.get("payload") or {}) == rule_id:
            existing["payload"] = payload
            existing["status"] = "pending"
            existing["updatedAt"] = now_str()
            save_json(PORTMAP_COMMANDS_FILE, {"commands": commands})
            return existing
    command = {
        "id": f"cmd-{int(time.time() * 1000)}-{secrets.token_hex(3)}",
        "router": target_router,
        "action": action,
        "payload": payload,
        "status": "pending",
        "attempts": 0,
        "createdAt": now_str(),
        "createdEpoch": now_epoch,
    }
    commands.append(command)
    save_json(PORTMAP_COMMANDS_FILE, {"commands": commands})
    return command


def _portmap_runtime_map(router_status: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    status = router_status.get("status") if isinstance(router_status.get("status"), dict) else router_status
    for row in status.get("rules", []) if isinstance(status, dict) else []:
        if not isinstance(row, dict):
            continue
        runtime = row.get("runtime") if isinstance(row.get("runtime"), dict) else {}
        rule = row.get("rule") if isinstance(row.get("rule"), dict) else {}
        rid = clean_saved_value(runtime.get("id") or rule.get("id"))
        if rid:
            out[rid] = runtime
    return out


def _append_portmap_history(status_payload: Dict[str, Any]) -> None:
    history = load_json(PORTMAP_HISTORY_FILE, {})
    if not isinstance(history, dict):
        history = {}
    now_epoch = int(time.time())
    status = status_payload.get("status") if isinstance(status_payload.get("status"), dict) else status_payload
    changed = False
    for row in status.get("rules", []) if isinstance(status, dict) else []:
        if not isinstance(row, dict):
            continue
        runtime = row.get("runtime") if isinstance(row.get("runtime"), dict) else {}
        rid = clean_saved_value(runtime.get("id") or (row.get("rule") or {}).get("id"))
        if not rid:
            continue
        samples = history.get(rid, []) if isinstance(history.get(rid), list) else []
        if samples and now_epoch - to_int(samples[-1].get("time"), 0) < 60:
            continue
        samples.append({
            "time": now_epoch,
            "activeConnections": to_int(runtime.get("activeConnections"), 0),
            "uploadBytes": to_int(runtime.get("totalUploadBytes"), 0),
            "downloadBytes": to_int(runtime.get("totalDownloadBytes"), 0),
            "state": clean_saved_value(runtime.get("state")),
        })
        history[rid] = samples[-1440:]
        changed = True
    if changed:
        save_json(PORTMAP_HISTORY_FILE, history)


@app.route("/api/portmaps", methods=["GET", "POST"])
def api_portmaps():
    if request.method == "GET":
        if not check_read_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        rules = _load_portmap_rules()
        router_status = load_json(PORTMAP_ROUTER_STATUS_FILE, {})
        runtime = _portmap_runtime_map(router_status)
        rows = [{**r, "runtime": runtime.get(r.get("id"), {})} for r in rules]
        received_epoch = to_int(router_status.get("receivedEpoch"), 0) if isinstance(router_status, dict) else 0
        agent_online = bool(received_epoch and time.time() - received_epoch <= 35)
        return jsonify({
            "ok": True,
            "rules": rows,
            "portRange": {"min": 20000, "max": 20020},
            "router": router_status.get("router", _portmap_router_name()) if isinstance(router_status, dict) else _portmap_router_name(),
            "agentOnline": agent_online,
            "agentLastSeenAt": router_status.get("receivedAt", "") if isinstance(router_status, dict) else "",
        })

    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    try:
        payload = request.get_json(silent=True) or {}
        rule = _clean_portmap_rule(payload)
        rows = _load_portmap_rules()
        _portmap_check_conflict(rows, rule)
        rows.append(rule)
        _save_portmap_rules(rows)
        _queue_portmap_command("upsert", {"rule": rule})
        add_event({"type": "portmap_created", "title": f"端口映射已创建：{rule['name']}", "name": rule["name"], "newValue": f"IPv6:{rule['listenPort']}"})
        return jsonify({"ok": True, "rule": rule}), 201
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/portmaps/<rule_id>", methods=["PUT", "DELETE"])
def api_portmap_item(rule_id: str):
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    rows = _load_portmap_rules()
    old = next((x for x in rows if x.get("id") == rule_id), None)
    if not old:
        return jsonify({"ok": False, "error": "rule not found"}), 404
    if request.method == "DELETE":
        _save_portmap_rules([x for x in rows if x.get("id") != rule_id])
        _queue_portmap_command("delete", {"id": rule_id})
        add_event({"type": "portmap_deleted", "title": f"端口映射已删除：{old.get('name')}", "name": old.get("name"), "oldValue": str(old.get("listenPort"))})
        return jsonify({"ok": True, "deleted": True, "id": rule_id})
    try:
        payload = request.get_json(silent=True) or {}
        payload["id"] = rule_id
        rule = _clean_portmap_rule(payload, old)
        _portmap_check_conflict(rows, rule)
        rows = [rule if x.get("id") == rule_id else x for x in rows]
        _save_portmap_rules(rows)
        _queue_portmap_command("upsert", {"rule": rule})
        return jsonify({"ok": True, "rule": rule})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/portmaps/<rule_id>/<action>", methods=["POST"])
def api_portmap_action(rule_id: str, action: str):
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    if action not in ["start", "stop"]:
        return jsonify({"ok": False, "error": "invalid action"}), 400
    rows = _load_portmap_rules()
    rule = next((x for x in rows if x.get("id") == rule_id), None)
    if not rule:
        return jsonify({"ok": False, "error": "rule not found"}), 404
    rule = dict(rule)
    rule["enabled"] = action == "start"
    if action == "start":
        expires_at = _portmap_epoch(rule.get("expiresAt"))
        lease_seconds = max(0, to_int(rule.get("leaseSeconds"), 0))
        now_epoch = int(time.time())
        # A timed rule that has already expired starts a fresh lease using the
        # exact duration selected last time. A manually stopped rule that has
        # not expired keeps its remaining time.
        if expires_at is not None and expires_at <= now_epoch:
            if lease_seconds <= 0:
                return jsonify({"ok": False, "error": "旧规则缺少有效期时长，请编辑并重新选择有效期"}), 400
            rule["expiresAt"] = now_epoch + lease_seconds
    rule["updatedAt"] = now_str()
    rows = [rule if x.get("id") == rule_id else x for x in rows]
    _save_portmap_rules(rows)
    _queue_portmap_command("upsert" if action == "start" else "stop", {"rule": rule} if action == "start" else {"id": rule_id})
    return jsonify({"ok": True, "rule": rule, "action": action})


@app.route("/api/portmaps/<rule_id>/history", methods=["GET"])
def api_portmap_history(rule_id: str):
    if not check_read_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    minutes = max(5, min(1440, to_int(request.args.get("minutes"), 60) or 60))
    cutoff = int(time.time()) - minutes * 60
    history = load_json(PORTMAP_HISTORY_FILE, {})
    samples = history.get(rule_id, []) if isinstance(history, dict) and isinstance(history.get(rule_id), list) else []
    return jsonify({"ok": True, "id": rule_id, "minutes": minutes, "samples": [x for x in samples if to_int(x.get("time"), 0) >= cutoff]})


@app.route("/api/router/portmaps/commands", methods=["GET"])
def api_router_portmap_commands():
    if not check_hook_token():
        return jsonify({"ok": False, "error": "bad hook token"}), 401
    router = clean_saved_value(request.args.get("router")) or _portmap_router_name()
    limit = max(1, min(50, to_int(request.args.get("limit"), 20) or 20))
    data = load_json(PORTMAP_COMMANDS_FILE, {"commands": []})
    commands = data.get("commands", []) if isinstance(data, dict) else []
    now_epoch = int(time.time())
    selected = []
    changed = False
    for command in commands:
        if not isinstance(command, dict) or command.get("router") != router:
            continue
        retry_due = command.get("status") == "delivered" and now_epoch - to_int(command.get("deliveredEpoch"), 0) >= 15 and to_int(command.get("attempts"), 0) < 5
        if command.get("status") == "pending" or retry_due:
            command["status"] = "delivered"
            command["deliveredAt"] = now_str()
            command["deliveredEpoch"] = now_epoch
            command["attempts"] = to_int(command.get("attempts"), 0) + 1
            selected.append({k: command.get(k) for k in ["id", "action", "payload", "createdAt"]})
            changed = True
            if len(selected) >= limit:
                break
    if changed:
        save_json(PORTMAP_COMMANDS_FILE, {"commands": commands})
    return jsonify({"ok": True, "commands": selected, "time": now_str()})


@app.route("/api/router/portmaps/ack", methods=["POST"])
def api_router_portmap_ack():
    if not check_hook_token():
        return jsonify({"ok": False, "error": "bad hook token"}), 401
    payload = request.get_json(silent=True) or {}
    acks = payload.get("acks", []) if isinstance(payload.get("acks"), list) else []
    data = load_json(PORTMAP_COMMANDS_FILE, {"commands": []})
    commands = data.get("commands", []) if isinstance(data, dict) else []
    ack_map = {clean_saved_value(x.get("id")): x for x in acks if isinstance(x, dict)}
    changed = 0
    for command in commands:
        ack = ack_map.get(clean_saved_value(command.get("id")))
        if not ack:
            continue
        command["status"] = "done" if bool(ack.get("ok")) else "failed"
        command["result"] = ack.get("result")
        command["finishedAt"] = now_str()
        command["finishedEpoch"] = int(time.time())
        changed += 1
    if changed:
        save_json(PORTMAP_COMMANDS_FILE, {"commands": commands})
    return jsonify({"ok": True, "acknowledged": changed})


@app.route("/api/router/portmaps/status", methods=["POST"])
def api_router_portmap_status():
    if not check_hook_token():
        return jsonify({"ok": False, "error": "bad hook token"}), 401
    payload = request.get_json(silent=True) or {}
    router = clean_saved_value(request.args.get("router")) or _portmap_router_name()
    record = {
        "router": router,
        "receivedAt": now_str(),
        "receivedEpoch": int(time.time()),
        "status": payload,
    }
    save_json(PORTMAP_ROUTER_STATUS_FILE, record)
    _append_portmap_history(record)

    # Reconcile Hub desired rules with router-local rules. This recovers from a
    # replaced binary/config or router reset without requiring APP to edit each rule.
    desired = {clean_saved_value(x.get("id")): x for x in _load_portmap_rules() if clean_saved_value(x.get("id"))}
    local_rows = payload.get("rules", []) if isinstance(payload.get("rules"), list) else []
    local = {}
    for row in local_rows:
        if not isinstance(row, dict):
            continue
        local_rule = row.get("rule") if isinstance(row.get("rule"), dict) else {}
        rid = clean_saved_value(local_rule.get("id") or (row.get("runtime") or {}).get("id"))
        if rid:
            local[rid] = local_rule
    compare_keys = ["enabled", "mode", "listenPort", "targetMode", "targetIpv4", "targetIpv6", "targetIpv6Suffix", "targetMac", "targetPort", "expiresAt", "leaseSeconds", "maxConnections", "idleTimeoutSec"]
    for rid, rule in desired.items():
        local_rule = local.get(rid)
        if not local_rule or any(local_rule.get(k) != rule.get(k) for k in compare_keys):
            _queue_portmap_command("upsert", {"rule": rule}, router)
    for rid in set(local) - set(desired):
        _queue_portmap_command("delete", {"id": rid}, router)

    return jsonify({"ok": True, "receivedAt": record["receivedAt"]})


@app.route("/api/status", methods=["GET"])
def api_status():
    if not check_read_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    state = load_json(STATE_FILE, {})
    force = request.args.get("refresh", "") in ["1", "true", "yes"]
    # v0.7.3：状态接口只返回缓存，避免外网 curl / DNS 卡住导致 APP 显示“连通但刷新不了”。
    trigger_status_refresh_if_needed(state, force=force)
    state["hub"] = {
        **(state.get("hub") if isinstance(state.get("hub"), dict) else {}),
        "name": "LabProbe Hub",
        "version": APP_VERSION,
        "updatedAt": now_str(),
        "statusMode": "cache_first",
        "refreshRunning": REFRESH_RUNNING,
    }
    state["vpnStunAddresses"] = vpn_addresses_list(state)
    state["vpnAddresses"] = state["vpnStunAddresses"]
    devices_state = load_json(DEVICES_FILE, {"updatedAt": None})
    state["devicesUpdatedAt"] = devices_state.get("updatedAt")
    return jsonify({"ok": True, "data": state})


@app.route("/api/status/refresh", methods=["POST", "GET"])
def api_status_refresh():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    threading.Thread(target=_refresh_status_cache_worker, kwargs={"force": True}, daemon=True).start()
    return jsonify({"ok": True, "message": "refresh started", "time": now_str()})


def build_magic_packet(mac: str) -> bytes:
    parts = bytes(int(x, 16) for x in norm_mac(mac).split(":"))
    if len(parts) != 6:
        raise ValueError("invalid mac")
    return b"\xff" * 6 + parts * 16


@app.route("/api/wol", methods=["POST"])
def api_wol():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    mac = norm_mac(payload.get("mac"))
    if not mac:
        return jsonify({"ok": False, "error": "invalid mac"}), 400
    port = to_int(payload.get("port"), 9) or 9
    packet = build_magic_packet(mac)
    targets = cfg_get("wol.broadcasts", []) or ["255.255.255.255"]
    if isinstance(targets, str):
        targets = [targets]
    sent = 0
    errors: List[str] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1.5)
        for host in targets:
            for p in [port, 9, 7]:
                try:
                    sock.sendto(packet, (str(host), int(p)))
                    sent += 1
                except Exception as e:
                    errors.append(f"{host}:{p} {e}")
    finally:
        sock.close()
    if sent <= 0:
        return jsonify({"ok": False, "error": "; ".join(errors[-3:]) or "send failed"}), 500
    add_event({"type": "wol_sent", "title": "WOL 唤醒", "name": mac, "newValue": f"sent {sent}", "mac": mac})
    return jsonify({"ok": True, "message": f"Hub 已发送 WOL · {sent} 个广播包", "mac": mac, "sent": sent, "time": now_str()})


@app.route("/api/devices", methods=["GET"])
def api_devices():
    if not check_read_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    devices = load_json(DEVICES_FILE, {"online": [], "watched": [], "updatedAt": None})
    view = request.args.get("view", "watched")
    key = view if view in ["online", "watched"] else "watched"
    archive = load_device_archive()
    items = [hydrate_device_with_archive(d, archive) for d in (devices.get(key, []) or [])]
    # v0.7.8：online / watched 都在返回前按 MAC 合并 IPv6 邻居归档，避免 Router Agent 已上报但 APP 仍显示 --。
    archive = load_device_archive()
    ipv6_neighbor_count = sum(1 for _, a in archive.items() if normalize_ipv6_list(a.get("ipv6List") or []))
    return jsonify({
        "ok": True,
        "updatedAt": devices.get("updatedAt"),
        "devices": items,
        "onlineDeviceCount": devices.get("onlineDeviceCount", 0),
        "ipv6Hydrated": True,
        "ipv6NeighborCount": ipv6_neighbor_count,
    })


@app.route("/api/ipv6-neighbors", methods=["GET"])
def api_ipv6_neighbors():
    if not check_read_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    archive = load_device_archive()
    rows = []
    for mac, item in archive.items():
        ipv6_list = normalize_ipv6_list(item.get("ipv6List") or [])
        if ipv6_list:
            rows.append({
                "mac": mac,
                "ipv6List": ipv6_list,
                "ipv6UpdatedAt": item.get("ipv6UpdatedAt", ""),
                "ndpState": item.get("ndpState", ""),
                "ndpDev": item.get("ndpDev", ""),
                "name": item.get("name", ""),
                "ip": item.get("ip") or item.get("lastIp") or "",
            })
    return jsonify({"ok": True, "count": len(rows), "neighbors": rows})


@app.route("/api/events", methods=["GET"])
def api_events():
    if not check_read_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    after = int(request.args.get("after", "0"))
    events = load_json(EVENTS_FILE, [])
    return jsonify({"ok": True, "events": [e for e in events if int(e.get("id", 0)) > after and not e.get("deleted")]})


@app.route("/api/events/<int:event_id>", methods=["DELETE"])
def api_delete_event(event_id: int):
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    events = load_json(EVENTS_FILE, [])
    changed = False
    for e in events:
        if int(e.get("id", 0)) == event_id:
            e["deleted"] = True
            e["deletedAt"] = now_str()
            changed = True
            break
    save_json(EVENTS_FILE, events)
    return jsonify({"ok": True, "deleted": changed, "id": event_id})


@app.route("/api/geo", methods=["GET"])
def api_geo():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "missing ip"}), 400
    return jsonify({"ok": True, "geo": lookup_geo(ip)})



def event_timestamp(e: Dict[str, Any]) -> str:
    return str(e.get("createdAt") or e.get("time") or e.get("offlineAt") or e.get("onlineSince") or "")


def note_file(day: str) -> Path:
    safe = re.sub(r"[^0-9-]", "", day or today_str()) or today_str()
    return NOTES_DIR / f"{safe}.json"


def get_daily_note(day: str) -> str:
    return str(load_json(note_file(day), {}).get("note", "") or "")


def set_daily_note(day: str, note: str) -> None:
    save_json(note_file(day), {"date": day, "note": note or "", "updatedAt": now_str()})


def pretty_duration_text(text: str) -> str:
    s = str(text or "").strip()
    if not s or s in {"-", "null", "None"}:
        return ""
    m = re.match(r"^(\d+)分(\d+)秒$", s)
    if m:
        total_min = int(m.group(1)); sec = int(m.group(2))
        h, mm = divmod(total_min, 60)
        return (f"{h}小时" if h else "") + (f"{mm}分" if mm or not h else "") + f"{sec}秒"
    m = re.match(r"^(\d+)分$", s)
    if m:
        total_min = int(m.group(1)); h, mm = divmod(total_min, 60)
        return f"{h}小时{mm}分" if h else f"{mm}分"
    return s.replace("时", "小时")


def duration_text_to_seconds(text: str) -> int:
    s = str(text or "").strip().replace("时", "小时")
    if not s or s in {"-", "null", "None"}:
        return 0
    total = 0
    m = re.search(r"(\d+)小时", s)
    if m:
        total += int(m.group(1)) * 3600
    m = re.search(r"(\d+)分", s)
    if m:
        total += int(m.group(1)) * 60
    m = re.search(r"(\d+)秒", s)
    if m:
        total += int(m.group(1))
    return total



def event_device_key(e: Dict[str, Any]) -> str:
    mac = norm_mac(e.get("mac"))
    if mac:
        return "mac:" + mac
    name = clean_saved_value(e.get("name") or str(e.get("title") or "").replace(" 上线", "").replace(" 离线", "")).lower()
    if name:
        return "name:" + name
    ip = clean_saved_value(e.get("ip") or e.get("lastIp"))
    return "ip:" + ip if ip else ""


def normalize_device_events_for_daily(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ordered = sorted(events, key=lambda e: (time_to_epoch(event_timestamp(e)) or 0, int(e.get("id", 0))))
    state: Dict[str, str] = {}
    online_at: Dict[str, float] = {}
    last_offline: Dict[str, float] = {}
    kept: List[Dict[str, Any]] = []
    for e in ordered:
        typ = str(e.get("type", ""))
        if typ not in ["device_online", "device_offline"]:
            kept.append(e); continue
        key = event_device_key(e)
        if not key:
            kept.append(e); continue
        at = time_to_epoch(event_timestamp(e))
        prev = state.get(key)
        if typ == "device_online":
            if prev == "online":
                continue
            state[key] = "online"
            if at:
                online_at[key] = at
            kept.append(e)
            continue
        # offline
        dur_sec = duration_text_to_seconds(pretty_duration_text(str(e.get("onlineDurationText") or "")))
        if dur_sec <= 0 and online_at.get(key) and at and at >= online_at[key]:
            dur_sec = int(at - online_at[key])
            e = dict(e)
            e["onlineDurationText"] = human_duration_precise(dur_sec)
        if dur_sec <= 0:
            continue
        if prev == "offline":
            continue
        if at and key in last_offline and 0 <= at - last_offline[key] <= 300:
            continue
        state[key] = "offline"
        if at:
            last_offline[key] = at
        online_at.pop(key, None)
        kept.append(e)
    return kept

def aggregate_daily(day: str) -> Dict[str, Any]:
    events = normalize_device_events_for_daily([e for e in load_json(EVENTS_FILE, []) if not e.get("deleted") and event_timestamp(e).startswith(day)])
    devices: Dict[str, Dict[str, Any]] = {}
    vpn_items: List[Dict[str, Any]] = []
    network_items: List[Dict[str, Any]] = []
    ddns_items: List[Dict[str, Any]] = []
    device_online_count = 0
    device_offline_count = 0

    for e in events:
        typ = str(e.get("type", ""))
        name = str(e.get("name") or e.get("title") or "未知")
        t = event_timestamp(e)[11:16] if len(event_timestamp(e)) >= 16 else ""
        new_value = str(e.get("newValue") or e.get("value") or e.get("address") or "").strip()
        title = str(e.get("title") or name or typ or "事件")

        if typ.startswith("device_"):
            dkey = event_device_key(e) or name
            d = devices.setdefault(dkey, {
                "name": name,
                "online": 0,
                "offline": 0,
                "onlineDurationSec": 0,
                "lastIp": "",
                "lastSignal": "",
            })
            if typ == "device_online":
                d["online"] += 1
                device_online_count += 1
            elif typ == "device_offline":
                d["offline"] += 1
                device_offline_count += 1

            ip = e.get("ip") or e.get("lastIp") or ""
            if ip:
                d["lastIp"] = ip
            rssi = str(e.get("rssi") or e.get("lastRssi") or "").strip()
            band = str(e.get("band") or e.get("lastBand") or "").strip()
            rxrate = str(e.get("rxrate") or e.get("lastRxrate") or "").strip()
            sig_parts = []
            if rssi and rssi not in ["-", "null", "None"]:
                sig_parts.append(rssi if rssi.endswith("dBm") else f"{rssi}dBm")
            if band and band not in ["-", "null", "None"]:
                sig_parts.append(band)
            if rxrate and rxrate not in ["-", "null", "None"]:
                sig_parts.append(rxrate)
            if sig_parts:
                d["lastSignal"] = " ".join(sig_parts)
            dur_text = pretty_duration_text(str(e.get("onlineDurationText") or ""))
            dur_sec = duration_text_to_seconds(dur_text)
            if dur_sec > 0:
                d["onlineDurationSec"] += dur_sec

        elif "stun" in typ or "wireguard" in typ or "vpn" in typ:
            service = str(e.get("name") or title).replace(" STUN 地址变化", "").replace("地址变化", "").strip() or "VPN/STUN"
            address = new_value
            vpn_items.append({
                "time": t,
                "name": service,
                "address": address,
                "text": f"{service} · {address}" if address else service,
            })

        elif "router" in typ or "wan" in typ or "nas" in typ or "network" in typ:
            service = str(e.get("name") or title).strip() or "网络变化"
            address = new_value or str(e.get("ip") or e.get("ipv6") or e.get("wanIpv6") or "").strip()
            network_items.append({
                "time": t,
                "name": service,
                "address": address,
                "text": f"{service} · {address}" if address else service,
            })

        elif "ddns" in typ:
            ddns_items.append({"time": t, "name": name, "text": f"{title} · {new_value}" if new_value else title})

    device_list = []
    for d in devices.values():
        duration = human_duration_precise(d.get("onlineDurationSec", 0))
        detail_parts = []
        if duration:
            detail_parts.append(f"在线 {duration}")
        if d.get("lastIp"):
            detail_parts.append(str(d["lastIp"]))
        if d.get("lastSignal"):
            detail_parts.append(str(d["lastSignal"]))
        line2 = f"上线 {d['online']} 次 · 下线 {d['offline']} 次"
        if detail_parts:
            line2 += " · " + " · ".join(detail_parts)
        device_list.append({
            "name": d["name"],
            "online": d["online"],
            "offline": d["offline"],
            "onlineDurationText": duration,
            "lastIp": d.get("lastIp", ""),
            "lastSignal": d.get("lastSignal", ""),
            "text": f"{d['name']}\n{line2}",
        })

    note = get_daily_note(day)
    summary = {
        "deviceChanges": device_online_count + device_offline_count,
        "deviceOnline": device_online_count,
        "deviceOffline": device_offline_count,
        "vpnChanges": len(vpn_items),
        "networkChanges": len(network_items),
        "ddnsChanges": len(ddns_items),
        "noteCount": 1 if note.strip() else 0,
        "eventCount": len(events),
    }
    sections = {"devices": device_list, "vpn": vpn_items, "network": network_items, "ddns": ddns_items}
    sections = {k: v for k, v in sections.items() if v}
    return {"date": day, "summary": summary, "sections": sections, "note": note}

def recent_dates(days: int = 7) -> List[str]:
    from datetime import timedelta
    today = date.today()
    return [(today - timedelta(days=i)).isoformat() for i in range(days)]



@app.route("/api/daily/note", methods=["GET", "PUT"])
def api_daily_note():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    day = request.args.get("date", today_str())
    if request.method == "GET":
        return jsonify({"ok": True, "date": day, "note": get_daily_note(day)})
    payload = request.get_json(silent=True) or {}
    note = str(payload.get("note", ""))[:2000]
    set_daily_note(day, note)
    return jsonify({"ok": True, "date": day, "note": note, "updatedAt": now_str()})


@app.route("/api/daily/latest", methods=["GET"])
def api_daily_latest():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return jsonify({"ok": True, "daily": aggregate_daily(today_str())})


@app.route("/api/daily", methods=["GET"])
def api_daily_by_date():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    day = request.args.get("date", today_str())
    return jsonify({"ok": True, "daily": aggregate_daily(day)})


@app.route("/api/daily/list", methods=["GET"])
def api_daily_list():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return jsonify({"ok": True, "dates": recent_dates(7)})


if __name__ == "__main__":
    print(f"[LabProbe] Hub v{APP_VERSION} starting on 0.0.0.0:{PORT}", flush=True)
    print(f"[LabProbe] config={CONFIG_PATH}, data={DATA_DIR}", flush=True)
    app.run(host="0.0.0.0", port=PORT)
