import os
import json
import socket
import subprocess
import ipaddress
import re
import time
import threading
from datetime import datetime, date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
import requests
import dns.resolver
from flask import Flask, request, jsonify

APP_VERSION = "0.7.6"
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
GEO_CACHE_FILE = DATA_DIR / "geo_cache.json"
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


def check_app_token() -> bool:
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    return token and token == get_app_token()


def check_hook_token() -> bool:
    return request.args.get("token", "") == get_hook_token()


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


def get_local_global_ip(ipv6: bool = False) -> str:
    # 低优先级兜底：在 host 网络模式下可从本机网卡读取 NAS IPv6。
    # Docker bridge 下可能读到容器地址，只有 public/global 才接受。
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
            # 避免优先拿 temporary，先放后面。
            score = 10 if "temporary" in line else 0
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
        "hostName", "devType", "osType", "manufacture", "devRecommend"
    ]
    snap = {k: dev.get(k) for k in keep_keys if k in dev}
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
    for k in ["name", "lastIp", "ssid", "band", "rssi", "rxrate", "channel", "connectType", "onlineSince", "onlineDurationText", "lastSeenAt", "hostName", "devType", "osType", "manufacture", "devRecommend"]:
        if not clean_saved_value(out.get(k)) and clean_saved_value(old.get(k)):
            out[k] = old.get(k)
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
        devices.append({
            "name": prefer_name(item),
            "mac": mac,
            "online": True,
            "ip": item.get("userIp"),
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
            "lastSeenAt": now_str(),
            "hostName": item.get("hostName"),
            "manufacture": item.get("manufacture"),
            "osType": item.get("osType"),
            "devType": item.get("devType"),
            "devRecommend": item.get("devRecommend"),
            "deviceAliasName": item.get("deviceAliasName"),
            "upBytes": to_int(item.get("up"), 0),
            "downBytes": to_int(item.get("down"), 0),
            "dailyUpBytes": to_int(item.get("dailyUp"), 0),
            "dailyDownBytes": to_int(item.get("dailyDown"), 0),
            "trafficText": f"↑{human_bytes(item.get('up'))} ↓{human_bytes(item.get('down'))}",
            "raw": item,
        })
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
    return {
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
        router_wan6 = clean_saved_value(payload.get("router_wan6") or payload.get("routerWanIpv6")) or state.get("router", {}).get("wanIpv6")

        # v0.7.4：路由器脚本只允许更新“路由 WAN6”类字段。
        # 注意：wan_ipv4 / wan_ipv6 是路由器侧外网探测结果，不能写入 nas.exitIpv4/exitIpv6，
        # 否则会把 NAS IPv6 错显示成路由 WAN6。
        router_update = {
            "name": router_name,
            "lanIp": clean_saved_value(payload.get("lan_ip")),
            "wanIpv6": router_wan6,
            "routerUpdatedAt": event_time,
            "routerStatus": "ok",
        }
        wan6_list = payload.get("router_wan6_list") or payload.get("routerWan6List") or payload.get("wan6List")
        if isinstance(wan6_list, list):
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

        return jsonify({"ok": True, "message": "snapshot saved", "time": now_str()})

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


@app.route("/api/status", methods=["GET"])
def api_status():
    if not check_app_token():
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


@app.route("/api/devices", methods=["GET"])
def api_devices():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    devices = load_json(DEVICES_FILE, {"online": [], "watched": [], "updatedAt": None})
    view = request.args.get("view", "watched")
    key = view if view in ["online", "watched"] else "watched"
    items = devices.get(key, [])
    if key == "watched":
        items = hydrate_watched_list(items)
    return jsonify({"ok": True, "updatedAt": devices.get("updatedAt"), "devices": items, "onlineDeviceCount": devices.get("onlineDeviceCount", 0)})


@app.route("/api/events", methods=["GET"])
def api_events():
    if not check_app_token():
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
