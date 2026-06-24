import os
import json
import socket
import subprocess
import ipaddress
import re
from datetime import datetime, date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
import requests
import dns.resolver
from flask import Flask, request, jsonify

APP_VERSION = "0.6.4"
PORT = int(os.environ.get("PORT", "58443"))
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/app/config/config.yaml"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

EVENTS_FILE = DATA_DIR / "events.json"
STATE_FILE = DATA_DIR / "state.json"
DEVICES_FILE = DATA_DIR / "devices.json"
DAILY_FILE = DATA_DIR / "daily.json"
GEO_CACHE_FILE = DATA_DIR / "geo_cache.json"

app = Flask(__name__)


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_str() -> str:
    return date.today().isoformat()


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


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
        return f"{h}时{m:02d}分"
    return f"{m}分"


def human_duration_precise(seconds: Any) -> str:
    sec = to_int(seconds, 0)
    if sec <= 0:
        return ""
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    if h > 0:
        return f"{h}时{m:02d}分{s:02d}秒"
    if m > 0:
        return f"{m}分{s:02d}秒"
    return f"{s}秒"


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
    now = now_str()

    for w in watched:
        wmac = norm_mac(w.get("mac"))
        old = previous_by_mac.get(wmac, {})
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
    found = False
    next_watched = []
    for d in watched:
        if norm_mac(d.get("mac")) == mac:
            nd = dict(d)
            nd.update({k: v for k, v in snapshot.items() if v not in [None, ""]})
            nd["online"] = online
            nd["lastChangedAt"] = event_time
            if online:
                nd["ip"] = snapshot.get("ip") or snapshot.get("lastIp") or d.get("ip")
                nd["offlineAt"] = None
                nd["onlineSince"] = snapshot.get("onlineSince") or event_time
                nd["lastSeenAt"] = event_time
            else:
                nd["lastIp"] = snapshot.get("lastIp") or snapshot.get("ip") or d.get("ip") or d.get("lastIp")
                nd["ip"] = None
                nd["offlineAt"] = snapshot.get("offlineAt") or event_time
                nd["lastSeenAt"] = snapshot.get("lastSeenAt") or d.get("lastSeenAt") or event_time
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
        next_watched.append(nd)
    devices_state["watched"] = next_watched
    devices_state["updatedAt"] = now_str()
    save_json(DEVICES_FILE, devices_state)

    state = load_json(STATE_FILE, {})
    state["devices"] = next_watched
    state["updatedAt"] = now_str()
    save_json(STATE_FILE, state)


def get_exit_ip(ipv6: bool = False) -> Optional[str]:
    # 多源检测 NAS 出口地址。Hub 跑在 NAS 上，所以这里得到的是 NAS 的出口 IPv4 / IPv6。
    cfg_url = cfg_get("exit_ip.ipv6_url" if ipv6 else "exit_ip.ipv4_url", None)
    urls = []
    if cfg_url:
        urls.append(cfg_url)
    if ipv6:
        urls += ["https://api6.ipify.org", "https://ipv6.icanhazip.com", "https://6.ipw.cn"]
    else:
        urls += ["https://api.ipify.org", "https://ipv4.icanhazip.com", "https://4.ipw.cn"]
    seen = set()
    for url in urls:
        if not url or url in seen:
            continue
        seen.add(url)
        cmd = ["curl", "-6" if ipv6 else "-4", "-s", "--max-time", "6", url]
        try:
            out = subprocess.check_output(cmd, text=True).strip()
            if out and len(out) < 80 and not out.lower().startswith("error"):
                return out
        except Exception:
            pass
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
    state["nas"].update({"exitIpv4": nas_ipv4, "exitIpv6": nas_ipv6, "updatedAt": now_str()})
    # 路由器 WAN IPv6 由 /hook/ruijie/router 推送；这里不再用 NAS 地址误填。
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


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "name": "LabProbe Hub", "version": APP_VERSION, "time": now_str()})


@app.route("/hook/lucky", methods=["POST", "GET"])
def hook_lucky():
    if not check_hook_token():
        return jsonify({"ok": False, "error": "bad hook token"}), 401
    if request.is_json:
        payload = request.get_json(silent=True) or {}
    else:
        payload = dict(request.form) or dict(request.args)
    event_type = payload.get("type", "lucky_webhook")
    address = payload.get("address") or payload.get("ipAddr") or payload.get("value")
    name = payload.get("name", "Lucky")
    # 只收到 URL token 的空 webhook 属于测试粘贴错误，不记录事件，避免泄露 token。
    if event_type == "lucky_webhook" and not address and set(payload.keys()).issubset({"token"}):
        return jsonify({"ok": True, "ignored": True, "reason": "empty webhook", "time": now_str()})
    state = load_json(STATE_FILE, {})
    state["updatedAt"] = now_str()
    if "stun" in event_type or "wireguard" in event_type:
        service = str(payload.get("service") or payload.get("name") or "stun").lower().replace(" ", "_")
        state.setdefault("vpn", {})
        old = state.get("vpn", {}).get(service, {}).get("address") or state.get("stun", {}).get("publicAddress")
        if address:
            state["vpn"][service] = {"address": address, "stun": address, "source": "Lucky Webhook", "updatedAt": now_str()}
            # 兼容旧 APP 字段
            state["stun"] = {"publicAddress": address, "source": "Lucky Webhook", "updatedAt": now_str()}
            if "wireguard" in service or "wg" in service:
                state["wireguard"] = {"publicAddress": address, "source": "Lucky Webhook", "updatedAt": now_str()}
        if address and address != old:
            add_event({"type": event_type, "title": f"{service} STUN 地址变化", "name": service, "oldValue": old, "newValue": address})
    elif "ddns" in event_type:
        domain = payload.get("domain") or name
        state.setdefault("ddns", {})
        old = state.get("ddns", {}).get(domain, {}).get("address")
        state["ddns"][domain] = {"domain": domain, "address": address, "source": "Lucky Webhook", "updatedAt": now_str()}
        if address and address != old:
            add_event({"type": event_type, "title": "DDNS 地址变化", "name": domain, "oldValue": old, "newValue": address})
    else:
        safe_payload = {k: v for k, v in payload.items() if k.lower() not in ["token", "password", "secret"]}
        if address or safe_payload:
            add_event({"type": event_type, "title": "Lucky Webhook", "name": name, "newValue": address or json.dumps(safe_payload, ensure_ascii=False)})
    save_json(STATE_FILE, state)
    return jsonify({"ok": True, "received": payload, "time": now_str()})


@app.route("/hook/ruijie/devices", methods=["POST"])
def hook_ruijie_devices():
    if not check_hook_token():
        return jsonify({"ok": False, "error": "bad hook token"}), 401
    raw = request.get_data(as_text=True)
    try:
        payload = json.loads(raw)
        online, total = parse_ruijie_devices(payload)
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


@app.route("/api/status", methods=["GET"])
def api_status():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    state = load_json(STATE_FILE, {})
    state = refresh_ddns_and_exit(state)
    state["hub"] = {"name": "LabProbe Hub", "version": APP_VERSION, "updatedAt": now_str()}
    state["updatedAt"] = now_str()
    save_json(STATE_FILE, state)
    return jsonify({"ok": True, "data": state})


@app.route("/api/devices", methods=["GET"])
def api_devices():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    devices = load_json(DEVICES_FILE, {"online": [], "watched": [], "updatedAt": None})
    view = request.args.get("view", "watched")
    return jsonify({"ok": True, "updatedAt": devices.get("updatedAt"), "devices": devices.get(view if view in ["online", "watched"] else "watched", []), "onlineDeviceCount": devices.get("onlineDeviceCount", 0)})


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


def aggregate_daily(day: str) -> Dict[str, Any]:
    events = [e for e in load_json(EVENTS_FILE, []) if not e.get("deleted") and event_timestamp(e).startswith(day)]
    devices: Dict[str, Dict[str, Any]] = {}
    vpn_items: List[Dict[str, Any]] = []
    network_items: List[Dict[str, Any]] = []
    ddns_items: List[Dict[str, Any]] = []
    for e in events:
        typ = str(e.get("type", ""))
        name = str(e.get("name") or e.get("title") or "未知")
        t = event_timestamp(e)[11:16] if len(event_timestamp(e)) >= 16 else ""
        if typ.startswith("device_"):
            d = devices.setdefault(name, {"name": name, "online": 0, "offline": 0, "onlineDurationText": "", "lastIp": "", "lastSignal": ""})
            if typ == "device_online":
                d["online"] += 1
                if e.get("ip"):
                    d["lastIp"] = e.get("ip")
                sig = " ".join([str(e.get("rssi") or ""), str(e.get("band") or ""), str(e.get("rxrate") or "")]).strip()
                if sig:
                    d["lastSignal"] = sig
            elif typ == "device_offline":
                d["offline"] += 1
                if e.get("onlineDurationText"):
                    d["onlineDurationText"] = e.get("onlineDurationText")
                if e.get("ip") or e.get("lastIp"):
                    d["lastIp"] = e.get("ip") or e.get("lastIp")
        elif "stun" in typ or "wireguard" in typ or "vpn" in typ:
            vpn_items.append({"time": t, "text": f"{e.get('title') or name} · {e.get('newValue','')}"})
        elif "router" in typ or "wan" in typ or "nas" in typ:
            network_items.append({"time": t, "text": f"{e.get('title') or name}"})
        elif "ddns" in typ:
            ddns_items.append({"time": t, "text": f"{e.get('title') or name}"})
    device_list = []
    for d in devices.values():
        parts = [f"上线 {d['online']} 次", f"下线 {d['offline']} 次"]
        if d.get("onlineDurationText"):
            parts.append(f"在线 {d['onlineDurationText']}")
        if d.get("lastIp"):
            parts.append(f"IP {d['lastIp']}")
        if d.get("lastSignal"):
            parts.append(d["lastSignal"])
        device_list.append({"text": f"{d['name']}：" + "，".join(parts)})
    summary = {
        "deviceChanges": sum(1 for e in events if str(e.get("type", "")).startswith("device_")),
        "vpnChanges": len(vpn_items),
        "networkChanges": len(network_items),
        "ddnsChanges": len(ddns_items),
        "eventCount": len(events),
    }
    sections = {"devices": device_list, "vpn": vpn_items, "network": network_items, "ddns": ddns_items}
    sections = {k: v for k, v in sections.items() if v}
    note = "今日暂无异常记录。" if not ddns_items else "今日存在 DDNS 相关变化，请按需检查。"
    return {"date": day, "summary": summary, "sections": sections, "note": note}


def recent_dates(days: int = 7) -> List[str]:
    from datetime import timedelta
    today = date.today()
    return [(today - timedelta(days=i)).isoformat() for i in range(days)]


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
