import os
import json
import socket
import subprocess
from datetime import datetime, date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
import requests
import dns.resolver
from flask import Flask, request, jsonify

APP_VERSION = "0.2.0"
PORT = int(os.environ.get("PORT", "58443"))
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/app/config/config.yaml"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

EVENTS_FILE = DATA_DIR / "events.json"
STATE_FILE = DATA_DIR / "state.json"
DEVICES_FILE = DATA_DIR / "devices.json"
DAILY_FILE = DATA_DIR / "daily.json"

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
            "activeTimeSec": to_int(item.get("activeTime"), 0),
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
    result = []
    previous = load_json(DEVICES_FILE, {}).get("watched", [])
    previous_by_mac = {norm_mac(d.get("mac")): d for d in previous}
    for w in watched:
        wmac = norm_mac(w.get("mac"))
        old = previous_by_mac.get(wmac, {})
        match = by_mac.get(wmac)
        if match:
            dev = dict(match)
            dev.update({
                "name": w.get("name") or match.get("name"),
                "online": True,
                "lastChangedAt": old.get("lastChangedAt") or now_str(),
            })
        else:
            dev = {
                "name": w.get("name") or old.get("name") or wmac,
                "mac": wmac,
                "online": False,
                "ip": None,
                "lastIp": old.get("ip") or old.get("lastIp"),
                "lastChangedAt": old.get("lastChangedAt") or now_str(),
            }
        # If status changed, update lastChangedAt and create event.
        old_online = old.get("online")
        if old_online is not None and old_online != dev.get("online"):
            dev["lastChangedAt"] = now_str()
            add_event({
                "type": "device_online" if dev.get("online") else "device_offline",
                "title": f"{dev.get('name')} {'上线' if dev.get('online') else '离线'}",
                "name": dev.get("name"),
                "mac": wmac,
                "oldValue": "online" if old_online else "offline",
                "newValue": "online" if dev.get("online") else "offline",
            })
        result.append(dev)
    return result


def get_exit_ip(ipv6: bool = False) -> Optional[str]:
    cfg_url = cfg_get("exit_ip.ipv6_url" if ipv6 else "exit_ip.ipv4_url", "https://api64.ipify.org")
    cmd = ["curl", "-6" if ipv6 else "-4", "-s", "--max-time", "5", cfg_url]
    try:
        out = subprocess.check_output(cmd, text=True).strip()
        return out or None
    except Exception:
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
    state.setdefault("router", {})
    state["router"].setdefault("exitIpv4", nas_ipv4)
    state["router"].setdefault("exitIpv6", None)

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
    state = load_json(STATE_FILE, {})
    state["updatedAt"] = now_str()
    if "stun" in event_type or "wireguard" in event_type:
        old = state.get("stun", {}).get("publicAddress")
        state["stun"] = {"publicAddress": address, "source": "Lucky Webhook", "updatedAt": now_str()}
        state["wireguard"] = {"publicAddress": address, "source": "Lucky Webhook", "updatedAt": now_str()}
        if address and address != old:
            add_event({"type": event_type, "title": "STUN / WireGuard 地址变化", "name": name, "oldValue": old, "newValue": address})
    elif "ddns" in event_type:
        domain = payload.get("domain") or name
        state.setdefault("ddns", {})
        old = state.get("ddns", {}).get(domain, {}).get("address")
        state["ddns"][domain] = {"domain": domain, "address": address, "source": "Lucky Webhook", "updatedAt": now_str()}
        if address and address != old:
            add_event({"type": event_type, "title": "DDNS 地址变化", "name": domain, "oldValue": old, "newValue": address})
    else:
        add_event({"type": event_type, "title": "Lucky Webhook", "name": name, "newValue": address or json.dumps(payload, ensure_ascii=False)})
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
    return jsonify({"ok": True, "events": [e for e in events if int(e.get("id", 0)) > after]})


@app.route("/api/daily/latest", methods=["GET"])
def api_daily():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    events = load_json(EVENTS_FILE, [])
    today = today_str()
    today_events = [e for e in events if str(e.get("createdAt", "")).startswith(today)]
    summary = {
        "date": today,
        "eventCount": len(today_events),
        "terminalChanges": len([e for e in today_events if str(e.get("type", "")).startswith("device_")]),
        "stunChanges": len([e for e in today_events if "stun" in str(e.get("type", ""))]),
        "ddnsChanges": len([e for e in today_events if "ddns" in str(e.get("type", ""))]),
        "text": f"今日事件 {len(today_events)} 条，终端变化 {len([e for e in today_events if str(e.get('type','')).startswith('device_')])} 次。",
    }
    save_json(DAILY_FILE, summary)
    return jsonify({"ok": True, "daily": summary})


if __name__ == "__main__":
    print(f"[LabProbe] Hub v{APP_VERSION} starting on 0.0.0.0:{PORT}", flush=True)
    print(f"[LabProbe] config={CONFIG_PATH}, data={DATA_DIR}", flush=True)
    app.run(host="0.0.0.0", port=PORT)
