import json
import os
import re
import subprocess
import threading
import time
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver
import requests
import yaml
from flask import Flask, jsonify, request

APP_NAME = "LabProbe Hub"
VERSION = "0.1.0"

DEFAULT_CONFIG = {
    "home": {"name": "Home Network"},
    "server": {"app_token": "change-app-token", "hook_token": "change-hook-token"},
    "ddns": [],
    "router": {"enabled": False},
    "watched_devices": [],
    "polling": {"enabled": False, "interval_seconds": 60},
    "exit_ip": {
        "ipv4_url": "https://api64.ipify.org",
        "ipv6_url": "https://api64.ipify.org",
    },
}

PORT = int(os.environ.get("PORT", "58443"))
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/app/config.yaml"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

STATE_FILE = DATA_DIR / "state.json"
EVENTS_FILE = DATA_DIR / "events.json"
LAST_DEVICES_FILE = DATA_DIR / "last_devices.json"

app = Flask(__name__)
state_lock = threading.Lock()


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_dt(s: str) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19], fmt)
        except Exception:
            pass
    return None


def deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = deepcopy(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> Dict[str, Any]:
    cfg = deepcopy(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            loaded = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                cfg = deep_merge(cfg, loaded)
        except Exception as e:
            print(f"[WARN] config load failed: {e}", flush=True)

    # 环境变量优先级最高，方便 Docker 部署。
    app_token = os.environ.get("APP_TOKEN")
    hook_token = os.environ.get("HOOK_TOKEN")
    if app_token:
        cfg.setdefault("server", {})["app_token"] = app_token
    if hook_token:
        cfg.setdefault("server", {})["hook_token"] = hook_token
    return cfg


CONFIG = load_config()


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def normalize_mac(mac: Optional[str]) -> str:
    if not mac:
        return ""
    return re.sub(r"[^0-9A-Fa-f]", "", str(mac)).lower()


def path_get(obj: Any, path: Optional[str], default: Any = None) -> Any:
    if not path:
        return obj
    cur = obj
    for part in str(path).split("."):
        if part == "":
            continue
        if isinstance(cur, dict):
            cur = cur.get(part, default)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except Exception:
                return default
        else:
            return default
    return cur


def first_field(item: Dict[str, Any], fields: List[str], default: Any = None) -> Any:
    for f in fields or []:
        val = path_get(item, f, None)
        if val not in (None, ""):
            return val
    return default


def check_app_token() -> bool:
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        token = request.args.get("token", "").strip()
    return token == str(CONFIG.get("server", {}).get("app_token", ""))


def require_auth():
    if not check_app_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return None


def get_exit_ip(ipv6: bool = False) -> Optional[str]:
    cfg = CONFIG.get("exit_ip", {}) or {}
    url = cfg.get("ipv6_url" if ipv6 else "ipv4_url") or "https://api64.ipify.org"
    family_flag = "-6" if ipv6 else "-4"
    try:
        out = subprocess.check_output(
            ["curl", family_flag, "-s", "--max-time", "5", url],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if out and "<" not in out and len(out) < 128:
            return out
    except Exception:
        pass
    return None


def dns_lookup(domain: str, record_type: str) -> Dict[str, Any]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 3
    started = time.time()
    try:
        ans = resolver.resolve(domain, record_type)
        values = [r.to_text().strip('"') for r in ans]
        return {
            "type": record_type,
            "ok": True,
            "values": values,
            "ttl": ans.rrset.ttl if ans.rrset else None,
            "latencyMs": int((time.time() - started) * 1000),
        }
    except Exception as e:
        return {
            "type": record_type,
            "ok": False,
            "values": [],
            "ttl": None,
            "latencyMs": int((time.time() - started) * 1000),
            "error": str(e),
        }


def add_event(event: Dict[str, Any]) -> Dict[str, Any]:
    with state_lock:
        events = load_json(EVENTS_FILE, [])
        next_id = int(events[-1].get("id", 0)) + 1 if events else 1
        event.setdefault("level", "normal")
        event["id"] = next_id
        event["createdAt"] = event.get("createdAt") or now_str()
        events.append(event)
        events = events[-1000:]
        save_json(EVENTS_FILE, events)
    return event


def load_state() -> Dict[str, Any]:
    state = load_json(STATE_FILE, {})
    if not isinstance(state, dict):
        state = {}
    state.setdefault("agent", {})
    state["agent"].update({"name": APP_NAME, "version": VERSION})
    state.setdefault("home", {"name": CONFIG.get("home", {}).get("name", "Home Network")})
    return state


def save_state(state: Dict[str, Any]) -> None:
    state["updatedAt"] = now_str()
    save_json(STATE_FILE, state)


def extract_router_devices(raw: Any) -> List[Dict[str, Any]]:
    router_cfg = CONFIG.get("router", {}) or {}
    schema = router_cfg.get("schema", {}) or {}
    items = path_get(raw, schema.get("items_path"), raw)
    if isinstance(items, dict):
        # 尝试找第一个数组字段
        for v in items.values():
            if isinstance(v, list):
                items = v
                break
    if not isinstance(items, list):
        return []

    online_values = schema.get("online_values", [True, 1, "1", "online", "ONLINE", "connected"])
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            continue
        mac = first_field(item, schema.get("mac_fields", []), "")
        online_raw = first_field(item, schema.get("online_fields", []), True)
        online = online_raw in online_values
        normalized.append(
            {
                "name": first_field(item, schema.get("name_fields", []), "未知设备"),
                "mac": mac,
                "macNormalized": normalize_mac(mac),
                "ip": first_field(item, schema.get("ip_fields", []), None),
                "ipv6": first_field(item, schema.get("ipv6_fields", []), None),
                "online": bool(online),
                "raw": item,
            }
        )
    return normalized


def fetch_router_devices() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    router_cfg = CONFIG.get("router", {}) or {}
    if not router_cfg.get("enabled"):
        return [], None
    url = router_cfg.get("api_url")
    if not url:
        return [], "router.api_url is empty"

    method = str(router_cfg.get("method", "GET")).upper()
    headers = router_cfg.get("headers") or {}
    timeout = int(router_cfg.get("timeout_seconds", 5))

    try:
        if method == "POST":
            resp = requests.post(url, headers=headers, timeout=timeout, json=router_cfg.get("body"))
        else:
            resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        raw = resp.json()
        return extract_router_devices(raw), None
    except Exception as e:
        return [], str(e)


def refresh_watched_devices(state: Dict[str, Any]) -> Dict[str, Any]:
    watched = CONFIG.get("watched_devices") or []
    router_devices, err = fetch_router_devices()
    router_map = {d.get("macNormalized"): d for d in router_devices if d.get("macNormalized")}

    previous = load_json(LAST_DEVICES_FILE, {})
    current_map = {}
    result = []

    for wd in watched:
        mac_norm = normalize_mac(wd.get("mac"))
        matched = router_map.get(mac_norm)
        old = previous.get(mac_norm, {})
        online = bool(matched and matched.get("online"))

        item = {
            "name": wd.get("name") or (matched or {}).get("name") or "未命名设备",
            "mac": wd.get("mac"),
            "online": online,
            "ip": (matched or {}).get("ip") or old.get("ip"),
            "ipv6": (matched or {}).get("ipv6") or old.get("ipv6"),
            "lastChangedAt": old.get("lastChangedAt"),
            "lastSeenAt": old.get("lastSeenAt"),
        }

        old_online = old.get("online")
        if old_online is not None and bool(old_online) != online:
            item["lastChangedAt"] = now_str()
            add_event(
                {
                    "type": "device_online" if online else "device_offline",
                    "title": f"{item['name']} {'上线' if online else '离线'}",
                    "name": item["name"],
                    "newValue": "online" if online else "offline",
                    "ip": item.get("ip"),
                }
            )
        elif not item.get("lastChangedAt"):
            item["lastChangedAt"] = now_str()

        if online:
            item["lastSeenAt"] = now_str()

        current_map[mac_norm] = item
        result.append(item)

    state["devices"] = result
    state.setdefault("router", {})["deviceApiError"] = err
    state["router"]["onlineDeviceCount"] = len([d for d in router_devices if d.get("online")])
    save_json(LAST_DEVICES_FILE, current_map)
    return state


def refresh_exit_and_ddns(state: Dict[str, Any]) -> Dict[str, Any]:
    nas_ipv4 = get_exit_ip(False)
    nas_ipv6 = get_exit_ip(True)

    state.setdefault("nas", {})
    state["nas"].update({"exitIpv4": nas_ipv4, "exitIpv6": nas_ipv6, "checkedAt": now_str()})

    state.setdefault("router", {})
    # 如果暂时没接路由器 WAN API，路由器 IPv4 一般与 NAS 出口 IPv4 相同。
    state["router"].setdefault("exitIpv4", nas_ipv4)
    state["router"].setdefault("exitIpv6", None)

    ddns_results = []
    for item in CONFIG.get("ddns") or []:
        domain = item.get("domain")
        if not domain:
            continue
        record_types = item.get("record_types") or ["A", "AAAA"]
        records = {rt: dns_lookup(domain, rt) for rt in record_types}

        expect_key = item.get("expect")
        expected = None
        if expect_key == "nas_ipv4":
            expected = state.get("nas", {}).get("exitIpv4")
        elif expect_key == "nas_ipv6":
            expected = state.get("nas", {}).get("exitIpv6")
        elif expect_key == "router_ipv4":
            expected = state.get("router", {}).get("exitIpv4")
        elif expect_key == "router_ipv6":
            expected = state.get("router", {}).get("exitIpv6")
        elif expect_key == "stun":
            expected = state.get("stun", {}).get("publicAddress")
        elif expect_key == "wireguard":
            expected = state.get("wireguard", {}).get("publicAddress")

        all_values = []
        for r in records.values():
            all_values.extend(r.get("values") or [])
        matched = bool(expected and expected in all_values)

        ddns_results.append(
            {
                "name": item.get("name") or domain,
                "domain": domain,
                "expect": expect_key,
                "expected": expected,
                "matched": matched,
                "records": records,
                "checkedAt": now_str(),
            }
        )

    state["ddnsChecks"] = ddns_results
    return state


def refresh_all() -> Dict[str, Any]:
    with state_lock:
        state = load_state()
        state = refresh_exit_and_ddns(state)
        state = refresh_watched_devices(state)
        save_state(state)
    return state


def update_state_from_hook(payload: Dict[str, Any]) -> Dict[str, Any]:
    event_type = payload.get("type") or payload.get("event") or "lucky_webhook"
    address = payload.get("address") or payload.get("ipAddr") or payload.get("value") or payload.get("ip")
    name = payload.get("name") or payload.get("domain") or "Lucky"

    with state_lock:
        state = load_state()

        if event_type in {"stun_changed", "wireguard_changed", "wireguard_endpoint_changed"}:
            old_value = state.get("stun", {}).get("publicAddress")
            state["stun"] = {
                "publicAddress": address,
                "updatedAt": now_str(),
                "source": "Lucky Webhook",
            }
            state["wireguard"] = {
                "publicAddress": address,
                "updatedAt": now_str(),
                "source": "Lucky Webhook",
            }
            if address and address != old_value:
                add_event(
                    {
                        "type": event_type,
                        "title": "STUN / WireGuard 地址变化",
                        "name": name,
                        "oldValue": old_value,
                        "newValue": address,
                    }
                )

        elif event_type in {"ddns_changed", "ddns_update"}:
            domain = payload.get("domain") or name or "net86.dynv6.net"
            old_value = state.get("ddns", {}).get(domain, {}).get("address")
            state.setdefault("ddns", {})[domain] = {
                "domain": domain,
                "address": address,
                "updatedAt": now_str(),
                "source": "Lucky Webhook",
            }
            if address and address != old_value:
                add_event(
                    {
                        "type": event_type,
                        "title": "DDNS 地址变化",
                        "name": domain,
                        "oldValue": old_value,
                        "newValue": address,
                    }
                )
        else:
            add_event(
                {
                    "type": event_type,
                    "title": "Lucky Webhook",
                    "name": name,
                    "newValue": address or json.dumps(payload, ensure_ascii=False),
                }
            )

        save_state(state)
    return state


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "name": APP_NAME, "version": VERSION, "time": now_str()})


@app.route("/hook/lucky", methods=["GET", "POST"])
def hook_lucky():
    hook_token = str(CONFIG.get("server", {}).get("hook_token", ""))
    token = request.args.get("token") or request.headers.get("X-Hook-Token") or ""
    if token != hook_token:
        return jsonify({"ok": False, "error": "bad hook token"}), 401

    if request.is_json:
        payload = request.get_json(silent=True) or {}
    else:
        payload = dict(request.form)
        if not payload:
            payload = dict(request.args)
            payload.pop("token", None)

    state = update_state_from_hook(payload)
    return jsonify({"ok": True, "received": payload, "data": state, "time": now_str()})


@app.route("/api/status", methods=["GET"])
def api_status():
    auth = require_auth()
    if auth:
        return auth
    state = refresh_all()
    return jsonify({"ok": True, "data": state})


@app.route("/api/refresh", methods=["POST", "GET"])
def api_refresh():
    auth = require_auth()
    if auth:
        return auth
    state = refresh_all()
    return jsonify({"ok": True, "data": state})


@app.route("/api/devices", methods=["GET"])
def api_devices():
    auth = require_auth()
    if auth:
        return auth
    with state_lock:
        state = load_state()
        state = refresh_watched_devices(state)
        save_state(state)
    return jsonify({"ok": True, "devices": state.get("devices", [])})


@app.route("/api/events", methods=["GET"])
def api_events():
    auth = require_auth()
    if auth:
        return auth
    after = int(request.args.get("after", "0"))
    limit = min(int(request.args.get("limit", "100")), 500)
    events = load_json(EVENTS_FILE, [])
    result = [e for e in events if int(e.get("id", 0)) > after]
    return jsonify({"ok": True, "events": result[-limit:]})


@app.route("/api/daily/latest", methods=["GET"])
def api_daily_latest():
    auth = require_auth()
    if auth:
        return auth
    events = load_json(EVENTS_FILE, [])
    since = datetime.now() - timedelta(days=1)
    recent = []
    for e in events:
        dt = parse_dt(e.get("createdAt", ""))
        if dt and dt >= since:
            recent.append(e)

    summary = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "totalEvents": len(recent),
        "terminalChanges": len([e for e in recent if "device" in e.get("type", "")]),
        "stunChanges": len([e for e in recent if "stun" in e.get("type", "")]),
        "ddnsChanges": len([e for e in recent if "ddns" in e.get("type", "")]),
        "text": f"近24小时共有 {len(recent)} 条事件，终端变化 {len([e for e in recent if 'device' in e.get('type', '')])} 次，STUN变化 {len([e for e in recent if 'stun' in e.get('type', '')])} 次，DDNS变化 {len([e for e in recent if 'ddns' in e.get('type', '')])} 次。",
    }
    return jsonify({"ok": True, "daily": summary})


@app.route("/api/config/redacted", methods=["GET"])
def api_config_redacted():
    auth = require_auth()
    if auth:
        return auth
    cfg = deepcopy(CONFIG)
    if "server" in cfg:
        cfg["server"]["app_token"] = "***"
        cfg["server"]["hook_token"] = "***"
    if "router" in cfg and "headers" in cfg["router"]:
        cfg["router"]["headers"] = {k: "***" for k in cfg["router"].get("headers", {})}
    return jsonify({"ok": True, "config": cfg})


def polling_worker():
    while True:
        polling = CONFIG.get("polling", {}) or {}
        interval = max(30, int(polling.get("interval_seconds", 60)))
        try:
            if polling.get("enabled"):
                print("[INFO] polling refresh", flush=True)
                refresh_all()
        except Exception as e:
            print(f"[WARN] polling failed: {e}", flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    print(f"[INFO] {APP_NAME} v{VERSION} starting on :{PORT}", flush=True)
    print(f"[INFO] config path: {CONFIG_PATH}", flush=True)
    print(f"[INFO] data dir: {DATA_DIR}", flush=True)
    t = threading.Thread(target=polling_worker, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=PORT)
