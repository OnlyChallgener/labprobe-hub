"""RDPI Custom Application Signature Manager for Ruijie / Reyee routers.

Supports reading, validating, adding, and removing custom application signatures
in `/usr/share/ndpi/db.default.json` with hot-reload via `ubus send rdpi_reinit`.
"""

from __future__ import annotations

import base64
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
import paramiko
from paramiko.transport import Transport
from paramiko.rsakey import RSAKey
from cryptography.hazmat.primitives import hashes

# Enable legacy ssh-rsa host key support for router Dropbear SSH
RSAKey.HASHES["ssh-rsa"] = hashes.SHA1
Transport._key_info["ssh-rsa"] = RSAKey
Transport._preferred_keys = ("ssh-rsa", "rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519")

DEFAULT_ROUTER_HOST = os.getenv("ROUTER_SSH_HOST", "111.23.167.108")
DEFAULT_ROUTER_PORT = int(os.getenv("ROUTER_SSH_PORT", "13512"))
DEFAULT_ROUTER_USER = os.getenv("ROUTER_SSH_USER", "root")
DEFAULT_ROUTER_PASS = os.getenv("ROUTER_SSH_PASS", "Re238950")

REMOTE_DB_PATH = "/usr/share/ndpi/db.default.json"
REMOTE_BAK_PATH = "/usr/share/ndpi/db.default.json.bak"
_INDEX_RE = re.compile(r"^\d+-\d+-\d+-\d+$")

STANDARD_RDPI_TEMPLATE: Dict[str, Any] = {
    "$schema": "labprobe-rdpi-v1",
    "comment": "锐捷/Reyee RDPI 自定义应用特征包标准格式，适用于儿童上网与流量审计",
    "app": {
        "index": "999-1-1-0",
        "name": "自定义应用/新游戏",
        "category": "game",
        "description": "基于抓包提取的域名(SNI)与TCP/UDP握手载荷特征",
        "rules": [
            {
                "protocol": "tcp",
                "hosts": [
                    "*.customgame.com",
                    "login.customgame.cn"
                ],
                "payloads": [
                    {
                        "pos": 0,
                        "length": 4,
                        "payload": "47 41 4d 45"
                    }
                ]
            },
            {
                "protocol": "udp",
                "hosts": [],
                "payloads": [
                    {
                        "pos": 0,
                        "length": 2,
                        "payload": "ff ff"
                    }
                ]
            }
        ]
    }
}


def _get_ssh_client() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        DEFAULT_ROUTER_HOST,
        port=DEFAULT_ROUTER_PORT,
        username=DEFAULT_ROUTER_USER,
        password=DEFAULT_ROUTER_PASS,
        timeout=10,
    )
    return client


def _remote_exec(client: paramiko.SSHClient, command: str) -> Tuple[str, str]:
    stdin, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    return out, err


def load_router_rdpi_db(client: Optional[paramiko.SSHClient] = None) -> Dict[str, Any]:
    close_client = False
    if client is None:
        client = _get_ssh_client()
        close_client = True
    try:
        out, err = _remote_exec(client, f"cat {REMOTE_DB_PATH}")
        if not out:
            raise RuntimeError(f"Failed to read {REMOTE_DB_PATH}: {err}")
        return json.loads(out)
    finally:
        if close_client:
            client.close()


def save_router_rdpi_db(
    db_data: Dict[str, Any],
    client: Optional[paramiko.SSHClient] = None,
    reload_rdpi: bool = True,
) -> str:
    close_client = False
    if client is None:
        client = _get_ssh_client()
        close_client = True
    try:
        # Backup if not already present
        _remote_exec(client, f"[ ! -f {REMOTE_BAK_PATH} ] && cp {REMOTE_DB_PATH} {REMOTE_BAK_PATH}")

        content_bytes = json.dumps(db_data, ensure_ascii=False, indent=2).encode("utf-8")
        stdin, stdout, stderr = client.exec_command("cat > /tmp/db.default.json.tmp")
        stdin.write(content_bytes)
        stdin.channel.shutdown_write()
        err_stream = stderr.read().decode("utf-8", errors="replace").strip()
        if err_stream:
            raise RuntimeError(f"Failed to stream remote db: {err_stream}")

        out_mv, err_mv = _remote_exec(client, f"cp /tmp/db.default.json.tmp {REMOTE_DB_PATH} && rm -f /tmp/db.default.json.tmp")
        if err_mv:
            raise RuntimeError(f"Failed to write remote db: {err_mv}")

        msg = "Saved successfully."
        if reload_rdpi:
            reload_msg, _ = _remote_exec(client, "ubus -t 3 send 'rdpi_reinit'")
            msg += f" (Hot-reload triggered: {reload_msg})"
        return msg
    finally:
        if close_client:
            client.close()


def validate_signature_object(obj: Any) -> Dict[str, Any]:
    """Validates and normalizes an incoming app signature dictionary."""
    if not isinstance(obj, dict):
        raise ValueError("Signature payload must be a JSON object")

    # If wrapped in {"app": {...}}, unwrap it
    app_data = obj.get("app") if isinstance(obj.get("app"), dict) else obj

    index = str(app_data.get("index") or "").strip()
    if not _INDEX_RE.fullmatch(index):
        raise ValueError(f"Invalid RDPI index format '{index}', expected X-X-X-X (e.g. 999-1-1-0)")

    name = str(app_data.get("name") or "").strip()
    if not name:
        raise ValueError("Signature name cannot be empty")

    raw_rules = app_data.get("rules", [])
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ValueError("Signature must have at least one rule")

    clean_rules = []
    for r in raw_rules:
        if not isinstance(r, dict):
            continue
        proto = str(r.get("protocol") or "any").strip().lower()
        if proto not in ("tcp", "udp", "any", "icmp"):
            proto = "any"

        hosts = [str(h).strip() for h in r.get("hosts", []) if str(h).strip()]

        clean_payloads = []
        for p in r.get("payloads", []):
            if not isinstance(p, dict):
                continue
            payload_hex = str(p.get("payload") or "").strip().replace("0x", "").replace(",", " ")
            bytes_list = [b for b in payload_hex.split() if b]
            if not bytes_list:
                # If continuous string without spaces, chunk by 2
                compact = payload_hex.replace(" ", "")
                if len(compact) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in compact):
                    bytes_list = [compact[i:i+2] for i in range(0, len(compact), 2)]
            if bytes_list:
                clean_payloads.append({
                    "pos": int(p.get("pos", 0)),
                    "length": len(bytes_list),
                    "payload": " ".join(bytes_list).lower(),
                })

        if hosts or clean_payloads:
            rule_entry: Dict[str, Any] = {"protocol": proto}
            if hosts:
                rule_entry["hosts"] = hosts
            if clean_payloads:
                rule_entry["payloads"] = clean_payloads
            clean_rules.append(rule_entry)

    if not clean_rules:
        raise ValueError("Rules must contain at least one valid host pattern or payload hex")

    return {
        "index": index,
        "name": name,
        "rules": clean_rules,
        "custom": True,
    }


def get_rdpi_signatures_summary() -> Dict[str, Any]:
    """Returns official count, custom count, custom rules list, and template."""
    client = _get_ssh_client()
    try:
        db = load_router_rdpi_db(client)
        apps = db.get("apps", [])
        total_count = len(apps)

        # Custom apps: index starts with '9' or has 'custom': True
        custom_apps = [
            a for a in apps
            if str(a.get("index", "")).startswith("9") or a.get("custom") is True
        ]
        official_count = total_count - len(custom_apps)

        return {
            "ok": True,
            "totalCount": total_count,
            "officialCount": max(0, official_count),
            "customCount": len(custom_apps),
            "customSignatures": custom_apps,
            "template": STANDARD_RDPI_TEMPLATE,
        }
    finally:
        client.close()


def add_or_update_rdpi_signature(payload: Any) -> Dict[str, Any]:
    """Validates and appends/updates custom signature into router RDPI DB."""
    signature = validate_signature_object(payload)
    client = _get_ssh_client()
    try:
        db = load_router_rdpi_db(client)
        apps = db.get("apps", [])

        idx = signature["index"]
        name = signature["name"]
        existing = next((a for a in apps if a.get("index") == idx or a.get("name") == name), None)

        if existing:
            existing["index"] = idx
            existing["name"] = name
            existing["rules"] = signature["rules"]
            existing["custom"] = True
            action_desc = "updated"
        else:
            apps.append(signature)
            action_desc = "added"

        db["apps"] = apps
        msg = save_router_rdpi_db(db, client=client, reload_rdpi=True)

        return {
            "ok": True,
            "action": action_desc,
            "index": idx,
            "name": name,
            "message": msg,
            "totalCount": len(apps),
        }
    finally:
        client.close()


def delete_rdpi_signature(target_index_or_name: str) -> Dict[str, Any]:
    """Deletes signature matching index or name and reloads RDPI."""
    target = target_index_or_name.strip()
    if not target:
        raise ValueError("Target index or name is required")

    client = _get_ssh_client()
    try:
        db = load_router_rdpi_db(client)
        apps = db.get("apps", [])
        before = len(apps)
        apps = [a for a in apps if a.get("index") != target and a.get("name") != target]
        after = len(apps)

        if before == after:
            return {"ok": False, "error": f"No signature found matching '{target}'"}

        db["apps"] = apps
        msg = save_router_rdpi_db(db, client=client, reload_rdpi=True)
        return {
            "ok": True,
            "deleted": target,
            "message": msg,
            "totalCount": len(apps),
        }
    finally:
        if close_client:
            client.close()


CURATED_SIGNATURE_EXTENSIONS: Dict[str, Dict[str, Any]] = {
    "10-1-2-0": {
        "name": "微信视频号",
        "category": "短视频/直播",
        "hosts": [
            "*.vweixinfp.tc.qq.com",
            "vweixinfp.tc.qq.com",
            "*.channels.weixin.qq.com",
            "channels.weixin.qq.com",
            "*.wxapp.tc.qq.com",
            "wxapp.tc.qq.com",
            "finderv1.video.qq.com",
            "finderd1p.video.qq.com",
            "finder.video.qq.com",
            "*.finder.video.qq.com",
            "*.live.weixin.qq.com",
            "voipfinderliveplay.wxqcloud.qq.com",
        ],
    },
    "7-1-2-12": {
        "name": "微信_other",
        "category": "即时通讯/音视频通话",
        "hosts": [
            "weixin.qq.com",
            "*.weixin.qq.com",
            "*.wechat.com",
            "szshort.weixin.qq.com",
            "szextshort.weixin.qq.com",
            "szminorshort.weixin.qq.com",
            "*.qpic.cn",
            "*.wx.qlogo.cn",
        ],
    },
    "10-5-1-0": {
        "name": "抖音",
        "category": "短视频/直播",
        "hosts": [
            "amemv.com",
            "*.amemv.com",
            "douyincdn.com",
            "*.douyincdn.com",
            "douyinpic.com",
            "*.douyinpic.com",
            "douyinvod.com",
            "*.douyinvod.com",
            "douyin.com",
            "*.douyin.com",
            "*.douyinstatic.com",
            "*.zijieapi.com",
            "*.snssdk.com",
        ],
    },
    "10-146-1-0": {
        "name": "快手",
        "category": "短视频/直播",
        "hosts": [
            "gifshow.com",
            "*.gifshow.com",
            "kuaishou.com",
            "*.kuaishou.com",
            "yximgs.com",
            "*.yximgs.com",
            "ksapisrv.com",
            "*.ksapisrv.com",
            "kwai.com",
            "*.kwai.com",
            "*.kwimgs.com",
            "*.kwaicdn.com",
        ],
    },
    "18-158-1-0": {
        "name": "拼多多",
        "category": "综合电商",
        "hosts": [
            "yangkeduo.com",
            "*.yangkeduo.com",
            "pinduoduo.com",
            "*.pinduoduo.com",
            "pddpic.com",
            "*.pddpic.com",
            "*.hutaojie.com",
            "*.pinduoduo.net",
        ],
    },
    "18-159-1-0": {
        "name": "京东",
        "category": "综合电商",
        "hosts": [
            "360buy.com",
            "*.360buy.com",
            "jd.com",
            "*.jd.com",
            "360buyimg.com",
            "*.360buyimg.com",
            "*.jd.hk",
            "*.jcloud.com",
        ],
    },
    "18-4-2-0": {
        "name": "淘宝",
        "category": "综合电商",
        "hosts": [
            "taobao.com",
            "*.taobao.com",
            "tbcdn.cn",
            "*.tbcdn.cn",
            "tmall.com",
            "*.tmall.com",
            "*.alicdn.com",
            "*.tbcache.com",
        ],
    },
}


def apply_curated_signature_bundle(client: Optional[paramiko.SSHClient] = None) -> Dict[str, Any]:
    """Applies curated high-frequency signatures (WeChat Channels, Douyin, Kuaishou, PDD, JD, Taobao) and reloads RDPI."""
    close_client = False
    if client is None:
        client = _get_ssh_client()
        close_client = True
    try:
        db = load_router_rdpi_db(client)
        apps = db.get("apps", [])

        total_hosts_added = 0
        enhanced_apps = []

        for idx, patch in CURATED_SIGNATURE_EXTENSIONS.items():
            app = next((a for a in apps if a.get("index") == idx or a.get("name") == patch["name"]), None)
            if not app:
                # If neither index nor name found, create a new custom entry
                new_app = {
                    "index": idx,
                    "name": patch["name"],
                    "rules": [{"protocol": "host", "hosts": patch["hosts"], "payloads": []}],
                    "custom": True,
                }
                apps.append(new_app)
                total_hosts_added += len(patch["hosts"])
                enhanced_apps.append(f"{patch['name']} (新增规则 {len(patch['hosts'])} 域名)")
                continue

            rules = app.setdefault("rules", [])
            host_rule = next((r for r in rules if "hosts" in r), None)
            if not host_rule:
                host_rule = {"protocol": "host", "hosts": [], "payloads": []}
                rules.insert(0, host_rule)

            current_hosts = host_rule.get("hosts", [])
            added_here = 0
            for h in patch["hosts"]:
                if h not in current_hosts:
                    current_hosts.append(h)
                    added_here += 1

            host_rule["hosts"] = current_hosts
            total_hosts_added += added_here
            enhanced_apps.append(f"{patch['name']} (+{added_here} 域名)")

        db["apps"] = apps
        msg = save_router_rdpi_db(db, client=client, reload_rdpi=True)

        return {
            "ok": True,
            "totalHostsAdded": total_hosts_added,
            "enhancedApps": enhanced_apps,
            "message": msg,
            "totalApps": len(apps),
        }
    finally:
        if close_client:
            client.close()


def sync_child_guard_ip6_block(macs: Optional[List[str]] = None, client: Optional[paramiko.SSHClient] = None) -> Dict[str, Any]:
    """Syncs guarded device MACs into router `child_guard_ip6_block` ipset.

    Forces dual-stack apps (WeChat, Douyin, etc.) on guarded devices to seamlessly
    fallback to IPv4, allowing `sniffer.ko` to capture 100% of their DPI flows.
    """
    close_client = False
    if client is None:
        client = _get_ssh_client()
        close_client = True
    try:
        target_macs = set()
        if macs:
            for m in macs:
                clean = str(m or "").strip().lower()
                if re.fullmatch(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", clean):
                    target_macs.add(clean)

        # If no explicit macs provided, read from router UCI
        if not target_macs:
            out_uci, _ = _remote_exec(client, "uci show child_guard | grep '\\.mac='")
            for line in out_uci.splitlines():
                if "=" in line:
                    val = line.split("=", 1)[1].strip("'\" ")
                    for item in val.split():
                        clean = item.strip().lower()
                        if re.fullmatch(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", clean):
                            target_macs.add(clean)

        # Ensure ipset exists
        _remote_exec(client, "ipset create child_guard_ip6_block hash:mac 2>/dev/null")

        # Add each target mac
        for mac in sorted(target_macs):
            _remote_exec(client, f"ipset add child_guard_ip6_block {mac} 2>/dev/null")

        # Fetch active members
        out_list, _ = _remote_exec(client, "ipset list child_guard_ip6_block")
        members = []
        capture = False
        for line in out_list.splitlines():
            if line.startswith("Members:"):
                capture = True
                continue
            if capture and line.strip():
                members.append(line.strip().lower())

        return {
            "ok": True,
            "syncedMacs": sorted(target_macs),
            "activeMembers": sorted(members),
            "count": len(members),
            "message": f"IPv6 降级审计已生效，共同步 {len(members)} 台受守护设备",
        }
    finally:
        if close_client:
            client.close()


def get_child_guard_ip6_block_status(client: Optional[paramiko.SSHClient] = None) -> Dict[str, Any]:
    """Returns current active members of `child_guard_ip6_block`."""
    close_client = False
    if client is None:
        client = _get_ssh_client()
        close_client = True
    try:
        out_list, _ = _remote_exec(client, "ipset list child_guard_ip6_block 2>/dev/null")
        members = []
        capture = False
        for line in out_list.splitlines():
            if line.startswith("Members:"):
                capture = True
                continue
            if capture and line.strip():
                members.append(line.strip().lower())

        return {
            "ok": True,
            "activeMembers": sorted(members),
            "count": len(members),
            "enabled": len(members) > 0,
        }
    finally:
        if close_client:
            client.close()

