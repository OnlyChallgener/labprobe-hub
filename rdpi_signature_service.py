"""RDPI Custom Application Signature Manager for Ruijie / Reyee routers.

Supports reading, validating, adding, and removing custom application signatures
in `/usr/share/ndpi/db.default.json` with hot-reload via `ubus send rdpi_reinit`.
"""

from __future__ import annotations

import base64
import copy
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

# These values are observed in the supplied BE72/Reyee db.default.json.  Do
# not silently turn a new protocol into ``any``: ``any`` is not present in the
# supplied official database and its meaning is firmware-specific.
_RDPI_PROTOCOLS = frozenset({
    "host", "tcp", "udp", "http-gets", "http-posts", "user-agent",
    "https-all-bitstream",
})
_APP_FIELDS = frozenset({"index", "name", "rules", "note"})
_ENVELOPE_FIELDS = frozenset({"$schema", "comment", "app"})
_RULE_FIELDS = frozenset({
    "protocol", "hosts", "payloads", "payload_length", "http-gets",
    "http-posts", "user-agents", "note", "notes", "name", "port_limit",
    "extra_packet",
})
_PAYLOAD_FIELDS = frozenset({"payload", "pos", "length", "stage", "note", "t_pos", "t_length"})

STANDARD_RDPI_TEMPLATE: Dict[str, Any] = {
    "$schema": "labprobe-rdpi-v1",
    "comment": "锐捷/Reyee RDPI 自定义应用特征包标准格式，适用于儿童上网与流量审计",
    "app": {
        "index": "999-1-1-0",
        "name": "自定义应用/新游戏",
        "rules": [
            {
                "protocol": "host",
                "hosts": [
                    "*.customgame.com",
                    "login.customgame.cn"
                ]
            },
            {
                "protocol": "tcp",
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
    channel = getattr(stdout, "channel", None)
    recv_exit_status = getattr(channel, "recv_exit_status", None)
    if callable(recv_exit_status):
        exit_status = recv_exit_status()
        if exit_status and not err:
            err = f"remote command exited with status {exit_status}"
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
    rollback_path = "/tmp/db.default.json.rollback"
    temp_path = "/tmp/db.default.json.tmp"
    written = False
    try:
        # Keep the historical .bak for operators, but use a fresh transaction
        # backup for this write.  A stale .bak cannot safely roll back a failed
        # hot reload.
        _, err_backup = _remote_exec(client, f"cp {REMOTE_DB_PATH} {rollback_path} && cp {REMOTE_DB_PATH} {REMOTE_BAK_PATH}")
        if err_backup:
            raise RuntimeError(f"Failed to backup {REMOTE_DB_PATH}: {err_backup}")

        content_bytes = json.dumps(db_data, ensure_ascii=False, indent=2).encode("utf-8")
        stdin, stdout, stderr = client.exec_command(f"cat > {temp_path}")
        stdin.write(content_bytes)
        stdin.channel.shutdown_write()
        err_stream = stderr.read().decode("utf-8", errors="replace").strip()
        if err_stream:
            raise RuntimeError(f"Failed to stream remote db: {err_stream}")

        out_mv, err_mv = _remote_exec(client, f"cp {temp_path} {REMOTE_DB_PATH} && rm -f {temp_path}")
        if err_mv:
            raise RuntimeError(f"Failed to write remote db: {err_mv}")
        written = True

        # Verify the exact JSON object that the router accepted before asking
        # the daemon to reload it.  This catches truncated writes and router
        # filesystem/proxy surprises without touching a real router in tests.
        readback, readback_err = _remote_exec(client, f"cat {REMOTE_DB_PATH}")
        if readback_err:
            raise RuntimeError(f"Failed to read back {REMOTE_DB_PATH}: {readback_err}")
        try:
            readback_obj = json.loads(readback)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"Router returned invalid JSON for {REMOTE_DB_PATH}") from exc
        if readback_obj != db_data:
            raise RuntimeError(f"Router read-back mismatch for {REMOTE_DB_PATH}")

        msg = "Saved successfully."
        if reload_rdpi:
            reload_msg, reload_err = _remote_exec(client, "ubus -t 3 send 'rdpi_reinit'")
            if reload_err:
                raise RuntimeError(f"RDPI hot-reload failed: {reload_err}")
            msg += f" (Hot-reload triggered: {reload_msg})"
        return msg
    except Exception as exc:
        if written:
            # Restore both the file and the running RDPI process.  Preserve the
            # original failure while making rollback failure explicit.
            _, rollback_err = _remote_exec(
                client,
                f"cp {rollback_path} {REMOTE_DB_PATH} && ubus -t 3 send 'rdpi_reinit'",
            )
            if rollback_err:
                raise RuntimeError(f"{exc}; rollback failed: {rollback_err}") from exc
        raise
    finally:
        _remote_exec(client, f"rm -f {temp_path} {rollback_path}")
        if close_client:
            client.close()


def validate_signature_object(obj: Any) -> Dict[str, Any]:
    """Validate an app signature against the observed official RDPI shape.

    The returned object retains official optional fields (``note``, ``stage``,
    ``http-gets`` etc.) instead of silently dropping them.  Service metadata
    such as ``custom`` is returned for the API/UI but must not be written into
    the router database by the caller.
    """
    if not isinstance(obj, dict):
        raise ValueError("Signature payload must be a JSON object")

    if "app" in obj:
        unknown_envelope = set(obj) - _ENVELOPE_FIELDS
        if unknown_envelope:
            raise ValueError(f"Unsupported RDPI envelope fields: {sorted(unknown_envelope)}")
        if not isinstance(obj["app"], dict):
            raise ValueError("RDPI app must be a JSON object")
        app_data = obj["app"]
    else:
        app_data = obj

    unknown_app = set(app_data) - _APP_FIELDS
    if unknown_app:
        raise ValueError(f"Unsupported RDPI app fields: {sorted(unknown_app)}")

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
            raise ValueError("Each RDPI rule must be a JSON object")
        unknown_rule = set(r) - _RULE_FIELDS
        if unknown_rule:
            raise ValueError(f"Unsupported RDPI rule fields: {sorted(unknown_rule)}")

        rule_entry: Dict[str, Any] = copy.deepcopy(r)
        if "protocol" in r:
            proto = r.get("protocol")
            if not isinstance(proto, str) or proto.strip().lower() not in _RDPI_PROTOCOLS:
                raise ValueError(f"Unsupported RDPI protocol '{proto}'")
            rule_entry["protocol"] = proto.strip().lower()

        if "hosts" in r:
            if not isinstance(r["hosts"], list) or any(not isinstance(h, str) or not h.strip() for h in r["hosts"]):
                raise ValueError("RDPI hosts must be a list of non-empty strings")
            rule_entry["hosts"] = [h.strip() for h in r["hosts"]]

        if "payloads" in r and not isinstance(r["payloads"], list):
            raise ValueError("RDPI payloads must be a list")
        clean_payloads = []
        for p in r.get("payloads", []):
            if not isinstance(p, dict):
                raise ValueError("RDPI payload must be a JSON object")
            unknown_payload = set(p) - _PAYLOAD_FIELDS
            if unknown_payload:
                raise ValueError(f"Unsupported RDPI payload fields: {sorted(unknown_payload)}")
            if not isinstance(p.get("payload"), str):
                raise ValueError("RDPI payload must be a hexadecimal string")
            payload_hex = p["payload"].strip().replace("0x", "").replace(",", " ")
            compact = payload_hex.replace(" ", "")
            if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
                raise ValueError("RDPI payload must contain valid hexadecimal bytes")
            pos = p.get("pos", 0)
            if isinstance(pos, bool) or not isinstance(pos, int) or pos < 0:
                raise ValueError("RDPI payload pos must be non-negative")
            bytes_list = [compact[i:i + 2].lower() for i in range(0, len(compact), 2)]
            if "length" in p:
                declared_length = p["length"]
                if isinstance(declared_length, bool) or not isinstance(declared_length, int) or declared_length < 0:
                    raise ValueError("RDPI payload length must be non-negative")
            else:
                declared_length = len(bytes_list)
            for field in ("stage", "t_pos", "t_length"):
                if field in p:
                    numeric = p[field]
                    if isinstance(numeric, bool) or not isinstance(numeric, int) or numeric < 0:
                        raise ValueError(f"RDPI payload {field} must be non-negative")
            if "note" in p and not isinstance(p["note"], str):
                raise ValueError("RDPI payload note must be a string")
            payload_entry = copy.deepcopy(p)
            # Keep an explicitly supplied length verbatim.  The supplied
            # official db contains legacy records whose declared length is
            # intentionally larger than the visible payload bytes.
            payload_entry.update({"pos": pos, "length": declared_length, "payload": " ".join(bytes_list)})
            clean_payloads.append(payload_entry)
        if "payloads" in r:
            rule_entry["payloads"] = clean_payloads

        for field in ("http-gets", "http-posts", "user-agents"):
            if field in r and (not isinstance(r[field], list)
                               or any(not isinstance(item, str) for item in r[field])):
                raise ValueError(f"RDPI {field} must be a list")
        for field in ("note", "notes", "name"):
            if field in r and not isinstance(r[field], str):
                raise ValueError(f"RDPI rule {field} must be a string")
        if "extra_packet" in r and (isinstance(r["extra_packet"], bool)
                                     or not isinstance(r["extra_packet"], int)):
            raise ValueError("RDPI rule extra_packet must be an integer")

        if "payload_length" in r:
            if not isinstance(r["payload_length"], list):
                raise ValueError("RDPI payload_length must be a list")
            for item in r["payload_length"]:
                if (not isinstance(item, dict)
                        or not isinstance(item.get("stage"), int)
                        or isinstance(item.get("stage"), bool)
                        or item["stage"] < 0
                        or not isinstance(item.get("length"), int)
                        or isinstance(item.get("length"), bool)
                        or item["length"] < 0):
                    raise ValueError("RDPI payload_length entries require non-negative integer stage/length")

        if "port_limit" in r:
            if not isinstance(r["port_limit"], list):
                raise ValueError("RDPI port_limit must be a list")
            for item in r["port_limit"]:
                if (not isinstance(item, dict)
                        or not isinstance(item.get("min"), int)
                        or isinstance(item.get("min"), bool)
                        or item["min"] < 0
                        or not isinstance(item.get("max"), int)
                        or isinstance(item.get("max"), bool)
                        or item["max"] < 0):
                    raise ValueError("RDPI port_limit entries require non-negative integer min/max")

        has_matcher = any(
            isinstance(rule_entry.get(field), list) and bool(rule_entry[field])
            for field in ("hosts", "payloads", "payload_length", "http-gets", "http-posts", "user-agents")
        )
        if not has_matcher:
            raise ValueError("Rules must contain at least one valid host, payload, or official HTTP/UA matcher")
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
            if str(a.get("index", "")).startswith("9")
            or a.get("custom") is True
            or any(a.get("index") == idx and a.get("name") == patch["name"]
                   for idx, patch in CURATED_SIGNATURE_EXTENSIONS.items())
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

        db_signature = {key: copy.deepcopy(value) for key, value in signature.items() if key != "custom"}
        if existing:
            # Update only fields represented by the imported official shape;
            # retain existing official optional fields (for example ``note``)
            # when the incoming payload does not mention them.
            existing.update(db_signature)
            action_desc = "updated"
        else:
            apps.append(db_signature)
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
    # 阿里CDN：官方特征库把 appid 绑死在自家编号体系里（18-4-1 支付宝、
    # 18-4-2 淘宝、7-4-1 阿里云盘、8-4-1-x 钉钉），阿里系共用 `*-4-*` 段。
    # 官方没有"阿里CDN"这个条目，于是按同一编号规则占 18-4-3-0，只收官方
    # **没有明确归属**的阿里域名：`*.alicdn.com`/`tanx.com`/`tbcdn.cn` 官方已
    # 绑给淘宝，钉钉/优酷各自绑了自己的 alicdn 子域，这些一律不抢，让明确
    # 的应用继续按官方归属显示，剩下的阿里基础设施流量落到 阿里CDN。
    "18-4-3-0": {
        "name": "阿里CDN",
        "category": "网络服务/CDN",
        "hosts": [
            "aliyuncs.com",
            "*.aliyuncs.com",
            "aliyun.com",
            "*.aliyun.com",
            "alibaba.com",
            "*.alibaba.com",
            "alibabausercontent.com",
            "*.alibabausercontent.com",
            "mmstat.com",
            "*.mmstat.com",
            "aliapp.org",
            "*.aliapp.org",
            "alimama.com",
            "*.alimama.com",
            "1688.com",
            "*.1688.com",
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
    # 官方特征库没有条目的应用，占用 9-* 自定义编号段（官方 db 未使用 9 开头
    # 的 index）。只写各应用**独占**的域名：字节系共享域名（snssdk/bytescm）
    # 同时服务抖音等多款应用，收进来会把别的应用流量错记到今日头条头上。
    "9-201-1-0": {
        "name": "豆包",
        "category": "AI/聊天",
        "hosts": [
            "doubao.com",
            "*.doubao.com",
        ],
    },
    "9-202-1-0": {
        "name": "DeepSeek",
        "category": "AI/聊天",
        "hosts": [
            "deepseek.com",
            "*.deepseek.com",
        ],
    },
    "9-203-1-0": {
        "name": "今日头条",
        "category": "新闻/资讯",
        "hosts": [
            "toutiao.com",
            "*.toutiao.com",
            "toutiaocdn.com",
            "*.toutiaocdn.com",
        ],
    },
    "9-204-1-0": {
        "name": "唯品会",
        "category": "综合电商",
        "hosts": [
            "vipshop.com",
            "*.vipshop.com",
            "vip.com",
            "*.vip.com",
        ],
    },
    "9-205-1-0": {
        "name": "顺丰速递",
        "category": "生活/物流",
        "hosts": [
            "sf-express.com",
            "*.sf-express.com",
        ],
    },
    # 夸克浏览器（UC/阿里系）：官方库只有 `pp.uc.cn`（归给豌豆荚），
    # quark.cn / myquark.cn 无人认领，实测路由器 db 里没有冲突条目。
    "9-206-1-0": {
        "name": "夸克",
        "category": "工具/浏览器",
        "hosts": [
            "quark.cn",
            "*.quark.cn",
            "myquark.cn",
            "*.myquark.cn",
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
                # Not in the official library yet: create the entry in the exact
                # shape the official db uses (index/name/rules only — `custom`
                # is API metadata and must never land in the router database,
                # and `payloads: []` mirrors the official host rules such as
                # 淘宝 18-4-2-0). Appended last so the official, more specific
                # entries keep winning the match.
                new_app = {
                    "index": idx,
                    "name": patch["name"],
                    "rules": [{"protocol": "host", "hosts": list(patch["hosts"]), "payloads": []}],
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

        # Force guarded WAN traffic onto IPv4 (where RDPI can identify it)
        # without breaking LAN-local IPv6 or replies headed back to the device.
        _remote_exec(client, "ip6tables -D FORWARD -m set --match-set child_guard_ip6_block dst -j REJECT --reject-with icmp6-adm-prohibited 2>/dev/null || true")
        _remote_exec(client, "ip6tables -D FORWARD -m set --match-set child_guard_ip6_block src -j REJECT --reject-with icmp6-adm-prohibited 2>/dev/null || true")
        _remote_exec(client, "ip6tables -C FORWARD ! -o br-lan -m set --match-set child_guard_ip6_block src -j REJECT --reject-with icmp6-adm-prohibited 2>/dev/null || ip6tables -I FORWARD 1 ! -o br-lan -m set --match-set child_guard_ip6_block src -j REJECT --reject-with icmp6-adm-prohibited")

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

