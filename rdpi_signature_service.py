"""RDPI 自定义应用特征：校验、合并、算卡片数字。

这里只管「一份合法的 `/usr/share/ndpi/db.default.json` 应该长什么样」。文件的读和写
都在路由器上：agent 把整库推上来（`hub.py` 的 `/api/router/rdpi/ingest`），要改就把
合并后的整库作为一条 `write_db` 命令下发回去。这个模块不再自己连路由器 —— 以前它用
paramiko 反向 SSH 进来，host/端口写死在默认值里，路由器一重拨就整块失效。
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Dict, List, Optional, Tuple

REMOTE_DB_PATH = "/usr/share/ndpi/db.default.json"
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


def summarize_rdpi_db(db: Dict[str, Any]) -> Dict[str, Any]:
    """从一份 RDPI 库算出卡片要的那几个数。

    单独拆出来是因为这份库现在有两个来源：路由器 agent 出站推进来的副本，和（兜底）
    Hub 自己 SSH 去读。判断「哪些算自定义」只能有一份，否则两条路会慢慢给出不一样
    的数字。
    """
    apps = db.get("apps")
    apps = apps if isinstance(apps, list) else []
    total_count = len(apps)
    # Custom apps: index starts with '9' or has 'custom': True
    custom_apps = [
        a for a in apps
        if str(a.get("index", "")).startswith("9")
        or a.get("custom") is True
        or any(a.get("index") == idx and a.get("name") == patch["name"]
               for idx, patch in CURATED_SIGNATURE_EXTENSIONS.items())
    ]
    return {
        "ok": True,
        "totalCount": total_count,
        "officialCount": max(0, total_count - len(custom_apps)),
        "customCount": len(custom_apps),
        "customSignatures": custom_apps,
        "template": STANDARD_RDPI_TEMPLATE,
    }


def merge_signature_into_db(db: Dict[str, Any], payload: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """把一条自定义特征合进整库，返回 (新库, 给界面的字段)。

    只合并、不落盘 —— 落盘是 agent 的 `write_db` 命令。校验失败抛 ValueError。
    """
    signature = validate_signature_object(payload)
    apps = list(db.get("apps") or [])

    idx = signature["index"]
    name = signature["name"]
    existing = next((a for a in apps if a.get("index") == idx or a.get("name") == name), None)

    db_signature = {key: copy.deepcopy(value) for key, value in signature.items() if key != "custom"}
    if existing is not None:
        # 只更新官方形态里有的字段；导入没提到的（例如 `note`）保留路由器上的原值。
        existing.update(db_signature)
        action = "updated"
    else:
        apps.append(db_signature)
        action = "added"

    db["apps"] = apps
    return db, {"action": action, "index": idx, "name": name, "totalCount": len(apps)}


def remove_signature_from_db(db: Dict[str, Any], target_index_or_name: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """按 index 或 name 删掉一条；没删到就返回 (None, 说明)。"""
    target = str(target_index_or_name or "").strip()
    if not target:
        raise ValueError("Target index or name is required")
    apps = db.get("apps") or []
    kept = [a for a in apps if a.get("index") != target and a.get("name") != target]
    if len(kept) == len(apps):
        return None, {"ok": False, "error": f"No signature found matching '{target}'"}
    db["apps"] = kept
    return db, {"deleted": target, "totalCount": len(kept)}


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


def apply_curated_extensions(db: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """把策划好的高频域名并进官方条目，返回 (新库, 给界面的字段)；没有新东西就 (None, 说明)。

    官方条目一律不删，只往它的 host 规则里补域名。新增的条目排在最后，让官方那些
    更具体的规则继续优先命中。
    """
    apps = list(db.get("apps") or [])

    total_hosts_added = 0
    enhanced_apps: List[str] = []

    for idx, patch in CURATED_SIGNATURE_EXTENSIONS.items():
        app = next((a for a in apps if a.get("index") == idx or a.get("name") == patch["name"]), None)
        if not app:
            # 官方库里还没有这一条：按官方 db 的形状新建（只有 index/name/rules ——
            # `custom` 是接口元数据，绝不能落进路由器数据库；`payloads: []` 对齐淘宝
            # 18-4-2-0 这类官方 host 规则）。
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
        for host in patch["hosts"]:
            if host not in current_hosts:
                current_hosts.append(host)
                added_here += 1

        host_rule["hosts"] = current_hosts
        total_hosts_added += added_here
        enhanced_apps.append(f"{patch['name']} (+{added_here} 域名)")

    stats = {"totalHostsAdded": total_hosts_added, "enhancedApps": enhanced_apps, "totalApps": len(apps)}
    if not total_hosts_added:
        # 一个域名都没新增，就别让路由器白热重载一次。
        return None, {**stats, "ok": True, "message": "高频特征包已是最新状态"}
    db["apps"] = apps
    return db, stats
