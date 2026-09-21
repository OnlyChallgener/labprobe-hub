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
                    "customgame.com",
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


# 引擎按**裸域名后缀**匹配（官方库 1093 个主机里没有一个带 `*`），所以这里一律
# 只写裸域名：`img.example.com` 这种精确主机名也照写，通配写法是永远不会命中的
# 死规则，留着只会让人误以为已经覆盖了整个域。
# 共享基础设施域名（阿里 alicdn/mmstat、字节 snssdk/zijieapi/pstatp/bytecdn、
# 腾讯 gtimg/qpic/dldir1、小米 mi.com、百度 bdstatic/bcebos、个推 getui/gepush）
# 一律不写：绑上去会把别的应用流量错记过来。
CURATED_SIGNATURE_EXTENSIONS: Dict[str, Dict[str, Any]] = {
    "10-1-2-0": {
        "name": "微信视频号",
        "category": "短视频/直播",
        "hosts": [
            "vweixinfp.tc.qq.com",
            "channels.weixin.qq.com",
            "wxapp.tc.qq.com",
            "finderv1.video.qq.com",
            "finderd1p.video.qq.com",
            "finder.video.qq.com",
            "live.weixin.qq.com",
            "voipfinderliveplay.wxqcloud.qq.com",
        ],
    },
    "7-1-2-12": {
        "name": "微信_other",
        "category": "即时通讯/音视频通话",
        "hosts": [
            "weixin.qq.com",
            "szshort.weixin.qq.com",
            "szextshort.weixin.qq.com",
            "szminorshort.weixin.qq.com",
            "wx.qlogo.cn",
        ],
    },
    "10-5-1-0": {
        "name": "抖音",
        "category": "短视频/直播",
        "hosts": [
            "amemv.com",
            "douyincdn.com",
            "douyinpic.com",
            "douyinvod.com",
            "douyin.com",
            "douyinstatic.com",
        ],
    },
    "10-146-1-0": {
        "name": "快手",
        "category": "短视频/直播",
        "hosts": [
            "gifshow.com",
            "kuaishou.com",
            "yximgs.com",
            "ksapisrv.com",
            "kwai.com",
            "kwimgs.com",
            "kwaicdn.com",
        ],
    },
    "18-158-1-0": {
        "name": "拼多多",
        "category": "综合电商",
        "hosts": [
            "yangkeduo.com",
            "pinduoduo.com",
            "pddpic.com",
            "pinduoduo.net",
        ],
    },
    "18-159-1-0": {
        "name": "京东",
        "category": "综合电商",
        "hosts": [
            "360buy.com",
            "jd.com",
            "360buyimg.com",
            "jd.hk",
        ],
    },
    # 阿里CDN：官方库把阿里系基础设施散在 钉钉_aliyuncs / 钉钉_alibaba / 钉钉_taobao
    # 这些派生条目里，正主（淘宝/天猫/闲鱼/饿了么）反而没有归属，于是 阿里CDN 兜住
    # 没有明确应用的阿里域名。编号用 9-217-1-0 —— 自定义段，线上库里确认过是空的；
    # 原来写的 18-4-3-0 在路由器上是一条重复的 云闪付，按编号合并就把 CDN 域名塞进
    # 了支付应用。
    # `alicdn.com` 以前被 `钉钉_alicdn`（位置 296）整片占着，摘掉之后才轮得到这里；
    # 优酷自己的 `ykimg.alicdn.com` 排在库前面，继续归优酷，不抢。
    # 菜鸟：用户列在「有独立特征」那一档里，但线上库审计下来 `cainiao.com` 是无主
    # 的 —— 属于「可能有漏掉」，这里补上独立条目，不并进 阿里CDN。
    "9-218-1-0": {
        "name": "菜鸟",
        "category": "生活/物流",
        "hosts": [
            "cainiao.com",
            "cainiao.cn",
            "guoguo-app.com",
        ],
    },
    # 阿里CDN 是**阿里系的兜底桶**（2026-09-21 定的规则）：淘宝 / 支付宝 / 钉钉 /
    # 优酷视频 / 阿里云盘 / 夸克 / 饿了么 / 菜鸟 这些有独立条目的继续按自己显示，
    # 没有独立条目的阿里系应用（闲鱼、高德、飞猪、一淘、1688、阿里妈妈…）落到这里。
    #
    # CDN 边缘主机只放行精确子域，不整片兜 `alicdn.com`：实测公共 DNS
    # 114.114.114.114 也被记成了阿里CDN，说明裸后缀会把「查询过某个 alicdn 名字」
    # 的流一起卷进来。名单取自官方库里 `钉钉_alicdn` 原本占着的那些主机 —— 主机是
    # 真的，只是不该记在钉钉名下。`ykimg.alicdn.com` / `liangcang-material.alicdn.com`
    # 官方已绑给优酷，不抢。
    "9-217-1-0": {
        "name": "阿里CDN",
        "category": "网络服务/CDN",
        "hosts": [
            "at.alicdn.com",
            "g.alicdn.com",
            "gw.alicdn.com",
            "gtms04.alicdn.com",
            "hudong.alicdn.com",
            "img.alicdn.com",
            "o.alicdn.com",
            "tbexpand.alicdn.com",
            "goofish.com",
            "amap.com",
            "fliggy.com",
            "etao.com",
            "tanx.com",
            "aliyuncs.com",
            "aliyun.com",
            "alibaba.com",
            "alibabausercontent.com",
            "mmstat.com",
            "aliapp.org",
            "alimama.com",
            "1688.com",
        ],
    },
    "18-4-2-0": {
        "name": "淘宝",
        "category": "综合电商",
        "hosts": [
            "taobao.com",
            "tbcdn.cn",
            "tmall.com",
            "tbcache.com",
            "taobaocdn.com",
            "m.taobao.com",
            "acs.m.taobao.com",
            "gw.taobao.com",
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
        ],
    },
    "9-202-1-0": {
        "name": "DeepSeek",
        "category": "AI/聊天",
        "hosts": [
            "deepseek.com",
        ],
    },
    "9-203-1-0": {
        "name": "今日头条",
        "category": "新闻/资讯",
        "hosts": [
            "toutiao.com",
            "toutiaocdn.com",
        ],
    },
    "9-204-1-0": {
        "name": "唯品会",
        "category": "综合电商",
        "hosts": [
            "vipshop.com",
            "vip.com",
        ],
    },
    "9-205-1-0": {
        "name": "顺丰速递",
        "category": "生活/物流",
        "hosts": [
            "sf-express.com",
        ],
    },
    # 夸克浏览器（UC/阿里系）：官方库只有 `pp.uc.cn`（归给豌豆荚），
    # quark.cn / myquark.cn 无人认领，实测路由器 db 里没有冲突条目。
    "9-206-1-0": {
        "name": "夸克",
        "category": "工具/浏览器",
        "hosts": [
            "quark.cn",
            "myquark.cn",
        ],
    },
    # 下面这批是 2026-09-21 新增的：官方库里根本没有这些应用。域名全部只用
    # **裸域名**（引擎按裸域名后缀匹配，官方库 1093 个主机里没有一个带 `*`），
    # 并且只收各应用独占的域名 —— 阿里 alicdn/mmstat、字节 snssdk/pstatp/
    # bytecdn、腾讯 gtimg/qpic/dldir1、小米 mi.com、百度 bdstatic/bcebos 这些
    # 共享基础设施一律不写，否则会把别的应用流量错记过来。
    # 企业微信官方有条目（8-1-3-0），但它的主机字段是个残缺的 `wework` token，
    # 按 name 命中后直接往官方条目里补真域名，不另建编号。
    "8-1-3-0": {
        "name": "企业微信",
        "category": "办公协作",
        "hosts": [
            "work.weixin.qq.com",
            "qyapi.weixin.qq.com",
            "wwcdn.weixin.qq.com",
            "wework.qpic.cn",
        ],
    },
    # 百度 App：官方 7-3-2-0 竟然不含 `www.baidu.com`，而 `baidu.com` 这个裸后缀
    # 会把百度网盘/贴吧/地图一起吞掉，所以只补精确主机名。`tieba.baidu.com` 官方
    # 已经绑给百度贴吧（7-3-1-0），不再抢。
    "7-3-2-0": {
        "name": "百度",
        "category": "工具/搜索",
        "hosts": [
            "www.baidu.com",
            "news.baidu.com",
        ],
    },
    "9-207-1-0": {
        "name": "饿了么",
        "category": "生活/外卖",
        "hosts": [
            "ele.me",
            "elemecdn.com",
            "elemecdn.cn",
            "elenet.me",
            "eleme.cn",
            "eleme.com.cn",
            "ele.to",
            "youcaishop.cn",
            "xyzele.com",
            "fengniaopaotui.cn",
            "fengniaozhongbao.cn",
        ],
    },
    "9-208-1-0": {
        "name": "番茄免费小说",
        "category": "阅读/资讯",
        "hosts": [
            "fqnovel.com",
            "fqnovelstatic.com",
            "fqnovelpic.com",
            "fqnovelvod.com",
            "fqnovelop.com",
            "fanqiesdk.com",
            "fanqiesdkpic.com",
            "fanqiesdkstatic.com",
            "fanqieopen.com",
            "fanqiecopyright.com",
            "changdunovel.com",
            "novelfm.com",
            "novelfmpic.com",
            "novelfmstatic.com",
        ],
    },
    "9-209-1-0": {
        "name": "西瓜视频",
        "category": "短视频/直播",
        "hosts": [
            "ixigua.com",
            "ixiguavideo.com",
            "xiguaapp.com",
            "xiguavideo.cn",
            "xiguavideo.net",
            "xiguashipin.cn",
            "365yg.com",
            "bdxiguaimg.com",
            "bdxiguavod.com",
            "bdxiguastatic.com",
        ],
    },
    # 醒图是字节的美图工具，独占域名只有 retouchpics.com。`xitu.io` 是稀土掘金，
    # 不是醒图 —— 网上不少规则表把它当成醒图，抄过来会把开发者社区记成修图软件。
    "9-210-1-0": {
        "name": "醒图",
        "category": "影像/剪辑",
        "hosts": [
            "retouchpics.com",
        ],
    },
    "9-211-1-0": {
        "name": "海尔智家",
        "category": "智能家居",
        "hosts": [
            "haier.net",
            "ehaier.com",
            "haige.com",
        ],
    },
    # 美的美居：`mics.me` 是它废弃的旧云（已 NXDOMAIN），别照抄网上还在传的规则。
    "9-212-1-0": {
        "name": "美的美居",
        "category": "智能家居",
        "hosts": [
            "smartmidea.net",
            "appsmb.com",
            "midea.com",
        ],
    },
    # TP-LINK 物联：`tplinkwifi.net` / `tplinklogin.net` 是局域网管理页，绑进来
    # 会把内网流量算成 App 使用，故意不写。
    "9-213-1-0": {
        "name": "TP-LINK物联",
        "category": "智能家居",
        "hosts": [
            "tp-link.com.cn",
            "tplink.com.cn",
            "tplinkcloud.com.cn",
            "tplinkiot.com",
        ],
    },
    # 三角洲行动：腾讯 GCloud 的节点域名是 `*.500638030-x-y.gcloudsvcs.com`
    # 这种按标题分配的形态，只能写完整节点名；绑 `gcloudsvcs.com` 后缀会把一整
    # 片腾讯游戏都记成它。`df-gcloud.*.tcdnos.com` 是共享 CDN，同样不绑。
    "9-214-1-0": {
        "name": "三角洲行动",
        "category": "游戏",
        "hosts": [
            "df.qq.com",
            "dir.500638030-2-1.gcloudsvcs.com",
            "puffer.500638030-11-1.gcloudsvcs.com",
        ],
    },
    "9-215-1-0": {
        "name": "山姆会员商店",
        "category": "综合电商",
        "hosts": [
            "samsclub.cn",
            "samsclub.com.cn",
        ],
    },
    # 小爱同学没有可用的独占域名：它跑在小米共用云上（mi.com / io.mi.com /
    # mistat.xiaomi.com 同时服务米家、小爱音箱、系统服务），绑进来会把米家记成
    # 小爱。下面三个是已注册但未经真机验证的候选，命中不了只会显示未识别，不会
    # 抢别的应用；等一次真机抓包再定。
    "9-216-1-0": {
        "name": "小爱同学",
        "category": "智能家居",
        "hosts": [
            "xiaoaiassist.com",
            "xiaomixiaoai.com",
            "micoce.com.cn",
        ],
    },
}


#: 官方库里抢别家域名的条目 —— 只往官方条目里**补**域名修不好误识别，必须能把错的
#: 域名摘掉。每条都在 2026-09-21 对着提取出来的官方库（472 条）逐条核对过。
#: 值是主机名列表表示只摘这些主机；值是 ``"*"`` 表示整条删除（它的全部匹配子都是
#: 别家的域名，留着就一定会误判）。
CURATED_SIGNATURE_REMOVALS: Dict[str, Any] = {
    # 钉钉_alipay 的三个主机全是支付宝的，而它排在数组第 300 位，真正的支付宝
    # 兜底条目 18-4-1-14 在第 433 位 —— 「支付宝被记成钉钉」就是这么来的。
    "8-4-1-11": "*",
    # 官方库把阿里系的 CDN 和埋点域名整片绑给了钉钉：`钉钉_alicdn`（位置 296）
    # 占了 img/gw/o/at/g/alibaba 等 8 个 alicdn 主机，`钉钉_mmstat`（位置 299）
    # 占了 4 个 mmstat 埋点主机。淘宝/天猫/闲鱼/饿了么的图片和埋点流量因此全被记
    # 成钉钉，而排在库尾的 阿里CDN 一条都拿不到 —— 这就是「阿里CDN 从来没识别过」
    # 的原因。这两条里没有任何钉钉自己的域名，整条删掉。
    # 注意：「数组位置靠前的规则优先」是 2026-09-21 从 支付宝→钉钉 这个现象推出来
    # 的假设，还没在固件上实测过；模拟流量验证跑通才算确认。
    "8-4-1-6": "*",
    "8-4-1-10": "*",
    # 飞书_other 收的是字节跳动公共基础设施域名，同时服务抖音/今日头条/西瓜；
    # api.feelgood.cn 才是飞书自己的（feelgood 是 Lark 的内部代号），保留。
    "8-5-1-4": [
        "cdn-tos.bytegoofy.com", "cdn-tos.bytescm.com", "hera.byteimg.com",
        "i.snssdk.com", "mcs.snssdk.com", "mon.zijieapi.com",
        "security.snssdk.com", "short.ibytedapm.com", "vcs.zijieapi.com",
        "zeus.byteimg.com",
    ],
    # 腾讯会议_login 里除 imtt 之外全是腾讯全线共用的信标/长连接域名，会把微信、
    # QQ、视频号的后台流量记成腾讯会议。imtt 才是腾讯会议的 SDK 命名空间。
    "8-1-1-1": [
        "android.rqd.qq.com", "oth.str.beacon.qq.com", "otheve.beacon.qq.com",
        "dp3.qq.com", "h.trace.qq.com", "p.l.qq.com", "sdk.e.qq.com",
        "tangram.e.qq.com", "tdid.m.qq.com", "ten.sngapm.qq.com",
        "us.l.qq.com", "work.medialab.qq.com",
    ],
    # 微软的 CDN 域名出现在腾讯会议条目里，明显是抄错的。
    "8-1-1-4": ["vo.msecnd.net"],
    # 这条唯一的主机是微软登录域名，摘掉就没有任何匹配子了，只能整条删。
    "8-1-1-5": "*",
    # 安全教育平台_null_relation 四个主机全是个推/gepush 推送 SDK —— 任何用个推的
    # App 都会被记成安全教育平台。
    "8-81-1-15": "*",
    # 线上路由器有一条重复的 云闪付 占在 18-4-3-0（真正的在 18-156-1-0）。它是早先
    # 下发留下的产物，上一轮又按 index 把 alicdn/mmstat 等 9 个阿里域名并了进来 ——
    # 支付应用不该兜 CDN 流量。删的时候必须核对名字：只按编号动手是这一批问题的根源。
    "18-4-3-0": {"delete_if_named": "云闪付"},
    # 阿里CDN 早期版本整片兜过裸 `alicdn.com`，实测公共 DNS 114.114.114.114 会被它
    # 卷进来记成阿里CDN。合并是只追加的，改特征表里的名单删不掉已经落到路由器上的
    # 那一行，必须在这里显式摘掉，再由下面的白名单换成精确子域。
    "9-217-1-0": ["alicdn.com"],
}


#: 校验器认的这些字段里至少有一个非空，规则才算有匹配子 —— 与
#: ``validate_signature_object`` 的判定保持一致，别在这里放宽。
_MATCHER_FIELDS = ("hosts", "payloads", "payload_length", "http-gets",
                   "http-posts", "user-agents")


def _has_matcher(rule: Dict[str, Any]) -> bool:
    return any(isinstance(rule.get(field), list) and rule[field] for field in _MATCHER_FIELDS)


def apply_removals(apps: List[Dict[str, Any]]) -> tuple:
    """按 :data:`CURATED_SIGNATURE_REMOVALS` 摘主机 / 删条目，返回三项统计。

    只按 index 精确匹配，不按 name —— 官方库的 name 有重名和 ``_weak_relation``
    后缀变体。摘完一个匹配子都不剩的条目会被跳过而不是清空，否则整库过不了
    ``validate_signature_object``，路由器那边还会回滚。
    """
    removed_hosts = 0
    removed_apps: List[str] = []
    skipped: List[str] = []
    for idx, spec in CURATED_SIGNATURE_REMOVALS.items():
        app = next((a for a in apps if a.get("index") == idx), None)
        if app is None:
            continue
        name = str(app.get("name") or idx)
        if isinstance(spec, dict):
            expected = str(spec.get("delete_if_named") or "")
            if name != expected:
                # 编号在线上库里被谁占着，只有路由器自己知道；名字对不上就不动手。
                skipped.append(f"{name} ({idx} 不是 {expected}，保留)")
                continue
            apps.remove(app)
            removed_apps.append(f"{name} ({idx} 整条删除)")
            continue
        if spec == "*":
            apps.remove(app)
            removed_apps.append(f"{name} ({idx} 整条删除)")
            continue
        drop = set(spec)
        rules = app.get("rules") or []
        host_rule = next((r for r in rules if r.get("hosts")), None)
        if host_rule is None:
            skipped.append(f"{name} ({idx} 没有主机规则)")
            continue
        left = [h for h in host_rule["hosts"] if h not in drop]
        if len(left) == len(host_rule["hosts"]):
            continue                      # 这条里没有要摘的主机
        if left:
            removed_hosts += len(host_rule["hosts"]) - len(left)
            host_rule["hosts"] = left
            continue
        # 摘空了：留着一条空规则整库就过不了校验，只能整条撤掉。
        if any(r is not host_rule and _has_matcher(r) for r in rules):
            removed_hosts += len(host_rule["hosts"])
            rules.remove(host_rule)
        else:
            skipped.append(f"{name} ({idx} 摘完就没有匹配子了，保留)")
    return removed_hosts, removed_apps, skipped


def _same_app_family(official_name: str, wanted_name: str) -> bool:
    """官方条目是不是就是我们要增强的那个应用。

    官方库会把一个应用拆成 `抖音系列` / `微信_other` / `优酷视频_weak_relation`
    这种派生名，中继按 `_` 截断后显示成主应用名。只认这三种关系，别的都算不相
    干 —— 路由器上的 18-4-3-0 是一条重复的 云闪付，早先按 index 直接合并把
    alicdn/mmstat 塞进了支付应用，把阿里 CDN 流量全记成了云闪付。
    """
    official = str(official_name or "").strip()
    wanted = str(wanted_name or "").strip()
    return (official == wanted
            or official.startswith(wanted + "系列")
            or official.startswith(wanted + "_"))


def _free_custom_index(apps: List[Dict[str, Any]], wanted: str, fallback: str) -> str:
    """给一个新应用挑一个路由器上真的没被占用的编号。

    编号只能对着**线上库**分配：提取出来的官方固件库是 472 条，路由器上是 486 条
    （历次下发新增的），拿固件库判断「这个编号是空的」会撞车。
    """
    taken = {str(a.get("index")) for a in apps}
    if fallback not in taken:
        return fallback
    for slot in range(217, 400):
        candidate = f"9-{slot}-1-0"
        if candidate not in taken:
            return candidate
    raise ValueError(f"没有可用的自定义编号给 {wanted}")


def apply_curated_extensions(db: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """把策划好的高频域名并进官方条目，返回 (新库, 给界面的字段)；没有新东西就 (None, 说明)。

    官方条目一律不删，只往它的 host 规则里补域名。新增的条目排在最后，让官方那些
    更具体的规则继续优先命中。
    """
    apps = list(db.get("apps") or [])

    # 先摘再补：删掉的条目不该在下一轮按 name 撞上别的补丁。
    hosts_removed, removed_apps, removal_skipped = apply_removals(apps)

    total_hosts_added = 0
    enhanced_apps: List[str] = list(removed_apps)

    for idx, patch in CURATED_SIGNATURE_EXTENSIONS.items():
        # 先认「同编号且同族」的官方条目（10-5-1-0 在路由器上叫 抖音系列），再按
        # 名字认；两个都不满足就当新应用建，编号再对着线上库挑一次真空位。
        app = next((a for a in apps
                    if a.get("index") == idx
                    and _same_app_family(a.get("name"), patch["name"])), None)
        if app is None:
            app = next((a for a in apps if a.get("name") == patch["name"]), None)
        if not app:
            # 官方库里还没有这一条：按官方 db 的形状新建（只有 index/name/rules ——
            # `custom` 是接口元数据，绝不能落进路由器数据库；`payloads: []` 对齐
            # 官方 host 规则）。
            new_app = {
                "index": _free_custom_index(apps, patch["name"], idx),
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

    stats = {
        "totalHostsAdded": total_hosts_added,
        "totalHostsRemoved": hosts_removed,
        "removedApps": removed_apps,
        "removalSkipped": removal_skipped,
        "enhancedApps": enhanced_apps,
        "totalApps": len(apps),
    }
    if not total_hosts_added and not hosts_removed and not removed_apps:
        # 一个域名都没变化，就别让路由器白热重载一次。
        return None, {**stats, "ok": True, "message": "高频特征包已是最新状态"}
    db["apps"] = apps
    return db, stats
