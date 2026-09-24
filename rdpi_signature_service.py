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

#: App 里「下载模板」拿到的就是这一份，所以它必须是一个**照抄就能用**的形状：
#: 三条实测出来的硬规矩都写在 comment 里，并且模板自身能通过校验。
#:   1. host 规则必须带 ``payloads: []`` —— 缺了它，引擎在这条之后停止解析域名规则，
#:      整库域名识别一起停摆（2026-09 实测过的那次事故就是这个形状）。
#:   2. 域名只写裸域。引擎按裸域后缀匹配，``.example.com`` 和 ``*.example.com``
#:      都永远不会命中（官方库 1093 个主机里一个带点的都没有）。
#:   3. 一条规则只放一种匹配子。库里 1100 条规则没有一条是 ``protocol: tcp`` 又同时
#:      带 hosts 和 payloads 的；要按域名走就单独一条 host 规则。
STANDARD_RDPI_TEMPLATE: Dict[str, Any] = {
    "$schema": "labprobe-rdpi-v1",
    "comment": (
        "锐捷/Reyee RDPI 自定义应用特征包标准格式，适用于儿童上网与流量审计。"
        "三条硬规矩：① host 规则必须带 payloads:[]，缺了引擎会停掉后面所有域名规则；"
        "② 域名只写裸域，.example.com 和 *.example.com 永远不会命中；"
        "③ 一条规则只放一种匹配子，别把 hosts 和 payloads 写进同一条 tcp 规则。"
        "index 用 9-开头且线上没被占用的编号；撞上一个编号不同名的已有条目会被拒绝导入。"
        "本地格式检查与模板不保证路由器加载或识别，导入后请真机验证一次命中。"
    ),
    "app": {
        "index": "9-999-1-0",
        "name": "自定义应用示例（请替换）",
        "rules": [
            {
                "protocol": "host",
                "hosts": [
                    "customgame.com",
                    "login.customgame.cn"
                ],
                # 这个空数组不是装饰：删掉它，整库的域名规则都会跟着失效。
                "payloads": []
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
                # 端口规则的形状照库里唯一先例 4-1-3-2 英雄联盟PC_Gaming：
                # port_limit 是 [{min,max}] 列表，不是 {"udp": ["2481"]} 这种字典。
                "protocol": "udp",
                "port_limit": [{"min": 2480, "max": 2482}],
                "payloads": [],
                "payload_length": [{"stage": 0, "length": 28}]
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
            # 引擎按裸域后缀匹配，`.example.com` 和 `*.example.com` 都永远不会命中。
            # 与其收下这条永不生效的规则（作者会以为已经覆盖了），不如当场拒绝。
            inert = [h for h in r["hosts"] if "*" in h or h.strip().startswith(".") or h.strip().endswith(".")]
            if inert:
                raise ValueError(
                    "RDPI hosts must be bare domains without '*' or leading/trailing dots; "
                    f"inert form rejected: {sorted(inert)}")
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

        if "hosts" in rule_entry and "payloads" not in rule_entry:
            # 官方库里每一条 host 规则都带 `payloads`（哪怕是空数组）。实测：少这个键，
            # 引擎解析到该条就中断，**它之后所有条目的域名规则一起失效** —— 2026-09-21
            # 那次「补 protocol=host」只补了 protocol，结果整库识别停摆，直到把库换回
            # 旧快照才恢复。宁可替它补一个空数组，也不能留下这种形状。
            rule_entry["payloads"] = []

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
               and idx not in CURATED_OFFICIAL_MERGE_INDEXES
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

    # 合并是**整条覆盖** rules 的，所以必须确认撞上的就是同一个应用：编号相同但名字
    # 不同，等于把别家条目（可能是官方条目）连规则一起换掉；名字相同但编号不同，会把
    # 条目挪到别的编号上，还可能撞上第三条。两种都拒绝，让作者改对再导入。
    if existing is not None and (existing.get("index") != idx or existing.get("name") != name):
        raise ValueError(
            f"导入被拒绝：库里已有 {existing.get('index')} {existing.get('name')}，"
            f"与要写入的 {idx} {name} 编号/名字不一致。改名字就单独建一条新编号，"
            f"要更新已有条目就让两者与库里完全对齐。")

    db_signature = {key: copy.deepcopy(value) for key, value in signature.items() if key != "custom"}
    if existing is not None:
        # 只更新官方形态里有的字段；导入没提到的（例如 `note`）保留路由器上的原值。
        existing.update(db_signature)
        action = "updated"
    else:
        apps.append(db_signature)
        action = "added"

    budget = entry_budget_error(apps)
    if budget:
        raise ValueError(budget)

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
    # 京东：主域 jd.com / 360buyimg.com 两个裸域就把 App 流量盖满了（2026-09-24 真机抓包
    # 核对：mars.jd.com ×471、storage.jd.com ×9、ex.m.jd.com ×6、api.m.jd.com ×5、
    # img30/img20/img14…/m11/m15/storage11/storage23.360buyimg.com、sso/sh/sgm-w/dns/ccc-x/
    # cactus/uranus/gias/jcap/blackhole/anti-sdk-report/h5speed/sdkfp/pro.m.jd.com 全部命中）。
    #
    # 漏的是**视频/图片域 300hu.com**（真机 vod ×7、discover ×3、jvod ×2，共 12 次），
    # 它不在 jd.com 下面，所以原来一条都盖不住。归属证据三条：
    #   1. 京东联盟开放 API 文档里商品视频的 playUrl 就是 https://vod.300hu.com/... ，
    #      主图地址是 300hu.com/4c1f7a6atransbjngwcloud1oss/...jpg；
    #   2. 京东国际商品详情页的视频 URL 形如 jvod.300hu.com/vod/product/<sku>/...mp4；
    #   3. Netify 把 jvod.300hu.com.gslb.qianxun.com 标为 Jingdong，走 Wangsu(网宿) CDN。
    # 裸域一条盖住 vod / jvod / discover / img / m 全部子域。
    "18-159-1-0": {
        "name": "京东",
        "category": "综合电商",
        "hosts": [
            "360buy.com",
            "jd.com",
            "360buyimg.com",
            "jd.hk",
            "300hu.com",
        ],
    },
    # 云闪付：路由器上还有一条重复的 18-4-3-0（正主就是这条 18-156-1-0），下面按名字
    # 守卫把它删掉之前，先把它独占的 unionpay 一族域名并到正主身上，否则删一条就少一片
    # 覆盖。通配写法（`*.unionpay.com`）在这个引擎里永远不命中，只写裸域名。
    "18-156-1-0": {
        "name": "云闪付",
        "category": "支付",
        "hosts": [
            "unionpay.com",
            "chinaunionpay.com",
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
    # 米家：线上库里只有 小米应用商店（19-165-1-0），米家自己一条都没有 —— 审计
    # 确认过。`io.mi.com` 是米家和小爱音箱共用的设备云，绑给任何一方都会把另一方
    # 记错，所以这里只收米家自己的域名。
    #
    # 2026-09-21 对着用户给的参考稿核过一遍，收的域名全部本地实测可解析；参考稿里
    # 没解析出来的两个（io.mi.com 顶点、api.iot.mi.com）不收 —— 解析不到的主机名
    # 永远不会出现在流里，写进去只是看着热闹。
    # 参考稿的另外两条规则也没采用：
    #   * `protocol: tcp` 同时带 hosts+payloads —— 全库 1100 条规则里这种形状 0 次；
    #   * `protocol: udp` 匹配 pos 12 的 "mio" —— 那是 miIO 局域网发现协议，
    #     每台小米/Broadlink 设备都在广播，4 字节定长匹配又太弱，收进来会把
    #     邻居设备的局域网喊话算成「米家在用」，和参考稿自称的「零误判」正好相反。
    # 代价说清楚：iot.mi.com / access.b.iot.mi.com 是小米设备云入口，被守护的音箱、
    # 摄像头自己也会连它们，于是那些设备的列表里会出现「米家」。要的是米家能被认出来，
    # 这一层混用在封禁侧无害（都是同一个云），在统计侧如实标注。
    "9-219-1-0": {
        "name": "米家",
        "category": "智能家居",
        "hosts": [
            "home.mi.com",
            "api.home.mi.com",
            "api.io.mi.com",
            "iot.mi.com",
            "access.b.iot.mi.com",
            # 米家特征文档里的第四个：device.io.mi.com 解析到 124.251.58.94，和已在库的
            # iot.mi.com（124.251.58.134）同段，同一运营方。文档建议的裸 io.mi.com 仍然
            # 不写 —— 那会把小爱音箱和小米系统服务全吸进米家。
            "device.io.mi.com",
            # 2026-09-24 真机（192.168.0.156 开米家 App 控设备）：流量大头全在
            # **mijia.tech** 上 —— app.processor.smartcamera.api.mijia.tech ×23、
            # app.business.smartcamera.api.mijia.tech ×4、api.mijia.tech ×4、
            # core.api.mijia.tech ×3，原来这 7 个域一个都没盖住。
            # 归属铁证：api.mijia.tech 解析 110.43.87.16 / 202.69.4.15 / 220.181.106.173，
            # 与在库的 api.io.mi.com 完全相同；第三方「Xiaomi Home Android app」域名清单
            # 也列着 api / core.api / stream.api / sts.api .mijia.tech。
            # 裸域一条盖住全部变体，包括带业务前缀的 smartcamera 那些。
            "mijia.tech",
        ],
    },
    # mijia.ai 已摘除（2026-09-24）：实测 https://mijia.ai 返回的是
    # 「mijia.ai for sale | Spaceship.com」—— 一个待售域名（AWS 44.232.173.249），
    # 不是小米在用的域，真机抓包零命中。留着就是「名字像米家就收」的典型误收。
    # UU远程（网易远程桌面）。触发原因不是「缺一个应用」而是抓包抓出来的误判：
    # 电脑没装支付宝也没开浏览器，一条 429MB 的 UDP 流却被记成 支付宝 18-4-1-0。
    # 只写裸域：这台引擎按域名后缀匹配，前导点 `.uuyc.163.com` 和 `*.` 一样不生效
    # （全库 1204 条主机只有 1 条前导点、7 条通配，那 7 条还是我们早期推的）。
    # 用户稿里第二条 `protocol: tcp` 同时带 hosts+payloads 不收：851 条规则里这种形状
    # 0 次，官方表达 HTTP 方法用的是 http-posts(2)/http-gets(182) 专用键，混写最可能的
    # 结果是主机条件被忽略、只剩包内容 —— 会把全屋明文 POST 都认成 UU远程。
    # UU远程（网易远程桌面）。触发原因不是「缺一个应用」而是抓包抓出来的误判：
    # 电脑没装支付宝也没开浏览器，一条 429MB 的 UDP 流却被记成 支付宝 18-4-1-0。
    #
    # 2026-09-21 深夜，用户给了一份 52 秒的退出重登 + 跨设备切换抓包（26116 包），
    # 里面第一次出现了真名字，域名全部改成实测拿到的：
    #   DNS 明文查询 4 条：sig-3303-d.nrd.nie.163.com、api-ipv4.nrd.nie.163.com、
    #     sentry.netease.com、online-logger.webapp.163.com
    #   TLS SNI 13 条，UU 相关的：sigma-*.proxima.nie.netease.com x49、
    #     api.nrd.nie.163.com x16、relay-mg-3303-d.nrd.nie.163.com x11、
    #     sig-3303-d.nrd.nie.163.com x4、fcount-api.webapp.163.com x3、
    #     nrd-file.fp.ps.netease.com、uuyc.webapp.163.com
    # `nrd` 就是 NetEase Remote Desktop，控制面、信令、中继全在 nrd.nie.163.com 底下，
    # 裸域后缀匹配一条就能盖住 api./sig-./relay-mg./api-ipv4. 这些子域。
    # 故意不收：sentry.netease.com 和 *.webapp.163.com 的日志域名是网易全线共用的
    # 上报口，收进来等于把别的网易应用也算成 UU远程（就是当初 阿里CDN 那个错）。
    # 另外更正一次：之前我说这台电脑「明文 DNS 结构性不可见」是说过头了 —— 重登那
    # 一下确实有明文 53（走 223.5.5.5），只是单纯连接/断开的那 25 秒里一次都不查。
    #
    # 端口规则是探引擎吃不吃 port_limit 的第二次尝试，形状照库里唯一先例
    # 4-1-3-2 英雄联盟PC_Gaming（port_limit + 两级 payload_length，payloads 留空）。
    # 上一版按 42 字节写，实测一次都没命中，原因是 42 是猜的：抓包里 PC 发往
    # 2480/2481/2482 的首包一律 28 字节，回来的首包一律 72 字节。
    # 3378（网易 ACD，39 个对端、首包固定 8 字节）不收：那是网易游戏/加速器共用的
    # 探测口，认成 UU远程就是又一次「用别人的口说自己的话」。
    "9-220-1-0": {
        "name": "UU远程",
        "category": "工具/远程",
        "hosts": [
            "uuyc.163.com",
            "gameviewer.com",
            "mofang.163.com",
            "nrd.nie.163.com",
            "proxima.nie.netease.com",
            "uuyc.webapp.163.com",
            "nrd-file.fp.ps.netease.com",
        ],
        "extra_rules": [
            {
                "protocol": "udp",
                "hosts": [],
                "payloads": [],
                "port_limit": [{"min": 2480, "max": 2482}],
                "payload_length": [{"stage": 0, "length": 28}, {"stage": 1, "length": 72}],
            },
        ],
    },
    # WPS Office：库里原有 8-118-1-0 只有 wpscdn/qwps/wps 三个域名，而且它的主机规则
    # 没有 protocol 字段（见下面的补 protocol 逻辑）—— 域名不够 + 规则形态不对，两件事
    # 一起造成「WPS 完全不命中」。补的是金山文档自家云协作域名，全部实测可解析，
    # 且线上库里没有别的条目占着它们。
    # 没收 wpsip.com：解析到 185.199.108.153（GitHub Pages 段），归属无法确认。
    "8-118-1-0": {
        "name": "WPS Office",
        "category": "办公",
        "hosts": [
            "kdocs.cn",
            "account.wps.cn",
            "docer.kdocs.cn",
            "kfp.kdocs.cn",
            "365.wps.cn",
        ],
    },
    # 360 两个应用刻意只收各自的官方子域，不收裸 `360.cn`：那是奇虎全线共用域，
    # 绑给谁都会把 360浏览器 / 安全卫士 / 云盘 一起卷进来，和当初裸 `alicdn.com`
    # 记成云闪付是同一类错。共享平台域（api/open/app/cloud.360.cn）因此宁可落
    # 未识别，也不猜给某一家 —— 代价是儿童手表走平台域的那部分不计入它自己。
    # 2026-09-24 真机（192.168.0.156 开 360 儿童卫士 App）翻出来的：
    # kids.360.cn ×146，而 **m.baby.360.cn 还有 ×135**（v7.baby 另有 2 次）—— 一半的流量
    # 原来压根没盖住。baby.360.cn 是 360 儿童卫士的**官网 / App 下载 / 固件升级域**：
    # 新浪、中新网多条报道写着「官方购买链接 baby.360.cn」「固件升级工具从 baby.360.cn
    # 下载」「在地址栏输入 baby.360.cn 或者 360儿童卫士」。
    # IP 也对得上：baby.360.cn 解析 101.198.3.97 / 106.63.24.79，与 kids.360.cn 完全相同。
    #
    # kidswatch-sg.com 是海外服务域（真机 api.kidswatch-sg.com ×1），名字就是「儿童手表」。
    #
    # ⚠️ 已知冲突（别硬掰）：儿童卫士用的 iotbear.live.360.cn / cloudcontrol.live.360.cn
    # 落在 live.360.cn 下，而 live.360.cn 已归 9-222 360智慧生活 → 这部分会显示成智慧生活。
    # ⚠️ 高德地图 amap.com 命中 147 次（定位用的第三方地图 SDK）—— 收了会把所有用高德的
    # 应用都记成儿童卫士，绝不能收。声网 agora.io（音视频 SDK）同理。
    "9-221-1-0": {
        "name": "360儿童卫士",
        "category": "智能家居",
        "hosts": [
            "kids.360.cn",
            "baby.360.cn",
            "kidswatch-sg.com",
        ],
    },
    "9-222-1-0": {
        "name": "360智慧生活",
        "category": "智能家居",
        "hosts": [
            "home.360.cn",
            "life.360.cn",
            # 摄像头实时流走 live.360.cn（speed./g-iot./qos. 三个子域在 3-23 的
            # 「360智慧生活」采集里占 23 次握手，是那份包 96% 的缺规则证据）。
            # 裸 360.cn 仍然不收：那会把奇虎全线卷进儿童设备。
            "live.360.cn",
            "p.s.360.cn",
            # 2026-09-23 两轮实测（用户 39s 包 + 睿易 br-lan 上 175s 定向抓包，客户端
            # 192.168.0.77）：设备云 API 与云存储回看全在 iot.360.cn 这一层 —— 
            # ad.iot 24 / ac-api.iot 10 / fastconn-api.iot 3 / cn-iot-deviceapi.iot 2，
            # 外加 {bj2,sh2,gz2}-hs-7days.<region>.xstore.qihu.com.iot.360.cn 11 次
            # （后缀匹配，一个裸域吃掉全部 7 个 FQDN、60 次握手）。jia.360.cn 是
            # 「360智能摄像机」自己的域：q5.jia 15 / ota5.jia 3。
            "iot.360.cn",
            "jia.360.cn",
            # 故意不收：passport.360.cn（奇虎统一登录）、dp.push.dc.360.cn（全线推送，
            # 儿童卫士也用）、*.ssl.qhimg.com 与 so.com（全公司 CDN/搜索）、
            # *.zztfly.com（实测是 MobTech 一键登录/短信 SDK，policy.zztfly.com 挂着
            # 「秒验SDK」「SMSSDK」隐私政策）、sg.tgalileo.com（RDAP 只查到注册商
            # MarkMonitor，持有人未证实）。收这些就是当年 alicdn.com 那个错。
        ],
    },
    # 亲宝宝：App 真正的业务域是 **qbb6.com**，不是官网域（2026-09-24 真机抓包定案）。
    # 现场：挂在 192.168.0.3 那台 TL-XDR3010 后面的手机正在用亲宝宝，110 秒里
    # qthumb0-sh.qbb6.com 命中 113 次，qfile6-sh / qfile1-sh / qfile0-sh /
    # apilog / api / apievt .qbb6.com 合计 130+ 次；而 qinbaobao.com 一条都没出现。
    # 归属证据：www.qbb6.com 返回的官网页面与 www.qinbaobao.com 逐字相同 ——
    # 同一备案主体「杭州点望科技有限公司」、同一 IP 121.40.177.227、
    # 同一邮箱 support@qinbaobao.com。裸域后缀匹配，一个 qbb6.com 就覆盖全部子域。
    #
    # qbaobei.com 已摘除：它现在是「亲亲宝贝 - 专业的育儿网站」（解析 122.10.42.170），
    # 是另一个育儿内容站，不是亲宝宝 App。真机抓包里亲宝宝的流量一条 qbaobei.com
    # 都没有 —— 留着就是把别人站点的流量记到亲宝宝名下（当年 alicdn.com 那个错）。
    "9-223-1-0": {
        "name": "亲宝宝",
        "category": "社交",
        "hosts": [
            "qinbaobao.com",
            "qbb6.com",
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
    # DeepSeek：裸域 deepseek.com 盖住 App 的会话与静态资源（真机：chat.deepseek.com、
    # static.deepseek.com、hif-leim / hif-dliq.deepseek.com 全部命中）。
    #
    # 另收 deepseeksvc.com（2026-09-24 真机抓到 files.deepseeksvc.com）：
    # 它解析到 116.205.40.113 / 116.205.40.114，与官方 chat.deepseek.com **完全相同**，
    # 是它自己的文件/附件服务域，不在 deepseek.com 下面，不补就漏。
    #
    # ⚠️ 只认这两条硬证据，**不按"名字像"收域** —— 奇安信统计过 DeepSeek 有 2650+ 仿冒
    # 域名，官方声明只认 deepseek.com / deepseek.cn。名字像 DeepSeek 的域一律不收。
    # deepseek.cn 虽在官方声明里，但 DNS 无 A 记录、真机零流量，暂不收。
    "9-202-1-0": {
        "name": "DeepSeek",
        "category": "AI/聊天",
        "hosts": [
            "deepseek.com",
            "deepseeksvc.com",
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
            # 2025-10-27「百度搜索WEB」采集里实测到、库里却没有的百度自有服务：
            # hpd 是 HTTPDNS（8 次握手 11KB，占那份包缺规则证据 62%），passport 是
            # 账号，sp1/hector 是搜索与内容接口。只补精确主机名，不写裸 baidu.com ——
            # 库里 baidu.com 下已有 27 个主机分属 百度/百度贴吧/百度网盘/baiduAPP，
            # 裸域放进族主条目会让它抢在派生条目之前命中（9-21 实测）。
            "hpd.baidu.com",
            "passport.baidu.com",
            "sp1.baidu.com",
            "hector.baidu.com",
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
    # 2026-09-24 在 192.168.0.77 播放红果短剧时定向抓包：下面两个 TLS 主机
    # 共承载 13.7 MB 视频流。当时只补完整主机名、不收 qznovelvod.com 裸域，
    # 是怕把同 CDN 的其它产品一起卷进来 —— 这个顾虑现在已经查清。
    #
    # 2026-09-24 全流程抓包（192.168.0.156：刷视频 / 切页 / 退出重进 / 检测新版本）：
    # 视频流命中 140+ 次，全在 qznovelvod.com 上，但分散在十几个**带地域码的调度域**上
    # （v5-gzb2-gddgtc-reading-video ×25、n98-v-readingvideo ×24、v95-hzyy-thr-daily-reading-videocdn
    # ×24、v5-gzb2-bjtc-reading-video ×22、v18-reading-videocdn302 ×16、v6-daily-reading-videocdn
    # ×13、v6-reading-ad ×11 …）。两个精确主机名只盖住 16 / 140，而地域码是 CDN 动态
    # 生成的，穷举不完。
    #
    # 同 CDN 的「其它产品」是谁？是**番茄免费小说**，但它走的是**另一个域**
    # fqnovelvod.com（v11 / v26 / v9-fq-tts 听书、v95-se-zjwztc-reading-video.fqnovelvod.com）。
    # 两轮抓包交叉验证：番茄的流量里 grep qznovelvod 零命中，红果的流量里也没有 fqnovelvod。
    # ⇒ qznovelvod.com 是红果独占，收裸域安全，当初的顾虑不成立。裸域一条盖住全部地域变体。
    #
    # ⚠️ 仍然共用的（域名层面无解，不要硬掰）：红果的 API / 日志 / 图片走
    # fqnovel.com / fqnovelpic.com / fqnovelstatic.com（api5-normal-lf、api5-normal-sinfonlinea/b、
    # mon11-misc-lf、log5-applog-lf、frontier100-toutiao-hl、lf3-reading …，本次 40+ 次），
    # 这些已归 9-208 番茄免费小说，所以红果这部分流量会显示成「番茄免费小说」。
    # 字节全线共享基础设施（snssdk / zijieapi / byteimg / douyinpic / douyincdn / bytegecko /
    # ecombdapi）一律不收。
    "10-5-2-0": {
        "name": "红果免费短剧",
        "category": "短视频/直播",
        "hosts": [
            "v18-reading-videocdn302.qznovelvod.com",
            "v91-reading-videocdnon.qznovelvod.com",
            "qznovelvod.com",
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
    # 山姆：App 的业务域是 **walmartmobile.cn**，不是官网域（2026-09-24 真机抓包定案）。
    # 现场：192.168.0.156 开着山姆会员商店，90 秒里 api-sams.walmartmobile.cn 命中 19 次、
    # aloha.walmartmobile.cn 与 tongdun-fingerprint.walmartmobile.cn 各 1 次，
    # 而 samsclub.cn / samsclub.com.cn 一条都没出现。
    # 归属证据：api-sams.walmartmobile.cn 解析 121.14.22.78，与 www.samsclub.cn 同 IP。
    # 裸域后缀匹配，一个 walmartmobile.cn 就覆盖 api-sams / aloha / tongdun-fingerprint 全部子域。
    #
    # 三个腾讯云 COS 素材桶也收（真机命中 7 / 2 / 1 次），桶名都带 sam、且是同一个
    # APPID 1302115363，就是山姆自己的桶。照阿里CDN 先例只收**精确主机名**：
    # 裸 file.myqcloud.com 是 COS 共享域，收了会把所有 COS 桶的流量都记成山姆。
    #
    # samsclub.cn 保留且真有命中（真机里 v.samsclub.cn 出现 1 次）；samsclub.com.cn
    # 是官网主域（161.165.193.39），一起留着给网页 / H5 场景。
    "9-215-1-0": {
        "name": "山姆会员商店",
        "category": "综合电商",
        "hosts": [
            "samsclub.cn",
            "samsclub.com.cn",
            "walmartmobile.cn",
            "0sam-material-online-1302115363.file.myqcloud.com",
            "6gz-cos-sam-yewu-online-01-1302115363.file.myqcloud.com",
            "1sam-web-admin-online-1302115363.file.myqcloud.com",
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
    # 美团：官方库里连条目都没有（按名字、按 meituan/dianping/sankuai 主机、按固件
    # 原始库和 OAF 应用树四处交叉查过，全为 0），所以它永远只会是 0-0-0-0。
    "9-231-1-0": {
        "name": "美团",
        "category": "生活/外卖",
        "hosts": [
            "meituan.com",
            "sankuai.com",
        ],
    },
    # 微信的 P2P 加速调度域：10 分钟采样里 `apd-pcdnwx*` 被查了 31 次（login 8 /
    # stat 18 / nat 5），是采样期最高频的无规则域名，却整条落在 0-0-0-0。这里只写
    # 实测到的三个精确主机名，不写 `tencent-cloud.net` 裸后缀 —— 那是腾讯云对外
    # 卖的产品域，裸绑会把租户应用全记成微信，和上面百度那条同一个道理。
    "7-1-2-0": {
        "name": "微信",
        "category": "社交通讯",
        "hosts": [
            "apd-pcdnwxlogin.teg.tencent-cloud.net",
            "apd-pcdnwxnat.teg.tencent-cloud.net",
            "apd-pcdnwxstat.teg.tencent-cloud.net",
        ],
    },
    # 绿联云（UGREEN NAS 私有云 App）：官方库里根本没有。域名来自 2025-10-30
    # 「绿联云.pcap」实测 + 厂商特征文档，两个都当场验过归属：
    #   ug.link   —— choubao.cn17.ug.link 110 次握手 37KB，占那份包缺规则证据 95%；
    #               choubao 正是这台 NAS 的主机名，归属没有疑问。
    #   ugnas.com —— 官网标题「绿联NAS私有云官网…绿联云」，且 www.ug.link 与
    #               api.ugnas.com 解析到同一个 119.23.87.190，同一运营方。
    # 特意不收 lulian.cn / ugreen.com：实测标题是「UGREEN绿联-品质新体验,数码选绿联」，
    # 那是消费电子官网，绑进来会把「看鼠标键盘」记成在用 NAS App。
    # 2026-09-24 真机（192.168.0.156 开绿联云 App）核对：api.ugnas.com ×3、
    # qt-api.ugnas.com ×4 全被 ugnas.com 裸域盖住；ug.link 这轮没出现（那份包里它是主力，
    # 取决于这台 NAS 用哪种方式连）。
    # 补一个日志桶 ugreen-log.oss-cn-shenzhen.aliyuncs.com（真机 1 次）：桶名带 ugreen，
    # 照山姆 COS 桶、阿里CDN 的先例只收**精确主机名** —— 裸 oss-cn-shenzhen.aliyuncs.com
    # 是阿里云 OSS 共享域，收了会把所有人的 OSS 桶都记成绿联云。
    "9-232-1-0": {
        "name": "绿联云",
        "category": "工具",
        "hosts": [
            "ug.link",
            "ugnas.com",
            "ugreen-log.oss-cn-shenzhen.aliyuncs.com",
        ],
    },
    # 飞牛 fnOS（私有云 App）：官方库里也没有。
    #   5ddd.com —— FN Connect 中继域，victor1664.5ddd.com 在 2025-11-12 的采集里
    #               322 次握手 92KB，占那份包缺规则证据 94%，是全部 12 份里最强的一条。
    #   fnos.net —— 统一网关域，官网标题「FN Connect 远程访问 - 飞牛 fnOS」，且与
    #               5ddd.com 同 IP（47.101.149.170）。
    #   fnnas.com —— 文档没提，但实测到 5 个子域共 13 次握手（event/static/static2/cnf/
    #               help-static），是它自己的另一组服务域。
    "9-233-1-0": {
        "name": "飞牛私有云",
        "category": "工具",
        "hosts": [
            "5ddd.com",
            "fnos.net",
            "fnnas.com",
        ],
    },
}


#: 这些补丁的编号在**官方固件库里本来就存在** —— 我们只是往官方条目里补域名，条目本身
#: 仍然是官方的，不能算进「自定义特征」的数目里。剩下那些补丁（9-2xx / 18-4-2-0）才是
#: 我们新建的应用。这份名单由测试拿官方固件库逐条核对，多一条少一条都会红。
CURATED_OFFICIAL_MERGE_INDEXES = frozenset({
    "7-1-2-0",      # 微信
    "7-1-2-12",     # 微信_other
    "7-3-2-0",      # 百度
    "8-1-3-0",      # 企业微信
    "8-118-1-0",    # WPS Office
    "10-1-2-0",     # 微信视频号
    "10-5-1-0",     # 抖音（官方叫「抖音系列」）
    "10-5-2-0",     # 红果免费短剧
    "10-146-1-0",   # 快手（官方叫「快手系列」）
    "18-156-1-0",   # 云闪付
    "18-158-1-0",   # 拼多多
    "18-159-1-0",   # 京东
})


#: 官方库里抢别家域名的条目 —— 只往官方条目里**补**域名修不好误识别，必须能把错的
#: 域名摘掉。每条都在 2026-09-21 对着提取出来的官方库（472 条）逐条核对过。
#: 值是主机名列表表示只摘这些主机；值是 ``"*"`` 表示整条删除（它的全部匹配子都是
#: 别家的域名，留着就一定会误判）。
CURATED_SIGNATURE_REMOVALS: Dict[str, Any] = {
    # 钉钉_alipay 的三个主机全是支付宝的，而它排在数组第 300 位，真正的支付宝
    # 兜底条目 18-4-1-14 在第 433 位 —— 「支付宝被记成钉钉」就是这么来的。
    # 官方库把阿里系的埋点/支付域名绑给了钉钉的派生条目：`钉钉_mmstat` 占 4 个 mmstat
    # 埋点主机（淘宝/天猫/闲鱼/饿了么的埋点流量因此记成钉钉），`钉钉_alipay` 占 3 个
    # alipay 主机（那是支付宝自己的域名，正主排在库尾所以一条拿不到）。
    #
    # 这两条按名字守卫整条删 —— 2026-09-22 实测修正：删官方条目**不是**整库识别停摆的
    # 原因，真正的原因是条目总数超过引擎上限（见 :data:`ENGINE_APP_ENTRY_LIMIT`），而
    # 删条目恰恰是腾出名额的手段。名字对不上就不动手：线上库的 编号↔名字 已经和固件库
    # 漂移过（8-4-1-6 在路由器上叫 阿里CDN，固件库里那条叫 钉钉_alicdn），只按编号动手
    # 是这一批问题的根源。
    "8-4-1-11": {"delete_if_named": "钉钉_alipay"},
    "8-4-1-10": {"delete_if_named": "钉钉_mmstat"},
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
    # 这条唯一的主机是微软登录域名 login.live.com，摘掉就没有任何匹配子了，整条删。
    "8-1-1-5": {"delete_if_named": "腾讯会议_join_meeting"},
    # 安全教育平台_null_relation 四个主机全是个推/gepush 推送 SDK —— 任何用个推的
    # App 都会被记成安全教育平台，而这条本身跟安全教育平台没有一个是自己的域名。
    "8-81-1-15": {"delete_if_named": "安全教育平台_null_relation"},
    # 线上路由器这条是早先下发留下的重复 云闪付（正主在 18-156-1-0）。它的 unionpay
    # 一族域名先并进正主再删，否则整条删掉会把 unionpay.com 的覆盖一起丢掉。
    "18-4-3-0": {"delete_if_named": "云闪付"},
    # 8-4-1-6 在路由器上已经是我们早先改名的 阿里CDN（固件库里那条叫 钉钉_alicdn），
    # 官方条目才是该用的那个号：以后要加阿里系域名，加到 8-4-1-6 上，别再克隆。
    # 阿里CDN 早期版本整片兜过裸 `alicdn.com`，实测公共 DNS 114.114.114.114 会被它
    # 卷进来记成阿里CDN。合并是只追加的，改特征表里的名单删不掉已经落到路由器上的
    # 那一行，必须在这里显式摘掉，再由下面的白名单换成精确子域。
    "9-217-1-0": ["alicdn.com"],
    # 支付宝的 UDP payload 规则（stage 0 / pos 1 / "00 00 00 01 12"）在实测中吃下了
    # UU远程的隧道流：抓 300 个 UDP 包，其中 3 个从载荷第 4 字节起就是这 5 个字节
    # （`81 cd 00 03 | 00 00 00 01 12 | 52 a8 …`，UU 的 RTCP 帧）。一条 429MB / 46.7 万
    # 包的流因此整条记成 支付宝，而那台电脑没装支付宝也没开浏览器 —— 引擎只要命中
    # 一个包就给整条流定性，1% 的命中率足够。
    # 支付宝真正的识别来自 3 个 alipay 主机 + user-agent，摘掉 UDP 不影响它认自己。
    "18-4-1-0": {"drop_protocols": ["udp"]},
    # 下面两条是**我们自己**早先下发时带进去的错域名，2026-09-24 真机抓包核对后判错：
    # 只把名字从 :data:`CURATED_SIGNATURE_EXTENSIONS` 里删掉是不够的 —— 合并只追加，
    # 已经落到路由器上的那一行不会被改回去，必须在这里显式摘。
    #
    # 亲宝宝：qbaobei.com 现在是「亲亲宝贝 - 专业的育儿网站」（122.10.42.170，另一个
    # 育儿内容站），真机抓包 110 秒里亲宝宝一条 qbaobei.com 都没有。留着就是把别人
    # 站点的流量记到亲宝宝名下（当年 alicdn.com 那个错的翻版）。正主域 qinbaobao.com
    # + 新加的 qbb6.com 保留。
    "9-223-1-0": ["qbaobei.com"],
    # 米家：mijia.ai 实测返回「mijia.ai for sale | Spaceship.com」，一个停在 AWS
    # 44.232.173.249 的待售域名，跟小米没关系，真机零命中。正主域 api.io.mi.com 一族
    # + 新加的 mijia.tech 保留。
    "9-219-1-0": ["mijia.ai"],
}


#: 校验器认的这些字段里至少有一个非空，规则才算有匹配子 —— 与
#: ``validate_signature_object`` 的判定保持一致，别在这里放宽。
_MATCHER_FIELDS = ("hosts", "payloads", "payload_length", "http-gets",
                   "http-posts", "user-agents")


#: BE72 引擎的条目表上限（2026-09-22 在同一台路由器上实测）：488 条时域名规则全部
#: 正常，490 条起整库一条域名都不命中，只剩协议级 appid（DNS 流还在，标记是 11-6-0-0）。
#: 主机数、被删的是哪几条、文件是紧凑还是缩进格式都试过了 —— 死的只有**条数**：
#: 498 条 / 1155 主机照样全灭，486 条 / 1242 主机 7/7 全中。
ENGINE_APP_ENTRY_LIMIT = 488


def apply_slot_retirements(apps: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """回收永远不会命中的空壳条目，给真正能识别的新应用腾名额。

    固件库自带 14 条一个匹配子都没有的壳（魔兽世界 / 永劫无间 / 鸣潮 / 蔚蓝档案 /
    蛋仔派对 / PUBG 那类 —— 官方把特征留在了别的文件里），它们在引擎里命中不了任何一条流，
    却和真正有用的条目一样占 :data:`ENGINE_APP_ENTRY_LIMIT` 的名额。只回收「所有规则
    都没有匹配子」的条目，有匹配子的一律不动。
    """
    kept: List[Dict[str, Any]] = []
    retired: List[str] = []
    for app in apps:
        if any(_has_matcher(rule) for rule in (app.get("rules") or [])):
            kept.append(app)
        else:
            retired.append(f"{app.get('name')} ({app.get('index')} 没有任何匹配子)")
    return kept, retired


def entry_budget_error(apps: List[Dict[str, Any]]) -> Optional[str]:
    """整库条数超过引擎上限时给出拒绝理由，没超过返回 None。

    没有这道闸，一次「多加几个应用」的下发就会把全网识别打死，而且现场看起来像是
    特征写错了 —— 宁可在这里拒绝，也不能让路由器带着超限库跑。
    """
    over = len(apps) - ENGINE_APP_ENTRY_LIMIT
    if over <= 0:
        return None
    return (f"合并后整库 {len(apps)} 条，超过引擎上限 {ENGINE_APP_ENTRY_LIMIT} 条："
            f"路由器会停止匹配所有域名规则。需要再减少 {over} 条。")


def _has_matcher(rule: Dict[str, Any]) -> bool:
    return any(isinstance(rule.get(field), list) and rule[field] for field in _MATCHER_FIELDS)


def apply_removals(apps: List[Dict[str, Any]]) -> tuple:
    """按 :data:`CURATED_SIGNATURE_REMOVALS` 摘主机 / 摘协议规则 / 整条删除，返回三项统计。

    三种动作都按 index 定位条目，但**整条删除必须再过名字这道闸**：线上库的
    编号↔名字 已经和固件库漂移过（8-4-1-6 在路由器上叫 阿里CDN，固件库里那条叫
    钉钉_alicdn），只按编号动手会把官方自己的 CDN 兜底条目当成钉钉删掉。
    删除是就地从数组里摘掉，因此它也是在给 :data:`ENGINE_APP_ENTRY_LIMIT` 腾名额。
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
            if expected:
                if name != expected:
                    # 编号在线上库里被谁占着，只有路由器自己知道；名字对不上就不动手。
                    skipped.append(f"{name} ({idx} 不是 {expected}，保留)")
                    continue
                apps.remove(app)
                removed_hosts += sum(len(r.get("hosts") or []) for r in app.get("rules") or [])
                removed_apps.append(f"{name} ({idx} 整条删除，条目不占名额了)")
                continue
            drop_protocols = {str(p).strip().lower() for p in spec.get("drop_protocols") or []}
            if drop_protocols:
                # 摘整条协议规则（不是摘主机）：支付宝那条误判就是 payload 规则造成的，
                # 主机清单动它不着。摘完必须还剩至少一个匹配子，否则整库过不了校验。
                rules = app.get("rules") or []
                kept = [r for r in rules
                        if str(r.get("protocol") or "").strip().lower() not in drop_protocols]
                if len(kept) == len(rules):
                    continue
                if not any(_has_matcher(r) for r in kept):
                    skipped.append(f"{name} ({idx} 摘掉 {'/'.join(sorted(drop_protocols))} "
                                   f"规则后没有匹配子了，保留)")
                    continue
                app["rules"] = kept
                removed_apps.append(f"{name} ({idx} 摘掉 {len(rules) - len(kept)} 条 "
                                    f"{'/'.join(sorted(drop_protocols))} 规则)")
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


_RULE_SHAPE_KEYS = ("protocol", "hosts", "payloads", "payload_length", "port_limit")


def _rule_shape(rule: Dict[str, Any]) -> str:
    """规则的稳定指纹：只看匹配子，note 之类注释字段不算。"""
    return json.dumps({key: rule.get(key) for key in _RULE_SHAPE_KEYS}, sort_keys=True)


def _append_extra_rules(rules: List[Dict[str, Any]], patch: Dict[str, Any]) -> int:
    """把补丁里的非主机规则（端口 / 包长那类）追加进去，同形状已存在就不重复加。

    整库下发是每次刷新都会跑的，所以这一步必须幂等 —— 否则每热重载一次就往条目里塞
    一条重复规则，路由器迟早拒收。
    """
    added = 0
    for extra in patch.get("extra_rules") or []:
        if any(_rule_shape(existing) == _rule_shape(extra) for existing in rules):
            continue
        rules.append(dict(extra))
        added += 1
    return added


def apply_curated_extensions(db: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """把策划好的高频域名并进官方条目，返回 (新库, 给界面的字段)；没有新东西就 (None, 说明)。

    先回收没有任何匹配子的空壳腾出名额，再摘后补；新增的条目排在最后，让官方那些
    更具体的规则继续优先命中。结果受 :data:`ENGINE_APP_ENTRY_LIMIT` 约束 —— 超了就
    拒绝下发，因为那会让路由器整库停止域名识别。
    """
    apps, retired_apps = apply_slot_retirements(list(db.get("apps") or []))

    # 先摘再补：删掉的条目不该在下一轮按 name 撞上别的补丁。
    hosts_removed, removed_apps, removal_skipped = apply_removals(apps)

    total_hosts_added = 0
    extra_rules_added = 0
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
            extra_here = _append_extra_rules(new_app["rules"], patch)
            apps.append(new_app)
            total_hosts_added += len(patch["hosts"])
            extra_rules_added += extra_here
            detail = f"{len(patch['hosts'])} 域名" + (f" + {extra_here} 条端口规则" if extra_here else "")
            enhanced_apps.append(f"{patch['name']} (新增规则 {detail})")
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
        # 同 validate_signature_object 里那条：动过的 host 规则必须带 payloads，
        # 缺了会让引擎在这条之后停止解析域名规则（整库识别停摆的实际原因）。
        had_payloads_key = "payloads" in host_rule
        host_rule.setdefault("payloads", [])
        note = ""
        if not str(host_rule.get("protocol") or "").strip():
            # 官方库里 WPS Office 的主机规则压根没有 protocol 字段（全库 55 条这种）。
            # 只补主机不改 protocol，规则还是不会被当主机规则评估 —— 「WPS 特征坏了」
            # 就是这个形状，不是域名不够。
            host_rule["protocol"] = "host"
            note = "，补 protocol=host"
        if not had_payloads_key:
            note += "，补 payloads"
        extra_here = _append_extra_rules(rules, patch)
        if extra_here:
            note += f"，另加 {extra_here} 条端口规则"
        enhanced_apps.append(f"{patch['name']} (+{added_here} 域名{note})")
        total_hosts_added += added_here
        extra_rules_added += extra_here

    stats = {
        "totalHostsAdded": total_hosts_added,
        "totalHostsRemoved": hosts_removed,
        "totalRulesAdded": extra_rules_added,
        "removedApps": removed_apps,
        "removalSkipped": removal_skipped,
        "retiredApps": retired_apps,
        "enhancedApps": enhanced_apps,
        "totalApps": len(apps),
        "entryLimit": ENGINE_APP_ENTRY_LIMIT,
    }
    budget = entry_budget_error(apps)
    if budget:
        # 宁可拒发，也不能让路由器带着超限库跑：现场只会看到「全是 0 分钟」，
        # 而看起来像是特征写错了，排查代价是一整晚。
        return None, {**stats, "ok": False, "errorCode": "entry_budget_exceeded", "error": budget}
    if (not total_hosts_added and not hosts_removed and not removed_apps
            and not extra_rules_added and not retired_apps):
        # 一个域名、一条条目都没变化，就别让路由器白热重载一次。
        return None, {**stats, "ok": True, "message": "高频特征包已是最新状态"}
    db["apps"] = apps
    return db, stats
