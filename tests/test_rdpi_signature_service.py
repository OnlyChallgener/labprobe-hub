"""Tests for RDPI signature service: validation, template, and schema checks."""

import json
from pathlib import Path

import pytest
from rdpi_signature_service import (
    STANDARD_RDPI_TEMPLATE,
    validate_signature_object,
)
import rdpi_signature_service as service


def test_standard_template_validates_successfully():
    result = validate_signature_object(STANDARD_RDPI_TEMPLATE)
    assert result["index"] == "999-1-1-0"
    assert result["name"] == "自定义应用/新游戏"
    assert result["custom"] is True
    assert len(result["rules"]) == 3
    assert result["rules"][0]["protocol"] == "host"
    # 模板里只给裸域名：`*.x.com` 在引擎侧永远不会命中，作为示例会把人带偏。
    assert "customgame.com" in result["rules"][0]["hosts"]
    assert result["rules"][1]["protocol"] == "tcp"
    assert result["rules"][1]["payloads"][0]["payload"] == "47 41 4d 45"


def test_validation_rejects_invalid_index():
    invalid_template = {
        "app": {
            "index": "invalid_index_123",
            "name": "Test App",
            "rules": [{"protocol": "tcp", "hosts": ["test.com"]}]
        }
    }
    with pytest.raises(ValueError, match="Invalid RDPI index format"):
        validate_signature_object(invalid_template)


def test_validation_rejects_empty_rules():
    invalid_template = {
        "app": {
            "index": "999-2-1-0",
            "name": "Test App",
            "rules": []
        }
    }
    with pytest.raises(ValueError, match="at least one rule"):
        validate_signature_object(invalid_template)


def test_validation_normalizes_hex_payload():
    template = {
        "index": "950-1-1-0",
        "name": "Hex App",
        "rules": [
            {
                "protocol": "udp",
                "payloads": [
                    {
                        "pos": 0,
                        "payload": "0xAA,0xBB,0xCC"
                    }
                ]
            }
        ]
    }
    result = validate_signature_object(template)
    assert result["rules"][0]["payloads"][0]["payload"] == "aa bb cc"
    assert result["rules"][0]["payloads"][0]["length"] == 3


def test_official_host_protocol_and_optional_fields_are_preserved():
    payload = {
        "index": "999-1-1-0",
        "name": "官方形状",
        "note": "keep this",
        "rules": [{
            "protocol": "host",
            "hosts": ["example.com"],
            "note": "host rule",
        }, {
            "protocol": "tcp",
            "payloads": [{"stage": 0, "pos": 3, "length": 2, "payload": "AA bb"}],
        }],
    }
    result = validate_signature_object(payload)
    assert result["rules"][0]["protocol"] == "host"
    assert result["rules"][0]["note"] == "host rule"
    assert result["rules"][1]["payloads"][0]["stage"] == 0
    assert result["rules"][1]["payloads"][0]["payload"] == "aa bb"


def test_validation_rejects_unknown_protocol_instead_of_turning_it_into_any():
    payload = {
        "index": "999-1-1-0", "name": "bad", "rules": [
            {"protocol": "future-protocol", "hosts": ["example.com"]}
        ]
    }
    with pytest.raises(ValueError, match="Unsupported RDPI protocol"):
        validate_signature_object(payload)


def test_validation_rejects_unknown_fields_and_invalid_payload_length():
    unknown = {
        "index": "999-1-1-0", "name": "bad", "vendorMagic": True,
        "rules": [{"protocol": "tcp", "hosts": ["example.com"]}],
    }
    with pytest.raises(ValueError, match="Unsupported RDPI app fields"):
        validate_signature_object(unknown)

    bad_length = {
        "index": "999-1-1-0", "name": "bad", "rules": [{
            "protocol": "tcp", "payloads": [{"pos": 0, "length": -1, "payload": "aa bb"}]
        }],
    }
    with pytest.raises(ValueError, match="length must be non-negative"):
        validate_signature_object(bad_length)

    with pytest.raises(ValueError, match="payload pos must be non-negative"):
        validate_signature_object({
            "index": "999-1-1-0", "name": "bad", "rules": [{
                "protocol": "tcp", "payloads": [{"pos": 0.5, "payload": "aa"}]
            }],
        })

    with pytest.raises(ValueError, match="http-gets must be a list"):
        validate_signature_object({
            "index": "999-1-1-0", "name": "bad", "rules": [{
                "protocol": "http-gets", "http-gets": [None]
            }],
        })


def test_validation_preserves_official_legacy_declared_length():
    payload = {
        "index": "999-1-1-0", "name": "legacy", "rules": [{
            "protocol": "tcp", "payloads": [{"pos": 0, "length": 10, "payload": "aa bb"}]
        }],
    }
    result = validate_signature_object(payload)
    assert result["rules"][0]["payloads"][0]["length"] == 10


def test_supplied_official_883_rules_round_trip_except_14_empty_placeholders():
    official_db = Path(
        r"D:\Github\LabProbeApp\test\_analysis\extract\rootfs\usr\share\ndpi\db.default.json"
    )
    if not official_db.exists():
        pytest.skip("local official rootfs fixture is unavailable")
    data = json.loads(official_db.read_text(encoding="utf-8"))
    rules = [
        {"index": app["index"], "name": app["name"], "rules": [rule]}
        for app in data["apps"]
        for rule in app.get("rules", [])
    ]
    accepted = []
    rejected = []
    for signature in rules:
        try:
            validate_signature_object(signature)
            accepted.append(signature)
        except ValueError:
            rejected.append(signature)
    assert len(rules) == 883
    assert len(accepted) == 869
    assert len(rejected) == 14


def _signature(index="999-1-1-0", name="自定义", host="b.com"):
    return {"index": index, "name": name, "rules": [{"protocol": "host", "hosts": [host]}]}


def test_merge_appends_and_keeps_top_level_fields():
    db = {"apps": [{"index": "1-1-1-0", "name": "官方", "rules": []}], "version": "2.1"}
    merged, extra = service.merge_signature_into_db(db, _signature())
    assert extra == {"action": "added", "index": "999-1-1-0", "name": "自定义", "totalCount": 2}
    # 中继按原文逐字节核对，顶层少一个 version 都算写坏。
    assert merged["version"] == "2.1"
    # `custom` 是接口元数据，绝不能落进路由器数据库。
    assert "custom" not in merged["apps"][-1]


def test_merge_updates_in_place_and_keeps_fields_the_payload_omits():
    db = {"apps": [{**_signature(), "note": "留着"}]}
    merged, extra = service.merge_signature_into_db(db, _signature(host="c.com"))
    assert extra["action"] == "updated"
    assert len(merged["apps"]) == 1
    assert merged["apps"][0]["note"] == "留着"
    assert merged["apps"][0]["rules"][0]["hosts"] == ["c.com"]


def test_merge_rejects_an_invalid_signature_before_any_write():
    with pytest.raises(ValueError, match="Invalid RDPI index format"):
        service.merge_signature_into_db({"apps": []}, _signature(index="nope"))


def test_remove_drops_by_index_or_name_and_reports_a_miss():
    db = {"apps": [_signature(name="第一个"), _signature(index="999-1-1-1", name="第二个")]}
    merged, extra = service.remove_signature_from_db(db, "第二个")
    assert extra == {"deleted": "第二个", "totalCount": 1}
    assert [app["name"] for app in merged["apps"]] == ["第一个"]

    missed, extra = service.remove_signature_from_db(merged, "999-9-9-9")
    assert missed is None
    assert extra["ok"] is False


def test_wps_like_rule_without_protocol_gets_it_backfilled():
    """官方库有些 host 规则没有 protocol 字段（WPS Office 就是这样），只补域名没用。"""
    official = {"index": "8-118-1-0", "name": "WPS Office",
                "rules": [{"hosts": ["wpscdn.cn", "qwps.cn", "wps.cn"]}]}
    merged, extra = service.apply_curated_extensions({"apps": [official]})
    rule = merged["apps"][0]["rules"][0]
    assert rule["protocol"] == "host", "缺 protocol 的主机规则不会被引擎当主机规则评估"
    assert "kdocs.cn" in rule["hosts"]
    assert any("补 protocol=host" in line for line in extra["enhancedApps"])


def test_new_entries_only_use_hosts_the_engine_can_actually_match():
    """新补的四个条目：裸域、无通配、无点号前缀，且都不收共享平台域。"""
    for index in ("9-221-1-0", "9-222-1-0", "9-223-1-0"):
        patch = service.CURATED_SIGNATURE_EXTENSIONS[index]
        for host in patch["hosts"]:
            assert not host.startswith((".", "*")) and "*" not in host, host
    # 米家补的域名同样不许带前导点，也不许顺手兜下整个 mi.com。
    mijia = service.CURATED_SIGNATURE_EXTENSIONS["9-219-1-0"]["hosts"]
    assert all(not h.startswith((".", "*")) and "*" not in h for h in mijia), mijia
    assert "mi.com" not in mijia, "裸 mi.com 会把小米商城/运动/视频全吸进米家"
    assert "api.io.mi.com" in mijia and "io.mi.com" not in mijia, "顶点不解析，收子域就够"
    # 裸 360.cn 会把奇虎全线（浏览器/安全卫士/云盘）卷进儿童手表，明确不收。
    assert "360.cn" not in service.CURATED_SIGNATURE_EXTENSIONS["9-221-1-0"]["hosts"]
    assert "360.cn" not in service.CURATED_SIGNATURE_EXTENSIONS["9-222-1-0"]["hosts"]


def test_curated_bundle_adds_missing_entries_last_without_touching_official_ones():
    official = {"index": "18-1-1-0", "name": "淘宝", "rules": [{"protocol": "host", "hosts": ["taobao.com"]}]}
    db = {"apps": [official]}
    merged, extra = service.apply_curated_extensions(db)
    assert merged is not None
    assert extra["totalHostsAdded"] > 0
    # 官方条目一个字不改，新增的排最后，让更具体的官方规则继续优先命中。
    assert merged["apps"][0] == official
    assert merged["apps"][-1]["rules"][0]["payloads"] == []
    assert all("custom" not in app for app in merged["apps"])


def _full_bundle_db(with_extra_rules: bool):
    """造一份「每个补丁都已经落库」的库，用来验证幂等。"""
    apps = []
    for index, patch in service.CURATED_SIGNATURE_EXTENSIONS.items():
        rules = [{"protocol": "host", "hosts": list(patch["hosts"]), "payloads": []}]
        if with_extra_rules:
            rules += json.loads(json.dumps(patch.get("extra_rules") or []))
        apps.append({"index": index, "name": patch["name"], "rules": rules})
    return {"apps": apps}


def test_curated_bundle_skips_the_write_when_nothing_is_new():
    merged, extra = service.apply_curated_extensions(_full_bundle_db(with_extra_rules=True))
    # 一个域名都没新增就不该让路由器白热重载一次。
    assert merged is None
    assert extra["totalHostsAdded"] == 0
    assert extra["totalRulesAdded"] == 0


def test_host_rules_always_carry_a_payloads_key():
    """引擎解析到缺 payloads 的 host 规则就中断，之后所有域名规则一起失效（实测）。"""
    result = validate_signature_object({
        "index": "8-118-1-0", "name": "WPS Office",
        "rules": [{"protocol": "host", "hosts": ["kdocs.cn"]}],
    })
    assert result["rules"][0]["payloads"] == []

    patched, _ = service.apply_curated_extensions({"apps": [
        {"index": "8-118-1-0", "name": "WPS Office",
         "rules": [{"hosts": ["wps.cn"]}]},
    ]})
    rule = patched["apps"][0]["rules"][0]
    assert rule["protocol"] == "host"
    assert rule["payloads"] == []


def test_port_rule_lands_on_its_entry_and_is_idempotent():
    patched, extra = service.apply_curated_extensions(_full_bundle_db(with_extra_rules=False))
    expected = sum(bool(patch.get("extra_rules"))
                   for patch in service.CURATED_SIGNATURE_EXTENSIONS.values())
    assert expected == 1
    assert extra["totalRulesAdded"] == expected

    uu = next(app for app in patched["apps"] if app["index"] == "9-220-1-0")
    # 端口规则加在主机规则后面，原有的三个域名一个字不动。
    assert uu["rules"][0]["hosts"] == list(service.CURATED_SIGNATURE_EXTENSIONS["9-220-1-0"]["hosts"])
    port_rule = uu["rules"][-1]
    assert port_rule["protocol"] == "udp"
    assert port_rule["payloads"] == []
    assert {"min": 2480, "max": 2482} in port_rule["port_limit"]
    assert port_rule["payload_length"] == [{"stage": 0, "length": 28}, {"stage": 1, "length": 72}]
    # 端口规则的匹配子只有 payload_length 能过校验器的「至少一个匹配子」，
    # 所以这条一旦哪天被摘掉 payload_length，整库就写不进路由器了。
    for app in patched["apps"]:
        validate_signature_object(app)

    again, second = service.apply_curated_extensions(json.loads(json.dumps(patched)))
    # 整库下发每次刷新都要跑一遍：第二次必须判「无新增」，否则每热重载一次就多塞一条
    # 重复规则，路由器迟早拒收。
    assert again is None
    assert second["totalRulesAdded"] == 0


# -- 摘除官方库里抢别家域名的条目 ---------------------------------------------


def _app(index, name, hosts, extra_rules=None):
    rules = [{"protocol": "host", "hosts": list(hosts)}]
    return {"index": index, "name": name, "rules": rules + (extra_rules or [])}


def test_removal_strips_only_the_named_hosts():
    apps = [_app("8-5-1-4", "飞书_other", ["api.feelgood.cn", "i.snssdk.com"])]
    removed, gone, skipped = service.apply_removals(apps)
    assert (removed, gone, skipped) == (1, [], [])
    assert apps[0]["rules"][0]["hosts"] == ["api.feelgood.cn"]


def test_removal_can_drop_a_whole_entry():
    apps = [_app("8-4-1-11", "钉钉_alipay", ["mdap.alipay.com"]),
            _app("7-1-1-0", "别的", ["x.com"])]
    removed, gone, skipped = service.apply_removals(apps)
    assert (removed, skipped) == (0, [])
    assert gone == ["钉钉_alipay (8-4-1-11 整条删除)"]
    assert [a["index"] for a in apps] == ["7-1-1-0"]


def test_removal_never_leaves_an_entry_with_no_matcher():
    """摘完就没有匹配子的条目要跳过，而不是清空 —— 空条目过不了校验，还会连累整库回滚。"""
    apps = [_app("8-1-1-1", "腾讯会议_login", ["android.rqd.qq.com"])]
    removed, gone, skipped = service.apply_removals(apps)
    assert (removed, gone) == (0, [])
    assert skipped and "8-1-1-1" in skipped[0]
    assert apps[0]["rules"][0]["hosts"] == ["android.rqd.qq.com"]


def test_an_emptied_host_rule_is_removed_not_left_invalid():
    """摘空的规则必须整条撤掉：留一条 hosts 为空的规则，整库就过不了校验。"""
    apps = [{"index": "8-1-1-1", "name": "腾讯会议_login", "rules": [
        {"protocol": "host", "hosts": ["android.rqd.qq.com"]},
        {"protocol": "host", "hosts": ["cfg.imtt.qq.com"]},
    ]}]
    removed, gone, skipped = service.apply_removals(apps)
    assert skipped == [] and removed == 1
    assert [r["hosts"] for r in apps[0]["rules"]] == [["cfg.imtt.qq.com"]]


def test_drop_protocols_removes_the_rule_but_keeps_the_entry():
    """支付宝那条 UDP payload 规则会把 429MB 的 UU远程流判成自己。摘规则而不是摘条目。"""
    apps = [{"index": "18-4-1-0", "name": "支付宝", "rules": [
        {"protocol": "host", "hosts": ["mobilegw.alipay.com"]},
        {"protocol": "udp", "payloads": [{"stage": 0, "pos": 1, "length": 5,
                                          "payload": "00 00 00 01 12"}]},
        {"protocol": "user-agent", "user-agents": ["%E6%94%AF%E4%BB%98%E5%AE%9D"]},
    ]}]
    removed, gone, skipped = service.apply_removals(apps)
    assert (removed, skipped) == (0, [])
    assert [r["protocol"] for r in apps[0]["rules"]] == ["host", "user-agent"]
    assert gone == ["支付宝 (18-4-1-0 摘掉 1 条 udp 规则)"]


def test_drop_protocols_refuses_to_strip_the_last_matcher():
    apps = [{"index": "18-4-1-0", "name": "支付宝", "rules": [
        {"protocol": "udp", "payloads": [{"stage": 0, "pos": 1, "length": 5,
                                          "payload": "00 00 00 01 12"}]}]}]
    removed, gone, skipped = service.apply_removals(apps)
    assert (removed, gone) == (0, [])
    assert skipped and "18-4-1-0" in skipped[0]
    assert len(apps[0]["rules"]) == 1, "只剩这一条规则时必须保留，不能清空条目"


def test_uu_remote_signature_matches_how_the_engine_actually_reads_hosts():
    """UU远程条目：主机必须是裸域，而且只能是抓包里真的出现过的那个产品自己的域名。"""
    patch = service.CURATED_SIGNATURE_EXTENSIONS["9-220-1-0"]
    assert patch["name"] == "UU远程"
    for host in patch["hosts"]:
        assert not host.startswith((".", "*")), host
        assert "*" not in host, host
    # nrd = NetEase Remote Desktop：控制面 api./信令 sig-./中继 relay-mg. 全在它下面，
    # 裸域后缀匹配一条就盖住这些子域（52 秒抓包实测出的名字）。
    assert "nrd.nie.163.com" in patch["hosts"]
    assert "proxima.nie.netease.com" in patch["hosts"]
    assert "uuyc.webapp.163.com" in patch["hosts"]
    # 网易全线共用的上报口不能占：那是把别人算成 UU远程，重演 阿里CDN 的错。
    for shared in ("sentry.netease.com", "webapp.163.com", "nie.163.com", "163.com", "netease.com"):
        assert shared not in patch["hosts"], shared
    # 3378 是网易 ACD 的探测口（39 个对端、首包固定 8 字节），UU加速器/网易游戏都用它。
    assert all(range_["max"] < 3378 or range_["min"] > 3378
               for rule in patch["extra_rules"] for range_ in rule["port_limit"])


def test_bundle_against_the_real_official_db_moves_alibaba_infra_off_dingtalk():
    official_db = Path(
        r"D:\Github\LabProbeApp\test\_analysis\extract\rootfs\usr\share\ndpi\db.default.json"
    )
    if not official_db.exists():
        pytest.skip("local official rootfs fixture is unavailable")
    db = json.loads(official_db.read_text(encoding="utf-8"))
    # 官方库自己就有 14 条空占位规则过不了我们的校验器（见上面那条 round-trip
    # 测试），所以只能比「改完之后有没有新增非法条目」，不能要求整库全绿。
    def invalid_indexes(apps):
        bad = set()
        for app in apps:
            try:
                validate_signature_object(app)
            except ValueError:
                bad.add(str(app.get("index")))
        return bad

    before = invalid_indexes(db["apps"])
    merged, extra = service.apply_curated_extensions(json.loads(
        official_db.read_text(encoding="utf-8")))

    assert merged is not None
    by_index = {app["index"]: app for app in merged["apps"]}
    # 钉钉不再占着阿里的 CDN / 埋点 / 支付宝域名。
    for stolen in ("8-4-1-6", "8-4-1-10", "8-4-1-11"):
        assert stolen not in by_index, f"{stolen} 还在把阿里的域名算成钉钉"
    # 飞书不再收字节跳动的公共域名，但自己的 feelgood 还在。
    feishu = by_index["8-5-1-4"]["rules"][0]["hosts"]
    assert "i.snssdk.com" not in feishu and "api.feelgood.cn" in feishu
    # 腾讯会议只留 imtt 自己的域名。
    meeting = by_index["8-1-1-1"]["rules"][0]["hosts"]
    assert "cfg.imtt.qq.com" in meeting and "dp3.qq.com" not in meeting
    # 淘宝官方库里根本没有，必须新建出来。
    assert "淘宝" in [app["name"] for app in merged["apps"]]
    # 阿里CDN 兜住阿里 CDN 边缘主机：这是它以前从来没命中过的原因。只放行精确
    # 子域，不整片兜 `alicdn.com`；编号必须落在自定义段，不能占 18-4-3-0 ——
    # 路由器上那个编号是一条重复的云闪付。
    alibaba_cdn = next(a for a in merged["apps"] if a["name"] == "阿里CDN")
    assert alibaba_cdn["index"].startswith("9-"), alibaba_cdn["index"]
    cdn_hosts = alibaba_cdn["rules"][0]["hosts"]
    assert "img.alicdn.com" in cdn_hosts and "gw.alicdn.com" in cdn_hosts
    assert "alicdn.com" not in cdn_hosts, "整片兜裸域会把查询过 alicdn 的流也算进来"
    assert extra["totalHostsRemoved"] > 0 and extra["removalSkipped"] == []
    # 改完的库必须仍然合法：不能引入任何官方库原本没有的非法条目，否则路由器会
    # 拒绝写入并回滚整库。
    assert invalid_indexes(merged["apps"]) <= before


def test_no_curated_host_uses_an_inert_wildcard():
    """引擎按裸域名后缀匹配，`*.x.com` 永远不会命中 —— 特征表里不许出现通配写法，
    否则那一行只是让人误以为整个域已经覆盖了。"""
    offenders = [f"{idx} {patch['name']} {host}"
                 for idx, patch in service.CURATED_SIGNATURE_EXTENSIONS.items()
                 for host in patch["hosts"] if host.startswith("*")]
    assert not offenders, "死规则：" + "; ".join(offenders)


def test_no_host_is_claimed_by_two_curated_apps():
    owners: dict = {}
    for patch in service.CURATED_SIGNATURE_EXTENSIONS.values():
        for host in patch["hosts"]:
            owners.setdefault(host, set()).add(patch["name"])
    shared = {h: sorted(n) for h, n in owners.items() if len(n) > 1}
    assert not shared, f"同一个域名被两个应用抢：{shared}"


def test_the_requested_apps_all_arrive_in_the_bundle():
    official_db = Path(
        r"D:\Github\LabProbeApp\test\_analysis\extract\rootfs\usr\share\ndpi\db.default.json"
    )
    if not official_db.exists():
        pytest.skip("local official rootfs fixture is unavailable")
    merged, _extra = service.apply_curated_extensions(json.loads(
        official_db.read_text(encoding="utf-8")))
    names = {app["name"] for app in merged["apps"]}
    for wanted in ("淘宝", "阿里CDN", "饿了么", "番茄免费小说", "西瓜视频", "醒图",
                   "海尔智家", "美的美居", "TP-LINK物联", "三角洲行动",
                   "山姆会员商店", "小爱同学", "企业微信", "百度", "菜鸟", "米家"):
        assert wanted in names, wanted
    # 有独立条目的阿里系不能被 阿里CDN 兜走；没有的才进兜底桶。
    cdn_hosts = set(next(a for a in merged["apps"] if a["name"] == "阿里CDN")["rules"][0]["hosts"])
    for independent in ("优酷视频", "钉钉", "支付宝", "阿里云盘", "夸克", "饿了么", "菜鸟", "淘宝"):
        entry = next(a for a in merged["apps"] if a["name"] == independent)
        overlap = set(entry["rules"][0]["hosts"]) & cdn_hosts
        assert not overlap, f"{independent} 的域名被 阿里CDN 抢了：{sorted(overlap)}"
    # 企业微信官方有条目但主机字段是个残缺 token，补进来的真域名必须落在同一条上。
    wecom = next(a for a in merged["apps"] if a["name"] == "企业微信")
    assert wecom["index"] == "8-1-3-0"
    assert "work.weixin.qq.com" in wecom["rules"][0]["hosts"]


def test_same_app_family_only_accepts_the_app_itself_and_its_derivatives():
    assert service._same_app_family("抖音系列", "抖音")
    assert service._same_app_family("微信_other", "微信")
    assert service._same_app_family("淘宝", "淘宝")
    assert not service._same_app_family("云闪付", "阿里CDN")
    assert not service._same_app_family("支付宝", "钉钉")


def test_a_taken_index_never_absorbs_an_unrelated_patch():
    """编号被不相干的条目占着时另找空位，绝不把域名并进别人家。"""
    occupant = {"index": "9-217-1-0", "name": "别的支付",
                "rules": [{"protocol": "host", "hosts": ["pay.example.com"]}]}
    merged, _extra = service.apply_curated_extensions({"apps": [occupant]})
    by_index = {a["index"]: a for a in merged["apps"]}
    assert by_index["9-217-1-0"]["rules"][0]["hosts"] == ["pay.example.com"], \
        "不相干的条目被并进了我们的 CDN 域名"
    created = [a for a in merged["apps"] if a["name"] == "阿里CDN"]
    assert created and created[0]["index"] != "9-217-1-0"
    assert created[0]["index"].startswith("9-"), created[0]["index"]


def test_deletion_by_index_is_refused_when_the_name_does_not_match():
    """只按编号删条目同样危险：名字对不上就不许删。"""
    apps = [{"index": "18-4-3-0", "name": "某个正经应用",
             "rules": [{"protocol": "host", "hosts": ["x.com"]}]}]
    removed, gone, skipped = service.apply_removals(apps)
    assert gone == [] and skipped and "18-4-3-0" in skipped[0]
    assert len(apps) == 1


def test_index_match_still_enhances_a_derived_official_name():
    """`抖音系列` 就是 抖音 的官方派生条目，按编号合并进它，不能再建一条重名应用。"""
    official = {"index": "10-5-1-0", "name": "抖音系列",
                "rules": [{"protocol": "host", "hosts": ["iesdouyin.com"]}]}
    merged, _extra = service.apply_curated_extensions({"apps": [official]})
    douyin = [a for a in merged["apps"] if a["index"] == "10-5-1-0"]
    assert len(douyin) == 1
    hosts = douyin[0]["rules"][0]["hosts"]
    assert "iesdouyin.com" in hosts and "amemv.com" in hosts
    assert not [a for a in merged["apps"] if a["name"] == "抖音"]


def test_a_new_app_never_lands_on_an_index_the_router_already_uses():
    taken = [{"index": f"9-{slot}-1-0", "name": f"占位{slot}",
              "rules": [{"protocol": "host", "hosts": ["x.com"]}]} for slot in range(200, 220)]
    merged, _extra = service.apply_curated_extensions({"apps": taken})
    indexes = [a["index"] for a in merged["apps"]]
    assert len(indexes) == len(set(indexes)), "同一个编号出现了两次"


def test_a_host_already_deployed_can_be_stripped_again():
    """合并只追加，改特征表删不掉已经落到路由器上的域名，必须能摘回来。"""
    deployed = {"index": "9-217-1-0", "name": "阿里CDN",
                "rules": [{"protocol": "host",
                           "hosts": ["alicdn.com", "aliyuncs.com", "mmstat.com"]}]}
    merged, _extra = service.apply_curated_extensions({"apps": [deployed]})
    hosts = merged["apps"][0]["rules"][0]["hosts"]
    assert "alicdn.com" not in hosts, "裸域还在，公共 DNS 会被记成阿里CDN"
    assert "img.alicdn.com" in hosts and "aliyuncs.com" in hosts
