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


def test_curated_bundle_skips_the_write_when_nothing_is_new():
    db = {"apps": [
        {"index": index, "name": patch["name"],
         "rules": [{"protocol": "host", "hosts": list(patch["hosts"]), "payloads": []}]}
        for index, patch in service.CURATED_SIGNATURE_EXTENSIONS.items()
    ]}
    merged, extra = service.apply_curated_extensions(db)
    # 一个域名都没新增就不该让路由器白热重载一次。
    assert merged is None
    assert extra["totalHostsAdded"] == 0


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
    # 阿里CDN 兜住 alicdn：这是它以前从来没命中过的原因。
    alicdn = by_index["18-4-3-0"]["rules"][0]["hosts"]
    assert "alicdn.com" in alicdn
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
                   "山姆会员商店", "小爱同学", "企业微信", "百度"):
        assert wanted in names, wanted
    # 企业微信官方有条目但主机字段是个残缺 token，补进来的真域名必须落在同一条上。
    wecom = next(a for a in merged["apps"] if a["name"] == "企业微信")
    assert wecom["index"] == "8-1-3-0"
    assert "work.weixin.qq.com" in wecom["rules"][0]["hosts"]
