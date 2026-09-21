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
    assert "*.customgame.com" in result["rules"][0]["hosts"]
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
