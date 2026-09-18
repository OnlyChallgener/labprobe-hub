"""Tests for RDPI signature service: validation, template, and schema checks."""

import pytest
from rdpi_signature_service import (
    STANDARD_RDPI_TEMPLATE,
    validate_signature_object,
)


def test_standard_template_validates_successfully():
    result = validate_signature_object(STANDARD_RDPI_TEMPLATE)
    assert result["index"] == "999-1-1-0"
    assert result["name"] == "自定义应用/新游戏"
    assert result["custom"] is True
    assert len(result["rules"]) == 2
    assert result["rules"][0]["protocol"] == "tcp"
    assert "*.customgame.com" in result["rules"][0]["hosts"]
    assert result["rules"][0]["payloads"][0]["payload"] == "47 41 4d 45"


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
