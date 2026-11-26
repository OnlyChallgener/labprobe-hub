import os

import pytest

from https_core import (
    atomic_write,
    certificate_covers_domain,
    certificate_details,
    certificate_domains,
    read_certificate_pair,
    render_nginx_conf,
    validate_certificate_bundle,
    validate_domain,
    validate_http_upstream,
    validate_port,
)


def test_nginx_config_has_separate_ipv4_ipv6_websocket_and_mqtt_routes():
    config = render_nginx_conf(
        58445,
        "http://127.0.0.1:58443",
        "http://127.0.0.1:9001",
        server_name="hub.example.com",
        cert_dir="/tmp/labprobe tls",
    )

    assert "listen 58445 ssl;" in config
    assert "listen [::]:58445 ssl ipv6only=on;" in config
    assert 'ssl_certificate "/tmp/labprobe tls/fullchain.pem";' in config
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in config
    assert "location = /mqtt {" in config
    assert "proxy_pass http://127.0.0.1:9001;" in config
    assert "proxy_pass http://127.0.0.1:58443;" in config
    assert "proxy_set_header Upgrade $http_upgrade;" in config
    assert "proxy_set_header X-Forwarded-Proto https;" in config
    assert config.count("proxy_read_timeout 3600s;") == 2
    assert "proxy_buffering off;" in config


def test_nginx_config_can_disable_ipv6_and_rejects_invalid_values():
    config = render_nginx_conf(58445, "http://127.0.0.1:58443", ipv6=False)
    assert "listen [::]:" not in config
    with pytest.raises(ValueError):
        render_nginx_conf(58445, "https://127.0.0.1:58443")
    with pytest.raises(ValueError):
        render_nginx_conf(58445, "http://127.0.0.1:58443/path")
    with pytest.raises(ValueError):
        render_nginx_conf(58445, "http://127.0.0.1:58443", cert_dir='/tmp"; bad')
    with pytest.raises(ValueError):
        validate_port(0)
    with pytest.raises(ValueError):
        validate_domain("a..example.com")
    with pytest.raises(ValueError):
        validate_domain("-bad.example.com")
    assert validate_http_upstream("http://[fd00::8]:58443/") == "http://[fd00::8]:58443"


def test_wildcard_certificate_matches_one_subdomain_only():
    domains = {"*.lab86.shinya.icu"}
    assert certificate_covers_domain(domains, "mq.lab86.shinya.icu")
    assert not certificate_covers_domain(domains, "lab86.shinya.icu")
    assert not certificate_covers_domain(domains, "a.b.lab86.shinya.icu")


def test_certificate_details_and_bundle_validation(https_certificate):
    cert, key = https_certificate
    details = certificate_details(cert)

    assert details.domains == frozenset({"hub.example.com", "*.example.com"})
    assert len(details.fingerprint) == 64
    assert details.chain_length == 1
    assert details.not_after > details.not_before
    assert certificate_domains(cert) == {"hub.example.com", "*.example.com"}
    assert validate_certificate_bundle(cert, key, "HUB.example.com", verify_chain=False) == details

    with pytest.raises(ValueError, match="不包含访问域名"):
        validate_certificate_bundle(cert, key, "other.test.org", verify_chain=False)
    with pytest.raises(ValueError, match="已过期"):
        validate_certificate_bundle(cert, key, "hub.example.com", verify_chain=False, now=details.not_after)
    with pytest.raises(ValueError, match="尚未生效"):
        validate_certificate_bundle(cert, key, "hub.example.com", verify_chain=False, now=details.not_before - 600)


def test_certificate_and_private_key_must_match(https_certificate, https_other_key):
    cert, _ = https_certificate
    with pytest.raises(ValueError, match="不匹配"):
        validate_certificate_bundle(cert, https_other_key, "hub.example.com", verify_chain=False)


def test_local_certificate_paths_cannot_escape_import_root(tmp_path, https_certificate):
    cert, key = https_certificate
    root = tmp_path / "import"
    root.mkdir()
    (root / "fullchain.pem").write_bytes(cert)
    (root / "privkey.pem").write_bytes(key)
    assert read_certificate_pair(root, "fullchain.pem", "privkey.pem") == (cert, key)
    with pytest.raises(ValueError, match="导入目录"):
        read_certificate_pair(root, "../fullchain.pem", "privkey.pem")


def test_atomic_write_replaces_file_with_restricted_mode(tmp_path):
    target = tmp_path / "secret.pem"
    target.write_text("old", encoding="utf-8")
    atomic_write(target, b"new", 0o600)
    assert target.read_bytes() == b"new"
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600
