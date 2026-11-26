import base64
import json

from scripts import labprobe_https


def test_validate_cli_does_not_print_private_key(https_certificate, tmp_path, capsys):
    cert, key = https_certificate
    cert_path = tmp_path / "fullchain.pem"
    key_path = tmp_path / "privkey.pem"
    cert_path.write_bytes(cert)
    key_path.write_bytes(key)

    assert labprobe_https.main([
        "validate", "--domain", "hub.example.com", "--cert", str(cert_path),
        "--key", str(key_path), "--no-chain-check",
    ]) == 0

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["ok"] is True
    assert payload["fingerprint"]
    assert "PRIVATE KEY" not in output
    assert base64.b64encode(key).decode() not in output


def test_render_cli_writes_only_local_certificate_and_config(https_certificate, tmp_path):
    cert, key = https_certificate
    cert_path = tmp_path / "fullchain.pem"
    key_path = tmp_path / "privkey.pem"
    cert_path.write_bytes(cert)
    key_path.write_bytes(key)
    output = tmp_path / "output"

    assert labprobe_https.main([
        "render", "--domain", "hub.example.com", "--cert", str(cert_path),
        "--key", str(key_path), "--output-dir", str(output), "--no-chain-check",
    ]) == 0

    assert (output / "fullchain.pem").read_bytes() == cert
    assert (output / "privkey.pem").read_bytes() == key
    config = (output / "nginx.conf").read_text(encoding="utf-8")
    assert "listen 58445 ssl;" in config
    assert "location = /mqtt {" in config
