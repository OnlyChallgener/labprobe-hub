import shutil
import subprocess

import pytest


def _openssl(*args: str) -> bytes:
    executable = shutil.which("openssl")
    if not executable:
        pytest.skip("openssl is required for certificate tests")
    result = subprocess.run(
        [executable, *args],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return result.stdout


@pytest.fixture(scope="session")
def https_certificate(tmp_path_factory):
    directory = tmp_path_factory.mktemp("https-certificate")
    cert_path = directory / "fullchain.pem"
    key_path = directory / "privkey.pem"
    _openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=hub.example.com",
        "-addext", "subjectAltName=DNS:hub.example.com,DNS:*.example.com",
        "-keyout", str(key_path),
        "-out", str(cert_path),
    )
    return cert_path.read_bytes(), key_path.read_bytes()


@pytest.fixture(scope="session")
def https_other_key(tmp_path_factory):
    directory = tmp_path_factory.mktemp("https-other-key")
    key_path = directory / "other-key.pem"
    _openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key_path))
    return key_path.read_bytes()
