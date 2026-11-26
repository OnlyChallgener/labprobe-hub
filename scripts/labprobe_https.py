#!/usr/bin/env python3
"""Validate certificates and render a standalone nginx HTTPS config."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from https_core import (  # noqa: E402
    DEFAULT_MQTT_UPSTREAM,
    DEFAULT_PORT,
    DEFAULT_UPSTREAM,
    atomic_write,
    certificate_covers_domain,
    render_nginx_conf,
    validate_certificate_bundle,
    validate_domain,
    validate_http_upstream,
    validate_port,
)


def write_pair(output_dir: Path, cert: bytes, key: bytes, port: int, upstream: str, mqtt_upstream: str, domain: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_dir, 0o700)
    atomic_write(output_dir / "fullchain.pem", cert, 0o644)
    atomic_write(output_dir / "privkey.pem", key, 0o600)
    config = render_nginx_conf(
        port,
        upstream,
        mqtt_upstream,
        server_name=domain,
        cert_dir=str(output_dir),
    )
    atomic_write(output_dir / "nginx.conf", config.encode(), 0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a certificate or render standalone nginx HTTPS configuration")
    sub = parser.add_subparsers(dest="action", required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("--domain", required=True)
    validate.add_argument("--cert", required=True)
    validate.add_argument("--key", required=True)
    validate.add_argument("--no-chain-check", action="store_true")

    render = sub.add_parser("render")
    render.add_argument("--domain", required=True)
    render.add_argument("--cert", required=True)
    render.add_argument("--key", required=True)
    render.add_argument("--output-dir", required=True)
    render.add_argument("--port", type=int, default=DEFAULT_PORT)
    render.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    render.add_argument("--mqtt-upstream", default=DEFAULT_MQTT_UPSTREAM)
    render.add_argument("--no-chain-check", action="store_true")

    args = parser.parse_args(argv)
    domain = validate_domain(args.domain)
    cert = Path(args.cert).read_bytes()
    key = Path(args.key).read_bytes()
    details = validate_certificate_bundle(cert, key, domain, verify_chain=not args.no_chain_check)
    if not certificate_covers_domain(details.domains, domain):
        raise ValueError(f"certificate does not cover {domain}")
    if args.action == "validate":
        print(json.dumps({"ok": True, "domain": domain, **details.public_dict()}, ensure_ascii=False, indent=2))
        return 0
    port = validate_port(args.port)
    upstream = validate_http_upstream(args.upstream, "Hub upstream")
    mqtt_upstream = validate_http_upstream(args.mqtt_upstream, "MQTT upstream")
    output = Path(args.output_dir)
    write_pair(output, cert, key, port, upstream, mqtt_upstream, domain)
    print(json.dumps({
        "ok": True,
        "domain": domain,
        "port": port,
        "certificate": details.public_dict(),
        "output": str(output),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
