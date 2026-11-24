#!/usr/bin/env python3
"""Offline configuration checks for the protocols retained in the compact build."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
args = parser.parse_args()
uid = '11111111-1111-4111-8111-111111111111'
nodes = [
    {'type': 'ss', 'cipher': 'aes-128-gcm', 'password': 'local-test-only'},
    {'type': 'vmess', 'uuid': uid, 'alterId': 0, 'cipher': 'auto'},
    {'type': 'vless', 'uuid': uid},
    {'type': 'trojan', 'password': 'local-test-only'},
    {'type': 'hysteria2', 'password': 'local-test-only'},
    {'type': 'tuic', 'uuid': uid, 'password': 'local-test-only', 'udp-relay-mode': 'native'},
    {'type': 'http'},
    {'type': 'socks5'},
]
results = []
with tempfile.TemporaryDirectory(prefix='mihomo-protocol-qa-') as home:
    for node in nodes:
        config = {'mode': 'rule', 'log-level': 'warning', 'tun': {'enable': False},
                  'dns': {'enable': False}, 'rules': ['MATCH,DIRECT'],
                  'proxies': [{'name': 'local-test', 'server': '127.0.0.1', 'port': 14443, **node}]}
        path = Path(home) / 'config.yaml'
        path.write_text(json.dumps(config))
        completed = subprocess.run([args.binary, '-t', '-d', home, '-f', str(path)],
                                   capture_output=True, text=True, timeout=12)
        result = {'protocol': node['type'], 'configuration_accepted': completed.returncode == 0}
        if completed.returncode:
            result['diagnostic'] = (completed.stdout + completed.stderr)[-1500:]
        results.append(result)
ok = all(item['configuration_accepted'] for item in results)
print(json.dumps({'ok': ok, 'network_scope': 'offline; no outbound connections requested',
                  'checks': results}))
raise SystemExit(0 if ok else 1)
