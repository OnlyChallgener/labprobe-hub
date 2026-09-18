#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simulate_rdpi_traffic.py

DPI Traffic Simulation Tool.
Executes on the NAS (192.168.5.46) to generate synthetic application traffic matching
router RDPI rules (e.g. 王者荣耀, 微信, or custom hex payload) through the router
gateway (192.168.5.1), then checks router /proc/flow_audit and /proc/net/sniffer_flow
to verify detection.
"""

import argparse
import sys
import time
import paramiko
from paramiko.transport import Transport
from paramiko.rsakey import RSAKey
from cryptography.hazmat.primitives import hashes

# Enable legacy ssh-rsa host key support
RSAKey.HASHES["ssh-rsa"] = hashes.SHA1
Transport._key_info["ssh-rsa"] = RSAKey
Transport._preferred_keys = ("ssh-rsa", "rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519")

ROUTER_HOST = "111.23.167.108"
ROUTER_PORT = 13512
ROUTER_USER = "root"
ROUTER_PASS = "Re238950"

NAS_HOST = "192.168.5.46"
NAS_PORT = 2122
NAS_USER = "18617143092"
NAS_PASS = "Tj19950115"

PRESETS = {
    "wangzhe_udp": {
        "desc": "王者荣耀 UDP 特征包 (01 02 00 00 9A BC)",
        "proto": "udp",
        "target_host": "119.29.29.29",
        "target_port": 10012,
        "payload_hex": "01 02 00 00 9A BC 00 00 00 00 12 34 56 78",
        "pos": 0
    },
    "wangzhe_tcp": {
        "desc": "王者荣耀 TCP 特征包 (pos 10: 72 34 e4 34)",
        "proto": "tcp",
        "target_host": "119.29.29.29",
        "target_port": 8013,
        "payload_hex": "00 00 00 00 00 00 00 00 00 00 72 34 e4 34 00 01",
        "pos": 10
    },
    "wechat": {
        "desc": "微信/WeChat HTTPS 握手模拟",
        "proto": "tcp",
        "target_host": "szextshort.weixin.qq.com",
        "target_port": 443,
        "payload_hex": "",
        "pos": 0
    }
}


def get_ssh_client(host, port, user, password, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password, timeout=timeout)
    return client


def send_traffic_from_nas(nas_client, proto, host, port, payload_bytes, count=10, delay=0.1):
    """Run a inline Python script on the NAS to send packets."""
    import base64
    b64_payload = base64.b64encode(payload_bytes).decode("ascii")
    
    python_script = f"""
import socket, time, base64

proto = "{proto.lower()}"
target_host = "{host}"
target_port = {port}
payload = base64.b64decode("{b64_payload}")
count = {count}
delay = {delay}

print(f"NAS: sending {{count}} {{proto.upper()}} packets to {{target_host}}:{{target_port}} (payload len: {{len(payload)}})...")

if proto == "udp":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(count):
        try:
            sock.sendto(payload, (target_host, target_port))
            time.sleep(delay)
        except Exception as e:
            print(f"Error sending UDP: {{e}}")
            break
    sock.close()
    print("NAS: UDP transmission finished.")
elif proto == "tcp":
    for i in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect((target_host, target_port))
            sock.sendall(payload)
            time.sleep(delay)
            sock.close()
        except Exception as e:
            # Connect may fail if destination refuses, but SYN+Payload or SYN was routed
            pass
    print("NAS: TCP transmission finished.")
"""
    b64_script = base64.b64encode(python_script.encode("utf-8")).decode("ascii")
    cmd = f"python3 -c \"$(echo '{b64_script}' | base64 -d)\""
    stdin, stdout, stderr = nas_client.exec_command(cmd)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return out, err


def query_router_audit(router_client, nas_ip="192.168.5.46"):
    """Check /proc/flow_audit and sniffer on router."""
    cmd = f"grep '{nas_ip}' /proc/flow_audit 2>/dev/null | tail -n 10"
    stdin, stdout, stderr = router_client.exec_command(cmd)
    audit_out = stdout.read().decode("utf-8", errors="replace")
    
    cmd_flow = "cat /proc/net/sniffer_flow 2>/dev/null"
    stdin, stdout, stderr = router_client.exec_command(cmd_flow)
    sniffer_out = stdout.read().decode("utf-8", errors="replace")
    
    return audit_out, sniffer_out


def main():
    parser = argparse.ArgumentParser(description="Simulate RDPI Traffic from NAS through Router")
    parser.add_argument("--preset", choices=list(PRESETS.keys()), default="wangzhe_udp", help="Traffic preset to send")
    parser.add_argument("--proto", choices=["tcp", "udp"], help="Override protocol")
    parser.add_argument("--host", help="Target host")
    parser.add_argument("--port", type=int, help="Target port")
    parser.add_argument("--payload", help="Custom hex payload string (e.g. '01 02 00 00 9A BC')")
    parser.add_argument("--count", type=int, default=5, help="Number of packets/connections to send")
    parser.add_argument("--nas-ip", default="192.168.5.46", help="NAS LAN IP")
    
    args = parser.parse_args()
    
    cfg = PRESETS.get(args.preset, {}).copy()
    if args.proto: cfg["proto"] = args.proto
    if args.host: cfg["target_host"] = args.host
    if args.port: cfg["target_port"] = args.port
    if args.payload: cfg["payload_hex"] = args.payload
    
    clean_hex = cfg.get("payload_hex", "").replace(" ", "").replace("0x", "")
    payload_bytes = bytes.fromhex(clean_hex) if clean_hex else b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    print(f"=== Starting Traffic Simulation ===")
    print(f"Preset: {args.preset} ({cfg.get('desc', '')})")
    print(f"Protocol: {cfg['proto'].upper()} -> {cfg['target_host']}:{cfg['target_port']}")
    print(f"Payload ({len(payload_bytes)} bytes): {payload_bytes.hex()}")
    
    # Connect to NAS
    print(f"Connecting to NAS ({NAS_HOST}:{NAS_PORT})...")
    nas_client = get_ssh_client(NAS_HOST, NAS_PORT, NAS_USER, NAS_PASS)
    
    try:
        out, err = send_traffic_from_nas(
            nas_client,
            proto=cfg["proto"],
            host=cfg["target_host"],
            port=cfg["target_port"],
            payload_bytes=payload_bytes,
            count=args.count
        )
        print(out.strip())
        if err.strip():
            print("NAS stderr:", err.strip())
    finally:
        nas_client.close()
        
    time.sleep(1)
    
    # Query Router
    print(f"\nConnecting to Router ({ROUTER_HOST}:{ROUTER_PORT}) to inspect flow audit...")
    router_client = get_ssh_client(ROUTER_HOST, ROUTER_PORT, ROUTER_USER, ROUTER_PASS)
    try:
        audit_out, sniffer_out = query_router_audit(router_client, args.nas_ip)
        print("--- Router Flow Audit Matches for NAS (192.168.5.46) ---")
        if audit_out.strip():
            print(audit_out.strip())
        else:
            print("(No active flow_audit entry matched NAS IP)")
            
        print("\n--- Router /proc/net/sniffer_flow ---")
        if sniffer_out.strip():
            print(sniffer_out.strip())
        else:
            print("(sniffer_flow is currently quiet or device is not in child guard table)")
    finally:
        router_client.close()
        
    print("\n=== Simulation Complete ===")


if __name__ == "__main__":
    main()
