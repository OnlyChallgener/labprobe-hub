#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_rdpi_custom_signatures.py

Router RDPI Custom Signature Manager for Ruijie / Reyee routers (e.g. BE72/EW7200).
Allows reading, adding, modifying, removing custom application signatures in
/usr/share/ndpi/db.default.json and triggering hot-reload via `ubus send rdpi_reinit`.
"""

import argparse
import json
import sys
import paramiko
from paramiko.transport import Transport
from paramiko.rsakey import RSAKey
from cryptography.hazmat.primitives import hashes

# Enable legacy ssh-rsa host key support for router Dropbear SSH
RSAKey.HASHES["ssh-rsa"] = hashes.SHA1
Transport._key_info["ssh-rsa"] = RSAKey
Transport._preferred_keys = ("ssh-rsa", "rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519")

DEFAULT_HOST = "111.23.167.108"
DEFAULT_PORT = 13512
DEFAULT_USER = "root"
DEFAULT_PASS = "Re238950"
REMOTE_DB_PATH = "/usr/share/ndpi/db.default.json"
REMOTE_BAK_PATH = "/usr/share/ndpi/db.default.json.bak"


def get_ssh_client(host=DEFAULT_HOST, port=DEFAULT_PORT, user=DEFAULT_USER, password=DEFAULT_PASS, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password, timeout=timeout)
    return client


def remote_exec(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return out, err


def load_remote_db(client):
    out, err = remote_exec(client, f"cat {REMOTE_DB_PATH}")
    if not out.strip():
        raise RuntimeError(f"Failed to read {REMOTE_DB_PATH}: {err}")
    return json.loads(out)


def save_remote_db(client, db_data, reload_rdpi=True):
    # Backup original first if not already backed up
    remote_exec(client, f"[ ! -f {REMOTE_BAK_PATH} ] && cp {REMOTE_DB_PATH} {REMOTE_BAK_PATH}")
    
    # Format JSON
    content = json.dumps(db_data, ensure_ascii=False, indent=2)
    # Upload via base64 to avoid escaping issues
    import base64
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    
    cmd = (
        f"echo '{b64}' | base64 -d > /tmp/db.default.json.tmp && "
        f"cp /tmp/db.default.json.tmp {REMOTE_DB_PATH} && "
        f"rm -f /tmp/db.default.json.tmp"
    )
    out, err = remote_exec(client, cmd)
    if err.strip():
        raise RuntimeError(f"Failed to write remote db: {err}")
    
    if reload_rdpi:
        reload_out, reload_err = trigger_rdpi_reload(client)
        return reload_out
    return "Saved successfully."


def trigger_rdpi_reload(client):
    cmd = "ubus -t 3 send 'rdpi_reinit'"
    out, err = remote_exec(client, cmd)
    return f"Triggered ubus rdpi_reinit (out: {out.strip()}, err: {err.strip()})", err


def list_signatures(client, filter_keyword=None):
    db = load_remote_db(client)
    apps = db.get("apps", [])
    print(f"Total signatures in router db: {len(apps)}")
    matched = []
    for app in apps:
        name = app.get("name", "")
        idx = app.get("index", "")
        if filter_keyword:
            if filter_keyword.lower() not in name.lower() and filter_keyword.lower() not in idx.lower():
                continue
        matched.append(app)
    
    print(f"Matched {len(matched)} signatures:")
    for app in matched:
        print(f"  [{app.get('index')}] {app.get('name')}")
        for r in app.get("rules", []):
            proto = r.get("protocol", "any")
            hosts = r.get("hosts", [])
            payloads = r.get("payloads", [])
            details = []
            if hosts:
                details.append(f"hosts={hosts}")
            if payloads:
                p_strs = [f"pos={p.get('pos')}:len={p.get('length')}:{p.get('payload')}" for p in payloads]
                details.append(f"payloads=[{', '.join(p_strs)}]")
            print(f"    - {proto}: {' | '.join(details)}")


def add_or_update_signature(client, index, name, proto="tcp", payload=None, pos=0, hosts=None):
    db = load_remote_db(client)
    apps = db.get("apps", [])
    
    existing = next((a for a in apps if a.get("index") == index or a.get("name") == name), None)
    
    rule = {"protocol": proto.lower()}
    if payload:
        clean_hex = payload.replace(" ", "").replace("0x", "")
        chunks = [clean_hex[i:i+2] for i in range(0, len(clean_hex), 2)]
        formatted_payload = " ".join(chunks)
        rule["payloads"] = [{
            "pos": pos,
            "length": len(chunks),
            "payload": formatted_payload
        }]
    if hosts:
        host_list = [h.strip() for h in hosts.split(",") if h.strip()]
        if host_list:
            rule["hosts"] = host_list
            
    if existing:
        print(f"Updating existing app [{existing.get('index')}] {existing.get('name')}")
        existing["index"] = index
        existing["name"] = name
        existing["rules"].append(rule)
    else:
        print(f"Adding new app signature [{index}] {name}")
        new_app = {
            "index": index,
            "name": name,
            "rules": [rule]
        }
        apps.append(new_app)
        
    db["apps"] = apps
    msg = save_remote_db(client, db, reload_rdpi=True)
    print(f"Success: {msg}")


def remove_signature(client, target):
    db = load_remote_db(client)
    apps = db.get("apps", [])
    before = len(apps)
    apps = [a for a in apps if a.get("index") != target and a.get("name") != target]
    after = len(apps)
    if before == after:
        print(f"No signature found matching '{target}'.")
        return
    print(f"Removed {before - after} signature(s).")
    db["apps"] = apps
    msg = save_remote_db(client, db, reload_rdpi=True)
    print(f"Success: {msg}")


def check_status(client):
    print("--- /proc/net/sniffer_info ---")
    out, _ = remote_exec(client, "cat /proc/net/sniffer_info 2>/dev/null || echo 'not available'")
    print(out.strip())
    print("\n--- /proc/flow_audit ---")
    out, _ = remote_exec(client, "head -n 20 /proc/flow_audit 2>/dev/null || echo 'not available'")
    print(out.strip())


def main():
    parser = argparse.ArgumentParser(description="Ruijie RDPI Custom Signature Tool")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Router SSH host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Router SSH port")
    parser.add_argument("--user", default=DEFAULT_USER, help="Router SSH username")
    parser.add_argument("--password", default=DEFAULT_PASS, help="Router SSH password")
    
    sub = parser.add_subparsers(dest="action")
    
    p_list = sub.add_parser("list", help="List router signatures")
    p_list.add_argument("--filter", help="Filter by name or index")
    
    p_add = sub.add_parser("add", help="Add or update a signature")
    p_add.add_argument("--index", required=True, help="App index (e.g. 4-900-1-0)")
    p_add.add_argument("--name", required=True, help="App name")
    p_add.add_argument("--proto", default="tcp", choices=["tcp", "udp"], help="Protocol")
    p_add.add_argument("--payload", help="Hex payload (e.g. '72 34 e4 34')")
    p_add.add_argument("--pos", type=int, default=0, help="Payload offset position")
    p_add.add_argument("--hosts", help="Comma-separated hosts (e.g. '*.mygame.com')")
    
    p_remove = sub.add_parser("remove", help="Remove a signature by index or name")
    p_remove.add_argument("--target", required=True, help="App index or name to remove")
    
    sub.add_parser("reload", help="Trigger ubus rdpi_reinit")
    sub.add_parser("status", help="Show sniffer info and flow audit")
    
    args = parser.parse_args()
    if not args.action:
        parser.print_help()
        return

    client = get_ssh_client(args.host, args.port, args.user, args.password)
    try:
        if args.action == "list":
            list_signatures(client, args.filter)
        elif args.action == "add":
            add_or_update_signature(client, args.index, args.name, args.proto, args.payload, args.pos, args.hosts)
        elif args.action == "remove":
            remove_signature(client, args.target)
        elif args.action == "reload":
            msg, _ = trigger_rdpi_reload(client)
            print(msg)
        elif args.action == "status":
            check_status(client)
    finally:
        client.close()


if __name__ == "__main__":
    main()
