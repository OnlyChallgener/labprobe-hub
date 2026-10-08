"""Quarantine confirmed foreign observations; dry run unless --apply is given.

Stop the affected Hub while applying. A plan contains routerSerial and observations
with mac, address and day. IP alone, SSID alone and a MAC seen on another router
are never sufficient grounds for deleting that router's history.
"""
from __future__ import annotations

import argparse
import copy
import json
import sqlite3
import sys
from contextlib import closing
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from labprobe_storage import SQLiteStore, _json_text, _now


def matching_observation(row, observations, day=None):
    if not isinstance(row, dict):
        return False
    mac = str(row.get("mac") or "").strip().lower().replace("-", ":")
    address = str(row.get("ip") or row.get("lastIp") or "").strip()
    observed_day = day or str(row.get("time") or row.get("lastSeenAt") or row.get("archivedAt") or "")[:10]
    return (mac, address, observed_day) in observations


def repaired_documents(documents, plan):
    observations = {
        (str(row["mac"]).strip().lower().replace("-", ":"), str(row["address"]).strip(), row["day"])
        for row in plan["observations"]
    }
    if not observations or any(not all(row) for row in observations):
        raise ValueError("plan needs explicit MAC, address and day")
    output = copy.deepcopy(documents)
    removed = {}
    archive = output.get("device_archive.json", {})
    removed["device_archive.json"] = {key: row for key, row in archive.items() if matching_observation(row, observations)}
    for key in removed["device_archive.json"]:
        archive.pop(key)
    events = output.get("events.json", [])
    removed["events.json"] = [row for row in events if matching_observation(row, observations)]
    output["events.json"] = [row for row in events if not matching_observation(row, observations)]
    removed["daily.json"] = {}
    for day, record in output.get("daily.json", {}).get("days", {}).items():
        devices = record.get("devices", {})
        bad = {key: row for key, row in devices.items() if matching_observation({**row, "mac": row.get("mac") or key}, observations, day)}
        if bad:
            removed["daily.json"][day] = bad
            for key in bad:
                devices.pop(key)
    # Refuse a repair that would delete an observation still reported as online.
    for row in documents.get("devices.json", {}).get("online", []):
        if matching_observation(row, observations):
            raise ValueError("selected observation is still online; recheck the plan")
    counts = {"archive": len(removed["device_archive.json"]), "events": len(removed["events.json"]),
              "dailyRows": sum(len(rows) for rows in removed["daily.json"].values())}
    return output, removed, counts


def router_serial(store):
    dashboard = store.load(store.data_dir / "router_dashboard.json", {})
    path = store.data_dir / "router_dashboard.json"
    if path.exists():
        dashboard = json.loads(path.read_text(encoding="utf-8"))
    details = dashboard.get("details", {})
    return str(details.get("identity", {}).get("serialNumber") or details.get("ap", {}).get("serialNumber") or "").strip()


def repair(store, plan, apply=False):
    expected = str(plan.get("routerSerial") or "").strip()
    if not expected or router_serial(store) != expected:
        raise ValueError("router serial does not match repair plan")
    keys = ("device_archive.json", "events.json", "daily.json", "devices.json")
    with store._lock, store.connect() as conn:
        documents = {key: store.load(store.data_dir / key, {} if key != "events.json" else []) for key in keys}
        after, removed, counts = repaired_documents(documents, plan)
        if not apply or not any(counts.values()):
            return {"applied": False, **counts}
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        target = store.backups_dir / ("device-history-repair-" + stamp)
        target.mkdir(parents=True, exist_ok=False)
        with closing(sqlite3.connect(str(target / "labprobe-before.db"))) as backup:
            conn.backup(backup)
        (target / "quarantine.json").write_text(
            json.dumps({"plan": plan, "removed": removed, "counts": counts}, ensure_ascii=False, indent=2), encoding="utf-8")
        conn.execute("BEGIN IMMEDIATE")
        try:
            # Refresh under the write lock; preserve any newer legitimate row.
            documents = {}
            for key in keys:
                row = conn.execute("SELECT value_json FROM documents WHERE key=?", (key,)).fetchone()
                documents[key] = json.loads(row[0]) if row else ([] if key == "events.json" else {})
            after, removed, counts = repaired_documents(documents, plan)
            for key in keys:
                if after[key] == documents[key]:
                    continue
                conn.execute("UPDATE documents SET value_json=?,updated_at=? WHERE key=?", (_json_text(after[key]), _now(), key))
                for entity, operation, entity_key, payload in store._changes_for_document(key, documents[key], after[key]):
                    conn.execute("INSERT INTO revisions(entity,operation,entity_key,payload_json,created_at) VALUES(?,?,?,?,?)",
                                 (entity, operation, entity_key, _json_text(payload) if payload is not None else None, _now()))
            # A repair can consist solely of old event/rollup observations.
            conn.execute("INSERT INTO revisions(entity,operation,entity_key,payload_json,created_at) VALUES(?,?,?,?,?)",
                         ("system", "snapshot_reset", "device_history_repair", None, _now()))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        (target / "quarantine.json").write_text(
            json.dumps({"plan": plan, "removed": removed, "counts": counts}, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"applied": True, "backup": str(target), **counts}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--backups-dir", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    store = SQLiteStore(args.data_dir, args.backups_dir)
    if not store.db_path.is_file():
        raise SystemExit("existing SQLite database required")
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    print(json.dumps(repair(store, plan, args.apply), ensure_ascii=False))
