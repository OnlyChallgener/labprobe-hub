"""Compare the router's child-guard membership with what the Hub has cached.

Why this exists: ``/api/router/child-guard/devices`` is the only route that runs
``get_users`` and writes ``child_guard_device``, and the App's 儿童上网 page never
calls it — it only reads ``/child-guard/overview``, which is a pure local read. So
devices added in the vendor app stay invisible in LabProbe indefinitely. Measured
2026-09-21 on the BE72: firmware had 7 uids / 9 MACs, the Hub had 4 uids / 6 MACs,
and the iPad's minutes were being recorded while no parent-facing row existed.

This script is the before/after check for a refresh fix. It holds no credentials:
it reads two dumps produced by the commands in ``DUMPING`` below.

Exit code: 0 = in sync, 1 = drift (so it can gate a deploy or a cron alert).
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

DUMPING = """\
Producing the two inputs
------------------------
Router (run over the NAS jump; TSV, one row per uid and per MAC flag):

    for s in $(uci show 2>/dev/null | grep -o "child_guard\\.[A-F0-9]\\{8,\\}" | sort -u | sed 's/child_guard\\.//'); do
      printf 'UID\\t%s\\t%s\\t%s\\n' "$s" "$(uci get child_guard.$s.name 2>/dev/null)" \\
        "$(uci get child_guard.$s.mac 2>/dev/null | tr ' ' ',')"
    done
    awk 'NF>=3 && $1 ~ /^[0-9a-fA-F:]{17}$/ {printf "MAC\\t%s\\t%s\\t%s\\n", $1, $2, $3}' /proc/net/sniffer_info

Hub (docker exec python3 - <<'PY' ... PY): see --hub example in README, or

    import json, sqlite3, time
    c = sqlite3.connect('/app/data/usage.db')
    out = {"cached": [], "lastGetUsers": None, "recordedMacs": []}
    for uid, name, macs, updated in c.execute(
            "SELECT uid, name, macs, updated_at FROM child_guard_device"):
        out["cached"].append({"uid": uid, "name": name,
                              "macs": [m for m in (macs or "").split(",") if m],
                              "updatedAt": updated})
    d = json.load(open('/app/data/child_guard_commands.json'))
    gu = [x for x in d.get("commands", []) if x.get("action") == "get_users"]
    if gu:
        last = max(gu, key=lambda x: x.get("createdEpoch", 0))
        res = last.get("result") or {}
        devices = (res.get("data") or res).get("devices") or []
        out["lastGetUsers"] = {"createdAt": last.get("createdAt"), "devices": [
            {"uid": x.get("uid"), "name": x.get("name"),
             "macs": [str(m).lower() for m in (x.get("macs") or [])]} for x in devices]}
    day = time.strftime('%Y-%m-%d', time.gmtime(time.time() + 28800))
    for mac, rows, newest in c.execute(
            "SELECT mac, COUNT(*), MAX(minute_epoch) FROM usage_device_minute"
            " WHERE date=? GROUP BY mac", (day,)):
        out["recordedMacs"].append({"mac": mac, "rows": rows, "newestMinute": newest})
    print(json.dumps(out, ensure_ascii=False))
"""


def parse_router(text: str) -> Dict[str, Any]:
    uids: Dict[str, Dict[str, Any]] = {}
    flags: Dict[str, Dict[str, str]] = {}
    for line in text.splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 2:
            continue
        kind = parts[0].strip().upper()
        if kind == "UID":
            uid = parts[1].strip()
            macs = [m.strip().lower() for m in (parts[3] if len(parts) > 3 else "").replace(",", " ").split() if m.strip()]
            uids[uid] = {"uid": uid, "name": (parts[2].strip() if len(parts) > 2 else ""), "macs": macs}
        elif kind == "MAC":
            flags[parts[1].strip().lower()] = {"child": parts[2].strip() if len(parts) > 2 else "",
                                               "idyc": parts[3].strip() if len(parts) > 3 else ""}
    return {"uids": uids, "flags": flags}


def norm(value: Any) -> Set[str]:
    return {str(mac).strip().lower() for mac in (value or []) if str(mac).strip()}


def compare(router: Dict[str, Any], hub: Dict[str, Any]) -> Tuple[List[str], bool]:
    cached = {str(row.get("uid") or ""): row for row in hub.get("cached") or []}
    firmware = router["uids"]
    lines: List[str] = []
    drift = False

    fw_macs = {m for row in firmware.values() for m in norm(row["macs"])}
    cached_macs = {m for row in cached.values() for m in norm(row.get("macs"))}
    lines.append(f"固件 uid={len(firmware)} mac={len(fw_macs)}   "
                 f"Hub 缓存 uid={len(cached)} mac={len(cached_macs)}   "
                 f"sniffer_info CHILD=1 mac={sum(1 for f in router['flags'].values() if f['child'] == '1')}")

    missing = sorted(set(firmware) - set(cached))
    extra = sorted(set(cached) - set(firmware))
    for uid in missing:
        row = firmware[uid]
        lines.append(f"  [缺失] {uid} name={row['name'] or '(无名)'} mac={','.join(row['macs'])}")
    for uid in extra:
        row = cached[uid]
        lines.append(f"  [多余] {uid} name={row.get('name') or '(无名)'} mac={','.join(norm(row.get('macs')))}")
    for uid in sorted(set(firmware) & set(cached)):
        want, got = firmware[uid], cached[uid]
        if norm(want["macs"]) != norm(got.get("macs")):
            drift = True
            lines.append(f"  [MAC 不一致] {uid} 固件={sorted(norm(want['macs']))} 缓存={sorted(norm(got.get('macs')))}")
        if want["name"] and got.get("name") and want["name"] != got.get("name"):
            lines.append(f"  [名称不一致] {uid} 固件={want['name']!r} 缓存={got.get('name')!r}")

    last = hub.get("lastGetUsers") or {}
    lines.append(f"  最后一次 get_users: {last.get('createdAt') or '从未'} "
                 f"(返回 {len(last.get('devices') or [])} 台)")

    # The user-visible consequence: minutes recorded for a MAC no cached uid covers.
    blind = []
    for row in hub.get("recordedMacs") or []:
        mac = str(row.get("mac") or "").lower()
        if mac and mac not in cached_macs:
            blind.append((mac, row.get("rows"), row.get("newestMinute")))
    if blind:
        drift = True
        lines.append(f"  [在记录但家长端看不到] {len(blind)} 个 MAC：")
        for mac, rows, newest in sorted(blind, key=lambda item: -int(item[1] or 0)):
            try:
                stamp = datetime.datetime.utcfromtimestamp(int(newest) + 8 * 3600).strftime("%H:%M")
            except Exception:
                stamp = "?" 
            lines.append(f"      {mac} 今日 {rows} 行 最新分钟 {stamp}")
    else:
        lines.append("  [在记录但家长端看不到] 无")
    return lines, drift or bool(missing) or bool(extra)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--router", required=True, type=Path, help="TSV dumped from the router")
    parser.add_argument("--hub", required=True, type=Path, help="JSON dumped from the Hub container")
    args = parser.parse_args(argv)
    hub = json.loads(args.hub.read_text(encoding="utf-8"))
    report, drift = compare(parse_router(args.router.read_text(encoding="utf-8")), hub)
    print("\n".join(report))
    print("结论: " + ("有漂移 —— 家长端设备目录不是固件的真值" if drift else "一致"))
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
