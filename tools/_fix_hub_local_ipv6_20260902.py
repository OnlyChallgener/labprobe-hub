from pathlib import Path

path = Path('hub.py')
text = path.read_text(encoding='utf-8')
start = text.index('def local_hub_ipv6_records() -> List[Dict[str, Any]]:')
end = text.index('\ndef attach_hub_local_ipv6_to_nas_devices', start)
new = '''def local_hub_ipv6_records() -> List[Dict[str, Any]]:
    """Return every usable global IPv6 currently configured on the Hub host.

    Route-source selection remains the primary signal, but exposing only that
    one address hid stable/compact addresses such as ``prefix::1c3b`` from the
    APP.  Keep all live global addresses with explicit state/prefix metadata so
    the APP can prefer a compact stable address while rejecting deprecated or
    tentative ones.
    """
    stamp = now_str()
    route_src = normalize_ipv6_list([get_route_source_ipv6()])
    primary_ip = route_src[0] if route_src else ""
    primary_prefix = ""
    if primary_ip:
        try:
            primary_prefix = str(ipaddress.IPv6Network(f"{primary_ip}/64", strict=False))
        except Exception:
            primary_prefix = ""

    rows: List[Dict[str, Any]] = []
    try:
        output = subprocess.check_output(
            ["ip", "-6", "-o", "addr", "show", "scope", "global"],
            text=True,
            timeout=3,
        )
    except Exception:
        output = ""

    for line in output.splitlines():
        match = re.search(r"\\binet6\\s+([0-9A-Fa-f:]+)/\\d+", line)
        if not match:
            continue
        values = normalize_ipv6_list([match.group(1)])
        if not values:
            continue
        ip = values[0]
        lowered = line.lower()
        if "dadfailed" in lowered:
            state = "DADFAILED"
        elif "tentative" in lowered:
            state = "TENTATIVE"
        elif "deprecated" in lowered:
            state = "DEPRECATED"
        else:
            state = "REACHABLE"
        current_prefix = True
        if primary_prefix:
            try:
                current_prefix = str(ipaddress.IPv6Network(f"{ip}/64", strict=False)) == primary_prefix
            except Exception:
                current_prefix = False
        temporary = " temporary " in f" {lowered} " or is_temporary_ipv6(ip, "hub_local_probe")
        rows.append({
            "ip": ip,
            "firstSeen": stamp,
            "lastSeen": stamp,
            "lastReachable": stamp if state == "REACHABLE" else "",
            "source": "hub_local_probe",
            "state": state,
            "dev": "hub",
            "currentPrefix": current_prefix,
            "temporary": temporary,
            "historical": bool(primary_prefix and not current_prefix and not is_ula_ipv6(ip)),
            "primary": bool(primary_ip and ip == primary_ip),
        })

    # Route-source is authoritative fallback if iproute did not expose it.
    if primary_ip and not any(row.get("ip") == primary_ip for row in rows):
        rows.append({
            "ip": primary_ip,
            "firstSeen": stamp,
            "lastSeen": stamp,
            "lastReachable": stamp,
            "source": "hub_local_probe",
            "state": "REACHABLE",
            "dev": "hub",
            "currentPrefix": True,
            "temporary": is_temporary_ipv6(primary_ip, "hub_local_probe"),
            "historical": False,
            "primary": True,
        })

    dedup: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        dedup[row["ip"]] = row
    return list(dedup.values())[:24]

'''
text = text[:start] + new + text[end + 1:]
path.write_text(text, encoding='utf-8')
