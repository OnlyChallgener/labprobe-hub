from pathlib import Path

path = Path('hub.py')
text = path.read_text(encoding='utf-8')
if 'def merge_ipv6_neighbors_to_archive(' in text:
    raise SystemExit('merge_ipv6_neighbors_to_archive already exists')
marker = '\ndef attach_hub_local_ipv6_to_nas_devices(devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:'
if marker not in text:
    raise SystemExit('attach_hub_local_ipv6_to_nas_devices marker not found')
helper = r'''

def merge_ipv6_neighbors_to_archive(neighbors: List[Dict[str, Any]], current_prefixes: Optional[List[str]] = None) -> int:
    if not neighbors:
        return 0
    current_prefixes = current_prefixes or []
    archive = load_device_archive()
    changed = 0
    nas_macs = configured_nas_macs()
    local_records = local_hub_ipv6_records()
    local_lan_ipv4 = get_local_lan_ipv4()
    for n in neighbors:
        mac = norm_mac(n.get("mac"))
        ip = clean_saved_value(n.get("ip"))
        if not mac or not ip:
            continue
        old = archive.get(mac, {})
        is_nas = mac in nas_macs or bool(
            local_lan_ipv4 and clean_saved_value(old.get("ip") or old.get("lastIp")) == local_lan_ipv4
        )
        old_records = normalize_ipv6_records(old.get("ipv6Records") or old.get("ipv6List") or [], current_prefixes)
        by_ip = {r.get("ip"): r for r in old_records if r.get("ip")}

        source = clean_saved_value(n.get("source")) or "router_ndp"
        if is_nas:
            source = "router_ndp_crosscheck"
        seen_at = clean_saved_value(n.get("seenAt")) or now_str()
        rec = by_ip.get(ip, {"ip": ip, "firstSeen": seen_at})
        rec["lastSeen"] = seen_at
        rec["source"] = source
        rec["state"] = clean_saved_value(n.get("state"))
        rec["dev"] = clean_saved_value(n.get("dev"))
        rec["currentPrefix"] = ipv6_in_prefixes(ip, current_prefixes)
        rec["temporary"] = is_temporary_ipv6(ip, source)
        rec["primary"] = False
        if rec["state"].upper() in ["REACHABLE", "DELAY", "PROBE", "LEASED"]:
            rec["lastReachable"] = seen_at
        rec["historical"] = bool(current_prefixes and not rec["currentPrefix"] and not is_ula_ipv6(ip))
        by_ip[ip] = rec

        if is_nas:
            for local_rec in local_records:
                local_ip = local_rec.get("ip")
                if local_ip:
                    existing = by_ip.get(local_ip, {"ip": local_ip, "firstSeen": local_rec.get("firstSeen")})
                    existing.update(local_rec)
                    by_ip[local_ip] = existing

        merged_records = normalize_ipv6_records(list(by_ip.values()), current_prefixes)
        best = pick_primary_ipv6(merged_records)
        for record in merged_records:
            record["primary"] = bool(best and record.get("ip") == best)
        ipv6_list = [best] + [r["ip"] for r in sorted(merged_records, key=score_ipv6_record, reverse=True) if r.get("ip") != best]
        ipv6_list = normalize_ipv6_list(ipv6_list)
        if merged_records != old.get("ipv6Records") or ipv6_list != old.get("ipv6List") or best != old.get("ipv6"):
            old["ipv6Records"] = merged_records
            old["ipv6List"] = ipv6_list
            if best:
                old["ipv6"] = best
                old["ipv6Address"] = best
                old["globalIpv6"] = best
            old["ipv6UpdatedAt"] = now_str()
            changed += 1
        old["mac"] = mac
        old["ndpState"] = n.get("state")
        old["ndpDev"] = n.get("dev")
        old["archivedAt"] = now_str()
        archive[mac] = old
    save_device_archive(archive)
    return changed
'''
path.write_text(text.replace(marker, helper + marker, 1), encoding='utf-8')
