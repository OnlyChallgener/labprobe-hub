"""Restore the IPv6-neighbor archive helper used by the legacy Hub push route.

The Router Core cutover keeps ``/api/router/push`` in ``hub.py`` for the
LabRelay/router telemetry contract.  Some test bundles retained the call to
``merge_ipv6_neighbors_to_archive`` while accidentally dropping its helper
body.  Install the helper back into the imported ``hub`` module without
changing Router Core, Session, RPC, or WSS.
"""
from typing import Any, Dict, List, Optional


def install_ipv6_neighbor_archive_patch(hub: Any):
    """Install the missing helper into ``hub`` and return the active function.

    If a future Hub already provides the helper natively, leave it untouched.
    """
    existing = getattr(hub, "merge_ipv6_neighbors_to_archive", None)
    if callable(existing):
        return existing

    def merge_ipv6_neighbors_to_archive(
        neighbors: List[Dict[str, Any]],
        current_prefixes: Optional[List[str]] = None,
    ) -> int:
        if not neighbors:
            return 0

        current_prefixes = current_prefixes or []
        archive = hub.load_device_archive()
        changed = 0
        nas_macs = hub.configured_nas_macs()
        local_records = hub.local_hub_ipv6_records()
        local_lan_ipv4 = hub.get_local_lan_ipv4()

        for neighbor in neighbors:
            mac = hub.norm_mac(neighbor.get("mac"))
            ip = hub.clean_saved_value(neighbor.get("ip"))
            if not mac or not ip:
                continue

            old = archive.get(mac, {})
            is_nas = mac in nas_macs or bool(
                local_lan_ipv4
                and hub.clean_saved_value(old.get("ip") or old.get("lastIp")) == local_lan_ipv4
            )
            old_records = hub.normalize_ipv6_records(
                old.get("ipv6Records") or old.get("ipv6List") or [],
                current_prefixes,
            )
            by_ip = {record.get("ip"): record for record in old_records if record.get("ip")}

            source = hub.clean_saved_value(neighbor.get("source")) or "router_ndp"
            if is_nas:
                # Router NDP for the Hub/NAS is cross-check data only.  The
                # Hub-local probe remains authoritative for the NAS address.
                source = "router_ndp_crosscheck"
            seen_at = hub.clean_saved_value(neighbor.get("seenAt")) or hub.now_str()
            record = by_ip.get(ip, {"ip": ip, "firstSeen": seen_at})
            record["lastSeen"] = seen_at
            record["source"] = source
            record["state"] = hub.clean_saved_value(neighbor.get("state"))
            record["dev"] = hub.clean_saved_value(neighbor.get("dev"))
            record["currentPrefix"] = hub.ipv6_in_prefixes(ip, current_prefixes)
            record["temporary"] = hub.is_temporary_ipv6(ip, source)
            record["primary"] = False
            if record["state"].upper() in {"REACHABLE", "DELAY", "PROBE", "LEASED"}:
                record["lastReachable"] = seen_at
            record["historical"] = bool(
                current_prefixes
                and not record["currentPrefix"]
                and not hub.is_ula_ipv6(ip)
            )
            by_ip[ip] = record

            if is_nas:
                for local_record in local_records:
                    local_ip = local_record.get("ip")
                    if not local_ip:
                        continue
                    existing_record = by_ip.get(
                        local_ip,
                        {"ip": local_ip, "firstSeen": local_record.get("firstSeen")},
                    )
                    existing_record.update(local_record)
                    by_ip[local_ip] = existing_record

            # Re-evaluate all records after prefix changes.  Old GUA addresses
            # stay as history, but no longer win primary selection.
            merged_records = hub.normalize_ipv6_records(list(by_ip.values()), current_prefixes)
            best = hub.pick_primary_ipv6(merged_records)
            for merged in merged_records:
                merged["primary"] = bool(best and merged.get("ip") == best)
            ipv6_list = [best] + [
                merged["ip"]
                for merged in sorted(merged_records, key=hub.score_ipv6_record, reverse=True)
                if merged.get("ip") != best
            ]
            ipv6_list = hub.normalize_ipv6_list(ipv6_list)

            if (
                merged_records != old.get("ipv6Records")
                or ipv6_list != old.get("ipv6List")
                or best != old.get("ipv6")
            ):
                old["ipv6Records"] = merged_records
                old["ipv6List"] = ipv6_list
                if best:
                    old["ipv6"] = best
                    old["ipv6Address"] = best
                    old["globalIpv6"] = best
                old["ipv6UpdatedAt"] = hub.now_str()
                changed += 1

            old["mac"] = mac
            old["ndpState"] = neighbor.get("state")
            old["ndpDev"] = neighbor.get("dev")
            old["archivedAt"] = hub.now_str()
            archive[mac] = old

        hub.save_device_archive(archive)
        return changed

    hub.merge_ipv6_neighbors_to_archive = merge_ipv6_neighbors_to_archive
    return merge_ipv6_neighbors_to_archive
