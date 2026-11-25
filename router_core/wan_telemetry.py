from __future__ import annotations

from typing import Any, Dict, List, Mapping, Tuple


_FIELDS: Dict[str, Tuple[str, ...]] = {
    "uploadBps": ("tx_rate_bps", "tx_rate", "upload_rate_bps", "up", "uploadBps", "upload_bps", "uploadSpeed", "upSpeed", "txSpeed"),
    "downloadBps": ("rx_rate_bps", "rx_rate", "download_rate_bps", "down", "downloadBps", "download_bps", "downloadSpeed", "downSpeed", "rxSpeed"),
    "totalUploadBytes": ("tx_bytes", "total_up", "totalUploadBytes", "totalUpload", "total_upload_bytes", "txBytes"),
    "totalDownloadBytes": ("rx_bytes", "total_down", "totalDownloadBytes", "totalDownload", "total_download_bytes", "rxBytes"),
    "dailyUploadBytes": ("daily_up", "dailyUploadBytes", "daily_upload_bytes"),
    "dailyDownloadBytes": ("daily_down", "dailyDownloadBytes", "daily_download_bytes"),
    "ipv4Connections": ("ipv4_connection_count", "ipv4Connections"),
    "ipv6Connections": ("ipv6_connection_count", "ipv6Connections"),
    "ipv4HalfConnections": ("ipv4_half_connection_count", "ipv4HalfConnections"),
    "ipv6HalfConnections": ("ipv6_half_connection_count", "ipv6HalfConnections"),
    "ipv4LocalConnections": ("ipv4_local_connection_count", "ipv4LocalConnections"),
    "ipv6LocalConnections": ("ipv6_local_connection_count", "ipv6LocalConnections"),
    "flowCount": ("flow_cnt", "flowCount"),
    "cps": ("cps",),
}


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _direct(row: Mapping[str, Any], keys: Tuple[str, ...]) -> Any:
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return None


def _unit(row: Mapping[str, Any]) -> str:
    return str(row.get("unit") or row.get("rateUnit") or row.get("rate_unit") or "").strip().lower()


_TRAFFIC_FIELDS = (
    "uploadBps",
    "downloadBps",
    "totalUploadBytes",
    "totalDownloadBytes",
    "dailyUploadBytes",
    "dailyDownloadBytes",
)
_WAN_ID_KEYS = ("wanId", "wan_id", "intf", "interface", "ifname", "name", "id")


def _wan_id(value: Any, fallback: Any = "") -> str:
    for candidate in (value, fallback):
        if isinstance(candidate, Mapping):
            for key in _WAN_ID_KEYS:
                text = str(candidate.get(key) or "").strip().lower()
                if text:
                    return text
        else:
            text = str(candidate or "").strip().lower()
            if text:
                return text
    return ""


def _observed_epoch(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    if number >= 100_000_000_000:
        number /= 1000.0
    return int(number)


def _row_observed_at(row: Mapping[str, Any], fallback: Any = None) -> int | None:
    for key in ("trafficObservedAt", "observedAt", "observed_at", "timestamp", "sampleEpochMs"):
        observed = _observed_epoch(row.get(key))
        if observed is not None:
            return observed
    return _observed_epoch(fallback)


def _source_observed_at(value: Any) -> int | None:
    if not isinstance(value, Mapping):
        return None
    for key in ("trafficObservedAt", "observedAt", "observed_at", "timestamp", "time", "sampleEpochMs", "updatedAt"):
        observed = _observed_epoch(value.get(key))
        if observed is not None:
            return observed
    return None


def _bits_per_second(value: Any, row: Mapping[str, Any]) -> float | None:
    number = _number(value)
    if number is None:
        return None
    unit = _unit(row)
    if unit in {"b/s", "byte/s", "bytes/s"}:
        number *= 8.0
    elif unit in {"kbit/s", "kbps"}:
        number *= 1000.0
    elif unit in {"mbit/s", "mbps"}:
        number *= 1_000_000.0
    return max(0.0, number)


def _canonical_row(
    row: Mapping[str, Any],
    *,
    fallback_id: str = "",
    source: str = "",
    observed_at: Any = None,
) -> Dict[str, Any] | None:
    wan_id = _wan_id(row, fallback_id)
    if not wan_id:
        return None
    result: Dict[str, Any] = {"wanId": wan_id}
    for target in _TRAFFIC_FIELDS:
        raw_value = _direct(row, _FIELDS[target])
        if raw_value is None:
            continue
        number = _bits_per_second(raw_value, row) if target in {"uploadBps", "downloadBps"} else _number(raw_value)
        if number is None:
            continue
        result[target] = max(0, int(number))
    result["trafficSource"] = str(row.get("trafficSource") or source or "").strip()
    observed = _row_observed_at(row, observed_at)
    if observed is not None:
        result["trafficObservedAt"] = observed
    result["trafficComplete"] = all(key in result for key in _TRAFFIC_FIELDS)
    return result


def canonical_wan_rows(value: Any, *, source: str = "", observed_at: Any = None) -> List[Dict[str, Any]]:
    """Return only explicitly identified per-WAN telemetry rows.

    Aggregate mappings (including ``{"wans": {"up": ...}}``) deliberately
    produce no rows. List positions are never used as WAN identities.
    """
    source_observed = _source_observed_at(value)
    if observed_at is None:
        observed_at = source_observed
    if isinstance(value, Mapping) and isinstance(value.get("wans"), (Mapping, list)):
        value = value.get("wans")
    if isinstance(value, list):
        rows = [_canonical_row(item, source=source, observed_at=observed_at) for item in value if isinstance(item, Mapping)]
    elif isinstance(value, Mapping):
        if any(key in value for keys in _FIELDS.values() for key in keys):
            return []
        # Some firmware puts the default WAN metrics directly under wan_stat.wan.
        if set(value) == {"wan"} and isinstance(value.get("wan"), Mapping) and any(
            key in value["wan"] for keys in _FIELDS.values() for key in keys
        ):
            rows = [_canonical_row(value["wan"], fallback_id="wan", source=source, observed_at=observed_at)]
        else:
            rows = []
            for key, item in value.items():
                if not isinstance(item, Mapping):
                    continue
                row = _canonical_row(item, fallback_id=str(key), source=source, observed_at=observed_at)
                if row is not None:
                    rows.append(row)
    else:
        rows = []
    result: List[Dict[str, Any]] = []
    indexes: Dict[str, int] = {}
    for row in rows:
        if row is None:
            continue
        wan_id = str(row["wanId"])
        if wan_id in indexes:
            result[indexes[wan_id]] = row
        else:
            indexes[wan_id] = len(result)
            result.append(row)
    return result


def normalize_wan_telemetry(value: Any) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    shape = "empty"
    if isinstance(value, list):
        shape = "list"
        for index, item in enumerate(value):
            if isinstance(item, Mapping):
                row = dict(item)
                row.setdefault("wanId", str(row.get("intf") or row.get("interface") or index))
                rows.append(row)
    elif isinstance(value, Mapping):
        if any(any(key in value for key in keys) for keys in _FIELDS.values()):
            shape = "aggregate"
            rows = [dict(value)]
        else:
            shape = "map"
            for wan_id, item in value.items():
                if not isinstance(item, Mapping):
                    continue
                row = dict(item)
                row.setdefault("wanId", str(wan_id))
                rows.append(row)

    if not rows:
        return {"aggregate": {}, "wans": [], "shape": shape, "complete": False, "unitMismatch": False}

    units = {_unit(row) for row in rows if _unit(row)}
    unit_mismatch = len(units) > 1
    aggregate: Dict[str, Any] = {}
    complete = not unit_mismatch and all(
        any(key in row for keys in _FIELDS.values() for key in keys)
        for row in rows
    )
    for target, keys in _FIELDS.items():
        numbers: List[float] = []
        for row in rows:
            number = _number(_direct(row, keys))
            if number is not None:
                numbers.append(number)
        if not numbers:
            continue
        if len(numbers) != len(rows):
            complete = False
            continue
        if target in {"uploadBps", "downloadBps"} and unit_mismatch:
            continue
        total = sum(numbers)
        aggregate[target] = int(total) if total.is_integer() else total

    return {
        "aggregate": aggregate,
        "wans": rows,
        "shape": shape,
        "complete": complete,
        "unitMismatch": unit_mismatch,
    }
