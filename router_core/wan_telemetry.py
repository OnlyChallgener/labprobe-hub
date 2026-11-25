from __future__ import annotations

from typing import Any, Dict, List, Mapping, Tuple


_FIELDS: Dict[str, Tuple[str, ...]] = {
    "uploadBps": ("tx_rate_bps", "tx_rate", "upload_rate_bps", "up", "uploadBps", "upload_bps", "uploadSpeed", "upSpeed", "txSpeed"),
    "downloadBps": ("rx_rate_bps", "rx_rate", "download_rate_bps", "down", "downloadBps", "download_bps", "downloadSpeed", "downSpeed", "rxSpeed"),
    "totalUploadBytes": ("total_up", "totalUploadBytes", "total_upload_bytes"),
    "totalDownloadBytes": ("total_down", "totalDownloadBytes", "total_download_bytes"),
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
