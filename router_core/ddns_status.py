import json
from typing import Any, Dict, List


_ID_KEYS = ("id", "serviceId", "service_id", "service")
_LIST_KEYS = ("list", "services", "records", "entries", "data")
_RECORD_KEYS = ("state", "status", "content", "detected_ip", "last_success")


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _epoch(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _status_rows(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, str):
        text = raw.strip()
        if not text.startswith(("{", "[")):
            return []
        try:
            raw = json.loads(text)
        except (TypeError, ValueError):
            return []
    if isinstance(raw, list):
        return [dict(row) for row in raw if isinstance(row, dict)]
    if not isinstance(raw, dict):
        return []
    for key in _LIST_KEYS:
        value = raw.get(key)
        if isinstance(value, list):
            return [dict(row) for row in value if isinstance(row, dict)]
        if isinstance(value, dict):
            if any(field in value for field in _RECORD_KEYS):
                return [dict(value)]
            mapped = []
            for record_id, nested in value.items():
                if not isinstance(nested, dict):
                    continue
                row = dict(nested)
                if not any(field in row for field in _ID_KEYS):
                    row["id"] = str(record_id)
                mapped.append(row)
            if mapped:
                return mapped
            nested = _status_rows(value)
            if nested:
                return nested
    if any(key in raw for key in _ID_KEYS) or any(key in raw for key in _RECORD_KEYS):
        return [dict(raw)]
    mapped = []
    for record_id, nested in raw.items():
        if not isinstance(nested, dict) or not any(field in nested for field in _RECORD_KEYS):
            continue
        row = dict(nested)
        if not any(field in row for field in _ID_KEYS):
            row["id"] = str(record_id)
        mapped.append(row)
    return mapped


def merge_ddns_status(rows: List[Dict[str, Any]], raw_status: Any) -> List[Dict[str, Any]]:
    status_by_id: Dict[str, Dict[str, Any]] = {}
    ambiguous_ids = set()
    for row in _status_rows(raw_status):
        record_id = next((_text(row.get(key)) for key in _ID_KEYS if _text(row.get(key))), "")
        if not record_id or record_id in ambiguous_ids:
            continue
        if record_id in status_by_id:
            status_by_id.pop(record_id, None)
            ambiguous_ids.add(record_id)
            continue
        status_by_id[record_id] = row

    merged: List[Dict[str, Any]] = []
    for source in rows:
        item = dict(source)
        record_id = next((_text(item.get(key)) for key in _ID_KEYS if _text(item.get(key))), "")
        status = status_by_id.get(record_id)
        if status:
            state = _text(status.get("state") or status.get("status"))
            if state:
                item["status"] = state
            for key in ("content", "detected_ip", "last_success"):
                if key in status:
                    item[key] = status[key]

            record_type = _text(item.get("record_type") or status.get("record_type")).upper()
            content = _text(status.get("content"))
            detected_ip = _text(status.get("detected_ip"))
            current_ip = _text(item.get("ip"))
            if record_type == "TXT":
                resolved_ip = content or current_ip
            else:
                resolved_ip = detected_ip or content or current_ip
            if resolved_ip:
                item["ip"] = resolved_ip

            last_success = _epoch(status.get("last_success"))
            if last_success > 0:
                item["lastSuccessAt"] = last_success
                item["lastUpdatedAt"] = last_success
        merged.append(item)
    return merged
