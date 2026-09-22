"""Router-native network speed test transport for LabProbe Hub.

The measurement itself lives entirely in the router firmware: the EWeb page runs
``speedtest.elf`` and the ``speedtest`` module of ``dev_sta`` only starts the
process and forwards whatever the binary wrote to
``/tmp/speedtest/cur_intf_rst_symlink.json`` and ``/etc/speedtest/history_rst.json``.

The Hub therefore implements **no** measurement logic.  It only transports the
six read/write operations over the already-authenticated Router Core RPC
channel (``ReyeeEWebDriver.rpc`` -> ``ReyeeRpcClient.rpc`` -> EWeb
``/cgi-bin/luci/api/cmd``), normalizes the firmware's string-typed payloads into
a stable App contract, and keeps the App unaware of eWeb wire details.

Wire facts verified against a live EW7200 (BE72, child_guard_version 2.1):

    devSta.get  module=speedtest  data={"type": "get_proc_stat"}
        -> {"get_proc_stat": "0" | "1"}

    devSta.get  module=speedtest  data={"type": "get_cur_intf_rst"}
        -> {"intf": ["wan"], "stat": "start|running|end", "error_code": "0",
            "tmp_rst": {"wan": {"latency": "1.68", "jitter": "0.23",
                                "loss": "0.00",
                                "downspeed": ["1559.21", ...],   # array
                                "upspeed": ["116.49", ...]}}}     # array

    devSta.get  module=speedtest  data={"type": "get_his_rst"}
        -> {"his_rst": [{"timestamp": "1789637285", "intf": ["wan"],
                         "tmp_rst": {"wan": {"downspeed": "587.07",   # scalar!
                                             "upspeed": "49.23", ...}}}]}

    devSta.get  module=speedtest  data={"type": "get_servers"}
        -> {"error_code": "0", "msg": "success",
            "servers": [{"id": "308000101", "name": "衡阳移动"}, ...]}

    devSta.get  module=port_status
        -> {"count": "9", "List": [{"portId": "5", "name": "WAN",
                                    "panel_name": "WAN", "status": "on",
                                    "speed": "2500", "duplex": "full",
                                    "ipaddr": "192.168.1.2", ...}]}

Note the deliberate trap: ``downspeed``/``upspeed`` are **arrays** in the live
interface but **string scalars** in the history interface.  Both are normalized
here so the App never has to know.

Nothing in this module writes router configuration.  ``start_test`` is the only
state-changing call and it is the official, user-initiated speed test.
"""

from __future__ import annotations

import math
import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from flask import Blueprint, jsonify, request

MODULE = "speedtest"
DEFAULT_NODE = "0"
MAX_SAMPLES = 600
MAX_HISTORY = 20
READ_TIMEOUT: Tuple[int, int] = (4, 16)
START_TIMEOUT: Tuple[int, int] = (5, 25)

_INTF_RE = re.compile(r"^wan[0-9]{0,2}$")
_NODE_RE = re.compile(r"^[A-Za-z0-9_-]{1,24}$")
_MAX_INTFS = 4


class SpeedTestError(RuntimeError):
    """Transport/validation failure surfaced to the App as a JSON error."""

    def __init__(self, message: str, code: str = "speedtest_failed", status: int = 502):
        super().__init__(message)
        self.code = code
        self.status = status


# --------------------------------------------------------------------------- #
# primitives
# --------------------------------------------------------------------------- #

def _text(value: Any, limit: int = 160) -> str:
    if value is None:
        return ""
    return str(value).strip()[:limit]


def _as_float(value: Any) -> Optional[float]:
    """Firmware numbers are strings; reject anything non-finite."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return round(number, 2)


def _as_epoch(value: Any) -> int:
    try:
        epoch = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return 0
    # Guard against obviously bogus timestamps so the App can render "--".
    return epoch if 1_000_000_000 <= epoch <= 4_000_000_000 else 0


def _series(value: Any) -> List[float]:
    if not isinstance(value, list):
        return []
    samples: List[float] = []
    for item in value[:MAX_SAMPLES]:
        number = _as_float(item)
        if number is not None:
            samples.append(number)
    return samples


def _payload(result: Any) -> Dict[str, Any]:
    """``ReyeeRpcClient.rpc`` already unwraps ``root['data']``; stay defensive."""
    if isinstance(result, dict):
        data = result.get("data")
        if isinstance(data, dict) and "error_code" not in result:
            return data
        return result
    if isinstance(result, list):
        return {"List": result}
    return {}


# --------------------------------------------------------------------------- #
# normalizers
# --------------------------------------------------------------------------- #

def normalize_ports(payload: Dict[str, Any]) -> Dict[str, Any]:
    rows = payload.get("List")
    if not isinstance(rows, list):
        rows = payload.get("list") if isinstance(payload.get("list"), list) else []
    ports: List[Dict[str, Any]] = []
    testable: List[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = _text(row.get("name"), 24)
        lowered = name.lower()
        status = _text(row.get("status"), 8).lower()
        up = status in {"on", "up", "1", "true"}
        speed = _as_float(row.get("speed")) or 0.0
        is_wan = _INTF_RE.fullmatch(lowered) is not None
        entry = {
            "portId": _text(row.get("portId"), 8),
            "name": name,
            "panelName": _text(row.get("panel_name"), 32),
            "status": status,
            "up": up,
            "speedMbps": int(speed),
            "duplex": _text(row.get("duplex"), 8),
            "ipAddress": _text(row.get("ipaddr"), 64),
            "wan": is_wan,
            "testable": bool(is_wan and up),
        }
        ports.append(entry)
        if entry["testable"] and lowered not in testable:
            testable.append(lowered)
    return {"ports": ports, "total": len(ports), "testable": testable}


def normalize_servers(payload: Dict[str, Any]) -> Dict[str, Any]:
    rows = payload.get("servers")
    if not isinstance(rows, list):
        rows = []
    servers: List[Dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        node_id = _text(row.get("id"), 24)
        if not node_id:
            continue
        servers.append({"id": node_id, "name": _text(row.get("name"), 64) or node_id})
    return {
        "servers": servers,
        "total": len(servers),
        "errorCode": _text(payload.get("error_code"), 8) or "0",
    }


def _normalize_interface(key: str, raw: Any, *, scalars: bool) -> Dict[str, Any]:
    block = raw if isinstance(raw, dict) else {}
    down_raw, up_raw = block.get("downspeed"), block.get("upspeed")
    if scalars:
        down_series: List[float] = []
        up_series: List[float] = []
        current_down = _as_float(down_raw)
        current_up = _as_float(up_raw)
    else:
        down_series = _series(down_raw)
        up_series = _series(up_raw)
        current_down = down_series[-1] if down_series else None
        current_up = up_series[-1] if up_series else None
    return {
        "intf": _text(key, 16),
        "latency": _as_float(block.get("latency")),
        "jitter": _as_float(block.get("jitter")),
        "loss": _as_float(block.get("loss")),
        "downspeed": down_series,
        "upspeed": up_series,
        "currentDown": current_down,
        "currentUp": current_up,
        "peakDown": max(down_series) if down_series else None,
        "peakUp": max(up_series) if up_series else None,
        "result": _text(block.get("result"), 32),
    }


def normalize_progress(payload: Dict[str, Any]) -> Dict[str, Any]:
    stat = _text(payload.get("stat"), 16).lower()
    if stat not in {"start", "running", "end"}:
        stat = "idle"
    raw_intfs = payload.get("intf")
    intf_keys = [str(item) for item in raw_intfs] if isinstance(raw_intfs, list) else []
    tmp = payload.get("tmp_rst") if isinstance(payload.get("tmp_rst"), dict) else {}
    if not intf_keys:
        intf_keys = [key for key in tmp.keys()]
    interfaces = [_normalize_interface(key, tmp.get(key), scalars=False) for key in intf_keys]
    primary = interfaces[0] if interfaces else None
    return {
        "stat": stat,
        "finished": stat == "end",
        "running": stat in {"start", "running"},
        "errorCode": _text(payload.get("error_code"), 8) or "0",
        "interfaces": interfaces,
        "primary": primary,
        "updatedAt": int(time.time()),
    }


def normalize_history(payload: Dict[str, Any]) -> Dict[str, Any]:
    rows = payload.get("his_rst")
    if not isinstance(rows, list):
        rows = []
    records: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw_intfs = row.get("intf")
        intf_keys = [str(item) for item in raw_intfs] if isinstance(raw_intfs, list) else []
        tmp = row.get("tmp_rst") if isinstance(row.get("tmp_rst"), dict) else {}
        if not intf_keys:
            intf_keys = [key for key in tmp.keys()]
        interfaces = [_normalize_interface(key, tmp.get(key), scalars=True) for key in intf_keys]
        primary = interfaces[0] if interfaces else None
        records.append({
            "timestamp": _text(row.get("timestamp"), 24),
            "epoch": _as_epoch(row.get("timestamp")),
            "interfaces": interfaces,
            "primary": primary,
        })
    records.sort(key=lambda item: item.get("epoch") or 0, reverse=True)
    return {"records": records[:MAX_HISTORY], "total": len(records)}


def normalize_state(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw = payload.get("get_proc_stat")
    flag = _text(raw, 4)
    return {"procState": flag, "running": flag == "1"}


# --------------------------------------------------------------------------- #
# request validation
# --------------------------------------------------------------------------- #

def clean_interfaces(value: Any) -> List[str]:
    if value is None:
        return ["wan"]
    raw = value if isinstance(value, list) else [value]
    cleaned: List[str] = []
    for item in raw:
        name = _text(item, 16).lower()
        if not name:
            continue
        if not _INTF_RE.fullmatch(name):
            raise SpeedTestError(f"不支持的测速端口：{name}", "invalid_request", 400)
        if name not in cleaned:
            cleaned.append(name)
    if not cleaned:
        raise SpeedTestError("至少需要选择一个测速端口", "invalid_request", 400)
    if len(cleaned) > _MAX_INTFS:
        raise SpeedTestError("测速端口数量超出上限", "invalid_request", 400)
    return cleaned


def clean_nodes(value: Any, interfaces: Sequence[str]) -> Dict[str, List[str]]:
    """The firmware wants ``{"wan": ["308000101"]}``; ``"0"`` means auto."""
    if not isinstance(value, dict):
        return {}
    allowed = set(interfaces)
    nodes: Dict[str, List[str]] = {}
    for key, raw in value.items():
        name = _text(key, 16).lower()
        if name not in allowed:
            continue
        raw_list = raw if isinstance(raw, list) else [raw]
        picked: List[str] = []
        for item in raw_list:
            node_id = _text(item, 24) or DEFAULT_NODE
            if not _NODE_RE.fullmatch(node_id):
                raise SpeedTestError(f"无效的测速节点：{node_id}", "invalid_request", 400)
            if node_id not in picked:
                picked.append(node_id)
        if picked:
            nodes[name] = picked
    return nodes


# --------------------------------------------------------------------------- #
# blueprint
# --------------------------------------------------------------------------- #

def _resolve_driver(hub: Any) -> Any:
    driver = getattr(hub, "ROUTER_DRIVER", None)
    if driver is None:
        raise SpeedTestError("Hub 尚未完成路由器连接初始化", "router_unavailable", 503)
    return driver


def _call(driver: Any, data: Optional[Dict[str, Any]], timeout: Tuple[int, int],
          module: str = MODULE) -> Dict[str, Any]:
    try:
        result = driver.rpc("devSta.get", module, data=data, timeout=timeout)
    except SpeedTestError:
        raise
    except Exception as error:  # noqa: BLE001 - mapped onto the public contract
        code = _text(getattr(error, "code", ""), 64) or "speedtest_failed"
        status = getattr(error, "http_status", None) or getattr(error, "status_code", None) or 502
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 502
        if not 400 <= status <= 599:
            status = 502
        message = _text(str(error), 300) or "测速请求失败，请稍后重试"
        raise SpeedTestError(message, code, status) from error
    return _payload(result)


def install_speedtest_service(hub: Any, logger: Optional[Callable[..., Any]] = None) -> Blueprint:
    """Registers ``/api/router/speedtest`` on the running Hub app."""
    log = logger or getattr(hub, "LOGGER", None)
    bp = Blueprint("router_speedtest", __name__, url_prefix="/api/router/speedtest")

    @bp.before_request
    def _authorize():  # pragma: no cover - exercised through the routes
        if not hub.check_app_token():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return None

    @bp.errorhandler(SpeedTestError)
    def _handle_speedtest_error(error: SpeedTestError):
        return jsonify({"ok": False, "error": error.code, "message": str(error)}), error.status

    @bp.errorhandler(Exception)
    def _handle_unexpected(error: Exception):  # pragma: no cover - safety net
        if log is not None and hasattr(log, "warning"):
            log.warning("speedtest api error path=%s type=%s message=%s",
                        request.path, type(error).__name__, error)
        return jsonify({"ok": False, "error": "INTERNAL_ERROR",
                        "message": "测速操作失败，请稍后重试"}), 500

    @bp.get("/ports")
    def get_ports():
        driver = _resolve_driver(hub)
        # port_status is its own dev_sta module, not part of `speedtest`.
        payload = _call(driver, None, READ_TIMEOUT, module="port_status")
        data = normalize_ports(payload)
        return jsonify({"ok": True, "data": data, "updatedAt": int(time.time())})

    @bp.get("/servers")
    def get_servers():
        driver = _resolve_driver(hub)
        payload = _call(driver, {"type": "get_servers"}, READ_TIMEOUT)
        data = normalize_servers(payload)
        return jsonify({"ok": True, "data": data})

    @bp.get("/state")
    def get_state():
        driver = _resolve_driver(hub)
        payload = _call(driver, {"type": "get_proc_stat"}, READ_TIMEOUT)
        data = normalize_state(payload)
        return jsonify({"ok": True, "data": data})

    @bp.get("/progress")
    def get_progress():
        driver = _resolve_driver(hub)
        payload = _call(driver, {"type": "get_cur_intf_rst"}, READ_TIMEOUT)
        data = normalize_progress(payload)
        return jsonify({"ok": True, "data": data})

    @bp.get("/history")
    def get_history():
        driver = _resolve_driver(hub)
        payload = _call(driver, {"type": "get_his_rst"}, READ_TIMEOUT)
        data = normalize_history(payload)
        return jsonify({"ok": True, "data": data})

    @bp.post("/start")
    def post_start():
        body = request.get_json(silent=True) or {}
        interfaces = clean_interfaces(body.get("intf") if body.get("intf") is not None
                                      else body.get("intfs"))
        nodes = clean_nodes(body.get("nodes"), interfaces)
        if not nodes:
            nodes = {name: [DEFAULT_NODE] for name in interfaces}
        data: Dict[str, Any] = {"type": "start_test", "intf": interfaces, "set_nodes": nodes}
        driver = _resolve_driver(hub)
        # 已经在测速时再发一次 start_test，固件回的是 error_code != 0 —— 那不是故障，
        # 是重复点击（界面一次按下会连着发两个 POST，实测 09:14:15 同一秒 202 + 409）。
        # 先把路由器自己的进程状态问一遍，正在跑就直接报「已在进行中」，别让它变成一条
        # 红色「未能启动测速」。
        if normalize_state(_call(driver, {"type": "get_proc_stat"}, READ_TIMEOUT))["running"]:
            return jsonify({
                "ok": True,
                "data": {
                    "intf": interfaces,
                    "nodes": nodes,
                    "alreadyRunning": True,
                    "startedAt": int(time.time()),
                },
            }), 202
        payload = _call(driver, data, START_TIMEOUT)
        error_code = _text(payload.get("error_code"), 8) or "0"
        if error_code not in {"0", "-0"}:
            raise SpeedTestError(
                "路由器未能启动测速，请确认宽带连接后重试",
                "router_rejected",
                409,
            )
        return jsonify({
            "ok": True,
            "data": {
                "intf": interfaces,
                "nodes": nodes,
                "errorCode": error_code,
                "startedAt": int(time.time()),
            },
        }), 202

    hub.app.register_blueprint(bp)
    if log is not None and hasattr(log, "info"):
        log.info("speedtest service registered at %s", bp.url_prefix)
    return bp
