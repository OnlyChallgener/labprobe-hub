"""Authenticated Flask blueprint for the first Hub AI surface."""

from __future__ import annotations

import json
import queue
import re
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List
from urllib.parse import urlparse

from flask import Blueprint, Response, jsonify, request, stream_with_context

from .provider import OpenAICompatibleProvider, ProviderError, usage_from_chunk, \
    accumulate_tool_call_fragment, tool_calls_from_accumulated
from .security import MasterKeyUnavailable, decrypt_secret_with_migration, encrypt_secret
from .storage import AIStore, usage_known
from .catalog import catalog, provider_tools, tool_id_from_function, tool_spec
from .domains import register_builtin
from .extend import drain_pending
from .notifications import AssistantNotificationService
from .tools import ToolError, ToolExecutor

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-flash"
TENCENT_HUNYUAN_BASE_URL = "https://tokenhub.tencentmaas.com/v1"
MAX_MESSAGES = 80
MAX_MESSAGE_CHARS = 32_000
MAX_REQUEST_CHARS = 80_000
MAX_REPLAY_CHARS = 24_000
TOOL_SYSTEM_PROMPT = (
    "你是极客网探 Hub 助手，可以查看和控制整个网络：设备、事件、Agent/Relay、STUN 穿透、"
    "WireGuard、路由器端口映射、IPv6、每日记录、防火墙（转发/入站/出站规则的查询、启停、"
    "新建、修改、删除）、TCP 峰值连接数测试、路由器 Beta 固件（版本查询与检测更新），以及让 APP 跳转页面或刷新数据。"
    "【排版格式铁律（严禁输出表格）】"
    "1. 严禁使用 Markdown 表格语法（禁止输出带“|”的表格），移动端竖屏宽度有限会导致严重折行排版混乱；"
    "2. 列表与数据展示一律使用卡片式分块结构：采用清晰小标题与 Emoji 分组（如【在线设备】、【当前设置】、【诊断结论】）；"
    "3. 多项数据一律采用圆点列表“• ”或键值对（例如“• 隐私模式：**已关闭**”）；"
    "4. 关键的名词、状态、IP 地址、端口使用“**加粗**”高亮（例如“**192.168.5.38**”），正文字号保持紧凑适中，不要使用一二级大标题（# 或 ##），整体保持精致小巧；"
    "5. 严禁输出原始未解析的 JSON 字符串。"
    "涉及查询时必须调用工具，不得猜测。只读工具可以直接调用；写入操作（新增/删除/启停端口映射、"
    "穿透规则、防火墙规则或 WireGuard 网关，升级 Agent）只能生成确认请求，在对话中出现对应的〔操作记录〕之前"
    "绝不能声称操作已经完成。"
    "用户问「路由器固件 / Beta 固件」时调用 router.firmware.status 或 router.firmware.check，"
    "不要把 Agent 版本当固件版本回答；固件检测结果用 content 字段的中文内容组织回复，不要输出 JSON。"
    "用户说‘今天/昨天/每日记录’时调用 daily.summary；相对日期不要按模型或设备本地时钟猜测，"
    "省略 date 让工具按 Hub 的北京时间解析，并在回复中使用工具返回的 date。"
    "确认后的执行结果会以〔操作记录〕消息出现在对话中；对话里没有〔操作记录〕的历史确认请求"
    "一律视为已过期、从未执行。用户提起这类旧请求时，先用 assistant.confirmations.list 或对应"
    "状态工具（agent.cleanup.status、stun.rules.list、router.portmap.list 等）核实实际状态再如实"
    "告知，禁止凭对话记忆声称“仍在等待确认”。"
    "用户说‘网络自检’时调用 network.self_check；说‘路由网络自检/路由器自检’时调用 router.diagnostic；"
    "说‘NAT检测’时调用 router.nat.diagnostic。检测和自检绝不能调用 app.navigate，只有明确要求打开/进入/跳转页面时才允许导航。"
    "用户请求进行 TCP 峰值连接数测试时（如‘测试TCP峰值’、‘测一下峰值连接数’等），一律调用 app.navigate 导航至 tcp_peak，"
    "引导用户进入 APP 的测试页面配置与实时观测走势，不要直接下发后台测试指令；仅在用户查询测试进度/状态时调用 tcp.peak.status。"
    "回答使用简洁生动的中文。"
)


def merge_usage(total: Dict[str, int], usage: Dict[str, int]) -> Dict[str, int]:
    for key in (
        "prompt_tokens", "completion_tokens", "total_tokens",
        "cache_hit_tokens", "cache_miss_tokens", "cache_reported_input_tokens",
    ):
        if key in usage:
            total[key] = int(total.get(key) or 0) + int(usage.get(key) or 0)
    return total


def update_usage_snapshot(current: Dict[str, int], usage: Dict[str, int]) -> Dict[str, int]:
    """Keep the latest cumulative usage snapshot for one provider request.

    OpenAI-compatible streaming usage frames are cumulative snapshots, not
    deltas. Summing repeated frames can multiply a single task's tokens. Tool
    rounds are still added together later with ``merge_usage``.
    """
    for key in (
        "prompt_tokens", "completion_tokens", "total_tokens",
        "cache_hit_tokens", "cache_miss_tokens", "cache_reported_input_tokens",
    ):
        if key in usage:
            current[key] = int(usage[key])
    return current


def diagnostic_tool_intent(text: str) -> str | None:
    normalized = "".join(str(text or "").lower().split())
    if any(word in normalized for word in ("打开", "进入", "跳转", "页面")):
        if any(word in normalized for word in ("nat检测", "nat测试", "nat诊断")):
            return "navigate.tool_nat"
        return None
    if "路由" in normalized and ("自检" in normalized or ("网络" in normalized and "检测" in normalized)):
        return "router.diagnostic"
    if "自检" in normalized or ("网络" in normalized and "检测" in normalized):
        return "network.self_check"
    if "nat" in normalized:
        if "路由" in normalized or "结果" in normalized or "状态" in normalized or "类型" in normalized:
            return "router.nat.diagnostic"
        return "navigate.tool_nat"
    return None


def fast_path_tool_intent(text: str) -> str | None:
    normalized = "".join(str(text or "").lower().split())
    if "tcp" in normalized or "峰值" in normalized:
        if any(w in normalized for w in ("测试", "测", "压测", "跑一下", "开始", "启动", "发起", "页面", "界面", "打开", "进入")):
            return "navigate.tool_tcp_peak"
        if any(w in normalized for w in ("状态", "进度", "结果", "跑完", "跑得怎么样")):
            return "tcp.peak.status"
    diag = diagnostic_tool_intent(text)
    if diag:
        return diag
    if any(word in normalized for word in ("打开", "进入", "跳转", "页面", "新建", "添加", "删除", "修改", "重启", "升级")):
        return None
    if ("agent" in normalized or "relay" in normalized) and any(
        w in normalized for w in ("在线", "状态", "上报", "连接", "心跳", "存活")
    ):
        return "agent.status"
    if "设置" in normalized and any(w in normalized for w in ("app", "客户端", "当前")):
        return "app.settings.get"
    if "固件" in normalized and any(w in normalized for w in ("版本", "状态", "当前")):
        return "router.firmware.status"
    return None


def diagnostic_result_query(text: str) -> bool:
    """True when the user asks for an existing result instead of a fresh run."""
    normalized = "".join(str(text or "").lower().split())
    return any(word in normalized for word in ("结果", "状态", "进度", "怎么样", "好了吗"))


_NAT_TYPE_ZH = {
    "open internet": "开放互联网", "open-internet": "开放互联网",
    "full cone": "完全锥形 NAT", "full-cone": "完全锥形 NAT", "full cone nat": "完全锥形 NAT",
    "restricted cone": "受限锥形 NAT", "restricted-cone": "受限锥形 NAT",
    "restricted cone nat": "受限锥形 NAT",
    "port-restricted cone": "端口受限锥形 NAT", "port restricted cone": "端口受限锥形 NAT",
    "port-restricted cone nat": "端口受限锥形 NAT",
    "symmetric": "对称型 NAT", "symmetric nat": "对称型 NAT",
    "symmetric udp firewall": "对称 UDP 防火墙",
    "udp blocked": "UDP 被阻断", "blocked": "UDP 被阻断",
}

_NAT_BEHAVIOR_ZH = {
    "endpoint-independent": "端点无关型",
    "address-dependent": "地址相关型",
    "address-and-port-dependent": "地址与端口相关型",
    "address and port dependent": "地址与端口相关型",
}

_DIAGNOSTIC_TITLE_ZH = (
    ("wan", "外网口连接"), ("external network port", "外网口连接"),
    ("lan", "局域网连接"), ("internal network", "局域网连接"),
    ("dns", "DNS 解析"), ("gateway", "网关连接"),
    ("internet", "互联网连接"), ("network access", "互联网连接"),
    ("speed", "端口协商速率"), ("negotiation", "端口协商速率"),
    ("cable", "网线连接"), ("link", "网线连接"),
)

_DIAGNOSTIC_TEXT_ZH = (
    # 完整句子级翻译（dev_diag 实测字符串）
    ("network port negotiation rate is abnormal", "网络端口协商速率异常"),
    ("may cause slow access to the internet", "可能导致上网变慢"),
    ("problem interface: {port}", "问题接口：{port}"),
    ("problem interface:", "问题接口："),
    ("repair suggestion:", "修复建议："),
    ("please try to change a network cable or check whether the network port rate "
     "of the intermediate device (switch/ap, etc.) is configured to 10m",
     "请尝试更换网线，或检查中间设备（交换机/AP 等）的网口速率是否被设置为 10M"),
    ("please check the external network port network cable", "请检查外网口网线连接是否正常"),
    ("check external network port network cable is ok", "请检查外网口网线连接是否正常"),
    ("external network port network cable is ok", "外网口网线连接正常"),
    ("check wan port network cable", "请检查 WAN 口网线连接"),
    ("network cable is unplugged", "网线未连接"),
    ("network cable is connected", "网线已连接"),
    ("please check the network cable connection", "请检查网线连接是否正常"),
    ("link is normal", "链路正常"),
    ("network is normal", "网络状态正常"),
    ("internet access is normal", "互联网连接正常"),
    ("dns is normal", "DNS 解析正常"),
    ("dns resolution is normal", "DNS 解析正常"),
    ("gateway is reachable", "网关可达"),
    ("gateway connection is normal", "网关连接正常"),
    ("check internet connection status", "请检查互联网连接状态"),
    ("check dns configuration and resolution status", "请检查 DNS 配置和解析状态"),
    ("check gateway configuration and connectivity", "请检查网关配置和连通性"),
    ("check port negotiation speed", "请检查端口协商速率"),
    ("check the network cable connection of the corresponding interface", "请检查对应接口的网线连接"),
    ("check network cable", "请检查对应接口的网线连接"),
    ("negotiation speed", "协商速率"),
    # 单词级兜底
    ("please check", "请检查"),
    ("internet", "互联网"),
    ("network cable", "网线"),
    ("network port", "网口"),
    ("negotiation", "协商"),
    ("interface", "接口"),
    ("gateway", "网关"),
    ("success", "正常"), ("failed", "失败"), ("failure", "失败"),
    ("abnormal", "异常"), ("normal", "正常"), ("error", "异常"),
)

def _diagnostic_apply_port(text: str, port: str) -> str:
    return text.replace("{port}", port or "未知接口")


def _diagnostic_segment_zh(raw: str, port: str) -> List[str]:
    """Translate one diagnostic field into cleaned Chinese sentence segments."""
    text = _diagnostic_apply_port(
        str(raw or "").replace("<br>", "；").replace("\n", "；").replace(";", "；"),
        port,
    )
    if not text.strip():
        return []
    if re.search(r"[A-Za-z]{2,}", text):
        for old, new in _DIAGNOSTIC_TEXT_ZH:
            text = re.sub(re.escape(old), new, text, flags=re.IGNORECASE)
    segments: List[str] = []
    for part in text.split("；"):
        piece = part.strip(" ；,，")
        if not piece:
            continue
        if len(piece) <= 12 and piece.endswith(("：", ":")):
            continue
        segments.append(re.sub(r"([：:])\s+", r"\1", piece))
    return segments


_ZH_STATUS_WORDS = {
    "ok": "运行正常", "connected": "已连接", "syncing": "正在同步",
    "sync": "正在同步", "reconnecting": "连接恢复中", "offline": "离线",
    "online": "在线", "error": "异常", "failed": "异常", "": "",
}


def _zh_status(value: str) -> str:
    text = str(value or "").strip()
    return _ZH_STATUS_WORDS.get(text.lower()) or text


def _first_text(source: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = source.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _nat_zh(value: str, table: Dict[str, str]) -> str:
    text = str(value or "").strip()
    if not text or any(ch > "\x7f" for ch in text):
        return text
    return table.get(text.lower(), text)


def _diagnostic_title_zh(item_type: str, raw: str) -> str:
    text = str(raw or "").strip()
    if any(ch > "\x7f" for ch in text) and text:
        return text
    lower = f"{item_type} {text}".lower()
    for needle, title in _DIAGNOSTIC_TITLE_ZH:
        if needle in lower:
            return title
    return text or "网络状态检查"


def _diagnostic_status_ok(status: str) -> bool:
    return str(status or "").strip().lower() in {"ok", "success", "normal", "pass", "passed", "connected", "up", "good"}


def _diagnostic_rows(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    groups = result.get("list") or result.get("List") or []
    rows: List[Dict[str, Any]] = []

    def row_of(item: Dict[str, Any], group_type: str, port: str) -> Dict[str, Any]:
        return {
            "type": str(group_type or ""),
            "title": _diagnostic_title_zh(str(group_type or ""), str(item.get("item") or "")),
            "ok": _diagnostic_status_ok(str(item.get("status") or "")),
            "status": str(item.get("status") or ""),
            "phenomena": _diagnostic_segment_zh(item.get("result"), port),
            "tips": _diagnostic_segment_zh(item.get("tips"), port),
            "advise": _diagnostic_segment_zh(item.get("advise"), port),
            "port": port,
        }

    for group in groups if isinstance(groups, list) else []:
        if not isinstance(group, dict):
            continue
        group_type = str(group.get("type") or "")
        children = group.get("list") or group.get("List") or []
        if isinstance(children, list) and children:
            for child in children:
                if not isinstance(child, dict):
                    continue
                child_data = child.get("data") if isinstance(child.get("data"), dict) else {}
                rows.append(row_of(child, group_type, str(child_data.get("port") or "")))
        else:
            rows.append(row_of(group, group_type, ""))
    return rows


def _diagnostic_item_lines(row: Dict[str, Any]) -> List[str]:
    head = f"• {row['title']}：{'正常' if row['ok'] else '异常'}"
    if row["port"]:
        head += f"（问题接口 {row['port']}）"
    lines = [head]
    if not row["ok"]:
        notes: List[tuple[str, List[str]]] = [
            ("现象", row["phenomena"]), ("提示", row["tips"]), ("建议", row["advise"]),
        ]
        seen: set[str] = set()
        for label, segments in notes:
            for segment in segments:
                if segment in seen:
                    continue
                seen.add(segment)
                lines.append(f"　{label}：{segment}")
    return lines


def router_diagnostic_content(task: Dict[str, Any]) -> str:
    state = str(task.get("state") or "")
    result = task.get("result") if isinstance(task.get("result"), dict) else {}
    stage = str(task.get("stageText") or "").strip()
    if state in {"idle", "queued", "running"}:
        progress = str(result.get("process") or "").strip()
        detail = progress or (stage or "正在执行")
        return f"路由器网络自检进行中（{detail}）。完成后回复“路由器网络自检结果”，我会汇总每项检查的通过情况。"
    if state == "timed_out":
        return "路由器网络自检超时：" + str(task.get("message") or "路由器长时间未返回完整结果") + "。可稍后重试。"
    if state == "failed":
        return "路由器网络自检失败：" + str(task.get("message") or "未知错误")
    rows = _diagnostic_rows(result)
    if not rows:
        return "路由器网络自检完成，路由器未返回检查项明细（进度 " + str(result.get("process") or "100%") + "）。"
    abnormal = [row for row in rows if not row["ok"]]
    lines = [f"路由器网络自检完成：共 {len(rows)} 项检查，{'全部通过' if not abnormal else f'{len(abnormal)} 项异常'}。"]
    for row in rows:
        lines.extend(_diagnostic_item_lines(row))
    return "\n".join(lines)


def nat_diagnostic_content(task: Dict[str, Any]) -> str:
    state = str(task.get("state") or "")
    result = task.get("result") if isinstance(task.get("result"), dict) else {}
    stage = str(task.get("stageText") or "").strip()
    if state in {"idle", "queued", "running"}:
        return (f"路由器 NAT 检测进行中（{stage or '检测中'}）。"
                "完成后回复“NAT诊断结果”，我会把 NAT 类型和公网映射发给你。")
    if state == "timed_out":
        return ("路由器 NAT 检测超时：路由器长时间未返回最终结果。"
                "可更换 STUN 服务器或 WAN 接口后重试。")
    if state == "failed":
        return "路由器 NAT 检测失败：" + str(task.get("message") or result.get("message") or "未知错误")
    lines = ["路由器 NAT 检测完成："]
    nat_type = _nat_zh(_first_text(result, "nat_type", "natType", "classic_type", "classicType"), _NAT_TYPE_ZH)
    if nat_type:
        lines.append(f"• NAT 类型：{nat_type}")
    mapping = _nat_zh(_first_text(result, "mapping_behavior", "mappingBehavior", "mapping"), _NAT_BEHAVIOR_ZH)
    if mapping:
        lines.append(f"• 映射行为：{mapping}")
    filtering = _nat_zh(_first_text(result, "filtering_behavior", "filteringBehavior", "filtering"), _NAT_BEHAVIOR_ZH)
    if filtering:
        lines.append(f"• 过滤行为：{filtering}")
    external = _first_text(result, "external_address", "externalAddress", "mapped_address", "mappedAddress")
    if external:
        lines.append(f"• 公网映射地址：{external}")
    mode = str(result.get("mode") or result.get("requested_mode") or "").strip()
    if mode:
        mode_zh = "RFC 3489 经典检测" if mode.lower() in {"classic", "rfc3489"} else mode
        lines.append(f"• 检测模式：{mode_zh}")
    if len(lines) == 1:
        lines.append("路由器未返回可读的 NAT 结果字段。")
    return "\n".join(lines)


def network_self_check_content(result: Dict[str, Any]) -> str:
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    router = summary.get("router") if isinstance(summary.get("router"), dict) else {}
    presence = summary.get("agent") if isinstance(summary.get("agent"), dict) else {}
    hub_info = summary.get("hub") if isinstance(summary.get("hub"), dict) else {}

    lines = ["Hub 综合网络状态（非路由器内置自检）："]

    router_lines: List[str] = []
    router_name = _first_text(router, "name")
    status_text = _zh_status(_first_text(router, "routerStatus"))
    head = "• 名称：" + (router_name or "未知")
    if status_text:
        head += f"（{status_text}）"
    router_lines.append(head)
    online = _first_text(router, "onlineDeviceCount")
    if online:
        router_lines.append(f"• 在线设备：{online} 台")
    for label, key in (("出口 IPv4", "exitIpv4"), ("出口 IPv6", "exitIpv6")):
        value = _first_text(router, key) or str(summary.get(key) or "")
        if value:
            router_lines.append(f"• {label}：{value}")
    if router_lines:
        lines.append("")
        lines.append("【路由器】")
        lines.extend(router_lines)

    agent_lines: List[str] = []
    agent_state = _first_text(presence, "agentStateText") or (
        "Agent 在线" if presence.get("agentOnline") else ""
    )
    if agent_state:
        detail_bits = []
        version = _first_text(presence, "agentVersion")
        arch = _first_text(presence, "agentArchitecture")
        if version:
            detail_bits.append(f"版本 {version}" + (f"（{arch}）" if arch else ""))
        last_seen = _first_text(presence, "agentLastSeenAt")
        if last_seen:
            detail_bits.append(f"最后上报 {last_seen}")
        agent_lines.append("• Relay 扩展：" + agent_state + ("（" + "，".join(detail_bits) + "）" if detail_bits else ""))
    hub_line = "• Hub：" + (str(hub_info.get("name") or "") or "labprobe-hub")
    if hub_info.get("version"):
        hub_line += f" v{hub_info['version']}"
    if hub_info.get("updatedAt"):
        hub_line += f"（数据更新 {hub_info['updatedAt']}）"
    agent_lines.append(hub_line)
    advertise = str(hub_info.get("advertiseUrl") or "")
    if advertise:
        agent_lines.append(f"• 访问地址：{advertise}")
    vpn_count = summary.get("vpnAddressCount")
    if isinstance(vpn_count, int):
        agent_lines.append(f"• STUN 公网地址记录：{vpn_count} 条")
    if agent_lines:
        lines.append("")
        lines.append("【Hub 与扩展】")
        lines.extend(agent_lines)

    counters: List[str] = []
    if summary.get("portmapRules") is not None:
        counters.append(f"端口映射 {summary.get('portmapRules')} 条")
    if summary.get("stunRules") is not None:
        counters.append(f"STUN 规则 {summary.get('stunRules')} 条")
    counters.append("WireGuard " + ("已启用" if summary.get("wireguardEnabled") else "未启用"))
    lines.append("")
    lines.append("【功能状态】")
    lines.append("• " + " · ".join(counters))

    lines.append("")
    lines.append('如需路由器内置自检（外网口/局域网/协商速率），请回复“路由器网络自检”。')
    return "\n".join(lines)


def _task_snapshot(hub_runtime: Any, kind: str) -> Dict[str, Any] | None:
    manager = getattr(hub_runtime, "ROUTER_TASK_MANAGER", None)
    snapshot = getattr(manager, "snapshot", None)
    if not callable(snapshot):
        return None
    try:
        value = snapshot(kind)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _wait_router_task(hub_runtime: Any, kind: str, timeout_seconds: float = 40.0) -> Dict[str, Any] | None:
    """Poll a router task to its terminal state within the APP request window."""
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    last = _task_snapshot(hub_runtime, kind)
    while True:
        if isinstance(last, dict) and str(last.get("state") or "") not in {"", "idle", "queued", "running"}:
            return last
        if time.monotonic() >= deadline:
            return last
        time.sleep(1.5)
        last = _task_snapshot(hub_runtime, kind) or last


def tool_display_name(tool_id: str) -> str:
    spec = tool_spec(tool_id)
    return str(spec["name"]) if spec else str(tool_id)


def record_confirmation_note(store, pending: Any, text: str) -> None:
    """Append a tool outcome to the conversation transcript.

    The APP runs incremental chat and never posts its local result bubbles,
    so without this note the model has no record that a confirmed write
    executed and will ask the user to confirm the same operation again.
    """
    conversation_id = pending.get("conversation_id") if isinstance(pending, dict) else None
    if not conversation_id:
        return
    try:
        store.add_message(str(conversation_id), "assistant", "〔操作记录〕" + str(text)[:600])
    except Exception:
        pass


def create_ai_blueprint(*, check_app_token: Callable[[], bool], db_path, logger,
                        hub_runtime: Any = None, enable_notifications: bool = False) -> Blueprint:
    store = AIStore(db_path)
    store.initialize()
    executor = ToolExecutor(hub_runtime) if hub_runtime is not None else None
    if hub_runtime is not None:
        # Capability domains read lifecycle data (confirmations) through the
        # same runtime stash the executor uses.
        setattr(hub_runtime, "ASSISTANT_AI_STORE", store)
    if executor is not None:
        # Feature modules attach tool handlers via the hub runtime during
        # hub_entry install, before the first chat request arrives. Buffered
        # registrations are drained here, then the built-in domains bind.
        setattr(hub_runtime, "ASSISTANT_TOOL_EXECUTOR", executor)
        drain_pending(executor)
        register_builtin(executor)
    notification_service = None
    if hub_runtime is not None and enable_notifications:
        notification_service = AssistantNotificationService(hub_runtime, store, logger)
        notification_service.start()
    bp = Blueprint("hub_ai", __name__, url_prefix="/api/ai")

    def authorized():
        if not check_app_token():
            return jsonify({"error": "未授权"}), 401
        return None

    def sse_response(events) -> Response:
        response = Response(stream_with_context(events), content_type="text/event-stream")
        response.headers["Cache-Control"] = "no-cache, no-transform"
        response.headers["X-Accel-Buffering"] = "no"
        response.headers["Connection"] = "keep-alive"
        return response

    def keepalive_items(items, interval: float = 10.0):
        """Consume a possibly-blocking provider iterator without starving SSE."""
        channel: queue.Queue = queue.Queue(maxsize=8)
        stop = threading.Event()
        sentinel = object()

        def publish(kind: str, value: Any) -> bool:
            while not stop.is_set():
                try:
                    channel.put((kind, value), timeout=0.1)
                    return True
                except queue.Full:
                    continue
            return False

        def pump() -> None:
            try:
                for item in items:
                    if not publish("item", item):
                        return
            except BaseException as exc:
                publish("error", exc)
            finally:
                publish("end", sentinel)

        threading.Thread(target=pump, name="labprobe-ai-provider-stream", daemon=True).start()
        try:
            while True:
                try:
                    kind, value = channel.get(timeout=interval)
                except queue.Empty:
                    yield None
                    continue
                if kind == "item":
                    yield value
                elif kind == "error":
                    raise value
                else:
                    return
        finally:
            stop.set()
            close = getattr(items, "close", None)
            if callable(close):
                try:
                    close()
                except (RuntimeError, ValueError):
                    pass

    def base_url_view(value: Any) -> str:
        """Never reflect legacy URL credentials or query secrets to clients."""
        raw = str(value or "")
        parsed = urlparse(raw)
        if not parsed.hostname:
            return ""
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            port = f":{parsed.port}" if parsed.port is not None else ""
        except ValueError:
            port = ""
        return parsed._replace(netloc=host + port, query="", fragment="").geturl()

    def canonicalize_config_base_url(row: Dict[str, Any]) -> str:
        old_url = str(row.get("base_url") or "")
        safe_url = base_url_view(old_url).rstrip("/")
        parsed = urlparse(safe_url)
        local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if not safe_url or ((parsed.scheme != "https" and not local_http) or not parsed.netloc):
            raise ValueError("stored AI provider base URL is invalid")
        # Tencent's legacy OpenAI-compatible Hunyuan endpoint is being
        # migrated to TokenHub. Existing configurations are moved lazily on
        # first read/use so users do not have to re-enter their API key.
        if parsed.hostname == "api.hunyuan.cloud.tencent.com":
            safe_url = TENCENT_HUNYUAN_BASE_URL
        if safe_url != old_url:
            store.migrate_config_base_url(int(row["id"]), old_url, safe_url)
            row["base_url"] = safe_url
        return safe_url

    def decrypt_config_secret(row: Dict[str, Any]) -> str:
        canonicalize_config_base_url(row)
        ciphertext = row.get("api_key_ciphertext")
        plaintext, replacement = decrypt_secret_with_migration(ciphertext)
        if replacement:
            store.migrate_config_ciphertext(int(row["id"]), str(ciphertext), replacement)
            row["api_key_ciphertext"] = replacement
        return plaintext

    def config_view(row):
        key_status = "not_configured"
        if row and row.get("api_key_ciphertext"):
            try:
                decrypt_config_secret(row)
                key_status = "configured"
            except MasterKeyUnavailable:
                key_status = "unavailable"
            except ValueError:
                key_status = "invalid"
        return {"id": int(row["id"]) if row else None,
                "name": row["name"] if row else "DeepSeek",
                "configured": bool(row and key_status == "configured"),
                "provider": row["provider"] if row else "deepseek",
                "baseUrl": base_url_view(row["base_url"]) if row else DEFAULT_BASE_URL,
                "model": row["model"] if row else DEFAULT_MODEL,
                "enabled": bool(row["enabled"]) if row else False,
                "tokenQuota": row["model_quota_tokens"] if row else None,
                "modelQuotaTokens": row["model_quota_tokens"] if row else None,
                "manualTotalTokens": row.get("manual_total_tokens") if row else None,
                "manualCalibratedAt": row.get("manual_calibrated_at") if row else None,
                "apiKey": "configured" if key_status == "configured" else None,
                "apiKeyStatus": key_status}

    def configs_response():
        rows = store.list_configs()
        primary = rows[0] if rows else None
        return {**config_view(primary), "configs": [config_view(row) for row in rows]}

    def default_base_url(provider: str) -> str:
        normalized = "".join(str(provider or "").lower().replace("-", "_").split())
        if normalized in {"hunyuan", "tencent", "tencent_hunyuan", "腾讯混元", "混元"}:
            return TENCENT_HUNYUAN_BASE_URL
        return DEFAULT_BASE_URL

    def parse_quota(body: Dict[str, Any], current: Any = None):
        supplied = "tokenQuota" in body or "modelQuotaTokens" in body
        if not supplied:
            return current["model_quota_tokens"] if current else None
        raw = body.get("tokenQuota") if "tokenQuota" in body else body.get("modelQuotaTokens")
        if raw is None or raw == "":
            return None
        if isinstance(raw, bool):
            raise ValueError("tokenQuota must be a positive integer or null")
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("tokenQuota must be a positive integer or null") from exc
        if value <= 0:
            raise ValueError("tokenQuota must be a positive integer or null")
        return value

    def save_config_request(*, create: bool):
        body = request.get_json(silent=True) or {}
        config_id = body.get("id")
        current = None
        if not create:
            try:
                current = store.get_config(int(config_id)) if config_id is not None else store.get_config()
            except (TypeError, ValueError):
                return jsonify({"error": "配置 ID 必须是整数"}), 400
            if config_id is not None and current is None:
                return jsonify({"error": "未找到 AI 配置"}), 404
            if current is not None:
                try:
                    canonicalize_config_base_url(current)
                except ValueError as exc:
                    return jsonify({"error": str(exc)}), 409
        provider = str(body.get("provider") or (current["provider"] if current else "deepseek")).strip().lower()
        if not provider or len(provider) > 64:
            return jsonify({"error": "AI 服务商配置无效"}), 400
        model = str(body.get("model") or (current["model"] if current else DEFAULT_MODEL)).strip()
        if not model or len(model) > 200:
            return jsonify({"error": "模型名称无效"}), 400
        name = str(body.get("name") or (current["name"] if current else model)).strip()
        if not name or len(name) > 64:
            return jsonify({"error": "配置名称长度必须为 1–64 个字符"}), 400
        provider_changed = bool(current and provider != str(current["provider"]).lower())
        fallback_url = default_base_url(provider) if provider_changed or not current else current["base_url"]
        base_url = str(body.get("baseUrl") or fallback_url).strip().rstrip("/")
        parsed = urlparse(base_url)
        local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (parsed.scheme != "https" and not local_http) or not parsed.netloc:
            return jsonify({"error": "AI 服务地址无效"}), 400
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            return jsonify({"error": "AI 服务地址不能包含账号凭据、查询参数或片段"}), 400
        api_key = body.get("apiKey")
        if current and (api_key is None or str(api_key).strip() in {"", "configured"}):
            try:
                decrypt_config_secret(current)
            except MasterKeyUnavailable as exc:
                return jsonify({"error": str(exc)}), 503
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 409
            ciphertext = current["api_key_ciphertext"]
        elif isinstance(api_key, str) and api_key.strip():
            try:
                ciphertext = encrypt_secret(api_key.strip())
            except MasterKeyUnavailable as exc:
                return jsonify({"error": str(exc)}), 503
        else:
            return jsonify({"error": "新建配置必须填写 API Key"}), 400
        try:
            quota = parse_quota(body, current)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        enabled = bool(body.get("enabled", bool(current["enabled"]) if current else True))
        if create or current is None:
            saved = store.create_config(name, provider, base_url, model, ciphertext, enabled, quota)
        else:
            saved = store.update_config(
                current["id"], name=name, provider=provider, base_url=base_url, model=model,
                ciphertext=ciphertext, enabled=enabled, model_quota_tokens=quota,
                position=int(current["position"]),
            )
        return jsonify(config_view(saved))

    @bp.get("/config")
    def get_config():
        denial = authorized()
        return denial or jsonify(configs_response())

    @bp.get("/configs")
    def get_configs_alias():
        denial = authorized()
        return denial or jsonify(configs_response())

    @bp.post("/config")
    def post_config():
        denial = authorized()
        return denial or save_config_request(create=True)

    @bp.put("/config")
    def put_config():
        denial = authorized()
        if denial:
            return denial
        return save_config_request(create=False)

    @bp.delete("/config")
    def delete_config():
        denial = authorized()
        if denial:
            return denial
        store.delete_config()
        return "", 204

    @bp.delete("/config/<int:config_id>")
    def delete_config_by_id(config_id: int):
        denial = authorized()
        if denial:
            return denial
        if not store.delete_config(config_id):
            return jsonify({"error": "未找到 AI 配置"}), 404
        return "", 204

    @bp.post("/config/<int:config_id>/promote")
    def promote_config(config_id: int):
        denial = authorized()
        if denial:
            return denial
        row = store.promote_config(config_id)
        if row is None:
            return jsonify({"error": "未找到 AI 配置"}), 404
        return jsonify(config_view(row))

    @bp.post("/config/<int:config_id>/move")
    def move_config(config_id: int):
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        direction = "up" if str(body.get("direction") or "").lower() == "up" else "down"
        if not store.move_config(config_id, direction):
            return jsonify({"error": "未找到 AI 配置"}), 404
        return jsonify({"ok": True})

    @bp.post("/usage/adjust")
    def adjust_usage():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        try:
            config_id = int(body.get("configId"))
            target = int(body.get("totalTokens"))
        except (TypeError, ValueError):
            return jsonify({"error": "配置 ID 与 Token 总数必须是整数"}), 400
        if target < 0:
            return jsonify({"error": "Token 总数不能小于 0"}), 400
        quota_supplied = "tokenQuota" in body or "modelQuotaTokens" in body
        try:
            quota = parse_quota(body) if quota_supplied else None
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        result = (
            store.record_usage_adjustment(config_id, target, quota)
            if quota_supplied else store.record_usage_adjustment(config_id, target)
        )
        if result is None:
            return jsonify({"error": "未找到 AI 配置"}), 404
        saved = store.get_config(config_id)
        return jsonify({"ok": True, **result, "adjustment": result, "config": config_view(saved)})

    @bp.delete("/usage/<int:usage_id>")
    def delete_usage_record(usage_id: int):
        denial = authorized()
        if denial:
            return denial
        if not store.delete_usage_record(usage_id):
            return jsonify({"error": "未找到用量记录"}), 404
        return jsonify({"ok": True, "deleted": usage_id})

    @bp.delete("/usage/config/<int:config_id>")
    def delete_config_usage_record(config_id: int):
        """Remove one quota/calibration card, never the provider config."""
        denial = authorized()
        if denial:
            return denial
        if not store.delete_config_usage_record(config_id):
            return jsonify({"error": "未找到 AI 配置"}), 404
        return jsonify({
            "ok": True,
            "configId": config_id,
            "providerConfigPreserved": True,
            "taskUsagePreserved": True,
        })

    @bp.get("/usage")
    def get_usage():
        denial = authorized()
        if denial:
            return denial
        try:
            limit = int(request.args.get("limit", 50))
        except (TypeError, ValueError):
            return jsonify({"error": "数量上限必须是整数"}), 400
        return jsonify({**store.usage_summary(), "recent": store.list_usage(limit),
                        "daily": store.usage_daily(14), "storage": store.conversation_storage(),
                        "config_usage": store.usage_by_config(),
                        "model_usage": store.usage_by_model()})

    @bp.get("/conversations")
    def list_conversations():
        denial = authorized()
        if denial:
            return denial
        raw_limit = request.args.get("limit")
        try:
            limit = max(int(raw_limit), 1) if raw_limit is not None else None
        except ValueError:
            limit = None
        return jsonify({"conversations": store.list_conversations(limit)})

    @bp.get("/conversations/<conversation_id>/messages")
    def conversation_messages(conversation_id: str):
        denial = authorized()
        if denial:
            return denial
        messages = store.get_messages(conversation_id, limit=MAX_MESSAGES)
        return jsonify({"conversationId": conversation_id, "messages": messages})

    @bp.delete("/conversations/<conversation_id>/messages/<int:message_id>")
    def delete_conversation_message(conversation_id: str, message_id: int):
        denial = authorized()
        if denial:
            return denial
        if not store.delete_message(conversation_id, message_id):
            return jsonify({"error": "未找到该消息"}), 404
        return jsonify({"ok": True, "deleted": message_id})

    @bp.patch("/conversations/<conversation_id>")
    def rename_conversation(conversation_id: str):
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        if not isinstance(body.get("title"), str):
            return jsonify({"error": "必须填写对话标题"}), 400
        try:
            row = store.rename_conversation(conversation_id, body["title"])
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if row is None:
            return jsonify({"error": "未找到该对话"}), 404
        return jsonify({"conversation": row})

    @bp.delete("/conversations/<conversation_id>")
    def delete_conversation(conversation_id: str):
        denial = authorized()
        if denial:
            return denial
        if not store.delete_conversation(conversation_id):
            return jsonify({"error": "未找到该对话"}), 404
        return jsonify({"ok": True, "deleted": conversation_id})

    @bp.get("/catalog")
    def get_catalog():
        denial = authorized()
        return denial or jsonify(catalog())

    @bp.get("/notifications")
    def notifications():
        denial = authorized()
        if denial:
            return denial
        try:
            after = max(int(request.args.get("after", "0")), 0)
        except ValueError:
            after = 0
        rows = store.list_notifications(after_id=after, limit=100)
        return jsonify({"notifications": rows, "latestId": rows[-1]["id"] if rows else after})

    @bp.get("/notifications/stream")
    def notifications_stream():
        """Server-sent events feed of assistant notifications.

        Replaces the APP's fixed-interval polling while it is in the
        foreground; the generator polls the local SQLite inbox so no
        cross-thread signalling is required.
        """
        denial = authorized()
        if denial:
            return denial
        try:
            after = max(int(request.args.get("after", "0")), 0)
        except ValueError:
            after = 0

        def generate():
            cursor = after
            last_heartbeat = time.monotonic()
            started = last_heartbeat
            yield ": connected\n\n"
            # 长流有寿命上限：到期正常关闭，APP 会带退避重连。
            while time.monotonic() - started < 240:
                try:
                    rows = store.list_notifications(after_id=cursor, limit=50)
                except Exception:
                    rows = []
                for row in rows:
                    cursor = int(row["id"])
                    yield "data: " + json.dumps({"type": "notification", "notification": row},
                                                ensure_ascii=False, separators=(",", ":")) + "\n\n"
                if time.monotonic() - last_heartbeat >= 10:
                    last_heartbeat = time.monotonic()
                    yield ": ping\n\n"
                time.sleep(2)

        return sse_response(generate())

    def require_executor():
        if executor is None:
            raise ToolError("Hub 工具运行时尚未就绪", "RUNTIME_UNAVAILABLE", 503)
        return executor

    def tool_error_response(exc: ToolError):
        return jsonify({"error": str(exc), "code": exc.code}), exc.status_code

    @bp.post("/tools/execute")
    def execute_tool():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        tool_id = str(body.get("toolId") or "")
        arguments = body.get("arguments") or {}
        client_context = body.get("clientContext") or {}
        request_id = str(uuid.uuid4())
        spec = tool_spec(tool_id) or {"risk": "unknown"}
        try:
            result = require_executor().execute(tool_id, arguments, client_context=client_context)
            store.add_tool_audit(request_id, tool_id, str(spec["risk"]), "completed", arguments, result)
            return jsonify({"requestId": request_id, "toolId": tool_id, "result": result})
        except ToolError as exc:
            store.add_tool_audit(request_id, tool_id, str(spec["risk"]), "rejected", arguments,
                                 {"code": exc.code, "error": str(exc)})
            return tool_error_response(exc)

    @bp.post("/tools/prepare")
    def prepare_tool():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        tool_id = str(body.get("toolId") or "")
        arguments = body.get("arguments") or {}
        client_context = body.get("clientContext") or {}
        try:
            preview = require_executor().preview(tool_id, arguments, client_context=client_context)
        except ToolError as exc:
            return tool_error_response(exc)
        confirmation_id = str(uuid.uuid4())
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds")
        normalized_arguments = preview.get("arguments") if isinstance(preview.get("arguments"), dict) else arguments
        store.create_confirmation(confirmation_id, tool_id, normalized_arguments, preview, expires_at)
        store.add_tool_audit(confirmation_id, tool_id, "write", "confirmation_required", normalized_arguments, preview)
        return jsonify({"confirmationId": confirmation_id, "expiresAt": expires_at, "preview": preview})

    @bp.post("/tools/confirm")
    def confirm_tool():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        confirmation_id = str(body.get("confirmationId") or "")
        pending = store.claim_confirmation(confirmation_id)
        if pending is None:
            return jsonify({"error": "确认已过期、已使用或不存在", "code": "CONFIRMATION_INVALID"}), 409
        if pending.get("preview", {}).get("executor") == "app":
            result = {"ok": True, "message": "用户已确认，交由 APP 本机执行"}
            store.add_tool_audit(confirmation_id, pending["tool_id"], "write", "client_executing", pending["arguments"], result)
            return jsonify({
                "confirmationId": confirmation_id,
                "toolId": pending["tool_id"],
                "clientAction": pending["preview"],
                "result": result,
            })
        if pending["tool_id"] == "batch":
            items = pending["arguments"].get("tools") or []
            results = []
            failed = False
            for item in items:
                tool_id = str(item.get("toolId") or "")
                arguments = item.get("arguments") or {}
                try:
                    item_result = require_executor().execute(tool_id, arguments, allow_write=True)
                    results.append({"toolId": tool_id, "ok": True, "result": item_result})
                    store.add_tool_audit(f"{confirmation_id}:{tool_id}", tool_id, "write", "completed", arguments, item_result)
                except ToolError as exc:
                    results.append({"toolId": tool_id, "ok": False, "error": str(exc)})
                    store.add_tool_audit(f"{confirmation_id}:{tool_id}", tool_id, "write", "failed", arguments, {"code": exc.code, "error": str(exc)})
                    failed = True
                    break
                except Exception:
                    results.append({"toolId": tool_id, "ok": False, "error": "操作执行失败"})
                    store.add_tool_audit(f"{confirmation_id}:{tool_id}", tool_id, "write", "failed", arguments, {"code": "TOOL_EXECUTION_FAILED"})
                    failed = True
                    break
            summary_result = {"ok": not failed, "message": f"已完成 {sum(1 for r in results if r['ok'])}/{len(items)} 项操作", "items": results}
            store.finish_confirmation(confirmation_id, "failed" if failed else "completed", summary_result)
            record_confirmation_note(store, pending, summary_result["message"])
            return jsonify({"confirmationId": confirmation_id, "toolId": "batch", "result": summary_result})
        try:
            result = require_executor().execute(pending["tool_id"], pending["arguments"], allow_write=True)
            store.finish_confirmation(confirmation_id, "completed", result)
            store.add_tool_audit(confirmation_id, pending["tool_id"], "write", "completed", pending["arguments"], result)
            detail = str((result or {}).get("message") or "").strip() if isinstance(result, dict) else ""
            record_confirmation_note(store, pending,
                                     f"用户已确认，{tool_display_name(pending['tool_id'])}：" + (detail or "执行成功"))
            return jsonify({"confirmationId": confirmation_id, "toolId": pending["tool_id"], "result": result})
        except ToolError as exc:
            failure = {"code": exc.code, "error": str(exc)}
            store.finish_confirmation(confirmation_id, "failed", failure)
            store.add_tool_audit(confirmation_id, pending["tool_id"], "write", "failed", pending["arguments"], failure)
            record_confirmation_note(store, pending,
                                     f"{tool_display_name(pending['tool_id'])}执行失败：{exc}")
            return tool_error_response(exc)
        except Exception:
            failure = {"code": "TOOL_EXECUTION_FAILED", "error": "操作执行失败"}
            store.finish_confirmation(confirmation_id, "failed", failure)
            store.add_tool_audit(confirmation_id, pending["tool_id"], "write", "failed", pending["arguments"], failure)
            record_confirmation_note(store, pending,
                                     f"{tool_display_name(pending['tool_id'])}执行失败：操作执行失败")
            return jsonify(failure), 500

    def confirmation_view(item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "confirmationId": item["id"],
            "conversationId": item.get("conversation_id"),
            "toolId": item.get("tool_id"),
            "status": item.get("status"),
            "expiresAt": item.get("expires_at"),
            "createdAt": item.get("created_at"),
            "confirmedAt": item.get("confirmed_at"),
            "expired": bool(item.get("expired")),
            "preview": item.get("preview") or {},
            "result": item.get("result"),
        }

    @bp.post("/tools/cancel")
    def cancel_tool():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        confirmation_id = str(body.get("confirmationId") or "").strip()
        if not confirmation_id:
            return jsonify({"error": "缺少确认单 ID"}), 400
        cancelled = store.cancel_confirmation(confirmation_id)
        if cancelled is None:
            current = store.get_confirmation(confirmation_id)
            if current is None:
                return jsonify({"error": "确认不存在", "code": "CONFIRMATION_NOT_FOUND"}), 404
            return jsonify({
                "error": "确认已执行、已取消或已过期", "code": "CONFIRMATION_INVALID",
                "confirmation": confirmation_view(current),
            }), 409
        store.add_tool_audit(
            confirmation_id, cancelled["tool_id"], "write", "cancelled",
            cancelled.get("arguments") or {}, {"ok": False, "message": "用户已取消"},
        )
        record_confirmation_note(
            store, cancelled,
            f"用户已取消{tool_display_name(cancelled['tool_id'])}，操作未执行",
        )
        return jsonify({"ok": True, "confirmation": confirmation_view(cancelled)})

    @bp.get("/conversations/<conversation_id>/confirmations")
    @bp.get("/conversations/<conversation_id>/pending-confirmation")
    def pending_confirmation(conversation_id: str):
        denial = authorized()
        if denial:
            return denial
        pending = store.pending_confirmation_for_conversation(conversation_id)
        return jsonify({
            "conversationId": conversation_id,
            "confirmation": confirmation_view(pending) if pending is not None else None,
        })

    @bp.get("/tools/confirmations/<confirmation_id>")
    def confirmation_status(confirmation_id: str):
        denial = authorized()
        if denial:
            return denial
        item = store.get_confirmation(confirmation_id)
        if item is None:
            return jsonify({"error": "确认不存在", "code": "CONFIRMATION_NOT_FOUND"}), 404
        view = confirmation_view(item)
        # Keep the nested shape used by the APP and mirror lifecycle fields at
        # top level for simple status polling clients.
        return jsonify({**view, "confirmation": view})

    @bp.post("/tools/complete")
    def complete_client_tool():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        confirmation_id = str(body.get("confirmationId") or "")
        ok = body.get("ok") is True
        message = str(body.get("message") or ("APP 本机操作已完成" if ok else "APP 本机操作失败"))[:1000]
        result = {"ok": ok, "message": message}
        pending = store.complete_client_confirmation(
            confirmation_id, "completed" if ok else "failed", result,
        )
        if pending is None:
            return jsonify({"error": "确认未在执行中、已过期或已完成", "code": "CONFIRMATION_INVALID"}), 409
        store.add_tool_audit(
            confirmation_id, pending["tool_id"], "write", "completed" if ok else "failed",
            pending["arguments"], result,
        )
        record_confirmation_note(
            store, pending,
            f"APP {tool_display_name(pending['tool_id'])}{'执行成功' if ok else '执行失败'}：{message}",
        )
        return jsonify({"confirmationId": confirmation_id, "toolId": pending["tool_id"], "result": result})

    @bp.post("/test")
    @bp.post("/config/<int:config_id>/test")
    def test_config(config_id: int | None = None):
        denial = authorized()
        if denial:
            return denial
        path_config_id = config_id
        if config_id is None:
            try:
                query_id = request.args.get("id")
                config_id = int(query_id) if query_id is not None else None
            except (TypeError, ValueError):
                return jsonify({"error": "配置 ID 必须是整数"}), 400
        if path_config_id is not None:
            selected = store.get_config(config_id)
            rows = [selected] if selected and selected["enabled"] else []
        else:
            rows = store.list_configs(enabled_only=True)
            if config_id is not None:
                rows.sort(key=lambda row: 0 if int(row["id"]) == config_id else 1)
        if not rows:
            return jsonify({"error": "AI 服务商尚未配置或已停用"}), 409
        last_error: Exception | None = None
        last_status = 502
        for row in rows:
            try:
                key = decrypt_config_secret(row)
                result = OpenAICompatibleProvider(row["base_url"], key, row["model"]).chat(
                    [{"role": "user", "content": "Reply with OK."}]
                )
            except MasterKeyUnavailable as exc:
                return jsonify({"error": str(exc)}), 503
            except ValueError as exc:
                last_error, last_status = exc, 503
                store.add_usage("", row["provider"], row["model"], {}, status="failed", config_id=row["id"])
                continue
            except ProviderError as exc:
                last_error, last_status = exc, exc.status_code
                store.add_usage("", row["provider"], row["model"], {}, status="failed", config_id=row["id"])
                continue
            store.add_usage("", row["provider"], row["model"], result.usage, config_id=row["id"])
            response = {"status": "ok", "usage": result.usage}
            if path_config_id is not None:
                response.update({"configId": row["id"], "provider": row["provider"], "model": row["model"]})
            return jsonify(response)
        return jsonify({"error": str(last_error or "AI 服务商暂不可用"), "status": "failed"}), last_status

    @bp.post("/chat")
    def chat():
        denial = authorized()
        if denial:
            return denial
        body = request.get_json(silent=True) or {}
        client_context = body.get("clientContext") or {}
        if len(json.dumps(client_context, ensure_ascii=False)) > 32_000:
            return jsonify({"error": "APP 上下文超过大小限制"}), 413
        incremental = isinstance(body.get("message"), str) and body.get("messages") is None
        supplied = [{"role": "user", "content": body["message"]}] if incremental else body.get("messages")
        if not isinstance(supplied, list) or not supplied:
            return jsonify({"error": "消息列表不能为空"}), 400
        if len(supplied) > MAX_MESSAGES:
            return jsonify({"error": f"消息数量超过限制（最多 {MAX_MESSAGES} 条），请只发送最近对话"}), 400
        messages: List[Dict[str, str]] = []
        total_chars = 0
        for item in supplied:
            if not isinstance(item, dict) or item.get("role") not in {"user", "assistant"} or not isinstance(item.get("content"), str):
                return jsonify({"error": "消息角色或内容格式无效"}), 400
            if len(item["content"]) > MAX_MESSAGE_CHARS:
                return jsonify({"error": "单条消息超过大小限制"}), 413
            total_chars += len(item["content"])
            messages.append({"role": item["role"], "content": item["content"]})
        if total_chars > MAX_REQUEST_CHARS:
            return jsonify({"error": "消息总量超过请求大小限制"}), 413
        if incremental and len(messages[0]["content"]) > MAX_REPLAY_CHARS:
            return jsonify({"error": "消息超过上下文回放上限"}), 413
        conversation_id = str(body.get("conversationId") or uuid.uuid4())
        first_user_message = next((item["content"] for item in messages if item["role"] == "user"), None)
        store.create_conversation(conversation_id, title=first_user_message)
        user_message_id: int | None = None
        if incremental:
            user_message_id = store.add_message(conversation_id, "user", messages[0]["content"])
            messages = [
                {"role": item["role"], "content": item["content"]}
                for item in store.get_messages(conversation_id, limit=MAX_MESSAGES)
            ]
            # Strictly cap replay. The current incremental user message has
            # already passed the per-message validation above, so discard whole
            # oldest messages until the transcript is within budget.
            replay_chars = sum(len(item["content"]) for item in messages)
            while len(messages) > 1 and replay_chars > MAX_REPLAY_CHARS:
                replay_chars -= len(messages[0]["content"])
                messages.pop(0)
            # Do not begin a replay with a detached assistant response.
            while len(messages) > 1 and messages[0]["role"] != "user":
                replay_chars -= len(messages[0]["content"])
                messages.pop(0)
        else:
            # Compatibility for older APP builds that still send a bounded transcript.
            # Merge the visible replay instead of replacing the authoritative
            # transcript: a model context/window limit must never erase older
            # stored history.
            store.merge_replayed_messages(conversation_id, messages)
            stored_messages = store.get_messages(conversation_id, limit=MAX_MESSAGES)
            user_message_id = next(
                (int(item["id"]) for item in reversed(stored_messages) if item["role"] == "user"),
                None,
            )
        latest_user_text = next(
            (item["content"] for item in reversed(messages) if item["role"] == "user"), "",
        )
        wants_stream = bool(body.get("stream"))

        def stream_event(event: Dict[str, Any]) -> str:
            return "data: " + json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n\n"

        def sse_done(payload: Dict[str, Any]) -> Response:
            def emit():
                yield ": connected\n\n"
                msg = payload.get("message")
                content = str(msg.get("content") or "") if isinstance(msg, dict) else ""
                if content:
                    yield stream_event({"type": "delta", "content": content})
                yield stream_event({"type": "done", **payload})
            return sse_response(emit())

        def failure_payload(error: Any) -> Dict[str, Any]:
            detail = " ".join(str(error or "请求失败").split())[:500]
            content = "〔请求失败〕" + detail
            message_id = store.add_message(conversation_id, "assistant", content)
            return {
                "error": detail,
                "conversationId": conversation_id,
                "userMessageId": user_message_id,
                "messageId": message_id,
                "message": {"role": "assistant", "content": content},
            }

        def post_persist_failure(error: Any, status_code: int):
            payload = failure_payload(error)
            if wants_stream:
                def emit():
                    yield ": connected\n\n"
                    yield stream_event({"type": "error", **payload})
                return sse_response(emit())
            return jsonify(payload), status_code

        forced_tool_id = fast_path_tool_intent(latest_user_text)
        if forced_tool_id == "navigate.tool_nat" and executor is not None:
            content = (
                "已打开工具箱页的「NAT 检测」。\n"
                "如需我直接读取路由器原生的 NAT 类型与映射/过滤行为，请说「路由NAT检测」。"
            )
            message_id = store.add_message(conversation_id, "assistant", content)
            payload = {
                "conversationId": conversation_id,
                "message": {"role": "assistant", "content": content},
                "messageId": message_id,
                "userMessageId": user_message_id,
                "usage": {},
                "usageKnown": False,
                "toolExecutions": [],
                "clientActions": [{"type": "navigate", "route": "nat"}],
            }
            return sse_done(payload) if wants_stream else jsonify(payload)
        if forced_tool_id == "navigate.tool_tcp_peak" and executor is not None:
            content = (
                "已打开「TCP 峰值连接数」测试页。\n"
                "你可以在测试页面选择【本机 APP】或【Relay 宿主机】，配置目标域名/IP与量程，实时观察活动连接数走势图与系统资源占用。"
            )
            message_id = store.add_message(conversation_id, "assistant", content)
            payload = {
                "conversationId": conversation_id,
                "message": {"role": "assistant", "content": content},
                "messageId": message_id,
                "userMessageId": user_message_id,
                "usage": {},
                "usageKnown": False,
                "toolExecutions": [],
                "clientActions": [{"type": "navigate", "route": "tcp_peak"}],
            }
            return sse_done(payload) if wants_stream else jsonify(payload)
        if forced_tool_id == "agent.status" and executor is not None:
            try:
                tool_result = executor.execute("agent.status", {}, client_context)
            except ToolError as exc:
                return post_persist_failure(exc, exc.status_code)
            except Exception:
                return post_persist_failure("工具执行失败", 500)
            agent = tool_result.get("agent") if isinstance(tool_result.get("agent"), dict) else {}
            online = bool(agent.get("agentOnline") or agent.get("online"))
            router = agent.get("router") or "路由器"
            version = agent.get("agentVersion") or agent.get("version") or ""
            arch = agent.get("agentArchitecture") or agent.get("architecture") or ""
            age = agent.get("agentAgeSeconds")
            last_seen = agent.get("agentLastSeenAt") or agent.get("lastSeenAt") or ""
            if online:
                age_desc = f"{age} 秒前刚上报过" if isinstance(age, int) and age >= 0 else "当前通信正常"
                ver_desc = f"，版本 **{version}**" if version else ""
                arch_desc = f" ({arch})" if arch else ""
                content = (
                    f"Agent **在线**。路由器 **{router}** 上的 LabRelay Agent 状态为 **online**，"
                    f"{age_desc}{ver_desc}{arch_desc}。\n"
                    f"• 运行状态：**在线 (Online)**\n"
                    f"• 最近通信：**{last_seen or '刚刚'}**"
                )
            else:
                state = str(agent.get("agentState") or "offline")
                state_zh = "状态稍旧 (Stale)" if state == "stale" else "未连接 / 离线"
                content = (
                    f"Agent 当前处于 **{state_zh}** 状态。\n"
                    f"• 目标路由器：**{router}**\n"
                    f"• 上次上报时间：**{last_seen or '无记录'}**\n"
                    f"• 建议检查路由器 LabRelay 进程是否正常运行。"
                )
            message_id = store.add_message(conversation_id, "assistant", content)
            payload = {
                "conversationId": conversation_id,
                "message": {"role": "assistant", "content": content},
                "messageId": message_id,
                "userMessageId": user_message_id,
                "usage": {},
                "usageKnown": False,
                "toolExecutions": [{"toolId": "agent.status", "status": "completed"}],
                "clientActions": [],
            }
            return sse_done(payload) if wants_stream else jsonify(payload)
        if forced_tool_id == "app.settings.get" and executor is not None:
            try:
                tool_result = executor.execute("app.settings.get", {}, client_context)
            except Exception:
                tool_result = {}
            settings = tool_result.get("settings") if isinstance(tool_result, dict) else {}
            settings = settings if isinstance(settings, dict) else {}
            privacy = "已开启" if settings.get("privacyMode") else "已关闭"
            mode = settings.get("favoriteNetworkMode") or "自动"
            name = settings.get("routerDisplayName") or "默认"
            content = (
                "【当前 APP 设置】\n"
                f"• 隐私模式：**{privacy}**\n"
                f"• 快捷访问网络偏好：**{mode}**\n"
                f"• 路由器显示名称：**{name}**"
            )
            message_id = store.add_message(conversation_id, "assistant", content)
            payload = {
                "conversationId": conversation_id,
                "message": {"role": "assistant", "content": content},
                "messageId": message_id,
                "userMessageId": user_message_id,
                "usage": {},
                "usageKnown": False,
                "toolExecutions": [{"toolId": "app.settings.get", "status": "completed"}],
                "clientActions": [],
            }
            return sse_done(payload) if wants_stream else jsonify(payload)
        if forced_tool_id == "tcp.peak.status" and executor is not None:
            try:
                tool_result = executor.execute("tcp.peak.status", {"side": "relay"}, client_context)
            except Exception:
                tool_result = {}
            content = tool_result.get("content") or tool_result.get("message") or "暂无 TCP 峰值连接数测试记录。"
            message_id = store.add_message(conversation_id, "assistant", content)
            payload = {
                "conversationId": conversation_id,
                "message": {"role": "assistant", "content": content},
                "messageId": message_id,
                "userMessageId": user_message_id,
                "usage": {},
                "usageKnown": False,
                "toolExecutions": [{"toolId": "tcp.peak.status", "status": "completed"}],
                "clientActions": [],
            }
            return sse_done(payload) if wants_stream else jsonify(payload)
        if forced_tool_id == "router.firmware.status" and executor is not None:
            try:
                tool_result = executor.execute("router.firmware.status", {}, client_context)
            except Exception:
                tool_result = {}
            content = tool_result.get("content") or tool_result.get("message") or "暂未获取到固件版本信息。"
            message_id = store.add_message(conversation_id, "assistant", content)
            payload = {
                "conversationId": conversation_id,
                "message": {"role": "assistant", "content": content},
                "messageId": message_id,
                "userMessageId": user_message_id,
                "usage": {},
                "usageKnown": False,
                "toolExecutions": [{"toolId": "router.firmware.status", "status": "completed"}],
                "clientActions": [],
            }
            return sse_done(payload) if wants_stream else jsonify(payload)
        if forced_tool_id and executor is not None:
            if forced_tool_id == "network.self_check":
                try:
                    tool_result = executor.execute(forced_tool_id, {})
                except ToolError as exc:
                    return post_persist_failure(exc, exc.status_code)
                except Exception:
                    return post_persist_failure("工具执行失败", 500)
                content = network_self_check_content(tool_result)
            else:
                task_kind = "nat" if forced_tool_id == "router.nat.diagnostic" else "diagnostic"
                snapshot = _task_snapshot(hub_runtime, task_kind)
                if (diagnostic_result_query(latest_user_text)
                        and isinstance(snapshot, dict)
                        and str(snapshot.get("state") or "") not in {"", "idle"}):
                    # Result/status queries answer from the existing task instead
                    # of silently restarting a finished detection.
                    task = snapshot
                else:
                    try:
                        tool_result = executor.execute(forced_tool_id, {})
                    except ToolError as exc:
                        return post_persist_failure(exc, exc.status_code)
                    except Exception:
                        return post_persist_failure("工具执行失败", 500)
                    started = tool_result.get("task") if isinstance(tool_result.get("task"), dict) else None
                    task = _wait_router_task(hub_runtime, task_kind, 40.0) or started
                content = nat_diagnostic_content(task) if task_kind == "nat" else router_diagnostic_content(task or {})
            message_id = store.add_message(conversation_id, "assistant", content)
            payload = {
                "conversationId": conversation_id,
                "message": {"role": "assistant", "content": content},
                "messageId": message_id,
                "userMessageId": user_message_id,
                "usage": {},
                "usageKnown": False,
                "toolExecutions": [{"toolId": forced_tool_id, "status": "completed"}],
                "clientActions": [],
            }
            return sse_done(payload) if wants_stream else jsonify(payload)
        # 停用自动切换（产品决定）：对话只使用第一个启用的配置；不可用时把
        # 模型名与真实原因返回给 APP 提醒用户切换，而不是悄悄换下一个继续烧。
        config_rows = store.list_configs(enabled_only=True)[:1]
        if not config_rows:
            return post_persist_failure("AI 服务商尚未配置", 409)
        internal_messages: List[Dict[str, Any]] = list(messages)
        if not internal_messages or internal_messages[0].get("role") != "system":
            internal_messages.insert(0, {"role": "system", "content": TOOL_SYSTEM_PROMPT})
        accumulated_usage: Dict[str, int] = {}
        config_index = -1
        active_row: Dict[str, Any] | None = None
        active_provider: Any = None
        last_provider_error: ProviderError | None = None
        last_failed_model: str | None = None

        def config_model_label(row: Dict[str, Any]) -> str:
            model = str(row.get("model") or "当前模型")
            display_name = str(row.get("name") or row.get("provider") or "").strip()
            if not display_name or display_name == model:
                return model
            return f"{model}（{display_name}）"

        def model_unavailable_error() -> ProviderError:
            if last_provider_error is None:
                return ProviderError("AI 服务商暂不可用")
            detail = str(last_provider_error)
            status = last_provider_error.status_code
            model = last_failed_model or "当前模型"
            return ProviderError(
                f"模型 {model} 不可用：{detail}。自动切换已停用，请在 AI 设置中更换模型或修复后重试",
                status,
            )

        def next_provider():
            nonlocal config_index, active_row, active_provider, last_provider_error, last_failed_model
            while True:
                if active_provider is None:
                    config_index += 1
                    if config_index >= len(config_rows):
                        raise model_unavailable_error()
                    active_row = config_rows[config_index]
                    try:
                        key = decrypt_config_secret(active_row)
                    except (MasterKeyUnavailable, ValueError) as exc:
                        store.add_usage(conversation_id, active_row["provider"], active_row["model"], {},
                                        status="failed", config_id=active_row["id"], error=str(exc))
                        last_failed_model = config_model_label(active_row)
                        active_row = None
                        last_provider_error = ProviderError(str(exc), 503)
                        continue
                    active_provider = OpenAICompatibleProvider(
                        active_row["base_url"], key, active_row["model"],
                    )
                return active_row, active_provider

        def fail_active_provider(exc: ProviderError) -> None:
            nonlocal accumulated_usage, active_row, active_provider, last_provider_error, last_failed_model
            last_provider_error = exc
            if active_row is not None:
                last_failed_model = config_model_label(active_row)
                store.add_usage(
                    conversation_id, active_row["provider"], active_row["model"], accumulated_usage,
                    status="failed", config_id=active_row["id"], error=str(exc),
                )
            accumulated_usage = {}
            active_row = None
            active_provider = None

        def provider_chat(chat_messages, tools=None):
            while True:
                row, provider = next_provider()
                try:
                    result = provider.chat(chat_messages, tools=tools)
                except ProviderError as exc:
                    fail_active_provider(exc)
                    continue
                merge_usage(accumulated_usage, result.usage)
                return result

        def process_tool_call(call, executions, client_actions, pending_writes):
            """Run one model tool call. Returns (call_id, tool_id, payload);

            payload is None when a write was queued for user confirmation."""
            call_id = str(call.get("id") or uuid.uuid4()) if isinstance(call, dict) else str(uuid.uuid4())
            function = call.get("function") if isinstance(call, dict) else {}
            function = function if isinstance(function, dict) else {}
            tool_id = tool_id_from_function(str(function.get("name") or ""))
            try:
                arguments = json.loads(str(function.get("arguments") or "{}"))
                if not isinstance(arguments, dict):
                    raise ValueError("arguments must be an object")
            except (ValueError, json.JSONDecodeError):
                arguments = {}
                tool_payload = {"ok": False, "code": "INVALID_ARGUMENTS", "error": "工具参数不是有效 JSON"}
            else:
                tool_payload = {}
            if tool_id is None:
                tool_payload = {"ok": False, "code": "TOOL_NOT_FOUND", "error": "不支持该工具"}
            elif not tool_payload:
                guarded_tool_id = diagnostic_tool_intent(latest_user_text)
                if tool_id == "app.navigate" and guarded_tool_id in {
                    "router.nat.diagnostic", "router.diagnostic", "network.self_check",
                }:
                    tool_id = guarded_tool_id
                    arguments = {}
                spec = tool_spec(tool_id) or {"risk": "unknown"}
                if spec["risk"] == "write":
                    try:
                        preview = require_executor().preview(tool_id, arguments, client_context=client_context)
                    except ToolError as exc:
                        tool_payload = {"ok": False, "code": exc.code, "error": str(exc)}
                        store.add_tool_audit(call_id, tool_id, "write", "rejected", arguments, tool_payload)
                    else:
                        normalized_arguments = preview.get("arguments") if isinstance(preview.get("arguments"), dict) else arguments
                        signature = tool_id + "|" + json.dumps(normalized_arguments, sort_keys=True, ensure_ascii=False)
                        if signature not in {p["signature"] for p in pending_writes}:
                            pending_writes.append({
                                "signature": signature, "toolId": tool_id,
                                "arguments": normalized_arguments, "preview": preview,
                                "executor": str(preview.get("executor") or "hub"),
                            })
                        return call_id, tool_id, None
                else:
                    try:
                        tool_result = require_executor().execute(tool_id, arguments, client_context=client_context)
                        tool_payload = {"ok": True, "result": tool_result}
                        if isinstance(tool_result, dict) and isinstance(tool_result.get("clientAction"), dict):
                            client_actions.append(tool_result["clientAction"])
                        store.add_tool_audit(call_id, tool_id, str(spec["risk"]), "completed", arguments, tool_result)
                    except ToolError as exc:
                        tool_payload = {"ok": False, "code": exc.code, "error": str(exc)}
                        store.add_tool_audit(call_id, tool_id, str(spec["risk"]), "failed", arguments, tool_payload)
            return call_id, tool_id, tool_payload

        def normalize_tool_calls(raw_calls):
            """Give every model call a stable id before echoing it upstream."""
            normalized = []
            for source in raw_calls if isinstance(raw_calls, list) else []:
                call = dict(source) if isinstance(source, dict) else {}
                call["id"] = str(call.get("id") or uuid.uuid4())
                normalized.append(call)
            return normalized

        def rejected_overflow_call(call):
            """Produce the mandatory tool result for calls above the safety cap."""
            call_id = str(call.get("id") or uuid.uuid4())
            function = call.get("function") if isinstance(call.get("function"), dict) else {}
            raw_name = str(function.get("name") or "")
            tool_id = tool_id_from_function(raw_name) or raw_name or "unknown"
            return call_id, tool_id, {
                "ok": False,
                "code": "TOOL_CALL_LIMIT",
                "error": "单轮最多执行 4 个工具，其余调用已安全跳过",
            }

        def build_confirmation_payload(executions, client_actions, pending_writes, usage_snapshot):
            confirmation_id = str(uuid.uuid4())
            expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds")
            executors = {str(item.get("executor") or "hub") for item in pending_writes}
            # APP-local actions have a separate executor and completion
            # handshake.  Never put them in a Hub batch (or combine multiple
            # local actions into a payload the APP cannot execute atomically).
            batchable = len(pending_writes) > 1 and executors == {"hub"}
            selected = pending_writes if batchable else pending_writes[:1]
            deferred_count = len(pending_writes) - len(selected)
            if len(selected) == 1:
                first = selected[0]
                preview = dict(first["preview"])
                confirm_tool_id = first["toolId"]
                confirm_arguments = first["arguments"]
            else:
                confirm_tool_id = "batch"
                confirm_arguments = {"tools": [{"toolId": p["toolId"], "arguments": p["arguments"]} for p in selected]}
                preview = {
                    "toolId": "batch",
                    "title": f"确认执行 {len(selected)} 项操作",
                    "summary": "；".join(
                        str(p["preview"].get("summary") or p["preview"].get("title") or p["toolId"])
                        for p in selected
                    ),
                    "arguments": confirm_arguments,
                    "executor": "hub",
                }
            store.create_confirmation(confirmation_id, confirm_tool_id, confirm_arguments, preview, expires_at,
                                      conversation_id=conversation_id)
            for item in selected:
                store.add_tool_audit(confirmation_id, item["toolId"], "write", "confirmation_required", item["arguments"], item["preview"])
            content = "需要你的确认：" + str(preview.get("summary") or preview.get("title") or confirm_tool_id)
            if deferred_count:
                content += f"。为避免混用 APP 与 Hub 执行器，本次仅处理第一项，其余 {deferred_count} 项未排队，请分别发起"
            message_id = store.add_message(conversation_id, "assistant", content)
            store.add_usage(conversation_id, active_row["provider"], active_row["model"],
                            usage_snapshot, config_id=active_row["id"])
            return {
                "conversationId": conversation_id,
                "message": {"role": "assistant", "content": content},
                "messageId": message_id,
                "userMessageId": user_message_id,
                "usage": usage_snapshot,
                "usageKnown": usage_known(usage_snapshot),
                "configId": active_row["id"],
                "provider": active_row["provider"],
                "model": active_row["model"],
                "toolExecutions": executions,
                "clientActions": client_actions,
                "confirmation": {"confirmationId": confirmation_id, "expiresAt": expires_at, "preview": preview},
            }

        if wants_stream:
            def generate():
                executions: List[Dict[str, Any]] = []
                client_actions: List[Dict[str, Any]] = []
                pending_writes: List[Dict[str, Any]] = []
                yield ": connected\n\n"
                try:
                    for _ in range(4):
                        content_parts: List[str] = []
                        reasoning_parts: List[str] = []
                        tool_acc: Dict[str, Dict[str, str]] = {}
                        round_usage: Dict[str, int] = {}
                        while True:
                            row, provider = next_provider()
                            try:
                                provider_items = provider.stream(
                                    internal_messages,
                                    tools=provider_tools() if executor is not None else None,
                                )
                                for chunk in keepalive_items(provider_items):
                                    if chunk is None:
                                        yield ": ping\n\n"
                                        continue
                                    update_usage_snapshot(round_usage, usage_from_chunk(chunk) or {})
                                    choices = chunk.get("choices") if isinstance(chunk.get("choices"), list) else []
                                    for choice in choices:
                                        delta = choice.get("delta") if isinstance(choice, dict) else {}
                                        delta = delta if isinstance(delta, dict) else {}
                                        text = delta.get("content")
                                        if text:
                                            content_parts.append(str(text))
                                            yield stream_event({"type": "delta", "content": str(text)})
                                        reasoning = delta.get("reasoning_content")
                                        if reasoning:
                                            reasoning_parts.append(str(reasoning))
                                        accumulate_tool_call_fragment(tool_acc, delta.get("tool_calls"))
                                break
                            except ProviderError as exc:
                                merge_usage(accumulated_usage, round_usage)
                                round_usage.clear()
                                fail_active_provider(exc)
                                if content_parts or reasoning_parts or tool_acc:
                                    # Partial text/reasoning/tool fragments of the failed
                                    # attempt are already in memory or on the wire; tell
                                    # the client to clear them before the retry and never
                                    # combine stale tool-call fragments with a new stream.
                                    content_parts.clear()
                                    reasoning_parts.clear()
                                    tool_acc.clear()
                                    round_usage.clear()
                                    yield stream_event({"type": "reset"})
                        merge_usage(accumulated_usage, round_usage)
                        tool_calls = normalize_tool_calls(tool_calls_from_accumulated(tool_acc))
                        if tool_calls:
                            assistant_tool_message = {
                                "role": "assistant",
                                "content": "".join(content_parts) or None,
                                "tool_calls": tool_calls,
                            }
                            # TokenHub (and other interleaved-thinking APIs) require
                            # the reasoning trace to be echoed with the assistant
                            # tool-call message on the next round. Dropping it makes
                            # otherwise valid tool calls fail with HTTP 400.
                            if reasoning_parts:
                                assistant_tool_message["reasoning_content"] = "".join(reasoning_parts)
                            internal_messages.append(assistant_tool_message)
                            for call in tool_calls[:4]:
                                call_id, tool_id, tool_payload = process_tool_call(call, executions, client_actions, pending_writes)
                                if tool_payload is None:
                                    continue
                                succeeded = bool(tool_payload.get("ok"))
                                executions.append({"toolId": tool_id, "status": "completed" if succeeded else "failed"})
                                internal_messages.append({
                                    "role": "tool", "tool_call_id": call_id,
                                    "content": json.dumps(tool_payload, ensure_ascii=False, separators=(",", ":")),
                                })
                                yield stream_event({"type": "tool", "toolId": tool_id, "status": "completed" if succeeded else "failed"})
                            for call in tool_calls[4:]:
                                call_id, tool_id, tool_payload = rejected_overflow_call(call)
                                executions.append({"toolId": tool_id, "status": "failed"})
                                internal_messages.append({
                                    "role": "tool", "tool_call_id": call_id,
                                    "content": json.dumps(tool_payload, ensure_ascii=False, separators=(",", ":")),
                                })
                                yield stream_event({"type": "tool", "toolId": tool_id, "status": "failed"})
                            if pending_writes:
                                payload = build_confirmation_payload(executions, client_actions, pending_writes, accumulated_usage)
                                yield stream_event({"type": "confirmation", **payload})
                                return
                            continue
                        content_text = "".join(content_parts)
                        if not content_text:
                            raise ProviderError("AI 服务商返回了空响应")
                        message_id = store.add_message(conversation_id, "assistant", content_text)
                        if not accumulated_usage and logger is not None:
                            logger.warning("ai: provider returned no usage tokens (model=%s)", active_row["model"])
                        store.add_usage(conversation_id, active_row["provider"], active_row["model"],
                                        accumulated_usage, config_id=active_row["id"])
                        yield stream_event({
                            "type": "done",
                            "conversationId": conversation_id,
                            "message": {"role": "assistant", "content": content_text},
                            "messageId": message_id,
                            "userMessageId": user_message_id,
                            "usage": accumulated_usage,
                            "usageKnown": usage_known(accumulated_usage),
                            "configId": active_row["id"],
                            "provider": active_row["provider"],
                            "model": active_row["model"],
                            "toolExecutions": executions,
                            "clientActions": client_actions,
                        })
                        return
                    raise ProviderError("AI 工具调用轮次超过限制")
                except ProviderError as exc:
                    if active_row is not None:
                        store.add_usage(conversation_id, active_row["provider"], active_row["model"],
                                        accumulated_usage, status="failed", config_id=active_row["id"],
                                        error=str(exc))
                    yield stream_event({"type": "error", **failure_payload(exc)})
                except Exception:
                    if active_row is not None:
                        store.add_usage(
                            conversation_id, active_row["provider"], active_row["model"],
                            accumulated_usage, status="failed", config_id=active_row["id"],
                            error="unexpected provider stream failure",
                        )
                    if logger is not None:
                        logger.exception("ai: unexpected provider stream failure")
                    yield stream_event({"type": "error", **failure_payload("AI 服务流发生异常")})
            return sse_response(generate())
        executions: List[Dict[str, Any]] = []
        client_actions: List[Dict[str, Any]] = []
        pending_writes: List[Dict[str, Any]] = []
        try:
            for _ in range(4):
                result = provider_chat(internal_messages, tools=provider_tools() if executor is not None else None)
                assistant_message = result.message or {"role": "assistant", "content": result.content}
                assistant_message.setdefault("role", "assistant")
                tool_calls = normalize_tool_calls(assistant_message.get("tool_calls") or [])
                if not isinstance(tool_calls, list) or not tool_calls:
                    if not result.content:
                        raise ProviderError("AI 服务商返回了空响应")
                    message_id = store.add_message(conversation_id, "assistant", result.content)
                    if not accumulated_usage and logger is not None:
                        logger.warning("ai: provider returned no usage tokens (model=%s)", active_row["model"])
                    store.add_usage(conversation_id, active_row["provider"], active_row["model"],
                                    accumulated_usage, config_id=active_row["id"])
                    return jsonify({
                        "conversationId": conversation_id,
                        "message": {"role": "assistant", "content": result.content},
                        "messageId": message_id,
                        "userMessageId": user_message_id,
                        "usage": accumulated_usage,
                        "usageKnown": usage_known(accumulated_usage),
                        "configId": active_row["id"],
                        "provider": active_row["provider"],
                        "model": active_row["model"],
                        "toolExecutions": executions,
                        "clientActions": client_actions,
                    })
                assistant_message["tool_calls"] = tool_calls
                internal_messages.append(assistant_message)
                for call in tool_calls[:4]:
                    call_id, tool_id, tool_payload = process_tool_call(call, executions, client_actions, pending_writes)
                    if tool_payload is None:
                        continue
                    executions.append({"toolId": tool_id, "status": "completed" if tool_payload.get("ok") else "failed"})
                    internal_messages.append({
                        "role": "tool", "tool_call_id": call_id,
                        "content": json.dumps(tool_payload, ensure_ascii=False, separators=(",", ":")),
                    })
                for call in tool_calls[4:]:
                    call_id, tool_id, tool_payload = rejected_overflow_call(call)
                    executions.append({"toolId": tool_id, "status": "failed"})
                    internal_messages.append({
                        "role": "tool", "tool_call_id": call_id,
                        "content": json.dumps(tool_payload, ensure_ascii=False, separators=(",", ":")),
                    })
                if pending_writes:
                    return jsonify(build_confirmation_payload(executions, client_actions, pending_writes, accumulated_usage))
            raise ProviderError("AI 工具调用轮次超过限制")
        except ProviderError as exc:
            if active_row is not None:
                store.add_usage(conversation_id, active_row["provider"], active_row["model"],
                                accumulated_usage, status="failed", config_id=active_row["id"])
            return jsonify(failure_payload(exc)), exc.status_code
        except Exception:
            if active_row is not None:
                store.add_usage(
                    conversation_id, active_row["provider"], active_row["model"],
                    accumulated_usage, status="failed", config_id=active_row["id"],
                    error="unexpected provider failure",
                )
            if logger is not None:
                logger.exception("ai: unexpected provider failure")
            return jsonify(failure_payload("AI 服务发生异常")), 502

    return bp
