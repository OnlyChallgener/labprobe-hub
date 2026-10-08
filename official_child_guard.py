"""Account-backed membership changes, independent of fast local usage reporting.

Protocol verified against the official APK and both routers. A router/MQ ACK
does not acknowledge an account membership change. Only an authenticated list
read followed by a native readback completes the operation.
"""
from __future__ import annotations

import copy
import json
import os
import re
import secrets
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from zoneinfo import ZoneInfo

import requests

from assistant.security import decrypt_secret_with_migration, encrypt_secret
from child_guard_service import router_alias


class OfficialGuardError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable


def mac_key(value: Any) -> str:
    text = re.sub(r"[:-]", "", str(value or "").strip()).upper()
    if not re.fullmatch(r"[0-9A-F]{12}", text):
        raise OfficialGuardError("invalid_request", "设备 MAC 格式不正确")
    return text


def member_macs(row: dict) -> set[str]:
    values = row.get("mergeMacs", row.get("macs", []))
    if not isinstance(values, list):
        raise OfficialGuardError("official_response_invalid", "守护名单格式异常，未执行更改")
    return {mac_key(v) for v in values}


def member_uid(row: dict) -> str:
    value = str(row.get("staId", row.get("uid", ""))).upper()
    if not re.fullmatch(r"[0-9A-F]{32}", value):
        raise OfficialGuardError("official_response_invalid", "守护编号格式异常，未执行更改")
    return value


def matching_members(rows: list[dict], macs: set[str]) -> list[dict]:
    return [row for row in rows if member_macs(row) & macs]


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=path.stem + "-", dir=path.parent)
    try:
        os.chmod(temp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class OfficialGuardClient:
    # Credentials must never be forwarded to an editable URL or a redirect.
    BASE = "https://shinyaapp.ruijie.com.cn"

    def __init__(self, token: str = "", binding: dict | None = None, *, session=None):
        self.token = token
        self.binding = dict(binding or {})
        self.session = session or requests.Session()

    def request(self, method: str, path: str, *, data=None, params=None):
        headers = {"Accept": "application/json", "Content-Type": "application/json",
                   "type": "shinyaApp", "Cache-Control": "no-cache",
                   "projectId": str(self.binding.get("projectId", ""))}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        body = dict(data) if isinstance(data, dict) else data
        if isinstance(body, dict) and self.binding.get("projectId"):
            body["projectId"] = self.binding["projectId"]
        try:
            response = self.session.request(method, self.BASE + path, headers=headers,
                json=body, params=params, timeout=(5, 10), allow_redirects=False)
            if response.status_code in (401, 403):
                raise OfficialGuardError("official_auth_required", "官方账号授权已失效，请重新授权")
            if response.status_code >= 500:
                raise OfficialGuardError("official_unavailable", "官方服务暂时不可用，正在等待确认", retryable=True)
            if response.status_code != 200:
                raise OfficialGuardError("official_request_rejected", "官方服务未接受此次操作")
            value = response.json()
        except (requests.RequestException, ValueError):
            # POST may already have committed: the next attempt reads before writing.
            raise OfficialGuardError("official_connection_pending", "官方名单尚待确认，正在重试", retryable=True) from None
        if not isinstance(value, dict) or "code" not in value:
            raise OfficialGuardError("official_response_invalid", "官方响应格式异常，未确认同步结果")
        code = str(value["code"])
        if code in {"401", "403"}:
            raise OfficialGuardError("official_auth_required", "官方账号授权已失效，请重新授权")
        if code != "0":
            raise OfficialGuardError("official_request_rejected", "官方服务未接受此次操作（" + code + "）",
                                     retryable=code == "500")
        return value.get("data")

    def login_password(self, account: str, password: str) -> dict:
        value = self.request("POST", "/api/v1/base/homeUser/accountPasswordLogin",
                             data={"account": account, "password": password})
        if not isinstance(value, dict) or not value.get("token"):
            raise OfficialGuardError("official_auth_required", "官方账号登录失败")
        self.token = str(value["token"])
        return {"expireTime": value.get("expireTime")}

    def projects(self) -> list[dict]:
        value = self.request("POST", "/homewlan/apMonitor/getProjectList2",
                             data={"startPage": "1", "pageSize": "500"})
        if not isinstance(value, dict) or not isinstance(value.get("dataList"), list):
            raise OfficialGuardError("official_response_invalid", "无法核对官方账号下的网络")
        return value["dataList"]

    def routers(self, project_id) -> dict:
        self.binding = {"projectId": project_id}
        day = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d")
        value = self.request("POST", "/homewlan/homeAp/getDeviceInfoList2", data={"day": day})
        if not isinstance(value, dict) or not isinstance(value.get("apList"), list):
            raise OfficialGuardError("official_response_invalid", "无法核对官方路由器归属")
        return value

    def discover_binding(self, serial: str) -> dict:
        matches = []
        for project in self.projects():
            pid = project.get("buildingId")
            if not pid:
                continue
            data = self.routers(pid)
            aps = data["apList"]
            # A mesh satellite cannot stand in for the network's main router.
            main = str(data.get("mainAp") or "")
            for ap in aps:
                if str(ap.get("sn") or "") == serial and main == serial:
                    created = str(ap.get("createTime") or "").replace("T", " ")[:19]
                    if not re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", created):
                        raise OfficialGuardError("official_response_invalid", "官方路由器创建时间异常")
                    matches.append({"projectId": pid, "serial": serial,
                        "createTime": created, "projectName": str(project.get("name") or ""),
                        "meshSerials": [str(a["sn"]) for a in aps if a.get("sn")]})
        if len(matches) != 1:
            raise OfficialGuardError("official_router_mismatch", "官方账号未唯一匹配当前路由器，未执行更改")
        self.binding = matches[0]
        self.members()  # Validate the binding against the real list endpoint as well.
        return dict(self.binding)

    def members(self) -> list[dict]:
        binding = self.binding
        result = []
        for page in range(1, 11):
            value = self.request("GET", "/api/v1/netguard/staGuard/getProtectStaListPage", params={
                "mainApSn": binding["serial"], "mainApCreateTime": binding["createTime"],
                # Official UI includes the main router in this comma-separated list.
                "meshApSnList": ",".join(binding["meshSerials"]), "pageIndex": page, "pageSize": 200})
            if not isinstance(value, dict) or not isinstance(value.get("rows"), list):
                raise OfficialGuardError("official_response_invalid", "官方守护名单读取失败")
            rows = value["rows"]
            for row in rows:
                if not isinstance(row, dict):
                    raise OfficialGuardError("official_response_invalid", "官方守护名单格式异常")
                member_uid(row)
                member_macs(row)
            result.extend(rows)
            if len(rows) < 200:
                if len({member_uid(r) for r in result}) != len(result):
                    raise OfficialGuardError("official_response_invalid", "官方守护名单重复，未执行更改")
                return result
        raise OfficialGuardError("official_response_invalid", "官方守护名单超出读取范围，未执行更改")

    def add(self, macs: set[str], name: str, device_type: str = "unknown", manufacturer: str = ""):
        return self.request("POST", "/homewlan/childProtection/addSta", data={"staList": [
            {"name": name, "staMac": mac_key(mac), "type": device_type, "manufacturer": manufacturer}
            for mac in sorted(macs)]})

    def remove(self, uid: str):
        return self.request("POST", "/api/v1/netguard/staGuard/deleteSta",
                            data={"mainApSn": self.binding["serial"], "staId": uid})


class OfficialGuardCoordinator:
    """Durable, ordered membership workflow. No HTTP/ACK waiter holds a data lock."""
    def __init__(self, directory: Path, commands, identity: Callable[[str], str],
                 notify: Callable[[], None], *, client_factory=OfficialGuardClient):
        self.directory = Path(directory)
        self.auth_path = self.directory / "official_child_guard_accounts.json"
        self.ops_path = self.directory / "official_child_guard_operations.json"
        self.commands, self.identity, self.notify = commands, identity, notify
        self.client_factory = client_factory
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.thread = None
        self.stopped = threading.Event()
        self.auth = self._load(self.auth_path)
        self.ops = self._load(self.ops_path)

    @staticmethod
    def _load(path: Path) -> dict:
        if not path.exists():
            return {}
        # Fail closed on corrupt journals rather than losing unconfirmed writes.
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("invalid official guard storage")
        return value

    def binding(self, router: str) -> dict:
        key = router_alias(router)
        with self.lock:
            encrypted = self.auth.get(key)
            if not encrypted:
                raise OfficialGuardError("official_auth_required", "请先授权当前路由器的官方账号；本次未更改守护名单")
            value, migrated = decrypt_secret_with_migration(encrypted)
            if migrated:
                self.auth[key] = migrated
                atomic_json(self.auth_path, self.auth)
            binding = json.loads(value)
        serial = self.identity(router)
        if not serial or binding.get("serial") != serial:
            raise OfficialGuardError("official_router_mismatch", "当前路由器与官方授权不匹配，未执行更改")
        return binding

    def connect(self, router: str, account: str, password: str):
        serial = self.identity(router)
        if not serial:
            raise OfficialGuardError("official_router_mismatch", "尚未确认当前路由器身份，未保存授权")
        client = self.client_factory()
        expiry = client.login_password(account, password)
        binding = client.discover_binding(serial)
        if self.identity(router) != serial:
            raise OfficialGuardError("official_router_mismatch", "路由器身份已变化，未保存授权")
        self.install_binding(router, {**binding, **expiry, "token": client.token})
        return {"ok": True, "router": router, "authorized": True,
                "projectName": binding.get("projectName", "")}

    def install_binding(self, router: str, binding: dict):
        if not binding.get("token") or self.identity(router) != binding.get("serial"):
            raise OfficialGuardError("official_router_mismatch", "官方授权与路由器身份不匹配")
        with self.lock:
            self.auth[router_alias(router)] = encrypt_secret(json.dumps(binding, ensure_ascii=False))
            atomic_json(self.auth_path, self.auth)
            for op in self.ops.values():
                if op["routerKey"] == router_alias(router) and op.get("errorCode") == "official_auth_required":
                    op.update(state="pending", nextAt=0, attempts=0, error="", errorCode="")
            atomic_json(self.ops_path, self.ops)
        self.start()

    def authorization_status(self, router: str) -> dict:
        try:
            value = self.binding(router)
            return {"ok": True, "router": router, "authorized": True,
                    "projectName": value.get("projectName", ""), "expireTime": value.get("expireTime")}
        except OfficialGuardError as error:
            return {"ok": True, "router": router, "authorized": False,
                    "errorCode": error.code, "error": str(error)}

    def start(self):
        with self.lock:
            if self.thread is None or not self.thread.is_alive():
                self.thread = threading.Thread(target=self._loop, name="official-child-guard", daemon=True)
                self.thread.start()
        self.wake.set()

    def status(self, command_id: str) -> dict | None:
        with self.lock:
            row = copy.deepcopy(self.ops.get(command_id))
        if row is None:
            return None
        self.start()
        if row["state"] == "done":
            return {**row.get("result", {}), "ok": True, "router": row["router"],
                    "officialSync": {"state": "confirmed", "cloudConfirmed": True, "routerConfirmed": True}}
        if row["state"] in {"failed", "superseded"}:
            return {"ok": False, "router": row["router"], "commandId": command_id,
                    "errorCode": row.get("errorCode", "operation_superseded"),
                    "error": row.get("error", "已有更新的守护操作，请刷新名单"),
                    "officialSync": {"state": row["state"], "cloudConfirmed": bool(row.get("cloudConfirmed"))}}
        return {"ok": True, "pending": True, "router": row["router"], "commandId": command_id,
                "action": row["action"], "officialSync": {"state": row.get("phase", "cloud"),
                "cloudConfirmed": bool(row.get("cloudConfirmed")), "routerConfirmed": False}}

    def submit(self, router: str, action: str, payload: dict) -> dict:
        self.binding(router)  # Identity is checked before accepting or replaying anything.
        if action not in {"add_device", "remove_device"}:
            raise OfficialGuardError("invalid_request", "不支持此守护操作")
        macs = {mac_key(m) for m in payload.get("macs", [])}
        if not macs:
            raise OfficialGuardError("invalid_request", "缺少设备 MAC，请刷新守护名单后重试")
        # The official service decides MAC merging. Never silently split a local group.
        if action == "add_device" and len(macs) != 1:
            raise OfficialGuardError("invalid_request", "请按设备的当前 MAC 单独加入守护")
        with self.lock:
            for op in reversed(list(self.ops.values())):
                if op["routerKey"] == router_alias(router) and set(op["macs"]) == macs and op["state"] == "pending":
                    if op["action"] == action:
                        return self.status(op["id"])
                    # A subsequent opposite intent is queued after the current operation;
                    # it cannot overtake a write already in flight on the router.
                    break
            command_id = secrets.token_hex(12)
            self.ops[command_id] = {"id": command_id, "router": router, "routerKey": router_alias(router),
                "action": action, "payload": copy.deepcopy(payload), "macs": sorted(macs),
                "sequence": time.time_ns(), "state": "pending", "phase": "cloud",
                "createdAt": time.time(), "nextAt": 0, "attempts": 0, "native": {}}
            atomic_json(self.ops_path, self.ops)
        self.start()
        return self.status(command_id)

    def _update(self, cid: str, **fields):
        with self.lock:
            self.ops[cid].update(fields, updatedAt=time.time())
            atomic_json(self.ops_path, self.ops)

    def _native(self, op: dict, key: str, action: str, payload: dict) -> dict:
        self.binding(op["router"])  # Recheck identity after every blocking cloud call.
        cid = op["id"]
        with self.lock:
            command_id = self.ops[cid]["native"].get(key)
        if not command_id:
            command = self.commands.enqueue(op["router"], action, {**payload, "router": op["router"]})
            command_id = command["id"]
            with self.lock:
                self.ops[cid]["native"][key] = command_id
                atomic_json(self.ops_path, self.ops)
            self.notify()
        row = self.commands.record(command_id)
        if not row or row.get("status") not in {"done", "failed"}:
            raise OfficialGuardError("router_confirmation_pending", "官方名单已更新，正在确认路由器执行结果", retryable=True)
        if row["status"] == "failed":
            self._update(cid, native={})
            raise OfficialGuardError("router_confirmation_pending", "路由器执行结果尚待确认，正在重试", retryable=True)
        result = row.get("result") or {}
        if result.get("router") and router_alias(result["router"]) != op["routerKey"]:
            raise OfficialGuardError("official_router_mismatch", "路由器回执归属不一致，未确认操作")
        return result

    def _members_native(self, op: dict, key: str) -> list[dict]:
        value = self._native(op, key, "get_users", {})
        rows = value.get("devices")
        if not isinstance(rows, list):
            raise OfficialGuardError("router_confirmation_pending", "尚未读到路由器守护名单", retryable=True)
        for row in rows:
            member_uid(row)
            member_macs(row)
        return rows

    def process(self, command_id: str):
        """One resumable step; public for deterministic failure/restart tests."""
        with self.lock:
            op = copy.deepcopy(self.ops[command_id])
        if op["state"] != "pending":
            return
        binding = self.binding(op["router"])
        client = self.client_factory(binding["token"], binding)
        macs = set(op["macs"])
        added = op["action"] == "add_device"
        if not op.get("cloudConfirmed") or op.get("reconciling"):
            rows = client.members()
            matches = matching_members(rows, macs)
            if len(matches) > 1:
                raise OfficialGuardError("official_member_ambiguous", "设备对应多个官方守护编号，请先核对官方名单")
            if op.get("reconciling") and bool(matches) != added:
                # A later change through the official app wins over our completed
                # operation. A stale native snapshot, however, is repaired below.
                self._update(command_id, state="superseded", error="官方名单已发生后续更改，请刷新名单")
                return
            if not added and op["payload"].get("uid"):
                requested = str(op["payload"]["uid"]).upper()
                by_id = next((r for r in rows if member_uid(r) == requested), None)
                if by_id and not (member_macs(by_id) & macs):
                    raise OfficialGuardError("official_member_mismatch", "设备编号与 MAC 不一致，未执行解除守护")
            if matches:
                macs |= member_macs(matches[0])
            if added and not matches:
                client.add(macs, str(op["payload"].get("deviceName") or "受守护设备")[:120],
                           str(op["payload"].get("deviceType") or "unknown"),
                           str(op["payload"].get("manufacturer") or ""))
            elif not added and matches:
                client.remove(member_uid(matches[0]))
            verified = client.members()
            matches = matching_members(verified, macs)
            if len(matches) > 1 or bool(matches) != added:
                raise OfficialGuardError("official_confirmation_pending", "官方名单尚未确认此次更改，正在重新核对", retryable=True)
            uid = member_uid(matches[0]) if added else str(op["payload"].get("uid") or "")
            self._update(command_id, cloudConfirmed=True, phase="router", officialUid=uid, macs=sorted(macs),
                         reconciling=False)
            op.update(cloudConfirmed=True, officialUid=uid, macs=sorted(macs))
        uid = op["officialUid"]
        rows = self._members_native(op, "before")
        matches = matching_members(rows, set(op["macs"]))
        if added:
            # Clean only a duplicate with no restrictions. Preserve a local-only
            # plan instead of destroying it while converting a legacy UID.
            duplicates = [r for r in matches if member_uid(r) != uid]
            if any(int(r.get("planCount") or 0) > 0 or r.get("blocked") or r.get("paused") for r in duplicates):
                raise OfficialGuardError("official_local_plan_conflict", "旧守护编号仍有管控规则，已保留规则；需要核对后合并")
            for row in duplicates:
                old = member_uid(row)
                self._native(op, "remove-duplicate-" + old, "remove_device", {"uid": old})
            self._native(op, "add", "add_device", {"macs": [":".join(m[i:i+2] for i in range(0, 12, 2)).lower() for m in op["macs"]],
                "deviceName": op["payload"].get("deviceName"), "officialUid": uid})
        else:
            for row in matches:
                target = member_uid(row)
                # No MAC fallback: a disappearing duplicate must not delete its
                # replacement with a different UID.
                self._native(op, "remove-" + target, "remove_device", {"uid": target})
        latest = self._members_native(op, "after")
        matches = matching_members(latest, set(op["macs"]))
        native_ok = len(matches) == 1 and member_uid(matches[0]) == uid if added else not matches
        if not native_ok:
            self._update(command_id, native={})
            raise OfficialGuardError("router_confirmation_pending", "路由器名单仍在更新，正在再次核对", retryable=True)
        final_cloud = matching_members(client.members(), set(op["macs"]))
        cloud_ok = (len(final_cloud) == 1 and member_uid(final_cloud[0]) == uid) if added else not final_cloud
        if not cloud_ok:
            self._update(command_id, cloudConfirmed=False, reconciling=True, native={})
            raise OfficialGuardError("official_confirmation_pending", "官方名单已发生变化，正在重新核对", retryable=True)
        with self.lock:
            after_id = self.ops[command_id]["native"]["after"]
        after_result = (self.commands.record(after_id) or {}).get("result", {})
        result = {"uid": uid, "macs": [":".join(m[i:i+2] for i in range(0, 12, 2)).lower() for m in op["macs"]],
                  "name": op["payload"].get("deviceName"),
                  "membershipVersion": int(after_result.get("membershipVersion") or 0)}
        if not added:
            result["removedUids"] = list({str(op["payload"].get("uid") or uid), *[member_uid(r) for r in rows if member_macs(r) & set(op["macs"])]})
        self._update(command_id, state="done", phase="confirmed", result=result, error="", errorCode="")

    def observe(self, router: str, rows: list[dict]):
        """A stale firmware full-list sync cannot silently restore a completed delete."""
        if not isinstance(rows, list):
            return
        key = router_alias(router)
        changed = False
        with self.lock:
            latest = {}
            for op in sorted(self.ops.values(), key=lambda r: r["sequence"]):
                if op["routerKey"] == key:
                    for mac in op["macs"]:
                        latest[mac] = op["id"]
            for op in self.ops.values():
                if op["routerKey"] != key or op["state"] != "done" or any(latest[m] != op["id"] for m in op["macs"]):
                    continue
                matches = matching_members(rows, set(op["macs"]))
                ok = (len(matches) == 1 and member_uid(matches[0]) == op.get("officialUid")) if op["action"] == "add_device" else not matches
                if not ok:
                    op.update(state="pending", reconciling=True, phase="verify", native={}, nextAt=0, attempts=0)
                    changed = True
            if changed:
                atomic_json(self.ops_path, self.ops)
        if changed:
            self.start()

    def _loop(self):
        while not self.stopped.is_set():
            self.wake.wait(1)
            self.wake.clear()
            with self.lock:
                pending = sorted((copy.deepcopy(r) for r in self.ops.values() if r["state"] == "pending"), key=lambda r: r["sequence"])
            first = {}
            for row in pending:
                first.setdefault(row["routerKey"], row)
            for row in first.values():
                if float(row.get("nextAt") or 0) > time.time():
                    continue
                try:
                    self.process(row["id"])
                except OfficialGuardError as error:
                    attempts = int(row.get("attempts") or 0) + 1
                    self._update(row["id"], state="pending" if error.retryable else "failed",
                        errorCode=error.code, error=str(error), attempts=attempts,
                        nextAt=time.time() + (1 if error.code == "router_confirmation_pending" else min(30, 2 ** min(attempts, 5))))
                except Exception:
                    # Never log a token, a raw response, a password or exception args.
                    self._update(row["id"], state="failed", errorCode="official_sync_failed",
                                 error="守护同步遇到异常，请重新核对官方授权")
