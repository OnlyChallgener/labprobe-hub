"""App-confirmed account metadata and native membership coordination.

The Hub never authenticates to the official cloud. The APP authenticates over
HTTPS, then installs metadata and cloud-confirmed native operations here.
"""
from __future__ import annotations

import copy
import hashlib
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


# A delivered native command is retried at 20s intervals, up to three attempts.
# Logout waits one full delivery window so a command cannot execute after a
# successful logout response. If the router/Relay disappears instead, logout
# reports pending/unknown rather than claiming the command stopped.
OFFICIAL_LOGOUT_NATIVE_TIMEOUT_SEC = 65.0

BINDING_FIELDS = {"projectId", "projectName", "serial", "createTime", "meshSerials",
                  "account", "accountFingerprint", "expireTime", "verifiedAt", "bindingVersion"}
CREDENTIAL_FIELDS = {"password", "passwd", "token", "refreshtoken", "accesstoken",
                     "idtoken", "authorization", "cookie", "secret", "credentials"}


def reject_credentials(value: Any) -> None:
    """Reject credential keys at every depth, before any persistence/dispatch."""
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).replace("_", "").replace("-", "").lower() in CREDENTIAL_FIELDS:
                raise OfficialGuardError("credentials_forbidden",
                    "Hub 不接受官方账号密码或云凭据；请由 APP 直连官方云认证", retryable=False)
            reject_credentials(child)
    elif isinstance(value, list):
        for child in value:
            reject_credentials(child)


def scrub_credentials(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: scrub_credentials(child) for key, child in value.items()
                if str(key).replace("_", "").replace("-", "").lower() not in CREDENTIAL_FIELDS}
    if isinstance(value, list):
        return [scrub_credentials(child) for child in value]
    return value


class OfficialGuardError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable


def normalize_serial(value: Any) -> str:
    return str(value or "").strip().upper()


def expire_time_ms(value: Any) -> int | None:
    """Normalize the official epoch-millisecond expiry without guessing units."""
    if value in (None, ""):
        return None
    if isinstance(value, bool) or isinstance(value, float):
        raise OfficialGuardError("official_response_invalid", "Official account expiry must be epoch milliseconds")
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        raise OfficialGuardError("official_response_invalid", "官方账号有效期格式异常") from None
    if result < 0:
        raise OfficialGuardError("official_response_invalid", "官方账号有效期格式异常")
    return result


def mask_account(value: Any) -> str:
    account = str(value or "").strip()
    if not account:
        return ""
    if "@" in account:
        local, domain = account.rsplit("@", 1)
        return (local[:1] or "*") + "***@" + domain
    if len(account) >= 7:
        return account[:3] + "****" + account[-4:]
    return account[:1] + "***"


def account_fingerprint(value: Any) -> str:
    account = str(value or "").strip()
    return hashlib.sha256(account.encode("utf-8")).hexdigest() if account else ""


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
                             data={"account": str(account).strip(), "password": password})
        if not isinstance(value, dict) or not value.get("token"):
            raise OfficialGuardError("official_auth_required", "官方账号登录失败")
        self.token = str(value["token"])
        return {"expireTime": expire_time_ms(value.get("expireTime"))}

    def refresh_token(self) -> dict:
        value = self.request("POST", "/api/v1/base/homeUser/refreshToken")
        if not isinstance(value, dict):
            raise OfficialGuardError("official_response_invalid", "官方账号刷新响应异常")
        token = str(value.get("token") or self.token or "")
        if not token:
            raise OfficialGuardError("official_auth_required", "官方账号刷新失败")
        self.token = token
        # Omission is not a non-expiring token. The coordinator retains a known
        # expiry on refresh and refuses authorization when none is known.
        return ({"expireTime": expire_time_ms(value.get("expireTime"))}
                if value.get("expireTime") not in (None, "") else {})

    def logout(self) -> None:
        self.request("POST", "/api/v1/base/homeUser/logout")

    def projects(self) -> list[dict]:
        result = []
        seen = set()
        page_size = 500
        total = None
        for page in range(1, 101):
            value = self.request("POST", "/homewlan/apMonitor/getProjectList2",
                                 data={"startPage": str(page), "pageSize": str(page_size)})
            if not isinstance(value, dict) or not isinstance(value.get("dataList"), list):
                raise OfficialGuardError("official_response_invalid", "无法核对官方账号下的网络")
            rows = value["dataList"]
            added = 0
            for project in rows:
                if not isinstance(project, dict):
                    raise OfficialGuardError("official_response_invalid", "官方网络列表格式异常")
                pid = str(project.get("buildingId") or "").strip()
                identity = pid or json.dumps(project, ensure_ascii=False, sort_keys=True, default=str)
                if identity in seen:
                    continue
                seen.add(identity)
                result.append(project)
                added += 1
            for field in ("totalCount", "total"):
                if value.get(field) not in (None, ""):
                    try:
                        total = max(0, int(value[field]))
                    except (TypeError, ValueError, OverflowError):
                        raise OfficialGuardError("official_response_invalid", "官方网络列表数量异常") from None
                    break
            if not rows or len(rows) < page_size or (total is not None and len(result) >= total):
                return result
            if not added:
                raise OfficialGuardError("official_response_invalid", "官方网络列表分页异常")
        raise OfficialGuardError("official_response_invalid", "官方网络列表超出读取范围")

    def routers(self, project_id) -> dict:
        self.binding = {"projectId": project_id}
        day = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d")
        value = self.request("POST", "/homewlan/homeAp/getDeviceInfoList2", data={"day": day})
        if not isinstance(value, dict) or not isinstance(value.get("apList"), list):
            raise OfficialGuardError("official_response_invalid", "无法核对官方路由器归属")
        return value

    def discover_binding(self, serial: str) -> dict:
        serial = normalize_serial(serial)
        if not serial:
            raise OfficialGuardError("official_router_mismatch", "尚未确认当前路由器身份，未执行更改")
        matches = []
        for project in self.projects():
            pid = str(project.get("buildingId") or "").strip()
            if not pid:
                continue
            data = self.routers(pid)
            aps = data["apList"]
            # Only the project's declared main AP may bind this worker. Mesh
            # membership and project names are deliberately never used.
            main = normalize_serial(data.get("mainAp"))
            if main != serial:
                continue
            ap = next((row for row in aps if isinstance(row, dict)
                       and normalize_serial(row.get("sn")) == serial), None)
            if ap is None:
                continue
            created = str(ap.get("createTime") or "").replace("T", " ")[:19]
            if not re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", created):
                raise OfficialGuardError("official_response_invalid", "官方路由器创建时间异常")
            matches.append({"projectId": pid, "serial": serial,
                "createTime": created, "projectName": str(project.get("name") or ""),
                "meshSerials": list(dict.fromkeys(normalize_serial(a["sn"]) for a in aps
                                       if isinstance(a, dict) and normalize_serial(a.get("sn"))))})
        if len(matches) != 1 or len({row["projectId"] for row in matches}) != 1:
            raise OfficialGuardError("official_router_mismatch", "官方账号未唯一匹配当前路由器，未执行更改")
        self.binding = matches[0]
        self.members()  # Validate the binding against the real list endpoint as well.
        return dict(self.binding)

    def verify_binding(self, serial: str) -> dict:
        """Validate the current token and rebind only this worker's real main AP."""
        return self.discover_binding(serial)

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
                 notify: Callable[[], None], *, client_factory=None):
        self.directory = Path(directory)
        self.auth_path = self.directory / "official_child_guard_accounts.json"
        self.ops_path = self.directory / "official_child_guard_operations.json"
        self.generation_path = self.directory / "official_child_guard_auth_generations.json"
        self.commands, self.identity, self.notify = commands, identity, notify
        # Retained only as an inert compatibility attribute. Production never
        # constructs OfficialGuardClient or calls the official cloud.
        self.client_factory = client_factory
        self.lock = threading.RLock()
        self._barriers: dict[str, threading.RLock] = {}
        self.wake = threading.Event()
        self.thread = None
        self.stopped = threading.Event()
        self._load_errors = set()
        self.auth = self._load(self.auth_path, self._load_errors)
        self.ops = self._load(self.ops_path, self._load_errors)
        self.generations = self._load(self.generation_path, self._load_errors)
        self._migrate_legacy_storage()

    @staticmethod
    def _load(path: Path, errors: set | None = None) -> dict:
        if not path.exists():
            return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("invalid official guard storage")
            return value
        except (ValueError, OSError):
            # Keep the damaged file untouched and fail this journal closed.
            if errors is not None:
                errors.add(path)
            return {}

    def _migrate_legacy_storage(self) -> None:
        """Idempotently remove legacy credentials and forbid cloud replay."""
        for key, encrypted in list(self.auth.items()):
            try:
                value, migrated = decrypt_secret_with_migration(encrypted)
                binding = json.loads(value)
                if not isinstance(binding, dict):
                    raise ValueError("invalid binding")
                clean = {field: binding[field] for field in BINDING_FIELDS if field in binding}
                clean["authGeneration"] = int(binding.get("authGeneration") or 0)
                changed = clean != binding
                if changed:
                    encrypted = encrypt_secret(json.dumps(clean, ensure_ascii=False))
                    self.auth[key] = encrypted
            except Exception:
                self._load_errors.add(self.auth_path)
        if self.auth_path not in self._load_errors:
            try:
                atomic_json(self.auth_path, self.auth)
            except OSError:
                self._load_errors.add(self.auth_path)
        for op in self.ops.values():
            if not isinstance(op, dict):
                continue
            clean = scrub_credentials(op)
            op.clear()
            op.update(clean)
            # Every legacy pending operation may have unconfirmed cloud writes.
            # Native-only processing must never replay or rediscover those writes.
            if op.get("state") == "pending" and op.get("protocol") != "app-confirmed-native-v1":
                op.update(state="superseded", errorCode="official_cloud_replay_forbidden",
                          error="旧官方云操作已失效，请由 APP 重新确认；Hub 不会重放云端调用", nextAt=0)
            elif op.get("state") == "done":
                op["cloudConfirmed"] = False
        if self.ops_path not in self._load_errors:
            try:
                atomic_json(self.ops_path, self.ops)
            except OSError:
                self._load_errors.add(self.ops_path)
        # Legacy pending native writes were never APP-confirmed. Cancel those
        # not yet delivered; an already delivered command cannot be recalled.
        command_ids = {str(cid) for op in self.ops.values() if op.get("state") == "superseded"
                       for cid in (op.get("native") or {}).values()}
        if command_ids and self.ops_path not in self._load_errors:
            with self.commands.changed:
                rows = self.commands._load()
                changed = False
                for command in rows:
                    if str(command.get("id") or "") in command_ids and command.get("status") == "pending":
                        command.update(status="failed", finishedAt=time.time(),
                            error="legacy official operation superseded before native dispatch",
                            result={"ok": False, "errorCode": "official_cloud_replay_forbidden"})
                        changed = True
                if changed:
                    self.commands._save(rows)
                    self.commands.changed.notify_all()

    def _router_barrier(self, router: str) -> threading.RLock:
        key = router_alias(router)
        with self.lock:
            return self._barriers.setdefault(key, threading.RLock())

    def _current_generation(self, router: str) -> int:
        key = router_alias(router)
        with self.lock:
            current = int(self.generations.get(key) or 0)
            encrypted = self.auth.get(key)
            if encrypted:
                try:
                    current = max(current, int(json.loads(
                        decrypt_secret_with_migration(encrypted)[0]).get("authGeneration") or 0))
                except Exception:
                    pass
            return current

    @staticmethod
    def _binding_expiry(binding: dict) -> int:
        expiry = expire_time_ms(binding.get("expireTime"))
        if expiry is None:
            raise OfficialGuardError("official_expiry_unknown",
                                     "官方账号有效期未知，请重新授权后再更改守护名单")
        return expiry

    def _quiesce_native_commands(self, router: str) -> None:
        """Cancel not-yet-delivered writes and wait for delivered writes.

        The Relay intentionally has no official-account coupling. A delivered
        command therefore cannot be recalled here; waiting for its terminal ACK
        is the only way to guarantee it will not execute after logout returns.
        """
        key = router_alias(router)
        with self.lock:
            command_ids = {str(command_id)
                for op in self.ops.values() if op.get("routerKey") == key
                for command_id in (op.get("native") or {}).values()}
        if not command_ids:
            return
        deadline = time.monotonic() + OFFICIAL_LOGOUT_NATIVE_TIMEOUT_SEC
        store = self.commands
        while True:
            delivered = False
            # RouterCommandStore exposes its durable queue lock/load/save
            # internally. Use that same lock so cancellation cannot race take().
            with store.changed:
                rows = store._load()
                changed = False
                for command in rows:
                    if str(command.get("id") or "") not in command_ids:
                        continue
                    if command.get("action") not in {"add_device", "remove_device"}:
                        continue
                    if command.get("status") == "pending":
                        command.update(status="failed", finishedAt=time.time(),
                            error="official account logged out before native dispatch",
                            result={"ok": False, "errorCode": "official_logged_out"})
                        changed = True
                    elif command.get("status") == "delivered":
                        delivered = True
                if changed:
                    store._save(rows)
                    store.changed.notify_all()
            if not delivered:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OfficialGuardError("official_logout_pending",
                    "本地授权已清除，但路由器命令结果尚待确认；请勿重复退出或重试守护操作",
                    retryable=True)
            with store.changed:
                store.changed.wait(timeout=min(0.5, remaining))

    def _raw_binding(self, router: str) -> dict:
        if self.auth_path in self._load_errors:
            raise OfficialGuardError("official_storage_corrupt", "官方绑定记录损坏，已停止守护更改；其他配置未改动")
        key = router_alias(router)
        with self.lock:
            encrypted = self.auth.get(key)
            if not encrypted:
                raise OfficialGuardError("official_auth_required", "请先由 APP 绑定当前路由器的官方账号元数据")
            try:
                value, migrated = decrypt_secret_with_migration(encrypted)
                if migrated:
                    raise OfficialGuardError("official_storage_corrupt", "官方绑定加密记录异常，已停止守护更改")
                binding = json.loads(value)
                if not isinstance(binding, dict):
                    raise ValueError("invalid binding")
            except OfficialGuardError:
                raise
            except Exception:
                raise OfficialGuardError("official_storage_corrupt", "官方绑定记录损坏，已停止守护更改") from None
            generation = int(binding.get("authGeneration") or 0)
            if int(self.generations.get(key) or generation) != generation:
                raise OfficialGuardError("official_auth_required", "官方账号授权已失效，请重新绑定")
            return binding

    def binding(self, router: str) -> dict:
        binding = self._raw_binding(router)
        serial = normalize_serial(self.identity(router))
        if not serial or normalize_serial(binding.get("serial")) != serial:
            raise OfficialGuardError("official_router_mismatch", "当前路由器与官方授权不匹配，未执行更改")
        expiry = self._binding_expiry(binding)
        if expiry <= int(time.time() * 1000):
            raise OfficialGuardError("official_token_expired", "官方账号授权已过期，请刷新授权")
        return binding

    def _bump_generation(self, router: str) -> int:
        key = router_alias(router)
        with self.lock:
            current = int(self.generations.get(key) or 0)
            encrypted = self.auth.get(key)
            if encrypted:
                try:
                    current = max(current, int(json.loads(decrypt_secret_with_migration(encrypted)[0]).get("authGeneration") or 0))
                except Exception:
                    pass
            current += 1
            self.generations[key] = current
            atomic_json(self.generation_path, self.generations)
            return current

    def _require_writable_storage(self) -> None:
        if self._load_errors:
            raise OfficialGuardError("official_storage_corrupt",
                "Official guard storage is corrupt; no configuration was overwritten")

    def _invalidate_router(self, router: str) -> None:
        key = router_alias(router)
        with self.lock:
            self.auth.pop(key, None)
            atomic_json(self.auth_path, self.auth)
            for op in self.ops.values():
                if op.get("routerKey") != key:
                    continue
                op["authInvalidated"] = True
                if op.get("state") == "pending":
                    op.update(state="superseded", errorCode="official_logged_out",
                              error="官方账号已退出，未完成的守护操作已停止", nextAt=0)
            if self.ops_path not in self._load_errors:
                atomic_json(self.ops_path, self.ops)
        self.wake.set()

    def connect(self, router: str, account: str, password: str):
        raise OfficialGuardError("password_login_deprecated",
            "Hub 不再接受官方账号密码；请由 APP 通过 HTTPS 直连官方云认证")

    def install_binding(self, router: str, binding: dict, *, expected_generation: int | None = None):
        self._require_writable_storage()
        if not isinstance(binding, dict):
            raise OfficialGuardError("invalid_request", "绑定元数据格式不正确")
        reject_credentials(binding)
        if set(binding) - BINDING_FIELDS - {"authGeneration"}:
            raise OfficialGuardError("invalid_request", "绑定包含不支持的字段，仅接受 APP 确认的元数据")
        with self._router_barrier(router):
            serial = normalize_serial(self.identity(router))
            if not serial or normalize_serial(binding.get("serial")) != serial:
                raise OfficialGuardError("official_router_mismatch", "绑定 SN 与本机身份不匹配")
            project_id = str(binding.get("projectId") or "").strip()
            version = binding.get("bindingVersion")
            if not project_id:
                raise OfficialGuardError("invalid_request", "projectId 不能为空")
            if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
                raise OfficialGuardError("invalid_request", "bindingVersion 必须为正整数")
            stored = {field: copy.deepcopy(binding[field]) for field in BINDING_FIELDS if field in binding}
            stored.update(projectId=project_id, serial=serial, bindingVersion=version)
            expiry = self._binding_expiry(stored)
            if expiry <= int(time.time() * 1000):
                raise OfficialGuardError("official_token_expired", "APP 确认的官方账号有效期已过期")
            key = router_alias(router)
            with self.lock:
                if expected_generation is not None and self._current_generation(router) != expected_generation:
                    raise OfficialGuardError("official_auth_changed", "官方账号授权已变化，本次绑定未保存")
                generation = self._bump_generation(router)
                stored.update(authGeneration=generation, verifiedAt=stored.get("verifiedAt") or time.time())
                self.auth[key] = encrypt_secret(json.dumps(stored, ensure_ascii=False))
                atomic_json(self.auth_path, self.auth)
                for op in self.ops.values():
                    if op.get("routerKey") != key:
                        continue
                    op["authInvalidated"] = True
                    if op.get("state") == "pending":
                        op.update(state="superseded", errorCode="official_auth_changed",
                                  error="官方账号绑定已变化，旧守护操作已停止", nextAt=0)
                atomic_json(self.ops_path, self.ops)
        self.start()
        return self.authorization_status(router)

    def refresh(self, router: str) -> dict:
        raise OfficialGuardError("cloud_refresh_deprecated",
            "Hub does not refresh cloud credentials; APP must refresh and rebind")

    def logout(self, router: str) -> dict:
        with self._router_barrier(router):
            if self.generation_path not in self._load_errors:
                self._bump_generation(router)
            self._invalidate_router(router)
            self._quiesce_native_commands(router)
            return {**self.authorization_status(router), "localCleared": True,
                    "remoteRevocation": "app-managed/confirmed-by-app"}

    def authorization_status(self, router: str, verify: bool = False) -> dict:
        if verify:
            with self._router_barrier(router):
                return self._authorization_status(router, verify=True)
        return self._authorization_status(router, verify=False)

    def _authorization_status(self, router: str, verify: bool) -> dict:
        # verify is accepted for API compatibility but is deliberately local-only.
        serial = normalize_serial(self.identity(router))
        result = {"ok": True, "router": router, "authorized": False, "account": "",
            "accountFingerprint": "", "projectId": None, "projectName": "", "serial": serial,
            "expireTime": None, "verifiedAt": None, "cloudVerified": False, "routerVerified": False}
        try:
            value = self._raw_binding(router)
            account = str(value.get("account") or "").strip()
            result.update(account=mask_account(account), accountFingerprint=account_fingerprint(account),
                projectId=value.get("projectId"), projectName=str(value.get("projectName") or ""),
                expireTime=expire_time_ms(value.get("expireTime")), verifiedAt=value.get("verifiedAt"),
                bindingVersion=value.get("bindingVersion"), cloudVerified=True)
            if not serial or normalize_serial(value.get("serial")) != serial:
                raise OfficialGuardError("official_router_mismatch", "Binding SN does not match this router")
            version = value.get("bindingVersion")
            if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
                raise OfficialGuardError("invalid_request", "bindingVersion must be a positive integer")
            if not str(value.get("projectId") or "").strip():
                raise OfficialGuardError("invalid_request", "projectId is required")
            result["routerVerified"] = True
            expiry = result["expireTime"]
            if expiry is None:
                raise OfficialGuardError("official_expiry_unknown", "Official account expiry is unknown")
            if expiry <= int(time.time() * 1000):
                raise OfficialGuardError("official_token_expired", "Official account binding has expired")
            result["authorized"] = True
        except OfficialGuardError as error:
            result.update(errorCode=error.code, error=str(error), cloudVerified=False)
            if error.code not in {"official_connection_pending", "official_unavailable"}:
                result["authorized"] = False
            if error.code in {"official_auth_changed", "official_logged_out", "official_router_mismatch"}:
                result["routerVerified"] = False
        return result

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
        if self.ops_path in self._load_errors:
            return {"ok": False, "router": row.get("router"), "commandId": command_id,
                    "errorCode": "official_storage_corrupt", "error": "Operation journal is corrupt",
                    "officialSync": {"state": "failed", "cloudConfirmed": False, "routerConfirmed": False}}
        self.start()
        cloud_confirmed = bool(row.get("cloudConfirmed"))
        router_confirmed = row.get("state") == "done" and cloud_confirmed
        if row["state"] == "done":
            return {**row.get("result", {}), "ok": True, "router": row["router"],
                    "officialSync": {"state": "confirmed", "cloudConfirmed": cloud_confirmed,
                                     "routerConfirmed": router_confirmed}}
        if row["state"] in {"failed", "superseded"}:
            return {"ok": False, "router": row["router"], "commandId": command_id,
                    "errorCode": row.get("errorCode", "operation_superseded"),
                    "error": row.get("error", "A newer guard operation exists"),
                    "officialSync": {"state": row["state"], "cloudConfirmed": cloud_confirmed,
                                     "routerConfirmed": False}}
        return {"ok": True, "pending": True, "router": row["router"], "commandId": command_id,
                "action": row["action"], "officialSync": {"state": row.get("phase", "router"),
                "cloudConfirmed": cloud_confirmed, "routerConfirmed": False}}

    def submit(self, router: str, action: str, payload: dict) -> dict:
        self._require_writable_storage()
        if not isinstance(payload, dict):
            raise OfficialGuardError("invalid_request", "Invalid official sync payload")
        reject_credentials(payload)
        if action not in {"add_device", "remove_device"}:
            raise OfficialGuardError("invalid_request", "Unsupported guard action")
        if payload.get("cloudConfirmed") is not True:
            raise OfficialGuardError("app_cloud_confirmation_required",
                "Explicit official sync requires APP cloud confirmation")
        operation_id = str(payload.get("operationId") or "").strip()
        if not operation_id or len(operation_id) > 128:
            raise OfficialGuardError("invalid_request", "operationId is required")
        version = payload.get("bindingVersion")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise OfficialGuardError("invalid_request", "bindingVersion must be a positive integer")
        with self._router_barrier(router):
            binding = self.binding(router)
            if version != binding.get("bindingVersion"):
                raise OfficialGuardError("binding_version_mismatch", "APP bindingVersion does not match local binding")
            generation = int(binding.get("authGeneration") or 0)
            macs = {mac_key(m) for m in payload.get("macs", [])}
            if not macs:
                raise OfficialGuardError("invalid_request", "Device MAC is required")
            if action == "add_device" and len(macs) != 1:
                raise OfficialGuardError("invalid_request", "Add one device MAC at a time")
            official_uids = payload.get("officialUids")
            if official_uids is None:
                official_uids = [payload.get("officialUid") or payload.get("targetUid") or payload.get("uid")]
            if not isinstance(official_uids, list) or not official_uids:
                raise OfficialGuardError("invalid_request", "Official UID is required")
            uids = list(dict.fromkeys(member_uid({"uid": value}) for value in official_uids))
            if action == "add_device" and len(uids) != 1:
                raise OfficialGuardError("invalid_request", "Add requires exactly one official UID")
            with self.lock:
                for op in self.ops.values():
                    if op.get("routerKey") == router_alias(router) and op.get("operationId") == operation_id:
                        if (op["action"] != action or op["macs"] != sorted(macs)
                                or op.get("officialUids") != uids):
                            raise OfficialGuardError("invalid_request", "operationId was reused with different intent")
                        return self.status(op["id"])
                for op in reversed(list(self.ops.values())):
                    if op["routerKey"] == router_alias(router) and set(op["macs"]) == macs and op["state"] == "pending":
                        if op["action"] == action:
                            return self.status(op["id"])
                        break
                command_id = secrets.token_hex(12)
                self.ops[command_id] = {"id": command_id, "router": router, "routerKey": router_alias(router),
                    "protocol": "app-confirmed-native-v1", "operationId": operation_id,
                    "action": action, "payload": copy.deepcopy(payload),
                    "macs": sorted(macs), "officialUid": uids[0], "officialUids": uids,
                    "bindingVersion": version, "cloudConfirmed": True,
                    "authGeneration": generation, "sequence": time.time_ns(), "state": "pending", "phase": "router",
                    "createdAt": time.time(), "nextAt": 0, "attempts": 0, "native": {}}
                atomic_json(self.ops_path, self.ops)
        self.start()
        return self.status(command_id)

    def _update(self, cid: str, *, expected_generation: int | None = None, **fields):
        with self.lock:
            row = self.ops[cid]
            if (expected_generation is not None and
                    (row.get("state") != "pending" or int(row.get("authGeneration") or 0) != expected_generation)):
                raise OfficialGuardError("official_logged_out", "官方账号授权已变化，旧守护操作已停止")
            row.update(fields, updatedAt=time.time())
            atomic_json(self.ops_path, self.ops)

    def _operation_binding(self, command_id: str, generation: int) -> dict:
        with self.lock:
            row = self.ops.get(command_id)
            if (not row or row.get("state") != "pending" or row.get("authInvalidated")
                    or int(row.get("authGeneration") or 0) != generation):
                raise OfficialGuardError("official_logged_out", "官方账号已退出，旧守护操作已停止")
            encrypted = self.auth.get(row["routerKey"])
            if not encrypted:
                raise OfficialGuardError("official_auth_required", "官方账号授权已失效，请重新授权")
            binding = json.loads(decrypt_secret_with_migration(encrypted)[0])
            if (int(binding.get("authGeneration") or 0) != generation
                    or int(self.generations.get(row["routerKey"]) or generation) != generation):
                row.update(state="superseded", errorCode="official_auth_changed",
                           error="官方账号授权已变化，旧守护操作已停止")
                atomic_json(self.ops_path, self.ops)
                raise OfficialGuardError("official_auth_changed", "官方账号授权已变化，旧守护操作已停止")
        serial = normalize_serial(self.identity(row["router"]))
        if not serial or normalize_serial(binding.get("serial")) != serial:
            raise OfficialGuardError("official_router_mismatch", "当前路由器与官方授权不匹配，未执行更改")
        expiry = self._binding_expiry(binding)
        if expiry <= int(time.time() * 1000):
            raise OfficialGuardError("official_token_expired", "官方账号授权已过期，请刷新授权")
        return binding

    def _native(self, op: dict, key: str, action: str, payload: dict) -> dict:
        generation = int(op.get("authGeneration") or 0)
        self._operation_binding(op["id"], generation)  # Recheck after every blocking cloud call.
        cid = op["id"]
        with self.lock:
            command_id = self.ops[cid]["native"].get(key)
        if not command_id:
            # Serialize the generation check and enqueue with logout. A native
            # command can therefore never be queued after logout has returned.
            with self._router_barrier(op["router"]):
                with self.lock:
                    self._operation_binding(cid, generation)
                    command = self.commands.enqueue(op["router"], action, {**payload, "router": op["router"]})
                    command_id = command["id"]
                    self.ops[cid]["native"][key] = command_id
                    atomic_json(self.ops_path, self.ops)
            self.notify()
        row = self.commands.record(command_id)
        self._operation_binding(cid, generation)
        if not row or row.get("status") not in {"done", "failed"}:
            raise OfficialGuardError("router_confirmation_pending", "官方名单已更新，正在确认路由器执行结果", retryable=True)
        if row["status"] == "failed":
            self._update(cid, expected_generation=generation, native={})
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
            op = copy.deepcopy(self.ops.get(command_id) or {})
        if op.get("state") != "pending":
            return
        with self._router_barrier(op["router"]):
            with self.lock:
                current = self.ops.get(command_id) or {}
            if current.get("state") == "pending":
                self._process_locked(command_id)

    def _process_locked(self, command_id: str):
        with self.lock:
            op = copy.deepcopy(self.ops[command_id])
        if op["state"] != "pending":
            return
        if op.get("cloudConfirmed") is not True:
            raise OfficialGuardError("app_cloud_confirmation_required", "APP cloud confirmation is required")
        generation = int(op.get("authGeneration") or 0)
        binding = self._operation_binding(command_id, generation)
        if op.get("bindingVersion") != binding.get("bindingVersion"):
            raise OfficialGuardError("binding_version_mismatch", "Binding version changed before dispatch")

        def guard():
            self._operation_binding(command_id, generation)

        def update(**fields):
            self._update(command_id, expected_generation=generation, **fields)

        # No OfficialGuardClient exists on this path: APP has already confirmed
        # the cloud mutation. Only native read/enqueue/readback is performed here.
        macs = set(op["macs"])
        added = op["action"] == "add_device"
        uid = member_uid({"uid": op.get("officialUid")})
        rows = self._members_native(op, "before")
        matches = matching_members(rows, macs)
        if added:
            duplicates = [r for r in matches if member_uid(r) != uid]
            if any(int(r.get("planCount") or 0) > 0 or r.get("blocked") or r.get("paused") for r in duplicates):
                raise OfficialGuardError("official_local_plan_conflict",
                    "Legacy native plan is preserved; merge it in APP first")
            for row in duplicates:
                old = member_uid(row)
                self._native(op, "remove-duplicate-" + old, "remove_device", {"uid": old})
            self._native(op, "add", "add_device", {
                "macs": [":".join(m[i:i+2] for i in range(0, 12, 2)).lower() for m in op["macs"]],
                "deviceName": op["payload"].get("deviceName"), "officialUid": uid})
        else:
            targets = set(op.get("officialUids") or [uid])
            if any(target != uid for target in targets if target != op["payload"].get("uid")):
                # Multiple UIDs are intentionally removed only when their MACs
                # were observed natively; an unrelated UID is never deleted.
                pass
            for row in matches:
                target = member_uid(row)
                if target not in targets:
                    raise OfficialGuardError("official_member_mismatch",
                        "Native UID differs from APP-confirmed removal target")
                self._native(op, "remove-" + target, "remove_device", {"uid": target})
        latest = self._members_native(op, "after")
        matches = matching_members(latest, macs)
        native_ok = len(matches) == 1 and member_uid(matches[0]) == uid if added else not matches
        if not native_ok:
            update(native={})
            raise OfficialGuardError("router_confirmation_pending",
                "Native membership has not reached the APP-confirmed state", retryable=True)
        guard()
        with self.lock:
            after_id = self.ops[command_id]["native"]["after"]
        after_result = (self.commands.record(after_id) or {}).get("result", {})
        result = {"uid": uid, "macs": [":".join(m[i:i+2] for i in range(0, 12, 2)).lower() for m in op["macs"]],
                  "name": op["payload"].get("deviceName"),
                  "membershipVersion": int(after_result.get("membershipVersion") or 0)}
        if not added:
            result["removedUids"] = list({str(op["payload"].get("uid") or uid), *op.get("officialUids", [])})
        update(state="done", phase="confirmed", result=result, error="", errorCode="")

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
                if op["routerKey"] != key or op["state"] != "done" or op.get("authInvalidated") or any(latest[m] != op["id"] for m in op["macs"]):
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
                    if error.code in {"official_logged_out", "official_auth_changed"}:
                        continue
                    attempts = int(row.get("attempts") or 0) + 1
                    try:
                        self._update(row["id"], expected_generation=int(row.get("authGeneration") or 0),
                            state="pending" if error.retryable else "failed",
                            errorCode=error.code, error=str(error), attempts=attempts,
                            nextAt=time.time() + (1 if error.code == "router_confirmation_pending" else min(30, 2 ** min(attempts, 5))))
                    except OfficialGuardError:
                        continue
                except Exception:
                    # Never log a token, a raw response, a password or exception args.
                    try:
                        self._update(row["id"], expected_generation=int(row.get("authGeneration") or 0),
                            state="failed", errorCode="official_sync_failed",
                            error="守护同步遇到异常，请重新核对官方授权")
                    except OfficialGuardError:
                        continue
