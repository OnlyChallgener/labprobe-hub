"""Optional multi-router gateway for isolated single-router Hub workers.

The existing Hub entry point remains unchanged.  This process starts one Hub
per explicit router ID and uses nginx for HTTP, SSE and WebSocket forwarding.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hmac
import json
import os
import re
import socket
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import parse_qs, urlsplit

import yaml


ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
TOPIC_PATTERN = re.compile(r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$")
PLACEHOLDERS = {"", "change-app-token", "change-hook-token", "replace-me", "changeme"}

# /health is not a trivial liveness stub: it counts revisions and reports database state, so
# a loaded worker on the 200MB+ library measured up to 1.14s. The old shared 0.35s budget
# reported healthy workers as offline and even 1.0s flapped. Probes run in parallel, so the
# list's latency is the maximum, not the sum. A cold worker that is still booting refuses the
# connection outright (measured ~9s for the small library, ~18s for the 200MB one) - that is
# correctly reported as offline, not something a longer timeout can fix.
PROBE_HTTP_TIMEOUT_SEC = 2.5
PROBE_TCP_TIMEOUT_SEC = 0.35
OFFICIAL_ACCOUNT_PATH = "/api/official-account"
OFFICIAL_WORKER_TIMEOUT_SEC = 45

# The front door renders each worker's APP secret into the nginx configuration.
# A secret that could carry a quote, a backslash, a variable marker or whitespace
# would let the value end its own string and add directives, so it is refused
# before anything is rendered rather than escaped afterwards.
UNSAFE_SECRET = re.compile(r'["\\`$\r\n\t ]')


def _port(value: object, label: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a TCP port") from exc
    if not 1 <= result <= 65535:
        raise ValueError(f"{label} must be between 1 and 65535")
    return result


def load_gateway_config(path: str | Path, environ: dict[str, str] | None = None) -> dict:
    env = os.environ if environ is None else environ
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise ValueError("multi-router config must have version: 1")
    gateway = raw.get("gateway")
    entries = raw.get("routers")
    if not isinstance(gateway, dict) or not isinstance(entries, list) or not entries:
        raise ValueError("gateway and a nonempty routers list are required")
    listen_port = _port(gateway.get("listenPort", 58443), "gateway.listenPort")
    registry_port = _port(gateway.get("registryPort", 58444), "gateway.registryPort")
    storage_root_raw = gateway.get("storageRoot")
    if not isinstance(storage_root_raw, str) or not Path(storage_root_raw).is_absolute():
        raise ValueError("gateway.storageRoot must be an absolute directory")
    storage_root = Path(storage_root_raw).resolve()
    public_base = str(gateway.get("publicBaseUrl") or "").strip().rstrip("/")
    if not re.fullmatch(r"https?://[^/\s]+", public_base):
        raise ValueError("gateway.publicBaseUrl must be an http(s) origin without a path")
    default_id = str(gateway.get("defaultRouterId") or "").strip()
    if not ID_PATTERN.fullmatch(default_id):
        raise ValueError("gateway.defaultRouterId must be a stable router ID")
    routers = []
    ids: set[str] = set()
    ports = {listen_port, registry_port}
    roots: set[Path] = set()
    topics: set[str] = set()
    eweb_urls: set[tuple[str, str, int]] = set()
    used_secrets: set[str] = set()
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            raise ValueError(f"routers[{index}] must be an object")
        router_id = str(item.get("routerId") or "").strip()
        if not ID_PATTERN.fullmatch(router_id) or router_id in ids:
            raise ValueError(f"routers[{index}].routerId is missing, invalid or duplicated")
        ids.add(router_id)
        worker_port = _port(item.get("workerPort"), f"routers[{index}].workerPort")
        if worker_port in ports:
            raise ValueError("gateway, registry and worker ports must be unique")
        ports.add(worker_port)
        root = (storage_root / router_id).resolve()
        if root.parent != storage_root or root in roots:
            raise ValueError("worker storage must be a unique direct child of storageRoot")
        roots.add(root)
        platform = str(item.get("platform") or "").strip().lower()
        if platform != "reyee":
            raise ValueError(f"routers[{index}].platform must be reyee")
        eweb_url = str(item.get("ewebUrl") or "").strip()
        try:
            parsed_eweb = urlsplit(eweb_url)
            parsed_port = parsed_eweb.port
            eweb_port = _port(parsed_port if parsed_port is not None else
                              (443 if parsed_eweb.scheme == "https" else 80),
                              f"routers[{index}].ewebUrl port")
        except ValueError as exc:
            raise ValueError(f"routers[{index}].ewebUrl has an invalid port or host") from exc
        if (parsed_eweb.scheme not in {"http", "https"} or not parsed_eweb.hostname
                or parsed_eweb.username or parsed_eweb.password or parsed_eweb.path not in {"", "/"}
                or parsed_eweb.query or parsed_eweb.fragment):
            raise ValueError(f"routers[{index}].ewebUrl must be an http(s) origin")
        transport = str(item.get("ewebTransport") or "direct").strip().lower()
        if transport not in {"direct", "local_tunnel"}:
            raise ValueError(f"routers[{index}].ewebTransport must be direct or local_tunnel")
        if transport == "local_tunnel" and (
                parsed_eweb.hostname not in {"127.0.0.1", "localhost", "::1"}
                or parsed_port is None):
            raise ValueError("local_tunnel requires a loopback eWeb URL with an explicit port")
        canonical_host = "127.0.0.1" if parsed_eweb.hostname == "localhost" else parsed_eweb.hostname.lower()
        canonical_eweb = (parsed_eweb.scheme, canonical_host, eweb_port)
        if canonical_eweb in eweb_urls:
            raise ValueError("two Reyee workers cannot share one eWeb endpoint without separate network namespaces")
        eweb_urls.add(canonical_eweb)
        topic = str(item.get("mqttTopicPrefix") or f"labprobe/hub/routers/{router_id}").strip()
        if not TOPIC_PATTERN.fullmatch(topic) or topic in topics:
            raise ValueError("MQTT topic prefixes must be unique and contain only literal segments")
        topics.add(topic)
        app_env = str(item.get("appTokenEnv") or "").strip()
        hook_env = str(item.get("hookTokenEnv") or "").strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", app_env) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", hook_env):
            raise ValueError("each worker needs appTokenEnv and hookTokenEnv")
        app_token = str(env.get(app_env) or "").strip()
        hook_token = str(env.get(hook_env) or "").strip()
        if (app_token.lower() in PLACEHOLDERS or hook_token.lower() in PLACEHOLDERS
                or len(app_token) < 24 or len(hook_token) < 24):
            raise ValueError(f"{router_id}: set strong APP and HOOK secrets in the environment")
        if app_token in used_secrets or hook_token in used_secrets or app_token == hook_token:
            raise ValueError("every APP and HOOK secret must be unique across workers")
        for field, value in (("appTokenEnv", app_token), ("hookTokenEnv", hook_token)):
            if UNSAFE_SECRET.search(value):
                raise ValueError(f"{router_id}: {field} contains a character that cannot be rendered into nginx")
        used_secrets.update((app_token, hook_token))
        optional_secrets = {}
        for field in ("ewebPasswordEnv", "routerConfigKeyEnv"):
            env_name = str(item.get(field) or "").strip()
            if env_name and not re.fullmatch(r"[A-Z][A-Z0-9_]*", env_name):
                raise ValueError(f"routers[{index}].{field} must name an environment variable")
            if env_name:
                value = str(env.get(env_name) or "")
                if not value:
                    raise ValueError(f"{router_id}: {field} is set but {env_name} is empty")
                optional_secrets[field] = value
        routers.append({
            "routerId": router_id,
            "name": str(item.get("name") or router_id).strip(),
            "site": str(item.get("site") or "").strip(),
            "model": str(item.get("model") or "").strip(),
            "platform": platform,
            "workerPort": worker_port,
            "root": root,
            "mqttTopicPrefix": topic,
            "ewebUrl": eweb_url,
            "ewebHost": parsed_eweb.hostname,
            "ewebPort": eweb_port,
            "ewebTransport": transport,
            "appToken": app_token,
            "hookToken": hook_token,
            "secretEnvNames": tuple(name for name in (
                app_env, hook_env,
                str(item.get("ewebPasswordEnv") or "").strip(),
                str(item.get("routerConfigKeyEnv") or "").strip(),
            ) if name),
            **optional_secrets,
        })
    if default_id not in ids:
        raise ValueError("defaultRouterId must match a routerId in routers")
    return {
        "listenPort": listen_port,
        "registryPort": registry_port,
        "storageRoot": storage_root,
        "publicBaseUrl": public_base,
        "defaultRouterId": default_id,
        "routers": routers,
    }


def worker_environment(router: dict, config: dict, parent_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if parent_env is None else parent_env)
    # A worker must receive only its own secrets. The gateway still owns every
    # *_TOKEN variable from the env file, but none of those named variables
    # should survive in a child process after mapping to APP_TOKEN/HOOK_TOKEN.
    secret_names = {
        name for entry in config["routers"] for name in entry["secretEnvNames"]
    }
    for key in list(env):
        if (key.startswith("ROUTER_") or
                key in {"APP_TOKEN_PREVIOUS", "HOOK_TOKEN_PREVIOUS"} or
                key in secret_names):
            env.pop(key, None)
    root = router["root"]
    env.update({
        "LABPROBE_BASE_DIR": str(root),
        "CONFIG_DIR": str(root / "config"),
        "DATA_DIR": str(root / "data"),
        "LUCKY_STORAGE_DIR": str(root.parent / "lucky"),
        "BACKUPS_DIR": str(root / "backups"),
        "LOGS_DIR": str(root / "logs"),
        "CONFIG_PATH": str(root / "config" / "config.yaml"),
        "DATABASE_PATH": str(root / "data" / "labprobe.db"),
        "PORT": str(router["workerPort"]),
        "HUB_BIND_HOST": "127.0.0.1",
        "APP_TOKEN": router["appToken"],
        "HOOK_TOKEN": router["hookToken"],
        "STRICT_TOKEN_SEPARATION": "1",
        "MULTI_ROUTER_LOCK_EWEB": "1",
        "MQTT_TOPIC_PREFIX": router["mqttTopicPrefix"],
        "ROUTER_ID": router["routerId"],
        "ROUTER_PLATFORM": router["platform"],
        "PRIMARY_ROUTER_NAME": router["name"],
        "HUB_NAME": router["name"],
        "HUB_ADVERTISE_URL": f"{config['publicBaseUrl']}/r/{router['routerId']}",
    })
    env["ROUTER_EWEB_URL"] = router["ewebUrl"]
    env["ROUTER_HOST"] = router["ewebUrl"]
    env["ROUTER_RPC_PRIMARY"] = "true"
    if router.get("ewebPasswordEnv"):
        env["ROUTER_EWEB_PASSWORD"] = router["ewebPasswordEnv"]
    if router.get("routerConfigKeyEnv"):
        env["ROUTER_CONFIG_KEY"] = router["routerConfigKeyEnv"]
    return env


def render_nginx_config(config: dict, pid_path: Path) -> str:
    lines = [
        "worker_processes 1;",
        f"pid {pid_path};",
        "events { worker_connections 1024; }",
        "http {",
        '  log_format labprobe_without_query \'$remote_addr - $remote_user [$time_local] "$request_method $uri $server_protocol" $status $body_bytes_sent\';',
        "  map $http_upgrade $connection_upgrade { default upgrade; '' close; }",
    ]
    # A relay presents its own HOOK credential and the worker must keep seeing it as
    # such; a management credential is rewritten into that worker's APP secret. The
    # gate reports which one opened the channel, and nginx decides per router from it.
    for router in config["routers"]:
        slug = "labprobe_" + router["routerId"].replace("-", "_")
        lines.extend([
            f"  map ${slug}_kind ${slug}_authorization {{",
            '    "device" $http_authorization;',
            f'    default "Bearer {router["appToken"]}";',
            "  }",
            f"  map ${slug}_kind ${slug}_token {{",
            '    "device" $labprobe_device_token;',
            f'    default "{router["appToken"]}";',
            "  }",
        ])
    # Relays keep pushing at the root path because that is where their Hub used to live.
    # A HOOK key names exactly one router, so /_routeauth can resolve it and the root can
    # forward the request there; management keys resolve to nothing and stay refused.
    lines.extend(["  map $labprobe_route $labprobe_root_worker {"])
    for router in config["routers"]:
        lines.append(f"    {router['routerId']} http://127.0.0.1:{router['workerPort']};")
    lines.extend([
        '    default "";',
        "  }",
    ])
    lines.extend([
        "  access_log /dev/stdout labprobe_without_query;",
        "  error_log /dev/stderr warn;",
        "  server {",
        f"    listen {config['listenPort']};",
        "    client_max_body_size 200m;",
        "    proxy_http_version 1.1;",
        "    proxy_set_header Host $http_host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto $scheme;",
        "    proxy_set_header Upgrade $http_upgrade;",
        "    proxy_set_header Connection $connection_upgrade;",
        "    proxy_read_timeout 600s;",
        "    proxy_send_timeout 600s;",
        "    proxy_buffering off;",
        "    proxy_request_buffering off;",
        f"    location = /api/routers {{ proxy_pass http://127.0.0.1:{config['registryPort']}/api/routers; }}",
        f"    location = /api/routers/default {{ proxy_pass http://127.0.0.1:{config['registryPort']}/api/routers/default; }}",
        f"    location = {OFFICIAL_ACCOUNT_PATH} {{ proxy_pass http://127.0.0.1:{config['registryPort']}{OFFICIAL_ACCOUNT_PATH}; }}",
        "    location ^~ /_gateauth/ {",
        "      internal;",
        f"      proxy_pass http://127.0.0.1:{config['registryPort']};",
        "      proxy_pass_request_body off;",
        '      proxy_set_header Content-Length "";',
        "      proxy_set_header Authorization $http_authorization;",
        "      proxy_set_header X-LabProbe-Token $http_x_labprobe_token;",
        "      proxy_set_header X-LabProbe-Original-Args $args;",
        "      proxy_set_header X-LabProbe-Original-URI $request_uri;",
        "    }",
        "    location = /_routeauth {",
        "      internal;",
        f"      proxy_pass http://127.0.0.1:{config['registryPort']}/_routeauth;",
        "      proxy_pass_request_body off;",
        '      proxy_set_header Content-Length "";',
        "      proxy_set_header Authorization $http_authorization;",
        "      proxy_set_header X-LabProbe-Token $http_x_labprobe_token;",
        "      proxy_set_header X-LabProbe-Original-Args $args;",
        "      proxy_set_header X-LabProbe-Original-URI $request_uri;",
        "    }",
        "    location @denied {",
        '      default_type application/json;',
        "      return 401 '{\"ok\": false, \"error\": \"未授权\"}';",
        "    }",
    ])
    for router in config["routers"]:
        router_id = router["routerId"]
        port = router["workerPort"]
        slug = "labprobe_" + router_id.replace("-", "_")
        # Both header names are replaced because the realtime WebSocket presents both,
        # and each worker only ever sees its own credential.
        lines.extend([
            f"    location = /r/{router_id} {{ return 308 /r/{router_id}/; }}",
            f"    location ^~ /r/{router_id}/ {{",
            f"      auth_request /_gateauth/{router_id};",
            f"      auth_request_set ${slug}_kind $upstream_http_x_labprobe_auth_kind;",
            "      auth_request_set $labprobe_device_token $upstream_http_x_labprobe_token;",
            "      error_page 401 = @denied;",
            f"      proxy_pass http://127.0.0.1:{port}/;",
            # nginx inherits proxy_set_header only when the current level declares none,
            # so rewriting the credential here would silently drop the WebSocket upgrade
            # and every forwarding header. They are restated inside the location.
            "      proxy_set_header Host $http_host;",
            "      proxy_set_header X-Real-IP $remote_addr;",
            "      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "      proxy_set_header X-Forwarded-Proto $scheme;",
            "      proxy_set_header Upgrade $http_upgrade;",
            "      proxy_set_header Connection $connection_upgrade;",
            f"      proxy_set_header Authorization ${slug}_authorization;",
            f"      proxy_set_header X-LabProbe-Token ${slug}_token;",
            "    }",
        ])
    lines.append("    location ^~ /r/ { return 404; }")
    default = next(r for r in config["routers"] if r["routerId"] == config["defaultRouterId"])
    # A root-path call carrying an owner key still cannot say which router the caller
    # meant, so it stays refused: silently forwarding it to the default worker would show
    # the caller another router's data while it believes it selected its own. A HOOK key
    # is different - it names exactly one router - so those root calls (the relays) are
    # resolved by /_routeauth and forwarded with the credential untouched, letting each
    # worker keep enforcing its own HOOK. The exact locations above still win, so the
    # registry and the internal gates keep working, and /health stays open.
    lines.extend([
        "    location ^~ /api/ {",
        "      auth_request /_routeauth;",
        # $upstream_http_* from an auth subrequest is only readable once copied out with
        # auth_request_set; reading it straight from the map evaluated to "" and nginx
        # answered 500 "invalid URL prefix" for every relay push at the root path.
        "      auth_request_set $labprobe_route $upstream_http_x_labprobe_route;",
        "      auth_request_set $labprobe_device_token $upstream_http_x_labprobe_token;",
        "      error_page 401 = @root_refused;",
        "      proxy_pass $labprobe_root_worker;",
        # Declaring any proxy_set_header here drops the server-level ones, so the
        # WebSocket upgrade and forwarding headers are restated - same trap as /r/<id>/.
        "      proxy_set_header Host $http_host;",
        "      proxy_set_header X-Real-IP $remote_addr;",
        "      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "      proxy_set_header X-Forwarded-Proto $scheme;",
        "      proxy_set_header Upgrade $http_upgrade;",
        "      proxy_set_header Connection $connection_upgrade;",
        "      proxy_set_header X-LabProbe-Token $labprobe_device_token;",
        "    }",
        "    location @root_refused {",
        "      default_type application/json;",
        "      return 400 '{\"ok\": false, \"error\": \"multi_router_path_required\"}';",
        "    }",
        f"    location / {{ proxy_pass http://127.0.0.1:{default['workerPort']}; }}",
        "  }",
        "}",
        "",
    ])
    return "\n".join(lines)


def _device_counts(router: dict) -> dict:
    # The worker's own endpoint uses the same device/archive calculation as its
    # Devices page. A local file is only a fallback while a worker starts.
    result = {}
    try:
        request = Request(
            f"http://127.0.0.1:{router['workerPort']}/api/routers",
            headers={"Authorization": f"Bearer {router['appToken']}"},
        )
        with urlopen(request, timeout=PROBE_HTTP_TIMEOUT_SEC) as response:
            payload = json.loads(response.read())
        row = payload["routers"][0]
        serial = row.get("serialNumber")
        if isinstance(serial, str) and re.fullmatch(r"[A-Za-z0-9_-]{4,64}", serial.strip()):
            result["serialNumber"] = serial.strip().upper()
        for key in ("deviceCount", "onlineDeviceCount"):
            value = row.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                result[key] = value
    except (OSError, URLError, TimeoutError, AttributeError, ValueError, TypeError, KeyError, IndexError):
        pass
    if all(key in result for key in ("deviceCount", "onlineDeviceCount")):
        return result
    try:
        payload = json.loads((router["root"] / "data" / "devices.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return result
    if not isinstance(payload, dict):
        return result
    for source, target in (("total", "deviceCount"), ("onlineDeviceCount", "onlineDeviceCount")):
        value = payload.get(source)
        if target not in result and isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            result[target] = value
    if "onlineDeviceCount" not in result and isinstance(payload.get("online"), list):
        result["onlineDeviceCount"] = len(payload["online"])
    if "deviceCount" not in result and "onlineDeviceCount" in result:
        result["deviceCount"] = result["onlineDeviceCount"]
    return result


def eweb_reachable(router: dict) -> bool:
    try:
        with socket.create_connection((router["ewebHost"], router["ewebPort"]), timeout=PROBE_TCP_TIMEOUT_SEC):
            return True
    except (OSError, TimeoutError):
        return False


def _router_row(router: dict) -> dict:
    try:
        with urlopen(f"http://127.0.0.1:{router['workerPort']}/health", timeout=PROBE_HTTP_TIMEOUT_SEC) as response:
            hub_online = response.status == 200
    except (OSError, URLError, TimeoutError):
        hub_online = False
    route_online = eweb_reachable(router)
    row = {
        "routerId": router["routerId"],
        "name": router["name"],
        "site": router["site"],
        "model": router["model"],
        "platform": router["platform"],
        "online": hub_online and route_online,
        "hubOnline": hub_online,
        "ewebReachable": route_online,
        "basePath": f"/r/{router['routerId']}",
    }
    row.update(_device_counts(router))
    return row


def router_list(config: dict) -> dict:
    # Bound total registry latency even if one or more workers are unhealthy.
    with ThreadPoolExecutor(max_workers=min(16, len(config["routers"]))) as pool:
        rows = list(pool.map(_router_row, config["routers"]))
    return {"ok": True, "defaultRouterId": config["defaultRouterId"], "routers": rows}


class DefaultRouterController:
    """Persist the default pointer without changing worker identities or data."""

    def __init__(self, config: dict, state_path: Path, apply_route=None):
        self.config = config
        self.state_path = state_path
        self.apply_route = apply_route or (lambda _config: None)
        self.lock = threading.RLock()
        known = {router["routerId"] for router in config["routers"]}
        try:
            saved = json.loads(state_path.read_text(encoding="utf-8"))["defaultRouterId"]
        except (OSError, ValueError, KeyError, TypeError):
            saved = None
        self.current_id = saved if saved in known else config["defaultRouterId"]

    def view(self) -> dict:
        with self.lock:
            return {**self.config, "defaultRouterId": self.current_id}

    def set_default(self, router_id: str) -> str:
        known = {router["routerId"] for router in self.config["routers"]}
        if router_id not in known:
            raise ValueError("routerId is not registered")
        with self.lock:
            if router_id == self.current_id:
                return router_id
            previous = self.current_id
            self.apply_route({**self.config, "defaultRouterId": router_id})
            try:
                self.state_path.parent.mkdir(parents=True, exist_ok=True)
                temporary = self.state_path.with_suffix(".tmp")
                temporary.write_text(json.dumps({"defaultRouterId": router_id}), encoding="utf-8")
                temporary.replace(self.state_path)
            except OSError:
                self.apply_route({**self.config, "defaultRouterId": previous})
                raise
            self.current_id = router_id
            return router_id


def _mask_official_account(value: object) -> str:
    account = str(value or "").strip()
    if not account:
        return ""
    if "@" in account:
        local, domain = account.rsplit("@", 1)
        return (local[:1] or "*") + "***@" + domain
    if len(account) >= 7:
        return account[:3] + "****" + account[-4:]
    return account[:1] + "***"


def _official_error_text(code: object) -> str:
    return {
        "worker_offline": "HUB 工作节点离线",
        "router_serial_unknown": "尚未确认路由器真实序列号",
        "official_auth_required": "官方账号授权已失效",
        "official_token_expired": "官方账号授权已过期，请刷新",
        "official_router_mismatch": "官方网络未唯一匹配当前路由器",
        "official_logout_failed": "本地授权已清除，但官方退出未确认",
        "official_logout_pending": "本地授权已清除，但退出操作仍待确认",
        "worker_timeout": "工作节点响应超时，退出操作可能仍在执行",
        "official_connection_pending": "官方服务结果尚待确认",
        "official_unavailable": "官方服务暂时不可用",
        "official_request_rejected": "官方服务未接受此次操作",
        "official_response_invalid": "官方服务响应异常",
        "official_sync_failed": "同步失败，请重新核对",
    }.get(str(code or ""), "官方账号同步未完成")


def _worker_official_call(router: dict, method: str, body: dict | None = None) -> tuple[bool, dict]:
    """Call one loopback worker; return reachability and a non-secret payload."""
    url = f"http://127.0.0.1:{router['workerPort']}{OFFICIAL_ACCOUNT_PATH}"
    if method == "GET":
        url += "?verify=1"
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    headers = {"Authorization": f"Bearer {router['appToken']}", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=OFFICIAL_WORKER_TIMEOUT_SEC) as response:
            raw = response.read(65536)
    except HTTPError as error:
        try:
            value = json.loads(error.read(65536))
        except Exception:
            value = {}
        return True, value if isinstance(value, dict) else {"ok": False, "errorCode": "official_request_rejected"}
    except (TimeoutError, socket.timeout):
        # A timed-out DELETE may still be revoking cloud auth or waiting for an
        # already-delivered native command. Never describe it as stopped.
        return True, {"ok": False, "errorCode": "worker_timeout",
                      "operationState": "pending_unknown", "retrySafe": False}
    except URLError as error:
        if isinstance(error.reason, (TimeoutError, socket.timeout)):
            return True, {"ok": False, "errorCode": "worker_timeout",
                          "operationState": "pending_unknown", "retrySafe": False}
        return False, {"ok": False, "errorCode": "worker_offline"}
    except (OSError, ValueError):
        return False, {"ok": False, "errorCode": "worker_offline"}
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return True, {"ok": False, "errorCode": "official_response_invalid"}
    return True, value if isinstance(value, dict) else {"ok": False, "errorCode": "official_response_invalid"}


def aggregate_official_account(config: dict, method: str, body: dict | None = None) -> dict:
    """Fan out concurrently and expose only the stable global status contract."""
    body = body or None
    with ThreadPoolExecutor(max_workers=max(1, len(config["routers"])),
                            thread_name_prefix="official-account") as pool:
        replies = list(pool.map(lambda router: _worker_official_call(router, method, body), config["routers"]))

    rows = []
    accounts = []
    fingerprints = set()
    for router, (online, value) in zip(config["routers"], replies):
        serial = str(value.get("serial") or "").strip().upper()
        account = str(value.get("account") or "")
        fingerprint = str(value.get("accountFingerprint") or account or "")
        if account:
            accounts.append(account)
        if fingerprint:
            fingerprints.add(fingerprint)
        authorized = bool(online and value.get("authorized") and serial)
        matched = bool(authorized and value.get("cloudVerified") and value.get("routerVerified")
                       and value.get("projectId"))
        code = str(value.get("errorCode") or "")
        logout_fields = {}
        if method == "DELETE":
            local_cleared = (bool(value.get("localCleared"))
                             if online and "localCleared" in value else
                             not bool(value.get("authorized"))
                             if online and value.get("ok") is True and "authorized" in value else None)
            if not online:
                remote, operation = "unknown", "pending_unknown" if code == "worker_timeout" else "unknown"
                sync_state, error_code = ("failed" if code == "worker_timeout" else "offline"), code or "worker_offline"
            elif value.get("ok") is False:
                pending = code in {"worker_timeout", "official_logout_pending",
                                   "official_connection_pending", "official_unavailable"}
                remote, operation = ("unknown" if pending else "failed"), ("pending_unknown" if pending else "failed")
                sync_state, error_code = ("checking" if pending else "failed"), code or "official_logout_failed"
            elif local_cleared is False:
                remote, operation = "failed", "failed"
                sync_state, error_code = "failed", code or "official_logout_failed"
            elif code:
                pending = code in {"worker_timeout", "official_logout_pending",
                                   "official_connection_pending", "official_unavailable"}
                remote, operation = ("unknown" if pending else "failed"), ("pending_unknown" if pending else "failed")
                sync_state, error_code = ("checking" if pending else "failed"), code
            elif local_cleared is True:
                remote, operation = "confirmed", "complete"
                sync_state, error_code = "unauthorized", ""
            else:
                remote, operation = "unknown", "unknown"
                sync_state, error_code = "failed", "official_logout_failed"
            logout_fields = {"localCleared": local_cleared, "remoteRevocation": remote,
                             "operationState": operation, "retrySafe": remote == "confirmed"}
        elif not online:
            sync_state, error_code = "offline", "worker_offline"
        elif not serial:
            sync_state, error_code = "offline", "router_serial_unknown"
        elif value.get("ok") is False or not authorized:
            if code in {"official_auth_required", "official_token_expired"}:
                sync_state = "unauthorized"
            elif code in {"official_connection_pending", "official_unavailable"}:
                sync_state = "checking"
            else:
                sync_state = "failed"
            error_code = code or "official_sync_failed"
        elif not value.get("cloudVerified"):
            sync_state, error_code = "checking", code or "official_connection_pending"
        elif not value.get("routerVerified") or not value.get("projectId"):
            sync_state, error_code = "failed", code or "official_router_mismatch"
        else:
            sync_state, error_code = "synced", ""
        row = {"routerId": router["routerId"], "name": router["name"], "site": router["site"],
               "model": router["model"], "serialNumber": serial, "online": bool(online and serial),
               "authorized": authorized, "matched": matched,
               "projectId": str(value.get("projectId") or ""),
               "projectName": str(value.get("projectName") or ""), "syncState": sync_state,
               **logout_fields}
        if error_code:
            row["errorCode"] = error_code
            row["error"] = _official_error_text(error_code)
        rows.append(row)

    project_ids = {row["projectId"] for row in rows if row["matched"] and row["projectId"]}
    serials = {row["serialNumber"] for row in rows if row["matched"] and row["serialNumber"]}
    expiries = []
    for row, (_, value) in zip(rows, replies):
        if row["matched"] and isinstance(value.get("expireTime"), int):
            expiries.append(value["expireTime"])
    all_synced = bool(rows) and all(row["syncState"] == "synced" for row in rows)
    conflict = len(fingerprints) > 1
    if conflict:
        state = "conflict"
    elif serials:
        state = "authorized" if all_synced else "partial"
    elif any(row["syncState"] in {"offline", "checking", "failed"} for row in rows):
        state = "checking"
    else:
        state = "unauthorized"

    if conflict:
        hub_authorization = "partial"
    elif all_synced:
        hub_authorization = "synced"
    elif serials:
        hub_authorization = "partial"
    elif any(row["syncState"] == "offline" for row in rows):
        hub_authorization = "offline"
    elif any(row["syncState"] in {"failed", "checking"} for row in rows):
        hub_authorization = "failed"
    else:
        hub_authorization = "unauthorized"

    if method == "DELETE":
        confirmed = sum(row["remoteRevocation"] == "confirmed" for row in rows)
        unknown = any(row["remoteRevocation"] == "unknown" for row in rows)
        failed = any(row["remoteRevocation"] == "failed" for row in rows)
        all_confirmed = bool(rows) and confirmed == len(rows)
        local_values = [row["localCleared"] for row in rows]
        local_cleared = (False if any(value is False for value in local_values)
                         else True if all(value is True for value in local_values) else None)
        if all_confirmed:
            logout_state, operation_state, hub_authorization = "unauthorized", "complete", "unauthorized"
        elif unknown:
            logout_state = "partial" if confirmed else "pending_unknown"
            operation_state, hub_authorization = "pending_unknown", "partial" if confirmed else "failed"
        elif confirmed:
            logout_state, operation_state, hub_authorization = "partial", "partial_failure", "partial"
        else:
            logout_state, operation_state, hub_authorization = "failed", "failed", "failed"
        remote = ("confirmed" if all_confirmed else "unknown" if unknown
                  else "partial" if confirmed and failed else "failed")
        return {"ok": all_confirmed,
                "account": accounts[0] if accounts else "",
                "authorized": (True if any(value is False for value in local_values)
                               else False if local_cleared is True else None),
                "localCleared": local_cleared, "remoteRevocation": remote,
                "operationState": operation_state, "retrySafe": all_confirmed,
                "state": logout_state, "projectCount": 0, "matchedRouterCount": 0,
                "hubAuthorization": hub_authorization, "routers": rows,
                "errors": [{"routerId": row["routerId"], "errorCode": row.get("errorCode", "official_logout_failed"),
                            "error": row.get("error", _official_error_text("official_logout_failed")),
                            "operationState": row["operationState"], "retrySafe": row["retrySafe"]}
                           for row in rows if row.get("errorCode")]}

    result = {"ok": True, "account": accounts[0] if accounts else _mask_official_account((body or {}).get("account")),
              "authorized": bool(serials), "state": state, "projectCount": len(project_ids),
              "matchedRouterCount": len(serials), "hubAuthorization": hub_authorization,
              "routers": rows}
    if expiries:
        result["expireTime"] = min(expiries)
    return result


def make_registry_handler(config: dict, controller: DefaultRouterController | None = None) -> type[BaseHTTPRequestHandler]:
    # Every worker's APP secret is an owner-level management credential. One front door only
    # delivers "log in once" if a key the user already holds for any of their routers also
    # opens the rest; making it depend on which row happened to be the initial default turned
    # the merge into a silent "wrong token" wall for everyone who kept the second key.
    # HOOK secrets never gain management rights - they stay device-channel-only.
    management = [router["appToken"].encode("utf-8") for router in config["routers"]]

    class RegistryHandler(BaseHTTPRequestHandler):
        def credential(self, allow_hook_query: bool = False) -> bytes:
            header = self.headers.get("Authorization", "").strip()
            candidate = header[7:].strip() if header.lower().startswith("bearer ") else header
            if not candidate:
                candidate = self.headers.get("X-LabProbe-Token", "").strip()
            if not candidate and allow_hook_query:
                original_args = self.headers.get("X-LabProbe-Original-Args", "").strip()
                original_uri = self.headers.get("X-LabProbe-Original-URI", "").strip()
                query = parse_qs(original_args or urlsplit(original_uri).query or urlsplit(self.path).query,
                    keep_blank_values=True, max_num_fields=32)
                for key in ("token", "hook_token", "hookToken", "key"):
                    candidate = (query.get(key) or [""])[0].strip()
                    if candidate:
                        break
            return candidate.encode("utf-8")

        def authorized(self) -> bool:
            presented = self.credential()
            return any(hmac.compare_digest(presented, secret) for secret in management)

        def gate_kind(self, router: dict) -> str:
            """Which credential opened this channel, or empty when none did.

            A management credential is rewritten into that worker's own APP secret by
            nginx. A device credential is passed through untouched so the worker keeps
            validating it as HOOK - rewriting it would hand the relay App-level access.
            """
            if self.authorized():
                return "management"
            presented = self.credential(allow_hook_query=True)
            if hmac.compare_digest(presented, router["hookToken"].encode("utf-8")):
                return "device"
            return ""

        def route_auth(self) -> str:
            """Which router a *device* credential belongs to, or empty.

            Relays still push at the front door's root path because that is where their
            Hub used to live. A HOOK key names exactly one router, so the root can route
            it without guessing. A management key deliberately answers empty: an owner
            key at the root still cannot say which router the caller meant, and pinning
            it to one would resurrect the cross-data accident the 400 exists to prevent.
            """
            presented = self.credential(allow_hook_query=True)
            if not presented or self.authorized():
                return ""
            for router in config["routers"]:
                if hmac.compare_digest(presented, router["hookToken"].encode("utf-8")):
                    return router["routerId"]
            return ""

        def answer_route_auth(self) -> bool:
            if urlsplit(self.path).path != "/_routeauth":
                return False
            router_id = self.route_auth()
            if not router_id:
                self.send_error(401)
                return True
            self.send_response(200)
            self.send_header("X-LabProbe-Route", router_id)
            presented = self.credential(allow_hook_query=True)
            if presented:
                self.send_header("X-LabProbe-Token", presented.decode("utf-8"))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return True

        def respond(self, body: dict, status: int = 200) -> None:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            if self.answer_route_auth():
                return
            if urlsplit(self.path).path == OFFICIAL_ACCOUNT_PATH:
                if not self.authorized():
                    self.send_error(401)
                    return
                self.respond(aggregate_official_account(config, "GET"))
                return
            if urlsplit(self.path).path.startswith("/_gateauth/"):
                router_id = urlsplit(self.path).path[len("/_gateauth/"):]
                router = next((item for item in config["routers"]
                               if item["routerId"] == router_id), None)
                if router is None:
                    self.send_error(403)
                    return
                kind = self.gate_kind(router)
                if not kind:
                    self.send_error(401)
                    return
                self.send_response(200)
                self.send_header("X-LabProbe-Auth-Kind", kind)
                if kind == "device":
                    presented = self.credential(allow_hook_query=True)
                    if presented:
                        self.send_header("X-LabProbe-Token", presented.decode("utf-8"))
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path != "/api/routers":
                self.send_error(404)
                return
            if not self.authorized():
                self.send_error(401)
                return
            self.respond(router_list(controller.view() if controller else config))

        def do_POST(self) -> None:
            if self.answer_route_auth():
                return
            if urlsplit(self.path).path == OFFICIAL_ACCOUNT_PATH:
                if not self.authorized():
                    self.send_error(401)
                    return
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 4096:
                        raise ValueError("invalid request size")
                    body = json.loads(self.rfile.read(size))
                    if not isinstance(body, dict):
                        raise ValueError("invalid request body")
                    action = body.get("action")
                    if action == "refresh":
                        worker_body = {"action": "refresh"}
                    elif action in (None, "", "login"):
                        account = str(body.get("account") or "")
                        password = str(body.get("password") or "")
                        if not account.strip() or not password or len(account) > 128 or len(password) > 256:
                            raise ValueError("account and password are required")
                        worker_body = {"account": account, "password": password}
                    else:
                        raise ValueError("unsupported action")
                except (ValueError, TypeError, json.JSONDecodeError):
                    self.respond({"ok": False, "errorCode": "invalid_request", "error": "invalid request"}, 400)
                    return
                self.respond(aggregate_official_account(config, "POST", worker_body))
                return
            if self.path != "/api/routers/default":
                self.send_error(404)
                return
            if not self.authorized():
                self.send_error(401)
                return
            if controller is None:
                self.send_error(503)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    raise ValueError("invalid request size")
                body = json.loads(self.rfile.read(size))
                router_id = str(body.get("routerId", "")).strip()
                selected = controller.set_default(router_id)
            except (ValueError, TypeError, json.JSONDecodeError) as error:
                self.respond({"ok": False, "error": str(error)}, 400)
                return
            except Exception:
                self.respond({"ok": False, "error": "default router change failed"}, 503)
                return
            self.respond({"ok": True, "defaultRouterId": selected})

        def do_DELETE(self) -> None:
            if self.answer_route_auth():
                return
            if urlsplit(self.path).path != OFFICIAL_ACCOUNT_PATH:
                self.send_error(501)
                return
            if not self.authorized():
                self.send_error(401)
                return
            result = aggregate_official_account(config, "DELETE")
            self.respond(result, 200 if result.get("ok") else 207)

        def _unsupported_method(self) -> None:
            # nginx auth_request replays the original method, so PUT/PATCH must be
            # answerable for /_routeauth; anything else keeps its 501.
            if not self.answer_route_auth():
                self.send_error(501)

        do_PUT = _unsupported_method
        do_PATCH = _unsupported_method

        def log_message(self, format: str, *args: object) -> None:
            pass

    return RegistryHandler


def write_nginx_conf(path: Path, text: str) -> None:
    # The rendered file now embeds every worker's APP secret, so it must not be
    # world-readable the way a plain proxy configuration would be.
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)


def run(config: dict, runtime_dir: Path) -> None:
    runtime_dir.mkdir(parents=True, exist_ok=True)
    nginx_conf = runtime_dir / "nginx.conf"
    nginx_pid = runtime_dir / "nginx.pid"
    processes: dict[str, subprocess.Popen] = {}
    nginx: subprocess.Popen | None = None
    stopping = False

    def apply_default_route(view: dict) -> None:
        if nginx is None or nginx.poll() is not None:
            raise RuntimeError("gateway is not running")
        previous = nginx_conf.read_text(encoding="utf-8")
        candidate = runtime_dir / "nginx.next.conf"
        write_nginx_conf(candidate, render_nginx_config(view, nginx_pid))
        subprocess.run(["nginx", "-t", "-c", str(candidate)], check=True)
        candidate.replace(nginx_conf)
        try:
            subprocess.run(["nginx", "-s", "reload", "-c", str(nginx_conf)], check=True)
        except Exception:
            write_nginx_conf(nginx_conf, previous)
            subprocess.run(["nginx", "-s", "reload", "-c", str(nginx_conf)], check=True)
            raise

    controller = DefaultRouterController(config, config["storageRoot"] / "default-router.json", apply_default_route)
    write_nginx_conf(nginx_conf, render_nginx_config(controller.view(), nginx_pid))
    subprocess.run(["nginx", "-t", "-c", str(nginx_conf)], check=True)
    server = ThreadingHTTPServer(("127.0.0.1", config["registryPort"]), make_registry_handler(config, controller))
    server.daemon_threads = True

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for router in config["routers"]:
            for directory in ("config", "data", "backups", "logs"):
                (router["root"] / directory).mkdir(parents=True, exist_ok=True)
            processes[router["routerId"]] = subprocess.Popen(
                [sys.executable, "/app/hub_entry.py"],
                cwd="/app",
                env=worker_environment(router, config),
            )
        nginx = subprocess.Popen(["nginx", "-c", str(nginx_conf), "-g", "daemon off;"])
        threading.Thread(target=server.serve_forever, daemon=True).start()
        while not stopping:
            if nginx.poll() is not None:
                raise RuntimeError(f"nginx exited with status {nginx.returncode}")
            for router in config["routers"]:
                router_id = router["routerId"]
                if processes[router_id].poll() is not None:
                    print(f"worker {router_id} exited; restarting", file=sys.stderr, flush=True)
                    processes[router_id] = subprocess.Popen(
                        [sys.executable, "/app/hub_entry.py"],
                        cwd="/app",
                        env=worker_environment(router, config),
                    )
            time.sleep(3)
    finally:
        server.shutdown()
        if nginx is not None:
            nginx.terminate()
        for process in processes.values():
            process.terminate()
        for process in ([nginx] if nginx is not None else []) + list(processes.values()):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description="Start isolated Hub workers behind one gateway")
    parser.add_argument("--config", default="/app/multi-router.yaml")
    parser.add_argument("--runtime-dir", default="/tmp/labprobe-multi-router")
    parser.add_argument("--check", action="store_true", help="validate only; start no services")
    parser.add_argument("--probe", action="store_true", help="check every configured eWeb TCP route")
    args = parser.parse_args()
    config = load_gateway_config(args.config)
    if args.check:
        print(f"validated {len(config['routers'])} routers; default={config['defaultRouterId']}")
        return 0
    if args.probe:
        results = [(r["routerId"], eweb_reachable(r)) for r in config["routers"]]
        for router_id, reachable in results:
            print(f"{router_id}: eWeb {'reachable' if reachable else 'unreachable'}")
        return 0 if all(reachable for _, reachable in results) else 1
    run(config, Path(args.runtime_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
