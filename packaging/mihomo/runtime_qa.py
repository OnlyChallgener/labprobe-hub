#!/usr/bin/env python3
"""Exercise a Mihomo binary and its packaged dashboard without installing either.

Run inside the ARM64 NAS build container, preferably with --network=none:
  python3 runtime_qa.py --binary /build/mihomo --ui-dir /build/dashboard

All traffic is local to the current network namespace. The optional transfer
rate is a NAS loopback smoke check, not a BE72, WAN, or encrypted proxy benchmark.
Only Python's standard library is required. JSON is written to stdout; a failed
check exits nonzero. Controller credentials exist only in the owned temp home.
"""

import argparse
import hashlib
import http.client
import http.server
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import unquote, urljoin, urlsplit


class CheckFailed(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def rss_kib(pid):
    """Return Linux process RSS, without confusing Python/server RSS with core RSS."""
    try:
        for line in Path("/proc/{}/status".format(pid)).read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


def choose_ports():
    # Reserve both simultaneously so the OS cannot return the same port twice.
    sockets = [socket.socket(), socket.socket()]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return tuple(sock.getsockname()[1] for sock in sockets)
    finally:
        for sock in sockets:
            sock.close()


def get_http(port, path, secret=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        headers = {"Connection": "close"}
        if secret is not None:
            headers["Authorization"] = "Bearer " + secret
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def get_ui(port, path):
    redirects = []
    for _ in range(4):
        status, headers, body = get_http(port, path)
        if status not in (301, 302, 303, 307, 308):
            return status, body, path, redirects
        location = next((v for k, v in headers.items() if k.lower() == "location"), "")
        target = urlsplit(urljoin(path, location))
        require(not target.netloc and not target.scheme and target.path.startswith("/ui/"),
                "Dashboard redirect escaped its local /ui/ path")
        redirects.append(status)
        path = target.path + (("?" + target.query) if target.query else "")
    raise CheckFailed("Too many dashboard redirects")


class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.styles = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            # The emitted module is required; config.js may be an optional stub.
            if values.get("type") == "module":
                self.scripts.insert(0, values["src"])
            else:
                self.scripts.append(values["src"])
        elif tag == "link" and "stylesheet" in values.get("rel", "").split():
            if values.get("href"):
                self.styles.append(values["href"])


def check_asset(port, ui_dir, candidates, suffix):
    for reference in candidates:
        target = urlsplit(urljoin("/ui/", reference))
        if target.scheme or target.netloc or not target.path.startswith("/ui/"):
            continue
        relative = unquote(target.path[len("/ui/"):])
        if not relative.lower().endswith(suffix):
            continue
        source = (ui_dir / relative).resolve()
        try:
            source.relative_to(ui_dir.resolve())
        except ValueError:
            continue
        if not source.is_file() or source.stat().st_size == 0:
            continue
        expected = source.read_bytes()
        status, _, actual = get_http(port, target.path)
        require(status == 200, "Dashboard emitted asset did not return HTTP 200")
        require(actual == expected, "Dashboard asset differs from the packaged file")
        return {"path": target.path, "status": status, "bytes": len(actual),
                "sha256": digest(actual)}
    raise CheckFailed("Dashboard has no real emitted {} asset".format(suffix))


class LocalServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False


def make_handler(payload, request_log):
    class PayloadHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path != "/payload":
                self.send_error(404)
                return
            request_log.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self.close_connection = True

        def log_message(self, *_args):
            pass

    return PayloadHandler


def read_exact(sock, count):
    chunks = []
    while count:
        chunk = sock.recv(count)
        require(bool(chunk), "Unexpected EOF in SOCKS negotiation")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def proxy_transfer(mixed_port, target_port, mode):
    """Use sockets explicitly so environment NO_PROXY cannot bypass Mihomo."""
    connection = http.client.HTTPConnection("127.0.0.1", mixed_port, timeout=15)
    try:
        if mode == "connect":
            connection.set_tunnel("127.0.0.1", target_port)
            path = "/payload"
        elif mode == "socks5":
            sock = socket.create_connection(("127.0.0.1", mixed_port), timeout=15)
            connection.sock = sock
            sock.sendall(b"\x05\x01\x00")
            require(read_exact(sock, 2) == b"\x05\x00", "SOCKS5 no-auth negotiation failed")
            sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                         + struct.pack("!H", target_port))
            reply = read_exact(sock, 4)
            require(reply[:3] == b"\x05\x00\x00", "SOCKS5 local CONNECT failed")
            if reply[3] == 1:
                read_exact(sock, 4)
            elif reply[3] == 4:
                read_exact(sock, 16)
            elif reply[3] == 3:
                read_exact(sock, read_exact(sock, 1)[0])
            else:
                raise CheckFailed("Invalid SOCKS5 address type")
            read_exact(sock, 2)
            path = "/payload"
        else:
            path = "http://127.0.0.1:{}/payload".format(target_port)
        started = time.perf_counter()
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        return response.status, body, time.perf_counter() - started
    finally:
        connection.close()


def stopped(process):
    if process is None:
        return True
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=6)
    return process.poll() is not None


def run(args, result):
    binary = args.binary.resolve(strict=True)
    ui_source = args.ui_dir.resolve(strict=True)
    require(binary.is_file(), "--binary must be a regular executable file")
    require((ui_source / "index.html").is_file(), "--ui-dir must contain index.html")
    process = None
    server = None
    temp_home = None
    log_path = None
    temporary = None
    secret = secrets.token_urlsafe(32)
    clean_environment = {k: v for k, v in os.environ.items()
                         if not k.startswith("CLASH_") and k not in ("SAFE_PATHS", "SKIP_SAFE_PATH_CHECK")}
    try:
        temporary = tempfile.TemporaryDirectory(prefix="mihomo-runtime-qa-")
        temp_home = Path(temporary.name)
        ui_dir = temp_home / "ui"
        shutil.copytree(ui_source, ui_dir)
        mixed_port, controller_port = choose_ports()
        config_path = temp_home / "config.yaml"
        config_path.write_text("""mixed-port: {mixed}
port: 0
socks-port: 0
redir-port: 0
tproxy-port: 0
allow-lan: false
bind-address: 127.0.0.1
ipv6: false
mode: rule
log-level: warning
find-process-mode: off
external-controller: 127.0.0.1:{controller}
external-ui: ./ui
external-ui-url: ""
secret: {secret}
geo-auto-update: false
dns:
  enable: false
tun:
  enable: false
sniffer:
  enable: false
ntp:
  enable: false
iptables:
  enable: false
profile:
  store-selected: false
  store-fake-ip: false
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
""".format(mixed=mixed_port, controller=controller_port, secret=secret), encoding="utf-8")
        config_path.chmod(0o600)
        command = [str(binary), "-d", str(temp_home), "-f", str(config_path)]
        result["stage"] = "version"
        version = subprocess.run([str(binary), "-v"], cwd=temp_home, env=clean_environment,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
        require(version.returncode == 0, "Mihomo version command failed")
        version_text = version.stdout.decode("utf-8", "replace").strip()
        require("mihomo" in version_text.lower(), "Version output does not identify Mihomo")
        result["version"] = version_text[:1024]
        result["binary_sha256"] = digest(binary.read_bytes())
        result["stage"] = "config_test"
        tested = subprocess.run(command + ["-t"], cwd=temp_home, env=clean_environment,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        require(tested.returncode == 0, "Config test failed: "
                + tested.stdout.decode("utf-8", "replace")[-2048:].replace(secret, "[redacted]"))
        result["config_test"] = "passed"
        result["stage"] = "startup"
        log_path = temp_home / "core.log"
        with log_path.open("wb") as log_file:
            process = subprocess.Popen(command, cwd=temp_home, env=clean_environment,
                                       stdout=log_file, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + args.startup_timeout
        while True:
            require(process.poll() is None, "Mihomo exited during startup")
            try:
                status, _, body = get_http(controller_port, "/version", secret)
                if status == 200:
                    break
            except (OSError, http.client.HTTPException):
                pass
            require(time.monotonic() < deadline, "Controller did not become ready")
            time.sleep(0.1)
        result["stage"] = "api"
        unauthenticated = get_http(controller_port, "/version")[0]
        wrong_secret = get_http(controller_port, "/configs", secret + "wrong")[0]
        require(unauthenticated == 401 and wrong_secret == 401,
                "Controller accepted a missing or incorrect secret")
        api_version = json.loads(body)
        require(bool(api_version.get("version")), "Authenticated /version has no version")
        status, _, body = get_http(controller_port, "/configs", secret)
        require(status == 200, "Authenticated /configs failed")
        config = json.loads(body)
        require(config.get("mode") == "rule" and config.get("mixed-port") == mixed_port,
                "Controller reports unexpected active mode or mixed port")
        require(config.get("allow-lan") is False and config.get("bind-address") == "127.0.0.1",
                "Proxy listener is not restricted to loopback")
        require(config.get("tun", {}).get("enable") is False, "TUN unexpectedly enabled")
        require(config.get("geo-auto-update") is False, "Geodata auto update unexpectedly enabled")
        result["api"] = {"unauthenticated_status": unauthenticated,
                         "wrong_secret_status": wrong_secret, "authenticated_status": status,
                         "version": api_version.get("version"), "loopback_only": True,
                         "mode": config["mode"], "tun_enabled": False,
                         "geo_auto_update": False}
        result["stage"] = "dashboard"
        status, index, final_path, redirects = get_ui(controller_port, "/ui/index.html")
        require(status == 200, "Dashboard index did not return HTTP 200")
        require(index == (ui_dir / "index.html").read_bytes(),
                "Served dashboard index differs from packaged index")
        parser = Assets()
        parser.feed(index.decode("utf-8"))
        result["dashboard"] = {"request": "/ui/index.html", "final_path": final_path,
                               "redirect_statuses": redirects, "status": status,
                               "index_bytes": len(index), "assets": [
                                   check_asset(controller_port, ui_dir, parser.scripts, ".js"),
                                   check_asset(controller_port, ui_dir, parser.styles, ".css")]}
        time.sleep(0.3)
        result["rss_kib"] = {"idle": rss_kib(process.pid)}
        result["stage"] = "local_proxy"
        size = args.transfer_mib * 1024 * 1024
        payload = (bytes(range(256)) * ((size + 255) // 256))[:size]
        payload_hash = digest(payload)
        request_log = []
        server = LocalServer(("127.0.0.1", 0), make_handler(payload, request_log))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        transfers = []
        for mode in ("http", "connect", "socks5"):
            status, body, duration = proxy_transfer(mixed_port, server.server_address[1], mode)
            require(status == 200, "{} proxy transfer failed".format(mode))
            require(len(body) == size and digest(body) == payload_hash,
                    "{} proxy payload integrity check failed".format(mode))
            transfers.append({"mode": mode, "status": status, "bytes": len(body),
                              "sha256": payload_hash, "seconds": round(duration, 6),
                              "nas_loopback_mbps": round(len(body) * 8 / duration / 1e6, 2)})
        require(len(request_log) == 3, "Local origin did not receive all proxy requests")
        result["local_proxy"] = {"transfers": transfers, "origin_requests": len(request_log),
                                 "benchmark_scope": "NAS loopback smoke check only; not BE72/WAN/encrypted throughput"}
        result["rss_kib"]["after_transfers"] = rss_kib(process.pid)
        result["stage"] = "complete"
        result["ok"] = True
        # Stop before TemporaryDirectory removes the live core's config/home.
        result["cleanup"]["core_stopped"] = stopped(process)
        process = None
        server.shutdown()
        server.server_close()
        server = None
    except BaseException:
        if log_path is not None and log_path.is_file():
            result["core_log_tail"] = log_path.read_text(errors="replace")[-2048:].replace(secret, "[redacted]")
        raise
    finally:
        result["cleanup"]["core_stopped"] = stopped(process)
        if server is not None:
            server.shutdown()
            server.server_close()
        if temporary is not None:
            temporary.cleanup()
        result["cleanup"]["temporary_home_removed"] = temp_home is None or not temp_home.exists()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--ui-dir", required=True, type=Path)
    parser.add_argument("--transfer-mib", type=int, default=4,
                        help="Payload size per local HTTP/CONNECT/SOCKS test (1-64; default 4)")
    parser.add_argument("--startup-timeout", type=float, default=20)
    args = parser.parse_args()
    if not 1 <= args.transfer_mib <= 64:
        parser.error("--transfer-mib must be between 1 and 64")
    if not 1 <= args.startup_timeout <= 120:
        parser.error("--startup-timeout must be between 1 and 120")
    result = {"ok": False, "stage": "arguments", "host_arch": platform.machine(),
              "host_os": platform.system(), "network_scope": "loopback-only",
              "cleanup": {"core_stopped": True, "temporary_home_removed": True}}

    def interrupted(_number, _frame):
        raise KeyboardInterrupt("Interrupted")

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, interrupted)
    try:
        run(args, result)
    except (Exception, KeyboardInterrupt) as error:
        result["ok"] = False
        result["error"] = {"type": type(error).__name__, "message": str(error)[:4096]}
    print(json.dumps(result, separators=(",", ":"), ensure_ascii=True))
    return 0 if result["ok"] and all(result["cleanup"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
