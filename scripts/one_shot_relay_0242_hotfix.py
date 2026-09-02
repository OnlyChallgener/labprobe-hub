#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing expected snippet in {path}: {old[:180]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_count(path: str, old: str, new: str, count: int) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    actual = text.count(old)
    if actual < count:
        raise SystemExit(f"expected at least {count} copies in {path}, found {actual}: {old!r}")
    p.write_text(text.replace(old, new, count), encoding="utf-8")


def append_once(path: str, marker: str, block: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if marker in text:
        return
    if not text.endswith("\n"):
        text += "\n"
    p.write_text(text + "\n" + block.strip() + "\n", encoding="utf-8")


replace_once("labrelay/Cargo.toml", 'version = "0.2.41"', 'version = "0.2.42"')

# 0.2.41 made high nofile a hard daemon-start requirement. On BE72 vendor
# procd the daemon may not be allowed to raise the inherited hard limit, which
# must not take STUN/PortMap/TCP-test data plane offline. Keep the raise as a
# best-effort optimization; extreme mode already reports/refuses low-FD runs.
replace_once(
    "labrelay/src/main.rs",
    '''async fn daemon(args: &[String]) -> Result<()> {
    raise_daemon_nofile_limit(131_072)?;
    tcp_session_test::restore_stale_extreme_port_range()?;
''',
    '''async fn daemon(args: &[String]) -> Result<()> {
    if let Err(error) = raise_daemon_nofile_limit(131_072) {
        eprintln!(
            "[labrelay] warning: Relay FD 上限未提升到 131072，将以当前限制继续运行：{error:#}"
        );
    }
    tcp_session_test::restore_stale_extreme_port_range()?;
''',
)

# The installer must not roll back a healthy Agent/daemon solely because the
# vendor firmware kept a low RLIMIT_NOFILE. Core forwarding stays available;
# only extreme/high-count testing is degraded and reports its own limit.
replace_once(
    "scripts/labprobe-install.sh",
    '''INSTALL_STAGE="校验 Relay FD 上限"
verify_relay_nofile || { show_stage_log /tmp/labprobe/service-start.log; rollback; }
INSTALL_STAGE="校验 Hub 连通性"
''',
    '''INSTALL_STAGE="校验 Relay FD 上限"
if ! verify_relay_nofile; then
  say "WARNING: Relay FD 上限低于 65536；核心转发继续运行，极限连接测试将保持受限"
fi
INSTALL_STAGE="校验 Hub 连通性"
''',
)

# The self-hosted update repository can lag behind GitHub Releases. Always try
# the canonical GitHub release manifest first so APP current/latest cannot get
# pinned to an old mirror version such as 0.2.28.
replace_once(
    "hub.py",
    '''    sources = list(dict.fromkeys(url for url in (AGENT_MANIFEST_URL, AGENT_GITHUB_MANIFEST_URL) if url))
''',
    '''    sources = list(dict.fromkeys(url for url in (AGENT_GITHUB_MANIFEST_URL, AGENT_MANIFEST_URL) if url))
''',
)

# PortMap already canonicalizes the legacy Agent identity `router` to the Hub
# primary router identity (for example BE72). STUN and WireGuard were still
# matching their command queues by raw string equality, so after an upgrade a
# legacy `router` Agent could stay online while never receiving BE72 commands.
replace_once(
    "stun_service.py",
    '''    def _router_name(self) -> str:
        value = getattr(self.hub, "_portmap_router_name", None)
        if callable(value):
            return _text(value()) or "router"
        return _text(os.environ.get("PORTMAP_ROUTER_NAME")) or "router"
''',
    '''    def _router_name(self) -> str:
        value = getattr(self.hub, "_portmap_router_name", None)
        raw = _text(value()) if callable(value) else _text(os.environ.get("PORTMAP_ROUTER_NAME"))
        canonicalize = getattr(self.hub, "_canonical_portmap_router", None)
        if callable(canonicalize):
            return _text(canonicalize(raw)) or raw or "router"
        return raw or "router"

    def _canonical_router(self, value: Any = "") -> str:
        raw = _text(value)
        canonicalize = getattr(self.hub, "_canonical_portmap_router", None)
        if callable(canonicalize):
            return _text(canonicalize(raw)) or self._router_name()
        return raw or self._router_name()
''',
)
replace_once(
    "stun_service.py",
    '''    def queue(self, action: str, payload: Dict[str, Any], router: str = "", revision: int = 0) -> Dict[str, Any]:
        router = router or self._router_name()
''',
    '''    def queue(self, action: str, payload: Dict[str, Any], router: str = "", revision: int = 0) -> Dict[str, Any]:
        router = self._canonical_router(router)
''',
)
replace_count(
    "stun_service.py",
    'row.get("router") == router',
    'self._canonical_router(row.get("router")) == router',
    2,
)
replace_once(
    "stun_service.py",
    '''        router = _text(request.args.get("router")) or service._router_name()
''',
    '''        router = service._canonical_router(request.args.get("router"))
''',
)
replace_once(
    "stun_service.py",
    '''                if command.get("router") != router:
                    continue
''',
    '''                if service._canonical_router(command.get("router")) != router:
                    continue
''',
)
replace_once(
    "stun_service.py",
    '''            record = {"router": _text(request.args.get("router")) or service._router_name(), "receivedAt": _now_text(), "receivedEpoch": _now(), "status": payload}
''',
    '''            record = {"router": service._canonical_router(request.args.get("router")), "receivedAt": _now_text(), "receivedEpoch": _now(), "status": payload}
''',
)

replace_once(
    "wireguard_service.py",
    '''    def _router_name(self) -> str:
        resolver = getattr(self.hub, "_portmap_router_name", None)
        return _text(resolver()) if callable(resolver) else "router"
''',
    '''    def _router_name(self) -> str:
        resolver = getattr(self.hub, "_portmap_router_name", None)
        raw = _text(resolver()) if callable(resolver) else "router"
        canonicalize = getattr(self.hub, "_canonical_portmap_router", None)
        if callable(canonicalize):
            return _text(canonicalize(raw)) or raw or "router"
        return raw or "router"

    def _canonical_router(self, value: Any = "") -> str:
        raw = _text(value)
        canonicalize = getattr(self.hub, "_canonical_portmap_router", None)
        if callable(canonicalize):
            return _text(canonicalize(raw)) or self._router_name()
        return raw or self._router_name()
''',
)
replace_once(
    "wireguard_service.py",
    '''    def queue(self, action: str, revision: int, payload: Dict[str, Any], router: str = "", revision_scope: str = "server") -> Dict[str, Any]:
        router = router or self._router_name() or "router"
''',
    '''    def queue(self, action: str, revision: int, payload: Dict[str, Any], router: str = "", revision_scope: str = "server") -> Dict[str, Any]:
        router = self._canonical_router(router)
''',
)
# The first three raw router comparisons are all inside WireGuardService.queue.
replace_count(
    "wireguard_service.py",
    'row.get("router") == router',
    'self._canonical_router(row.get("router")) == router',
    3,
)
replace_count(
    "wireguard_service.py",
    '''        router = _text(request.args.get("router")) or service._router_name()
''',
    '''        router = service._canonical_router(request.args.get("router"))
''',
    2,
)
replace_once(
    "wireguard_service.py",
    '''                if row.get("router") == router and (row.get("status") == "pending" or retry):
''',
    '''                if service._canonical_router(row.get("router")) == router and (row.get("status") == "pending" or retry):
''',
)

# Update the source-order contract test now that GitHub Releases is canonical.
replace_once(
    "tests/test_agent_release_fallback.py",
    '''    assert calls == [primary, github]
''',
    '''    assert calls == [github]
''',
)

append_once(
    "tests/test_stun_service.py",
    "test_legacy_router_alias_receives_canonical_stun_command",
    r'''
def test_legacy_router_alias_receives_canonical_stun_command(tmp_path):
    hub = _hub(tmp_path)
    hub._portmap_router_name = lambda: "BE72"
    hub._canonical_portmap_router = lambda value="": (
        "BE72" if not str(value or "").strip() or str(value).strip().casefold() in {"router", "be72"}
        else str(value).strip()
    )
    service = StunService(hub, _Client())
    service._save_commands([])
    service.queue("upsert", {"rule": {"id": "stun-alias"}}, revision=1)
    hub.app.register_blueprint(create_stun_blueprint(hub, service))
    client = hub.app.test_client()

    delivered = client.get("/api/router/stun/commands?router=router").get_json()["commands"]
    assert [row["payload"]["rule"]["id"] for row in delivered] == ["stun-alias"]

    response = client.post("/api/router/stun/status?router=router", json={"rules": []})
    assert response.status_code == 200
    assert hub.load_json(service.status_path, {})["router"] == "BE72"
''',
)

append_once(
    "tests/test_wireguard_service.py",
    "test_legacy_router_alias_receives_canonical_wireguard_command",
    r'''
def test_legacy_router_alias_receives_canonical_wireguard_command(tmp_path):
    hub = _hub(tmp_path)
    hub._portmap_router_name = lambda: "BE72"
    hub._canonical_portmap_router = lambda value="": (
        "BE72" if not str(value or "").strip() or str(value).strip().casefold() in {"router", "be72"}
        else str(value).strip()
    )
    service = install_wireguard_service(hub)
    service.queue("apply", 1, {"server": {"interfaceName": "labwg0"}})
    client = hub.app.test_client()

    delivered = client.get("/api/router/wireguard/commands?router=router").get_json()["commands"]
    assert [row["revision"] for row in delivered] == [1]

    response = client.post("/api/router/wireguard/status?router=router", json={"revision": 1})
    assert response.status_code == 200
    assert hub.load_json(service.status_path, {})["router"] == "BE72"
''',
)

# Keep the release manifest/body aligned with the hotfix version and scope.
replace_once(
    ".github/workflows/labrelay-release.yml",
    "'changelog': 'Fix BE72 Relay nofile inheritance, add guarded TCP peak extreme mode with automatic source-port restoration, and allow router-self TCP STUN listener/keepalive to share the configured middle port.',",
    "'changelog': '0.2.42 hotfix: keep Relay online when nofile escalation is unavailable, restore STUN/WireGuard router identity aliases, and prefer the canonical GitHub update manifest.',",
)
replace_once(
    ".github/workflows/labrelay-release.yml",
    '''            0.2.41 fixes:
            - Relay daemon raises and verifies `RLIMIT_NOFILE=131072` instead of silently running with BE72 `1024/4096` limits;
            - the unified `/etc/init.d/labprobe` installer is now the canonical update installer;
            - TCP peak test supports guarded extreme mode with temporary `ip_local_port_range=1024 65535` and automatic restoration on completion/stop/error or next daemon startup;
            - router-self TCP STUN allows its listener and outbound STUN keepalive to share the configured middle port via `SO_REUSEPORT`;
            - existing CPU, memory, Conntrack, FD and source-port protection remains active.
''',
    '''            0.2.42 hotfix:
            - Relay daemon no longer exits when vendor firmware prevents raising `RLIMIT_NOFILE`; normal STUN/PortMap/WireGuard service remains online;
            - installer treats a low FD limit as a degraded extreme-test capability instead of rolling the whole update back;
            - STUN and WireGuard command delivery now share the existing `router` ↔ canonical router (for example `BE72`) identity alias;
            - Hub update checks prefer the canonical GitHub Release manifest so a stale mirror cannot pin APP to an older Agent version;
            - guarded TCP extreme mode and router-self STUN `SO_REUSEPORT` behavior remain unchanged.
''',
)

print("0.2.42 regression hotfix applied")
