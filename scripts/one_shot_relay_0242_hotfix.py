#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing expected snippet in {path}: {old[:180]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once("labrelay/Cargo.toml", 'version = "0.2.41"', 'version = "0.2.42"')

# 0.2.41 made high nofile a hard daemon-start requirement. On BE72 vendor
# procd the daemon may not be allowed to raise the inherited hard limit, which
# must not take STUN/PortMap/TCP-test data plane offline. Keep the raise as a
# best-effort optimization; extreme mode already refuses to run on low FD.
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

print("0.2.42 regression hotfix applied")
