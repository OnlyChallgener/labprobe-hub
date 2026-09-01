#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing expected snippet in {path}: {old[:160]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once("labrelay/Cargo.toml", 'version = "0.2.40"', 'version = "0.2.41"')
replace_once("labrelay/Cargo.toml", 'anyhow = "1"\n', 'anyhow = "1"\nlibc = "0.2"\n')

# Unified OpenWrt service: ask procd for the high limit and raise hard before soft
# in the shell. LabRelay itself performs a second setrlimit/verification below.
replace_once(
    "scripts/labprobe-install.sh",
    "procd_set_param command /bin/sh -c 'ulimit -n 131072; exec /usr/bin/labrelay daemon --config /etc/labprobe/relay.json --socket /tmp/labrelay.sock --state /tmp/labprobe/relay-state.json --port-min 20000 --port-max 32767 --lan-if br-lan'",
    "procd_set_param command /bin/sh -c 'ulimit -Hn 131072 2>/dev/null || true; ulimit -Sn 131072 2>/dev/null || true; exec /usr/bin/labrelay daemon --config /etc/labprobe/relay.json --socket /tmp/labrelay.sock --state /tmp/labprobe/relay-state.json --port-min 20000 --port-max 32767 --lan-if br-lan'",
)

# Hub-hosted installer must be the unified /etc/init.d/labprobe installer.
replace_once(
    "Dockerfile",
    "COPY agent/install.sh /app/agent/install.sh",
    "COPY scripts/labprobe-install.sh /app/agent/install.sh",
)

# Hub contract: match LabRelay's 10k CPS ceiling and carry Relay-only extreme mode.
replace_once(
    "tcp_session_service.py",
    '"cps": max(1, min(2000, _integer(payload.get("cps"), 500))),\n            "connectTimeoutMs":',
    '"cps": max(1, min(10000, _integer(payload.get("cps"), 500))),\n            "extremeMode": payload.get("extremeMode") is True,\n            "connectTimeoutMs":',
)
replace_once(
    "tests/test_tcp_session_service.py",
    'task = client.post("/api/tcp-session-test/start", json=start_payload(targetConnections=999999, cps=9999)).get_json()["task"]',
    'task = client.post("/api/tcp-session-test/start", json=start_payload(targetConnections=999999, cps=99999, extremeMode=True)).get_json()["task"]',
)
replace_once(
    "tests/test_tcp_session_service.py",
    'assert task["config"]["cps"] == 2000',
    'assert task["config"]["cps"] == 10000\n    assert task["config"]["extremeMode"] is True',
)

# TCP STUN router_self uses one middle port for the listening socket and the
# connected STUN flow. Both sockets must join the same SO_REUSEPORT group.
replace_once(
    "labrelay/src/main.rs",
    "use socket2::{Domain, Protocol, Socket, Type};",
    "use socket2::{Domain, Protocol, SockRef, Socket, Type};",
)
replace_once(
    "labrelay/src/main.rs",
    '''    socket
        .set_reuseaddr(true)
        .context("设置 STUN TCP 套接字失败")?;
    socket.bind(SocketAddr::V4(SocketAddrV4::new(
''',
    '''    socket
        .set_reuseaddr(true)
        .context("设置 STUN TCP 套接字失败")?;
    #[cfg(unix)]
    SockRef::from(&socket)
        .set_reuse_port(true)
        .context("设置 STUN TCP 端口复用失败")?;
    socket.bind(SocketAddr::V4(SocketAddrV4::new(
''',
)

# The BE72 user's actual daemon inherited soft=1024/hard=4096. Do not silently
# run in that state: daemon startup raises and verifies its own RLIMIT_NOFILE.
replace_once(
    "labrelay/src/main.rs",
    '''async fn daemon(args: &[String]) -> Result<()> {
    let config =
''',
    '''fn raise_daemon_nofile_limit(target: u64) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let target = target as libc::rlim_t;
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) } != 0 {
            return Err(anyhow!(
                "读取 Relay FD 上限失败：{}",
                std::io::Error::last_os_error()
            ));
        }
        if current.rlim_cur < target || current.rlim_max < target {
            let requested = libc::rlimit {
                rlim_cur: target,
                rlim_max: target,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &requested) } != 0 {
                return Err(anyhow!(
                    "提升 Relay FD 上限失败（当前 soft={} hard={}，目标={}）：{}",
                    current.rlim_cur,
                    current.rlim_max,
                    target,
                    std::io::Error::last_os_error()
                ));
            }
        }
        let mut verified = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut verified) } != 0 {
            return Err(anyhow!(
                "复核 Relay FD 上限失败：{}",
                std::io::Error::last_os_error()
            ));
        }
        if verified.rlim_cur < target || verified.rlim_max < target {
            bail!(
                "Relay FD 上限未达到要求：soft={} hard={} target={}",
                verified.rlim_cur,
                verified.rlim_max,
                target
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = target;
    }
    Ok(())
}

async fn daemon(args: &[String]) -> Result<()> {
    raise_daemon_nofile_limit(131_072)?;
    tcp_session_test::restore_stale_extreme_port_range()?;
    let config =
''',
)

replace_once(
    "labrelay/src/main.rs",
    '''    async fn tcp_stun_connect_keeps_the_same_port_as_the_listener() {
        // Reserve a port briefly, then release it before the outbound socket
        // binds. The production path has only the STUN socket on this port;
        // keeping this helper listener alive would create a false conflict.
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source_port = inbound.local_addr().unwrap().port();
        drop(inbound);
''',
    '''    async fn tcp_stun_socket_shares_middle_port_with_listener() {
        // router_self TCP STUN keeps a listener and an outbound STUN flow on
        // the same local middle port. Both sockets must join SO_REUSEPORT.
        let inbound = create_ipv4_listener(0).unwrap();
        let source_port = inbound.local_addr().unwrap().port();
''',
)

# Relay TCP peak extreme mode. The backup file makes the global sysctl
# recoverable after a crash/reboot; daemon startup restores any stale backup.
replace_once(
    "labrelay/src/tcp_session_test.rs",
    "use std::net::SocketAddr;\n",
    "use std::net::SocketAddr;\nuse std::path::Path;\n",
)
replace_once(
    "labrelay/src/tcp_session_test.rs",
    "const CPU_HIGH_SAMPLE_LIMIT: u8 = 3;\n",
    'const CPU_HIGH_SAMPLE_LIMIT: u8 = 3;\nconst IP_LOCAL_PORT_RANGE_PATH: &str = "/proc/sys/net/ipv4/ip_local_port_range";\nconst EXTREME_PORT_RANGE_BACKUP: &str = "/tmp/labprobe/tcp-peak-port-range.original";\nconst EXTREME_PORT_RANGE: &str = "1024 65535\\n";\n',
)
replace_once(
    "labrelay/src/tcp_session_test.rs",
    "    max_duration_seconds: u64,\n}",
    "    max_duration_seconds: u64,\n    extreme_mode: bool,\n}",
)
replace_once(
    "labrelay/src/tcp_session_test.rs",
    "            max_duration_seconds: 180,\n        }",
    "            max_duration_seconds: 180,\n            extreme_mode: false,\n        }",
)
replace_once(
    "labrelay/src/tcp_session_test.rs",
    "        self.max_duration_seconds = self.max_duration_seconds.clamp(10, 300);\n        Ok(self)",
    '        self.max_duration_seconds = self.max_duration_seconds.clamp(10, 300);\n        if self.extreme_mode && fd_soft_limit().unwrap_or(0) < 65_536 {\n            bail!("极限模式不可用：Relay FD 软上限低于 65536");\n        }\n        Ok(self)',
)

marker = '#[derive(Debug, Clone, Serialize)]\n#[serde(rename_all = "camelCase")]\nstruct FamilyMetric {'
guard = r'''struct ExtremePortRangeGuard {
    original: String,
    active: bool,
}

impl ExtremePortRangeGuard {
    fn activate() -> Result<Self> {
        restore_stale_extreme_port_range()?;
        let original = fs::read_to_string(IP_LOCAL_PORT_RANGE_PATH)
            .context("读取临时源端口范围失败")?;
        let current: Vec<&str> = original.split_whitespace().collect();
        if current == ["1024", "65535"] {
            return Ok(Self {
                original,
                active: false,
            });
        }
        if let Some(parent) = Path::new(EXTREME_PORT_RANGE_BACKUP).parent() {
            fs::create_dir_all(parent).context("创建极限模式状态目录失败")?;
        }
        fs::write(EXTREME_PORT_RANGE_BACKUP, &original)
            .context("保存原临时源端口范围失败")?;
        if let Err(error) = fs::write(IP_LOCAL_PORT_RANGE_PATH, EXTREME_PORT_RANGE) {
            let _ = fs::remove_file(EXTREME_PORT_RANGE_BACKUP);
            return Err(error).context("启用极限模式临时源端口范围失败");
        }
        let (first, last) = source_port_range();
        if first > 1024 || last < 65535 {
            let _ = fs::write(IP_LOCAL_PORT_RANGE_PATH, &original);
            let _ = fs::remove_file(EXTREME_PORT_RANGE_BACKUP);
            bail!("极限模式临时源端口范围未生效");
        }
        Ok(Self {
            original,
            active: true,
        })
    }

    fn restore(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        fs::write(IP_LOCAL_PORT_RANGE_PATH, &self.original)
            .context("恢复原临时源端口范围失败")?;
        let _ = fs::remove_file(EXTREME_PORT_RANGE_BACKUP);
        self.active = false;
        Ok(())
    }
}

impl Drop for ExtremePortRangeGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub(crate) fn restore_stale_extreme_port_range() -> Result<()> {
    let backup = Path::new(EXTREME_PORT_RANGE_BACKUP);
    if !backup.exists() {
        return Ok(());
    }
    let original = fs::read_to_string(backup).context("读取极限模式恢复信息失败")?;
    fs::write(IP_LOCAL_PORT_RANGE_PATH, original).context("恢复遗留临时源端口范围失败")?;
    fs::remove_file(backup).context("清理极限模式恢复信息失败")?;
    Ok(())
}

'''
p = Path("labrelay/src/tcp_session_test.rs")
text = p.read_text(encoding="utf-8")
if marker not in text:
    raise SystemExit("missing FamilyMetric marker")
p.write_text(text.replace(marker, guard + marker, 1), encoding="utf-8")

replace_once(
    "labrelay/src/tcp_session_test.rs",
    '''    async fn run_task(&self, config: TcpSessionConfig, control: Arc<ActiveControl>) {
        let families: Vec<bool> = match config.family.as_str() {
''',
    '''    async fn run_task(&self, config: TcpSessionConfig, control: Arc<ActiveControl>) {
        let mut extreme_port_guard = if config.extreme_mode {
            match ExtremePortRangeGuard::activate() {
                Ok(guard) => {
                    self.update(&control.task_id, |snapshot| {
                        push_log(
                            snapshot,
                            "极限模式已启用：临时源端口范围 1024-65535，测试结束自动恢复".into(),
                        );
                    })
                    .await;
                    Some(guard)
                }
                Err(error) => {
                    let reason = format!("极限模式准备失败：{error:#}");
                    self.update(&control.task_id, |snapshot| {
                        snapshot.state = "failed".into();
                        snapshot.status = "极限模式准备失败".into();
                        snapshot.finish_reason = reason.clone();
                        snapshot.resources_released = true;
                        snapshot.release_status = "未创建测试连接".into();
                        snapshot.finished_epoch = now_epoch();
                        push_log(snapshot, reason.clone());
                    })
                    .await;
                    let mut inner = self.inner.lock().await;
                    if inner.active.as_ref().map(|value| value.task_id.as_str())
                        == Some(control.task_id.as_str())
                    {
                        inner.active = None;
                    }
                    return;
                }
            }
        } else {
            None
        };
        let families: Vec<bool> = match config.family.as_str() {
''',
)
replace_once(
    "labrelay/src/tcp_session_test.rs",
    '''        let stopped = control.stop.load(Ordering::Acquire);
        let reason = if stopped {
''',
    '''        if let Some(guard) = extreme_port_guard.as_mut() {
            match guard.restore() {
                Ok(()) => {
                    self.update(&control.task_id, |snapshot| {
                        push_log(snapshot, "极限模式已恢复原临时源端口范围".into());
                    })
                    .await;
                }
                Err(error) => {
                    failed = true;
                    reasons.push(format!("恢复临时源端口范围失败：{error:#}"));
                }
            }
        }
        let stopped = control.stop.load(Ordering::Acquire);
        let reason = if stopped {
''',
)
replace_once(
    "labrelay/src/tcp_session_test.rs",
    "        let plan = resource_plan(config.target_connections);",
    "        let plan = resource_plan(config.target_connections, config.extreme_mode);",
)
replace_once(
    "labrelay/src/tcp_session_test.rs",
    "fn resource_plan(requested: usize) -> ResourcePlan {",
    "fn resource_plan(requested: usize, extreme_mode: bool) -> ResourcePlan {",
)
replace_once(
    "labrelay/src/tcp_session_test.rs",
    '''    let fd_ceiling = soft_limit
        .saturating_mul(80)
''',
    '''    let fd_ceiling_percent = if extreme_mode { 90 } else { 80 };
    let fd_ceiling = soft_limit
        .saturating_mul(fd_ceiling_percent)
''',
)
replace_once(
    "labrelay/src/tcp_session_test.rs",
    "    let conntrack_ceiling = conntrack_max.saturating_mul(75) / 100;",
    "    let conntrack_ceiling = conntrack_max.saturating_mul(if extreme_mode { 90 } else { 75 }) / 100;",
)
replace_once(
    "labrelay/src/tcp_session_test.rs",
    "    let source_port_ceiling = source_port_capacity.saturating_mul(90) / 100;",
    "    let source_port_ceiling = source_port_capacity.saturating_mul(if extreme_mode { 95 } else { 90 }) / 100;",
)

print("0.2.41 focused source patch applied")
