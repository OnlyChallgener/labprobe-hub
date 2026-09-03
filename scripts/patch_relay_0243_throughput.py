from pathlib import Path
import re

path = Path('labrelay/src/tcp_session_test.rs')
text = path.read_text(encoding='utf-8')


def once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected exactly one match, got {count}')
    text = text.replace(old, new, 1)


once('use std::collections::VecDeque;', 'use std::collections::{HashSet, VecDeque};', 'collections import')
once(
    'use std::net::{SocketAddr, TcpStream as StdTcpStream};',
    'use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream};',
    'net import',
)
once('const EXTREME_SOCKET_BUFFER_BYTES: u32 = 4 * 1024;\n', '', 'remove socket buffer constant')
once(
    'const MIN_PENDING_CONNECTS: usize = 256;\nconst MAX_PENDING_CONNECTS: usize = 1_024;\n',
    'const MIN_PENDING_CONNECTS: usize = 256;\nconst MAX_PENDING_CONNECTS: usize = 1_024;\n'
    'const EXTREME_MIN_PENDING_CONNECTS: usize = 2_048;\n'
    'const EXTREME_MAX_PENDING_CONNECTS: usize = 16_384;\n',
    'pending constants',
)
once(
    'const LOOP_INTERVAL: Duration = Duration::from_millis(100);',
    'const LOOP_INTERVAL: Duration = Duration::from_millis(5);',
    'loop interval',
)
once(
    'let pending_limit = pending_connect_limit(config.cps, safe_target);',
    'let pending_limit = pending_connect_limit(config.cps, safe_target, config.extreme_mode);',
    'pending call',
)
once(
    'let mut pending = FuturesUnordered::new();',
    '''let mut pending = FuturesUnordered::new();
        let mut source_port_pool = if config.extreme_mode {
            let (first, last) = source_port_range();
            available_source_ports(first, last)
        } else {
            VecDeque::new()
        };
        if config.extreme_mode {
            self.update(&control.task_id, |snapshot| {
                push_log(
                    snapshot,
                    format!(
                        "{} 极限建连器：显式源端口池 {} 个，5ms 平滑调度，pending 上限 {}",
                        label,
                        source_port_pool.len(),
                        pending_limit
                    ),
                );
            })
            .await;
        }''',
    'source pool init',
)
once(
    '''                    ConnectResult::Failed(kind) => {
                        failure += 1;''',
    '''                    ConnectResult::Failed(FailureKind::SourcePortBusy) => {
                        // Explicit source-port allocation may race with unrelated router traffic.
                        // Skip that port without poisoning connection-quality heuristics.
                    }
                    ConnectResult::Failed(kind) => {
                        failure += 1;''',
    'port busy handling',
)
once(
    '''            for _ in 0..launches {
                let timeout_duration = Duration::from_millis(config.connect_timeout_ms);
                pending.push(connect_once(address, timeout_duration, config.extreme_mode));
            }''',
    '''            for _ in 0..launches {
                let source_port = if config.extreme_mode {
                    match source_port_pool.pop_front() {
                        Some(port) => Some(port),
                        None => {
                            finish_reason = "显式源端口池已耗尽".into();
                            break 'testing;
                        }
                    }
                } else {
                    None
                };
                let timeout_duration = Duration::from_millis(config.connect_timeout_ms);
                pending.push(connect_once(address, timeout_duration, source_port));
            }''',
    'launch explicit ports',
)
once(
    '''enum FailureKind {
    SourcePort,
    FileDescriptor,''',
    '''enum FailureKind {
    SourcePort,
    SourcePortBusy,
    FileDescriptor,''',
    'failure enum',
)

old_pending = '''fn pending_connect_limit(cps: u64, safe_target: usize) -> usize {
    let desired = (cps as usize / 4).clamp(MIN_PENDING_CONNECTS, MAX_PENDING_CONNECTS);
    desired.min(safe_target.max(1))
}'''
new_pending = '''fn pending_connect_limit(cps: u64, safe_target: usize, extreme_mode: bool) -> usize {
    let desired = if extreme_mode {
        (cps as usize)
            .saturating_mul(2)
            .clamp(EXTREME_MIN_PENDING_CONNECTS, EXTREME_MAX_PENDING_CONNECTS)
    } else {
        (cps as usize / 4).clamp(MIN_PENDING_CONNECTS, MAX_PENDING_CONNECTS)
    };
    desired.min(safe_target.max(1))
}'''
once(old_pending, new_pending, 'pending function')

old_cpu = '''fn extreme_cpu_rate_scale(cpu_percent: f64) -> f64 {
    if cpu_percent >= 99.5 {
        0.10
    } else if cpu_percent >= 98.0 {
        0.25
    } else if cpu_percent >= 95.0 {
        0.75
    } else {
        1.0
    }
}'''
new_cpu = '''fn extreme_cpu_rate_scale(cpu_percent: f64) -> f64 {
    if cpu_percent >= 99.8 {
        0.10
    } else if cpu_percent >= 99.0 {
        0.50
    } else {
        1.0
    }
}'''
once(old_cpu, new_cpu, 'extreme cpu scale')

pattern = re.compile(
    r'''async fn connect_once\(\n    address: SocketAddr,\n    connect_timeout: Duration,\n    extreme_mode: bool,\n\) -> ConnectResult \{.*?\n\}\n\nasync fn resolve_target''',
    re.S,
)
replacement = '''async fn connect_once(
    address: SocketAddr,
    connect_timeout: Duration,
    source_port: Option<u16>,
) -> ConnectResult {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    };
    let socket = match socket {
        Ok(value) => value,
        Err(error) => return ConnectResult::Failed(classify_connect_error(&error)),
    };
    if let Some(port) = source_port {
        let source = if address.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))
        };
        if let Err(error) = socket.bind(source) {
            return ConnectResult::Failed(classify_connect_error(&error));
        }
    }
    match timeout(connect_timeout, socket.connect(address)).await {
        Ok(Ok(stream)) => match stream.into_std() {
            Ok(stream) => ConnectResult::Connected(stream),
            Err(error) => ConnectResult::Failed(classify_connect_error(&error)),
        },
        Ok(Err(error)) => ConnectResult::Failed(classify_connect_error(&error)),
        Err(_) => ConnectResult::Failed(FailureKind::Other),
    }
}

async fn resolve_target'''
text, count = pattern.subn(replacement, text, count=1)
if count != 1:
    raise SystemExit(f'connect_once replacement count={count}')

once(
    '''    match error.raw_os_error() {
        Some(99) => FailureKind::SourcePort,''',
    '''    match error.raw_os_error() {
        Some(98) => FailureKind::SourcePortBusy,
        Some(99) => FailureKind::SourcePort,''',
    'EADDRINUSE classify',
)

pattern = re.compile(
    r'''fn source_ports_in_use\(first: usize, last: usize\) -> usize \{.*?\n\}\n\nfn read_cpu_counters''',
    re.S,
)
replacement = '''fn source_ports_used_set(first: usize, last: usize) -> HashSet<u16> {
    let mut ports = HashSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let Some(port) = line
                .split_whitespace()
                .nth(1)
                .and_then(|address| address.rsplit(':').next())
                .and_then(|port| u16::from_str_radix(port, 16).ok())
            else {
                continue;
            };
            let value = port as usize;
            if value >= first && value <= last {
                ports.insert(port);
            }
        }
    }
    ports
}

fn source_ports_in_use(first: usize, last: usize) -> usize {
    source_ports_used_set(first, last).len()
}

fn available_source_ports(first: usize, last: usize) -> VecDeque<u16> {
    let used = source_ports_used_set(first, last);
    (first..=last)
        .filter_map(|port| u16::try_from(port).ok())
        .filter(|port| !used.contains(port))
        .collect()
}

fn read_cpu_counters'''
text, count = pattern.subn(replacement, text, count=1)
if count != 1:
    raise SystemExit(f'source port helper replacement count={count}')

once(
    'assert_eq!(pending_connect_limit(500, 65_535), 256);',
    'assert_eq!(pending_connect_limit(500, 65_535, false), 256);',
    'normal pending 500 test',
)
once(
    'assert_eq!(pending_connect_limit(4_000, 65_535), 1_000);',
    'assert_eq!(pending_connect_limit(4_000, 65_535, false), 1_000);',
    'normal pending 4000 test',
)
once(
    'assert_eq!(pending_connect_limit(10_000, 65_535), 1_024);',
    'assert_eq!(pending_connect_limit(10_000, 65_535, false), 1_024);',
    'normal pending 10000 test',
)
once(
    '''        assert_eq!(extreme_cpu_rate_scale(94.0), 1.0);
        assert_eq!(extreme_cpu_rate_scale(95.0), 0.75);
        assert_eq!(extreme_cpu_rate_scale(98.0), 0.25);
        assert_eq!(extreme_cpu_rate_scale(99.5), 0.10);''',
    '''        assert_eq!(pending_connect_limit(1_000, 65_535, true), 2_048);
        assert_eq!(pending_connect_limit(4_000, 65_535, true), 8_000);
        assert_eq!(pending_connect_limit(10_000, 65_535, true), 16_384);
        assert_eq!(extreme_cpu_rate_scale(98.9), 1.0);
        assert_eq!(extreme_cpu_rate_scale(99.0), 0.50);
        assert_eq!(extreme_cpu_rate_scale(99.8), 0.10);''',
    'extreme tests',
)

path.write_text(text, encoding='utf-8')

cargo = Path('labrelay/Cargo.toml')
cargo_text = cargo.read_text(encoding='utf-8')
if 'version = "0.2.42"' not in cargo_text:
    raise SystemExit('expected LabRelay 0.2.42 before bump')
cargo.write_text(cargo_text.replace('version = "0.2.42"', 'version = "0.2.43"', 1), encoding='utf-8')
