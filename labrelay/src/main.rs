use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket, UnixListener};
use tokio::sync::{watch, Mutex, RwLock, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};

mod agent;
mod ddns_address;
mod wireguard;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_CONFIG: &str = "/etc/labprobe/relay.json";
const DEFAULT_SOCKET: &str = "/tmp/labrelay.sock";
const DEFAULT_STATE: &str = "/tmp/labrelay/state.json";
const DEFAULT_PID: &str = "/tmp/labrelay.pid";
const DEFAULT_UDP_STUN_SERVER: &str = "stun.cloudflare.com:3478";
const DEFAULT_TCP_STUN_SERVER: &str = "stunserver2025.stunprotocol.org:3478";
const LEGACY_TCP_STUN_SERVER: &str = DEFAULT_UDP_STUN_SERVER;

fn default_true() -> bool {
    true
}
fn default_max_connections() -> u32 {
    32
}
fn default_idle_timeout() -> u64 {
    300
}
fn default_rule_kind() -> String {
    "portmap".to_string()
}
fn default_stun_server(protocol: &str) -> String {
    if protocol.eq_ignore_ascii_case("TCP") {
        DEFAULT_TCP_STUN_SERVER.to_string()
    } else {
        DEFAULT_UDP_STUN_SERVER.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Rule {
    kind: String,
    id: String,
    name: String,
    enabled: bool,
    mode: String,
    listen_port: u16,
    target_mode: String,
    target_ipv4: String,
    target_ipv6: String,
    target_ipv6_suffix: String,
    target_mac: String,
    target_port: u16,
    transport_protocol: String,
    service_type: String,
    stun_server: String,
    prefer_current_prefix: bool,
    expires_at: Option<u64>,
    max_connections: u32,
    idle_timeout_sec: u64,
}

fn rules_are_equal(left: &Rule, right: &Rule) -> bool {
    left == right
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            kind: default_rule_kind(),
            id: String::new(),
            name: String::new(),
            enabled: false,
            mode: "6to4".to_string(),
            listen_port: 0,
            target_mode: "ipv4".to_string(),
            target_ipv4: String::new(),
            target_ipv6: String::new(),
            target_ipv6_suffix: String::new(),
            target_mac: String::new(),
            target_port: 0,
            transport_protocol: "TCP".to_string(),
            service_type: "Custom".to_string(),
            stun_server: default_stun_server("TCP"),
            prefer_current_prefix: default_true(),
            expires_at: None,
            max_connections: default_max_connections(),
            idle_timeout_sec: default_idle_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ConfigFile {
    version: u32,
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeSnapshot {
    id: String,
    name: String,
    mode: String,
    state: String,
    listen: String,
    resolved_target: String,
    active_connections: u64,
    active_peers: u64,
    total_upload_bytes: u64,
    total_download_bytes: u64,
    total_upload_packets: u64,
    total_download_packets: u64,
    started_at: Option<u64>,
    expires_at: Option<u64>,
    last_resolved_at: Option<u64>,
    last_error: String,
    public_endpoint: String,
    public_ip: String,
    public_port: u16,
    mapping_updated_at: Option<u64>,
}

impl RuntimeSnapshot {
    fn stopped(rule: &Rule) -> Self {
        Self {
            id: rule.id.clone(),
            name: rule.name.clone(),
            mode: rule.mode.clone(),
            state: if is_expired(rule) {
                "expired"
            } else {
                "stopped"
            }
            .to_string(),
            listen: if rule.kind == "stun" {
                format!("0.0.0.0:{}", rule.listen_port)
            } else {
                format!("[::]:{}", rule.listen_port)
            },
            resolved_target: String::new(),
            active_connections: 0,
            active_peers: 0,
            total_upload_bytes: 0,
            total_download_bytes: 0,
            total_upload_packets: 0,
            total_download_packets: 0,
            started_at: None,
            expires_at: rule.expires_at,
            last_resolved_at: None,
            last_error: String::new(),
            public_endpoint: String::new(),
            public_ip: String::new(),
            public_port: 0,
            mapping_updated_at: None,
        }
    }
}

struct RuntimeShared {
    base: RwLock<RuntimeSnapshot>,
    active: AtomicU64,
    upload: AtomicU64,
    download: AtomicU64,
    active_peers: AtomicU64,
    upload_packets: AtomicU64,
    download_packets: AtomicU64,
}

impl RuntimeShared {
    fn new(mut snapshot: RuntimeSnapshot) -> Self {
        let active = snapshot.active_connections;
        let upload = snapshot.total_upload_bytes;
        let download = snapshot.total_download_bytes;
        let upload_packets = snapshot.total_upload_packets;
        let download_packets = snapshot.total_download_packets;
        snapshot.active_connections = 0;
        snapshot.active_peers = 0;
        Self {
            base: RwLock::new(snapshot),
            active: AtomicU64::new(active),
            upload: AtomicU64::new(upload),
            download: AtomicU64::new(download),
            active_peers: AtomicU64::new(0),
            upload_packets: AtomicU64::new(upload_packets),
            download_packets: AtomicU64::new(download_packets),
        }
    }

    async fn snapshot(&self) -> RuntimeSnapshot {
        let mut s = self.base.read().await.clone();
        s.active_connections = self.active.load(Ordering::Relaxed);
        s.active_peers = self.active_peers.load(Ordering::Relaxed);
        if s.active_peers > 0 && s.active_connections == 0 {
            s.active_connections = s.active_peers;
        }
        s.total_upload_bytes = self.upload.load(Ordering::Relaxed);
        s.total_download_bytes = self.download.load(Ordering::Relaxed);
        s.total_upload_packets = self.upload_packets.load(Ordering::Relaxed);
        s.total_download_packets = self.download_packets.load(Ordering::Relaxed);
        s
    }
}

struct RuntimeHandle {
    cancel: watch::Sender<bool>,
    join: JoinHandle<()>,
    shared: Arc<RuntimeShared>,
}

#[derive(Clone)]
struct Manager {
    rules: Arc<RwLock<HashMap<String, Rule>>>,
    runtimes: Arc<Mutex<HashMap<String, RuntimeHandle>>>,
    operation_lock: Arc<Mutex<()>>,
    last_status: Arc<RwLock<HashMap<String, RuntimeSnapshot>>>,
    config_path: PathBuf,
    state_path: PathBuf,
    port_min: u16,
    port_max: u16,
    lan_if: String,
}

impl Manager {
    async fn load(
        config_path: PathBuf,
        state_path: PathBuf,
        port_min: u16,
        port_max: u16,
        lan_if: String,
    ) -> Result<Self> {
        let cfg = load_config(&config_path)?;
        let rules = cfg.rules.into_iter().map(|r| (r.id.clone(), r)).collect();
        Ok(Self {
            rules: Arc::new(RwLock::new(rules)),
            runtimes: Arc::new(Mutex::new(HashMap::new())),
            operation_lock: Arc::new(Mutex::new(())),
            last_status: Arc::new(RwLock::new(HashMap::new())),
            config_path,
            state_path,
            port_min,
            port_max,
            lan_if,
        })
    }

    async fn persist(&self) -> Result<()> {
        let mut rules: Vec<Rule> = self.rules.read().await.values().cloned().collect();
        rules.sort_by_key(|r| r.listen_port);
        let cfg = ConfigFile { version: 1, rules };
        atomic_json_write(&self.config_path, &cfg)
    }

    async fn start_enabled(&self) {
        let ids: Vec<String> = self
            .rules
            .read()
            .await
            .values()
            .filter(|r| r.enabled && !is_expired(r))
            .map(|r| r.id.clone())
            .collect();
        for id in ids {
            if let Err(e) = self.start_rule(&id).await {
                eprintln!("[labrelay] start {} failed: {:#}", id, e);
            }
        }
    }

    async fn upsert(&self, mut rule: Rule) -> Result<Value> {
        normalize_rule(&mut rule);
        validate_rule(&rule, self.port_min, self.port_max)?;
        self.ensure_port_available(&rule).await?;
        let id = rule.id.clone();
        let enabled = rule.enabled;
        let previous = self.rules.read().await.get(&id).cloned();
        if enabled
            && previous
                .as_ref()
                .is_some_and(|old| rules_are_equal(old, &rule))
        {
            let runtime_present = self.runtimes.lock().await.contains_key(&id);
            if runtime_present {
                return Ok(json!({"ok": true, "id": id, "state": "running", "unchanged": true}));
            }
        }
        self.rules.write().await.insert(id.clone(), rule);
        self.persist().await?;
        if enabled {
            if let Err(error) = self.start_rule(&id).await {
                // Do not leave a previously working rule replaced by a failed
                // rebind. Restore its desired configuration and best-effort
                // runtime so Hub reconciliation can observe the real state.
                if let Some(old) = previous {
                    self.rules.write().await.insert(id.clone(), old.clone());
                    self.persist().await?;
                    if old.enabled {
                        let _ = self.start_rule(&id).await;
                    }
                } else {
                    self.rules.write().await.remove(&id);
                    self.persist().await?;
                }
                return Err(error);
            }
        } else {
            self.stop_rule(&id, true).await?;
        }
        Ok(json!({"ok": true, "id": id}))
    }

    async fn start_rule(&self, id: &str) -> Result<Value> {
        let rule = self
            .rules
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| anyhow!("rule not found"))?;
        validate_rule(&rule, self.port_min, self.port_max)?;
        self.ensure_port_available(&rule).await?;
        if is_expired(&rule) {
            self.set_cached_state(&rule, "expired", "rule expired")
                .await;
            bail!("rule expired");
        }
        self.stop_runtime(id, true).await;

        let previous = self.last_status.read().await.get(id).cloned();
        let snapshot = RuntimeSnapshot {
            id: rule.id.clone(),
            name: rule.name.clone(),
            mode: rule.mode.clone(),
            state: "starting".to_string(),
            listen: if rule.kind == "stun" {
                format!("0.0.0.0:{}", rule.listen_port)
            } else {
                format!("[::]:{}", rule.listen_port)
            },
            resolved_target: previous
                .as_ref()
                .map(|x| x.resolved_target.clone())
                .unwrap_or_default(),
            active_connections: 0,
            active_peers: 0,
            total_upload_bytes: previous.as_ref().map(|x| x.total_upload_bytes).unwrap_or(0),
            total_download_bytes: previous
                .as_ref()
                .map(|x| x.total_download_bytes)
                .unwrap_or(0),
            total_upload_packets: previous
                .as_ref()
                .map(|x| x.total_upload_packets)
                .unwrap_or(0),
            total_download_packets: previous
                .as_ref()
                .map(|x| x.total_download_packets)
                .unwrap_or(0),
            started_at: Some(now_epoch()),
            expires_at: rule.expires_at,
            last_resolved_at: None,
            last_error: String::new(),
            public_endpoint: previous
                .as_ref()
                .map(|x| x.public_endpoint.clone())
                .unwrap_or_default(),
            public_ip: previous
                .as_ref()
                .map(|x| x.public_ip.clone())
                .unwrap_or_default(),
            public_port: previous.as_ref().map(|x| x.public_port).unwrap_or(0),
            mapping_updated_at: previous.as_ref().and_then(|x| x.mapping_updated_at),
        };
        let shared = Arc::new(RuntimeShared::new(snapshot));
        let target = Arc::new(RwLock::new(
            resolve_rule_target(&rule, &self.lan_if).await.ok(),
        ));
        update_target_status(&shared, &rule, target.read().await.clone(), None).await;

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let shared_task = shared.clone();
        let target_task = target.clone();
        let rule_task = rule.clone();
        let lan_if = self.lan_if.clone();
        let join = match rule.transport_protocol.as_str() {
            "TCP" => match if rule.kind == "stun" {
                create_ipv4_listener(rule.listen_port)
            } else {
                create_ipv6_listener(rule.listen_port)
            } {
                Ok(listener) => tokio::spawn(async move {
                    run_tcp_listener(
                        listener,
                        rule_task,
                        lan_if,
                        target_task,
                        shared_task,
                        cancel_rx,
                    )
                    .await;
                }),
                Err(error) => {
                    self.set_cached_state(&rule, "error", &error.to_string())
                        .await;
                    return Err(error);
                }
            },
            "UDP" => match if rule.kind == "stun" {
                create_ipv4_udp_listener(rule.listen_port)
            } else {
                create_ipv6_udp_listener(rule.listen_port)
            } {
                Ok(socket) => tokio::spawn(async move {
                    run_udp_listener(
                        socket,
                        rule_task,
                        lan_if,
                        target_task,
                        shared_task,
                        cancel_rx,
                    )
                    .await;
                }),
                Err(error) => {
                    self.set_cached_state(&rule, "error", &error.to_string())
                        .await;
                    return Err(error);
                }
            },
            _ => unreachable!("validate_rule normalizes transportProtocol"),
        };
        self.runtimes.lock().await.insert(
            id.to_string(),
            RuntimeHandle {
                cancel: cancel_tx,
                join,
                shared,
            },
        );
        Ok(json!({"ok": true, "id": id, "state": "running"}))
    }

    async fn ensure_port_available(&self, rule: &Rule) -> Result<()> {
        let conflict = self
            .rules
            .read()
            .await
            .values()
            .find(|other| rules_conflict(other, rule))
            .cloned();
        if let Some(other) = conflict {
            bail!(
                "listen port {} already reserved by {}",
                rule.listen_port,
                other.name
            );
        }
        Ok(())
    }

    async fn stop_runtime(&self, id: &str, mark_stopped: bool) {
        let handle = self.runtimes.lock().await.remove(id);
        if let Some(handle) = handle {
            let RuntimeHandle {
                cancel,
                mut join,
                shared,
            } = handle;
            let _ = cancel.send(true);
            match timeout(Duration::from_secs(3), &mut join).await {
                Ok(_) => {}
                Err(_) => {
                    // A listener that did not acknowledge cancellation must
                    // not keep the port occupied while a replacement binds.
                    join.abort();
                    let _ = join.await;
                }
            }
            let mut snap = shared.snapshot().await;
            if mark_stopped && snap.state != "expired" {
                snap.state = "stopped".to_string();
            }
            snap.active_connections = 0;
            self.last_status.write().await.insert(id.to_string(), snap);
        }
    }

    async fn stop_rule(&self, id: &str, update_config: bool) -> Result<Value> {
        if update_config {
            let mut rules = self.rules.write().await;
            let rule = rules.get_mut(id).ok_or_else(|| anyhow!("rule not found"))?;
            rule.enabled = false;
            drop(rules);
            self.persist().await?;
        }
        self.stop_runtime(id, true).await;
        if let Some(rule) = self.rules.read().await.get(id).cloned() {
            let mut cache = self.last_status.write().await;
            cache
                .entry(id.to_string())
                .or_insert_with(|| RuntimeSnapshot::stopped(&rule))
                .state = "stopped".to_string();
        }
        Ok(json!({"ok": true, "id": id, "state": "stopped"}))
    }

    async fn enable_rule(&self, id: &str) -> Result<Value> {
        {
            let mut rules = self.rules.write().await;
            let rule = rules.get_mut(id).ok_or_else(|| anyhow!("rule not found"))?;
            rule.enabled = true;
        }
        self.persist().await?;
        self.start_rule(id).await
    }

    async fn delete_rule(&self, id: &str) -> Result<Value> {
        self.stop_runtime(id, false).await;
        let removed = self.rules.write().await.remove(id).is_some();
        self.last_status.write().await.remove(id);
        self.persist().await?;
        Ok(json!({"ok": true, "id": id, "deleted": removed}))
    }

    async fn set_cached_state(&self, rule: &Rule, state: &str, err: &str) {
        let mut snap = self
            .last_status
            .read()
            .await
            .get(&rule.id)
            .cloned()
            .unwrap_or_else(|| RuntimeSnapshot::stopped(rule));
        snap.state = state.to_string();
        snap.last_error = err.to_string();
        self.last_status.write().await.insert(rule.id.clone(), snap);
    }

    async fn status_value(&self, scope: Option<&str>) -> Value {
        let rules: Vec<Rule> = self
            .rules
            .read()
            .await
            .values()
            .filter(|rule| scope.map(|value| rule.kind == value).unwrap_or(true))
            .cloned()
            .collect();
        let runtime_refs: HashMap<String, Arc<RuntimeShared>> = self
            .runtimes
            .lock()
            .await
            .iter()
            .map(|(id, h)| (id.clone(), h.shared.clone()))
            .collect();
        let cached = self.last_status.read().await.clone();
        let mut rows = Vec::new();
        for rule in rules {
            let mut snap = if let Some(shared) = runtime_refs.get(&rule.id) {
                shared.snapshot().await
            } else {
                cached
                    .get(&rule.id)
                    .cloned()
                    .unwrap_or_else(|| RuntimeSnapshot::stopped(&rule))
            };
            if is_expired(&rule) && snap.state != "running" {
                snap.state = "expired".to_string();
            }
            rows.push(json!({"rule": rule, "runtime": snap}));
        }
        rows.sort_by_key(|v| {
            v.get("rule")
                .and_then(|r| r.get("listenPort"))
                .and_then(Value::as_u64)
                .unwrap_or(0)
        });
        json!({
            "ok": true,
            "version": VERSION,
            "updatedAt": now_epoch(),
            "portRange": {"min": self.port_min, "max": self.port_max},
            "rules": rows
        })
    }

    async fn write_state(&self) {
        let value = self.status_value(None).await;
        if let Err(e) = atomic_value_write(&self.state_path, &value) {
            eprintln!("[labrelay] write state failed: {:#}", e);
        }
    }
}

fn create_ipv4_listener(port: u16) -> Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket
        .bind(&addr.into())
        .with_context(|| format!("bind 0.0.0.0:{}", port))?;
    socket.listen(128)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

fn create_ipv6_listener(port: u16) -> Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    socket
        .bind(&addr.into())
        .with_context(|| format!("bind [::]:{}", port))?;
    socket.listen(128)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

fn rules_conflict(left: &Rule, right: &Rule) -> bool {
    left.id != right.id
        && left.listen_port == right.listen_port
        && left
            .transport_protocol
            .eq_ignore_ascii_case(&right.transport_protocol)
}

#[derive(Clone)]
struct UdpPeer {
    upstream: Arc<UdpSocket>,
    target: SocketAddr,
    last_seen: Arc<AtomicU64>,
    token: u64,
    cancel: watch::Sender<bool>,
}

fn create_ipv6_udp_listener(port: u16) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    socket
        .bind(&addr.into())
        .with_context(|| format!("bind UDP [::]:{}", port))?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_socket)?)
}

fn create_ipv4_udp_listener(port: u16) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket
        .bind(&addr.into())
        .with_context(|| format!("bind UDP 0.0.0.0:{}", port))?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_socket)?)
}

static STUN_TRANSACTION_COUNTER: AtomicU64 = AtomicU64::new(1);
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

fn stun_binding_request() -> [u8; 20] {
    let mut request = [0u8; 20];
    request[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    request[2..4].copy_from_slice(&0u16.to_be_bytes());
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    let counter = STUN_TRANSACTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    request[8..16].copy_from_slice(&(nanos as u64 ^ counter).to_be_bytes());
    request[16..20].copy_from_slice(&((nanos >> 64) as u32 ^ counter as u32).to_be_bytes());
    request
}

fn parse_stun_mapped_address(message: &[u8]) -> Result<SocketAddr> {
    if message.len() < 20
        || u16::from_be_bytes([message[0], message[1]]) != 0x0101
        || u32::from_be_bytes([message[4], message[5], message[6], message[7]]) != STUN_MAGIC_COOKIE
    {
        bail!("invalid STUN binding response");
    }
    let body_len = u16::from_be_bytes([message[2], message[3]]) as usize;
    if message.len() < 20 + body_len {
        bail!("truncated STUN binding response");
    }
    let mut offset = 20usize;
    while offset + 4 <= 20 + body_len {
        let kind = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let len = u16::from_be_bytes([message[offset + 2], message[offset + 3]]) as usize;
        let value = offset + 4;
        if value + len > message.len() {
            bail!("truncated STUN attribute");
        }
        if matches!(kind, 0x0001 | 0x0020) && len >= 8 && message[value + 1] == 0x01 {
            let mut port = u16::from_be_bytes([message[value + 2], message[value + 3]]);
            let mut octets = [message[value + 4], message[value + 5], message[value + 6], message[value + 7]];
            if kind == 0x0020 {
                port ^= (STUN_MAGIC_COOKIE >> 16) as u16;
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for index in 0..4 {
                    octets[index] ^= cookie[index];
                }
            }
            return Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port)));
        }
        offset = value + ((len + 3) & !3);
    }
    bail!("STUN response has no IPv4 mapped address")
}

async fn mark_stun_mapping(shared: &Arc<RuntimeShared>, endpoint: SocketAddr) {
    let mut base = shared.base.write().await;
    base.state = "mapped".to_string();
    base.public_endpoint = endpoint.to_string();
    base.public_ip = endpoint.ip().to_string();
    base.public_port = endpoint.port();
    base.mapping_updated_at = Some(now_epoch());
    base.last_error.clear();
}

async fn resolve_stun_server(value: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(value)
        .await
        .context("resolve STUN server")?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| anyhow!("STUN server has no IPv4 address"))
}

fn connect_is_in_progress(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    ) {
        return true;
    }
    // BusyBox/musl on the router reports the first nonblocking connect as raw
    // EINPROGRESS (115), rather than mapping it to WouldBlock. EALREADY is
    // also a pending connect, so wait for writable in both cases.
    #[cfg(target_os = "linux")]
    {
        matches!(error.raw_os_error(), Some(114 | 115))
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

async fn connect_tcp_stun(local_port: u16, server: SocketAddr) -> Result<TcpStream> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local_port).into())?;
    let server_addr = SockAddr::from(server);
    match socket.connect(&server_addr) {
        Ok(_) => {}
        Err(error) if connect_is_in_progress(&error) => {}
        Err(error) => return Err(error.into()),
    }
    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;
    timeout(Duration::from_secs(8), stream.writable())
        .await
        .context("STUN TCP connect timeout")??;
    if let Some(error) = stream.take_error()? {
        return Err(error.into());
    }
    Ok(stream)
}

async fn run_tcp_stun_keepalive(
    rule: Rule,
    shared: Arc<RuntimeShared>,
    mut cancel: watch::Receiver<bool>,
) {
    loop {
        if *cancel.borrow() {
            return;
        }
        let result: Result<()> = async {
            let server = resolve_stun_server(&rule.stun_server).await?;
            let mut stream = connect_tcp_stun(rule.listen_port, server).await?;
            let mut tick = tokio::time::interval(Duration::from_secs(20));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = cancel.changed() => {
                        if *cancel.borrow() { return Ok(()); }
                    }
                    _ = tick.tick() => {
                        let request = stun_binding_request();
                        stream.write_all(&request).await?;
                        let mut header = [0u8; 20];
                        timeout(Duration::from_secs(8), stream.read_exact(&mut header))
                            .await.context("STUN TCP response timeout")??;
                        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
                        let mut message = Vec::with_capacity(20 + length);
                        message.extend_from_slice(&header);
                        message.resize(20 + length, 0);
                        timeout(Duration::from_secs(8), stream.read_exact(&mut message[20..]))
                            .await.context("STUN TCP body timeout")??;
                        mark_stun_mapping(&shared, parse_stun_mapped_address(&message)?).await;
                    }
                }
            }
        }.await;
        if let Err(error) = result {
            let mut base = shared.base.write().await;
            if base.public_endpoint.is_empty() {
                base.state = "mapping".to_string();
            }
            base.last_error = error.to_string();
        }
        tokio::select! {
            _ = cancel.changed() => if *cancel.borrow() { return; },
            _ = sleep(Duration::from_secs(5)) => {}
        }
    }
}

async fn run_tcp_listener(
    listener: TcpListener,
    rule: Rule,
    lan_if: String,
    target: Arc<RwLock<Option<IpAddr>>>,
    shared: Arc<RuntimeShared>,
    mut cancel: watch::Receiver<bool>,
) {
    let stun_task = if rule.kind == "stun" {
        Some(tokio::spawn(run_tcp_stun_keepalive(
            rule.clone(),
            shared.clone(),
            cancel.clone(),
        )))
    } else {
        None
    };
    let semaphore = Arc::new(Semaphore::new(rule.max_connections as usize));
    let mut resolve_tick = tokio::time::interval(Duration::from_secs(30));
    resolve_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.changed() => {
                if *cancel.borrow() { break; }
            }
            _ = resolve_tick.tick() => {
                if is_expired(&rule) {
                    let mut base = shared.base.write().await;
                    base.state = "expired".to_string();
                    base.last_error = "rule expired".to_string();
                    break;
                }
                if rule.mode == "6to6" && rule.target_mode == "ipv6_suffix" {
                    match resolve_rule_target(&rule, &lan_if).await {
                        Ok(ip) => {
                            *target.write().await = Some(ip);
                            update_target_status(&shared, &rule, Some(ip), None).await;
                        }
                        Err(e) => {
                            *target.write().await = None;
                            update_target_status(&shared, &rule, None, Some(e.to_string())).await;
                        }
                    }
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        let target_ip = target.read().await.clone();
                        let Some(target_ip) = target_ip else {
                            let mut base = shared.base.write().await;
                            base.state = "waiting_target".to_string();
                            base.last_error = "target IPv6 not resolved".to_string();
                            drop(stream);
                            continue;
                        };
                        let permit = match semaphore.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                let mut base = shared.base.write().await;
                                base.last_error = "maximum connections reached".to_string();
                                drop(stream);
                                continue;
                            }
                        };
                        let shared_conn = shared.clone();
                        let target_addr = SocketAddr::new(target_ip, rule.target_port);
                        let idle = rule.idle_timeout_sec;
                        let preserve_mapped_state = rule.kind == "stun";
                        tokio::spawn(async move {
                            let _permit = permit;
                            shared_conn.active.fetch_add(1, Ordering::Relaxed);
                            let result = proxy_connection(
                                stream,
                                target_addr,
                                idle,
                                shared_conn.clone(),
                                preserve_mapped_state,
                            ).await;
                            shared_conn.active.fetch_sub(1, Ordering::Relaxed);
                            if let Err(e) = result {
                                shared_conn.base.write().await.last_error = e.to_string();
                            }
                        });
                    }
                    Err(e) => {
                        shared.base.write().await.last_error = format!("accept failed: {}", e);
                        sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        }
    }
    if let Some(task) = stun_task {
        task.abort();
        let _ = task.await;
    }
    let mut base = shared.base.write().await;
    if base.state != "expired" {
        base.state = "stopped".to_string();
    }
}

async fn udp_upstream_socket(target: SocketAddr) -> Result<UdpSocket> {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .context("bind UDP upstream socket")?;
    socket.connect(target).await.context("connect UDP target")?;
    Ok(socket)
}

fn udp_peer_expired(last_seen: u64, now: u64, idle_timeout_sec: u64) -> bool {
    now.saturating_sub(last_seen) >= idle_timeout_sec.max(30)
}

fn udp_peer_requires_replacement(peer: &UdpPeer, target: SocketAddr) -> bool {
    peer.target != target
}

async fn run_udp_listener(
    socket: UdpSocket,
    rule: Rule,
    lan_if: String,
    target: Arc<RwLock<Option<IpAddr>>>,
    shared: Arc<RuntimeShared>,
    mut cancel: watch::Receiver<bool>,
) {
    let listener = Arc::new(socket);
    let peers: Arc<Mutex<HashMap<SocketAddr, UdpPeer>>> = Arc::new(Mutex::new(HashMap::new()));
    let next_token = Arc::new(AtomicU64::new(1));
    let mut peer_tasks = JoinSet::new();
    let mut recv_buffer = vec![0u8; 65_535];
    let mut resolve_tick = tokio::time::interval(Duration::from_secs(30));
    resolve_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut stun_tick = tokio::time::interval(Duration::from_secs(20));
    stun_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut stun_server: Option<SocketAddr> = None;

    loop {
        tokio::select! {
            _ = cancel.changed() => {
                if *cancel.borrow() { break; }
            }
            _ = peer_tasks.join_next(), if !peer_tasks.is_empty() => {}
            _ = stun_tick.tick(), if rule.kind == "stun" => {
                match resolve_stun_server(&rule.stun_server).await {
                    Ok(server) => {
                        stun_server = Some(server);
                        let request = stun_binding_request();
                        if let Err(error) = listener.send_to(&request, server).await {
                            shared.base.write().await.last_error = format!("STUN UDP send failed: {}", error);
                        }
                    }
                    Err(error) => {
                        let mut base = shared.base.write().await;
                        if base.public_endpoint.is_empty() { base.state = "mapping".to_string(); }
                        base.last_error = error.to_string();
                    }
                }
            }
            _ = resolve_tick.tick() => {
                if is_expired(&rule) {
                    let mut base = shared.base.write().await;
                    base.state = "expired".to_string();
                    base.last_error = "rule expired".to_string();
                    break;
                }
                if rule.mode == "6to6" && rule.target_mode == "ipv6_suffix" {
                    match resolve_rule_target(&rule, &lan_if).await {
                        Ok(ip) => {
                            *target.write().await = Some(ip);
                            update_target_status(&shared, &rule, Some(ip), None).await;
                        }
                        Err(e) => {
                            *target.write().await = None;
                            update_target_status(&shared, &rule, None, Some(e.to_string())).await;
                        }
                    }
                }
            }
            received = listener.recv_from(&mut recv_buffer) => {
                let (size, client) = match received {
                    Ok(value) => value,
                    Err(error) => {
                        shared.base.write().await.last_error = format!("UDP receive failed: {}", error);
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                if rule.kind == "stun" && stun_server == Some(client) {
                    match parse_stun_mapped_address(&recv_buffer[..size]) {
                        Ok(endpoint) => mark_stun_mapping(&shared, endpoint).await,
                        Err(error) => shared.base.write().await.last_error = error.to_string(),
                    }
                    continue;
                }
                let Some(target_ip) = target.read().await.clone() else {
                    let mut base = shared.base.write().await;
                    base.state = "waiting_target".to_string();
                    base.last_error = "target IPv6 not resolved".to_string();
                    continue;
                };
                let now = now_epoch();
                let target_addr = SocketAddr::new(target_ip, rule.target_port);
                let existing = peers.lock().await.get(&client).cloned();
                if let Some(existing) = existing.as_ref().filter(|peer| udp_peer_requires_replacement(peer, target_addr)) {
                    let _ = existing.cancel.send(true);
                    let removed = {
                        let mut current = peers.lock().await;
                        current.get(&client).is_some_and(|peer| peer.token == existing.token)
                            && current.remove(&client).is_some()
                    };
                    if removed {
                        shared.active_peers.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                let peer = match existing {
                    Some(existing) if !udp_peer_requires_replacement(&existing, target_addr) => {
                        existing.last_seen.store(now, Ordering::Relaxed);
                        Some(existing)
                    }
                    _ => None,
                };
                let peer = if peer.is_some() {
                    peer
                } else {
                    if peers.lock().await.len() >= rule.max_connections as usize {
                        shared.base.write().await.last_error = "maximum UDP peers reached".to_string();
                        None
                    } else {
                        match udp_upstream_socket(target_addr).await {
                            Ok(upstream) => {
                                let (peer_cancel_tx, peer_cancel_rx) = watch::channel(false);
                                let peer = UdpPeer {
                                    upstream: Arc::new(upstream),
                                    target: target_addr,
                                    last_seen: Arc::new(AtomicU64::new(now)),
                                    token: next_token.fetch_add(1, Ordering::Relaxed),
                                    cancel: peer_cancel_tx,
                                };
                                peers.lock().await.insert(client, peer.clone());
                                shared.active_peers.fetch_add(1, Ordering::Relaxed);
                                let task_listener = listener.clone();
                                let task_peers = peers.clone();
                                let task_shared = shared.clone();
                                let task_last_seen = peer.last_seen.clone();
                                let task_upstream = peer.upstream.clone();
                                let task_cancel = peer_cancel_rx;
                                let task_token = peer.token;
                                let idle = rule.idle_timeout_sec;
                                peer_tasks.spawn(async move {
                                    run_udp_peer(
                                        task_listener,
                                        task_upstream,
                                        client,
                                        task_token,
                                        task_last_seen,
                                        task_peers,
                                        task_shared,
                                        idle,
                                        task_cancel,
                                    ).await;
                                });
                                Some(peer)
                            }
                            Err(error) => {
                                shared.base.write().await.last_error = format!("UDP target setup failed: {}", error);
                                None
                            }
                        }
                    }
                };
                if let Some(peer) = peer {
                    match peer.upstream.send(&recv_buffer[..size]).await {
                        Ok(sent) => {
                            peer.last_seen.store(now_epoch(), Ordering::Relaxed);
                            shared.upload.fetch_add(sent as u64, Ordering::Relaxed);
                            shared.upload_packets.fetch_add(1, Ordering::Relaxed);
                            let mut base = shared.base.write().await;
                            if rule.kind != "stun" {
                                base.state = "running".to_string();
                            }
                            base.last_error.clear();
                        }
                        Err(error) => shared.base.write().await.last_error = format!("UDP target send failed: {}", error),
                    }
                }
            }
        }
    }
    peer_tasks.abort_all();
    while peer_tasks.join_next().await.is_some() {}
    peers.lock().await.clear();
    shared.active_peers.store(0, Ordering::Relaxed);
    let mut base = shared.base.write().await;
    if base.state != "expired" {
        base.state = "stopped".to_string();
    }
}

async fn run_udp_peer(
    listener: Arc<UdpSocket>,
    upstream: Arc<UdpSocket>,
    client: SocketAddr,
    token: u64,
    last_seen: Arc<AtomicU64>,
    peers: Arc<Mutex<HashMap<SocketAddr, UdpPeer>>>,
    shared: Arc<RuntimeShared>,
    idle_timeout_sec: u64,
    mut cancel: watch::Receiver<bool>,
) {
    let mut buffer = vec![0u8; 65_535];
    let mut cleanup_tick = tokio::time::interval(Duration::from_secs(5));
    cleanup_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.changed() => {
                if *cancel.borrow() { break; }
            }
            _ = cleanup_tick.tick() => {
                if udp_peer_expired(last_seen.load(Ordering::Relaxed), now_epoch(), idle_timeout_sec) {
                    break;
                }
            }
            received = upstream.recv(&mut buffer) => {
                match received {
                    Ok(size) => match listener.send_to(&buffer[..size], client).await {
                        Ok(sent) => {
                            last_seen.store(now_epoch(), Ordering::Relaxed);
                            shared.download.fetch_add(sent as u64, Ordering::Relaxed);
                            shared.download_packets.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(error) => {
                            shared.base.write().await.last_error = format!("UDP client send failed: {}", error);
                            break;
                        }
                    },
                    Err(error) => {
                        shared.base.write().await.last_error = format!("UDP target receive failed: {}", error);
                        break;
                    }
                }
            }
        }
    }
    let removed = {
        let mut current = peers.lock().await;
        current.get(&client).is_some_and(|peer| peer.token == token)
            && current.remove(&client).is_some()
    };
    if removed {
        shared.active_peers.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn proxy_connection(
    mut client: TcpStream,
    target: SocketAddr,
    idle_timeout_sec: u64,
    shared: Arc<RuntimeShared>,
    preserve_mapped_state: bool,
) -> Result<()> {
    client.set_nodelay(true).ok();
    let mut upstream = timeout(Duration::from_secs(8), TcpStream::connect(target))
        .await
        .context("target connect timeout")??;
    upstream.set_nodelay(true).ok();
    {
        let mut base = shared.base.write().await;
        if !preserve_mapped_state {
            base.state = "running".to_string();
        }
        base.last_error.clear();
    }
    let mut cbuf = vec![0u8; 32 * 1024];
    let mut ubuf = vec![0u8; 32 * 1024];
    let idle = Duration::from_secs(idle_timeout_sec.max(30));
    let mut client_read_closed = false;
    let mut upstream_read_closed = false;
    while !(client_read_closed && upstream_read_closed) {
        tokio::select! {
            read = client.read(&mut cbuf), if !client_read_closed => {
                let n = read?;
                if n == 0 {
                    client_read_closed = true;
                    let _ = upstream.shutdown().await;
                } else {
                    upstream.write_all(&cbuf[..n]).await?;
                    shared.upload.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
            read = upstream.read(&mut ubuf), if !upstream_read_closed => {
                let n = read?;
                if n == 0 {
                    upstream_read_closed = true;
                    let _ = client.shutdown().await;
                } else {
                    client.write_all(&ubuf[..n]).await?;
                    shared.download.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
            _ = sleep(idle) => {
                bail!("connection idle timeout");
            }
        }
    }
    Ok(())
}

async fn update_target_status(
    shared: &Arc<RuntimeShared>,
    rule: &Rule,
    target: Option<IpAddr>,
    error: Option<String>,
) {
    let mut base = shared.base.write().await;
    if let Some(ip) = target {
        base.resolved_target = format_target(ip, rule.target_port);
        base.last_resolved_at = Some(now_epoch());
        base.state = if rule.kind == "stun" { "mapping" } else { "running" }.to_string();
        base.last_error.clear();
    } else {
        base.state = "waiting_target".to_string();
        base.last_error = error.unwrap_or_else(|| "target unavailable".to_string());
    }
}

async fn resolve_rule_target(rule: &Rule, lan_if: &str) -> Result<IpAddr> {
    match rule.mode.as_str() {
        "6to4" | "stun" => {
            let ip = IpAddr::V4(Ipv4Addr::from_str(&rule.target_ipv4)?);
            let iface = lan_if.to_string();
            tokio::task::spawn_blocking(move || ensure_target_uses_lan(ip, &iface)).await??;
            Ok(ip)
        }
        "6to6" if rule.target_mode == "ipv6_full" => {
            let ip = IpAddr::V6(Ipv6Addr::from_str(strip_brackets(&rule.target_ipv6))?);
            let iface = lan_if.to_string();
            tokio::task::spawn_blocking(move || ensure_target_uses_lan(ip, &iface)).await??;
            Ok(ip)
        }
        "6to6" if rule.target_mode == "ipv6_suffix" => {
            let rule = rule.clone();
            let lan_if = lan_if.to_string();
            let ip =
                tokio::task::spawn_blocking(move || resolve_ipv6_suffix(&rule, &lan_if)).await??;
            Ok(ip)
        }
        _ => bail!("unsupported mode/targetMode"),
    }
}

fn ensure_target_uses_lan(ip: IpAddr, lan_if: &str) -> Result<()> {
    let text_ip = ip.to_string();
    let mut command = Command::new("ip");
    if ip.is_ipv6() {
        command.arg("-6");
    }
    let output = command
        .args(["route", "get", text_ip.as_str()])
        .output()
        .or_else(|_| {
            let mut fallback = Command::new("/sbin/ip");
            if ip.is_ipv6() {
                fallback.arg("-6");
            }
            fallback.args(["route", "get", text_ip.as_str()]).output()
        })
        .context("run ip route get")?;
    if !output.status.success() {
        bail!("target route lookup failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.split_whitespace().collect();
    let route_dev = fields
        .iter()
        .position(|x| *x == "dev")
        .and_then(|i| fields.get(i + 1))
        .copied()
        .unwrap_or("");
    if route_dev != lan_if {
        bail!("target is not routed through {}", lan_if);
    }
    Ok(())
}

fn resolve_ipv6_suffix(rule: &Rule, lan_if: &str) -> Result<IpAddr> {
    let suffix = suffix_bytes(&rule.target_ipv6_suffix)?;
    let target_mac = normalize_mac(&rule.target_mac);
    let output = Command::new("ip")
        .args(["-6", "neigh", "show", "dev", lan_if])
        .output()
        .or_else(|_| {
            Command::new("/sbin/ip")
                .args(["-6", "neigh", "show", "dev", lan_if])
                .output()
        })
        .context("run ip -6 neigh")?;
    if !output.status.success() {
        bail!("ip -6 neigh failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let current_prefixes = current_lan_prefixes(lan_if);
    let mut candidates: Vec<(i32, Ipv6Addr, String)> = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let Ok(ip) = Ipv6Addr::from_str(fields[0].split('/').next().unwrap_or("")) else {
            continue;
        };
        if ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_unicast_link_local()
        {
            continue;
        }
        let octets = ip.octets();
        if octets[8..] != suffix[..] {
            continue;
        }
        let mac = fields
            .iter()
            .position(|x| *x == "lladdr")
            .and_then(|i| fields.get(i + 1))
            .map(|x| normalize_mac(x))
            .unwrap_or_default();
        if !target_mac.is_empty() && mac != target_mac {
            continue;
        }
        let state = fields.last().unwrap_or(&"").to_ascii_uppercase();
        if state == "FAILED" || state == "INCOMPLETE" {
            continue;
        }
        let mut score = 0;
        if !target_mac.is_empty() && mac == target_mac {
            score += 100;
        }
        if rule.prefer_current_prefix && current_prefixes.iter().any(|p| octets[..8] == p[..]) {
            score += 30;
        }
        score += match state.as_str() {
            "REACHABLE" => 30,
            "DELAY" | "PROBE" => 20,
            "STALE" | "PERMANENT" => 10,
            _ => 2,
        };
        candidates.push((score, ip, state));
    }
    if candidates.is_empty() {
        bail!("no IPv6 neighbor matches suffix/MAC");
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    if target_mac.is_empty() && candidates.len() > 1 && candidates[0].0 == candidates[1].0 {
        bail!("ambiguous suffix: configure target MAC");
    }
    Ok(IpAddr::V6(candidates[0].1))
}

fn current_lan_prefixes(lan_if: &str) -> Vec<[u8; 8]> {
    let output = Command::new("ip")
        .args(["-6", "addr", "show", "dev", lan_if, "scope", "global"])
        .output()
        .or_else(|_| {
            Command::new("/sbin/ip")
                .args(["-6", "addr", "show", "dev", lan_if, "scope", "global"])
                .output()
        });
    let Ok(output) = output else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = Vec::new();
    for fields in text
        .lines()
        .map(|x| x.split_whitespace().collect::<Vec<_>>())
    {
        if let Some(i) = fields.iter().position(|x| *x == "inet6") {
            if let Some(raw) = fields.get(i + 1) {
                if let Ok(ip) = Ipv6Addr::from_str(raw.split('/').next().unwrap_or("")) {
                    let mut p = [0u8; 8];
                    p.copy_from_slice(&ip.octets()[..8]);
                    if !out.contains(&p) {
                        out.push(p);
                    }
                }
            }
        }
    }
    out
}

fn suffix_bytes(raw: &str) -> Result<[u8; 8]> {
    let text = raw.trim().trim_matches(['[', ']']);
    let normalized = if text.contains("::") {
        text.to_string()
    } else {
        format!("::{}", text.trim_start_matches(':'))
    };
    let ip = Ipv6Addr::from_str(&normalized).context("invalid IPv6 suffix")?;
    let mut out = [0u8; 8];
    out.copy_from_slice(&ip.octets()[8..]);
    if out.iter().all(|b| *b == 0) {
        bail!("IPv6 suffix must not be all zero");
    }
    Ok(out)
}

fn normalize_rule(rule: &mut Rule) {
    rule.kind = rule.kind.trim().to_ascii_lowercase();
    if rule.kind.is_empty() {
        rule.kind = default_rule_kind();
    }
    rule.id = rule.id.trim().to_ascii_lowercase();
    rule.name = rule.name.trim().to_string();
    rule.mode = rule.mode.trim().to_ascii_lowercase();
    rule.target_mode = rule.target_mode.trim().to_ascii_lowercase();
    rule.target_ipv4 = rule.target_ipv4.trim().to_string();
    rule.target_ipv6 = strip_brackets(&rule.target_ipv6).to_string();
    rule.target_ipv6_suffix = rule.target_ipv6_suffix.trim().to_ascii_lowercase();
    rule.target_mac = normalize_mac(&rule.target_mac);
    rule.transport_protocol = rule.transport_protocol.trim().to_ascii_uppercase();
    rule.service_type = rule.service_type.trim().to_string();
    rule.stun_server = rule.stun_server.trim().to_string();
    if rule.kind == "stun" {
        rule.mode = "stun".to_string();
        rule.target_mode = "ipv4".to_string();
        if rule.stun_server.is_empty()
            || (rule.transport_protocol == "TCP" && rule.stun_server == LEGACY_TCP_STUN_SERVER)
        {
            rule.stun_server = default_stun_server(&rule.transport_protocol);
        }
    }
    if rule.transport_protocol.is_empty() {
        rule.transport_protocol = "TCP".to_string();
    }
    rule.max_connections = rule.max_connections.clamp(1, 256);
    rule.idle_timeout_sec = rule.idle_timeout_sec.clamp(30, 3600);
}

fn validate_rule(rule: &Rule, port_min: u16, port_max: u16) -> Result<()> {
    if rule.id.is_empty()
        || !rule
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("invalid rule id");
    }
    if rule.name.is_empty() || rule.name.len() > 64 {
        bail!("invalid rule name");
    }
    if !rule.target_mac.is_empty() {
        let parts: Vec<&str> = rule.target_mac.split(':').collect();
        if parts.len() != 6
            || parts
                .iter()
                .any(|part| part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()))
        {
            bail!("invalid target MAC");
        }
    }
    if rule.listen_port < port_min || rule.listen_port > port_max {
        bail!("listenPort outside allowed range {}-{}", port_min, port_max);
    }
    if rule.target_port == 0 {
        bail!("invalid targetPort");
    }
    if !matches!(rule.transport_protocol.as_str(), "TCP" | "UDP") {
        bail!("unsupported transportProtocol: {}", rule.transport_protocol);
    }
    if !matches!(rule.kind.as_str(), "portmap" | "stun") {
        bail!("unsupported rule kind");
    }
    if rule.kind == "stun" && !rule.stun_server.contains(':') {
        bail!("invalid STUN server");
    }
    if matches!(rule.mode.as_str(), "6to4" | "stun") {
        let ip = Ipv4Addr::from_str(&rule.target_ipv4).context("invalid targetIpv4")?;
        if !(ip.is_private() || ip.is_loopback() || ip.is_link_local()) {
            bail!("target IPv4 must be LAN/private");
        }
    } else if rule.mode == "6to6" {
        match rule.target_mode.as_str() {
            "ipv6_full" => {
                let ip = Ipv6Addr::from_str(strip_brackets(&rule.target_ipv6))
                    .context("invalid targetIpv6")?;
                if ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_unicast_link_local()
                {
                    bail!("invalid target IPv6 scope");
                }
            }
            "ipv6_suffix" => {
                suffix_bytes(&rule.target_ipv6_suffix)?;
            }
            _ => bail!("targetMode must be ipv6_full or ipv6_suffix"),
        }
    } else {
        bail!("mode must be 6to4, 6to6 or stun");
    }
    Ok(())
}

fn is_expired(rule: &Rule) -> bool {
    rule.expires_at
        .map(|x| x > 0 && x <= now_epoch())
        .unwrap_or(false)
}
fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn strip_brackets(v: &str) -> &str {
    v.trim().trim_start_matches('[').trim_end_matches(']')
}
fn normalize_mac(v: &str) -> String {
    v.trim().replace('-', ":").to_ascii_lowercase()
}
fn format_target(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v) => format!("{}:{}", v, port),
        IpAddr::V6(v) => format!("[{}]:{}", v, port),
    }
}

fn load_config(path: &Path) -> Result<ConfigFile> {
    if !path.exists() {
        return Ok(ConfigFile {
            version: 1,
            rules: Vec::new(),
        });
    }
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if text.trim().is_empty() {
        return Ok(ConfigFile {
            version: 1,
            rules: Vec::new(),
        });
    }
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

fn atomic_json_write<T: Serialize>(path: &Path, data: &T) -> Result<()> {
    let value = serde_json::to_value(data)?;
    atomic_value_write(path, &value)
}

fn atomic_value_write(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

async fn handle_command_fixed(manager: Manager, raw: &str) -> Value {
    let v: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return json!({"ok": false, "error": "invalid JSON"}),
    };
    let action = v.get("action").and_then(Value::as_str).unwrap_or("");
    // Dashboard reconciliation can submit the same rule more than once while
    // a previous rebind is still stopping. Serialize mutating RPCs so only
    // one listener owns a port at a time; status/list remain concurrent.
    let _operation_guard = if matches!(action, "upsert" | "start" | "stop" | "delete") {
        Some(manager.operation_lock.lock().await)
    } else {
        None
    };
    let result = match action {
        "status" | "list" => Ok(manager
            .status_value(v.get("scope").and_then(Value::as_str))
            .await),
        "upsert" => {
            match serde_json::from_value::<Rule>(v.get("rule").cloned().unwrap_or(Value::Null)) {
                Ok(rule) => manager.upsert(rule).await,
                Err(e) => Err(e.into()),
            }
        }
        "start" => {
            manager
                .enable_rule(v.get("id").and_then(Value::as_str).unwrap_or(""))
                .await
        }
        "stop" => {
            manager
                .stop_rule(v.get("id").and_then(Value::as_str).unwrap_or(""), true)
                .await
        }
        "delete" => {
            manager
                .delete_rule(v.get("id").and_then(Value::as_str).unwrap_or(""))
                .await
        }
        _ => Err(anyhow!("unknown action")),
    };
    result.unwrap_or_else(|e| json!({"ok": false, "error": e.to_string()}))
}

async fn unix_server_fixed(manager: Manager, socket_path: PathBuf) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if socket_path.exists() {
        let _ = tokio::fs::remove_file(&socket_path).await;
    }
    let listener = UnixListener::bind(&socket_path)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let manager = manager.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = TokioBufReader::new(read_half);
            let mut line = String::new();
            let response = match timeout(Duration::from_secs(5), reader.read_line(&mut line)).await
            {
                Ok(Ok(n)) if n > 0 && line.len() <= 128 * 1024 => {
                    handle_command_fixed(manager, line.trim()).await
                }
                Ok(Ok(_)) => json!({"ok": false, "error": "empty command"}),
                Ok(Err(e)) => json!({"ok": false, "error": e.to_string()}),
                Err(_) => json!({"ok": false, "error": "command timeout"}),
            };
            let _ = write_half
                .write_all(format!("{}\n", response).as_bytes())
                .await;
        });
    }
}

pub(crate) fn ctl_request(socket_path: &Path, request: &Value) -> Result<Value> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
        .with_context(|| format!("connect {}", socket_path.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(format!("{}\n", request).as_bytes())?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(serde_json::from_str(line.trim())?)
}

fn agent_apply(socket_path: &Path, input_path: &Path) -> Result<Value> {
    let root: Value = serde_json::from_slice(&fs::read(input_path)?)?;
    let commands = root
        .get("commands")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut acks = Vec::new();
    for command in commands {
        let command_id = command
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let action = command.get("action").and_then(Value::as_str).unwrap_or("");
        let payload = command.get("payload").cloned().unwrap_or_else(|| json!({}));
        let local = match action {
            "upsert" => {
                json!({"action": "upsert", "rule": payload.get("rule").cloned().unwrap_or(Value::Null)})
            }
            "start" | "stop" | "delete" => {
                json!({"action": action, "id": payload.get("id").and_then(Value::as_str).unwrap_or("")})
            }
            _ => json!({"action": "invalid"}),
        };
        let result = ctl_request(socket_path, &local)
            .unwrap_or_else(|e| json!({"ok": false, "error": e.to_string()}));
        acks.push(json!({"id": command_id, "ok": result.get("ok").and_then(Value::as_bool).unwrap_or(false), "result": result}));
    }
    Ok(json!({"acks": acks, "appliedAt": now_epoch()}))
}

async fn daemon(args: &[String]) -> Result<()> {
    let config =
        PathBuf::from(arg_value(args, "--config").unwrap_or_else(|| DEFAULT_CONFIG.to_string()));
    let socket =
        PathBuf::from(arg_value(args, "--socket").unwrap_or_else(|| DEFAULT_SOCKET.to_string()));
    let state =
        PathBuf::from(arg_value(args, "--state").unwrap_or_else(|| DEFAULT_STATE.to_string()));
    let pid = PathBuf::from(arg_value(args, "--pid").unwrap_or_else(|| DEFAULT_PID.to_string()));
    let port_min = arg_value(args, "--port-min")
        .and_then(|x| x.parse().ok())
        .unwrap_or(20000);
    let port_max = arg_value(args, "--port-max")
        .and_then(|x| x.parse().ok())
        .unwrap_or(20020);
    let lan_if = arg_value(args, "--lan-if").unwrap_or_else(|| "br-lan".to_string());
    if port_min > port_max {
        bail!("invalid port range");
    }
    if let Some(parent) = pid.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pid, std::process::id().to_string())?;

    let manager = Manager::load(config, state, port_min, port_max, lan_if).await?;
    manager.start_enabled().await;
    let manager_state = manager.clone();
    tokio::spawn(async move {
        loop {
            manager_state.write_state().await;
            sleep(Duration::from_secs(5)).await;
        }
    });
    let socket_task = tokio::spawn(unix_server_fixed(manager.clone(), socket.clone()));
    println!(
        "[labrelay] v{} ready socket={} ports={}-{}",
        VERSION,
        socket.display(),
        port_min,
        port_max
    );
    tokio::select! {
        res = socket_task => { res??; }
        _ = tokio::signal::ctrl_c() => {}
    }
    let ids: Vec<String> = manager.rules.read().await.keys().cloned().collect();
    for id in ids {
        manager.stop_runtime(&id, false).await;
    }
    let _ = fs::remove_file(socket);
    let _ = fs::remove_file(pid);
    Ok(())
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|x| x == key)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("daemon") => daemon(&args[1..]).await,
        Some("ctl") => {
            let socket = PathBuf::from(
                arg_value(&args, "--socket").unwrap_or_else(|| DEFAULT_SOCKET.to_string()),
            );
            let mut raw: Option<String> = None;
            let mut i = 1usize;
            while i < args.len() {
                if args[i] == "--socket" {
                    i += 2;
                    continue;
                }
                if !args[i].starts_with("--") {
                    raw = Some(args[i].clone());
                    break;
                }
                i += 1;
            }
            let raw = raw
                .or_else(|| {
                    let mut input = String::new();
                    std::io::stdin().read_to_string(&mut input).ok()?;
                    (!input.trim().is_empty()).then_some(input)
                })
                .ok_or_else(|| anyhow!("missing JSON command"))?;
            println!("{}", ctl_request(&socket, &serde_json::from_str(&raw)?)?);
            Ok(())
        }
        Some("agent-apply") => {
            let socket = PathBuf::from(
                arg_value(&args, "--socket").unwrap_or_else(|| DEFAULT_SOCKET.to_string()),
            );
            let file = arg_value(&args, "--file").ok_or_else(|| anyhow!("missing --file"))?;
            println!("{}", agent_apply(&socket, Path::new(&file))?);
            Ok(())
        }
        Some("agent") => agent::run(&args[1..], false).await,
        Some("agent-once") => agent::run(&args[1..], true).await,
        Some("configure") => agent::configure(&args[1..]),
        Some("doctor") => agent::doctor(&args[1..]).await,
        Some("status") => agent::print_status(&args[1..]),
        Some("test-hub") => agent::test_hub(&args[1..]).await,
        Some("version") | Some("--version") | Some("-V") => {
            println!("labrelay {}", VERSION);
            Ok(())
        }
        _ => {
            eprintln!(
                "{}",
                r#"Usage:
  labrelay daemon [--config PATH] [--socket PATH] [--state PATH]
  labrelay agent|agent-once [--config PATH]
  labrelay configure --hub URL --hook-token TOKEN --name NAME [--config PATH]
  labrelay doctor|status|test-hub [--config PATH]
  labrelay ctl '{"action":"status"}' [--socket PATH]
  labrelay version"#
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv6_suffix64() {
        let bytes = suffix_bytes("::dead:beef").unwrap();
        assert_eq!(bytes, [0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn rejects_all_zero_suffix() {
        assert!(suffix_bytes("::").is_err());
    }

    #[test]
    fn validates_private_6to4_rule() {
        let mut rule = Rule {
            id: "nas-https".into(),
            name: "NAS HTTPS".into(),
            enabled: false,
            mode: "6to4".into(),
            listen_port: 20001,
            target_mode: "ipv4".into(),
            target_ipv4: "192.168.1.50".into(),
            target_port: 443,
            ..Rule::default()
        };
        normalize_rule(&mut rule);
        validate_rule(&rule, 20000, 20020).unwrap();
    }

    #[test]
    fn rejects_public_6to4_target() {
        let rule = Rule {
            id: "bad".into(),
            name: "Bad".into(),
            mode: "6to4".into(),
            listen_port: 20001,
            target_mode: "ipv4".into(),
            target_ipv4: "8.8.8.8".into(),
            target_port: 53,
            ..Rule::default()
        };
        assert!(validate_rule(&rule, 20000, 20020).is_err());
    }

    #[test]
    fn legacy_rule_defaults_to_tcp_and_udp_is_supported() {
        let mut rule = Rule {
            id: "udp".into(),
            name: "UDP".into(),
            mode: "6to4".into(),
            listen_port: 20001,
            target_mode: "ipv4".into(),
            target_ipv4: "192.168.1.50".into(),
            target_port: 53,
            transport_protocol: "udp".into(),
            ..Rule::default()
        };
        normalize_rule(&mut rule);
        assert_eq!(rule.transport_protocol, "UDP");
        validate_rule(&rule, 20000, 20020).unwrap();
        assert_eq!(Rule::default().transport_protocol, "TCP");
    }

    #[test]
    fn udp_6to6_rule_and_config_round_trip_are_supported() {
        let mut rule = Rule {
            id: "udp-v6".into(),
            name: "UDP IPv6".into(),
            enabled: true,
            mode: "6to6".into(),
            listen_port: 20001,
            target_mode: "ipv6_full".into(),
            target_ipv6: "2001:db8::53".into(),
            target_port: 53,
            transport_protocol: "UDP".into(),
            ..Rule::default()
        };
        normalize_rule(&mut rule);
        validate_rule(&rule, 20000, 20020).unwrap();

        let saved = serde_json::to_string(&ConfigFile {
            version: 1,
            rules: vec![rule],
        })
        .unwrap();
        let restored: ConfigFile = serde_json::from_str(&saved).unwrap();
        assert_eq!(restored.rules[0].transport_protocol, "UDP");

        let legacy: ConfigFile = serde_json::from_str(
            r#"{"version":1,"rules":[{"id":"legacy","name":"Legacy","enabled":false,"mode":"6to4","listenPort":20001,"targetMode":"ipv4","targetIpv4":"192.168.1.50","targetPort":53}]}"#,
        )
        .unwrap();
        assert_eq!(legacy.rules[0].transport_protocol, "TCP");
    }

    #[test]
    fn tcp_and_udp_can_share_listen_port_but_same_protocol_cannot() {
        let tcp = Rule {
            id: "tcp".into(),
            name: "TCP".into(),
            listen_port: 20001,
            transport_protocol: "TCP".into(),
            ..Rule::default()
        };
        let udp = Rule {
            id: "udp".into(),
            name: "UDP".into(),
            listen_port: 20001,
            transport_protocol: "UDP".into(),
            ..Rule::default()
        };
        let other_tcp = Rule {
            id: "tcp-2".into(),
            ..tcp.clone()
        };
        assert!(!rules_conflict(&tcp, &udp));
        assert!(rules_conflict(&tcp, &other_tcp));
    }

    #[test]
    fn udp_peer_timeout_uses_the_rule_idle_timeout_with_safe_minimum() {
        assert!(!udp_peer_expired(100, 129, 5));
        assert!(udp_peer_expired(100, 130, 5));
        assert!(!udp_peer_expired(100, 399, 300));
        assert!(udp_peer_expired(100, 400, 300));
    }

    #[tokio::test]
    async fn udp_peer_target_change_requires_replacement() {
        let upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (cancel, _) = watch::channel(false);
        let peer = UdpPeer {
            upstream,
            target: "[2409:8a50:2e40:8dc0::a]:53".parse().unwrap(),
            last_seen: Arc::new(AtomicU64::new(0)),
            token: 1,
            cancel,
        };

        assert!(!udp_peer_requires_replacement(
            &peer,
            "[2409:8a50:2e40:8dc0::a]:53".parse().unwrap(),
        ));
        assert!(udp_peer_requires_replacement(
            &peer,
            "[2409:8a50:2e40:8dc0::b]:53".parse().unwrap(),
        ));
    }

    #[tokio::test]
    async fn udp_6to4_forwards_two_clients_and_counts_packets() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (size, peer) = echo.recv_from(&mut buf).await.unwrap();
                echo.send_to(&buf[..size], peer).await.unwrap();
            }
        });
        let inbound = create_ipv6_udp_listener(0).unwrap();
        let listen_port = inbound.local_addr().unwrap().port();
        let rule = Rule {
            id: "udp-echo".into(),
            name: "UDP echo".into(),
            enabled: true,
            mode: "6to4".into(),
            listen_port,
            target_mode: "ipv4".into(),
            target_ipv4: "127.0.0.1".into(),
            target_port: echo_addr.port(),
            transport_protocol: "UDP".into(),
            max_connections: 4,
            ..Rule::default()
        };
        let shared = Arc::new(RuntimeShared::new(RuntimeSnapshot::stopped(&rule)));
        let target = Arc::new(RwLock::new(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))));
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let forwarder = tokio::spawn(run_udp_listener(
            inbound,
            rule,
            String::new(),
            target,
            shared.clone(),
            cancel_rx,
        ));
        let destination: SocketAddr = format!("[::1]:{listen_port}").parse().unwrap();
        let first = UdpSocket::bind("[::1]:0").await.unwrap();
        let second = UdpSocket::bind("[::1]:0").await.unwrap();
        first.send_to(b"one", destination).await.unwrap();
        second.send_to(b"two", destination).await.unwrap();
        let mut reply = [0u8; 16];
        assert_eq!(
            timeout(Duration::from_secs(2), first.recv_from(&mut reply))
                .await
                .unwrap()
                .unwrap()
                .0,
            3
        );
        assert_eq!(
            timeout(Duration::from_secs(2), second.recv_from(&mut reply))
                .await
                .unwrap()
                .unwrap()
                .0,
            3
        );
        let snapshot = shared.snapshot().await;
        assert_eq!(snapshot.active_peers, 2);
        assert_eq!(snapshot.total_upload_packets, 2);
        assert_eq!(snapshot.total_download_packets, 2);
        let _ = cancel_tx.send(true);
        timeout(Duration::from_secs(2), forwarder)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(shared.snapshot().await.active_peers, 0);
        echo_task.abort();
    }

    #[tokio::test]
    async fn udp_peer_target_change_routes_next_client_packet_to_new_target() {
        let first_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = first_target.local_addr().unwrap().port();
        let second_target = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), target_port))
            .await
            .unwrap();
        let first_task = tokio::spawn(async move {
            let mut buffer = [0u8; 32];
            let (_, peer) = first_target.recv_from(&mut buffer).await.unwrap();
            first_target.send_to(b"first", peer).await.unwrap();
        });
        let second_task = tokio::spawn(async move {
            let mut buffer = [0u8; 32];
            let (_, peer) = second_target.recv_from(&mut buffer).await.unwrap();
            second_target.send_to(b"second", peer).await.unwrap();
        });
        let inbound = create_ipv6_udp_listener(0).unwrap();
        let listen_port = inbound.local_addr().unwrap().port();
        let rule = Rule {
            id: "udp-target-change".into(),
            name: "UDP target change".into(),
            enabled: true,
            mode: "6to4".into(),
            listen_port,
            target_mode: "ipv4".into(),
            target_ipv4: "127.0.0.1".into(),
            target_port,
            transport_protocol: "UDP".into(),
            ..Rule::default()
        };
        let shared = Arc::new(RuntimeShared::new(RuntimeSnapshot::stopped(&rule)));
        let target = Arc::new(RwLock::new(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))));
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let forwarder = tokio::spawn(run_udp_listener(
            inbound,
            rule,
            String::new(),
            target.clone(),
            shared,
            cancel_rx,
        ));
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        let destination = format!("[::1]:{listen_port}");
        let mut reply = [0u8; 16];
        client.send_to(b"before", &destination).await.unwrap();
        let (first_size, _) = timeout(Duration::from_secs(2), client.recv_from(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..first_size], b"first");

        *target.write().await = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
        client.send_to(b"after", &destination).await.unwrap();
        let (second_size, _) = timeout(Duration::from_secs(2), client.recv_from(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..second_size], b"second");

        let _ = cancel_tx.send(true);
        timeout(Duration::from_secs(2), forwarder)
            .await
            .unwrap()
            .unwrap();
        first_task.await.unwrap();
        second_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_6to6_forwards_packets() {
        let echo = UdpSocket::bind("[::1]:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (size, peer) = echo.recv_from(&mut buf).await.unwrap();
                echo.send_to(&buf[..size], peer).await.unwrap();
            }
        });
        let inbound = create_ipv6_udp_listener(0).unwrap();
        let listen_port = inbound.local_addr().unwrap().port();
        let rule = Rule {
            id: "udp-v6-echo".into(),
            name: "UDP IPv6 echo".into(),
            enabled: true,
            mode: "6to6".into(),
            listen_port,
            target_mode: "ipv6_full".into(),
            // A production rule is validated with a stable global address;
            // the local test injects ::1 as the resolved target below.
            target_ipv6: "2001:db8::53".into(),
            target_port: echo_addr.port(),
            transport_protocol: "UDP".into(),
            ..Rule::default()
        };
        validate_rule(&rule, 1, u16::MAX).unwrap();
        let shared = Arc::new(RuntimeShared::new(RuntimeSnapshot::stopped(&rule)));
        let target = Arc::new(RwLock::new(Some(IpAddr::V6(Ipv6Addr::LOCALHOST))));
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let forwarder = tokio::spawn(run_udp_listener(
            inbound,
            rule,
            String::new(),
            target,
            shared.clone(),
            cancel_rx,
        ));
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        client
            .send_to(b"ipv6", format!("[::1]:{listen_port}"))
            .await
            .unwrap();
        let mut reply = [0u8; 16];
        assert_eq!(
            timeout(Duration::from_secs(2), client.recv_from(&mut reply))
                .await
                .unwrap()
                .unwrap()
                .0,
            4
        );
        assert_eq!(shared.snapshot().await.total_download_packets, 1);
        let _ = cancel_tx.send(true);
        timeout(Duration::from_secs(2), forwarder)
            .await
            .unwrap()
            .unwrap();
        echo_task.abort();
    }

    #[test]
    fn stun_xor_mapped_address_is_decoded() {
        let mut response = vec![0u8; 32];
        response[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response[20..22].copy_from_slice(&0x0020u16.to_be_bytes());
        response[22..24].copy_from_slice(&8u16.to_be_bytes());
        response[25] = 0x01;
        let port = 34789u16;
        let encoded_port = port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        response[26..28].copy_from_slice(&encoded_port.to_be_bytes());
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let ip = [203u8, 0, 113, 9];
        for index in 0..4 {
            response[28 + index] = ip[index] ^ cookie[index];
        }
        assert_eq!(parse_stun_mapped_address(&response).unwrap().to_string(), "203.0.113.9:34789");
    }

    #[test]
    fn stun_rule_is_ipv4_and_reserves_a_transport_port() {
        let mut rule = Rule {
            id: "stun-test".into(),
            name: "STUN test".into(),
            kind: "stun".into(),
            target_ipv4: "192.168.5.46".into(),
            target_port: 443,
            listen_port: 20001,
            transport_protocol: "TCP".into(),
            ..Rule::default()
        };
        normalize_rule(&mut rule);
        validate_rule(&rule, 20000, 20020).unwrap();
        assert_eq!(rule.mode, "stun");
        assert_eq!(rule.target_mode, "ipv4");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn tcp_stun_connect_treats_einprogress_as_pending() {
        assert!(connect_is_in_progress(&std::io::Error::from_raw_os_error(115)));
        assert!(connect_is_in_progress(&std::io::Error::from_raw_os_error(114)));
    }

    #[tokio::test]
    async fn tcp_stun_connect_keeps_the_same_port_as_the_listener() {
        let inbound = create_ipv4_listener(0).unwrap();
        let source_port = inbound.local_addr().unwrap().port();
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let stream = timeout(Duration::from_secs(2), connect_tcp_stun(source_port, server_addr))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stream.local_addr().unwrap().port(), source_port);
        let (_, peer) = timeout(Duration::from_secs(2), server.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer.port(), source_port);
        drop(stream);
        drop(inbound);
    }

    #[test]
    fn tcp_stun_uses_a_tcp_capable_default() {
        let mut rule = Rule {
            id: "tcp-default".into(),
            name: "TCP default".into(),
            kind: "stun".into(),
            target_ipv4: "192.168.5.46".into(),
            target_port: 443,
            listen_port: 20001,
            transport_protocol: "TCP".into(),
            stun_server: LEGACY_TCP_STUN_SERVER.into(),
            ..Rule::default()
        };
        normalize_rule(&mut rule);
        assert_eq!(rule.stun_server, DEFAULT_TCP_STUN_SERVER);
    }
}
