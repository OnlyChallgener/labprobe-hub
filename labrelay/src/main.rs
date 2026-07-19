use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::{watch, Mutex, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

mod agent;

const VERSION: &str = "0.2.1";
const DEFAULT_CONFIG: &str = "/etc/labprobe/relay.json";
const DEFAULT_SOCKET: &str = "/tmp/labrelay.sock";
const DEFAULT_STATE: &str = "/tmp/labrelay/state.json";
const DEFAULT_PID: &str = "/tmp/labrelay.pid";

fn default_true() -> bool {
    true
}
fn default_max_connections() -> u32 {
    32
}
fn default_idle_timeout() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Rule {
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
    prefer_current_prefix: bool,
    expires_at: Option<u64>,
    max_connections: u32,
    idle_timeout_sec: u64,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
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
    total_upload_bytes: u64,
    total_download_bytes: u64,
    started_at: Option<u64>,
    expires_at: Option<u64>,
    last_resolved_at: Option<u64>,
    last_error: String,
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
            listen: format!("[::]:{}", rule.listen_port),
            resolved_target: String::new(),
            active_connections: 0,
            total_upload_bytes: 0,
            total_download_bytes: 0,
            started_at: None,
            expires_at: rule.expires_at,
            last_resolved_at: None,
            last_error: String::new(),
        }
    }
}

struct RuntimeShared {
    base: RwLock<RuntimeSnapshot>,
    active: AtomicU64,
    upload: AtomicU64,
    download: AtomicU64,
}

impl RuntimeShared {
    fn new(mut snapshot: RuntimeSnapshot) -> Self {
        let active = snapshot.active_connections;
        let upload = snapshot.total_upload_bytes;
        let download = snapshot.total_download_bytes;
        snapshot.active_connections = 0;
        Self {
            base: RwLock::new(snapshot),
            active: AtomicU64::new(active),
            upload: AtomicU64::new(upload),
            download: AtomicU64::new(download),
        }
    }

    async fn snapshot(&self) -> RuntimeSnapshot {
        let mut s = self.base.read().await.clone();
        s.active_connections = self.active.load(Ordering::Relaxed);
        s.total_upload_bytes = self.upload.load(Ordering::Relaxed);
        s.total_download_bytes = self.download.load(Ordering::Relaxed);
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
        self.rules.write().await.insert(id.clone(), rule);
        self.persist().await?;
        if enabled {
            self.start_rule(&id).await?;
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

        let listener = match create_ipv6_listener(rule.listen_port) {
            Ok(listener) => listener,
            Err(error) => {
                self.set_cached_state(&rule, "error", &error.to_string())
                    .await;
                return Err(error);
            }
        };

        let previous = self.last_status.read().await.get(id).cloned();
        let snapshot = RuntimeSnapshot {
            id: rule.id.clone(),
            name: rule.name.clone(),
            mode: rule.mode.clone(),
            state: "starting".to_string(),
            listen: format!("[::]:{}", rule.listen_port),
            resolved_target: previous
                .as_ref()
                .map(|x| x.resolved_target.clone())
                .unwrap_or_default(),
            active_connections: 0,
            total_upload_bytes: previous.as_ref().map(|x| x.total_upload_bytes).unwrap_or(0),
            total_download_bytes: previous
                .as_ref()
                .map(|x| x.total_download_bytes)
                .unwrap_or(0),
            started_at: Some(now_epoch()),
            expires_at: rule.expires_at,
            last_resolved_at: None,
            last_error: String::new(),
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
        let join = tokio::spawn(async move {
            run_listener(
                listener,
                rule_task,
                lan_if,
                target_task,
                shared_task,
                cancel_rx,
            )
            .await;
        });
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
            .find(|other| other.id != rule.id && other.listen_port == rule.listen_port)
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
            let _ = handle.cancel.send(true);
            let _ = timeout(Duration::from_secs(3), handle.join).await;
            let mut snap = handle.shared.snapshot().await;
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

    async fn status_value(&self) -> Value {
        let rules: Vec<Rule> = self.rules.read().await.values().cloned().collect();
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
        let value = self.status_value().await;
        if let Err(e) = atomic_value_write(&self.state_path, &value) {
            eprintln!("[labrelay] write state failed: {:#}", e);
        }
    }
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

async fn run_listener(
    listener: TcpListener,
    rule: Rule,
    lan_if: String,
    target: Arc<RwLock<Option<IpAddr>>>,
    shared: Arc<RuntimeShared>,
    mut cancel: watch::Receiver<bool>,
) {
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
                        tokio::spawn(async move {
                            let _permit = permit;
                            shared_conn.active.fetch_add(1, Ordering::Relaxed);
                            let result = proxy_connection(stream, target_addr, idle, shared_conn.clone()).await;
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
    let mut base = shared.base.write().await;
    if base.state != "expired" {
        base.state = "stopped".to_string();
    }
}

async fn proxy_connection(
    mut client: TcpStream,
    target: SocketAddr,
    idle_timeout_sec: u64,
    shared: Arc<RuntimeShared>,
) -> Result<()> {
    client.set_nodelay(true).ok();
    let mut upstream = timeout(Duration::from_secs(8), TcpStream::connect(target))
        .await
        .context("target connect timeout")??;
    upstream.set_nodelay(true).ok();
    {
        let mut base = shared.base.write().await;
        base.state = "running".to_string();
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
        base.state = "running".to_string();
        base.last_error.clear();
    } else {
        base.state = "waiting_target".to_string();
        base.last_error = error.unwrap_or_else(|| "target unavailable".to_string());
    }
}

async fn resolve_rule_target(rule: &Rule, lan_if: &str) -> Result<IpAddr> {
    match rule.mode.as_str() {
        "6to4" => {
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
    rule.id = rule.id.trim().to_ascii_lowercase();
    rule.name = rule.name.trim().to_string();
    rule.mode = rule.mode.trim().to_ascii_lowercase();
    rule.target_mode = rule.target_mode.trim().to_ascii_lowercase();
    rule.target_ipv4 = rule.target_ipv4.trim().to_string();
    rule.target_ipv6 = strip_brackets(&rule.target_ipv6).to_string();
    rule.target_ipv6_suffix = rule.target_ipv6_suffix.trim().to_ascii_lowercase();
    rule.target_mac = normalize_mac(&rule.target_mac);
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
    if rule.mode == "6to4" {
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
        bail!("mode must be 6to4 or 6to6");
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
    let result = match action {
        "status" | "list" => Ok(manager.status_value().await),
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
}
