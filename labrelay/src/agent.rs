use anyhow::{anyhow, bail, Context, Result};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

use crate::ctl_request;

const DEFAULT_AGENT_CONFIG: &str = "/etc/labprobe/agent.json";
const DEFAULT_AGENT_STATE: &str = "/tmp/labprobe/agent-state.json";
const DEFAULT_AGENT_LOG: &str = "/tmp/labprobe/labrelay-agent.log";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentConfig {
    pub version: u32,
    pub hub_url: String,
    pub client_token: String,
    pub router_name: String,
    pub interval_seconds: u64,
    pub status_interval_seconds: u64,
    pub relay_socket: String,
    pub state_path: String,
    pub log_path: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            version: 1,
            hub_url: String::new(),
            client_token: String::new(),
            router_name: "Ruijie".into(),
            interval_seconds: 15,
            status_interval_seconds: 15,
            relay_socket: "/tmp/labrelay.sock".into(),
            state_path: DEFAULT_AGENT_STATE.into(),
            log_path: DEFAULT_AGENT_LOG.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct AgentState {
    devices: BTreeMap<String, Value>,
    pending_events: Vec<Value>,
    last_success_at: u64,
    last_error: String,
    last_command_at: u64,
    update_state: String,
    update_message: String,
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|x| x == key)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn config_path(args: &[String]) -> PathBuf {
    PathBuf::from(arg_value(args, "--config").unwrap_or_else(|| DEFAULT_AGENT_CONFIG.into()))
}

fn load_config(path: &Path) -> Result<AgentConfig> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let config: AgentConfig =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    if config.hub_url.trim().is_empty() {
        bail!("Hub URL is empty");
    }
    if config.client_token.trim().is_empty() {
        bail!("client token is empty; re-pair the agent");
    }
    Ok(config)
}

fn save_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(tmp, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn load_state(path: &Path) -> AgentState {
    fs::read(path)
        .ok()
        .and_then(|x| serde_json::from_slice(&x).ok())
        .unwrap_or_default()
}

fn redact(value: &str, token: &str) -> String {
    if token.is_empty() {
        value.to_string()
    } else {
        value.replace(token, "***")
    }
}

fn log_line(config: &AgentConfig, level: &str, message: &str) {
    let path = Path::new(&config.log_path);
    if fs::metadata(path)
        .map(|x| x.len() > 1_000_000)
        .unwrap_or(false)
    {
        let _ = fs::rename(path, path.with_extension("log.1"));
    }
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let line = format!(
        "{} {} {}\n",
        now_epoch(),
        level,
        redact(message, &config.client_token)
    );
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        use std::io::Write;
        let _ = file.write_all(line.as_bytes());
    }
}

fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(12))
        .user_agent(concat!("labrelay/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

async fn post_json(
    client: &Client,
    config: &AgentConfig,
    path: &str,
    body: &Value,
) -> Result<Value> {
    let url = format!("{}{}", config.hub_url.trim_end_matches('/'), path);
    let mut last = None;
    for attempt in 0..3u64 {
        match client
            .post(&url)
            .header("X-LabProbe-Token", &config.client_token)
            .json(body)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                if status.is_success() {
                    return Ok(serde_json::from_str(&text).unwrap_or_else(|_| json!({"ok": true})));
                }
                last = Some(anyhow!(
                    "HTTP {}: {}",
                    status,
                    text.chars().take(160).collect::<String>()
                ));
            }
            Err(error) => last = Some(error.into()),
        }
        sleep(Duration::from_secs(1 << attempt)).await;
    }
    Err(last.unwrap_or_else(|| anyhow!("request failed")))
}

async fn get_json(client: &Client, config: &AgentConfig, path: &str) -> Result<Value> {
    let url = format!("{}{}", config.hub_url.trim_end_matches('/'), path);
    let response = client
        .get(url)
        .header("X-LabProbe-Token", &config.client_token)
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!(
            "HTTP {}: {}",
            status,
            text.chars().take(160).collect::<String>()
        );
    }
    Ok(serde_json::from_str(&text)?)
}

async fn report_agent_status(client: &Client, config: &AgentConfig, state: &AgentState) -> Result<()> {
    post_json(
        client,
        config,
        "/api/router/agent/status",
        &json!({
            "router": config.router_name,
            "version": env!("CARGO_PKG_VERSION"),
            "architecture": std::env::consts::ARCH,
            "updateState": if state.update_state.is_empty() { "idle" } else { &state.update_state },
            "message": state.update_message,
        }),
    )
    .await?;
    Ok(())
}

async fn acknowledge_agent_command(
    client: &Client,
    config: &AgentConfig,
    id: &str,
    state: &str,
    message: &str,
) {
    let _ = post_json(
        client,
        config,
        "/api/router/agent/ack",
        &json!({"id": id, "state": state, "message": message}),
    )
    .await;
}

async fn sync_agent_update(client: &Client, config: &AgentConfig, state: &mut AgentState) -> Result<bool> {
    let router = url_encode(&config.router_name);
    let root = get_json(
        client,
        config,
        &format!("/api/router/agent/commands?router={}", router),
    )
    .await?;
    let commands = root
        .get("commands")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for command in commands {
        if command.get("action").and_then(Value::as_str) != Some("update") {
            continue;
        }
        let id = command.get("id").and_then(Value::as_str).unwrap_or("");
        let repository_root = command
            .get("repositoryRoot")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim_end_matches('/');
        let installer_url = command
            .get("installerUrl")
            .and_then(Value::as_str)
            .unwrap_or("");
        if id.is_empty()
            || !(repository_root.starts_with("https://") || repository_root.starts_with("http://"))
            || !(installer_url.starts_with("https://") || installer_url.starts_with("http://"))
        {
            acknowledge_agent_command(client, config, id, "failed", "更新指令参数无效").await;
            continue;
        }
        let installer_response = match client.get(installer_url).send().await {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                acknowledge_agent_command(client, config, id, "failed", &format!("安装脚本 HTTP {}", response.status())).await;
                continue;
            }
            Err(error) => {
                acknowledge_agent_command(client, config, id, "failed", &format!("下载安装脚本失败：{}", error)).await;
                continue;
            }
        };
        let installer_bytes = match installer_response.bytes().await {
            Ok(bytes) if bytes.starts_with(b"#!/bin/sh") => bytes,
            _ => {
                acknowledge_agent_command(client, config, id, "failed", "安装脚本内容无效").await;
                continue;
            }
        };
        let installer_path = Path::new("/tmp/labprobe-install.sh");
        if let Err(error) = fs::write(installer_path, &installer_bytes)
            .and_then(|_| fs::set_permissions(installer_path, fs::Permissions::from_mode(0o700)))
        {
            acknowledge_agent_command(client, config, id, "failed", &format!("保存安装脚本失败：{}", error)).await;
            continue;
        }
        acknowledge_agent_command(client, config, id, "accepted", "路由器已领取指令，准备升级").await;
        let spawned = Command::new("sh")
            .arg("-c")
            .arg("sleep 2; sh /tmp/labprobe-install.sh upgrade >>/tmp/labprobe/agent-update.log 2>&1")
            .env("LABPROBE_NONINTERACTIVE", "1")
            .env("LABPROBE_UPDATE_ROOT", repository_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match spawned {
            Ok(_) => {
                state.update_state = "scheduled".into();
                state.update_message = "升级任务已启动".into();
                return Ok(true);
            }
            Err(error) => {
                acknowledge_agent_command(client, config, id, "failed", &format!("启动升级失败：{}", error)).await;
            }
        }
    }
    Ok(false)
}

fn command_output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {}", program))?;
    if !output.status.success() {
        bail!(
            "{} failed: {}",
            program,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn collect_user_list() -> Result<Value> {
    let raw = command_output(
        "dev_sta",
        &[
            "get",
            "-m",
            "user_list",
            r#"{"devType":"all","dataType":"timely"}"#,
        ],
    )?;
    if raw.trim().is_empty() {
        bail!("dev_sta returned an empty user_list");
    }
    serde_json::from_str(&raw).context("parse dev_sta user_list")
}

fn normalize_mac(value: &str) -> String {
    let raw = value.trim().replace('-', ":").to_ascii_lowercase();
    if raw.contains(':') || raw.len() != 12 {
        return raw;
    }
    (0..6)
        .map(|i| &raw[i * 2..i * 2 + 2])
        .collect::<Vec<_>>()
        .join(":")
}

fn device_mac(object: &Map<String, Value>) -> Option<String> {
    ["mac", "devMac", "macAddr", "staMac", "deviceMac"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(normalize_mac)
        .filter(|x| !x.is_empty())
}

fn find_devices(value: &Value, output: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(object) => {
            if let Some(mac) = device_mac(object) {
                output.insert(mac, value.clone());
            }
            for child in object.values() {
                find_devices(child, output);
            }
        }
        Value::Array(items) => {
            for child in items {
                find_devices(child, output);
            }
        }
        _ => {}
    }
}

fn router_snapshot(config: &AgentConfig) -> Value {
    let route = command_output("ip", &["-6", "route", "show", "default"]).unwrap_or_default();
    let default_if = route
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|x| x[0] == "dev")
        .map(|x| x[1].to_string())
        .unwrap_or_default();
    let address_text = if default_if.is_empty() {
        String::new()
    } else {
        command_output(
            "ip",
            &["-6", "addr", "show", "dev", &default_if, "scope", "global"],
        )
        .unwrap_or_default()
    };
    let addresses: Vec<Value> = address_text
        .lines()
        .filter_map(|line| {
            let text = line.trim();
            if !text.starts_with("inet6 ") {
                return None;
            }
            let ip = text
                .split_whitespace()
                .nth(1)?
                .split('/')
                .next()?
                .to_string();
            Some(json!({"ip": ip, "name": "WAN IPv6", "primary": true, "source": "rust_agent"}))
        })
        .collect();
    let neighbors_text = command_output("ip", &["-6", "neigh", "show"]).unwrap_or_default();
    let neighbors: Vec<Value> = neighbors_text.lines().filter_map(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let ip = parts.first()?.to_string();
        let mac = parts.windows(2).find(|x| x[0] == "lladdr").map(|x| x[1])?;
        let dev = parts.windows(2).find(|x| x[0] == "dev").map(|x| x[1]).unwrap_or("");
        Some(json!({"ip": ip, "mac": normalize_mac(mac), "dev": dev, "state": parts.last().unwrap_or(&""), "source": "rust_agent"}))
    }).collect();
    json!({"type":"snapshot","ts":now_epoch(),"router":config.router_name,"ipv6_mode":if addresses.is_empty(){"unknown"}else{"native"},
        "ipv6_default_if":default_if,"router_wan6":addresses.first().and_then(|x|x.get("ip")).and_then(Value::as_str).unwrap_or(""),
        "wan_ipv6_list":addresses,"ipv6_neighbors":neighbors})
}

fn event_payload(event: &str, mac: &str, device: &Value) -> Value {
    let mut body = device.as_object().cloned().unwrap_or_default();
    body.insert("type".into(), json!("device_event"));
    body.insert("event".into(), json!(event));
    body.insert("ts".into(), json!(now_epoch()));
    body.insert("mac".into(), json!(mac));
    body.insert("device".into(), device.clone());
    Value::Object(body)
}

fn queue_device_events(state: &mut AgentState, new: &BTreeMap<String, Value>) {
    let online_events = new
        .iter()
        .filter(|(mac, _)| !state.devices.contains_key(*mac))
        .map(|(mac, device)| event_payload("online", mac, device))
        .collect::<Vec<_>>();
    let offline_events = state
        .devices
        .iter()
        .filter(|(mac, _)| !new.contains_key(*mac))
        .map(|(mac, device)| event_payload("offline", mac, device))
        .collect::<Vec<_>>();
    state.pending_events.extend(online_events);
    state.pending_events.extend(offline_events);
    state.devices = new.clone();
}

async fn flush_device_events(client: &Client, config: &AgentConfig, state: &mut AgentState) {
    let pending = std::mem::take(&mut state.pending_events);
    let mut retry = Vec::new();
    for body in pending {
        if let Err(error) = post_json(client, config, "/api/router/push", &body).await {
            let event = body.get("event").and_then(Value::as_str).unwrap_or("device");
            let mac = body.get("mac").and_then(Value::as_str).unwrap_or("");
            log_line(
                config,
                "WARN",
                &format!("{} event queued for retry mac={} error={:#}", event, mac, error),
            );
            retry.push(body);
        }
    }
    state.pending_events = retry;
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
            _ => format!("%{:02X}", b),
        })
        .collect()
}

async fn sync_portmaps(
    client: &Client,
    config: &AgentConfig,
    state: &mut AgentState,
) -> Result<()> {
    let router = url_encode(&config.router_name);
    let root = get_json(
        client,
        config,
        &format!("/api/router/portmaps/commands?router={}&limit=20", router),
    )
    .await?;
    let commands = root
        .get("commands")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !commands.is_empty() {
        let mut acks = Vec::new();
        for command in commands {
            let id = command.get("id").and_then(Value::as_str).unwrap_or("");
            let action = command.get("action").and_then(Value::as_str).unwrap_or("");
            let payload = command.get("payload").cloned().unwrap_or_else(|| json!({}));
            let local = match action {
                "upsert" => {
                    json!({"action":"upsert","rule":payload.get("rule").cloned().unwrap_or(Value::Null)})
                }
                "start" | "stop" | "delete" => {
                    json!({"action":action,"id":payload.get("id").and_then(Value::as_str).unwrap_or("")})
                }
                _ => json!({"action":"invalid"}),
            };
            let result = ctl_request(Path::new(&config.relay_socket), &local)
                .unwrap_or_else(|e| json!({"ok":false,"error":e.to_string()}));
            acks.push(json!({"id":id,"ok":result.get("ok").and_then(Value::as_bool).unwrap_or(false),"result":result}));
        }
        post_json(
            client,
            config,
            &format!("/api/router/portmaps/ack?router={}", router),
            &json!({"acks":acks}),
        )
        .await?;
        state.last_command_at = now_epoch();
    }
    if Path::new(&config.relay_socket).exists() {
        let relay = ctl_request(Path::new(&config.relay_socket), &json!({"action":"status"}))?;
        post_json(
            client,
            config,
            &format!("/api/router/portmaps/status?router={}", router),
            &relay,
        )
        .await?;
    }
    Ok(())
}

async fn agent_cycle(client: &Client, config: &AgentConfig, state: &mut AgentState) -> Result<()> {
    if let Err(error) = report_agent_status(client, config, state).await {
        log_line(config, "WARN", &format!("agent status report skipped: {:#}", error));
    }
    match sync_agent_update(client, config, state).await {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(error) => log_line(config, "WARN", &format!("agent update check skipped: {:#}", error)),
    }
    let user_list = collect_user_list()?;
    let mut current = BTreeMap::new();
    find_devices(&user_list, &mut current);
    queue_device_events(state, &current);
    post_json(client, config, "/hook/ruijie/devices", &user_list).await?;
    flush_device_events(client, config, state).await;
    post_json(client, config, "/api/router/push", &router_snapshot(config)).await?;
    sync_portmaps(client, config, state).await?;
    state.last_success_at = now_epoch();
    state.last_error.clear();
    state.update_state = "idle".into();
    state.update_message.clear();
    Ok(())
}

pub async fn run(args: &[String], once: bool) -> Result<()> {
    let config = load_config(&config_path(args))?;
    let state_path = PathBuf::from(&config.state_path);
    let mut state = load_state(&state_path);
    let client = http_client()?;
    log_line(&config, "INFO", "Rust agent started");
    loop {
        if let Err(error) = agent_cycle(&client, &config, &mut state).await {
            state.last_error = redact(&format!("{:#}", error), &config.client_token);
            log_line(&config, "ERROR", &state.last_error);
        }
        save_json(&state_path, &state)?;
        if once {
            return if state.last_error.is_empty() {
                Ok(())
            } else {
                Err(anyhow!(state.last_error))
            };
        };
        sleep(Duration::from_secs(config.interval_seconds.clamp(5, 300))).await;
    }
}

pub async fn pair(args: &[String]) -> Result<()> {
    let hub = arg_value(args, "--hub")
        .ok_or_else(|| anyhow!("missing --hub"))?
        .trim_end_matches('/')
        .to_string();
    let code = arg_value(args, "--code").ok_or_else(|| anyhow!("missing --code"))?;
    let name = arg_value(args, "--name").unwrap_or_else(|| "Ruijie".into());
    let path = config_path(args);
    let response = http_client()?
        .post(format!("{}/api/pair", hub))
        .json(&json!({"pairingCode":code,"clientType":"agent","clientName":name}))
        .send()
        .await?;
    let status = response.status();
    let root: Value = response.json().await.context("parse pairing response")?;
    if status != StatusCode::OK {
        bail!(
            "pairing failed: {}",
            root.get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        );
    }
    let token = root
        .get("clientToken")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing client token"))?;
    let mut config = if path.exists() {
        serde_json::from_slice::<AgentConfig>(&fs::read(&path)?).unwrap_or_default()
    } else {
        AgentConfig::default()
    };
    config.hub_url = hub;
    config.client_token = token.to_string();
    config.router_name = name;
    save_json(&path, &config)?;
    println!(
        "paired agent id={}",
        root.get("clientId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(8)
            .collect::<String>()
    );
    Ok(())
}

pub async fn doctor(args: &[String]) -> Result<()> {
    let path = config_path(args);
    let config = load_config(&path)?;
    let dev_sta = Command::new("dev_sta").arg("--help").output().is_ok();
    let ip = Command::new("ip").arg("-V").output().is_ok() || Path::new("/sbin/ip").exists();
    let state = load_state(Path::new(&config.state_path));
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"ok":dev_sta&&ip,"config":path,"hub":config.hub_url,"router":config.router_name,"devSta":dev_sta,"ip":ip,"lastSuccessAt":state.last_success_at,"lastError":state.last_error,"token":"***"})
        )?
    );
    if !dev_sta || !ip {
        bail!("router environment check failed");
    }
    Ok(())
}

pub async fn test_hub(args: &[String]) -> Result<()> {
    let config = load_config(&config_path(args))?;
    let root = get_json(&http_client()?, &config, "/api/sync/revision").await?;
    println!("{}", serde_json::to_string_pretty(&root)?);
    Ok(())
}

pub fn print_status(args: &[String]) -> Result<()> {
    let config = load_config(&config_path(args))?;
    let state = load_state(Path::new(&config.state_path));
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"hub":config.hub_url,"router":config.router_name,"lastSuccessAt":state.last_success_at,"lastError":state.last_error,"deviceCount":state.devices.len(),"token":"***"})
        )?
    );
    Ok(())
}
