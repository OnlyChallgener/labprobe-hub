use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
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
    pub hook_token: String,
    pub router_name: String,
    pub interval_seconds: u64,
    pub status_interval_seconds: u64,
    pub dashboard_interval_seconds: u64,
    pub dashboard_details_interval_seconds: u64,
    pub dashboard_network_interval_seconds: u64,
    pub relay_socket: String,
    pub state_path: String,
    pub log_path: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            version: 1,
            hub_url: String::new(),
            hook_token: String::new(),
            router_name: "router".into(),
            interval_seconds: 15,
            status_interval_seconds: 15,
            dashboard_interval_seconds: 2,
            dashboard_details_interval_seconds: 30,
            dashboard_network_interval_seconds: 60,
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
    last_logged_errors: BTreeMap<String, u64>,
    last_command_at: u64,
    update_state: String,
    update_message: String,
    last_dashboard_fast_at: u64,
    last_dashboard_details_at: u64,
    last_dashboard_network_at: u64,
    last_dashboard_refresh_nonce: u64,
    last_credentials_refresh_nonce: u64,
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
    let mut config: AgentConfig =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    // Runtime state and logs are intentionally volatile to avoid router flash wear.
    config.state_path = DEFAULT_AGENT_STATE.into();
    config.log_path = DEFAULT_AGENT_LOG.into();
    if config.hub_url.trim().is_empty() {
        bail!("Hub URL is empty");
    }
    if config.hook_token.trim().is_empty() {
        bail!("HOOK_TOKEN is empty; configure the agent");
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
        .map(|x| x.len() >= 256 * 1024)
        .unwrap_or(false)
    {
        let rotated = path.with_extension("log.1");
        let _ = fs::remove_file(&rotated);
        let _ = fs::rename(path, rotated);
    }
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let line = format!(
        "{} {} {}\n",
        now_epoch(),
        level,
        redact(message, &config.hook_token)
    );
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        use std::io::Write;
        let _ = file.write_all(line.as_bytes());
    }
}

fn log_limited(config: &AgentConfig, state: &mut AgentState, level: &str, key: &str, message: &str) {
    let now = now_epoch();
    if state
        .last_logged_errors
        .get(key)
        .map(|last| now.saturating_sub(*last) < 300)
        .unwrap_or(false)
    {
        return;
    }
    state.last_logged_errors.insert(key.to_string(), now);
    state.last_logged_errors.retain(|_, last| now.saturating_sub(*last) < 86_400);
    log_line(config, level, message);
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
            .header("X-LabProbe-Token", &config.hook_token)
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
        .header("X-LabProbe-Token", &config.hook_token)
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


fn command_json(program: &str, args: &[&str]) -> Result<Value> {
    let raw = command_output(program, args)?;
    if raw.trim().is_empty() {
        bail!("{} returned empty JSON", program);
    }
    let root: Value = serde_json::from_str(raw.trim())
        .with_context(|| format!("parse {} JSON", program))?;
    if let Some(code) = root.get("rcode").and_then(Value::as_str) {
        if code != "00000000" {
            bail!("{} returned rcode {}", program, code);
        }
    }
    if root.get("message").and_then(Value::as_str) == Some("success") {
        return Ok(root.get("data").cloned().unwrap_or(Value::Null));
    }
    Ok(root)
}

fn number(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::Number(v)) => v.as_f64().unwrap_or(0.0),
        Some(Value::String(v)) => v.trim().trim_end_matches('%').parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn object_path<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = root;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn sanitize_config_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut clean = Map::new();
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                if ["password", "passwd", "pwd", "secret", "token", "privatekey", "private_key", "username", "account"]
                    .iter()
                    .any(|needle| lower.contains(needle))
                {
                    continue;
                }
                clean.insert(key.clone(), sanitize_config_value(child));
            }
            Value::Object(clean)
        }
        Value::Array(items) => Value::Array(items.iter().map(sanitize_config_value).collect()),
        _ => value.clone(),
    }
}

fn router_model() -> String {
    for path in ["/tmp/sysinfo/model", "/etc/board.json"] {
        if path.ends_with("model") {
            if let Ok(text) = fs::read_to_string(path) {
                let value = text.trim();
                if !value.is_empty() {
                    return value.to_string();
                }
            }
        }
    }
    command_json("ubus", &["call", "system", "board"])
        .ok()
        .and_then(|root| root.get("model").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default()
}

fn telemetry_from_fast(fast: &Value, online_devices: usize) -> Value {
    let wan = object_path(fast, &["wan_stat", "wans"])
        .or_else(|| object_path(fast, &["wan_stat", "wan"]))
        .unwrap_or(&Value::Null);
    let upload_raw = number(wan.get("up"));
    let download_raw = number(wan.get("down"));
    json!({
        "cpuPercent": number(fast.get("cpu_usage")).max(number(fast.get("cpuutil"))),
        "memoryPercent": number(fast.get("memutil")),
        "temperatureC": number(fast.get("temp")),
        "temperature2gC": number(fast.get("temp_2g")),
        "temperature5gC": number(fast.get("temp_5g")),
        "uptimeSeconds": number(fast.get("runtime")) as u64,
        "onlineDeviceCount": online_devices,
        "wan": {
            "uploadRaw": upload_raw,
            "downloadRaw": download_raw,
            "uploadBps": (upload_raw * 8.0) as u64,
            "downloadBps": (download_raw * 8.0) as u64
        },
        "connections": {
            "ipv4": number(wan.get("ipv4_connection_count")) as u64,
            "ipv6": number(wan.get("ipv6_connection_count")) as u64,
            "flow": number(wan.get("flow_cnt")) as u64,
            "cps": number(wan.get("cps")) as u64
        }
    })
}

fn csv_values(value: Option<&Value>) -> Value {
    let items = value
        .and_then(Value::as_str)
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| Value::String(item.to_string()))
        .collect::<Vec<_>>();
    Value::Array(items)
}

fn first_array_object<'a>(root: &'a Value, key: &str) -> Option<&'a Value> {
    root.get(key)?.as_array()?.iter().find(|item| item.is_object())
}

fn meaningful(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
        _ => true,
    }
}

fn insert_meaningful(map: &mut Map<String, Value>, key: &str, value: Value) {
    if meaningful(&value) {
        map.insert(key.to_string(), value);
    }
}

fn value_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.trim().to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        _ => String::new(),
    }
}

fn first_text_by_keys(root: &Value, keys: &[&str]) -> String {
    match root {
        Value::Object(map) => {
            for key in keys {
                if let Some(value) = map.get(*key) {
                    let text = value_text(Some(value));
                    if !text.is_empty() {
                        return text;
                    }
                }
            }
            for child in map.values() {
                let text = first_text_by_keys(child, keys);
                if !text.is_empty() {
                    return text;
                }
            }
            String::new()
        }
        Value::Array(items) => items
            .iter()
            .find_map(|child| {
                let text = first_text_by_keys(child, keys);
                if text.is_empty() { None } else { Some(text) }
            })
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn normalized_interface_name(value: &str) -> String {
    let lower = value.trim().to_ascii_lowercase();
    if lower == "wan" || lower == "wan0" {
        "WAN".into()
    } else if lower.starts_with("wan") {
        lower.to_ascii_uppercase()
    } else {
        value.trim().to_string()
    }
}

fn wan_interface_display(network: &Value) -> String {
    let mut names = Vec::<String>::new();
    if let Some(items) = network.get("wan").and_then(Value::as_array) {
        for item in items {
            let raw = value_text(item.get("name").or_else(|| item.get("intf_name")).or_else(|| item.get("ifname")));
            let name = normalized_interface_name(&raw);
            if name.is_empty() {
                continue;
            }
            let status = value_text(item.get("enable").or_else(|| item.get("enabled")).or_else(|| item.get("status"))).to_ascii_lowercase();
            let configured = name == "WAN"
                || matches!(status.as_str(), "1" | "true" | "on" | "up" | "connected")
                || !first_text_by_keys(item, &["username", "account", "ipaddr", "ip", "gateway"]).is_empty();
            if configured && !names.contains(&name) {
                names.push(name);
            }
        }
    }
    if names.is_empty() {
        names.push("WAN".into());
    }
    names.join(" / ")
}

fn details_from_sources(
    slow: Option<&Value>,
    network: Option<&Value>,
    ipinfo: Option<&Value>,
    ap_list: Option<&Value>,
) -> Value {
    let mut details = Map::new();

    let ports = slow
        .and_then(|root| object_path(root, &["port_status", "List"]))
        .cloned()
        .or_else(|| network.and_then(|root| root.get("ports").cloned()));
    if let Some(value) = ports.as_ref().filter(|value| meaningful(value)) {
        details.insert("ports".into(), value.clone());
    }

    if let Some(wireless) = slow.and_then(|root| root.get("wireless")).filter(|value| meaningful(value)) {
        details.insert("wireless".into(), wireless.clone());
    }
    if let Some(network) = network {
        let clean = sanitize_config_value(network);
        if meaningful(&clean) {
            details.insert("network".into(), clean);
        }
    }

    let network_lan = network.and_then(|root| first_array_object(root, "lan"));
    let network_wan = network.and_then(|root| first_array_object(root, "wan"));
    let lan_ip_from_port = ports
        .as_ref()
        .and_then(Value::as_array)
        .and_then(|items| items.iter().find(|item| item.get("name").and_then(Value::as_str) == Some("LAN")))
        .and_then(|item| item.get("ipaddr"))
        .and_then(Value::as_str)
        .unwrap_or("");

    if network_lan.is_some() || !lan_ip_from_port.trim().is_empty() {
        let mut lan = Map::new();
        let lan_ip = network_lan
            .and_then(|item| item.get("ipaddr"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(lan_ip_from_port);
        insert_meaningful(&mut lan, "ipv4", Value::String(lan_ip.to_string()));
        if let Some(item) = network_lan {
            let lan_mac = first_text_by_keys(item, &["mac", "macaddr", "macAddress", "hwaddr"]);
            insert_meaningful(&mut lan, "mac", Value::String(lan_mac));
            insert_meaningful(&mut lan, "netmask", item.get("netmask").cloned().unwrap_or(Value::Null));
            insert_meaningful(
                &mut lan,
                "vlanId",
                item.get("vlanid").or_else(|| item.get("vlanId")).cloned().unwrap_or(Value::Null),
            );
            insert_meaningful(
                &mut lan,
                "dhcpLease",
                item.get("leasetime").or_else(|| item.get("leaseTime")).cloned().unwrap_or(Value::Null),
            );
        }
        if let Some(item) = network_wan {
            insert_meaningful(
                &mut lan,
                "uplink",
                item.get("name").or_else(|| item.get("intf_name")).cloned().unwrap_or(Value::Null),
            );
        }
        if !lan.is_empty() {
            details.insert("lan".into(), Value::Object(lan));
        }
    }

    let wan_info = ipinfo.and_then(|root| root.get("wan"));
    if wan_info.is_some() || slow.and_then(|root| root.get("wan_ip")).is_some() {
        let mut wan = Map::new();
        let wan_ipv4 = wan_info
            .and_then(|item| item.get("ip"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .or_else(|| slow.and_then(|root| root.get("wan_ip")).and_then(Value::as_str))
            .unwrap_or("");
        insert_meaningful(&mut wan, "ipv4", Value::String(wan_ipv4.to_string()));
        if let Some(item) = wan_info {
            insert_meaningful(&mut wan, "gateway", item.get("gateway").cloned().unwrap_or(Value::Null));
            insert_meaningful(&mut wan, "netmask", item.get("mask").cloned().unwrap_or(Value::Null));
            insert_meaningful(&mut wan, "proto", item.get("proto").cloned().unwrap_or(Value::Null));
            insert_meaningful(&mut wan, "mtu", item.get("mtu").cloned().unwrap_or(Value::Null));
            insert_meaningful(&mut wan, "dnsServers", csv_values(item.get("dnsList")));
        } else if let Some(item) = network_wan {
            insert_meaningful(&mut wan, "proto", item.get("proto").cloned().unwrap_or(Value::Null));
            insert_meaningful(&mut wan, "mtu", item.get("mtu").cloned().unwrap_or(Value::Null));
        }
        if let Some(network_root) = network {
            insert_meaningful(
                &mut wan,
                "interfaceDisplay",
                Value::String(wan_interface_display(network_root)),
            );
            let operator = first_text_by_keys(
                network_root,
                &["operator", "isp", "ispName", "serviceName", "carrier", "provider"],
            );
            insert_meaningful(&mut wan, "operator", Value::String(operator));
        }
        if let Some(status) = slow.and_then(|root| root.get("status")) {
            insert_meaningful(&mut wan, "status", status.clone());
        }
        if !wan.is_empty() {
            details.insert("wan".into(), Value::Object(wan));
        }
    }

    let ap = ap_list.and_then(|root| first_array_object(root, "list"));
    if let Some(item) = ap {
        let mut ap_out = Map::new();
        insert_meaningful(&mut ap_out, "networkName", item.get("networkName").cloned().unwrap_or(Value::Null));
        insert_meaningful(&mut ap_out, "hostName", item.get("hostName").cloned().unwrap_or(Value::Null));
        insert_meaningful(
            &mut ap_out,
            "model",
            item.get("devModel").or_else(|| item.get("deviceType")).cloned().unwrap_or(Value::Null),
        );
        insert_meaningful(&mut ap_out, "managementIp", item.get("ip").cloned().unwrap_or(Value::Null));
        insert_meaningful(&mut ap_out, "status", item.get("status").cloned().unwrap_or(Value::Null));
        insert_meaningful(&mut ap_out, "bands", csv_values(item.get("band")));
        insert_meaningful(&mut ap_out, "channels", csv_values(item.get("channel")));
        insert_meaningful(&mut ap_out, "stationCount", item.get("staNum").cloned().unwrap_or(Value::Null));
        insert_meaningful(&mut ap_out, "software", item.get("software").cloned().unwrap_or(Value::Null));
        insert_meaningful(&mut ap_out, "serialNumber", item.get("serialNumber").cloned().unwrap_or(Value::Null));
        insert_meaningful(&mut ap_out, "mac", item.get("mac").cloned().unwrap_or(Value::Null));
        if !ap_out.is_empty() {
            details.insert("ap".into(), Value::Object(ap_out));
        }
    }

    let ap_hostname = ap
        .and_then(|item| item.get("hostName"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| slow.and_then(|root| root.get("hostname")).and_then(Value::as_str));
    let ap_model = ap
        .and_then(|item| item.get("devModel").or_else(|| item.get("deviceType")))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty());
    if ap_hostname.is_some() || ap_model.is_some() || slow.is_some() {
        let mut identity = Map::new();
        if let Some(hostname) = ap_hostname {
            insert_meaningful(&mut identity, "hostname", Value::String(hostname.to_string()));
        }
        let model = ap_model.map(str::to_string).unwrap_or_else(router_model);
        insert_meaningful(&mut identity, "model", Value::String(model));
        if !identity.is_empty() {
            details.insert("identity".into(), Value::Object(identity));
        }
    }

    Value::Object(details)
}

fn collect_dashboard_payload(
    config: &AgentConfig,
    state: &mut AgentState,
    force_details: bool,
    refresh_nonce: u64,
) -> Result<Value> {
    let now = now_epoch();
    let fast = command_json("dev_sta", &["get", "-m", "ws_sysinfo", r#"{"get":"fast"}"#])?;
    state.last_dashboard_fast_at = now;
    let mut payload = json!({
        "router": config.router_name,
        "telemetryAt": now,
        "telemetryEpoch": now,
        "telemetry": telemetry_from_fast(&fast, state.devices.len())
    });

    let details_due = force_details
        || state.last_dashboard_details_at == 0
        || now.saturating_sub(state.last_dashboard_details_at)
            >= config.dashboard_details_interval_seconds.clamp(15, 300);
    let network_due = force_details
        || state.last_dashboard_network_at == 0
        || now.saturating_sub(state.last_dashboard_network_at)
            >= config.dashboard_network_interval_seconds.clamp(30, 600);

    let mut slow_value = None;
    let mut ipinfo_value = None;
    let mut ap_list_value = None;
    if details_due {
        match command_json("dev_sta", &["get", "-m", "ws_sysinfo", r#"{"get":"slow"}"#]) {
            Ok(value) => slow_value = Some(value),
            Err(error) => log_limited(config, state, "WARN", "router-slow", &format!("router slow telemetry skipped: {:#}", error)),
        }
        match command_json("dev_sta", &["get", "-m", "ipinfo", "{}"]) {
            Ok(value) => ipinfo_value = Some(value),
            Err(error) => log_limited(config, state, "WARN", "router-ipinfo", &format!("router ipinfo skipped: {:#}", error)),
        }
        match command_json("dev_sta", &["get", "-m", "ap_list", "{}"]) {
            Ok(value) => ap_list_value = Some(value),
            Err(error) => log_limited(config, state, "WARN", "router-ap-list", &format!("router ap_list skipped: {:#}", error)),
        }
        if slow_value.is_some() || ipinfo_value.is_some() || ap_list_value.is_some() {
            state.last_dashboard_details_at = now;
        }
    }
    let mut network_value = None;
    if network_due {
        match command_json("dev_config", &["get", "-m", "network", "{}"] ) {
            Ok(value) => {
                state.last_dashboard_network_at = now;
                network_value = Some(value);
            }
            Err(error) => log_limited(config, state, "WARN", "router-network", &format!("router network config skipped: {:#}", error)),
        }
    }
    if slow_value.is_some() || network_value.is_some() || ipinfo_value.is_some() || ap_list_value.is_some() {
        payload["details"] = details_from_sources(
            slow_value.as_ref(),
            network_value.as_ref(),
            ipinfo_value.as_ref(),
            ap_list_value.as_ref(),
        );
        payload["detailsAt"] = json!(now);
        payload["detailsEpoch"] = json!(now);
    }
    if refresh_nonce > 0 {
        payload["refreshNonce"] = json!(refresh_nonce);
    }
    Ok(payload)
}

fn collect_router_credentials(config: &AgentConfig, refresh_nonce: u64) -> Result<Value> {
    let network = command_json("dev_config", &["get", "-m", "network", "{}"]) ?;
    let wan_scope = network.get("wan").unwrap_or(&network);
    let lan_scope = network.get("lan").unwrap_or(&network);
    let username = first_text_by_keys(
        wan_scope,
        &["username", "userName", "user_name", "account", "pppoeUser", "pppoe_username", "pppoe_account", "broadbandAccount", "user"],
    );
    let password = first_text_by_keys(
        wan_scope,
        &["password", "passwd", "pwd", "pppoePassword", "pppoe_password", "pppoe_passwd", "broadbandPassword"],
    );
    let lan_mac = first_text_by_keys(lan_scope, &["mac", "macaddr", "macAddress", "hwaddr"]);
    Ok(json!({
        "router": config.router_name,
        "lanMac": lan_mac,
        "username": username,
        "password": password,
        "refreshNonce": refresh_nonce,
    }))
}

async fn sync_router_credentials(
    client: &Client,
    config: &AgentConfig,
    state: &mut AgentState,
    refresh_nonce: u64,
) -> Result<()> {
    let payload = collect_router_credentials(config, refresh_nonce)?;
    post_json(client, config, "/api/router/dashboard/credentials/push", &payload).await?;
    state.last_credentials_refresh_nonce = refresh_nonce;
    Ok(())
}

async fn sync_router_dashboard(client: &Client, config: &AgentConfig, state: &mut AgentState, force: bool) -> Result<()> {
    let payload = collect_dashboard_payload(config, state, force, if force { state.last_dashboard_refresh_nonce } else { 0 })?;
    let response = post_json(client, config, "/api/router/dashboard/push", &payload).await?;
    let requested = response.get("refreshNonce").and_then(Value::as_u64).unwrap_or(0);
    if requested > state.last_dashboard_refresh_nonce {
        let full = collect_dashboard_payload(config, state, true, requested)?;
        post_json(client, config, "/api/router/dashboard/push", &full).await?;
        state.last_dashboard_refresh_nonce = requested;
    }
    let credentials_requested = response
        .get("credentialsRefreshNonce")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if credentials_requested > state.last_credentials_refresh_nonce {
        sync_router_credentials(client, config, state, credentials_requested).await?;
    }
    Ok(())
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
            log_limited(
                config,
                state,
                "WARN",
                "event-retry",
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
        log_limited(config, state, "WARN", "agent-status", &format!("agent status report skipped: {:#}", error));
    }
    match sync_agent_update(client, config, state).await {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(error) => log_limited(config, state, "WARN", "agent-update-check", &format!("agent update check skipped: {:#}", error)),
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
    state.update_state = "idle".into();
    state.update_message.clear();
    Ok(())
}

pub async fn run(args: &[String], once: bool) -> Result<()> {
    let config = load_config(&config_path(args))?;
    let state_path = PathBuf::from(&config.state_path);
    let mut state = load_state(&state_path);
    let client = http_client()?;
    let mut last_agent_cycle_at = 0u64;
    log_line(&config, "INFO", "Rust agent started");
    loop {
        let now = now_epoch();
        let was_unhealthy = !state.last_error.is_empty();
        let mut errors = Vec::new();
        if once || last_agent_cycle_at == 0 || now.saturating_sub(last_agent_cycle_at) >= config.interval_seconds.clamp(5, 300) {
            if let Err(error) = agent_cycle(&client, &config, &mut state).await {
                let text = redact(&format!("{:#}", error), &config.hook_token);
                log_limited(&config, &mut state, "ERROR", "agent-cycle", &text);
                errors.push(text);
            }
            last_agent_cycle_at = now;
        }
        let dashboard_due = once
            || state.last_dashboard_fast_at == 0
            || now.saturating_sub(state.last_dashboard_fast_at)
                >= config.dashboard_interval_seconds.clamp(2, 30);
        if dashboard_due {
            if let Err(error) = sync_router_dashboard(&client, &config, &mut state, once).await {
                let text = redact(&format!("router dashboard: {:#}", error), &config.hook_token);
                log_limited(&config, &mut state, "WARN", "router-dashboard", &text);
                errors.push(text);
            }
        }
        if errors.is_empty() {
            if was_unhealthy {
                log_line(&config, "INFO", "sync recovered");
            }
            state.last_error.clear();
            state.last_success_at = now_epoch();
        } else {
            state.last_error = errors.join(" | ");
        }
        save_json(&state_path, &state)?;
        if once {
            return if state.last_error.is_empty() { Ok(()) } else { Err(anyhow!(state.last_error)) };
        }
        sleep(Duration::from_secs(1)).await;
    }
}

pub fn configure(args: &[String]) -> Result<()> {
    let hub = arg_value(args, "--hub")
        .ok_or_else(|| anyhow!("missing --hub"))?
        .trim_end_matches('/')
        .to_string();
    let hook_token = arg_value(args, "--hook-token")
        .ok_or_else(|| anyhow!("missing --hook-token"))?;
    if hook_token.trim().is_empty() {
        bail!("HOOK_TOKEN is empty");
    }
    let name = arg_value(args, "--name").unwrap_or_else(|| "router".into());
    let path = config_path(args);
    let mut config = if path.exists() {
        serde_json::from_slice::<AgentConfig>(&fs::read(&path)?).unwrap_or_default()
    } else {
        AgentConfig::default()
    };
    config.hub_url = hub;
    config.hook_token = hook_token.trim().to_string();
    config.router_name = name;
    config.state_path = DEFAULT_AGENT_STATE.into();
    config.log_path = DEFAULT_AGENT_LOG.into();
    save_json(&path, &config)?;
    println!("agent configuration saved");
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
