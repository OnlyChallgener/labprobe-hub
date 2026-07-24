use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use serde_json::{json, Map, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::sync::watch;
use tokio::time::{sleep, timeout, MissedTickBehavior};

use crate::agent::AgentConfig;

const DEMAND_WAIT_SECONDS: u64 = 55;
const DEVICES_SAMPLE_INTERVAL: Duration = Duration::from_secs(2);
const COMMAND_TIMEOUT: Duration = Duration::from_millis(1_400);

#[derive(Debug, Clone, Default)]
struct Demand {
    sequence: u64,
    devices_active: bool,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn decode_wire(mut value: Value) -> Result<Value> {
    for _ in 0..6 {
        if let Some(code) = value.get("rcode").and_then(Value::as_str) {
            if code != "00000000" {
                bail!("dev_sta returned rcode {code}");
            }
        }
        if let Some(code) = value.get("code") {
            let ok = match code {
                Value::Number(number) => number.as_i64() == Some(0),
                Value::String(text) => matches!(text.trim(), "0" | "00000000"),
                _ => true,
            };
            if !ok {
                bail!("dev_sta returned code {code}");
            }
        }
        let unwrap_data = value
            .as_object()
            .map(|object| {
                object.contains_key("data")
                    && (object.get("message").and_then(Value::as_str) == Some("success")
                        || object.keys().all(|key| {
                            matches!(
                                key.as_str(),
                                "data" | "code" | "rcode" | "message" | "msg" | "id" | "error"
                            )
                        }))
            })
            .unwrap_or(false);
        if unwrap_data {
            value = value.get("data").cloned().unwrap_or(Value::Null);
            if let Value::String(text) = &value {
                let trimmed = text.trim();
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    value = serde_json::from_str(trimmed).context("parse nested dev_sta JSON")?;
                }
            }
            continue;
        }
        break;
    }
    Ok(value)
}

async fn dev_sta_json(module: &'static str, data: &'static str) -> Result<Value> {
    let mut command = Command::new("dev_sta");
    command
        .args(["get", "-m", module, data])
        .kill_on_drop(true);
    let output = timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| anyhow!("dev_sta {module} timed out"))??;
    if !output.status.success() {
        bail!(
            "dev_sta {module} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if text.trim().is_empty() {
        bail!("dev_sta {module} returned empty output");
    }
    decode_wire(serde_json::from_str(text.trim()).context("parse dev_sta JSON")?)
}

fn number(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::Number(number)) => number.as_f64().unwrap_or(0.0).max(0.0) as u64,
        Some(Value::String(text)) => text
            .trim()
            .trim_end_matches('%')
            .parse::<f64>()
            .unwrap_or(0.0)
            .max(0.0) as u64,
        _ => 0,
    }
}

fn normalized_mac(value: &str) -> String {
    let raw = value.trim().replace('-', ":").to_ascii_lowercase();
    if raw.contains(':') || raw.len() != 12 {
        return raw;
    }
    (0..6)
        .map(|index| &raw[index * 2..index * 2 + 2])
        .collect::<Vec<_>>()
        .join(":")
}

fn device_array(root: &Value) -> Vec<&Value> {
    if let Some(items) = root.as_array() {
        return items.iter().collect();
    }
    if let Some(object) = root.as_object() {
        for key in ["list", "items", "devices", "users"] {
            if let Some(items) = object.get(key).and_then(Value::as_array) {
                return items.iter().collect();
            }
        }
        if let Some(data) = object.get("data") {
            return device_array(data);
        }
    }
    Vec::new()
}

fn item_number(object: &Map<String, Value>, keys: &[&str]) -> u64 {
    keys.iter()
        .find_map(|key| object.get(*key))
        .map(|value| number(Some(value)))
        .unwrap_or(0)
}

fn device_rows(root: &Value) -> Vec<Value> {
    let mut rows = device_array(root)
        .into_iter()
        .filter_map(|item| item.as_object())
        .filter_map(|object| {
            let mac = ["mac", "devMac", "macAddr", "staMac", "deviceMac"]
                .iter()
                .find_map(|key| object.get(*key).and_then(Value::as_str))
                .map(normalized_mac)
                .unwrap_or_default();
            if mac.is_empty() {
                return None;
            }
            Some(json!({
                "mac": mac,
                "uploadBps": item_number(object, &[
                    "realtimeUploadBytes", "realtimeUpBytes", "realtimeUpload",
                    "flowUp", "uploadBps", "upSpeed", "txSpeed", "tx_rate"
                ]),
                "downloadBps": item_number(object, &[
                    "realtimeDownloadBytes", "realtimeDownBytes", "realtimeDownload",
                    "flowDown", "downloadBps", "downSpeed", "rxSpeed", "rx_rate"
                ]),
                "connectionCount": item_number(object, &[
                    "connectionCount", "flow_cnt", "flowCnt", "connCount", "connections"
                ]),
            }))
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left.get("mac")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(right.get("mac").and_then(Value::as_str).unwrap_or(""))
    });
    rows
}

async fn collect_devices() -> Result<Vec<Value>> {
    let devices = dev_sta_json(
        "user_list",
        r#"{"devType":"all","dataType":"timely"}"#,
    )
    .await?;
    Ok(device_rows(&devices))
}

fn parse_demand(root: &Value, fallback_sequence: u64) -> Demand {
    Demand {
        sequence: root
            .get("sequence")
            .and_then(Value::as_u64)
            .unwrap_or(fallback_sequence),
        devices_active: root
            .get("devicesActive")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

async fn demand_long_poll(client: &Client, config: &AgentConfig, sequence: u64) -> Result<Demand> {
    let url = format!(
        "{}/api/router/realtime/agent/demand?router={}&since={}&wait={}",
        config.hub_url.trim_end_matches('/'),
        url_encode(&config.router_name),
        sequence,
        DEMAND_WAIT_SECONDS,
    );
    let response = client
        .get(url)
        .header("X-LabProbe-Token", &config.hook_token)
        .timeout(Duration::from_secs(DEMAND_WAIT_SECONDS + 10))
        .send()
        .await?;
    let status = response.status();
    let root: Value = response.json().await?;
    if !status.is_success() {
        bail!("realtime demand HTTP {status}");
    }
    Ok(parse_demand(&root, sequence))
}

async fn push_samples(
    client: &Client,
    config: &AgentConfig,
    demand: &Demand,
    devices: Vec<Value>,
) -> Result<Demand> {
    let sampled_at_ms = now_ms();
    let mut body = json!({
        "router": config.router_name,
        "agentVersion": env!("CARGO_PKG_VERSION"),
        "sampleEpochMs": sampled_at_ms,
        "source": "relay_local_dev_sta",
    });
    body["devices"] = Value::Array(devices);
    let url = format!(
        "{}/api/router/realtime/agent/push",
        config.hub_url.trim_end_matches('/')
    );
    let response = client
        .post(url)
        .header("X-LabProbe-Token", &config.hook_token)
        .json(&body)
        .timeout(Duration::from_millis(900))
        .send()
        .await?;
    let status = response.status();
    let root: Value = response.json().await?;
    if !status.is_success() {
        bail!("realtime push HTTP {status}");
    }
    Ok(parse_demand(&root, demand.sequence))
}

async fn demand_lane(client: Client, config: AgentConfig, demand_tx: watch::Sender<Demand>) {
    let mut sequence = 0u64;
    loop {
        let currently_active = {
            let demand = demand_tx.borrow();
            demand.devices_active
        };
        if currently_active {
            sleep(Duration::from_secs(2)).await;
        }
        match demand_long_poll(&client, &config, sequence).await {
            Ok(next) => {
                sequence = next.sequence;
                let _ = demand_tx.send(next);
            }
            Err(_) => {
                let _ = demand_tx.send(Demand {
                    sequence,
                    ..Demand::default()
                });
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn devices_lane(client: Client, config: AgentConfig, demand_rx: watch::Receiver<Demand>) {
    let mut tick = tokio::time::interval(DEVICES_SAMPLE_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let demand = demand_rx.borrow().clone();
        if !demand.devices_active {
            continue;
        }
        if let Ok(sample) = collect_devices().await {
            let _ = push_samples(&client, &config, &demand, sample).await;
        }
    }
}

pub async fn run(config: AgentConfig) {
    let client = match Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(70))
        .user_agent(concat!("labrelay-runtime/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(_) => return,
    };
    let (demand_tx, demand_rx) = watch::channel(Demand::default());
    tokio::join!(
        demand_lane(client.clone(), config.clone(), demand_tx),
        devices_lane(client, config, demand_rx),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_small_device_runtime_fields() {
        let result = device_rows(&json!({"list": [{
            "mac": "AA-BB-CC-DD-EE-FF",
            "flowUp": "1234",
            "flowDown": 5678,
            "flow_cnt": "9",
            "name": "ignored"
        }]}));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(result[0]["uploadBps"], 1234);
        assert_eq!(result[0]["downloadBps"], 5678);
        assert_eq!(result[0]["connectionCount"], 9);
        assert!(result[0].get("name").is_none());
    }

    #[test]
    fn parses_demand_flags() {
        let result = parse_demand(
            &json!({"sequence": 5, "routerActive": true, "devicesActive": false}),
            1,
        );
        assert_eq!(result.sequence, 5);
        assert!(!result.devices_active);
    }
}
