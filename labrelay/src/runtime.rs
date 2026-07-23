use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use serde_json::{json, Map, Value};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::time::{sleep, timeout};

use crate::agent::AgentConfig;

const DEMAND_WAIT_SECONDS: u64 = 55;
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const COMMAND_TIMEOUT: Duration = Duration::from_millis(1_400);

#[derive(Debug, Clone, Default)]
struct Demand {
    sequence: u64,
    router_active: bool,
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

fn decimal(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::Number(number)) => number.as_f64().unwrap_or(0.0),
        Some(Value::String(text)) => text
            .trim()
            .trim_end_matches('%')
            .parse::<f64>()
            .unwrap_or(0.0),
        _ => 0.0,
    }
}

fn first_value<'a>(root: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    match root {
        Value::Object(object) => {
            for key in keys {
                if let Some(value) = object.get(*key) {
                    if !value.is_null() {
                        return Some(value);
                    }
                }
            }
            object.values().find_map(|child| first_value(child, keys))
        }
        Value::Array(items) => items.iter().find_map(|child| first_value(child, keys)),
        _ => None,
    }
}

fn router_metrics(fast: &Value) -> Value {
    let wan_stat = fast.get("wan_stat").or_else(|| fast.get("wanStat"));
    let aggregate = wan_stat
        .and_then(|value| value.get("wans"))
        .or_else(|| wan_stat.and_then(|value| value.get("wan")))
        .or(wan_stat)
        .unwrap_or(&Value::Null);
    json!({
        "uploadBps": number(aggregate.get("up")),
        "downloadBps": number(aggregate.get("down")),
        "totalUploadBytes": number(aggregate.get("total_up").or_else(|| aggregate.get("totalUploadBytes"))),
        "totalDownloadBytes": number(aggregate.get("total_down").or_else(|| aggregate.get("totalDownloadBytes"))),
        "cpuPercent": decimal(first_value(fast, &["cpu_usage", "cpuUsage", "cpuutil"])),
        "memoryPercent": decimal(first_value(fast, &["memutil", "memoryPercent", "memory_usage"])),
        "temperatureC": decimal(first_value(fast, &["temp", "temperature", "temperatureC"])),
        "uptimeSeconds": number(first_value(fast, &["runtime", "uptime", "uptimeSeconds"])),
        "ipv4Connections": number(aggregate.get("ipv4_connection_count")),
        "ipv6Connections": number(aggregate.get("ipv6_connection_count")),
        "ipv4HalfConnections": number(aggregate.get("ipv4_half_connection_count")),
        "ipv6HalfConnections": number(aggregate.get("ipv6_half_connection_count")),
        "cps": number(aggregate.get("cps")),
    })
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

async fn collect_router() -> Result<Value> {
    let fast = dev_sta_json("ws_sysinfo", r#"{"get":"fast"}"#).await?;
    Ok(router_metrics(&fast))
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
        router_active: root
            .get("routerActive")
            .and_then(Value::as_bool)
            .unwrap_or(false),
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
    router: Option<Value>,
    devices: Option<Vec<Value>>,
) -> Result<Demand> {
    let sampled_at_ms = now_ms();
    let mut body = json!({
        "router": config.router_name,
        "agentVersion": env!("CARGO_PKG_VERSION"),
        "sampleEpochMs": sampled_at_ms,
        "source": "relay_local_dev_sta",
    });
    if let Some(metrics) = router {
        body["routerSample"] = metrics;
    }
    if let Some(rows) = devices {
        body["devices"] = Value::Array(rows);
    }
    let url = format!(
        "{}/api/router/realtime/agent/push",
        config.hub_url.trim_end_matches('/')
    );
    let response = client
        .post(url)
        .header("X-LabProbe-Token", &config.hook_token)
        .json(&body)
        .timeout(Duration::from_secs(8))
        .send()
        .await?;
    let status = response.status();
    let root: Value = response.json().await?;
    if !status.is_success() {
        bail!("realtime push HTTP {status}");
    }
    Ok(parse_demand(&root, demand.sequence))
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
    let mut demand = Demand::default();
    let mut consecutive_push_errors = 0u8;
    loop {
        if !demand.router_active && !demand.devices_active {
            match demand_long_poll(&client, &config, demand.sequence).await {
                Ok(next) => demand = next,
                Err(_) => sleep(Duration::from_secs(2)).await,
            }
            continue;
        }

        let started = Instant::now();
        let router_future = async {
            if demand.router_active {
                collect_router().await.ok()
            } else {
                None
            }
        };
        let devices_future = async {
            if demand.devices_active {
                collect_devices().await.ok()
            } else {
                None
            }
        };
        let (mut router_sample, device_sample) = tokio::join!(router_future, devices_future);
        if let (Some(Value::Object(metrics)), Some(devices)) = (&mut router_sample, &device_sample) {
            metrics.insert("onlineDeviceCount".into(), json!(devices.len()));
        }

        if router_sample.is_some() || device_sample.is_some() {
            match push_samples(&client, &config, &demand, router_sample, device_sample).await {
                Ok(next) => {
                    demand = next;
                    consecutive_push_errors = 0;
                }
                Err(_) => {
                    consecutive_push_errors = consecutive_push_errors.saturating_add(1);
                    if consecutive_push_errors >= 5 {
                        demand.router_active = false;
                        demand.devices_active = false;
                    }
                }
            }
        }

        let elapsed = started.elapsed();
        if elapsed < SAMPLE_INTERVAL {
            sleep(SAMPLE_INTERVAL - elapsed).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_router_fast_metrics() {
        let fast = json!({
            "cpu_usage": 12,
            "memutil": "34",
            "temp": 48,
            "runtime": 3600,
            "wan_stat": {"wans": {
                "up": "111", "down": 222,
                "total_up": 333, "total_down": 444,
                "ipv4_connection_count": 7,
                "ipv6_connection_count": 8,
                "ipv4_half_connection_count": 1,
                "ipv6_half_connection_count": 2,
                "cps": 3
            }}
        });
        let result = router_metrics(&fast);
        assert_eq!(result["uploadBps"], 111);
        assert_eq!(result["downloadBps"], 222);
        assert_eq!(result["ipv4Connections"], 7);
        assert_eq!(result["ipv6Connections"], 8);
    }

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
        assert!(result.router_active);
        assert!(!result.devices_active);
    }
}
