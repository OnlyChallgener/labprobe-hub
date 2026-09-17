use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CONFIG: &str = "child_guard";
const VERIFY_TIMEOUT: Duration = Duration::from_secs(14);
static ID_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct UciSection {
    kind: String,
    name: String,
    options: BTreeMap<String, String>,
    lists: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Default)]
struct Snapshot {
    sections: Vec<UciSection>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct DeviceIdentity {
    device_type: String,
    manufacturer: String,
    hostname: String,
    recommended_name: String,
    user_defined_name: String,
    os: String,
}

impl Snapshot {
    fn sections_of(&self, kind: &str) -> impl Iterator<Item = &UciSection> {
        self.sections
            .iter()
            .filter(move |section| section.kind == kind)
    }

    fn named(&self, name: &str) -> Option<&UciSection> {
        self.sections.iter().find(|section| section.name == name)
    }

    fn user(&self, uid: &str) -> Option<&UciSection> {
        self.sections_of("user")
            .find(|section| section.name.eq_ignore_ascii_case(uid))
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quoted {
            escaped = true;
        } else if ch == '\'' {
            quoted = !quoted;
        } else if ch.is_whitespace() && !quoted {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn parse_uci_export(raw: &str) -> Snapshot {
    let mut snapshot = Snapshot::default();
    let mut current: Option<UciSection> = None;
    for line in raw.lines() {
        let words = shell_words(line.trim());
        if words.is_empty() {
            continue;
        }
        match words[0].as_str() {
            "config" if words.len() >= 3 => {
                if let Some(section) = current.take() {
                    snapshot.sections.push(section);
                }
                current = Some(UciSection {
                    kind: words[1].clone(),
                    name: words[2].clone(),
                    ..UciSection::default()
                });
            }
            "option" if words.len() >= 3 => {
                if let Some(section) = current.as_mut() {
                    section
                        .options
                        .insert(words[1].clone(), words[2..].join(" "));
                }
            }
            "list" if words.len() >= 3 => {
                if let Some(section) = current.as_mut() {
                    section
                        .lists
                        .entry(words[1].clone())
                        .or_default()
                        .push(words[2..].join(" "));
                }
            }
            _ => {}
        }
    }
    if let Some(section) = current {
        snapshot.sections.push(section);
    }
    snapshot
}

fn command_output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))?;
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
    let output = command_output(program, args)?;
    if output.trim().is_empty() {
        return Ok(json!({"ok": true}));
    }
    serde_json::from_str(output.trim()).with_context(|| format!("parse {program} JSON"))
}

fn load_snapshot() -> Result<Snapshot> {
    let output = command_output("uci", &["-q", "export", CONFIG])?;
    Ok(parse_uci_export(&output))
}

fn ubus_show(object: &str) -> Result<Value> {
    command_json("ubus", &["call", object, "show", "{}"])
}

fn normalize_mac(value: &str) -> String {
    let compact = value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| !matches!(ch, ':' | '-' | '.'))
        .collect::<String>();
    if compact.len() == 12 && compact.chars().all(|ch| ch.is_ascii_hexdigit()) {
        compact
            .as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8_lossy(pair).to_string())
            .collect::<Vec<_>>()
            .join(":")
    } else {
        value.trim().to_ascii_lowercase()
    }
}

fn parse_device_identities(value: &Value) -> BTreeMap<String, DeviceIdentity> {
    value
        .get("devices")
        .and_then(Value::as_array)
        .map(|devices| {
            devices
                .iter()
                .filter_map(|device| {
                    let mac = normalize_mac(device.get("mac")?.as_str()?);
                    if mac.is_empty() {
                        return None;
                    }
                    let text = |key: &str| {
                        device
                            .get(key)
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .trim()
                            .to_string()
                    };
                    Some((
                        mac,
                        DeviceIdentity {
                            device_type: text("type"),
                            manufacturer: text("manufac"),
                            hostname: text("hostname"),
                            recommended_name: text("recomd"),
                            user_defined_name: text("user_define"),
                            os: text("os"),
                        },
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn query_device_identities(snapshot: &Snapshot) -> Result<BTreeMap<String, DeviceIdentity>> {
    let macs = snapshot
        .sections_of("user")
        .flat_map(|user| user.lists.get("mac").into_iter().flatten())
        .map(|mac| normalize_mac(mac))
        .filter(|mac| !mac.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if macs.is_empty() {
        return Ok(BTreeMap::new());
    }
    let body = serde_json::to_string(&json!({"mac": macs}))?;
    let response = command_json("ubus", &["call", "dev_identify", "get_dev_info", &body])?;
    if response.get("code").and_then(Value::as_i64).unwrap_or(0) != 0 {
        bail!("dev_identify get_dev_info failed");
    }
    Ok(parse_device_identities(&response))
}

fn is_rdpi_id(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

fn all_rdpi_ids() -> Result<Vec<String>> {
    let output =
        command_output("/usr/sbin/rdpi", &["-t"]).or_else(|_| command_output("rdpi", &["-t"]))?;
    let mut values = BTreeSet::new();
    for token in output.split_whitespace() {
        let candidate = token.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '-');
        if is_rdpi_id(candidate) {
            values.insert(candidate.to_string());
        }
    }
    if values.is_empty() {
        bail!("RDPI application table is empty");
    }
    Ok(values.into_iter().collect())
}

fn json_strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn plan_pid() -> String {
    let counter = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let value = now_epoch().wrapping_mul(1_000_003).wrapping_add(counter);
    format!("{:07x}_labprobe", value & 0x0fff_ffff)
}

fn fnv64(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn public_plan_id(section: &UciSection) -> String {
    section
        .options
        .get("labprobe_plan_id")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| format!("lp_{:016x}", fnv64(&section.name)))
}

fn resolve_policy<'a>(snapshot: &'a Snapshot, uid: &str, plan_id: &str) -> Option<&'a UciSection> {
    let user = snapshot.user(uid)?;
    user.lists.get("policy")?.iter().find_map(|pid| {
        let section = snapshot.named(pid)?;
        (public_plan_id(section) == plan_id).then_some(section)
    })
}

fn parse_times(section: &UciSection) -> BTreeMap<String, Vec<(String, String)>> {
    let mut result: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for value in section.lists.get("time").cloned().unwrap_or_default() {
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() == 3 {
            result
                .entry(parts[0].to_string())
                .or_default()
                .push((parts[1].to_string(), parts[2].to_string()));
        }
    }
    result
}

fn desired_times(
    policy: &UciSection,
    snapshot: &Snapshot,
) -> BTreeMap<String, Vec<(String, String)>> {
    if let Some(raw) = policy.options.get("labprobe_time") {
        if let Ok(Value::Object(days)) = serde_json::from_str::<Value>(raw) {
            let mut result = BTreeMap::new();
            for (day, ranges) in days {
                let parsed = ranges
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|pair| {
                        let values = pair.as_array()?;
                        Some((
                            values.first()?.as_str()?.to_string(),
                            values.get(1)?.as_str()?.to_string(),
                        ))
                    })
                    .collect::<Vec<_>>();
                if !parsed.is_empty() {
                    result.insert(day, parsed);
                }
            }
            if !result.is_empty() {
                return result;
            }
        }
    }
    policy
        .options
        .get("tr")
        .and_then(|name| snapshot.named(name))
        .map(parse_times)
        .unwrap_or_default()
}

fn times_json(times: &BTreeMap<String, Vec<(String, String)>>) -> Value {
    let mut result = Map::new();
    for (day, ranges) in times {
        result.insert(
            day.clone(),
            Value::Array(
                ranges
                    .iter()
                    .map(|(start, end)| json!([start, end]))
                    .collect(),
            ),
        );
    }
    Value::Object(result)
}

fn applications_metadata(policy: &UciSection, allowed: &[String]) -> Vec<Value> {
    if let Some(raw) = policy.options.get("labprobe_applications") {
        if let Ok(Value::Array(values)) = serde_json::from_str::<Value>(raw) {
            return values;
        }
    }
    allowed
        .iter()
        .map(|rdpi| json!({"id": rdpi, "name": rdpi, "rdpiIds": [rdpi]}))
        .collect()
}

fn allowed_rdpi_ids(policy: &UciSection) -> Vec<String> {
    if let Some(raw) = policy.options.get("labprobe_allowed_rdpi") {
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            return json_strings(Some(&value));
        }
    }
    let listed = policy.lists.get("app").cloned().unwrap_or_default();
    if policy.options.get("type").map(String::as_str) == Some("1") {
        // Original child_guard type=1 stores the effective block complement in
        // sniffer.policy/app. Reconstruct the public allow list when the plan
        // has no LabProbe metadata instead of exposing the complement as if it
        // were selected applications.
        let blocked = listed.into_iter().collect::<BTreeSet<_>>();
        return all_rdpi_ids()
            .map(|all| {
                all.into_iter()
                    .filter(|value| !blocked.contains(value))
                    .collect()
            })
            .unwrap_or_default();
    }
    listed
}

fn plan_value(policy: &UciSection, snapshot: &Snapshot) -> Value {
    let kind = policy
        .options
        .get("type")
        .map(String::as_str)
        .unwrap_or("0");
    let mode = match kind {
        "1" => "app_allowlist",
        "2" => "app_blocklist",
        _ => "internet_window",
    };
    let times = desired_times(policy, snapshot);
    let first = times
        .values()
        .flatten()
        .next()
        .cloned()
        .unwrap_or(("00:00".into(), "23:59".into()));
    let allowed = allowed_rdpi_ids(policy);
    json!({
        "id": public_plan_id(policy),
        "name": policy.options.get("labprobe_name").cloned().unwrap_or_else(|| "上网计划".into()),
        "enabled": policy.options.get("labprobe_enabled").map(|value| value != "0").unwrap_or_else(|| !times.is_empty()),
        "startTime": first.0,
        "endTime": first.1,
        "weekdays": times.keys().cloned().collect::<Vec<_>>(),
        "mode": mode,
        "applications": applications_metadata(policy, &allowed),
        "applicationRdpiIds": allowed,
        "runtimePid": policy.name,
        "source": if policy.options.contains_key("labprobe_plan_id") { "labprobe" } else { "router" },
    })
}

fn user_value(
    user: &UciSection,
    snapshot: &Snapshot,
    identities: &BTreeMap<String, DeviceIdentity>,
) -> Value {
    let policy_count = user
        .lists
        .get("policy")
        .map(|values| values.len())
        .unwrap_or(0);
    let paused_until = user
        .options
        .get("pause")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let blocked_until = user
        .options
        .get("block")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let identity = user
        .lists
        .get("mac")
        .into_iter()
        .flatten()
        .find_map(|mac| identities.get(&normalize_mac(mac)));
    let configured_name = user.options.get("name").map(String::as_str).unwrap_or("");
    let name = [
        configured_name,
        identity
            .map(|value| value.user_defined_name.as_str())
            .unwrap_or(""),
        identity
            .map(|value| value.recommended_name.as_str())
            .unwrap_or(""),
        identity.map(|value| value.hostname.as_str()).unwrap_or(""),
    ]
    .into_iter()
    .find(|value| !value.trim().is_empty())
    .unwrap_or("受保护设备");
    let identity_value = identity.cloned().unwrap_or_default();
    json!({
        "uid": user.name,
        "macs": user.lists.get("mac").cloned().unwrap_or_default(),
        "name": name,
        "iconKey": &identity_value.device_type,
        "deviceType": &identity_value.device_type,
        "recommendedName": identity_value.recommended_name,
        "userDefinedName": identity_value.user_defined_name,
        "manufacturer": identity_value.manufacturer,
        "hostname": identity_value.hostname,
        "os": identity_value.os,
        "identitySource": if identity.is_some() { "dev_identify" } else { "child_guard" },
        "pausedUntilEpoch": paused_until,
        "blockedUntilEpoch": blocked_until,
        "blocked": blocked_until > now_epoch(),
        "planCount": policy_count,
        "appControlSupported": snapshot.named("config").and_then(|config| config.options.get("rdpi_enable")).map(|value| value == "1").unwrap_or(false),
    })
}

fn user_payload(
    snapshot: &Snapshot,
    uid: &str,
    policies: &[UciSection],
    fallback: Option<&Value>,
) -> Result<Value> {
    let user = snapshot.user(uid);
    let fallback_mac = fallback
        .and_then(|value| value.get("deviceMac"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut macs = user
        .and_then(|value| value.lists.get("mac").cloned())
        .unwrap_or_default();
    if macs.is_empty() && !fallback_mac.is_empty() {
        macs.push(fallback_mac.to_ascii_lowercase());
    }
    if macs.is_empty() {
        bail!("device is not registered in child_guard and deviceMac was not supplied");
    }
    let mut policy_values = Vec::new();
    for policy in policies {
        let mut value = json!({
            "id": policy.name,
            "type": policy.options.get("type").cloned().unwrap_or_else(|| "0".into()),
            "tr": times_json(&policy.options.get("tr").and_then(|name| snapshot.named(name)).map(parse_times).unwrap_or_default()),
        });
        if let Some(object) = value.as_object_mut() {
            for (key, list_key) in [
                ("app", "app"),
                ("app_fbt_list", "app_fbt_list"),
                ("url_fbt_list", "url_fbt_list"),
            ] {
                if let Some(items) = policy.lists.get(list_key) {
                    object.insert(key.into(), json!(items));
                }
            }
            if let Some(flag) = policy.options.get("url_fbt_enable") {
                object.insert("url_fbt_enable".into(), json!(flag));
            }
        }
        policy_values.push(value);
    }
    Ok(json!({
        "uid": uid,
        "macs": macs,
        "policies": policy_values,
        "block": user.and_then(|value| value.options.get("block")).cloned().unwrap_or_else(|| "0".into()),
        "pause": user.and_then(|value| value.options.get("pause")).cloned().unwrap_or_else(|| "0".into()),
        "name": user.and_then(|value| value.options.get("name")).cloned()
            .or_else(|| fallback.and_then(|value| value.get("deviceName")).and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| "LabProbe 设备".into()),
    }))
}

fn direct_policy(plan: &Value, public_id: &str) -> Result<UciSection> {
    let mode = plan
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("internet_window");
    let enabled = plan.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let start = plan
        .get("startTime")
        .and_then(Value::as_str)
        .unwrap_or("00:00");
    let end = plan
        .get("endTime")
        .and_then(Value::as_str)
        .unwrap_or("23:59");
    let weekdays = json_strings(plan.get("weekdays"));
    let allowed = json_strings(plan.get("applicationRdpiIds"));
    let mut desired = BTreeMap::new();
    for day in weekdays {
        desired.insert(day, vec![(start.to_string(), end.to_string())]);
    }
    let apps = match mode {
        "app_allowlist" => {
            let allowed_set = allowed.iter().cloned().collect::<BTreeSet<_>>();
            all_rdpi_ids()?
                .into_iter()
                .filter(|value| !allowed_set.contains(value))
                .collect()
        }
        "app_blocklist" => allowed.clone(),
        _ => Vec::new(),
    };
    let pid = plan_pid();
    let mut options = BTreeMap::new();
    options.insert(
        "type".into(),
        match mode {
            "app_allowlist" => "1",
            "app_blocklist" => "2",
            _ => "0",
        }
        .into(),
    );
    options.insert("tr".into(), format!("child_tr_{}", &pid[..7]));
    options.insert("labprobe_plan_id".into(), public_id.into());
    options.insert(
        "labprobe_name".into(),
        plan.get("name")
            .and_then(Value::as_str)
            .unwrap_or("上网计划")
            .into(),
    );
    options.insert(
        "labprobe_enabled".into(),
        if enabled { "1" } else { "0" }.into(),
    );
    options.insert(
        "labprobe_time".into(),
        serde_json::to_string(&times_json(&desired))?,
    );
    options.insert(
        "labprobe_allowed_rdpi".into(),
        serde_json::to_string(&allowed)?,
    );
    let application_metadata = plan
        .get("applications")
        .cloned()
        .unwrap_or_else(|| json!([]));
    options.insert(
        "labprobe_applications".into(),
        serde_json::to_string(&application_metadata)?,
    );
    let mut lists = BTreeMap::new();
    if !apps.is_empty() {
        lists.insert("app".into(), apps);
    }
    let tr_times = if enabled { desired } else { BTreeMap::new() };
    lists.insert(
        "_times".into(),
        tr_times
            .iter()
            .flat_map(|(day, ranges)| ranges.iter().map(move |(a, b)| format!("{day}-{a}-{b}")))
            .collect(),
    );
    Ok(UciSection {
        kind: "policy".into(),
        name: pid,
        options,
        lists,
    })
}

fn policy_with_enabled(policy: &UciSection, snapshot: &Snapshot, enabled: bool) -> UciSection {
    let mut updated = policy.clone();
    updated.options.insert(
        "labprobe_enabled".into(),
        if enabled { "1" } else { "0" }.into(),
    );
    let desired = desired_times(policy, snapshot);
    updated.lists.insert(
        "_times".into(),
        if enabled {
            desired
                .iter()
                .flat_map(|(day, ranges)| ranges.iter().map(move |(a, b)| format!("{day}-{a}-{b}")))
                .collect()
        } else {
            Vec::new()
        },
    );
    updated
}

fn payload_policy(policy: &UciSection, snapshot: &Snapshot) -> UciSection {
    let mut copy = policy.clone();
    let times = copy.lists.remove("_times").unwrap_or_else(|| {
        let enabled = copy
            .options
            .get("labprobe_enabled")
            .map(|value| value != "0")
            .unwrap_or(true);
        if !enabled {
            return Vec::new();
        }
        desired_times(&copy, snapshot)
            .iter()
            .flat_map(|(day, ranges)| {
                ranges
                    .iter()
                    .map(move |(start, end)| format!("{day}-{start}-{end}"))
            })
            .collect()
    });
    let tr_name = copy.options.get("tr").cloned().unwrap_or_default();
    copy.options.insert(
        "_payload_times".into(),
        serde_json::to_string(&times).unwrap_or_else(|_| "[]".into()),
    );
    copy.options.insert("tr".into(), tr_name);
    copy
}

fn user_payload_with_times(
    snapshot: &Snapshot,
    uid: &str,
    policies: &[UciSection],
    fallback: Option<&Value>,
) -> Result<Value> {
    let mut value = user_payload(snapshot, uid, policies, fallback)?;
    if let Some(items) = value.get_mut("policies").and_then(Value::as_array_mut) {
        for (index, item) in items.iter_mut().enumerate() {
            let policy = &policies[index];
            if let Some(raw) = policy.options.get("_payload_times") {
                if let Ok(Value::Array(times)) = serde_json::from_str::<Value>(raw) {
                    let mut days: Map<String, Value> = Map::new();
                    for time in times.iter().filter_map(Value::as_str) {
                        let parts: Vec<&str> = time.split('-').collect();
                        if parts.len() == 3 {
                            days.entry(parts[0].into()).or_insert_with(|| json!([]));
                            if let Some(values) =
                                days.get_mut(parts[0]).and_then(Value::as_array_mut)
                            {
                                values.push(json!([parts[1], parts[2]]));
                            }
                        }
                    }
                    item["tr"] = Value::Object(days);
                }
            }
        }
    }
    Ok(value)
}

fn write_user(
    snapshot: &Snapshot,
    uid: &str,
    policies: &[UciSection],
    fallback: Option<&Value>,
) -> Result<()> {
    let policies = policies
        .iter()
        .map(|policy| payload_policy(policy, snapshot))
        .collect::<Vec<_>>();
    let data = user_payload_with_times(snapshot, uid, &policies, fallback)?;
    let body = serde_json::to_string(&json!({"data": data}))?;
    command_output("dev_config", &["add", "-m", CONFIG, &body])?;
    restore_metadata(&policies)?;
    Ok(())
}

fn restore_metadata(policies: &[UciSection]) -> Result<()> {
    for policy in policies {
        for key in [
            "labprobe_plan_id",
            "labprobe_name",
            "labprobe_enabled",
            "labprobe_time",
            "labprobe_allowed_rdpi",
            "labprobe_applications",
        ] {
            if let Some(value) = policy.options.get(key) {
                let assignment = format!("{}.{}.{}={}", CONFIG, policy.name, key, value);
                command_output("uci", &["-q", "set", &assignment])?;
            }
        }
    }
    command_output("uci", &["-q", "commit", CONFIG])?;
    Ok(())
}

fn delete_user(uid: &str) -> Result<()> {
    let body = serde_json::to_string(&json!({"list": [uid]}))?;
    command_output("dev_config", &["del", "-m", CONFIG, &body])?;
    Ok(())
}

fn policies_for(snapshot: &Snapshot, uid: &str) -> Vec<UciSection> {
    snapshot
        .user(uid)
        .and_then(|user| user.lists.get("policy"))
        .into_iter()
        .flatten()
        .filter_map(|pid| snapshot.named(pid).cloned())
        .collect()
}

fn snapshot_user_restore(snapshot: &Snapshot, uid: &str) -> Result<()> {
    if snapshot.user(uid).is_some() {
        write_user(snapshot, uid, &policies_for(snapshot, uid), None)?;
    } else {
        delete_user(uid)?;
    }
    verify_snapshot_restored(snapshot, uid)
}

fn verify_snapshot_restored(snapshot: &Snapshot, uid: &str) -> Result<()> {
    let expected = policies_for(snapshot, uid);
    let deadline = Instant::now() + VERIFY_TIMEOUT;
    loop {
        let current = load_snapshot()?;
        let uci_matches = if snapshot.user(uid).is_some() {
            let current_pids = policies_for(&current, uid)
                .iter()
                .map(|policy| policy.name.clone())
                .collect::<BTreeSet<_>>();
            let expected_pids = expected
                .iter()
                .map(|policy| policy.name.clone())
                .collect::<BTreeSet<_>>();
            current.user(uid).is_some() && current_pids == expected_pids
        } else {
            current.user(uid).is_none()
        };
        let user_text = serde_json::to_string(&ubus_show("sniffer.user").unwrap_or(Value::Null))
            .unwrap_or_default();
        let runtime_matches = if snapshot.user(uid).is_some() {
            user_text.contains(uid)
                && expected
                    .iter()
                    .filter(|policy| {
                        policy
                            .options
                            .get("type")
                            .map(|value| value != "0")
                            .unwrap_or(false)
                    })
                    .all(|policy| user_text.contains(&policy.name))
        } else {
            !user_text.contains(uid)
        };
        if uci_matches && runtime_matches {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("rollback verification timed out");
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn verify_policy(uid: &str, pid: &str, should_exist: bool, app_policy: bool) -> Result<()> {
    let deadline = Instant::now() + VERIFY_TIMEOUT;
    loop {
        let snapshot = load_snapshot()?;
        let in_uci = snapshot.user(uid).is_some() && snapshot.named(pid).is_some();
        let sniffer_user = ubus_show("sniffer.user").unwrap_or(Value::Null);
        let user_text = serde_json::to_string(&sniffer_user).unwrap_or_default();
        let in_user = user_text.contains(uid) && (!app_policy || user_text.contains(pid));
        let policy_text =
            serde_json::to_string(&ubus_show("sniffer.policy").unwrap_or(Value::Null))
                .unwrap_or_default();
        let in_policy = !app_policy || policy_text.contains(pid);
        if should_exist && in_uci && in_user && in_policy {
            return Ok(());
        }
        if !should_exist && !in_uci && !user_text.contains(pid) && !policy_text.contains(pid) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("child_guard reload verification timed out");
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn transactional_write<S, W, V, R>(
    snapshot: &S,
    mut write: W,
    mut verify: V,
    mut rollback: R,
) -> Result<()>
where
    W: FnMut() -> Result<()>,
    V: FnMut() -> Result<()>,
    R: FnMut(&S) -> Result<()>,
{
    if let Err(error) = write() {
        match rollback(snapshot) {
            Ok(_) => bail!("{}; rollback=completed", error),
            Err(rollback_error) => bail!("{}; rollback=failed: {}", error, rollback_error),
        }
    }
    if let Err(error) = verify() {
        match rollback(snapshot) {
            Ok(_) => bail!("{}; rollback=completed", error),
            Err(rollback_error) => bail!("{}; rollback=failed: {}", error, rollback_error),
        }
    }
    Ok(())
}

fn capabilities() -> Value {
    let snapshot = load_snapshot();
    let ubus = command_output("ubus", &["list"]).unwrap_or_default();
    let config = snapshot
        .as_ref()
        .ok()
        .and_then(|value| value.named("config"));
    let child_guard = snapshot.is_ok();
    let sniffer_user = ubus.lines().any(|line| line.trim() == "sniffer.user");
    let sniffer_policy = ubus.lines().any(|line| line.trim() == "sniffer.policy");
    let rdpi_available =
        Path::new("/usr/sbin/rdpi").exists() || Path::new("/usr/bin/rdpi").exists();
    let rdpi_enabled = config
        .and_then(|value| value.options.get("rdpi_enable"))
        .map(|value| value == "1")
        .unwrap_or(false);
    let available = child_guard && available() && sniffer_user && sniffer_policy;
    json!({
        "ok": true,
        "capabilities": {
            "available": available,
            "version": config.and_then(|value| value.options.get("version")).cloned().unwrap_or_default(),
            "rdpiEnabled": rdpi_enabled,
            "rdpiAvailable": rdpi_available,
            "appControlSupported": available && rdpi_available && rdpi_enabled,
            "supportedDeviceTypes": ["phone", "pad", "pc", "wired_pc"],
            "fullModeRequired": false,
        }
    })
}

fn recursive_object_by_uid<'a>(value: &'a Value, uid: &str) -> Option<&'a Map<String, Value>> {
    match value {
        Value::Object(object) => {
            if object
                .get("uid")
                .and_then(Value::as_str)
                .map(|value| value.eq_ignore_ascii_case(uid))
                .unwrap_or(false)
            {
                return Some(object);
            }
            object
                .values()
                .find_map(|child| recursive_object_by_uid(child, uid))
        }
        Value::Array(items) => items
            .iter()
            .find_map(|child| recursive_object_by_uid(child, uid)),
        _ => None,
    }
}

fn runtime_mapping(uid: &str, user_show: &Value, policy_show: &Value) -> Value {
    let object = recursive_object_by_uid(user_show, uid);
    let policies = object
        .and_then(|value| value.get("policy").or_else(|| value.get("policies")))
        .map(|value| match value {
            Value::Array(_) => json_strings(Some(value)),
            Value::String(value) if value != "none" && !value.is_empty() => vec![value.clone()],
            _ => Vec::new(),
        })
        .unwrap_or_default();
    let effect = object
        .and_then(|value| {
            value
                .get("effect policy")
                .or_else(|| value.get("effect_policy"))
                .or_else(|| value.get("effectPolicy"))
        })
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && *value != "none")
        .map(str::to_string);
    let policy_text = serde_json::to_string(policy_show).unwrap_or_default();
    let defined = policies
        .iter()
        .filter(|pid| policy_text.contains(*pid))
        .cloned()
        .collect::<Vec<_>>();
    json!({
        "uid": uid,
        "policyIds": policies,
        "definedPolicyIds": defined,
        "effectPolicyId": effect,
        "active": effect.is_some(),
        "verifiedAtEpoch": now_epoch(),
    })
}

fn mutate_plan(action: &str, payload: &Value) -> Result<Value> {
    let uid = payload
        .get("uid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing uid"))?;
    let before = load_snapshot()?;
    let mut policies = policies_for(&before, uid);
    let old_plan_id = payload.get("planId").and_then(Value::as_str).unwrap_or("");
    let old_index = if old_plan_id.is_empty() {
        None
    } else {
        policies
            .iter()
            .position(|policy| public_plan_id(policy) == old_plan_id)
    };
    let (verify_pid, should_exist, app_policy, response_plan, stale_policy) = match action {
        "create_plan" => {
            let plan = payload.get("plan").ok_or_else(|| anyhow!("missing plan"))?;
            let public_id = format!("lp_{:016x}", fnv64(&format!("{}:{}", uid, plan_pid())));
            let policy = direct_policy(plan, &public_id)?;
            let pid = policy.name.clone();
            let is_app = policy
                .options
                .get("type")
                .map(|value| value != "0")
                .unwrap_or(false);
            policies.push(policy.clone());
            (pid, true, is_app, Some(policy), None)
        }
        "update_plan" => {
            let index = old_index.ok_or_else(|| anyhow!("plan not found"))?;
            let plan = payload.get("plan").ok_or_else(|| anyhow!("missing plan"))?;
            let replaced = policies[index].clone();
            let policy = direct_policy(plan, old_plan_id)?;
            let pid = policy.name.clone();
            let is_app = policy
                .options
                .get("type")
                .map(|value| value != "0")
                .unwrap_or(false);
            policies[index] = policy.clone();
            let replaced_is_app = replaced
                .options
                .get("type")
                .map(|value| value != "0")
                .unwrap_or(false);
            (
                pid,
                true,
                is_app,
                Some(policy),
                Some((replaced.name, replaced_is_app)),
            )
        }
        "delete_plan" => {
            let index = old_index.ok_or_else(|| anyhow!("plan not found"))?;
            let removed = policies.remove(index);
            (
                removed.name,
                false,
                removed
                    .options
                    .get("type")
                    .map(|value| value != "0")
                    .unwrap_or(false),
                None,
                None,
            )
        }
        "set_plan_enabled" => {
            let index = old_index.ok_or_else(|| anyhow!("plan not found"))?;
            let enabled = payload
                .get("enabled")
                .and_then(Value::as_bool)
                .ok_or_else(|| anyhow!("missing enabled"))?;
            let updated = policy_with_enabled(&policies[index], &before, enabled);
            let pid = updated.name.clone();
            let is_app = updated
                .options
                .get("type")
                .map(|value| value != "0")
                .unwrap_or(false);
            policies[index] = updated.clone();
            (pid, true, is_app, Some(updated), None)
        }
        _ => bail!("unsupported mutation"),
    };
    let fallback = payload.get("plan");
    transactional_write(
        &before,
        || write_user(&before, uid, &policies, fallback),
        || {
            verify_policy(uid, &verify_pid, should_exist, app_policy)?;
            if let Some((stale_pid, stale_is_app)) = stale_policy.as_ref() {
                if stale_pid != &verify_pid {
                    verify_policy(uid, stale_pid, false, *stale_is_app)?;
                }
            }
            Ok(())
        },
        |snapshot| snapshot_user_restore(snapshot, uid),
    )?;
    let after = load_snapshot()?;
    let plan = response_plan.and_then(|policy| {
        after
            .named(&policy.name)
            .map(|value| plan_value(value, &after))
    });
    Ok(
        json!({"ok": true, "uid": uid, "plan": plan, "deleted": !should_exist, "rollback": "not_needed"}),
    )
}

fn device_pause(action: &str, payload: &Value) -> Result<Value> {
    let uid = payload
        .get("uid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing uid"))?;
    let timestamp = if action == "pause_device" {
        payload
            .get("untilEpoch")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| now_epoch() + 86_400)
    } else {
        0
    };
    let snapshot = load_snapshot()?;
    let previous = snapshot
        .user(uid)
        .ok_or_else(|| anyhow!("device not found"))?
        .options
        .get("block")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    transactional_write(
        &previous,
        || set_device_block(uid, timestamp),
        || verify_device_block(uid, timestamp),
        |old| {
            set_device_block(uid, *old)?;
            verify_device_block(uid, *old)
        },
    )?;
    Ok(json!({"ok": true, "uid": uid, "blockedUntilEpoch": timestamp, "rollback": "not_needed"}))
}

fn set_device_block(uid: &str, timestamp: u64) -> Result<()> {
    let body = serde_json::to_string(&json!({"uid": uid, "ts": timestamp}))?;
    command_output("dev_sta", &["set", "-m", "child_block", &body])?;
    Ok(())
}

fn verify_device_block(uid: &str, timestamp: u64) -> Result<()> {
    let deadline = Instant::now() + VERIFY_TIMEOUT;
    loop {
        let snapshot = load_snapshot()?;
        let user = snapshot.user(uid);
        let current = user
            .and_then(|value| value.options.get("block"))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let reload_completed = user
            .and_then(|value| value.options.get("reload"))
            .map(|value| value == "0")
            .unwrap_or(false);
        if current == timestamp && reload_completed {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("child_guard block verification timed out");
        }
        thread::sleep(Duration::from_secs(1));
    }
}

pub fn execute(action: &str, payload: &Value) -> Value {
    let result: Result<Value> = (|| match action {
        "get_capabilities" => Ok(capabilities()),
        "get_users" => {
            let snapshot = load_snapshot()?;
            // Device identity is auxiliary metadata. Routers without dev_identify still expose
            // their child_guard users; no device type is used as an app-control gate.
            let identities = query_device_identities(&snapshot).unwrap_or_default();
            let devices = snapshot
                .sections_of("user")
                .map(|user| user_value(user, &snapshot, &identities))
                .collect::<Vec<_>>();
            Ok(json!({"ok": true, "devices": devices}))
        }
        "get_plans" => {
            let uid = payload
                .get("uid")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing uid"))?;
            let snapshot = load_snapshot()?;
            let plans = policies_for(&snapshot, uid)
                .iter()
                .map(|policy| plan_value(policy, &snapshot))
                .collect::<Vec<_>>();
            Ok(json!({"ok": true, "uid": uid, "plans": plans}))
        }
        "get_runtime_state" => {
            let uid = payload
                .get("uid")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing uid"))?;
            let mut runtime = runtime_mapping(
                uid,
                &ubus_show("sniffer.user")?,
                &ubus_show("sniffer.policy")?,
            );
            let snapshot = load_snapshot()?;
            let blocked_until = snapshot
                .user(uid)
                .and_then(|user| user.options.get("block"))
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            if let Some(object) = runtime.as_object_mut() {
                object.insert("blocked".into(), json!(blocked_until > now_epoch()));
                object.insert("blockedUntilEpoch".into(), json!(blocked_until));
            }
            Ok(json!({"ok": true, "runtime": runtime}))
        }
        "create_plan" | "update_plan" | "delete_plan" | "set_plan_enabled" => {
            mutate_plan(action, payload)
        }
        "pause_device" | "resume_device" => device_pause(action, payload),
        _ => bail!("unsupported child_guard action"),
    })();
    result.unwrap_or_else(|error| {
        let text = error.to_string();
        let rollback = if text.contains("rollback=completed") {
            Value::String("completed".into())
        } else if text.contains("rollback=failed") {
            Value::String("failed".into())
        } else {
            Value::Null
        };
        json!({
            "ok": false,
            "errorCode": if text.contains("not found") { "not_found" } else if text.contains("rollback=failed") { "rollback_failed" } else { "child_guard_failed" },
            "error": text,
            "rollback": rollback,
        })
    })
}

pub fn available() -> bool {
    Path::new("/usr/bin/dev_config").exists()
        || Path::new("/sbin/dev_config").exists()
        || Path::new("/usr/sbin/dev_config").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
config config 'config'
 option version '2.1'
 option rdpi_enable '1'
config user 'aabbccddeeff'
 option name 'iPad'
 list mac 'aa:bb:cc:dd:ee:ff'
 list policy 'abc1234_wechat'
config policy 'abc1234_wechat'
 option type '1'
 option tr 'child_tr_abc1234'
 option labprobe_plan_id 'lp_1234567890abcdef'
 option labprobe_name '微信计划'
 option labprobe_enabled '1'
 option labprobe_allowed_rdpi '["7-1-2-0","7-1-2-3"]'
 list app '4-1-1-0'
config timerange 'child_tr_abc1234'
 list time 'mon-08:00-09:00'
 list time 'tue-08:00-09:00'
 option pid 'abc1234_wechat'
"#;

    #[test]
    fn parses_child_guard_export() {
        let parsed = parse_uci_export(SAMPLE);
        assert_eq!(
            parsed.user("aabbccddeeff").unwrap().lists["mac"][0],
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(parsed.named("abc1234_wechat").unwrap().options["type"], "1");
    }

    #[test]
    fn plan_serializes_and_deserializes_without_raw_rules() {
        let parsed = parse_uci_export(SAMPLE);
        let value = plan_value(parsed.named("abc1234_wechat").unwrap(), &parsed);
        assert_eq!(value["id"], "lp_1234567890abcdef");
        assert_eq!(value["startTime"], "08:00");
        assert_eq!(value["applicationRdpiIds"].as_array().unwrap().len(), 2);
        assert!(value.get("app").is_none());
    }

    #[test]
    fn whole_user_replacement_preserves_existing_policy_timerange() {
        let parsed = parse_uci_export(SAMPLE);
        let policies = policies_for(&parsed, "aabbccddeeff")
            .iter()
            .map(|policy| payload_policy(policy, &parsed))
            .collect::<Vec<_>>();
        let payload = user_payload_with_times(&parsed, "aabbccddeeff", &policies, None).unwrap();
        assert_eq!(
            payload["policies"][0]["tr"]["mon"][0],
            json!(["08:00", "09:00"])
        );
        assert_eq!(
            payload["policies"][0]["tr"]["tue"][0],
            json!(["08:00", "09:00"])
        );
    }

    #[test]
    fn runtime_effect_policy_is_normalized() {
        let user =
            json!({"users":[{"uid":"aabbccddeeff","policy":["pid1"],"effect policy":"pid1"}]});
        let policy = json!({"policies":[{"pid":"pid1","app":["7-1-2-0"]}]});
        let result = runtime_mapping("aabbccddeeff", &user, &policy);
        assert_eq!(result["effectPolicyId"], "pid1");
        assert_eq!(result["active"], true);
    }

    #[test]
    fn transaction_rolls_back_after_verification_failure() {
        let mut wrote = false;
        let mut rolled_back = false;
        let result = transactional_write(
            &"snapshot",
            || {
                wrote = true;
                Ok(())
            },
            || bail!("verify failed"),
            |_| {
                rolled_back = true;
                Ok(())
            },
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("rollback=completed"));
        assert!(wrote);
        assert!(rolled_back);
    }

    #[test]
    fn transaction_rolls_back_after_partial_write_failure() {
        let mut rolled_back = false;
        let result = transactional_write(
            &"snapshot",
            || bail!("metadata commit failed"),
            || Ok(()),
            |_| {
                rolled_back = true;
                Ok(())
            },
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("rollback=completed"));
        assert!(rolled_back);
    }

    #[test]
    fn app_family_expansion_is_not_one_to_one() {
        let allowed = vec![
            "7-1-2-0".to_string(),
            "7-1-2-3".to_string(),
            "7-1-2-12".to_string(),
            "7-1-2-14".to_string(),
        ];
        let all = ["7-1-2-0", "7-1-2-3", "7-1-2-12", "7-1-2-14", "10-1-1-0"];
        let allowed_set = allowed.into_iter().collect::<BTreeSet<_>>();
        let blocked = all
            .into_iter()
            .filter(|value| !allowed_set.contains(*value))
            .collect::<Vec<_>>();
        assert_eq!(blocked, vec!["10-1-1-0"]);
    }

    #[test]
    fn dev_identify_metadata_enriches_pc_without_gating_app_control() {
        let parsed = parse_uci_export(SAMPLE);
        let identities = parse_device_identities(&json!({
            "devices": [{
                "mac": "AA-BB-CC-DD-EE-FF",
                "manufac": "intel",
                "type": "pc",
                "hostname": "DESKTOP-LAB",
                "recomd": "电脑",
                "user_define": "书房电脑",
                "os": "windows"
            }],
            "code": 0
        }));
        let value = user_value(parsed.user("aabbccddeeff").unwrap(), &parsed, &identities);
        assert_eq!(value["name"], "iPad");
        assert_eq!(value["deviceType"], "pc");
        assert_eq!(value["identitySource"], "dev_identify");
        assert_eq!(value["appControlSupported"], true);
    }

    #[test]
    fn dev_identify_name_is_used_when_child_guard_has_no_name() {
        let parsed = parse_uci_export(
            r#"
config config 'config'
 option rdpi_enable '1'
config user 'router_uid'
 list mac 'aa:bb:cc:dd:ee:ff'
"#,
        );
        let identities = parse_device_identities(&json!({
            "devices": [{
                "mac": "aabb.ccdd.eeff",
                "type": "pc",
                "hostname": "DESKTOP-LAB",
                "recomd": "电脑",
                "user_define": "书房电脑"
            }]
        }));
        let value = user_value(parsed.user("router_uid").unwrap(), &parsed, &identities);
        assert_eq!(value["name"], "书房电脑");
        assert_eq!(value["hostname"], "DESKTOP-LAB");
    }
}
