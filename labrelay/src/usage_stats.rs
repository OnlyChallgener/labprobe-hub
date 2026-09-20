//! Shared firmware primitives for the usage pipeline.
//!
//! The statistics themselves live in `minute_stats` (natural-minute buckets).
//! What is left here is the parsing and the firmware plumbing that module needs:
//! the sniffer flow record layout, the `rdpi -t` appid table, and the two
//! switches that make app identification work at all.
//!
//! ## Record layout (15 whitespace-separated columns)
//!
//! ```text
//! mac src_ip dst_ip sport dport proto flag appid idle timeout pkts_up bytes_up pkts_down bytes_down dir
//! ```
//!
//! `idle` counts **down** toward 0 (it is the remaining budget, not elapsed
//! silence); `timeout` is the flow's maximum age (3600s TCP / 180s UDP). The
//! byte/packet counters are cumulative and only advance when new packets
//! arrive, so the delta between two consecutive samples is the traffic that
//! happened in between.
//!
//! The table is **sparse** — it only holds recently identified flows, so it can
//! legitimately contain a single row while the LAN is busy. Anything that reads
//! it must therefore accumulate deltas rather than assume the table is a full
//! inventory.

use std::collections::BTreeMap;

use serde_json::json;

/// Rows whose appid is the engine's "no idea" marker carry no app attribution.
pub const UNIDENTIFIED_APPID: &str = "0-0-0-0";

// ---------------------------------------------------------------------------
// Sniffer flow records
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowKey {
    pub mac: String,
    pub dst_ip: String,
    pub sport: u32,
    pub dport: u32,
    pub appid: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowCounters {
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRow {
    pub mac: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub sport: u32,
    pub dport: u32,
    pub proto: String,
    pub appid: String,
    pub idle: u32,
    pub timeout: u32,
    pub counters: FlowCounters,
}

impl FlowRow {
    pub fn key(&self) -> FlowKey {
        FlowKey {
            mac: self.mac.clone(),
            dst_ip: self.dst_ip.clone(),
            sport: self.sport,
            dport: self.dport,
            appid: self.appid.clone(),
        }
    }
}

/// Parse one sniffer flow row. Returns `None` for blank lines and anything that
/// does not look like a record, so a firmware format drift degrades into "no
/// data" instead of a hard failure.
pub fn parse_flow_line(line: &str) -> Option<FlowRow> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 15 {
        return None;
    }
    let mac = fields[0].to_ascii_lowercase();
    if mac.len() != 17 || !mac.contains(':') {
        return None;
    }
    let appid = fields[7].to_string();
    if appid.is_empty() {
        return None;
    }
    Some(FlowRow {
        mac,
        src_ip: fields[1].to_string(),
        dst_ip: fields[2].to_string(),
        sport: fields[3].parse().ok()?,
        dport: fields[4].parse().ok()?,
        proto: fields[5].to_ascii_uppercase(),
        appid,
        idle: fields[8].parse().unwrap_or(0),
        timeout: fields[9].parse().unwrap_or(0),
        counters: FlowCounters {
            bytes_up: fields[11].parse().unwrap_or(0),
            bytes_down: fields[13].parse().unwrap_or(0),
        },
    })
}

/// Parse every record in a sniffer flow table (`sniffer_flow` or
/// `sniffer_flow_full` — same layout, the full one also keeps unidentified rows).
pub fn parse_proc_flow(text: &str) -> Vec<FlowRow> {
    text.lines().filter_map(parse_flow_line).collect()
}

// ---------------------------------------------------------------------------
// App naming
// ---------------------------------------------------------------------------

/// Map of appid (`7-1-2-0`) to human name, built from `rdpi -t`.
pub type AppIdMap = BTreeMap<String, String>;

/// Parse the `rdpi -t` table: one `<name> <appid>` pair per line.
pub fn parse_rdpi_table(text: &str) -> AppIdMap {
    let mut map = AppIdMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let appid = fields[fields.len() - 1];
        if !looks_like_appid(appid) {
            continue;
        }
        let name = fields[..fields.len() - 1].join(" ");
        map.insert(appid.to_string(), name);
    }
    map
}

fn looks_like_appid(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

/// Fold the engine's fine-grained variants into one app.
///
/// `微信_weak_relation` -> `微信`, `抖音系列` -> `抖音`. Variants the product
/// genuinely treats as separate apps (`微信视频号`, `企业微信`, `微信支付`) are
/// left alone because the official report lists them separately.
pub fn canonical_app(name: &str) -> String {
    let base = name.split('_').next().unwrap_or(name).trim();
    match base {
        "抖音系列" => "抖音".to_string(),
        "快手系列" => "快手".to_string(),
        "哔哩哔哩" => "哔哩哔哩".to_string(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Glue: reading sources, persisting aggregates
// ---------------------------------------------------------------------------

/// Cache of `rdpi -t` so we do not shell out on every tick.
pub const RDPI_TABLE_CACHE: &str = "/tmp/labprobe_rdpi_table.txt";
/// The firmware's child-device table, one `MAC  CHILD  DEV_IDYC` row per station.
pub const SNIFFER_INFO: &str = "/proc/net/sniffer_info";

pub fn read_text(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Write via a temporary file + rename so a crash cannot leave a half-written
/// store behind.
pub fn atomic_write(path: &str, body: &str) -> std::io::Result<()> {
    let temp = format!("{}.tmp", path);
    std::fs::write(&temp, body)?;
    std::fs::rename(&temp, path)
}

/// App map from the cached `rdpi -t` table. Empty when the cache is missing,
/// in which case rows still feed byte totals but not per-app minutes.
pub fn load_app_map() -> AppIdMap {
    read_text(RDPI_TABLE_CACHE)
        .map(|text| parse_rdpi_table(&text))
        .unwrap_or_default()
}

/// Refresh the cache by running `rdpi -t` on the router.
///
/// The feature library changes on firmware upgrade, so this is worth re-running
/// occasionally rather than trusting a stale cache forever.
pub fn refresh_app_map() -> AppIdMap {
    match std::process::Command::new("rdpi").arg("-t").output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            let map = parse_rdpi_table(&text);
            if !map.is_empty() {
                let _ = atomic_write(RDPI_TABLE_CACHE, &text);
            }
            map
        }
        _ => AppIdMap::new(),
    }
}


/// Stations the firmware currently treats as child devices.
///
/// `/proc/net/sniffer_info` is the authoritative list: it is the same child
/// membership the guard policies are built from, so it picks up devices the
/// App adds without the relay having to re-read UCI.
pub fn child_macs() -> Vec<String> {
    let Some(text) = read_text(SNIFFER_INFO) else {
        return Vec::new();
    };
    let mut macs: Vec<String> = text
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 2 || fields[1] != "1" {
                return None;
            }
            let mac = fields[0].to_ascii_lowercase();
            if mac.len() == 17 && mac.contains(':') {
                Some(mac)
            } else {
                None
            }
        })
        .collect();
    macs.sort();
    macs.dedup();
    macs
}

fn ubus_call(object: &str, method: &str, body: &str) -> bool {
    match std::process::Command::new("ubus")
        .args(["call", object, method, body])
        .output()
    {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Turn on the two firmware switches the usage pipeline depends on.
///
/// Neither is set by the vendor's `child_guard` reload path on this model:
///
/// * `sniffer.idyc add` puts a MAC in the identify list (`DEV_IDYC=1` in
///   `/proc/net/sniffer_info`). The call *silently ignores every MAC but the
///   first* when handed an array — it still answers `code 0`, so a batch call
///   looks like it worked while four of five devices stay unidentified. One
///   process per MAC is the only form the firmware honours; measured 2026-09-20
///   on the BE72, all six children flipped to 1 that way and none of them did
///   with the array.
/// * `sniffer enable {"mod":"full_mode"}` is what makes the firmware keep the
///   per-flow table at all.
///
/// Identification is still partial with it on — RDPI only names a minority of
/// connections (9 of ~64 rows on a busy box), so unclassified traffic must keep
/// counting towards the device, never be discarded.
///
/// Every call is idempotent, so this is safe to re-run and it self-heals after a
/// firmware reload wipes the runtime state.
pub fn prepare_sniffer() -> bool {
    let macs = child_macs();
    if macs.is_empty() {
        return false;
    }
    let identifiers = macs.iter().all(|mac| {
        ubus_call(
            "sniffer.idyc",
            "add",
            &json!({ "mac": [mac] }).to_string(),
        )
    });
    let full_mode = ubus_call(
        "sniffer",
        "enable",
        &json!({ "mod": "full_mode" }).to_string(),
    );
    identifiers && full_mode
}
