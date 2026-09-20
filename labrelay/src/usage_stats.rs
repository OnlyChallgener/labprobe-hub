//! Child-internet usage statistics: sampling, aggregation and retention.
//!
//! ## Data sources (both are shipped by the firmware)
//!
//! * `/tmp/sniffer_flow_dump.txt` — periodic dump, one header block per ~60s:
//!   ```text
//!   [ 1789721025 2026-09-18 16:43:45 ]
//!   <flow rows...>
//!   ```
//!   The header carries both the epoch **and the router's local datetime**, so
//!   no timezone library is needed.
//! * `/proc/net/sniffer_flow` — live snapshot of the same records.
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
//!
//! ## What counts as "usage time"
//!
//! Bytes are cheap to attribute; *time* is not. Merely having traffic must not
//! buy usage seconds, because every backgrounded app keeps a heartbeat alive —
//! a few hundred bytes a minute — and crediting those produces the classic
//! "抖音 used for 24 hours" chart. A flow only earns seconds for an interval
//! when it cleared the active-traffic gate (`ACTIVE_MIN_BYTES` /
//! `ACTIVE_MIN_BYTES_PER_SEC`) inside that interval. Heartbeat-only flows still
//! add to the byte totals; they simply do not add to the clock.
//!
//! ## Privacy / retention
//!
//! Nothing is stored raw. Every sample is folded straight into hourly and
//! per-app buckets; raw flow records are dropped as soon as the sample has been
//! ingested. Only aggregated buckets survive, and buckets older than
//! `keep_days` distinct calendar days are pruned on write. Ten days matches the
//! official 上网统计 window, so the retention story is identical.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

/// How many distinct calendar days of aggregates to keep.
///
/// The official ``上网统计`` page offers 今日 / 昨日 / 过去七天, so ten days is
/// enough headroom and keeps the footprint trivial.
pub const DEFAULT_KEEP_DAYS: usize = 10;

/// A single hour can never contribute more than an hour of "online" time.
const MAX_SECS_PER_HOUR: u32 = 3600;

/// Per-app totals are daily, so they clamp at a full day instead of an hour.
const MAX_SECS_PER_DAY: u32 = 24 * 3600;

/// Ignore sample gaps larger than this when crediting activity (guards against
/// crediting hours of "online time" after the relay was suspended).
const MAX_SAMPLE_GAP_SECS: u64 = 300;

/// Rows whose appid is the engine's "no idea" marker are dropped.
const UNIDENTIFIED_APPID: &str = "0-0-0-0";

// ---------------------------------------------------------------------------
// Active-traffic gate
// ---------------------------------------------------------------------------
//
// A flow existing is not the same thing as the app being *used*. Chat and
// social apps keep a heartbeat running on their long-lived connections even
// when they sit in the background — a keepalive is a couple of hundred bytes
// every 30-60s, and a push channel may poll once a minute forever. Crediting
// those as usage time is exactly what makes a phone that spent the night on a
// nightstand look like it spent eight hours in 微信, and it is why a naive
// "any bytes this minute" rule produces a 24-hour 抖音 bar.
//
// So a flow only earns seconds for an interval when it moved *meaningful*
// traffic inside that interval. Genuine interaction — a message, a feed page,
// a video frame, a voice call — is orders of magnitude above the gate; a
// heartbeat is orders of magnitude below it.

/// Absolute byte floor (up+down) a flow must move within one sample interval
/// before it counts as "in use" for that interval.
///
/// Ten seconds of a typical background push or audio ping is ~1.5 KB, so 2 KB
/// sits comfortably above keepalives while catching real user interactions.
pub const ACTIVE_MIN_BYTES: u64 = 2048;

/// The same gate as a sustained rate, so a single short burst inside a long
/// interval cannot buy the whole interval as usage time.
pub const ACTIVE_MIN_BYTES_PER_SEC: u64 = 32;

/// Effective per-sample byte floor for an interval of `gap_secs` seconds.
///
/// `max(floor, rate * gap)` — the absolute floor protects short intervals, the
/// rate protects long ones.
pub fn active_floor_bytes(gap_secs: u64) -> u64 {
    ACTIVE_MIN_BYTES.max(ACTIVE_MIN_BYTES_PER_SEC.saturating_mul(gap_secs.max(1)))
}

// ---------------------------------------------------------------------------
// Parsing
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

/// Parse the live `/proc/net/sniffer_flow` snapshot.
pub fn parse_proc_flow(text: &str) -> Vec<FlowRow> {
    text.lines().filter_map(parse_flow_line).collect()
}

/// One `[ epoch YYYY-MM-DD HH:MM:SS ]` block from the periodic dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    pub epoch: u64,
    pub date: String,
    pub hour: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpSample {
    pub stamp: Stamp,
    pub rows: Vec<FlowRow>,
}

/// Parse a `[ <epoch> <YYYY-MM-DD> <HH:MM:SS> ]` header line.
fn parse_header(line: &str) -> Option<Stamp> {
    let inner = line.trim().strip_prefix('[')?.strip_suffix(']')?.trim();
    let parts: Vec<&str> = inner.split_whitespace().collect();
    if parts.len() != 3 {
        return None;
    }
    let epoch = parts[0].parse::<u64>().ok()?;
    let date = parts[1].to_string();
    if date.len() != 10 {
        return None;
    }
    let hour = parts[2].split(':').next()?.parse::<u8>().ok()?;
    if hour > 23 {
        return None;
    }
    Some(Stamp { epoch, date, hour })
}

/// Parse the whole periodic dump. Header blocks without any rows are kept so
/// the sampler can still see the time advancing.
pub fn parse_dump(text: &str) -> Vec<DumpSample> {
    let mut samples: Vec<DumpSample> = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with('[') {
            if let Some(stamp) = parse_header(line) {
                samples.push(DumpSample {
                    stamp,
                    rows: Vec::new(),
                });
            }
            continue;
        }
        if let Some(row) = parse_flow_line(line) {
            if let Some(last) = samples.last_mut() {
                last.rows.push(row);
            }
        }
    }
    samples
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
    if name == "支付宝_weak_relation" || name.contains("alipayobjects") || name.contains("alicdn") || name == "阿里CDN" {
        return "阿里CDN".to_string();
    }
    let base = name.split('_').next().unwrap_or(name).trim();
    match base {
        "抖音系列" => "抖音".to_string(),
        "快手系列" => "快手".to_string(),
        "哔哩哔哩" => "哔哩哔哩".to_string(),
        "红果短剧" | "红果免费短剧" => "红果免费短剧".to_string(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// IPv6 prefix attribution (supplement layer)
// ---------------------------------------------------------------------------

/// Parse an IPv6 literal (with `::` compression) into a u128.
pub fn ipv6_to_u128(text: &str) -> Option<u128> {
    let s = text.trim().split('%').next()?.trim();
    if s.is_empty() {
        return None;
    }
    let (head, tail) = match s.find("::") {
        Some(idx) => (&s[..idx], Some(&s[idx + 2..])),
        None => (s, None),
    };
    fn groups(part: &str) -> Option<Vec<u16>> {
        if part.is_empty() {
            return Some(Vec::new());
        }
        let mut out = Vec::new();
        for group in part.split(':') {
            if group.is_empty() || group.len() > 4 {
                return None;
            }
            out.push(u16::from_str_radix(group, 16).ok()?);
        }
        Some(out)
    }
    let head_groups = groups(head)?;
    let mut all = head_groups.clone();
    match tail {
        Some(part) => {
            let tail_groups = groups(part)?;
            if all.len() + tail_groups.len() > 8 {
                return None;
            }
            all.resize(8 - tail_groups.len(), 0);
            all.extend(tail_groups);
        }
        None => {
            if all.len() != 8 {
                return None;
            }
        }
    }
    if all.len() != 8 {
        return None;
    }
    let mut value: u128 = 0;
    for group in all {
        value = (value << 16) | group as u128;
    }
    Some(value)
}

/// Does `addr` fall inside `prefix` (`2409:8c50:a00::/48`, or a bare address)?
pub fn ipv6_in_prefix(addr: &str, prefix: &str) -> bool {
    let (net_text, bits) = match prefix.split_once('/') {
        Some((net, bits)) => (net, bits.trim().parse::<u32>().unwrap_or(128)),
        None => (prefix, 128),
    };
    if bits > 128 {
        return false;
    }
    let (addr_value, net_value) = match (ipv6_to_u128(addr), ipv6_to_u128(net_text)) {
        (Some(a), Some(n)) => (a, n),
        _ => return false,
    };
    if bits == 0 {
        return true;
    }
    let shift = 128 - bits;
    (addr_value >> shift) == (net_value >> shift)
}

/// App attribution from an IPv6 prefix table.
///
/// Deliberately refuses to guess: a prefix claimed by more than one app (the
/// China-Mobile CDN pools are shared by several large apps) yields `None`
/// rather than a coin flip.
#[derive(Debug, Default, Clone)]
pub struct PrefixAttributor {
    entries: Vec<(String, String)>,
}

impl PrefixAttributor {
    pub fn new(entries: Vec<(String, String)>) -> Self {
        Self { entries }
    }

    /// Build from the `{"apps": {"微信": {"prefixes48": [...]}}}` shape.
    pub fn from_json(value: &Value) -> Self {
        let mut entries = Vec::new();
        if let Some(apps) = value.get("apps").and_then(Value::as_object) {
            for (app, spec) in apps {
                for field in ["prefixes48", "prefixes64"] {
                    if let Some(list) = spec.get(field).and_then(Value::as_array) {
                        for item in list {
                            if let Some(prefix) = item.as_str() {
                                entries.push((app.clone(), prefix.to_string()));
                            }
                        }
                    }
                }
            }
        }
        Self { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `Some(app)` only when exactly one distinct app claims the address.
    pub fn attribute(&self, addr: &str) -> Option<&str> {
        let mut hit: Option<&str> = None;
        for (app, prefix) in &self.entries {
            if ipv6_in_prefix(addr, prefix) {
                match hit {
                    Some(existing) if existing != app.as_str() => return None,
                    Some(_) => {}
                    None => hit = Some(app.as_str()),
                }
            }
        }
        hit
    }
}

// ---------------------------------------------------------------------------
// Aggregation store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HourBucket {
    pub active_secs: u32,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppBucket {
    pub active_secs: u32,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub sessions: u32,
}

#[derive(Debug, Default, Clone)]
pub struct UsageStore {
    /// (mac, date, hour) -> activity for that wall-clock hour.
    pub hourly: BTreeMap<(String, String, u8), HourBucket>,
    /// (mac, date, app) -> per-app totals for that day.
    pub apps: BTreeMap<(String, String, String), AppBucket>,
    /// Counters from the previous sample, used to derive deltas.
    last: BTreeMap<FlowKey, FlowCounters>,
    last_epoch: u64,
    /// Last active epoch per (mac, app) to cluster continuous usage into interaction sessions.
    last_active_app_epoch: BTreeMap<(String, String), u64>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IngestReport {
    pub new_flows: usize,
    pub updated_flows: usize,
    pub bytes_delta: u64,
    pub active_macs: usize,
    pub unknown_apps: usize,
    /// Flows that moved some traffic this interval but stayed under the
    /// active-traffic gate (heartbeats, keepalives, background polling). They
    /// still contribute bytes, they just do not buy usage time.
    pub heartbeat_flows: usize,
}

impl UsageStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop all observations. Used when the membership set changes enough that
    /// prior deltas would be misattributed.
    pub fn clear_deltas(&mut self) {
        self.last.clear();
        self.last_active_app_epoch.clear();
    }

    /// Fold one sample into the buckets.
    ///
    /// `app_of` maps an appid to the product-level app name; returning `None`
    /// means "not a real app" (engine placeholder, or unidentified) and the row
    /// is skipped for app accounting while still feeding byte totals.
    pub fn ingest<F>(&mut self, stamp: &Stamp, rows: &[FlowRow], app_of: F) -> IngestReport
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut report = IngestReport::default();

        // Gap between samples. A first sample (or one taken after a long
        // suspension) credits no activity time, because the interval cannot be
        // attributed honestly — we clamp rather than guess.
        let gap = if stamp.epoch <= self.last_epoch {
            0
        } else {
            let delta = stamp.epoch - self.last_epoch;
            if delta > MAX_SAMPLE_GAP_SECS {
                0
            } else {
                delta
            }
        };

        let mut active: BTreeSet<(String, String)> = BTreeSet::new();
        let mut cur: BTreeMap<FlowKey, FlowCounters> = BTreeMap::new();

        // Byte floor a flow must clear inside this interval to count as "in
        // use". Everything below it is heartbeat/keepalive noise: it still adds
        // to the byte totals, but it must not buy usage seconds.
        let active_floor = active_floor_bytes(gap);

        for row in rows {
            if row.appid == UNIDENTIFIED_APPID {
                continue;
            }
            let key = row.key();
            let previous = self.last.get(&key);
            let is_new = previous.is_none();
            let (delta_up, delta_down) = match previous {
                // If the sampler is running (gap > 0), a newly appeared flow started
                // in this interval, so its current counters are the delta for this interval.
                // On cold start baseline (gap == 0), credit nothing to avoid historical spill.
                None => {
                    if gap > 0 {
                        (row.counters.bytes_up, row.counters.bytes_down)
                    } else {
                        (0, 0)
                    }
                }
                Some(prev) => (
                    row.counters.bytes_up.saturating_sub(prev.bytes_up),
                    row.counters
                        .bytes_down
                        .saturating_sub(prev.bytes_down),
                ),
            };

            let delta = delta_up + delta_down;
            report.bytes_delta += delta;

            if is_new {
                report.new_flows += 1;
            } else if delta > 0 {
                report.updated_flows += 1;
            }

            let app = match app_of(&row.appid) {
                Some(name) => name,
                None => {
                    report.unknown_apps += 1;
                    cur.insert(key, row.counters.clone());
                    continue;
                }
            };

            // A flow whose delta clears the gate counts as active usage.
            if delta >= active_floor {
                active.insert((row.mac.clone(), app.clone()));
            } else if delta > 0 {
                report.heartbeat_flows += 1;
            }

            let app_slot = self
                .apps
                .entry((row.mac.clone(), stamp.date.clone(), app))
                .or_default();
            app_slot.tx_bytes += delta_up;
            app_slot.rx_bytes += delta_down;
            if is_new {
                app_slot.sessions += 1;
            }

            let hour_slot = self
                .hourly
                .entry((row.mac.clone(), stamp.date.clone(), stamp.hour))
                .or_default();
            hour_slot.tx_bytes += delta_up;
            hour_slot.rx_bytes += delta_down;

            cur.insert(key, row.counters.clone());
        }

        // Credit activity time once per mac per hour (two apps active in the
        // same minute is still one minute online), but per app for the per-app
        // totals -- and only for the apps that were actually active, never for
        // every app the device happens to have used today.
        if gap > 0 {
            let active_macs: BTreeSet<&String> = active.iter().map(|(mac, _)| mac).collect();
            for mac in active_macs {
                let hour_slot = self
                    .hourly
                    .entry((mac.clone(), stamp.date.clone(), stamp.hour))
                    .or_default();
                hour_slot.active_secs = hour_slot
                    .active_secs
                    .saturating_add(gap as u32)
                    .min(MAX_SECS_PER_HOUR);
            }
            for (mac, app) in &active {
                let app_slot = self
                    .apps
                    .entry((mac.clone(), stamp.date.clone(), app.clone()))
                    .or_default();
                app_slot.active_secs = app_slot
                    .active_secs
                    .saturating_add(gap as u32)
                    .min(MAX_SECS_PER_DAY);
            }
        }
        report.active_macs = active.iter().map(|(mac, _)| mac).collect::<BTreeSet<_>>().len();

        self.last = cur;
        self.last_epoch = stamp.epoch;
        report
    }

    /// Ingest every block of a dump, in chronological order, skipping blocks we
    /// have already folded in (identified by epoch).
    pub fn ingest_dump<F>(&mut self, text: &str, app_of: F) -> Vec<IngestReport>
    where
        F: Fn(&str) -> Option<String> + Copy,
    {
        let mut reports = Vec::new();
        for sample in parse_dump(text) {
            if sample.stamp.epoch <= self.last_epoch && self.last_epoch != 0 {
                continue;
            }
            reports.push(self.ingest(&sample.stamp, &sample.rows, app_of));
        }
        reports
    }

    /// Total "online" seconds for a mac on a date (the sum of the hourly bars,
    /// which is exactly how the official report derives 在线时间).
    pub fn online_secs(&self, mac: &str, date: &str) -> u32 {
        self.hourly
            .iter()
            .filter(|((m, d, _), _)| m == mac && d == date)
            .map(|(_, bucket)| bucket.active_secs)
            .sum()
    }

    pub fn hourly_json(&self, mac: &str, date: &str) -> Vec<Value> {
        let mut by_hour: BTreeMap<u8, HourBucket> = BTreeMap::new();
        for ((m, d, hour), bucket) in &self.hourly {
            if m == mac && d == date {
                let slot = by_hour.entry(*hour).or_default();
                slot.active_secs = slot.active_secs.saturating_add(bucket.active_secs);
                slot.tx_bytes += bucket.tx_bytes;
                slot.rx_bytes += bucket.rx_bytes;
            }
        }
        by_hour
            .into_iter()
            .map(|(hour, bucket)| {
                json!({
                    "hour": hour,
                    "minutes": (bucket.active_secs + 30) / 60,
                    "txBytes": bucket.tx_bytes,
                    "rxBytes": bucket.rx_bytes,
                })
            })
            .collect()
    }

    pub fn apps_json(&self, mac: &str, date: &str) -> Vec<Value> {
        let mut rows: Vec<Value> = self
            .apps
            .iter()
            .filter(|((m, d, _), _)| m == mac && d == date)
            .map(|((_, _, app), bucket)| {
                json!({
                    "app": app,
                    "minutes": (bucket.active_secs + 30) / 60,
                    "sessions": bucket.sessions,
                    "txBytes": bucket.tx_bytes,
                    "rxBytes": bucket.rx_bytes,
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            let left = a["minutes"].as_u64().unwrap_or(0);
            let right = b["minutes"].as_u64().unwrap_or(0);
            right.cmp(&left)
        });
        rows
    }

    pub fn dates(&self) -> BTreeSet<String> {
        self.hourly
            .keys()
            .map(|(_, date, _)| date.clone())
            .chain(self.apps.keys().map(|(_, date, _)| date.clone()))
            .collect()
    }

    /// Keep only the newest `keep_days` distinct calendar dates.
    ///
    /// Comparing ISO dates lexicographically avoids needing calendar arithmetic,
    /// and working in "distinct dates present" avoids depending on the current
    /// date being passed in correctly.
    pub fn prune(&mut self, keep_days: usize) -> usize {
        let dates = self.dates();
        if dates.len() <= keep_days || keep_days == 0 {
            return 0;
        }
        let cutoff_index = dates.len() - keep_days;
        let drop_dates: BTreeSet<String> = dates.into_iter().take(cutoff_index).collect();
        let before = self.hourly.len() + self.apps.len();
        self.hourly.retain(|(_, date, _), _| !drop_dates.contains(date));
        self.apps.retain(|(_, date, _), _| !drop_dates.contains(date));
        before - (self.hourly.len() + self.apps.len())
    }

    /// Serialise so the store survives a relay restart.
    /// Hourly buckets as JSON rows, in the exact shape the Hub's
    /// `usage_hourly` table accepts (absolute counters, camelCase).
    pub fn hourly_rows(&self) -> Vec<Value> {
        self.hourly
            .iter()
            .map(|((mac, date, hour), bucket)| {
                json!({
                    "mac": mac, "date": date, "hour": hour,
                    "activeSecs": bucket.active_secs,
                    "txBytes": bucket.tx_bytes,
                    "rxBytes": bucket.rx_bytes,
                })
            })
            .collect()
    }

    /// Per-app buckets, matching the Hub's `usage_daily_app` table.
    pub fn app_rows(&self) -> Vec<Value> {
        self.apps
            .iter()
            .map(|((mac, date, app), bucket)| {
                json!({
                    "mac": mac, "date": date, "app": app,
                    "activeSecs": bucket.active_secs,
                    "txBytes": bucket.tx_bytes,
                    "rxBytes": bucket.rx_bytes,
                    "sessions": bucket.sessions,
                })
            })
            .collect()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "version": 1,
            "lastEpoch": self.last_epoch,
            "hourly": self.hourly_rows(),
            "apps": self.app_rows(),
        })
    }

    /// Newest calendar date present in the store — the router's local "today"
    /// as far as the sampler is concerned, without needing a calendar call.
    pub fn newest_date(&self) -> Option<String> {
        self.dates().into_iter().next_back()
    }

    pub fn from_json(value: &Value) -> Self {
        let mut store = UsageStore::new();
        store.last_epoch = value.get("lastEpoch").and_then(Value::as_u64).unwrap_or(0);
        if let Some(rows) = value.get("hourly").and_then(Value::as_array) {
            for row in rows {
                let (Some(mac), Some(date), Some(hour)) = (
                    row.get("mac").and_then(Value::as_str),
                    row.get("date").and_then(Value::as_str),
                    row.get("hour").and_then(Value::as_u64),
                ) else {
                    continue;
                };
                store.hourly.insert(
                    (mac.to_string(), date.to_string(), hour as u8),
                    HourBucket {
                        active_secs: row
                            .get("activeSecs")
                            .and_then(Value::as_u64)
                            .unwrap_or(0) as u32,
                        tx_bytes: row.get("txBytes").and_then(Value::as_u64).unwrap_or(0),
                        rx_bytes: row.get("rxBytes").and_then(Value::as_u64).unwrap_or(0),
                    },
                );
            }
        }
        if let Some(rows) = value.get("apps").and_then(Value::as_array) {
            for row in rows {
                let (Some(mac), Some(date), Some(app)) = (
                    row.get("mac").and_then(Value::as_str),
                    row.get("date").and_then(Value::as_str),
                    row.get("app").and_then(Value::as_str),
                ) else {
                    continue;
                };
                store.apps.insert(
                    (mac.to_string(), date.to_string(), app.to_string()),
                    AppBucket {
                        active_secs: row
                            .get("activeSecs")
                            .and_then(Value::as_u64)
                            .unwrap_or(0) as u32,
                        tx_bytes: row.get("txBytes").and_then(Value::as_u64).unwrap_or(0),
                        rx_bytes: row.get("rxBytes").and_then(Value::as_u64).unwrap_or(0),
                        sessions: row.get("sessions").and_then(Value::as_u64).unwrap_or(0) as u32,
                    },
                );
            }
        }
        store
    }
}

// ---------------------------------------------------------------------------
// Glue: reading sources, persisting aggregates
// ---------------------------------------------------------------------------

/// Periodic dump written by the firmware every ~60s, with epoch + local time.
pub const SNIFFER_DUMP: &str = "/tmp/sniffer_flow_dump.txt";
/// Live snapshot of the same records (sparse; a delta source, not an inventory).
pub const SNIFFER_PROC: &str = "/proc/net/sniffer_flow";
/// Cache of `rdpi -t` so we do not shell out on every tick.
pub const RDPI_TABLE_CACHE: &str = "/tmp/labprobe_rdpi_table.txt";
/// Aggregated buckets. The only thing we persist; raw samples never land here.
pub const USAGE_STORE: &str = "/tmp/labprobe_usage_store.json";
/// Optional IPv6 prefix table (supplement layer), written by the Hub.
pub const PREFIX_TABLE: &str = "/tmp/labprobe_ipv6_prefixes.json";

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

pub fn load_prefixes() -> PrefixAttributor {
    match read_text(PREFIX_TABLE) {
        Some(text) => match serde_json::from_str::<Value>(&text) {
            Ok(value) => PrefixAttributor::from_json(&value),
            Err(_) => PrefixAttributor::default(),
        },
        None => PrefixAttributor::default(),
    }
}

pub fn load_store() -> UsageStore {
    match read_text(USAGE_STORE) {
        Some(text) => match serde_json::from_str::<Value>(&text) {
            Ok(value) => UsageStore::from_json(&value),
            Err(_) => UsageStore::new(),
        },
        None => UsageStore::new(),
    }
}

pub fn save_store(store: &UsageStore) -> std::io::Result<()> {
    atomic_write(USAGE_STORE, &store.to_json().to_string())
}

/// One sampling tick: fold newly-dumped blocks into the buckets, prune, persist.
///
/// Raw rows are consumed and dropped inside `ingest_dump`; only aggregates ever
/// reach disk. Re-reading the same dump is a no-op because blocks are ordered
/// and already-seen epochs are skipped.
pub fn tick(keep_days: usize) -> (UsageStore, Vec<IngestReport>) {
    let mut store = load_store();
    let apps = load_app_map();
    let reports = match read_text(SNIFFER_DUMP) {
        Some(text) => store.ingest_dump(&text, |appid| {
            apps.get(appid)
                .map(|name| canonical_app(name))
                .filter(|s| !s.is_empty())
        }),
        None => Vec::new(),
    };
    if !reports.is_empty() {
        store.prune(keep_days);
        let _ = save_store(&store);
    }
    (store, reports)
}

/// Build the payload the App consumes: hourly bars plus per-app totals, which
/// mirrors the official 上网统计 page. `onlineSeconds` is the sum of the hourly
/// bars, exactly how the official report derives 在线时间.
///
/// `macs` is the guarded device's mac list; only rows for those macs on `date`
/// are included.
pub fn report_json(store: &UsageStore, macs: &[String], date: &str) -> Value {
    let wanted: BTreeSet<String> = macs.iter().map(|mac| mac.to_ascii_lowercase()).collect();
    let selected = |mac: &str, row_date: &str| {
        row_date == date && wanted.contains(&mac.to_ascii_lowercase())
    };

    let mut hourly: BTreeMap<u8, HourBucket> = BTreeMap::new();
    for ((mac, row_date, hour), bucket) in &store.hourly {
        if !selected(mac, row_date) {
            continue;
        }
        let slot = hourly.entry(*hour).or_default();
        slot.active_secs = slot.active_secs.saturating_add(bucket.active_secs);
        slot.tx_bytes += bucket.tx_bytes;
        slot.rx_bytes += bucket.rx_bytes;
    }

    let mut apps: BTreeMap<String, AppBucket> = BTreeMap::new();
    for ((mac, row_date, app), bucket) in &store.apps {
        if !selected(mac, row_date) {
            continue;
        }
        let slot = apps.entry(app.clone()).or_default();
        slot.active_secs = slot.active_secs.saturating_add(bucket.active_secs);
        slot.tx_bytes += bucket.tx_bytes;
        slot.rx_bytes += bucket.rx_bytes;
        slot.sessions += bucket.sessions;
    }

    let to_minutes = |secs: u32| (secs + 30) / 60;
    let online_secs: u32 = hourly.values().map(|bucket| bucket.active_secs).sum();
    let hourly_json: Vec<Value> = hourly
        .iter()
        .map(|(hour, bucket)| {
            json!({
                "hour": hour,
                "minutes": to_minutes(bucket.active_secs),
                "txBytes": bucket.tx_bytes,
                "rxBytes": bucket.rx_bytes,
            })
        })
        .collect();
    let mut app_rows: Vec<Value> = apps
        .iter()
        .map(|(app, bucket)| {
            json!({
                "app": app,
                "minutes": to_minutes(bucket.active_secs),
                "sessions": bucket.sessions,
                "txBytes": bucket.tx_bytes,
                "rxBytes": bucket.rx_bytes,
            })
        })
        .collect();
    app_rows.sort_by(|a, b| {
        b["minutes"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["minutes"].as_u64().unwrap_or(0))
    });

    json!({
        "date": date,
        "onlineSeconds": online_secs,
        "onlineMinutes": to_minutes(online_secs),
        "hourly": hourly_json,
        "apps": app_rows,
    })
}

// ---------------------------------------------------------------------------
// Periodic sampler: the thing that actually turns the module on
// ---------------------------------------------------------------------------

/// How often to fold a new dump sample into the buckets.
///
/// The firmware writes `/tmp/sniffer_flow_dump.txt` every ~60s, so sampling any
/// faster just re-reads the same block.
pub const SAMPLE_INTERVAL_SECS: u64 = 60;

/// How often to hand the aggregates to the Hub (which is our cloud).
///
/// Aggregates are absolute values merged with `max()`, so a push is always
/// idempotent; five minutes keeps the App's view fresh while keeping WAN traffic
/// in the tens of KB.
pub const PUSH_INTERVAL_SECS: u64 = 300;

/// How often to re-read `rdpi -t`.
///
/// The feature library only changes on firmware upgrade, so a six-hourly
/// refresh is plenty and keeps the appid -> name map from going stale.
pub const APP_MAP_REFRESH_SECS: u64 = 6 * 3600;

/// Clock + dirty flag for the periodic sampler.
///
/// Kept separate from `UsageStore` so the cadence logic is unit-testable with
/// plain epoch numbers instead of a running event loop.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SamplerState {
    pub last_sample_at: u64,
    pub last_push_at: u64,
    pub last_app_map_at: u64,
    /// Set when a sample changed something; cleared after a successful push.
    /// Without it a quiet LAN would re-upload the same aggregate every cycle.
    pub dirty: bool,
}

impl SamplerState {
    pub fn sample_due(&self, now: u64) -> bool {
        self.last_sample_at == 0
            || now.saturating_sub(self.last_sample_at) >= SAMPLE_INTERVAL_SECS
    }

    pub fn push_due(&self, now: u64) -> bool {
        if !self.dirty {
            return false;
        }
        self.last_push_at == 0 || now.saturating_sub(self.last_push_at) >= PUSH_INTERVAL_SECS
    }

    pub fn app_map_due(&self, now: u64) -> bool {
        self.last_app_map_at == 0
            || now.saturating_sub(self.last_app_map_at) >= APP_MAP_REFRESH_SECS
    }

    /// Record a completed sample and decide whether a push is warranted.
    ///
    /// A relay that has never pushed always marks itself dirty, so a fresh boot
    /// hands its (possibly empty) baseline to the Hub instead of staying silent
    /// until the first packet arrives.
    pub fn note_sample(&mut self, now: u64, reports: &[IngestReport]) {
        self.last_sample_at = now;
        if self.last_push_at == 0 || self.dirty {
            self.dirty = true;
            return;
        }
        for report in reports {
            if report.bytes_delta > 0
                || report.new_flows > 0
                || report.updated_flows > 0
                || report.heartbeat_flows > 0
            {
                self.dirty = true;
                break;
            }
        }
    }

    pub fn note_push(&mut self, now: u64) {
        self.last_push_at = now;
        self.dirty = false;
    }

    pub fn note_app_map(&mut self, now: u64) {
        self.last_app_map_at = now;
    }
}

/// Body for `POST /api/router/child-guard/usage/ingest`.
///
/// Absolute bucket values, exactly like the on-disk store: the Hub merges with
/// `max()`, so re-sending the whole window is a no-op and we never have to
/// track "what did I already send".
///
/// `today` is the prune reference. It should come from `router_today()` — the
/// router's own calendar via the dump header — because the Hub may run in a
/// different timezone. Falls back to the newest observed date, which is never
/// ahead of reality, so a prune can only ever keep more than needed.
pub fn ingest_payload(store: &UsageStore, keep_days: usize, today: Option<&str>) -> Value {
    let today = today
        .map(str::to_string)
        .or_else(|| store.newest_date());
    let mut body = json!({
        "hours": store.hourly_rows(),
        "apps": store.app_rows(),
        "hourlyKeepDays": keep_days,
        "dailyKeepDays": keep_days,
    });
    if let Some(today) = today {
        body["today"] = json!(today);
    }
    body
}

/// The router's local calendar date, read from the newest dump header.
///
/// The firmware stamps every block with local time, so this needs no timezone
/// database — and it stays correct even before the first sample lands, which is
/// why it is preferred over "newest date in the store".
pub fn router_today() -> Option<String> {
    let text = read_text(SNIFFER_DUMP)?;
    parse_dump(&text)
        .last()
        .map(|sample| sample.stamp.date.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW_A: &str = "da:1f:85:0c:19:fc 192.168.5.132 117.185.244.54 47218 443 TCP 3 18-158-1-0 3572 3600 11 1006 11 1372 1";

    /// Realistic epoch base; real samples are ~60s apart.
    const BASE: u64 = 1_789_700_000;

    fn stamp(epoch: u64, date: &str, hour: u8) -> Stamp {
        Stamp {
            epoch,
            date: date.to_string(),
            hour,
        }
    }

    fn row(bytes_up: u64, bytes_down: u64, appid: &str) -> FlowRow {
        FlowRow {
            mac: "da:1f:85:0c:19:fc".into(),
            src_ip: "192.168.5.132".into(),
            dst_ip: "117.185.244.54".into(),
            sport: 47218,
            dport: 443,
            proto: "TCP".into(),
            appid: appid.into(),
            idle: 3500,
            timeout: 3600,
            counters: FlowCounters {
                bytes_up,
                bytes_down,
            },
        }
    }

    fn pdd(appid: &str) -> Option<String> {
        match appid {
            "18-158-1-0" => Some("拼多多".to_string()),
            "7-1-2-0" => Some("微信".to_string()),
            _ => None,
        }
    }

    #[test]
    fn parses_flow_row() {
        let parsed = parse_flow_line(ROW_A).expect("row should parse");
        assert_eq!(parsed.mac, "da:1f:85:0c:19:fc");
        assert_eq!(parsed.dport, 443);
        assert_eq!(parsed.appid, "18-158-1-0");
        assert_eq!(parsed.idle, 3572);
        assert_eq!(parsed.timeout, 3600);
        assert_eq!(parsed.counters.bytes_up, 1006);
        assert_eq!(parsed.counters.bytes_down, 1372);
    }

    #[test]
    fn rejects_malformed_rows() {
        assert!(parse_flow_line("").is_none());
        assert!(parse_flow_line("not a flow row at all").is_none());
        assert!(parse_flow_line("zz:zz 1 2 3 4 TCP 3 7-1-2-0 1 2 3 4 5 6 7").is_none());
    }

    #[test]
    fn parses_dump_headers_without_chrono() {
        let text = "\
[ 1789721025 2026-09-18 16:43:45 ]
da:1f:85:0c:19:fc 192.168.5.132 117.185.244.54 47218 443 TCP 3 18-158-1-0 3565 3600 5 384 6 717 1

[ 1789721085 2026-09-18 16:44:45 ]
da:1f:85:0c:19:fc 192.168.5.132 117.185.244.54 47218 443 TCP 3 18-158-1-0 3560 3600 11 1006 11 1372 1
";
        let samples = parse_dump(text);
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].stamp.date, "2026-09-18");
        assert_eq!(samples[1].stamp.hour, 16);
        assert_eq!(samples[1].stamp.epoch, 1789721085);
        assert_eq!(samples[0].rows.len(), 1);
    }

    #[test]
    fn first_sample_establishes_baseline_without_inflating_bytes() {
        let mut store = UsageStore::new();
        let report = store.ingest(&stamp(BASE, "2026-09-18", 10), &[row(1000, 1000, "18-158-1-0")], pdd);
        assert_eq!(report.new_flows, 1);
        assert_eq!(report.bytes_delta, 0, "unknown baseline must credit nothing");
        let apps = store.apps_json("da:1f:85:0c:19:fc", "2026-09-18");
        assert_eq!(apps[0]["sessions"], 1);
        assert_eq!(apps[0]["txBytes"], 0);
    }

    #[test]
    fn byte_delta_accumulates_across_samples() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 10), &[row(1000, 2000, "18-158-1-0")], pdd);
        let report = store.ingest(&stamp(BASE + 60, "2026-09-18", 10), &[row(1500, 2800, "18-158-1-0")], pdd);
        assert_eq!(report.bytes_delta, 500 + 800);
        assert_eq!(report.updated_flows, 1);
        assert_eq!(report.new_flows, 0);
        let apps = store.apps_json("da:1f:85:0c:19:fc", "2026-09-18");
        assert_eq!(apps[0]["txBytes"], 500);
        assert_eq!(apps[0]["rxBytes"], 800);
        assert_eq!(apps[0]["sessions"], 1, "same flow must not count twice");
    }

    #[test]
    fn counter_reset_is_not_counted_as_negative() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 10), &[row(5000, 5000, "18-158-1-0")], pdd);
        let report = store.ingest(&stamp(BASE + 60, "2026-09-18", 10), &[row(20, 30, "18-158-1-0")], pdd);
        assert_eq!(report.bytes_delta, 0);
    }

    #[test]
    fn hourly_activity_is_capped_at_one_hour() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 10), &[row(0, 0, "18-158-1-0")], pdd);
        for i in 1..=200u64 {
            store.ingest(
                &stamp(BASE + i * 60, "2026-09-18", 10),
                &[row(i * 8_192, i * 8_192, "18-158-1-0")],
                pdd,
            );
        }
        let buckets = store.hourly_json("da:1f:85:0c:19:fc", "2026-09-18");
        assert_eq!(buckets[0]["minutes"], 60);
    }

    #[test]
    fn long_gaps_do_not_credit_activity() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 10), &[row(0, 0, "18-158-1-0")], pdd);
        store.ingest(&stamp(BASE + 4000, "2026-09-18", 11), &[row(100, 0, "18-158-1-0")], pdd);
        let buckets = store.hourly_json("da:1f:85:0c:19:fc", "2026-09-18");
        let total: u64 = buckets.iter().filter_map(|b| b["minutes"].as_u64()).sum();
        assert_eq!(total, 0, "a >5min suspension must not be credited as online");
    }

    #[test]
    fn online_secs_sums_the_hourly_bars() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 12), &[row(0, 0, "18-158-1-0")], pdd);
        store.ingest(&stamp(BASE + 60, "2026-09-18", 12), &[row(8_192, 0, "18-158-1-0")], pdd);
        store.ingest(&stamp(BASE + 120, "2026-09-18", 13), &[row(16_384, 0, "18-158-1-0")], pdd);
        assert_eq!(store.online_secs("da:1f:85:0c:19:fc", "2026-09-18"), 120);
    }

    #[test]
    fn heartbeat_traffic_alone_buys_no_usage_time() {
        let mut store = UsageStore::new();
        // A backgrounded app's push channel: a few hundred bytes a minute, all
        // night long. This is exactly the case that used to make a sleeping
        // phone look busy.
        store.ingest(&stamp(BASE, "2026-09-18", 2), &[row(0, 0, "7-1-2-0")], pdd);
        let mut heartbeat_flows = 0;
        for i in 1..=60u64 {
            let report = store.ingest(
                &stamp(BASE + i * 60, "2026-09-18", 2),
                &[row(i * 120, i * 60, "7-1-2-0")],
                pdd,
            );
            heartbeat_flows += report.heartbeat_flows;
        }
        let mac = "da:1f:85:0c:19:fc";
        assert_eq!(
            store.online_secs(mac, "2026-09-18"),
            0,
            "a device doing nothing but heartbeats was not in use"
        );
        let apps = store.apps_json(mac, "2026-09-18");
        assert_eq!(apps[0]["minutes"], 0, "heartbeats must not buy app minutes");
        assert_eq!(apps[0]["txBytes"], 60 * 120, "but the bytes are still counted");
        assert_eq!(heartbeat_flows, 60, "every sample should be flagged heartbeat-only");
    }

    #[test]
    fn real_interaction_clears_the_gate() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 20), &[row(0, 0, "7-1-2-0")], pdd);
        // A video feed: kilobytes per minute.
        for i in 1..=5u64 {
            store.ingest(
                &stamp(BASE + i * 60, "2026-09-18", 20),
                &[row(i * 512_000, i * 4_096_000, "7-1-2-0")],
                pdd,
            );
        }
        assert_eq!(store.online_secs("da:1f:85:0c:19:fc", "2026-09-18"), 300);
    }

    #[test]
    fn a_single_burst_cannot_buy_a_long_interval() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 20), &[row(0, 0, "7-1-2-0")], pdd);
        // Five minutes pass; the flow moved 3 KB in total, i.e. 10 B/s. That is
        // a stray background sync, not five minutes of screen time.
        let report = store.ingest(
            &stamp(BASE + 300, "2026-09-18", 20),
            &[row(3_000, 0, "7-1-2-0")],
            pdd,
        );
        assert_eq!(report.heartbeat_flows, 1);
        assert_eq!(store.online_secs("da:1f:85:0c:19:fc", "2026-09-18"), 0);
    }

    #[test]
    fn active_floor_scales_with_the_interval() {
        assert_eq!(active_floor_bytes(1), ACTIVE_MIN_BYTES);
        assert_eq!(
            active_floor_bytes(60),
            ACTIVE_MIN_BYTES.max(ACTIVE_MIN_BYTES_PER_SEC * 60)
        );
        assert!(
            active_floor_bytes(300) > active_floor_bytes(60),
            "a longer interval must demand proportionally more traffic"
        );
    }

    #[test]
    fn unidentified_appid_is_skipped_for_app_accounting() {
        let mut store = UsageStore::new();
        let report = store.ingest(
            &stamp(BASE, "2026-09-18", 10),
            &[row(0, 0, "0-0-0-0")],
            pdd,
        );
        assert_eq!(report.new_flows, 0);
        assert!(store.apps_json("da:1f:85:0c:19:fc", "2026-09-18").is_empty());
    }

    #[test]
    fn prune_keeps_newest_dates_only() {
        let mut store = UsageStore::new();
        for day in 1..=10u32 {
            let date = format!("2026-09-{:02}", day);
            store.ingest(&stamp(BASE + day as u64 * 100_000, &date, 10), &[row(0, 0, "18-158-1-0")], pdd);
        }
        assert_eq!(store.dates().len(), 10);
        let removed = store.prune(3);
        assert!(removed > 0);
        let dates = store.dates();
        assert_eq!(dates.len(), 3);
        assert!(dates.contains("2026-09-10"));
        assert!(!dates.contains("2026-09-01"));
    }

    #[test]
    fn prune_is_noop_when_within_retention() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 10), &[row(0, 0, "18-158-1-0")], pdd);
        assert_eq!(store.prune(30), 0);
        assert_eq!(store.dates().len(), 1);
    }

    #[test]
    fn canonical_app_folds_variants_but_keeps_real_products_separate() {
        assert_eq!(canonical_app("微信_weak_relation"), "微信");
        assert_eq!(canonical_app("微信_call"), "微信");
        assert_eq!(canonical_app("抖音系列"), "抖音");
        assert_eq!(canonical_app("快手系列"), "快手");
        assert_eq!(canonical_app("企业微信"), "企业微信");
        assert_eq!(canonical_app("微信视频号"), "微信视频号");
    }

    #[test]
    fn parses_rdpi_table() {
        let table = "\
微信 7-1-2-0
微信_weak_relation 7-1-2-14
抖音系列 10-5-1-0
拼多多 18-158-1-0
some garbage line
";
        let map = parse_rdpi_table(table);
        assert_eq!(map.get("7-1-2-0").map(String::as_str), Some("微信"));
        assert_eq!(map.get("18-158-1-0").map(String::as_str), Some("拼多多"));
        assert_eq!(map.len(), 4);
    }

    #[test]
    fn round_trips_through_json() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 9), &[row(100, 200, "18-158-1-0")], pdd);
        store.ingest(&stamp(BASE + 60, "2026-09-18", 9), &[row(300, 400, "18-158-1-0")], pdd);
        let restored = UsageStore::from_json(&store.to_json());
        assert_eq!(
            restored.apps_json("da:1f:85:0c:19:fc", "2026-09-18"),
            store.apps_json("da:1f:85:0c:19:fc", "2026-09-18")
        );
        assert_eq!(restored.last_epoch, BASE + 60);
    }

    #[test]
    fn ingest_dump_skips_already_seen_blocks() {
        let text = "\
[ 1789721025 2026-09-18 16:43:45 ]
da:1f:85:0c:19:fc 192.168.5.132 117.185.244.54 47218 443 TCP 3 18-158-1-0 3565 3600 5 384 6 717 1

[ 1789721085 2026-09-18 16:44:45 ]
da:1f:85:0c:19:fc 192.168.5.132 117.185.244.54 47218 443 TCP 3 18-158-1-0 3560 3600 11 1006 11 1372 1
";
        let mut store = UsageStore::new();
        let first = store.ingest_dump(text, pdd);
        assert_eq!(first.len(), 2);
        let second = store.ingest_dump(text, pdd);
        assert_eq!(second.len(), 0, "re-reading the dump must not double count");
    }

    #[test]
    fn parses_ipv6_literals() {
        assert_eq!(ipv6_to_u128("::1"), Some(1));
        assert_eq!(ipv6_to_u128("2409:8c50:a00::"), Some(0x2409_8c50_0a00u128 << 80 >> 0));
        assert!(ipv6_to_u128("2409:8c50:a00:4032::23").is_some());
        assert!(ipv6_to_u128("not-an-address").is_none());
        assert!(ipv6_to_u128("2409:8c50:a00:4032::23::1").is_none());
    }

    #[test]
    fn matches_ipv6_prefixes() {
        assert!(ipv6_in_prefix("2409:8c50:a00:4032::23", "2409:8c50:a00::/48"));
        assert!(!ipv6_in_prefix("2409:8c1e:75b0:1120::36", "2409:8c50:a00::/48"));
        assert!(ipv6_in_prefix("2409:8c1e:75b0:1120::36", "2409:8c1e:75b0::/48"));
        assert!(ipv6_in_prefix("2402:5ec0:1001:9101::", "2402:5ec0:1001::/48"));
    }

    #[test]
    fn shared_prefixes_are_refused_rather_than_guessed() {
        let table = json!({
            "apps": {
                "抖音": {"prefixes48": ["2409:8c50:a00::/48"]},
                "京东": {"prefixes48": ["2409:8c50:a00::/48"]},
                "快手": {"prefixes48": ["2402:5ec0:1001::/48"]}
            }
        });
        let attributor = PrefixAttributor::from_json(&table);
        assert_eq!(attributor.attribute("2409:8c50:a00:4032::23"), None);
        assert_eq!(attributor.attribute("2402:5ec0:1001:9101::"), Some("快手"));
        assert_eq!(attributor.attribute("2409:8c44:5900:c00:3::24"), None);
    }

    #[test]
    fn empty_prefix_table_is_detectable() {
        assert!(PrefixAttributor::new(Vec::new()).is_empty());
        assert!(!PrefixAttributor::from_json(&json!({"apps": {"微信": {"prefixes48": ["2409:8c1e:8f60::/48"]}}})).is_empty());
    }

    #[test]
    fn report_json_matches_official_report_shape() {
        let mut store = UsageStore::new();
        // Baseline sample: both flows are new, so neither earns time from it.
        store.ingest(
            &stamp(BASE, "2026-09-18", 10),
            &[row(0, 0, "18-158-1-0"), row(0, 0, "7-1-2-0")],
            pdd,
        );
        store.ingest(
            &stamp(BASE + 60, "2026-09-18", 10),
            &[row(40_960, 20_480, "18-158-1-0"), row(20_480, 12_288, "7-1-2-0")],
            pdd,
        );
        store.ingest(
            &stamp(BASE + 120, "2026-09-18", 11),
            &[row(81_920, 40_960, "18-158-1-0"), row(20_480, 12_288, "7-1-2-0")],
            pdd,
        );
        let mac = vec!["da:1f:85:0c:19:fc".to_string()];
        let report = report_json(&store, &mac, "2026-09-18");

        assert_eq!(report["date"], "2026-09-18");
        // one credited minute in hour 10, one in hour 11 -> 在线时间 2 分钟
        assert_eq!(report["onlineMinutes"], 2);
        let hourly = report["hourly"].as_array().unwrap();
        assert_eq!(hourly.len(), 2);
        assert_eq!(hourly[0]["hour"], 10);
        assert_eq!(hourly[0]["minutes"], 1);
        assert_eq!(hourly[1]["hour"], 11);
        assert_eq!(hourly[1]["minutes"], 1);

        let apps = report["apps"].as_array().unwrap();
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0]["app"], "拼多多", "sorted by minutes desc");
        assert_eq!(apps[0]["minutes"], 2);
        assert_eq!(apps[1]["app"], "微信");
        assert_eq!(
            apps[1]["minutes"], 1,
            "wechat had no traffic in hour 11, so it must not be credited"
        );
    }

    #[test]
    fn report_json_filters_by_mac_and_date() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 10), &[row(0, 0, "18-158-1-0")], pdd);
        let other = vec!["aa:bb:cc:dd:ee:ff".to_string()];
        let report = report_json(&store, &other, "2026-09-18");
        assert_eq!(report["onlineMinutes"], 0);
        assert!(report["apps"].as_array().unwrap().is_empty());

        let mac = vec!["DA:1F:85:0C:19:FC".to_string()];
        let report = report_json(&store, &mac, "2026-09-19");
        assert_eq!(report["onlineMinutes"], 0, "wrong date yields nothing");

        let report = report_json(&store, &mac, "2026-09-18");
        assert_eq!(report["apps"].as_array().unwrap().len(), 1, "mac match is case-insensitive");
    }

    #[test]
    fn persisted_store_is_aggregates_only() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 10), &[row(0, 0, "18-158-1-0")], pdd);
        let text = store.to_json().to_string();
        assert!(!text.contains("117.185.244.54"), "no remote address may be stored");
        assert!(!text.contains("47218"), "no source port may be stored");
        assert!(text.contains("\"app\":\"拼多多\""));
    }

    // -- sampler cadence -----------------------------------------------------

    fn moving_report() -> IngestReport {
        IngestReport {
            bytes_delta: 8192,
            updated_flows: 1,
            ..Default::default()
        }
    }

    #[test]
    fn sampler_samples_within_the_minute_and_pushes_within_five() {
        let mut sampler = SamplerState::default();
        assert!(sampler.sample_due(1_000), "a cold sampler always samples");
        sampler.note_sample(1_000, &[moving_report()]);
        assert!(sampler.push_due(1_000), "the very first push must happen immediately");

        assert!(!sampler.sample_due(1_030), "30s is too soon to re-read the dump");
        assert!(sampler.sample_due(1_060));

        sampler.note_push(1_000);
        assert!(!sampler.push_due(1_060), "just pushed, nothing new yet");
        sampler.note_sample(1_060, &[moving_report()]);
        assert!(!sampler.push_due(1_200), "pushes are batched, not per sample");
        assert!(sampler.push_due(1_300));
    }

    #[test]
    fn a_quiet_lan_is_not_re_uploaded_forever() {
        let mut sampler = SamplerState::default();
        sampler.note_sample(BASE, &[moving_report()]);
        sampler.note_push(BASE);

        // Nothing moved for an hour: no bytes, no new flows, no heartbeats.
        let idle = IngestReport::default();
        for step in 1..=60u64 {
            sampler.note_sample(BASE + step * 60, &[idle.clone()]);
        }
        assert!(
            !sampler.push_due(BASE + 3_600),
            "an idle device must not re-upload the same aggregates every cycle"
        );
    }

    #[test]
    fn a_heartbeat_only_interval_still_warrants_a_push() {
        let mut sampler = SamplerState::default();
        sampler.note_sample(BASE, &[moving_report()]);
        sampler.note_push(BASE);

        let heartbeat = IngestReport { heartbeat_flows: 3, ..Default::default() };
        sampler.note_sample(BASE + 60, &[heartbeat]);
        assert!(sampler.dirty, "heartbeats move bytes, so the Hub should learn about them");
    }

    #[test]
    fn app_map_refreshes_on_a_six_hour_cycle() {
        let mut sampler = SamplerState::default();
        assert!(sampler.app_map_due(BASE), "startup must warm the rdpi cache");
        sampler.note_app_map(BASE);
        assert!(!sampler.app_map_due(BASE + 3_600));
        assert!(sampler.app_map_due(BASE + APP_MAP_REFRESH_SECS));
    }

    #[test]
    fn ingest_payload_matches_the_hub_contract() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 10), &[row(0, 0, "18-158-1-0")], pdd);
        store.ingest(
            &stamp(BASE + 60, "2026-09-18", 10),
            &[row(40_960, 20_480, "18-158-1-0")],
            pdd,
        );
        let body = ingest_payload(&store, 10, Some("2026-09-18"));

        assert_eq!(body["hourlyKeepDays"], 10);
        assert_eq!(body["dailyKeepDays"], 10);
        assert_eq!(body["today"], "2026-09-18");
        // Absolute counters, camelCase: exactly what usage_hourly expects.
        let hour = &body["hours"][0];
        assert_eq!(hour["mac"], "da:1f:85:0c:19:fc");
        assert_eq!(hour["hour"], 10);
        assert_eq!(hour["activeSecs"], 60);
        assert_eq!(hour["txBytes"], 40_960);
        assert_eq!(hour["rxBytes"], 20_480);
        let app = &body["apps"][0];
        assert_eq!(app["app"], "拼多多");
        assert_eq!(app["sessions"], 1);
    }

    #[test]
    fn ingest_payload_omits_today_when_nothing_was_seen() {
        let body = ingest_payload(&UsageStore::new(), 10, None);
        assert!(body.get("today").is_none(), "no observed date means no prune reference");
        assert_eq!(body["hours"].as_array().unwrap().len(), 0);
        assert_eq!(body["apps"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn ingest_payload_falls_back_to_the_newest_observed_date() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 10), &[row(0, 0, "18-158-1-0")], pdd);
        let body = ingest_payload(&store, 10, None);
        assert_eq!(body["today"], "2026-09-18");
        // An explicit router date always wins over the store's newest date.
        let body = ingest_payload(&store, 10, Some("2026-09-19"));
        assert_eq!(body["today"], "2026-09-19");
    }

    #[test]
    fn newest_date_is_the_prune_reference() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-17", 10), &[row(0, 0, "18-158-1-0")], pdd);
        store.ingest(&stamp(BASE + 86_400, "2026-09-18", 10), &[row(0, 0, "18-158-1-0")], pdd);
        assert_eq!(store.newest_date().as_deref(), Some("2026-09-18"));
    }

    #[test]
    fn hourly_and_app_rows_round_trip_through_the_store() {
        let mut store = UsageStore::new();
        store.ingest(&stamp(BASE, "2026-09-18", 10), &[row(0, 0, "18-158-1-0")], pdd);
        store.ingest(
            &stamp(BASE + 60, "2026-09-18", 10),
            &[row(9_000, 9_000, "18-158-1-0")],
            pdd,
        );
        let rebuilt = UsageStore::from_json(&json!({
            "lastEpoch": store.last_epoch,
            "hourly": store.hourly_rows(),
            "apps": store.app_rows(),
        }));
        assert_eq!(rebuilt.hourly_json("da:1f:85:0c:19:fc", "2026-09-18"),
                   store.hourly_json("da:1f:85:0c:19:fc", "2026-09-18"));
        assert_eq!(rebuilt.apps_json("da:1f:85:0c:19:fc", "2026-09-18"),
                   store.apps_json("da:1f:85:0c:19:fc", "2026-09-18"));
    }
}
