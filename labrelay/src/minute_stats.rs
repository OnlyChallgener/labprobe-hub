//! 分钟桶统计（v3 采样口径）。
//!
//! 与 v2 (`usage_stats`) 的区别是这套模型不再估算“活跃秒数”，只回答一个问题：
//! 某个自然分钟里这台设备（或这个应用）到底用没用。一条证据最多贡献 1 分钟，
//! 所以“这一分钟只用了 5 秒”和“用了 55 秒”都记 1 分钟。
//!
//! 两条链路彻底分开：
//!
//! * **设备总流量**：`flow_audit` 的固件计数（`get_ip` 的 daily_up/daily_down，
//!   历史日走 `get_daily_ip`），与应用识别无关，所以未识别流量、内网流量都不会
//!   从总数里漏掉，也不会因为 RDPI 只覆盖 IPv4 而偏小。
//! * **应用时长**：每 5 秒读一次 `/proc/net/sniffer_flow_full`，按 MAC + 归一化
//!   应用名把同一应用族的多条 flow 合并（微信 = 7-1-2-0/3/12/14）后再判定分钟。
//!
//! 设备上网时长也用分钟桶，但取这台设备**所有**有效业务流量的并集：同一分钟里
//! 微信、小红书、支付宝一起活跃，三个应用各 +1 分钟，设备只 +1 分钟。因此
//! “各应用时长之和 > 设备总时长”是设计如此，不是统计错误。

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use serde_json::{json, Value};

use crate::usage_stats::{
    atomic_write, canonical_app, load_app_map, parse_flow_line, read_text, refresh_app_map,
    AppIdMap, FlowKey, FlowRow, UNIDENTIFIED_APPID,
};

/// 采样间隔：每 5 秒读一次 RDPI flow 表与固件计数。
pub const SAMPLE_INTERVAL_SECS: u64 = 5;

/// 推送间隔：分钟桶很小，30 秒推一次，家长端 15~30 秒轮询基本是实时的。
pub const PUSH_INTERVAL_SECS: u64 = 30;

/// 保留多少个自然日，与 App 的“最近 10 天”窗口一致。
pub const DEFAULT_KEEP_DAYS: usize = 10;

/// 单个 5 秒窗口的字节达到这个数，本分钟直接算活跃。
pub const MINUTE_ACTIVE_BYTES: u64 = 1024;

/// 一分钟内出现这么多个“有真实 payload”的窗口就算活跃。
pub const MINUTE_ACTIVE_WINDOWS: u64 = 2;

/// 多少字节算“真实 payload”。
///
/// 256B 是刻意留的下限：聊天消息、页面请求都在它之上，而 TCP ACK / 保活探测
/// 通常在一两百字节。没有这层下限，微信后台每 30 秒一次的心跳就能凑满
/// `MINUTE_ACTIVE_WINDOWS`，整晚被记成“在用”。
pub const WINDOW_PAYLOAD_FLOOR: u64 = 256;

/// flow 计数基线的存活时间，与固件最长 flow timeout 对齐。
const FLOW_BASELINE_TTL_SECS: u64 = 3600;

pub const MINUTE_STORE_PATH: &str = "/tmp/labprobe_minute_store.json";
pub const SNIFFER_FLOW_FULL: &str = "/proc/net/sniffer_flow_full";
pub const SNIFFER_FLOW: &str = "/proc/net/sniffer_flow";
pub const DHCP_LEASES: &str = "/tmp/dhcp.leases";
pub const SNIFFER_INFO: &str = "/proc/net/sniffer_info";

use std::sync::{Mutex, OnceLock};

/// 分钟桶在**进程生命周期内只有一份**。
///
/// APP 每打开一次页面就会下发一条 `get_usage_stats` 命令；如果这个命令去
/// `load_store()` 重新读盘，采样器攒下的 flow / IP 基线就会被丢掉，下一轮采样
/// 只能重新建立基线——表现为"总时长一直不涨"。所以读命令和采样共用这一份内存
/// 状态，磁盘只作为重启后的恢复点。
static MINUTE_STORE: OnceLock<Mutex<MinuteStore>> = OnceLock::new();

pub fn with_store<T>(f: impl FnOnce(&mut MinuteStore) -> T) -> T {
    let lock = MINUTE_STORE.get_or_init(|| Mutex::new(load_minute_store()));
    // 采样任务不会 panic，中毒只可能来自一次失败的落盘；拿回状态继续跑。
    let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

/// 采样节拍同样全局唯一：它记着 flow 基线之外的所有"上次什么时候干的"。
static MINUTE_SAMPLER: OnceLock<Mutex<MinuteSampler>> = OnceLock::new();

pub fn with_sampler<T>(f: impl FnOnce(&mut MinuteSampler) -> T) -> T {
    let lock = MINUTE_SAMPLER.get_or_init(|| Mutex::new(MinuteSampler::default()));
    let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

/// 供 `spawn_blocking` 调用的入口：整轮采样（fork 进程 + 读文件 + 记账 + 落盘）。
pub fn sample_now(now: u64) -> Result<MinuteReport, String> {
    with_sampler(|sampler| sampler.sample(now))
}

pub fn sample_due(now: u64) -> bool {
    with_sampler(|sampler| sampler.sample_due(now))
}

pub fn push_due(now: u64) -> bool {
    with_sampler(|sampler| sampler.push_due(now))
}

pub fn sniffer_due(now: u64) -> bool {
    with_sampler(|sampler| sampler.sniffer_due(now))
}

pub fn note_push(now: u64) {
    with_sampler(|sampler| sampler.note_push(now));
}

pub fn note_sniffer(now: u64) {
    with_sampler(|sampler| sampler.note_sniffer(now));
}

pub fn log_due(now: u64) -> bool {
    with_sampler(|sampler| sampler.log_due(now))
}

/// 有未推送内容才构造 body，空轮询不该打到 Hub。
pub fn unsent_payload() -> Option<Value> {
    with_store(|store| {
        store
            .has_unsent()
            .then(|| store.ingest_payload(DEFAULT_KEEP_DAYS))
    })
}

/// 推送成功后推进水位并立刻落盘；失败时不调用，下次整批重发。
pub fn note_payload_pushed(payload: &Value) {
    with_store(|store| {
        store.note_pushed(payload);
        let _ = save_minute_store(store);
    });
}

/// 自然分钟起点（epoch 秒）。中国时区是整小时偏移，所以它与北京时间对齐。
pub fn minute_start(epoch: u64) -> u64 {
    epoch - epoch % 60
}

// ---------------------------------------------------------------------------
// 分钟活跃判定
// ---------------------------------------------------------------------------

/// 一个自然分钟内累计到的采样证据。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MinuteEvidence {
    /// 本分钟内所有窗口的字节合计。
    pub bytes: u64,
    /// 达到 `WINDOW_PAYLOAD_FLOOR` 的窗口个数。
    pub windows: u64,
    /// 本分钟新建立、且带 payload 的业务连接数。
    pub new_flows: u64,
}

impl MinuteEvidence {
    pub fn add_window(&mut self, bytes: u64, is_new_flow: bool) {
        if bytes == 0 {
            return;
        }
        self.bytes = self.bytes.saturating_add(bytes);
        if bytes >= WINDOW_PAYLOAD_FLOOR {
            self.windows = self.windows.saturating_add(1);
        }
        if is_new_flow && bytes >= WINDOW_PAYLOAD_FLOOR {
            self.new_flows = self.new_flows.saturating_add(1);
        }
    }

    /// 少漏记优先，三条规则任一成立即活跃：整分钟合计够 1KB、有 2 个带真实
    /// payload 的窗口、或出现过新的业务连接。
    ///
    /// 合计这一条是刻意加的：细水长流的真实使用（例如持续 40B/s 的长连接）每
    /// 个 5 秒窗口都够不到单窗口门槛，但一整分钟已经走了 2KB。只按窗口判会让
    /// 这种分钟整段漏记，正是"用了几分钟就不涨了"的口径。只有"整分钟不足 1KB
    /// 且只出现过一两个孤立小窗口"的心跳会被过滤掉。
    pub fn is_active(&self) -> bool {
        self.bytes >= MINUTE_ACTIVE_BYTES
            || self.windows >= MINUTE_ACTIVE_WINDOWS
            || self.new_flows >= 1
    }
}

#[derive(Debug, Clone)]
struct Pending {
    minute: u64,
    evidence: MinuteEvidence,
}

// ---------------------------------------------------------------------------
// 固件设备计数
// ---------------------------------------------------------------------------

/// `flow_audit get_ip` 里一个 IP 的计数。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpCounters {
    /// 开机以来累计，差分得到每个采样窗口的字节。
    pub total_up: u64,
    pub total_down: u64,
    /// 固件的今日累计，直接作为设备今日流量。
    pub daily_up: u64,
    pub daily_down: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficCounters {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

fn json_u64(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::String(text)) => text.trim().parse().unwrap_or(0),
        Some(Value::Number(number)) => number.as_u64().unwrap_or(0),
        _ => 0,
    }
}

/// 解析 `flow_audit get_ip` 的 JSON 为 IP -> 计数。
pub fn parse_flow_audit_ips(text: &str) -> BTreeMap<String, IpCounters> {
    let mut out = BTreeMap::new();
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return out;
    };
    let Some(list) = value.get("ip_list").and_then(Value::as_array) else {
        return out;
    };
    for row in list {
        let Some(ip) = row.get("ip_addr").and_then(Value::as_str) else {
            continue;
        };
        // 固件把这些数字以字符串下发，两种类型都要接住。
        out.insert(
            ip.to_string(),
            IpCounters {
                total_up: json_u64(row.get("total_up")),
                total_down: json_u64(row.get("total_down")),
                daily_up: json_u64(row.get("daily_up")),
                daily_down: json_u64(row.get("daily_down")),
            },
        );
    }
    out
}

/// 解析 `flow_audit get_daily_ip` 的历史日流量。
///
/// 固件对“今天”会同时下发一条已结算记录和一条 `today_inprogress`，两者不互相
/// 包含（实测 inprogress 的下载量远大于结算行、上传量却更小）。今天只认
/// `today_inprogress`，历史日只认结算行；混着取 max 会凭空放大总数。
pub fn parse_flow_audit_daily(text: &str, today: &str) -> BTreeMap<String, TrafficCounters> {
    let mut out = BTreeMap::new();
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return out;
    };
    let Some(list) = value.get("ip_list").and_then(Value::as_array) else {
        return out;
    };
    for row in list {
        let Some(days) = row.get("daily").and_then(Value::as_array) else {
            continue;
        };
        for day in days {
            let raw = day
                .get("date")
                .map(|v| match v {
                    Value::String(text) => text.clone(),
                    Value::Number(number) => number.to_string(),
                    _ => String::new(),
                })
                .unwrap_or_default();
            if raw.len() != 8 {
                continue;
            }
            let date = format!("{}-{}-{}", &raw[0..4], &raw[4..6], &raw[6..8]);
            let in_progress = day
                .get("stat")
                .and_then(Value::as_str)
                .map(|stat| stat == "today_inprogress")
                .unwrap_or(false);
            if in_progress != (date == today) {
                continue;
            }
            out.insert(
                date,
                TrafficCounters {
                    tx_bytes: json_u64(day.get("tx_bytes")),
                    rx_bytes: json_u64(day.get("rx_bytes")),
                },
            );
        }
    }
    out
}

/// `/tmp/dhcp.leases` -> MAC -> 该 MAC 当前的全部 IPv4。
pub fn parse_mac_ips(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let mac = fields[1].to_ascii_lowercase();
        let ip = fields[2];
        if mac.len() != 17 || !mac.contains(':') || !ip.contains('.') {
            continue;
        }
        out.entry(mac).or_default().insert(ip.to_string());
    }
    out
}

// ---------------------------------------------------------------------------
// 存储
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MinuteStore {
    /// (mac, date) -> 设备活跃自然分钟起点集合。
    pub device_minutes: BTreeMap<(String, String), BTreeSet<u64>>,
    /// (mac, date, app) -> 应用活跃自然分钟起点集合。
    pub app_minutes: BTreeMap<(String, String, String), BTreeSet<u64>>,
    /// (mac, date) -> 固件日流量计数。
    pub traffic: BTreeMap<(String, String), TrafficCounters>,
    /// 已推送水位，避免每次重发整天数据。
    pushed_device: BTreeMap<(String, String), u64>,
    pushed_app: BTreeMap<(String, String, String), u64>,
    pushed_traffic: BTreeMap<(String, String), TrafficCounters>,
    /// 当前尚未结束的自然分钟。
    pending_device: BTreeMap<(String, String), Pending>,
    pending_app: BTreeMap<(String, String, String), Pending>,
    /// 跨采样保留的 flow 计数基线（含远端地址端口，故意不落盘）。
    seen_flows: BTreeMap<FlowKey, SeenFlow>,
    ip_baseline: BTreeMap<String, IpCounters>,
    /// 冷启动后的第一次采样只建立基线，不给任何分钟记账。
    resume_pending: bool,
    last_sample: u64,
}

#[derive(Debug, Clone, Copy)]
struct SeenFlow {
    bytes_up: u64,
    bytes_down: u64,
    epoch: u64,
}

impl Default for MinuteStore {
    fn default() -> Self {
        Self {
            device_minutes: BTreeMap::new(),
            app_minutes: BTreeMap::new(),
            traffic: BTreeMap::new(),
            pushed_device: BTreeMap::new(),
            pushed_app: BTreeMap::new(),
            pushed_traffic: BTreeMap::new(),
            pending_device: BTreeMap::new(),
            pending_app: BTreeMap::new(),
            seen_flows: BTreeMap::new(),
            ip_baseline: BTreeMap::new(),
            resume_pending: true,
            last_sample: 0,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MinuteReport {
    pub app_minutes: usize,
    pub device_minutes: usize,
    pub apps_with_traffic: usize,
    pub flow_rows: usize,
    pub counted_ips: usize,
}

impl MinuteReport {
    /// 一行采样计数器，写进路由器日志用来判断"管道断在哪一段"。
    pub fn summary(&self) -> String {
        format!(
            "flow_rows={} counted_ips={} apps_active={} app_minutes={} device_minutes={}",
            self.flow_rows,
            self.counted_ips,
            self.apps_with_traffic,
            self.app_minutes,
            self.device_minutes
        )
    }
}

impl MinuteStore {
    /// 记下一个应用族在一个窗口里的字节；跨分钟时先把上一分钟结算入桶。
    fn add_app_evidence(
        &mut self,
        mac: &str,
        date: &str,
        app: &str,
        minute: u64,
        bytes: u64,
        new_flow: bool,
    ) {
        let key = (mac.to_string(), date.to_string(), app.to_string());
        if let Some(existing) = self.pending_app.get(&key) {
            if existing.minute != minute {
                let settled = existing.clone();
                self.pending_app.remove(&key);
                self.settle_app(&key, settled.minute, &settled.evidence);
            }
        }
        let slot = self.pending_app
            .entry(key)
            .or_insert(Pending { minute, evidence: MinuteEvidence::default() });
        slot.minute = minute;
        slot.evidence.add_window(bytes, new_flow);
    }

    fn add_device_evidence(&mut self, mac: &str, date: &str, minute: u64, bytes: u64) {
        let key = (mac.to_string(), date.to_string());
        if let Some(existing) = self.pending_device.get(&key) {
            if existing.minute != minute {
                let settled = existing.clone();
                self.pending_device.remove(&key);
                self.settle_device(&key, settled.minute, &settled.evidence);
            }
        }
        let slot = self.pending_device
            .entry(key)
            .or_insert(Pending { minute, evidence: MinuteEvidence::default() });
        slot.minute = minute;
        slot.evidence.add_window(bytes, false);
    }

    fn settle_app(&mut self, key: &(String, String, String), minute: u64, evidence: &MinuteEvidence) {
        if !evidence.is_active() {
            return;
        }
        self.app_minutes
            .entry((key.0.clone(), key.1.clone()))
            .or_default()
            .insert(minute);
    }

    fn settle_device(&mut self, key: &(String, String), minute: u64, evidence: &MinuteEvidence) {
        if !evidence.is_active() {
            return;
        }
        self.device_minutes.entry(key.clone()).or_default().insert(minute);
    }

    /// 结算所有已经过去的自然分钟。
    ///
    /// 分钟一结束就立刻结算（下一个采样周期，即最多滞后 5 秒），**不等 TTL**。
    /// 早先的版本要求"最后一次证据超过 10 分钟"才结算，结果每一段使用的最后一
    /// 分钟要拖 10 分钟才入账，设备一停下来时长就长时间不涨——这正是"用了几分钟
    /// 就停住"的成因。
    pub fn advance_to(&mut self, now: u64) {
        let current = minute_start(now);

        let app_keys: Vec<(String, String, String)> = self.pending_app.keys().cloned().collect();
        for key in app_keys {
            let Some(pending) = self.pending_app.get(&key) else {
                continue;
            };
            if pending.minute >= current {
                continue;
            }
            let settled = pending.clone();
            self.pending_app.remove(&key);
            self.settle_app(&key, settled.minute, &settled.evidence);
        }

        let device_keys: Vec<(String, String)> = self.pending_device.keys().cloned().collect();
        for key in device_keys {
            let Some(pending) = self.pending_device.get(&key) else {
                continue;
            };
            if pending.minute >= current {
                continue;
            }
            let settled = pending.clone();
            self.pending_device.remove(&key);
            self.settle_device(&key, settled.minute, &settled.evidence);
        }
    }

    pub fn prune(&mut self, keep_days: usize, today: &str) {
        let Some(cutoff) = shift_date(today, -(keep_days as i32)) else {
            return;
        };
        self.device_minutes.retain(|(_, date), _| date.as_str() >= cutoff.as_str());
        self.app_minutes.retain(|(_, date, _), _| date.as_str() >= cutoff.as_str());
        self.traffic.retain(|(_, date), _| date.as_str() >= cutoff.as_str());
        self.pushed_device.retain(|(_, date), _| date.as_str() >= cutoff.as_str());
        self.pushed_app.retain(|(_, date, _), _| date.as_str() >= cutoff.as_str());
        self.pushed_traffic.retain(|(_, date), _| date.as_str() >= cutoff.as_str());
        let floor = self.last_sample.saturating_sub(FLOW_BASELINE_TTL_SECS);
        self.seen_flows.retain(|_, seen| seen.epoch >= floor);
    }

    fn unsent_device_minutes(&self) -> BTreeMap<(String, String), Vec<u64>> {
        let mut out = BTreeMap::new();
        for (key, minutes) in &self.device_minutes {
            let watermark = self.pushed_device.get(key).copied().unwrap_or(0);
            let fresh: Vec<u64> = minutes.iter().copied().filter(|m| *m > watermark).collect();
            if !fresh.is_empty() {
                out.insert(key.clone(), fresh);
            }
        }
        out
    }

    fn unsent_app_minutes(&self) -> BTreeMap<(String, String, String), Vec<u64>> {
        let mut out = BTreeMap::new();
        for (key, minutes) in &self.app_minutes {
            let watermark = self.pushed_app.get(key).copied().unwrap_or(0);
            let fresh: Vec<u64> = minutes.iter().copied().filter(|m| *m > watermark).collect();
            if !fresh.is_empty() {
                out.insert(key.clone(), fresh);
            }
        }
        out
    }

    fn unsent_traffic(&self) -> Vec<((String, String), TrafficCounters)> {
        self.traffic
            .iter()
            .filter(|(key, counters)| self.pushed_traffic.get(*key) != Some(counters))
            .map(|(key, counters)| (key.clone(), *counters))
            .collect()
    }

    /// 中继重启后基线为空，第一次采样必须只建立基线。
    pub fn needs_baseline(&self) -> bool {
        self.resume_pending
    }

    pub fn ingest_payload(&self, keep_days: usize) -> Value {
        let device: Vec<Value> = self
            .unsent_device_minutes()
            .into_iter()
            .map(|((mac, date), minutes)| json!({"mac": mac, "date": date, "minutes": minutes}))
            .collect();
        let apps: Vec<Value> = self
            .unsent_app_minutes()
            .into_iter()
            .map(|((mac, date, app), minutes)| {
                json!({"mac": mac, "date": date, "app": app, "minutes": minutes})
            })
            .collect();
        let traffic: Vec<Value> = self
            .unsent_traffic()
            .into_iter()
            .map(|((mac, date), counters)| {
                json!({
                    "mac": mac, "date": date,
                    "txBytes": counters.tx_bytes, "rxBytes": counters.rx_bytes,
                    "totalBytes": counters.tx_bytes.saturating_add(counters.rx_bytes),
                })
            })
            .collect();
        json!({
            "version": 3,
            "keepDays": keep_days,
            "generatedAt": self.last_sample,
            "deviceMinutes": device,
            "appMinutes": apps,
            "traffic": traffic,
        })
    }

    /// 推送成功后推进水位；失败时不调用，下次整批重发。
    pub fn note_pushed(&mut self, payload: &Value) {
        if let Some(rows) = payload.get("deviceMinutes").and_then(Value::as_array) {
            for row in rows {
                let key = string_key(row, &["mac", "date"]);
                let top = max_minute(row);
                let entry = self.pushed_device.entry(key).or_insert(0);
                *entry = (*entry).max(top);
            }
        }
        if let Some(rows) = payload.get("appMinutes").and_then(Value::as_array) {
            for row in rows {
                let key = (
                    field(row, "mac"),
                    field(row, "date"),
                    field(row, "app"),
                );
                let top = max_minute(row);
                let entry = self.pushed_app.entry(key).or_insert(0);
                *entry = (*entry).max(top);
            }
        }
        if let Some(rows) = payload.get("traffic").and_then(Value::as_array) {
            for row in rows {
                let key = (field(row, "mac"), field(row, "date"));
                self.pushed_traffic.insert(
                    key,
                    TrafficCounters {
                        tx_bytes: json_u64(row.get("txBytes")),
                        rx_bytes: json_u64(row.get("rxBytes")),
                    },
                );
            }
        }
    }

    pub fn has_unsent(&self) -> bool {
        !self.unsent_device_minutes().is_empty()
            || !self.unsent_app_minutes().is_empty()
            || !self.unsent_traffic().is_empty()
    }

    /// 路由器本地报表，供 `get_usage_stats` 调试输出使用。
    pub fn report_json(&self, macs: &[String], date: &str) -> Value {
        let wanted: BTreeSet<String> = macs.iter().map(|mac| mac.to_ascii_lowercase()).collect();
        let includes = |mac: &str| wanted.is_empty() || wanted.contains(mac);
        let mut online_minutes = 0usize;
        for ((mac, day), minutes) in &self.device_minutes {
            if includes(mac) && day == date {
                online_minutes += minutes.len();
            }
        }
        let mut traffic = TrafficCounters::default();
        for ((mac, day), counters) in &self.traffic {
            if includes(mac) && day == date {
                traffic.tx_bytes = traffic.tx_bytes.saturating_add(counters.tx_bytes);
                traffic.rx_bytes = traffic.rx_bytes.saturating_add(counters.rx_bytes);
            }
        }
        let apps: Vec<Value> = self
            .app_minutes
            .iter()
            .filter(|((mac, day, _), _)| includes(mac) && day == date)
            .map(|((mac, _, app), minutes)| {
                json!({
                    "mac": mac, "app": app, "minutes": minutes.len(),
                    "ranges": ranges_from_minutes(minutes),
                })
            })
            .collect();
        json!({
            "version": 3,
            "date": date,
            "onlineMinutes": online_minutes,
            "todayTxBytes": traffic.tx_bytes,
            "todayRxBytes": traffic.rx_bytes,
            "todayTotalBytes": traffic.tx_bytes.saturating_add(traffic.rx_bytes),
            "apps": apps,
            // 家长端靠这两个字段区分"没数据"和"今天确实 0 分钟"，以及判断数据
            // 是不是已经过期。缺了它们页面就只能靠猜。
            "lastSampleAt": self.last_sample,
            "baselining": self.needs_baseline(),
            "hasData": online_minutes > 0 || !apps.is_empty() || self.last_sample > 0,
        })
    }

    // -- 持久化 -----------------------------------------------------------

    pub fn to_json(&self) -> Value {
        json!({
            "version": 3,
            "deviceMinutes": self.device_minutes.iter().map(|((mac, date), minutes)| {
                json!({"mac": mac, "date": date, "minutes": minutes.iter().copied().collect::<Vec<_>>()})
            }).collect::<Vec<_>>(),
            "appMinutes": self.app_minutes.iter().map(|((mac, date, app), minutes)| {
                json!({"mac": mac, "date": date, "app": app, "minutes": minutes.iter().copied().collect::<Vec<_>>()})
            }).collect::<Vec<_>>(),
            "traffic": self.traffic.iter().map(|((mac, date), counters)| {
                json!({"mac": mac, "date": date, "txBytes": counters.tx_bytes, "rxBytes": counters.rx_bytes})
            }).collect::<Vec<_>>(),
            "pushedDevice": self.pushed_device.iter().map(|((mac, date), top)| {
                json!({"mac": mac, "date": date, "top": top})
            }).collect::<Vec<_>>(),
            "pushedApp": self.pushed_app.iter().map(|((mac, date, app), top)| {
                json!({"mac": mac, "date": date, "app": app, "top": top})
            }).collect::<Vec<_>>(),
            "pushedTraffic": self.pushed_traffic.iter().map(|((mac, date), counters)| {
                json!({"mac": mac, "date": date, "txBytes": counters.tx_bytes, "rxBytes": counters.rx_bytes})
            }).collect::<Vec<_>>(),
            "lastSample": self.last_sample,
        })
    }

    pub fn from_json(value: &Value) -> Self {
        // 重启后 flow / IP 计数基线全部丢失，第一次采样只能重新建立基线。
        let mut store = Self::default();
        for row in rows(value, "deviceMinutes") {
            let key = (field(row, "mac").to_ascii_lowercase(), field(row, "date"));
            if let Some(list) = row.get("minutes").and_then(Value::as_array) {
                let entry = store.device_minutes.entry(key).or_default();
                entry.extend(list.iter().filter_map(Value::as_u64));
            }
        }
        for row in rows(value, "appMinutes") {
            let key = (
                field(row, "mac").to_ascii_lowercase(),
                field(row, "date"),
                field(row, "app"),
            );
            if let Some(list) = row.get("minutes").and_then(Value::as_array) {
                let entry = store.app_minutes.entry(key).or_default();
                entry.extend(list.iter().filter_map(Value::as_u64));
            }
        }
        for row in rows(value, "traffic") {
            let key = (field(row, "mac").to_ascii_lowercase(), field(row, "date"));
            store.traffic.insert(key, counters_of(row));
        }
        for row in rows(value, "pushedDevice") {
            if let Some(top) = row.get("top").and_then(Value::as_u64) {
                store.pushed_device.insert((field(row, "mac"), field(row, "date")), top);
            }
        }
        for row in rows(value, "pushedApp") {
            if let Some(top) = row.get("top").and_then(Value::as_u64) {
                store
                    .pushed_app
                    .insert((field(row, "mac"), field(row, "date"), field(row, "app")), top);
            }
        }
        for row in rows(value, "pushedTraffic") {
            store
                .pushed_traffic
                .insert((field(row, "mac"), field(row, "date")), counters_of(row));
        }
        store.last_sample = value.get("lastSample").and_then(Value::as_u64).unwrap_or(0);
        store
    }
}

fn rows(value: &Value, key: &str) -> Vec<&Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|list| list.iter().collect())
        .unwrap_or_default()
}

fn field(row: &Value, key: &str) -> String {
    row.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn string_key(row: &Value, keys: &[&str]) -> (String, String) {
    (field(row, keys[0]), field(row, keys[1]))
}

fn counters_of(row: &Value) -> TrafficCounters {
    TrafficCounters {
        tx_bytes: json_u64(row.get("txBytes")),
        rx_bytes: json_u64(row.get("rxBytes")),
    }
}

fn max_minute(row: &Value) -> u64 {
    row.get("minutes")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_u64).max().unwrap_or(0))
        .unwrap_or(0)
}

/// 连续分钟合成真实时间段：`end` 是最后一个活跃分钟 +60，即 08:15/08:16/08:17
/// 显示成 08:15–08:18、3 分钟。断开的分钟必然落成两段，不会用首末时间冒充连续。
pub fn ranges_from_minutes(minutes: &BTreeSet<u64>) -> Vec<Value> {
    let mut out = Vec::new();
    let mut run: Option<(u64, u64, usize)> = None;
    for minute in minutes.iter() {
        match run {
            Some((start, previous, count)) if *minute == previous + 60 => {
                run = Some((start, *minute, count + 1));
            }
            _ => {
                if let Some((start, last, count)) = run.take() {
                    out.push(range_json(start, last, count));
                }
                run = Some((*minute, *minute, 1));
            }
        }
    }
    if let Some((start, last, count)) = run {
        out.push(range_json(start, last, count));
    }
    out
}

fn range_json(start: u64, last: u64, count: usize) -> Value {
    json!({"startEpoch": start, "endEpoch": last + 60, "minutes": count})
}

// ---------------------------------------------------------------------------
// 采样
// ---------------------------------------------------------------------------

/// 一次 5 秒采样的输入。全部以参数注入，便于单测复现真实固件数据。
#[derive(Debug, Clone, Default)]
pub struct SampleInput {
    pub now: u64,
    pub date: String,
    pub flow_rows: Vec<FlowRow>,
    pub ip_counters: BTreeMap<String, IpCounters>,
    pub mac_ips: BTreeMap<String, BTreeSet<String>>,
    pub app_names: AppIdMap,
    pub child_macs: BTreeSet<String>,
}

/// 把一次采样的证据写进 store：应用族按 MAC + 归一化名合并，设备按所有 IP 并集。
pub fn apply_sample(store: &mut MinuteStore, input: &SampleInput) -> MinuteReport {
    let mut report = MinuteReport::default();
    let now = input.now;
    let minute = minute_start(now);
    let baselining = store.resume_pending;

    // -- RDPI flow：同一应用族的多条 flow 先合并再判定 ---------------------
    let mut app_window: BTreeMap<(String, String), (u64, bool)> = BTreeMap::new();
    let mut live_keys: BTreeSet<FlowKey> = BTreeSet::new();
    for row in &input.flow_rows {
        if !input.child_macs.is_empty() && !input.child_macs.contains(&row.mac) {
            continue;
        }
        // 0-0-0-0 是引擎的“不知道”，它只进设备总时长，不进应用列表。
        if row.appid == UNIDENTIFIED_APPID {
            continue;
        }
        let Some(name) = input.app_names.get(&row.appid) else {
            continue;
        };
        let app = canonical_app(name);
        let key = row.key();
        live_keys.insert(key.clone());
        let previous = store.seen_flows.get(&key).copied();
        store.seen_flows.insert(
            key,
            SeenFlow {
                bytes_up: row.counters.bytes_up,
                bytes_down: row.counters.bytes_down,
                epoch: now,
            },
        );
        let (delta, is_new) = match previous {
            Some(seen)
                if row.counters.bytes_up >= seen.bytes_up
                    && row.counters.bytes_down >= seen.bytes_down =>
            {
                (
                    row.counters
                        .bytes_up
                        .saturating_sub(seen.bytes_up)
                        .saturating_add(row.counters.bytes_down.saturating_sub(seen.bytes_down)),
                    false,
                )
            }
            // 计数器倒退说明固件把这条五元组的槽位复用给了新连接。继续按差值算
            // 会永远得到 0，这条 flow 从此不再入账——就是"flow 一直在、时长却
            // 不涨"。按新连接重新起算。
            Some(_) | None => (
                // 冷启动首次见到的 flow 已经带着整条连接的累计字节，不能记账。
                if baselining {
                    0
                } else {
                    row.counters.bytes_up + row.counters.bytes_down
                },
                !baselining,
            ),
        };
        if delta == 0 {
            continue;
        }
        let slot = app_window.entry((row.mac.clone(), app)).or_insert((0, false));
        slot.0 = slot.0.saturating_add(delta);
        slot.1 |= is_new;
    }
    // 已经从表里消失的 flow 不可能再贡献字节，基线留着只占内存。
    let floor = now.saturating_sub(FLOW_BASELINE_TTL_SECS);
    store
        .seen_flows
        .retain(|key, seen| live_keys.contains(key) || seen.epoch >= floor);

    for ((mac, app), (bytes, is_new)) in &app_window {
        store.add_app_evidence(mac, &input.date, app, minute, *bytes, *is_new);
        report.apps_with_traffic += 1;
    }
    report.flow_rows = input.flow_rows.len();

    // -- 固件设备计数：MAC 的全部 IP 求并集 -------------------------------
    for (mac, ips) in &input.mac_ips {
        if !input.child_macs.is_empty() && !input.child_macs.contains(mac) {
            continue;
        }
        let mut window_bytes = 0u64;
        let mut today = TrafficCounters::default();
        let mut saw_counters = false;
        for ip in ips {
            let Some(counters) = input.ip_counters.get(ip) else {
                continue;
            };
            saw_counters = true;
            today.tx_bytes = today.tx_bytes.saturating_add(counters.daily_up);
            today.rx_bytes = today.rx_bytes.saturating_add(counters.daily_down);
            if let Some(previous) = store.ip_baseline.get(ip) {
                window_bytes = window_bytes.saturating_add(
                    counters
                        .total_up
                        .saturating_sub(previous.total_up)
                        .saturating_add(counters.total_down.saturating_sub(previous.total_down)),
                );
            }
            store.ip_baseline.insert(ip.clone(), *counters);
            report.counted_ips += 1;
        }
        // `flow_audit` 偶尔会超时。查不到计数时必须保留上一次的真值，否则一次
        // 失败的 ubus 调用就把今天的流量清零，家长端看到的是"突然没用过"。
        if saw_counters {
            store
                .traffic
                .insert((mac.clone(), input.date.clone()), today);
        }
        if !baselining && window_bytes > 0 {
            store.add_device_evidence(mac, &input.date, minute, window_bytes);
        }
    }

    store.advance_to(now);
    store.last_sample = now;
    store.resume_pending = false;
    report.device_minutes = store
        .device_minutes
        .values()
        .map(|minutes| minutes.len())
        .sum();
    report.app_minutes = store.app_minutes.values().map(|minutes| minutes.len()).sum();
    report
}

// ---------------------------------------------------------------------------
// 与系统的接缝
// ---------------------------------------------------------------------------

/// 路由器本地日期（BusyBox `date`），固件与报表都按这个口径分天。
pub fn local_date() -> Option<String> {
    let text = command_text("date", &["+%Y-%m-%d"])?;
    (text.len() == 10).then_some(text)
}

/// 路由器本地 epoch 秒。
pub fn now_epoch() -> u64 {
    command_text("date", &["+%s"])
        .and_then(|text| text.parse().ok())
        .unwrap_or(0)
}

fn command_text(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn load_minute_store() -> MinuteStore {
    read_text(MINUTE_STORE_PATH)
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .map(MinuteStore::from_json)
        .unwrap_or_default()
}

pub fn save_minute_store(store: &MinuteStore) -> std::io::Result<()> {
    atomic_write(MINUTE_STORE_PATH, &store.to_json().to_string())
}

/// 读 RDPI flow 表：优先 full 表（含全部主机与未识别 flow），退回旧表。
pub fn read_flow_rows() -> Vec<FlowRow> {
    for path in [SNIFFER_FLOW_FULL, SNIFFER_FLOW] {
        if let Some(text) = read_text(path) {
            let rows: Vec<FlowRow> = text.lines().filter_map(parse_flow_line).collect();
            if !rows.is_empty() {
                return rows;
            }
        }
    }
    Vec::new()
}

fn ubus_text(object: &str, method: &str, body: &str) -> Option<String> {
    command_text("ubus", &["-t", "5", "call", object, method, body])
}

pub fn read_ip_counters() -> BTreeMap<String, IpCounters> {
    ubus_text("flow_audit", "get_ip", "{}")
        .map(|text| parse_flow_audit_ips(&text))
        .unwrap_or_default()
}

/// 按 IP 取历史日流量（固件只留最近几天，用来补中继重启当天的空档）。
pub fn read_daily_traffic(ip: &str, today: &str) -> BTreeMap<String, TrafficCounters> {
    let body = json!({"ip": ip}).to_string();
    ubus_text("flow_audit", "get_daily_ip", &body)
        .map(|text| parse_flow_audit_daily(&text, today))
        .unwrap_or_default()
}

pub fn read_mac_ips() -> BTreeMap<String, BTreeSet<String>> {
    read_text(DHCP_LEASES)
        .map(parse_mac_ips)
        .unwrap_or_default()
}

/// 固件儿童设备列表。空列表时不过滤，避免中继比策略先启动时什么都记不到。
pub fn read_child_macs() -> BTreeSet<String> {
    let Some(text) = read_text(SNIFFER_INFO) else {
        return BTreeSet::new();
    };
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 2 || fields[1] != "1" {
                return None;
            }
            let mac = fields[0].to_ascii_lowercase();
            (mac.len() == 17 && mac.contains(':')).then_some(mac)
        })
        .collect()
}

/// `rdpi -t` 的 appid -> 名称表；采样期间只读缓存，刷新交给调用方按小时安排。
pub fn app_names() -> AppIdMap {
    let cached = load_app_map();
    if cached.is_empty() {
        refresh_app_map()
    } else {
        cached
    }
}

/// 把日期往前/往后挪若干天，用于保留窗口裁剪（不依赖时区库）。
fn shift_date(date: &str, days: i32) -> Option<String> {
    if date.len() != 10 {
        return None;
    }
    let mut year: i32 = date[0..4].parse().ok()?;
    let mut month: i32 = date[5..7].parse().ok()?;
    let mut total = date[8..10].parse::<i32>().ok()? + days;
    loop {
        let length = days_in_month(year, month);
        if total > length {
            total -= length;
            month += 1;
            if month > 12 {
                month = 1;
                year += 1;
            }
        } else if total < 1 {
            month -= 1;
            if month < 1 {
                month = 12;
                year -= 1;
            }
            total += days_in_month(year, month);
        } else {
            break;
        }
    }
    Some(format!("{:04}-{:02}-{:02}", year, month, total))
}

fn days_in_month(year: i32, month: i32) -> i32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        _ => 28,
    }
}

/// 打开识别列表 / full mode。`child_guard` 每次重载策略都会把它们清掉。
pub fn prepare_sniffer() -> bool {
    crate::usage_stats::prepare_sniffer()
}

// ---------------------------------------------------------------------------
// 节拍
// ---------------------------------------------------------------------------

/// `rdpi -t` 特征库只在固件升级时变化，六小时刷一次足够。
pub const APP_MAP_REFRESH_SECS: u64 = 6 * 3600;

/// 分钟桶落盘周期。
pub const PERSIST_INTERVAL_SECS: u64 = 30;

/// 采样计数器写日志的周期。每 5 秒一条会把日志冲掉，一分钟一条正好用来盯
/// "flow 有没有在动、分钟桶有没有在涨"。
pub const SAMPLE_LOG_INTERVAL_SECS: u64 = 60;

/// 识别列表与 full mode 的重申周期。它决定应用时长能不能记上，必须比采样更勤，
/// 又不能每 5 秒起两个 ubus 进程。
pub const SNIFFER_PREPARE_INTERVAL_SECS: u64 = 300;

/// 采样节拍与只读文件/命令的缓存，本身不含统计状态（那在 [`MinuteStore`] 里）。
#[derive(Debug, Default)]
pub struct MinuteSampler {
    last_sample_at: u64,
    last_push_at: u64,
    last_app_map_at: u64,
    last_sniffer_at: u64,
    app_names: AppIdMap,
    last_saved_at: u64,
    last_log_at: u64,
    /// 本地日期按分钟缓存，省掉每 5 秒一次的 `date` fork。
    cached_date: Option<(u64, String)>,
}

impl MinuteSampler {
    pub fn sample_due(&self, now: u64) -> bool {
        self.last_sample_at == 0
            || now.saturating_sub(self.last_sample_at) >= SAMPLE_INTERVAL_SECS
    }

    pub fn push_due(&self, now: u64) -> bool {
        self.last_push_at == 0 || now.saturating_sub(self.last_push_at) >= PUSH_INTERVAL_SECS
    }

    pub fn sniffer_due(&self, now: u64) -> bool {
        self.last_sniffer_at == 0
            || now.saturating_sub(self.last_sniffer_at) >= SNIFFER_PREPARE_INTERVAL_SECS
    }

    pub fn note_push(&mut self, now: u64) {
        self.last_push_at = now;
    }

    pub fn note_sniffer(&mut self, now: u64) {
        self.last_sniffer_at = now;
    }

    /// 这一轮的采样计数器该不该写日志。
    pub fn log_due(&mut self, now: u64) -> bool {
        if self.last_log_at != 0 && now.saturating_sub(self.last_log_at) < SAMPLE_LOG_INTERVAL_SECS {
            return false;
        }
        self.last_log_at = now;
        true
    }

    /// 本地日期（北京时区的日历日），每个自然分钟只算一次。
    fn date_of(&mut self, now: u64) -> Option<String> {
        let bucket = minute_start(now);
        match &self.cached_date {
            Some((key, date)) if *key == bucket => Some(date.clone()),
            _ => {
                let date = local_date()?;
                self.cached_date = Some((bucket, date.clone()));
                Some(date)
            }
        }
    }

    /// appid -> 名称表。只在缺失或到期时才付 `rdpi -t` 的开销。
    fn app_names(&mut self, now: u64) -> AppIdMap {
        if self.app_names.is_empty() {
            self.app_names = load_app_map();
        }
        let stale = self.last_app_map_at == 0
            || now.saturating_sub(self.last_app_map_at) >= APP_MAP_REFRESH_SECS;
        if stale {
            self.last_app_map_at = now;
            let refreshed = refresh_app_map();
            // 引擎没答话就退回缓存文件，别把已有的一张表清空。
            if !refreshed.is_empty() {
                self.app_names = refreshed;
            } else if self.app_names.is_empty() {
                self.app_names = load_app_map();
            }
        }
        self.app_names.clone()
    }

    /// 采一次样：读固件表 + `flow_audit`，写进程内的分钟桶，落盘。
    ///
    /// 文件和 `ubus` 都在锁外读，锁里只做纯计算和写盘，这样 `get_usage_stats`
    /// 的读请求不会和采样抢同一把锁。
    pub fn sample(&mut self, now: u64) -> Result<MinuteReport, String> {
        let date = self.date_of(now).ok_or("无法读取路由器本地日期")?;
        let app_names = self.app_names(now);
        let input = SampleInput {
            now,
            date: date.clone(),
            flow_rows: read_flow_rows(),
            ip_counters: read_ip_counters(),
            mac_ips: read_mac_ips(),
            app_names,
            child_macs: read_child_macs(),
        };
        let persist = now.saturating_sub(self.last_saved_at) >= PERSIST_INTERVAL_SECS;
        let report = with_store(|store| {
            let report = apply_sample(store, &input);
            store.prune(DEFAULT_KEEP_DAYS, &date);
            if persist {
                save_minute_store(store).map_err(|error| format!("写入分钟桶失败: {}", error))?;
            }
            Ok(report)
        })?;
        self.last_sample_at = now;
        if persist {
            self.last_saved_at = now;
        }
        Ok(report)
    }
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usage_stats::parse_proc_flow;

    const MAC: &str = "da:1f:85:0c:19:fc";
    const OTHER: &str = "1a:9c:c5:c5:b7:bb";
    /// 2026-09-20 08:15:00 +08:00
    const T0: u64 = 1_789_862_100;

    fn names() -> AppIdMap {
        AppIdMap::from([
            ("7-1-2-0".to_string(), "微信".to_string()),
            ("7-1-2-3".to_string(), "微信".to_string()),
            ("18-158-1-0".to_string(), "抖音".to_string()),
        ])
    }

    fn flow(appid: &str, up: u64, down: u64, port: u32) -> FlowRow {
        FlowRow {
            mac: MAC.to_string(),
            src_ip: "192.168.5.132".to_string(),
            dst_ip: "117.185.244.54".to_string(),
            sport: port,
            dport: 443,
            proto: "TCP".to_string(),
            appid: appid.to_string(),
            idle: 0,
            timeout: 3600,
            counters: crate::usage_stats::FlowCounters {
                bytes_up: up,
                bytes_down: down,
            },
        }
    }

    fn counters(total_up: u64, total_down: u64) -> IpCounters {
        IpCounters {
            total_up,
            total_down,
            daily_up: total_up / 2,
            daily_down: total_down / 2,
        }
    }

    fn input(now: u64, flows: Vec<FlowRow>, ip: IpCounters) -> SampleInput {
        SampleInput {
            now,
            date: "2026-09-20".to_string(),
            flow_rows: flows,
            ip_counters: BTreeMap::from([("192.168.5.132".to_string(), ip)]),
            mac_ips: BTreeMap::from([(
                MAC.to_string(),
                BTreeSet::from(["192.168.5.132".to_string()]),
            )]),
            app_names: names(),
            child_macs: BTreeSet::from([MAC.to_string()]),
        }
    }

    #[test]
    fn five_seconds_of_traffic_is_one_minute() {
        let mut store = MinuteStore::default();
        let sample = input(
            T0,
            vec![flow("7-1-2-0", 4000, 9000, 47218)],
            counters(0, 0),
        );
        // 冷启动只建基线，一条字节都不记。
        apply_sample(&mut store, &sample);
        assert_eq!(store.app_minutes.values().map(|m| m.len()).sum::<usize>(), 0);

        let next = input(
            T0 + 5,
            vec![flow("7-1-2-0", 4000 + 600, 9000 + 900, 47218)],
            counters(1_000_000, 8_000_000),
        );
        apply_sample(&mut store, &next);
        // 结算分钟要等分钟过去，先手工推进到下一分钟。
        store.advance_to(T0 + 60);
        let minutes = store
            .app_minutes
            .get(&(MAC.to_string(), "2026-09-20".to_string(), "微信".to_string()))
            .cloned()
            .unwrap_or_default();
        assert_eq!(minutes.iter().copied().collect::<Vec<_>>(), vec![minute_start(T0)]);
        // 5 秒和 55 秒一样，只有一分钟。
        assert_eq!(
            store
                .device_minutes
                .get(&(MAC.to_string(), "2026-09-20".to_string()))
                .map(|m| m.len()),
            Some(1)
        );
    }

    #[test]
    fn app_family_merges_sub_appids_into_one_name() {
        let mut store = MinuteStore::default();
        apply_sample(
            &mut store,
            &input(T0, vec![], counters(0, 0)),
        );
        let sample = input(
            T0 + 5,
            vec![
                flow("7-1-2-0", 5_000, 5_000, 47218),
                flow("7-1-2-3", 3_000, 3_000, 47219),
            ],
            counters(10_000, 10_000),
        );
        apply_sample(&mut store, &sample);
        store.advance_to(T0 + 60);
        let keys: Vec<String> = store
            .app_minutes
            .keys()
            .map(|(_, _, app)| app.clone())
            .collect();
        // 合并成一个应用族，UI 里只有一个"微信"。
        assert_eq!(keys, vec!["微信".to_string()]);
    }

    #[test]
    fn isolated_heartbeat_window_is_filtered() {
        let mut store = MinuteStore::default();
        apply_sample(&mut store, &input(T0, vec![], counters(0, 0)));
        // 整分钟 200B、单窗口 < WINDOW_PAYLOAD_FLOOR、没有新连接：不算活跃。
        let sample = input(
            T0 + 5,
            vec![flow("7-1-2-0", 100, 100, 47218)],
            counters(100, 100),
        );
        apply_sample(&mut store, &sample);
        store.advance_to(T0 + 60);
        assert!(store.app_minutes.is_empty());
        assert!(store.device_minutes.is_empty());
    }

    #[test]
    fn two_windows_of_real_payload_count_as_active() {
        let mut store = MinuteStore::default();
        apply_sample(&mut store, &input(T0, vec![], counters(0, 0)));
        for (offset, up) in [(5u64, 400u64), (10, 800)] {
            let sample = input(
                T0 + offset,
                vec![flow("7-1-2-0", up, up, 47218)],
                counters(up * 2, up * 2),
            );
            apply_sample(&mut store, &sample);
        }
        store.advance_to(T0 + 60);
        assert_eq!(
            store
                .app_minutes
                .get(&(MAC.to_string(), "2026-09-20".to_string(), "微信".to_string()))
                .map(|m| m.len()),
            Some(1)
        );
    }

    #[test]
    fn unidentified_traffic_counts_for_the_device_only() {
        let mut store = MinuteStore::default();
        apply_sample(&mut store, &input(T0, vec![], counters(0, 0)));
        let sample = input(
            T0 + 5,
            vec![flow("0-0-0-0", 50_000, 50_000, 47218)],
            counters(200_000, 200_000),
        );
        apply_sample(&mut store, &sample);
        store.advance_to(T0 + 60);
        // 0-0-0-0 只进设备总时长。
        assert!(store.app_minutes.is_empty());
        assert_eq!(
            store
                .device_minutes
                .get(&(MAC.to_string(), "2026-09-20".to_string()))
                .map(|m| m.len()),
            Some(1)
        );
        // 设备总流量来自固件计数，与 RDPI 无关。
        assert_eq!(
            store.traffic.get(&(MAC.to_string(), "2026-09-20".to_string())),
            Some(&TrafficCounters {
                tx_bytes: 100_000,
                rx_bytes: 100_000
            })
        );
    }

    #[test]
    fn three_separate_minutes_become_three_ranges() {
        let minutes = BTreeSet::from([minute_start(T0), minute_start(T0) + 60, minute_start(T0) + 600]);
        let ranges = ranges_from_minutes(&minutes);
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0]["minutes"], json!(2));
        assert_eq!(
            ranges[0]["endEpoch"].as_u64().unwrap() - ranges[0]["startEpoch"].as_u64().unwrap(),
            120
        );
        assert_eq!(ranges[2]["minutes"], json!(1));
    }

    #[test]
    fn only_child_devices_are_counted() {
        let mut store = MinuteStore::default();
        apply_sample(&mut store, &input(T0, vec![], counters(0, 0)));
        // 非管控设备的大流量 burst 不能进应用桶；管控设备自己的固件计数照常入账。
        let mut sample = input(
            T0 + 5,
            vec![flow("7-1-2-0", 9_000, 9_000, 47218)],
            counters(20_000, 20_000),
        );
        sample.flow_rows[0].mac = OTHER.to_string();
        apply_sample(&mut store, &sample);
        store.advance_to(T0 + 60);
        assert!(store.app_minutes.is_empty());
        assert_eq!(
            store
                .device_minutes
                .get(&(MAC.to_string(), "2026-09-20".to_string()))
                .map(|minutes| minutes.len()),
            Some(1)
        );
        assert!(!store
            .device_minutes
            .contains_key(&(OTHER.to_string(), "2026-09-20".to_string())));
    }

    #[test]
    fn a_reused_flow_slot_resumes_counting_instead_of_freezing() {
        let mut store = MinuteStore::default();
        apply_sample(&mut store, &input(T0, vec![], counters(0, 0)));
        apply_sample(
            &mut store,
            &input(T0 + 5, vec![flow("7-1-2-0", 9_000, 9_000, 47218)], counters(9_000, 9_000)),
        );
        // 固件把同一条五元组复用给新连接：计数器倒退必须重新起算，否则这条
        // flow 之后每个窗口的差值都是 0，时长就永远停在这里。
        apply_sample(
            &mut store,
            &input(
                T0 + 10,
                vec![flow("7-1-2-0", 4_000, 4_000, 47218)],
                counters(20_000, 20_000),
            ),
        );
        store.advance_to(T0 + 60);
        assert_eq!(
            store
                .app_minutes
                .get(&(MAC.to_string(), "2026-09-20".to_string(), "微信".to_string()))
                .map(|minutes| minutes.len()),
            Some(1)
        );
    }

    #[test]
    fn payload_only_carries_minutes_after_the_watermark() {
        let mut store = MinuteStore::default();
        store
            .device_minutes
            .insert((MAC.to_string(), "2026-09-20".to_string()), BTreeSet::from([T0, T0 + 60]));
        let body = store.ingest_payload(DEFAULT_KEEP_DAYS);
        assert_eq!(body["deviceMinutes"][0]["minutes"].as_array().unwrap().len(), 2);
        store.note_pushed(&body);
        assert!(!store.has_unsent());
        store
            .device_minutes
            .get_mut(&(MAC.to_string(), "2026-09-20".to_string()))
            .unwrap()
            .insert(T0 + 120);
        let body = store.ingest_payload(DEFAULT_KEEP_DAYS);
        // 只重发新增的那一分钟，不整天重传。
        assert_eq!(body["deviceMinutes"][0]["minutes"].as_array().unwrap().len(), 1);
        assert_eq!(body["deviceMinutes"][0]["minutes"][0], json!(T0 + 120));
    }

    #[test]
    fn store_round_trips_through_json() {
        let mut store = MinuteStore::default();
        store
            .device_minutes
            .insert((MAC.to_string(), "2026-09-20".to_string()), BTreeSet::from([T0]));
        store
            .app_minutes
            .insert((MAC.to_string(), "2026-09-20".to_string(), "微信".to_string()), BTreeSet::from([T0, T0 + 60]));
        store.traffic.insert(
            (MAC.to_string(), "2026-09-20".to_string()),
            TrafficCounters { tx_bytes: 11, rx_bytes: 22 },
        );
        let restored = MinuteStore::from_json(&store.to_json());
        assert_eq!(restored.device_minutes, store.device_minutes);
        assert_eq!(restored.app_minutes, store.app_minutes);
        assert_eq!(restored.traffic, store.traffic);
        assert!(restored.needs_baseline());
    }

    #[test]
    fn parses_firmware_ip_counters() {
        let text = r#"{"ip_list":[{"ip_addr":"192.168.5.132","total_up":"123","total_down":"456","daily_up":"12","daily_down":"45"}]}"#;
        let parsed = parse_flow_audit_ips(text);
        assert_eq!(
            parsed.get("192.168.5.132"),
            Some(&IpCounters { total_up: 123, total_down: 456, daily_up: 12, daily_down: 45 })
        );
    }

    #[test]
    fn daily_history_prefers_inprogress_for_today() {
        let text = r#"{"ip_list":[{"ip_addr":"192.168.5.132","daily":[
            {"date":"20260920","tx_bytes":"100","rx_bytes":"200","stat":"closed"},
            {"date":"20260920","tx_bytes":"900","rx_bytes":"5000","stat":"today_inprogress"},
            {"date":"20260919","tx_bytes":"70","rx_bytes":"80","stat":"closed"}
        ]}]}"#;
        let parsed = parse_flow_audit_daily(text, "2026-09-20");
        assert_eq!(
            parsed.get("2026-09-20"),
            Some(&TrafficCounters { tx_bytes: 900, rx_bytes: 5000 })
        );
        assert_eq!(
            parsed.get("2026-09-19"),
            Some(&TrafficCounters { tx_bytes: 70, rx_bytes: 80 })
        );
    }

    #[test]
    fn parses_dhcp_leases_into_mac_ip_sets() {
        let parsed = parse_mac_ips(
            "1789862000 da:1f:85:0c:19:fc 192.168.5.132 00:00:00:00:00:00 host\nbad line\n",
        );
        assert_eq!(
            parsed.get(MAC),
            Some(&BTreeSet::from(["192.168.5.132".to_string()]))
        );
    }

    #[test]
    fn real_flow_row_line_parses() {
        let row = parse_proc_flow(
            "da:1f:85:0c:19:fc 192.168.5.132 117.185.244.54 47218 443 TCP 3 18-158-1-0 3572 3600 11 1006 11 1372 1",
        )
        .expect("row");
        assert_eq!(row.appid, "18-158-1-0");
        assert_eq!(row.counters.bytes_up, 1006);
    }
}
