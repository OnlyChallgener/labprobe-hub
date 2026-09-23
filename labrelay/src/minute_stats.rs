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
    /// 上行合计。v4 起单独记账：夜间要区分「人在用」和「只在下载」。
    pub up: u64,
    /// 下行合计。
    pub down: u64,
    /// 达到 `WINDOW_PAYLOAD_FLOOR` 的窗口个数。
    pub windows: u64,
    /// 本分钟新建立、且带 payload 的业务连接数。
    pub new_flows: u64,
}

impl MinuteEvidence {
    pub fn add_window(&mut self, up: u64, down: u64, is_new_flow: bool) {
        let window = up.saturating_add(down);
        if window == 0 {
            return;
        }
        self.bytes = self.bytes.saturating_add(window);
        self.up = self.up.saturating_add(up);
        self.down = self.down.saturating_add(down);
        if window >= WINDOW_PAYLOAD_FLOOR {
            self.windows = self.windows.saturating_add(1);
        }
        if is_new_flow && window >= WINDOW_PAYLOAD_FLOOR {
            self.new_flows = self.new_flows.saturating_add(1);
        }
    }

    /// 上线给 Hub 的四个数，顺序即 wire 数组顺序：up, down, windows, new_flows。
    pub fn wire(&self) -> [u64; 4] {
        [self.up, self.down, self.windows, self.new_flows]
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
    /// (mac, date) -> 活跃自然分钟起点 -> 该分钟证据。
    pub device_minutes: BTreeMap<(String, String), BTreeMap<u64, MinuteEvidence>>,
    /// (mac, date, app) -> 应用活跃自然分钟起点 -> 该分钟证据。
    pub app_minutes: BTreeMap<(String, String, String), BTreeMap<u64, MinuteEvidence>>,
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
    #[allow(clippy::too_many_arguments)]
    fn add_app_evidence(
        &mut self,
        mac: &str,
        date: &str,
        app: &str,
        minute: u64,
        up: u64,
        down: u64,
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
        let evidence = {
            let slot = self
                .pending_app
                .entry(key.clone())
                .or_insert(Pending { minute, evidence: MinuteEvidence::default() });
            slot.minute = minute;
            slot.evidence.add_window(up, down, new_flow);
            slot.evidence.clone()
        };
        // 证据一够就立刻入账，当前分钟当场可见，不用等它过完。分钟起点是天然
        // 的稳定去重键，同一分钟后面再命中也只是往集合里插同一个值。
        self.settle_app(&key, minute, &evidence);
    }

    fn add_device_evidence(&mut self, mac: &str, date: &str, minute: u64, up: u64, down: u64) {
        let key = (mac.to_string(), date.to_string());
        if let Some(existing) = self.pending_device.get(&key) {
            if existing.minute != minute {
                let settled = existing.clone();
                self.pending_device.remove(&key);
                self.settle_device(&key, settled.minute, &settled.evidence);
            }
        }
        let evidence = {
            let slot = self
                .pending_device
                .entry(key.clone())
                .or_insert(Pending { minute, evidence: MinuteEvidence::default() });
            slot.minute = minute;
            slot.evidence.add_window(up, down, false);
            slot.evidence.clone()
        };
        self.settle_device(&key, minute, &evidence);
    }

    fn settle_app(
        &mut self,
        key: &(String, String, String),
        minute: u64,
        evidence: &MinuteEvidence,
    ) {
        if !evidence.is_active() {
            return;
        }
        self.app_minutes
            .entry((key.0.clone(), key.1.clone(), key.2.clone()))
            .or_default()
            // 每个窗口都带整分钟的累计值进来，所以覆盖就是"取最新最全的那份"。
            .insert(minute, evidence.clone());
    }

    fn settle_device(&mut self, key: &(String, String), minute: u64, evidence: &MinuteEvidence) {
        if !evidence.is_active() {
            return;
        }
        self.device_minutes
            .entry(key.clone())
            .or_default()
            .insert(minute, evidence.clone());
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

    /// 只推「已经结束」的分钟。
    ///
    /// 分钟在活跃的那一刻就当场入账，所以本分钟的证据还在往上长；水位又是
    /// 「推过的最大分钟」，一旦把半分钟的证据推上去，这一分钟就再也不会重发，
    /// Hub 拿到的上下行永远停在半分钟那份。等它结束再推，每条分钟到的时候就是
    /// 终值。代价是最新一分钟最多晚 60 秒可见，而 `activeNow` 本来就同时看上一
    /// 分钟（Hub 侧注释同此），家长端不会因此觉得卡住。
    fn unsent_device_minutes(&self) -> BTreeMap<(String, String), Vec<(u64, MinuteEvidence)>> {
        let floor = minute_start(self.last_sample);
        let mut out = BTreeMap::new();
        for (key, minutes) in &self.device_minutes {
            let watermark = self.pushed_device.get(key).copied().unwrap_or(0);
            let fresh: Vec<(u64, MinuteEvidence)> = minutes
                .iter()
                .filter(|(minute, _)| **minute > watermark && **minute < floor)
                .map(|(minute, evidence)| (*minute, evidence.clone()))
                .collect();
            if !fresh.is_empty() {
                out.insert(key.clone(), fresh);
            }
        }
        out
    }

    fn unsent_app_minutes(&self) -> BTreeMap<(String, String, String), Vec<(u64, MinuteEvidence)>> {
        let floor = minute_start(self.last_sample);
        let mut out = BTreeMap::new();
        for (key, minutes) in &self.app_minutes {
            let watermark = self.pushed_app.get(key).copied().unwrap_or(0);
            let fresh: Vec<(u64, MinuteEvidence)> = minutes
                .iter()
                .filter(|(minute, _)| **minute > watermark && **minute < floor)
                .map(|(minute, evidence)| (*minute, evidence.clone()))
                .collect();
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
            .map(|((mac, date), minutes)| {
                let (marks, up, down, win, flow) = evidence_columns(&minutes);
                json!({
                    "mac": mac, "date": date, "minutes": marks,
                    "up": up, "down": down, "win": win, "flow": flow,
                })
            })
            .collect();
        let apps: Vec<Value> = self
            .unsent_app_minutes()
            .into_iter()
            .map(|((mac, date, app), minutes)| {
                let (marks, up, down, win, flow) = evidence_columns(&minutes);
                json!({
                    "mac": mac, "date": date, "app": app, "minutes": marks,
                    "up": up, "down": down, "win": win, "flow": flow,
                })
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
            "version": 4,
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
                    "ranges": ranges_from_minutes(minutes.keys()),
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
            "version": 4,
            "deviceMinutes": self.device_minutes.iter().map(|((mac, date), minutes)| {
                let list: Vec<(u64, MinuteEvidence)> = minutes.iter().map(|(m, e)| (*m, e.clone())).collect();
                let (marks, up, down, win, flow) = evidence_columns(&list);
                json!({"mac": mac, "date": date, "minutes": marks,
                       "up": up, "down": down, "win": win, "flow": flow})
            }).collect::<Vec<_>>(),
            "appMinutes": self.app_minutes.iter().map(|((mac, date, app), minutes)| {
                let list: Vec<(u64, MinuteEvidence)> = minutes.iter().map(|(m, e)| (*m, e.clone())).collect();
                let (marks, up, down, win, flow) = evidence_columns(&list);
                json!({"mac": mac, "date": date, "app": app, "minutes": marks,
                       "up": up, "down": down, "win": win, "flow": flow})
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
            let parsed = parse_minute_row(row);
            if !parsed.is_empty() {
                store.device_minutes.entry(key).or_default().extend(parsed);
            }
        }
        for row in rows(value, "appMinutes") {
            let key = (
                field(row, "mac").to_ascii_lowercase(),
                field(row, "date"),
                field(row, "app"),
            );
            let parsed = parse_minute_row(row);
            if !parsed.is_empty() {
                store.app_minutes.entry(key).or_default().extend(parsed);
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

/// 分钟和它的四条证据各存一个等长数组。每条分钟包一个对象的话，光键名就能把
/// payload 撑大几倍，而这东西每 30 秒要走一次路由器出站隧道。
fn evidence_columns(
    minutes: &[(u64, MinuteEvidence)],
) -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>) {
    (
        minutes.iter().map(|(minute, _)| *minute).collect(),
        minutes.iter().map(|(_, e)| e.up).collect(),
        minutes.iter().map(|(_, e)| e.down).collect(),
        minutes.iter().map(|(_, e)| e.windows).collect(),
        minutes.iter().map(|(_, e)| e.new_flows).collect(),
    )
}

/// 读一行分钟。v3 的落盘文件只有 `minutes`，证据按「未知」处理（全 0）——
/// Hub 侧见到全 0 就退回旧口径，不会把「没有证据」误读成「零字节」。
fn parse_minute_row(row: &Value) -> BTreeMap<u64, MinuteEvidence> {
    let mut out = BTreeMap::new();
    let Some(list) = row.get("minutes").and_then(Value::as_array) else {
        return out;
    };
    let column = |key: &str| -> Vec<u64> {
        row.get(key)
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default()
    };
    let (up, down, win, flow) = (column("up"), column("down"), column("win"), column("flow"));
    for (index, value) in list.iter().enumerate() {
        let Some(minute) = value.as_u64() else {
            continue;
        };
        let (up_bytes, down_bytes) = (
            up.get(index).copied().unwrap_or(0),
            down.get(index).copied().unwrap_or(0),
        );
        out.insert(
            minute,
            MinuteEvidence {
                bytes: up_bytes.saturating_add(down_bytes),
                up: up_bytes,
                down: down_bytes,
                windows: win.get(index).copied().unwrap_or(0),
                new_flows: flow.get(index).copied().unwrap_or(0),
            },
        );
    }
    out
}

fn rows<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
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
pub fn ranges_from_minutes<'a, I>(minutes: I) -> Vec<Value>
where
    I: IntoIterator<Item = &'a u64>,
{
    let mut out = Vec::new();
    let mut run: Option<(u64, u64, usize)> = None;
    for minute in minutes {
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
    let mut app_window: BTreeMap<(String, String), (u64, u64, bool)> = BTreeMap::new();
    let mut live_keys: BTreeSet<FlowKey> = BTreeSet::new();
    for row in &input.flow_rows {
        if !input.child_macs.contains(&row.mac) {
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
        let (up_delta, down_delta, is_new) = match previous {
            Some(seen)
                if row.counters.bytes_up >= seen.bytes_up
                    && row.counters.bytes_down >= seen.bytes_down =>
            {
                (
                    row.counters.bytes_up.saturating_sub(seen.bytes_up),
                    row.counters.bytes_down.saturating_sub(seen.bytes_down),
                    false,
                )
            }
            // 计数器倒退说明固件把这条五元组的槽位复用给了新连接。继续按差值算
            // 会永远得到 0，这条 flow 从此不再入账——就是"flow 一直在、时长却
            // 不涨"。按新连接重新起算。
            Some(_) | None => (
                // 冷启动首次见到的 flow 已经带着整条连接的累计字节，不能记账。
                if baselining { 0 } else { row.counters.bytes_up },
                if baselining { 0 } else { row.counters.bytes_down },
                !baselining,
            ),
        };
        if up_delta == 0 && down_delta == 0 {
            continue;
        }
        let slot = app_window.entry((row.mac.clone(), app)).or_insert((0, 0, false));
        slot.0 = slot.0.saturating_add(up_delta);
        slot.1 = slot.1.saturating_add(down_delta);
        slot.2 |= is_new;
    }
    // 已经从表里消失的 flow 不可能再贡献字节，基线留着只占内存。
    let floor = now.saturating_sub(FLOW_BASELINE_TTL_SECS);
    store
        .seen_flows
        .retain(|key, seen| live_keys.contains(key) || seen.epoch >= floor);

    for ((mac, app), (up, down, is_new)) in &app_window {
        store.add_app_evidence(mac, &input.date, app, minute, *up, *down, *is_new);
        report.apps_with_traffic += 1;
    }
    report.flow_rows = input.flow_rows.len();

    // -- 固件设备计数：MAC 的全部 IP 求并集 -------------------------------
    for (mac, ips) in &input.mac_ips {
        if !input.child_macs.contains(mac) {
            continue;
        }
        let mut window_up = 0u64;
        let mut window_down = 0u64;
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
                window_up =
                    window_up.saturating_add(counters.total_up.saturating_sub(previous.total_up));
                window_down = window_down
                    .saturating_add(counters.total_down.saturating_sub(previous.total_down));
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
        if !baselining && (window_up > 0 || window_down > 0) {
            store.add_device_evidence(mac, &input.date, minute, window_up, window_down);
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
        .map(|value| MinuteStore::from_json(&value))
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

pub fn read_mac_ips() -> BTreeMap<String, BTreeSet<String>> {
    read_text(DHCP_LEASES)
        .map(|text| parse_mac_ips(&text))
        .unwrap_or_default()
}

/// 上一次读到的受守护 MAC 列表。
static LAST_CHILD_MACS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

/// 解析 `/proc/net/sniffer_info`：每行 `<mac> <flag> ...`，flag 为 1 才是被守护设备。
pub fn parse_child_macs(text: &str) -> BTreeSet<String> {
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

/// 固件儿童设备列表。
///
/// 读到空列表时**沿用上一次的非空结果**。原来这里是反的：空列表等于"不过滤"，
/// 于是 `/proc/net/sniffer_info` 偶发读空、或策略还没写进固件，中继会悄悄把记录
/// 范围从"被守护设备"放大到"全屋设备"—— 实测 Hub 的分钟表里就躺着 NAS 和电热水器。
/// 没有守护设备就没有该记的对象，记空比记全网对。
pub fn read_child_macs() -> BTreeSet<String> {
    let mut current = read_text(SNIFFER_INFO)
        .map(|text| parse_child_macs(&text))
        .unwrap_or_default();
    // 守护配置里的 MAC 也算在册：总开关关掉只该停限制，不该停上网报告。固件名单会在
    // reload 时清空，而中继一重启就把下面那份内存里的"上次结果"抹掉 —— 0.2.68 换机
    // 后分钟桶冻结几小时就是这么来的。UCI 配置是重启后还在的权威成员表。
    current.extend(crate::child_guard::configured_child_macs());
    let lock = LAST_CHILD_MACS.get_or_init(|| Mutex::new(BTreeSet::new()));
    let mut last = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if !current.is_empty() {
        if *last != current {
            *last = current.clone();
        }
        return current;
    }
    last.clone()
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

/// 看门狗用：有没有受守护设备（没有就不该把 sniffer 重启），以及带冷却的重启。
pub fn has_guarded_devices() -> bool {
    crate::usage_stats::has_guarded_devices()
}

pub fn restart_sniffer(now: u64) -> bool {
    crate::usage_stats::restart_sniffer(now)
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
        let report = with_store(|store| -> Result<MinuteReport, String> {
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

    /// (分钟, 上行, 下行) -> 分钟桶。windows/new_flows 给非零值，这样 round-trip
    /// 是真的走过证据数组，而不是靠默认 0 蒙混过去。
    fn credited(items: &[(u64, u64, u64)]) -> BTreeMap<u64, MinuteEvidence> {
        items
            .iter()
            .map(|(minute, up, down)| {
                (
                    *minute,
                    MinuteEvidence {
                        bytes: up + down,
                        up: *up,
                        down: *down,
                        windows: 2,
                        new_flows: 1,
                    },
                )
            })
            .collect()
    }

    fn counters(total_up: u64, total_down: u64) -> IpCounters {        IpCounters {
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
        store.advance_to(T0 + 60);
        let minutes = store
            .app_minutes
            .get(&(MAC.to_string(), "2026-09-20".to_string(), "微信".to_string()))
            .cloned()
            .unwrap_or_default();
        assert_eq!(minutes.keys().copied().collect::<Vec<_>>(), vec![minute_start(T0)]);
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
    fn current_minute_is_visible_before_it_closes() {
        let mut store = MinuteStore::default();
        apply_sample(&mut store, &input(T0, vec![], counters(0, 0)));
        // 11:03:05 用微信：证据一够就当分钟入账，不等 11:03 过完。
        apply_sample(
            &mut store,
            &input(
                T0 + 5,
                vec![flow("7-1-2-0", 4_600, 10_000, 47218)],
                counters(1_000_000, 8_000_000),
            ),
        );
        let key = (MAC.to_string(), "2026-09-20".to_string(), "微信".to_string());
        let credited = store.app_minutes.get(&key).cloned().unwrap_or_default();
        assert_eq!(credited.keys().copied().collect::<Vec<_>>(), vec![minute_start(T0)]);

        // 同一分钟再命中 20 次也只能是 1 分钟，且分钟起点这个键不会漂。
        for i in 0..20 {
            apply_sample(
                &mut store,
                &input(
                    T0 + 10 + i,
                    vec![flow("7-1-2-0", 4_600 + (i as u64) * 500, 10_000, 47218)],
                    counters(1_000_000, 8_000_000),
                ),
            );
        }
        assert_eq!(store.app_minutes.get(&key).map(|m| m.len()), Some(1));
        assert_eq!(
            store
                .device_minutes
                .get(&(MAC.to_string(), "2026-09-20".to_string()))
                .map(|m| m.len()),
            Some(1)
        );
        // 跨过分钟边界也不该多出第二个桶，或把已记的分钟挪走。
        store.advance_to(T0 + 60);
        assert_eq!(store.app_minutes.get(&key).map(|m| m.len()), Some(1));
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
    fn an_empty_guarded_list_records_nothing() {
        // 反过来的那句话就是原来那个 bug：空列表 = 不过滤 = 全屋设备逐分钟入账，
        // NAS 和电热水器的分钟行就是这么进 Hub 的。
        let mut store = MinuteStore::default();
        let mut sample = input(
            T0 + 5,
            vec![flow("7-1-2-0", 40_000, 90_000, 47218)],
            counters(1_000_000, 8_000_000),
        );
        sample.child_macs = BTreeSet::new();
        apply_sample(&mut store, &sample);
        store.advance_to(T0 + 60);
        assert!(store.device_minutes.is_empty(), "没有守护设备就没有该记的对象");
        assert!(store.app_minutes.is_empty());
        assert!(store.traffic.is_empty());
    }

    #[test]
    fn child_mac_parsing_keeps_only_flagged_well_formed_macs() {
        let text = concat!(
            "da:1f:85:0c:19:fc 1 phone\n",
            "6C:1F:F7:76:71:04 1 nas\n",
            "28:7e:80:ed:12:21 0 not-guarded\n",
            "garbage-line\n",
            "short 1\n",
        );
        let parsed = parse_child_macs(text);
        assert_eq!(
            parsed,
            BTreeSet::from([
                "da:1f:85:0c:19:fc".to_string(),
                "6c:1f:f7:76:71:04".to_string(),
            ])
        );
    }

    #[test]
    fn consecutive_minutes_merge_and_a_gap_starts_a_new_range() {
        // 08:15 + 08:16 是连续的两分钟，合成一段 08:15–08:17；08:25 单独一段。
        // 断开的分钟绝不并成一段，也不用首末时间冒充连续使用。
        let minutes = BTreeSet::from([
            minute_start(T0),
            minute_start(T0) + 60,
            minute_start(T0) + 600,
        ]);
        let ranges = ranges_from_minutes(&minutes);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0]["minutes"], json!(2));
        assert_eq!(
            ranges[0]["endEpoch"].as_u64().unwrap() - ranges[0]["startEpoch"].as_u64().unwrap(),
            120
        );
        assert_eq!(ranges[1]["minutes"], json!(1));
        assert_eq!(
            ranges[1]["endEpoch"].as_u64().unwrap() - ranges[1]["startEpoch"].as_u64().unwrap(),
            60
        );
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
        // 分钟要「已经结束」才推：last_sample 落在 T0+180 这一分钟里，所以
        // T0 / T0+60 / T0+120 都是终值，本分钟 T0+180 还得等。
        store.last_sample = T0 + 180;
        store.device_minutes.insert(
            (MAC.to_string(), "2026-09-20".to_string()),
            credited(&[(T0, 100, 900), (T0 + 60, 200, 800)]),
        );
        let body = store.ingest_payload(DEFAULT_KEEP_DAYS);
        assert_eq!(body["deviceMinutes"][0]["minutes"].as_array().unwrap().len(), 2);
        // 证据数组和分钟数组必须等长且同序，Hub 是按同一个下标读的。
        assert_eq!(body["deviceMinutes"][0]["up"].as_array().unwrap().len(), 2);
        assert_eq!(body["deviceMinutes"][0]["up"][0], json!(100));
        assert_eq!(body["deviceMinutes"][0]["down"][1], json!(800));
        store.note_pushed(&body);
        assert!(!store.has_unsent());
        store
            .device_minutes
            .get_mut(&(MAC.to_string(), "2026-09-20".to_string()))
            .unwrap()
            .insert(T0 + 120, MinuteEvidence::default());
        let body = store.ingest_payload(DEFAULT_KEEP_DAYS);
        // 只重发新增的那一分钟，不整天重传。
        assert_eq!(body["deviceMinutes"][0]["minutes"].as_array().unwrap().len(), 1);
        assert_eq!(body["deviceMinutes"][0]["minutes"][0], json!(T0 + 120));
    }

    #[test]
    fn the_running_minute_is_never_pushed() {
        // 半分钟的证据一旦推上去就再也补不回来（水位只往前走），上下行会永远停在
        // 那一刻。这一条守住「等分钟结束再推」。
        let mut store = MinuteStore::default();
        store.last_sample = T0 + 30;
        store.device_minutes.insert(
            (MAC.to_string(), "2026-09-20".to_string()),
            credited(&[(T0, 100, 100)]),
        );
        assert!(!store.has_unsent(), "本分钟还没结束，不该带着半截证据出门");
        store.last_sample = T0 + 61;
        assert!(store.has_unsent(), "跨过分钟边界后这一分钟就是终值了");
    }

    #[test]
    fn store_round_trips_through_json() {
        let mut store = MinuteStore::default();
        store
            .device_minutes
            .insert((MAC.to_string(), "2026-09-20".to_string()), credited(&[(T0, 7, 11)]));
        store.app_minutes.insert(
            (MAC.to_string(), "2026-09-20".to_string(), "微信".to_string()),
            credited(&[(T0, 1, 2), (T0 + 60, 3, 4)]),
        );
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
    fn a_v3_store_file_loads_with_unknown_evidence() {
        // 中继升级前落盘的文件没有证据数组：分钟必须照读，证据按「未知」处理，
        // 否则一次升级就把已有的一天时长清零了。
        let value = json!({
            "version": 3,
            "deviceMinutes": [{"mac": MAC, "date": "2026-09-20", "minutes": [T0, T0 + 60]}],
        });
        let store = MinuteStore::from_json(&value);
        let minutes = store
            .device_minutes
            .get(&(MAC.to_lowercase(), "2026-09-20".to_string()))
            .expect("v3 minutes must load");
        assert_eq!(minutes.len(), 2);
        assert_eq!(minutes[&T0], MinuteEvidence::default());
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
        let mut rows = parse_proc_flow(
            "da:1f:85:0c:19:fc 192.168.5.132 117.185.244.54 47218 443 TCP 3 18-158-1-0 3572 3600 11 1006 11 1372 1",
        );
        let row = rows.remove(0);
        assert_eq!(row.appid, "18-158-1-0");
        assert_eq!(row.counters.bytes_up, 1006);
    }
}
