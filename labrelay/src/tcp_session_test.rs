use anyhow::{anyhow, bail, Context, Result};
use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use socket2::SockRef;
use std::collections::VecDeque;
use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{lookup_host, TcpSocket, TcpStream};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

const ABSOLUTE_CONNECTION_LIMIT: usize = 65_535;
const MAX_PENDING_CONNECTS: usize = 256;
const CONSECUTIVE_FAILURE_LIMIT: usize = 200;
const RECENT_OUTCOME_WINDOW: usize = 200;
const STATUS_INTERVAL: Duration = Duration::from_secs(1);
const HEAVY_RESOURCE_SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
const LOOP_INTERVAL: Duration = Duration::from_millis(100);
const CPU_HIGH_SAMPLE_PERCENT: f64 = 95.0;
const CPU_RECOVERY_PERCENT: f64 = 90.0;
const CPU_HIGH_SAMPLE_LIMIT: u8 = 3;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct TcpSessionConfig {
    host: String,
    port: u16,
    family: String,
    target_connections: usize,
    cps: u64,
    connect_timeout_ms: u64,
    max_duration_seconds: u64,
}

impl Default for TcpSessionConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 443,
            family: "both".into(),
            target_connections: ABSOLUTE_CONNECTION_LIMIT,
            cps: 500,
            connect_timeout_ms: 1_500,
            max_duration_seconds: 180,
        }
    }
}

impl TcpSessionConfig {
    fn validate(mut self) -> Result<Self> {
        self.host = self
            .host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        if self.host.is_empty()
            || self.host.contains("://")
            || self.host.chars().any(char::is_whitespace)
        {
            bail!("测试目标主机无效");
        }
        if self.port == 0 {
            bail!("测试目标端口无效");
        }
        if !matches!(self.family.as_str(), "ipv4" | "ipv6" | "both") {
            bail!("测试协议只能选择 IPv4、IPv6 或分别测试");
        }
        self.target_connections = self.target_connections.clamp(1, ABSOLUTE_CONNECTION_LIMIT);
        self.cps = self.cps.clamp(1, 2_000);
        self.connect_timeout_ms = self.connect_timeout_ms.clamp(300, 10_000);
        self.max_duration_seconds = self.max_duration_seconds.clamp(10, 300);
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FamilyMetric {
    current: usize,
    peak: usize,
    success: u64,
    failure: u64,
    cps: u64,
    status: String,
    elapsed_ms: u64,
    finish_reason: String,
}

impl Default for FamilyMetric {
    fn default() -> Self {
        Self {
            current: 0,
            peak: 0,
            success: 0,
            failure: 0,
            cps: 0,
            status: "待测试".into(),
            elapsed_ms: 0,
            finish_reason: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TcpSessionSnapshot {
    id: String,
    state: String,
    status: String,
    finish_reason: String,
    ipv4: FamilyMetric,
    ipv6: FamilyMetric,
    logs: Vec<String>,
    conntrack_peak: u64,
    cpu_peak: f64,
    memory_min_available_mb: u64,
    resources_released: bool,
    release_status: String,
    started_epoch: u64,
    updated_epoch: u64,
    finished_epoch: u64,
}

impl Default for TcpSessionSnapshot {
    fn default() -> Self {
        Self {
            id: String::new(),
            state: "idle".into(),
            status: "当前没有测试任务".into(),
            finish_reason: String::new(),
            ipv4: FamilyMetric::default(),
            ipv6: FamilyMetric::default(),
            logs: Vec::new(),
            conntrack_peak: 0,
            cpu_peak: 0.0,
            memory_min_available_mb: 0,
            resources_released: true,
            release_status: "当前没有待释放资源".into(),
            started_epoch: 0,
            updated_epoch: now_epoch(),
            finished_epoch: 0,
        }
    }
}

struct ActiveControl {
    task_id: String,
    stop: AtomicBool,
}

struct Inner {
    snapshot: TcpSessionSnapshot,
    active: Option<Arc<ActiveControl>>,
}

#[derive(Clone)]
pub(crate) struct TcpSessionTestManager {
    inner: Arc<Mutex<Inner>>,
}

impl TcpSessionTestManager {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                snapshot: TcpSessionSnapshot::default(),
                active: None,
            })),
        }
    }

    pub(crate) async fn start(&self, request: &Value) -> Result<Value> {
        let task_id = request
            .get("taskId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if task_id.is_empty() {
            bail!("测试任务编号缺失");
        }
        let config: TcpSessionConfig = serde_json::from_value(
            request.get("config").cloned().unwrap_or(Value::Null),
        )
        .context("测试参数格式无效")?;
        let config = config.validate()?;

        let control = Arc::new(ActiveControl {
            task_id: task_id.clone(),
            stop: AtomicBool::new(false),
        });
        {
            let mut inner = self.inner.lock().await;
            if inner.snapshot.id == task_id {
                return Ok(json!({"ok": true, "idempotent": true, "taskId": task_id}));
            }
            if inner.active.is_some() {
                bail!("已有 TCP 峰值连接数测试正在运行");
            }
            let now = now_epoch();
            inner.snapshot = TcpSessionSnapshot {
                id: task_id.clone(),
                state: "running".into(),
                status: "正在准备测试".into(),
                finish_reason: String::new(),
                ipv4: FamilyMetric::default(),
                ipv6: FamilyMetric::default(),
                logs: vec!["Relay 已开始 TCP 峰值连接数测试".into()],
                conntrack_peak: 0,
                cpu_peak: 0.0,
                memory_min_available_mb: 0,
                resources_released: false,
                release_status: "测试中".into(),
                started_epoch: now,
                updated_epoch: now,
                finished_epoch: 0,
            };
            inner.active = Some(control.clone());
        }

        let manager = self.clone();
        tokio::spawn(async move {
            manager.run_task(config, control).await;
        });
        Ok(json!({"ok": true, "taskId": task_id}))
    }

    pub(crate) async fn stop(&self, task_id: &str) -> Result<Value> {
        let mut inner = self.inner.lock().await;
        if inner.snapshot.id != task_id {
            bail!("测试任务已经变化");
        }
        if let Some(control) = inner.active.as_ref() {
            control.stop.store(true, Ordering::Release);
            inner.snapshot.state = "stop_requested".into();
            inner.snapshot.status = "正在停止并释放连接".into();
            inner.snapshot.updated_epoch = now_epoch();
        }
        Ok(json!({"ok": true, "taskId": task_id}))
    }

    pub(crate) async fn status(&self) -> Value {
        let inner = self.inner.lock().await;
        let mut value = serde_json::to_value(&inner.snapshot)
            .unwrap_or_else(|_| json!({"state":"interrupted","status":"测试状态无法读取"}));
        if let Some(row) = value.as_object_mut() {
            row.insert("ok".into(), Value::Bool(true));
        }
        value
    }

    async fn run_task(&self, config: TcpSessionConfig, control: Arc<ActiveControl>) {
        let families: Vec<bool> = match config.family.as_str() {
            "ipv4" => vec![false],
            "ipv6" => vec![true],
            _ => vec![false, true],
        };
        let mut failed = false;
        let mut reasons = Vec::new();
        for ipv6 in families {
            if control.stop.load(Ordering::Acquire) {
                break;
            }
            match self.run_family(&config, &control, ipv6).await {
                Ok(reason) => reasons.push(reason),
                Err(error) => {
                    failed = true;
                    reasons.push(format!("{}：{}", family_label(ipv6), error));
                }
            }
        }

        let stopped = control.stop.load(Ordering::Acquire);
        let reason = if stopped {
            "用户停止测试".to_string()
        } else if reasons.is_empty() {
            "测试未产生结果".to_string()
        } else {
            reasons.join("；")
        };
        self.update(&control.task_id, |snapshot| {
            snapshot.state = if stopped {
                "stopped"
            } else if failed {
                "failed"
            } else {
                "completed"
            }
            .into();
            snapshot.status = if stopped {
                "测试已停止"
            } else if failed {
                "测试结束，部分协议失败"
            } else {
                "测试已完成"
            }
            .into();
            snapshot.finish_reason = reason.clone();
            snapshot.finished_epoch = now_epoch();
            push_log(snapshot, format!("测试结束：{}", reason));
        })
        .await;
        let mut inner = self.inner.lock().await;
        if inner
            .active
            .as_ref()
            .map(|value| value.task_id.as_str())
            == Some(control.task_id.as_str())
        {
            inner.active = None;
        }
    }

    async fn run_family(
        &self,
        config: &TcpSessionConfig,
        control: &Arc<ActiveControl>,
        ipv6: bool,
    ) -> Result<String> {
        let label = family_label(ipv6);
        self.update(&control.task_id, |snapshot| {
            snapshot.status = format!("{} 正在解析目标地址", label);
            snapshot.resources_released = true;
            snapshot.release_status = "尚未创建测试连接".into();
            let metric = family_metric(snapshot, ipv6);
            metric.status = "正在解析目标地址".into();
            push_log(snapshot, format!("开始 {} TCP 测试", label));
        })
        .await;
        let address = resolve_target(&config.host, config.port, ipv6).await?;
        let plan = resource_plan(config.target_connections);
        let safe_target = plan.safe_target;
        self.update(&control.task_id, |snapshot| {
            snapshot.status = format!("{} 正在建立连接", label);
            snapshot.resources_released = false;
            snapshot.release_status = "测试连接正在使用资源".into();
            family_metric(snapshot, ipv6).status = "正在建立连接".into();
            push_log(
                snapshot,
                format!(
                    "{} 当前安全连接上限为 {}（{}；进程 FD 软上限 {}，测试前占用 {}）",
                    label,
                    safe_target,
                    plan.limiting_reason,
                    plan.fd_soft_limit,
                    plan.baseline_fd
                ),
            );
        })
        .await;

        let started = Instant::now();
        let mut last_tick = Instant::now();
        let mut last_report = Instant::now();
        let mut last_report_success = 0u64;
        let mut last_growth = Instant::now();
        let mut last_heavy_resource_sample = Instant::now();
        let mut credit = 0f64;
        let mut held: Vec<TcpStream> = Vec::with_capacity(safe_target.min(16_384));
        let mut pending = FuturesUnordered::new();
        let mut success = 0u64;
        let mut failure = 0u64;
        let mut resource_failures = 0u64;
        let mut source_port_failures = 0u64;
        let mut fd_failures = 0u64;
        let mut memory_failures = 0u64;
        let mut consecutive_failures = 0usize;
        let mut recent_outcomes = VecDeque::with_capacity(RECENT_OUTCOME_WINDOW);
        let mut previous_cpu = read_cpu_counters();
        let mut high_cpu_samples = 0u8;
        let mut cpu_scale = 1.0f64;
        let mut cached_fd_used = plan.baseline_fd;
        let mut cached_source_ports = plan.baseline_source_ports;
        let finish_reason: String;

        'testing: loop {
            let now = Instant::now();
            let elapsed = now.duration_since(started);
            if control.stop.load(Ordering::Acquire) {
                finish_reason = "用户停止测试".into();
                break;
            }
            if elapsed >= Duration::from_secs(config.max_duration_seconds) {
                finish_reason = "达到最长测试时间".into();
                break;
            }
            if held.len() >= safe_target {
                finish_reason = if safe_target < config.target_connections {
                    plan.limiting_reason.clone()
                } else {
                    "达到设定连接数".into()
                };
                break;
            }
            if source_port_failures >= 3 {
                finish_reason = "单目标临时源端口已接近耗尽".into();
                break;
            }
            if fd_failures >= 3 {
                finish_reason = "Relay 进程 FD 已接近安全阈值".into();
                break;
            }
            if memory_failures >= 3 {
                finish_reason = "Relay 内存余量已接近安全阈值".into();
                break;
            }
            if resource_failures >= 8 {
                finish_reason = "Relay 系统资源不足".into();
                break;
            }
            if failure >= 100 && success == 0 && elapsed >= Duration::from_secs(5) {
                finish_reason = "目标持续拒绝连接或连接超时".into();
                break;
            }
            if failure > 0
                && now.duration_since(last_growth) >= Duration::from_secs(4)
                && held.len() >= safe_target.saturating_mul(9) / 10
            {
                finish_reason = "连接数已稳定在当前峰值".into();
                break;
            }

            while let Some(Some(result)) = pending.next().now_or_never() {
                match result {
                    ConnectResult::Connected(stream) => {
                        if control.stop.load(Ordering::Acquire) {
                            drop(stream);
                        } else {
                            held.push(stream);
                            success += 1;
                            consecutive_failures = 0;
                            record_recent_outcome(&mut recent_outcomes, true);
                            last_growth = Instant::now();
                        }
                    }
                    ConnectResult::Failed(kind) => {
                        failure += 1;
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        record_recent_outcome(&mut recent_outcomes, false);
                        match kind {
                            FailureKind::SourcePort => source_port_failures += 1,
                            FailureKind::FileDescriptor => fd_failures += 1,
                            FailureKind::Memory => memory_failures += 1,
                            FailureKind::Other => {}
                        }
                        if kind != FailureKind::Other {
                            resource_failures += 1;
                        }
                        if let Some(reason) = connection_quality_stop_reason(
                            &recent_outcomes,
                            consecutive_failures,
                            last_growth.elapsed(),
                        ) {
                            finish_reason = reason.into();
                            break 'testing;
                        }
                    }
                }
            }

            let tick_seconds = now.duration_since(last_tick).as_secs_f64();
            last_tick = now;
            let load = (held.len() + pending.len()) as f64 / safe_target.max(1) as f64;
            let load_scale = if load >= 0.95 {
                0.20
            } else if load >= 0.80 {
                0.50
            } else {
                1.0
            };
            let rate_scale = load_scale.min(cpu_scale);
            if rate_scale <= f64::EPSILON {
                credit = 0.0;
            } else {
                credit = (credit + config.cps as f64 * rate_scale * tick_seconds)
                    .min(MAX_PENDING_CONNECTS as f64);
            }
            let available = safe_target.saturating_sub(held.len() + pending.len());
            let launches = if rate_scale <= f64::EPSILON {
                0
            } else {
                (credit.floor() as usize)
                    .min(available)
                    .min(MAX_PENDING_CONNECTS.saturating_sub(pending.len()))
                    .min(
                        CONSECUTIVE_FAILURE_LIMIT
                            .saturating_sub(consecutive_failures.saturating_add(pending.len())),
                    )
            };
            credit -= launches as f64;
            for _ in 0..launches {
                let timeout_duration = Duration::from_millis(config.connect_timeout_ms);
                pending.push(connect_once(address, timeout_duration));
            }

            if now.duration_since(last_report) >= STATUS_INTERVAL {
                let approximate_fd = plan
                    .baseline_fd
                    .saturating_add(held.len())
                    .saturating_add(pending.len());
                let approximate_source_ports = plan
                    .baseline_source_ports
                    .saturating_add(held.len())
                    .saturating_add(pending.len());
                let near_fd_limit = approximate_fd >= plan.fd_ceiling.saturating_mul(8) / 10;
                let near_source_limit = approximate_source_ports
                    >= plan.source_port_ceiling.saturating_mul(8) / 10;
                if last_heavy_resource_sample.elapsed() >= HEAVY_RESOURCE_SAMPLE_INTERVAL
                    || near_fd_limit
                    || near_source_limit
                {
                    cached_fd_used = current_fd_count();
                    let (source_first, source_last) = source_port_range();
                    cached_source_ports = source_ports_in_use(source_first, source_last);
                    last_heavy_resource_sample = Instant::now();
                }
                let effective_fd = cached_fd_used.max(approximate_fd);
                let effective_source_ports = cached_source_ports.max(approximate_source_ports);
                let sample = sample_resources(previous_cpu, effective_fd, effective_source_ports);
                previous_cpu = sample.cpu_counters;
                cpu_scale = cpu_rate_scale(sample.cpu_percent);
                if sample.cpu_percent >= CPU_HIGH_SAMPLE_PERCENT {
                    high_cpu_samples = high_cpu_samples.saturating_add(1);
                } else if sample.cpu_percent < CPU_RECOVERY_PERCENT {
                    high_cpu_samples = 0;
                }
                self.publish_resources(&control.task_id, &sample).await;
                if let Some(reason) = health_stop_reason(&plan, &sample, high_cpu_samples) {
                    self.update(&control.task_id, |snapshot| {
                        push_log(snapshot, format!("系统保护停止新增连接：{}", reason));
                    })
                    .await;
                    drop(pending);
                    let peak = held.len();
                    self.update(&control.task_id, |snapshot| {
                        snapshot.state = "releasing".into();
                        snapshot.status = format!("{} 正在释放连接", label);
                        snapshot.release_status = "正在取消连接并回收测试资源".into();
                        let metric = family_metric(snapshot, ipv6);
                        metric.peak = metric.peak.max(peak);
                    })
                    .await;
                    for stream in &held {
                        let _ = SockRef::from(stream).set_linger(Some(Duration::ZERO));
                    }
                    held.clear();
                    let released = self
                        .wait_for_release(&control.task_id, &plan, Duration::from_secs(15))
                        .await;
                    self.finish_family_metric(
                        &control.task_id,
                        ipv6,
                        success,
                        failure,
                        started.elapsed(),
                        &reason,
                        released,
                    )
                    .await;
                    if !released {
                        return Err(anyhow!("测试连接已关闭，但资源回落确认超时"));
                    }
                    return Ok(format!("{} {}", label, reason));
                }
                let report_seconds = now.duration_since(last_report).as_secs_f64().max(0.001);
                let current_cps = ((success - last_report_success) as f64 / report_seconds) as u64;
                last_report_success = success;
                last_report = now;
                self.publish_metric(
                    &control.task_id,
                    ipv6,
                    held.len(),
                    success,
                    failure,
                    current_cps,
                    elapsed,
                    "正在建立连接",
                    "",
                )
                .await;
            }
            sleep(LOOP_INTERVAL).await;
        }

        self.update(&control.task_id, |snapshot| {
            snapshot.state = "releasing".into();
            snapshot.status = format!("{} 正在释放连接", label);
            family_metric(snapshot, ipv6).status = "正在释放连接".into();
            snapshot.release_status = "正在取消连接并回收测试资源".into();
        })
        .await;
        drop(pending);
        let peak = held.len();
        for stream in &held {
            let _ = SockRef::from(stream).set_linger(Some(Duration::ZERO));
        }
        held.clear();
        let released = self
            .wait_for_release(&control.task_id, &plan, Duration::from_secs(15))
            .await;
        self.finish_family_metric(
            &control.task_id,
            ipv6,
            success,
            failure,
            started.elapsed(),
            &finish_reason,
            released,
        )
        .await;
        self.update(&control.task_id, |snapshot| {
            let metric = family_metric(snapshot, ipv6);
            metric.peak = metric.peak.max(peak);
            push_log(
                snapshot,
                format!("{} 测试结束：{}，峰值 {}", label, finish_reason, peak),
            );
        })
        .await;
        if !released {
            return Err(anyhow!("测试连接已关闭，但资源回落确认超时"));
        }
        Ok(format!("{} {}", label, finish_reason))
    }

    async fn finish_family_metric(
        &self,
        task_id: &str,
        ipv6: bool,
        success: u64,
        failure: u64,
        elapsed: Duration,
        finish_reason: &str,
        released: bool,
    ) {
        self.publish_metric(
            task_id,
            ipv6,
            0,
            success,
            failure,
            0,
            elapsed,
            if released { "已完成" } else { "释放确认超时" },
            finish_reason,
        )
        .await;
    }

    async fn publish_resources(&self, task_id: &str, sample: &ResourceSample) {
        self.update(task_id, |snapshot| {
            snapshot.conntrack_peak = snapshot.conntrack_peak.max(sample.conntrack as u64);
            snapshot.cpu_peak = snapshot.cpu_peak.max(sample.cpu_percent);
            if sample.memory_available_mb > 0 {
                snapshot.memory_min_available_mb = if snapshot.memory_min_available_mb == 0 {
                    sample.memory_available_mb as u64
                } else {
                    snapshot
                        .memory_min_available_mb
                        .min(sample.memory_available_mb as u64)
                };
            }
        })
        .await;
    }

    async fn wait_for_release(
        &self,
        task_id: &str,
        plan: &ResourcePlan,
        maximum_wait: Duration,
    ) -> bool {
        let started = Instant::now();
        let (source_first, source_last) = source_port_range();
        loop {
            let sample = sample_resources(
                None,
                current_fd_count(),
                source_ports_in_use(source_first, source_last),
            );
            self.publish_resources(task_id, &sample).await;
            let fd_released = sample.fd_used <= plan.baseline_fd.saturating_add(16);
            let source_released = sample.source_ports_used
                <= plan.baseline_source_ports.saturating_add(32);
            let conntrack_released = sample.conntrack
                <= plan.baseline_conntrack.saturating_add(128);
            if fd_released && source_released && conntrack_released {
                self.update(task_id, |snapshot| {
                    snapshot.resources_released = true;
                    snapshot.release_status = "测试连接已释放，系统资源已回落".into();
                })
                .await;
                return true;
            }
            if started.elapsed() >= maximum_wait {
                self.update(task_id, |snapshot| {
                    snapshot.resources_released = false;
                    snapshot.release_status = "测试连接已关闭，资源回落确认超时".into();
                })
                .await;
                return false;
            }
            sleep(Duration::from_secs(1)).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish_metric(
        &self,
        task_id: &str,
        ipv6: bool,
        current: usize,
        success: u64,
        failure: u64,
        cps: u64,
        elapsed: Duration,
        status: &str,
        finish_reason: &str,
    ) {
        self.update(task_id, |snapshot| {
            let metric = family_metric(snapshot, ipv6);
            metric.current = current;
            metric.peak = metric.peak.max(current);
            metric.success = success;
            metric.failure = failure;
            metric.cps = cps;
            metric.elapsed_ms = elapsed.as_millis().min(u64::MAX as u128) as u64;
            metric.status = status.into();
            metric.finish_reason = finish_reason.into();
        })
        .await;
    }

    async fn update<F>(&self, task_id: &str, update: F)
    where
        F: FnOnce(&mut TcpSessionSnapshot),
    {
        let mut inner = self.inner.lock().await;
        if inner.snapshot.id == task_id {
            update(&mut inner.snapshot);
            inner.snapshot.updated_epoch = now_epoch();
        }
    }
}

enum ConnectResult {
    Connected(TcpStream),
    Failed(FailureKind),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    SourcePort,
    FileDescriptor,
    Memory,
    Other,
}

fn record_recent_outcome(outcomes: &mut VecDeque<bool>, success: bool) {
    outcomes.push_back(success);
    while outcomes.len() > RECENT_OUTCOME_WINDOW {
        outcomes.pop_front();
    }
}

fn connection_quality_stop_reason(
    recent_outcomes: &VecDeque<bool>,
    consecutive_failures: usize,
    no_growth: Duration,
) -> Option<&'static str> {
    if consecutive_failures >= CONSECUTIVE_FAILURE_LIMIT {
        return Some("连续连接失败 200 次，停止新增连接");
    }
    if recent_outcomes.len() >= 100
        && consecutive_failures >= 50
        && no_growth >= Duration::from_secs(3)
    {
        let failures = recent_outcomes.iter().filter(|success| !**success).count();
        if failures.saturating_mul(100) >= recent_outcomes.len().saturating_mul(80) {
            return Some("连接成功率持续过低，已确认增长平台");
        }
    }
    None
}

fn cpu_rate_scale(cpu_percent: f64) -> f64 {
    if cpu_percent >= 90.0 {
        0.0
    } else if cpu_percent >= 85.0 {
        0.15
    } else if cpu_percent >= 75.0 {
        0.40
    } else if cpu_percent >= 65.0 {
        0.70
    } else {
        1.0
    }
}

async fn connect_once(address: SocketAddr, connect_timeout: Duration) -> ConnectResult {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    };
    let socket = match socket {
        Ok(value) => value,
        Err(error) => return ConnectResult::Failed(classify_connect_error(&error)),
    };
    match timeout(connect_timeout, socket.connect(address)).await {
        Ok(Ok(stream)) => ConnectResult::Connected(stream),
        Ok(Err(error)) => ConnectResult::Failed(classify_connect_error(&error)),
        Err(_) => ConnectResult::Failed(FailureKind::Other),
    }
}

async fn resolve_target(host: &str, port: u16, ipv6: bool) -> Result<SocketAddr> {
    timeout(Duration::from_secs(8), lookup_host((host, port)))
        .await
        .map_err(|_| anyhow!("目标地址解析超时"))?
        .context("目标地址解析失败")?
        .find(|address| address.is_ipv6() == ipv6)
        .ok_or_else(|| anyhow!("目标没有可用的 {} 地址", family_label(ipv6)))
}

fn classify_connect_error(error: &std::io::Error) -> FailureKind {
    match error.raw_os_error() {
        Some(99) => FailureKind::SourcePort,
        Some(23) | Some(24) => FailureKind::FileDescriptor,
        Some(12) | Some(105) => FailureKind::Memory,
        _ if error
            .to_string()
            .to_ascii_lowercase()
            .contains("too many open files") => FailureKind::FileDescriptor,
        _ => FailureKind::Other,
    }
}

#[derive(Clone)]
struct ResourcePlan {
    safe_target: usize,
    limiting_reason: String,
    baseline_fd: usize,
    fd_soft_limit: usize,
    fd_ceiling: usize,
    baseline_conntrack: usize,
    conntrack_ceiling: usize,
    memory_floor_mb: usize,
    baseline_source_ports: usize,
    source_port_ceiling: usize,
}

#[derive(Clone, Copy)]
struct CpuCounters {
    total: u64,
    idle: u64,
}

struct ResourceSample {
    fd_used: usize,
    conntrack: usize,
    memory_available_mb: usize,
    source_ports_used: usize,
    cpu_percent: f64,
    cpu_counters: Option<CpuCounters>,
}

fn resource_plan(requested: usize) -> ResourcePlan {
    let baseline_fd = current_fd_count();
    let soft_limit = fd_soft_limit().unwrap_or(ABSOLUTE_CONNECTION_LIMIT + baseline_fd + 2_048);
    let fd_ceiling = soft_limit
        .saturating_mul(80)
        .checked_div(100)
        .unwrap_or(soft_limit)
        .max(baseline_fd.saturating_add(1));
    let fd_budget = fd_ceiling.saturating_sub(baseline_fd).max(1);

    let baseline_conntrack = read_number("/proc/sys/net/netfilter/nf_conntrack_count").unwrap_or(0);
    let conntrack_max = read_number("/proc/sys/net/netfilter/nf_conntrack_max").unwrap_or(65_536);
    let conntrack_ceiling = conntrack_max.saturating_mul(75) / 100;
    let conntrack_budget = conntrack_ceiling.saturating_sub(baseline_conntrack).max(1);

    let (memory_total_mb, memory_available_mb) = memory_megabytes();
    let memory_floor_mb = (memory_total_mb / 5)
        .max(192)
        .min(memory_available_mb.saturating_sub(1));
    let memory_budget = memory_available_mb
        .saturating_sub(memory_floor_mb)
        .saturating_mul(128)
        .max(1);

    let (source_first, source_last) = source_port_range();
    let source_port_capacity = source_last.saturating_sub(source_first).saturating_add(1);
    let source_port_ceiling = source_port_capacity.saturating_mul(90) / 100;
    let baseline_source_ports = source_ports_in_use(source_first, source_last);
    let source_port_budget = source_port_ceiling
        .saturating_sub(baseline_source_ports)
        .max(1);

    let candidates = [
        (requested.min(ABSOLUTE_CONNECTION_LIMIT), "达到设定连接数"),
        (fd_budget, "Relay 进程 FD 已达到安全阈值"),
        (conntrack_budget, "Conntrack 已达到安全阈值"),
        (memory_budget, "Relay 内存已达到安全阈值"),
        (source_port_budget, "单目标临时源端口已达到安全阈值"),
    ];
    let (safe_target, limiting_reason) = candidates
        .into_iter()
        .min_by_key(|(value, _)| *value)
        .unwrap_or((1, "系统安全阈值"));
    ResourcePlan {
        safe_target: safe_target.clamp(1, ABSOLUTE_CONNECTION_LIMIT),
        limiting_reason: limiting_reason.into(),
        baseline_fd,
        fd_soft_limit: soft_limit,
        fd_ceiling,
        baseline_conntrack,
        conntrack_ceiling,
        memory_floor_mb,
        baseline_source_ports,
        source_port_ceiling,
    }
}

fn health_stop_reason(
    plan: &ResourcePlan,
    sample: &ResourceSample,
    high_cpu_samples: u8,
) -> Option<String> {
    if sample.fd_used >= plan.fd_ceiling {
        Some("Relay 进程 FD 已达到安全阈值".into())
    } else if sample.conntrack >= plan.conntrack_ceiling {
        Some("Conntrack 已达到安全阈值".into())
    } else if sample.memory_available_mb <= plan.memory_floor_mb {
        Some("Relay 内存已达到安全阈值".into())
    } else if sample.source_ports_used >= plan.source_port_ceiling {
        Some("单目标临时源端口已达到安全阈值".into())
    } else if high_cpu_samples >= CPU_HIGH_SAMPLE_LIMIT {
        Some("CPU 持续高负载，已触发系统保护".into())
    } else {
        None
    }
}

fn sample_resources(
    previous_cpu: Option<CpuCounters>,
    fd_used: usize,
    source_ports_used: usize,
) -> ResourceSample {
    let counters = read_cpu_counters();
    let cpu_percent = match (previous_cpu, counters) {
        (Some(previous), Some(current)) => {
            let total = current.total.saturating_sub(previous.total);
            let idle = current.idle.saturating_sub(previous.idle);
            if total == 0 {
                0.0
            } else {
                100.0 * (total - idle) as f64 / total as f64
            }
        }
        _ => 0.0,
    };
    let (_, memory_available_mb) = memory_megabytes();
    ResourceSample {
        fd_used,
        conntrack: read_number("/proc/sys/net/netfilter/nf_conntrack_count").unwrap_or(0),
        memory_available_mb,
        source_ports_used,
        cpu_percent,
        cpu_counters: counters,
    }
}

fn current_fd_count() -> usize {
    fs::read_dir("/proc/self/fd")
        .map(|rows| rows.filter_map(std::result::Result::ok).count())
        .unwrap_or(64)
}

fn fd_soft_limit() -> Option<usize> {
    fs::read_to_string("/proc/self/limits").ok().and_then(|text| {
        text.lines()
            .find(|line| line.starts_with("Max open files"))
            .and_then(|line| {
                line.split_whitespace()
                    .find_map(|part| part.parse::<usize>().ok())
            })
    })
}

fn memory_megabytes() -> (usize, usize) {
    let text = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let read_kib = |name: &str| {
        text.lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0)
    };
    (
        read_kib("MemTotal:") / 1024,
        read_kib("MemAvailable:") / 1024,
    )
}

fn read_number(path: &str) -> Option<usize> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn source_port_range() -> (usize, usize) {
    let values: Vec<usize> = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .map(|text| {
            text.split_whitespace()
                .filter_map(|value| value.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    match values.as_slice() {
        [first, last, ..] if first < last => (*first, *last),
        _ => (32_768, 60_999),
    }
}

fn source_ports_in_use(first: usize, last: usize) -> usize {
    let mut count = 0usize;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let Some(port) = line
                .split_whitespace()
                .nth(1)
                .and_then(|address| address.rsplit(':').next())
                .and_then(|port| usize::from_str_radix(port, 16).ok())
            else {
                continue;
            };
            if port >= first && port <= last {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

fn read_cpu_counters() -> Option<CpuCounters> {
    let text = fs::read_to_string("/proc/stat").ok()?;
    let mut values = text.lines().next()?.split_whitespace();
    if values.next()? != "cpu" {
        return None;
    }
    let numbers: Vec<u64> = values.filter_map(|value| value.parse().ok()).collect();
    if numbers.len() < 4 {
        return None;
    }
    Some(CpuCounters {
        total: numbers.iter().copied().sum(),
        idle: numbers[3].saturating_add(*numbers.get(4).unwrap_or(&0)),
    })
}

fn family_label(ipv6: bool) -> &'static str {
    if ipv6 {
        "IPv6"
    } else {
        "IPv4"
    }
}

fn family_metric(snapshot: &mut TcpSessionSnapshot, ipv6: bool) -> &mut FamilyMetric {
    if ipv6 {
        &mut snapshot.ipv6
    } else {
        &mut snapshot.ipv4
    }
}

fn push_log(snapshot: &mut TcpSessionSnapshot, line: String) {
    snapshot.logs.push(line);
    if snapshot.logs.len() > 80 {
        snapshot.logs.drain(..snapshot.logs.len() - 80);
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consecutive_failure_guard_stops_at_two_hundred() {
        let outcomes = VecDeque::from(vec![false; CONSECUTIVE_FAILURE_LIMIT]);

        assert_eq!(
            connection_quality_stop_reason(
                &outcomes,
                CONSECUTIVE_FAILURE_LIMIT,
                Duration::from_millis(500),
            ),
            Some("连续连接失败 200 次，停止新增连接")
        );
    }

    #[test]
    fn rolling_failure_guard_requires_rate_streak_and_no_growth() {
        let mut outcomes = VecDeque::from(vec![true; 20]);
        outcomes.extend(vec![false; 80]);

        assert_eq!(
            connection_quality_stop_reason(&outcomes, 50, Duration::from_secs(3)),
            Some("连接成功率持续过低，已确认增长平台")
        );
        assert_eq!(
            connection_quality_stop_reason(&outcomes, 49, Duration::from_secs(3)),
            None
        );
        assert_eq!(
            connection_quality_stop_reason(&outcomes, 50, Duration::from_millis(2_999)),
            None
        );
    }

    #[test]
    fn cpu_rate_scale_throttles_before_system_protection() {
        assert_eq!(cpu_rate_scale(50.0), 1.0);
        assert_eq!(cpu_rate_scale(65.0), 0.70);
        assert_eq!(cpu_rate_scale(75.0), 0.40);
        assert_eq!(cpu_rate_scale(85.0), 0.15);
        assert_eq!(cpu_rate_scale(90.0), 0.0);
        assert_eq!(cpu_rate_scale(99.0), 0.0);
    }
}
