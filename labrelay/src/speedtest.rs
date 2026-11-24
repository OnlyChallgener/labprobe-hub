//! Candidate router-local HTTP throughput engine. No production nodes are bundled.
//! Only operator-installed nodes are accepted; commands never supply URLs.
use anyhow::{bail, Context, Result};
use futures_util::stream;
use reqwest::{Client, Response, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::lookup_host;
use tokio::sync::{watch, Mutex};
use tokio::time::timeout;

const NODE_PATH: &str = "/etc/labprobe/speedtest-nodes.json";
const BLOCK: usize = 64 * 1024;
const MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REPLY: usize = 4096;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Node {
    id: String,
    name: String,
    protocol: String,
    // Evidence identifying the operator's authorized endpoint and verification.
    verification: String,
    latency_url: String,
    download_url: String,
    upload_url: String,
}

#[derive(Clone, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct Options {
    node_id: String,
    download_bytes: u64,
    upload_bytes: u64,
    phase_timeout_seconds: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            download_bytes: 16 * 1024 * 1024,
            upload_bytes: 16 * 1024 * 1024,
            phase_timeout_seconds: 15,
        }
    }
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    id: String,
    node_id: String,
    node_name: String,
    state: String,
    phase: String,
    error: Option<String>,
    latency_ms: Option<f64>,
    jitter_ms: Option<f64>,
    download_mbps: Option<f64>,
    upload_mbps: Option<f64>,
    download_bytes: u64,
    upload_bytes_sent: u64,
    upload_bytes: Option<u64>,
    started_at: Option<u64>,
    updated_at: Option<u64>,
    finished_at: Option<u64>,
}

struct Inner {
    snapshot: Snapshot,
    cancel: Option<watch::Sender<bool>>,
    // Avoid replaying recent command IDs even after another task has finished.
    seen: VecDeque<String>,
}

#[derive(Clone)]
pub(crate) struct SpeedTestManager {
    inner: Arc<Mutex<Inner>>,
    node_path: PathBuf,
    #[cfg(test)]
    allow_loopback: bool,
}

fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}

fn endpoint(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("测速节点 URL 无效")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || raw.len() > 2048
    {
        bail!("测速节点必须使用无凭据的 HTTP/HTTPS URL");
    }
    Ok(url)
}

// Conservatively allow global unicast only; IPv4-mapped IPv6 is checked as IPv4.
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || b == 0 || (b == 2)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return public_ip(v4.into());
            }
            let s = v.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && !(s[0] == 0x2002)
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

impl SpeedTestManager {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                snapshot: Snapshot {
                    state: "idle".into(),
                    phase: "idle".into(),
                    ..Snapshot::default()
                },
                cancel: None,
                seen: VecDeque::new(),
            })),
            node_path: PathBuf::from(NODE_PATH),
            #[cfg(test)]
            allow_loopback: false,
        }
    }

    fn nodes(&self) -> Result<Vec<Node>> {
        load_nodes(&self.node_path)
    }

    pub(crate) fn capability(&self) -> Value {
        match self.nodes() {
            Ok(nodes) => json!({"ok":true,"available":!nodes.is_empty(),"engine":"agent",
                "protocol":"labprobe-http-v1","method":"single_tcp_http_payload",
                "maxConcurrentTasks":1,"maxConnections":1,"maxBytesPerPhase":MAX_BYTES,
                "nodes":nodes.iter().map(|n| json!({"id":n.id,"name":n.name})).collect::<Vec<_>>(),
                "reason":if nodes.is_empty() {Some("no_verified_nodes")} else {None}}),
            Err(e) => json!({"ok":true,"available":false,"engine":"agent",
                "nodes":[],"reason":"no_verified_nodes","error":e.to_string()}),
        }
    }

    pub(crate) async fn start(&self, request: &Value) -> Result<Value> {
        let id = request.get("taskId").and_then(Value::as_str).unwrap_or("");
        if !valid_id(id) {
            bail!("测速任务编号无效");
        }
        let options: Options =
            serde_json::from_value(request.get("config").cloned().unwrap_or_else(|| json!({})))
                .context("测速参数格式无效")?;
        if !valid_id(&options.node_id)
            || !(1..=MAX_BYTES).contains(&options.download_bytes)
            || !(1..=MAX_BYTES).contains(&options.upload_bytes)
            || !(1..=15).contains(&options.phase_timeout_seconds)
        {
            bail!("测速参数超出资源限制");
        }
        let mut inner = self.inner.lock().await;
        if inner.seen.iter().any(|seen| seen == id) {
            return Ok(json!({"ok":true,"taskId":id,"idempotent":true}));
        }
        if inner.cancel.is_some() {
            bail!("已有测速任务正在运行");
        }
        let node = self
            .nodes()?
            .into_iter()
            .find(|n| n.id == options.node_id)
            .context("没有已验证的测速节点，请先配置受控节点")?;
        let (cancel, receiver) = watch::channel(false);
        inner.snapshot = Snapshot {
            id: id.into(),
            node_id: node.id.clone(),
            node_name: node.name.clone(),
            state: "running".into(),
            phase: "preparing".into(),
            started_at: Some(epoch()),
            updated_at: Some(epoch()),
            ..Snapshot::default()
        };
        inner.cancel = Some(cancel);
        inner.seen.push_back(id.into());
        if inner.seen.len() > 32 {
            inner.seen.pop_front();
        }
        drop(inner);
        let manager = self.clone();
        tokio::spawn(async move {
            manager.run(node, options, receiver).await;
        });
        Ok(json!({"ok":true,"taskId":id}))
    }

    pub(crate) async fn cancel(&self, id: &str) -> Result<Value> {
        let mut inner = self.inner.lock().await;
        if inner.snapshot.id != id || id.is_empty() {
            bail!("测速任务已经变化");
        }
        if let Some(cancel) = inner.cancel.as_ref() {
            let _ = cancel.send(true);
            inner.snapshot.state = "cancel_requested".into();
        }
        Ok(json!({"ok":true,"taskId":id}))
    }

    pub(crate) async fn status(&self) -> Value {
        let inner = self.inner.lock().await;
        let mut value = serde_json::to_value(&inner.snapshot).unwrap_or(Value::Null);
        value["ok"] = json!(true);
        value["engine"] = json!("agent");
        value["measurement"] = json!("single_tcp_http_payload");
        value
    }

    async fn update(&self, change: impl FnOnce(&mut Snapshot)) {
        let mut inner = self.inner.lock().await;
        change(&mut inner.snapshot);
        inner.snapshot.updated_at = Some(epoch());
    }

    async fn run(&self, node: Node, options: Options, mut cancel: watch::Receiver<bool>) {
        // Dropping the selected-out future releases response/body streams immediately.
        let outcome = tokio::select! {
            biased;
            _ = cancel.changed() => ("cancelled", Some("用户取消测速".into())),
            result = timeout(TOTAL_TIMEOUT, self.measure(&node, &options)) => match result {
                Ok(Ok(())) => ("completed", None),
                Ok(Err(e)) => ("failed", Some(format!("{e:#}"))),
                Err(_) => ("failed", Some("测速总时限已到".into())),
            }
        };
        let mut inner = self.inner.lock().await;
        inner.snapshot.state = outcome.0.into();
        inner.snapshot.error = outcome.1;
        inner.snapshot.finished_at = Some(epoch());
        inner.snapshot.updated_at = Some(epoch());
        inner.cancel = None;
    }

    async fn client(&self, node: &Node) -> Result<Client> {
        let mut builder = Client::builder()
            .no_proxy()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(4))
            .pool_max_idle_per_host(0)
            .user_agent("LabProbe-Agent-Speedtest/1");
        for raw in [&node.latency_url, &node.download_url, &node.upload_url] {
            let url = endpoint(raw)?;
            let host = url
                .host_str()
                .context("节点缺少主机")?
                .trim_matches(['[', ']']);
            let port = url.port_or_known_default().context("节点端口无效")?;
            let addresses: Vec<SocketAddr> =
                timeout(Duration::from_secs(4), lookup_host((host, port)))
                    .await
                    .context("节点 DNS 解析超时")??
                    .take(16)
                    .collect();
            if addresses.is_empty() {
                bail!("节点没有可用地址");
            }
            for address in &addresses {
                let allowed = public_ip(address.ip());
                #[cfg(test)]
                let allowed = allowed || (self.allow_loopback && address.ip().is_loopback());
                if !allowed {
                    bail!("测速节点解析到非公网地址");
                }
            }
            // Pin validated DNS results. No second lookup may redirect into the LAN.
            builder = builder.resolve_to_addrs(host, &addresses);
        }
        builder.build().context("创建测速 HTTP 客户端失败")
    }

    async fn measure(&self, node: &Node, options: &Options) -> Result<()> {
        let client = self.client(node).await?;
        let deadline = Duration::from_secs(options.phase_timeout_seconds);
        self.update(|s| s.phase = "latency".into()).await;
        let mut latencies = Vec::with_capacity(3);
        for _ in 0..3 {
            let started = Instant::now();
            timeout(deadline, async {
                let response = checked(
                    client
                        .get(&node.latency_url)
                        .header("Cache-Control", "no-store")
                        .header("Accept-Encoding", "identity")
                        .send()
                        .await?,
                )?;
                bounded_reply(response, MAX_REPLY).await?;
                Result::<()>::Ok(())
            })
            .await
            .context("延迟测量超时")??;
            latencies.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        let latency = latencies.iter().sum::<f64>() / latencies.len() as f64;
        let jitter = latencies
            .windows(2)
            .map(|p| (p[1] - p[0]).abs())
            .sum::<f64>()
            / 2.0;
        self.update(|s| {
            s.latency_ms = Some(latency);
            s.jitter_ms = Some(jitter);
            s.phase = "download".into();
        })
        .await;
        timeout(deadline, self.download(&client, node, options))
            .await
            .context("下载测量超时")??;
        self.update(|s| s.phase = "upload".into()).await;
        timeout(deadline, self.upload(&client, node, options))
            .await
            .context("上传测量超时")??;
        self.update(|s| s.phase = "complete".into()).await;
        Ok(())
    }

    async fn download(&self, client: &Client, node: &Node, options: &Options) -> Result<()> {
        let start = Instant::now();
        let mut response = checked(
            client
                .get(&node.download_url)
                .header("Accept-Encoding", "identity")
                .header("Cache-Control", "no-store")
                .header("X-LabProbe-Bytes", options.download_bytes)
                .send()
                .await?,
        )?;
        let mut received = 0u64;
        let mut updated = Instant::now();
        while let Some(chunk) = response.chunk().await? {
            received = received.saturating_add(chunk.len() as u64);
            if received > options.download_bytes {
                bail!("下载节点超过约定流量上限");
            }
            if updated.elapsed() >= Duration::from_millis(250) {
                self.update(|s| s.download_bytes = received).await;
                updated = Instant::now();
            }
        }
        if received != options.download_bytes {
            bail!("下载节点返回字节数不符");
        }
        let mbps = received as f64 * 8.0 / start.elapsed().as_secs_f64() / 1_000_000.0;
        self.update(|s| {
            s.download_bytes = received;
            s.download_mbps = Some(mbps);
        })
        .await;
        Ok(())
    }

    async fn upload(&self, client: &Client, node: &Node, options: &Options) -> Result<()> {
        let manager = self.clone();
        let total = options.upload_bytes;
        // Prepare one block outside the timed upload so router CPU generation does
        // not become the measured link bottleneck. Reuse it for every body chunk.
        let mut payload = vec![0u8; BLOCK];
        let mut x = 0x9e3779b97f4a7c15u64;
        for byte in &mut payload {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *byte = x as u8;
        }
        let payload = Arc::new(payload);
        // At most one 64 KiB application block per stream poll. Never buffer the payload.
        let body = stream::unfold(
            (0u64, manager, Instant::now(), payload),
            move |(sent, manager, mut updated, payload)| async move {
                if sent >= total {
                    return None;
                }
                let count = (total - sent).min(BLOCK as u64) as usize;
                let chunk = payload[..count].to_vec();
                let next = sent + count as u64;
                if updated.elapsed() >= Duration::from_millis(250) || next == total {
                    manager.update(|s| s.upload_bytes_sent = next).await;
                    updated = Instant::now();
                }
                Some((
                    Ok::<_, std::io::Error>(chunk),
                    (next, manager, updated, payload),
                ))
            },
        );
        let start = Instant::now();
        let response = checked(
            client
                .post(&node.upload_url)
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", total)
                .header("Accept-Encoding", "identity")
                .header("Cache-Control", "no-store")
                .body(reqwest::Body::wrap_stream(body))
                .send()
                .await?,
        )?;
        let reply = bounded_reply(response, MAX_REPLY).await?;
        let result: Value = serde_json::from_slice(&reply).context("上传节点未返回有效确认")?;
        if self.inner.lock().await.snapshot.upload_bytes_sent != total {
            bail!("上传节点在请求体发送完成前返回确认");
        }
        if result.get("bytesReceived").and_then(Value::as_u64) != Some(total) {
            bail!("上传节点确认字节数不符");
        }
        let mbps = total as f64 * 8.0 / start.elapsed().as_secs_f64() / 1_000_000.0;
        self.update(|s| {
            s.upload_bytes_sent = total;
            s.upload_bytes = Some(total);
            s.upload_mbps = Some(mbps);
        })
        .await;
        Ok(())
    }
}

fn load_nodes(path: &Path) -> Result<Vec<Node>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .context("测速节点未配置")?
        .take(65_537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        bail!("测速节点配置超过上限");
    }
    let nodes: Vec<Node> = serde_json::from_slice(&bytes).context("测速节点配置格式无效")?;
    if nodes.len() > 16 {
        bail!("测速节点数量超过上限");
    }
    for (index, node) in nodes.iter().enumerate() {
        if !valid_id(&node.id)
            || node.name.is_empty()
            || node.name.len() > 128
            || node.protocol != "labprobe-http-v1"
            || node.verification.trim().is_empty()
            || nodes[..index].iter().any(|n| n.id == node.id)
        {
            bail!("测速节点身份或协议未验证");
        }
        for raw in [&node.latency_url, &node.download_url, &node.upload_url] {
            endpoint(raw)?;
        }
    }
    Ok(nodes)
}

fn checked(response: Response) -> Result<Response> {
    if response.status() != reqwest::StatusCode::OK {
        bail!("测速节点 HTTP {}", response.status());
    }
    if response
        .headers()
        .get("content-encoding")
        .is_some_and(|v| v != "identity")
    {
        bail!("测速节点返回压缩内容，不能可靠计量");
    }
    Ok(response)
}

async fn bounded_reply(mut response: Response, max: usize) -> Result<Vec<u8>> {
    let mut reply = Vec::with_capacity(max);
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > max - reply.len() {
            bail!("测速节点确认响应超过上限");
        }
        reply.extend_from_slice(&chunk);
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    struct Fixture {
        manager: SpeedTestManager,
        requests: Arc<AtomicU64>,
        uploads: Arc<AtomicU64>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
            let _ = std::fs::remove_file(&self.manager.node_path);
        }
    }

    async fn fixture(mode: &'static str) -> Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicU64::new(0));
        let uploads = Arc::new(AtomicU64::new(0));
        let (r, u) = (requests.clone(), uploads.clone());
        let server = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (r, u) = (r.clone(), u.clone());
                tokio::spawn(async move {
                    let mut socket = BufReader::new(socket);
                    let mut line = String::new();
                    socket.read_line(&mut line).await.unwrap();
                    let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    let mut length = 0u64;
                    let mut download = 0u64;
                    loop {
                        line.clear();
                        if socket.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" {
                            break;
                        }
                        if let Some((key, value)) = line.split_once(':') {
                            if key.eq_ignore_ascii_case("content-length") {
                                length = value.trim().parse().unwrap();
                            }
                            if key.eq_ignore_ascii_case("x-labprobe-bytes") {
                                download = value.trim().parse().unwrap();
                            }
                        }
                    }
                    r.fetch_add(1, Ordering::SeqCst);
                    if mode == "stall" {
                        // Remain blocked until the client actually closes its request.
                        let _ = socket.read_u8().await;
                        return;
                    }
                    if mode == "redirect" {
                        let _ = socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                        return;
                    }
                    if mode == "early_ack" && path == "/upload" {
                        let body = json!({"bytesReceived":length}).to_string();
                        let _ = socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await;
                        return;
                    }
                    let mut buffer = [0u8; 8192];
                    let mut received = 0;
                    while received < length {
                        let count = (length - received).min(buffer.len() as u64) as usize;
                        if socket.read_exact(&mut buffer[..count]).await.is_err() {
                            return;
                        }
                        received += count as u64;
                    }
                    u.fetch_add(received, Ordering::SeqCst);
                    if path == "/download" {
                        let _ = socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {download}\r\nConnection: close\r\n\r\n").as_bytes()).await;
                        let mut sent = 0;
                        while sent < download {
                            let count = (download - sent).min(buffer.len() as u64) as usize;
                            if socket.write_all(&buffer[..count]).await.is_err() {
                                return;
                            }
                            sent += count as u64;
                        }
                    } else {
                        let body = if path == "/upload" {
                            json!({"bytesReceived":if mode == "bad_ack" { received-1 } else { received }}).to_string()
                        } else {
                            "ok".into()
                        };
                        let _ = socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await;
                    }
                });
            }
        });
        let mut manager = SpeedTestManager::new();
        manager.allow_loopback = true;
        manager.node_path = std::env::temp_dir().join(format!(
            "labprobe-speedtest-{}-{}.json",
            std::process::id(),
            address.port()
        ));
        let base = format!("http://{address}");
        std::fs::write(&manager.node_path, json!([{"id":"fixture","name":"Local fixture",
            "protocol":"labprobe-http-v1","verification":"Local integration fixture, not a production node",
            "latencyUrl":format!("{base}/latency"),"downloadUrl":format!("{base}/download"),"uploadUrl":format!("{base}/upload")}]).to_string()).unwrap();
        Fixture {
            manager,
            requests,
            uploads,
            server,
        }
    }

    fn request(id: &str) -> Value {
        json!({"taskId":id,"config":{"nodeId":"fixture","downloadBytes":262144,"uploadBytes":196608,"phaseTimeoutSeconds":1}})
    }

    async fn terminal(manager: &SpeedTestManager) -> Value {
        timeout(Duration::from_secs(4), async {
            loop {
                let status = manager.status().await;
                if matches!(
                    status["state"].as_str(),
                    Some("completed" | "failed" | "cancelled")
                ) {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn counts_real_streamed_payload_and_status_has_no_network_side_effects() {
        let f = fixture("ok").await;
        assert!(f.manager.capability()["available"].as_bool().unwrap());
        for _ in 0..20 {
            assert!(f.manager.status().await["downloadMbps"].is_null());
        }
        assert_eq!(f.requests.load(Ordering::SeqCst), 0);
        f.manager.start(&request("one")).await.unwrap();
        let status = terminal(&f.manager).await;
        assert_eq!(status["state"], "completed", "{status}");
        assert_eq!(status["downloadBytes"], 262144);
        assert_eq!(status["uploadBytes"], 196608);
        assert_eq!(f.uploads.load(Ordering::SeqCst), 196608);
        assert!(status["downloadMbps"].as_f64().unwrap() > 0.0);
        assert!(status["uploadMbps"].as_f64().unwrap() > 0.0);
        assert!(status["latencyMs"].as_f64().unwrap() > 0.0);
        assert_eq!(f.requests.load(Ordering::SeqCst), 5);
        f.manager.start(&request("two")).await.unwrap();
        terminal(&f.manager).await;
        assert_eq!(
            f.manager.start(&request("one")).await.unwrap()["idempotent"],
            true
        );
        for _ in 0..20 {
            f.manager.status().await;
        }
        assert_eq!(f.requests.load(Ordering::SeqCst), 10);
    }

    #[tokio::test]
    async fn one_task_timeout_cancel_and_unknown_results() {
        let f = fixture("stall").await;
        f.manager.start(&request("timeout")).await.unwrap();
        assert!(f.manager.start(&request("duplicate")).await.is_err());
        let status = terminal(&f.manager).await;
        assert_eq!(status["state"], "failed");
        assert!(status["downloadMbps"].is_null());
        assert!(status["latencyMs"].is_null());
        f.manager.start(&request("cancel")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let started = Instant::now();
        f.manager.cancel("cancel").await.unwrap();
        assert_eq!(terminal(&f.manager).await["state"], "cancelled");
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(f.manager.cancel("wrong").await.is_err());
    }

    #[tokio::test]
    async fn server_must_acknowledge_upload_and_redirects_are_rejected() {
        let f = fixture("bad_ack").await;
        f.manager.start(&request("bad-ack")).await.unwrap();
        let status = terminal(&f.manager).await;
        assert_eq!(status["state"], "failed");
        assert!(status["uploadMbps"].is_null());
        assert!(status["uploadBytes"].is_null());
        assert!(status["downloadMbps"].is_number());
        let f = fixture("redirect").await;
        f.manager.start(&request("redirect")).await.unwrap();
        assert_eq!(terminal(&f.manager).await["state"], "failed");
        assert_eq!(f.requests.load(Ordering::SeqCst), 1);
        let f = fixture("early_ack").await;
        let mut early = request("early-ack");
        early["config"]["uploadBytes"] = json!(MAX_BYTES);
        f.manager.start(&early).await.unwrap();
        let status = terminal(&f.manager).await;
        assert_eq!(status["state"], "failed", "{status}");
        assert!(status["uploadMbps"].is_null());
    }

    #[tokio::test]
    async fn production_rejects_private_endpoints_and_command_urls() {
        let mut f = fixture("ok").await;
        f.manager.allow_loopback = false;
        f.manager.start(&request("ssrf")).await.unwrap();
        assert_eq!(terminal(&f.manager).await["state"], "failed");
        assert_eq!(f.requests.load(Ordering::SeqCst), 0);
        let mut invalid = request("url");
        invalid["config"]["downloadUrl"] = json!("http://192.168.1.1/admin");
        assert!(f.manager.start(&invalid).await.is_err());
    }

    #[test]
    fn rejects_reserved_addresses_and_unconfigured_nodes() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "2002:7f00:1::",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public_ip(ip.parse().unwrap()));
        }
        let mut manager = SpeedTestManager::new();
        manager.node_path = std::env::temp_dir().join("labprobe-no-such-speedtest-node.json");
        assert_eq!(manager.capability()["available"], false);
        assert!(endpoint("file:///etc/passwd").is_err());
        assert!(endpoint("http://user:password@example.com/").is_err());
    }
}
