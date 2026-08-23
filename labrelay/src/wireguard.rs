//! WireGuard capability detection and the Agent-owned server control plane.
//!
//! Detection remains non-mutating. Provisioning is an explicit Agent command:
//! it uses the kernel Generic Netlink backend, keeps the private key on the
//! router, and never accepts arbitrary shell input.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, KeyPair, PeerConfigBuilder};

const DEFAULT_PRIVATE_KEY_PATH: &str = "/etc/labprobe/wireguard/private.key";

/// A public endpoint profile belongs to exactly one updater.  DDNS and STUN
/// are separate profiles so two background jobs can never race on one client
/// endpoint.  The Agent does not resolve these values; it only preserves and
/// reports the selected source as part of the desired configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardEndpointProfile {
    pub id: String,
    pub endpoint_source: String,
    /// Stable updater identity (`ddns:<profile-id>` or `stun:<rule-id>`).
    /// Manual profiles have no owner and reject automatic updates.
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub public_endpoint: String,
    #[serde(default)]
    pub resolved_endpoint: String,
    #[serde(default)]
    pub stun_rule_id: String,
    #[serde(default)]
    pub binding_mode: String,
    #[serde(default)]
    pub forward_mode: String,
    #[serde(default)]
    pub transport_protocol: String,
    #[serde(default)]
    pub local_target_port: u16,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub endpoint_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardEndpointUpdate {
    pub profile_id: String,
    pub endpoint_source: String,
    pub owner: String,
    pub endpoint: String,
    pub expected_endpoint_revision: u64,
    pub endpoint_revision: u64,
}

/// Apply a public endpoint observation without changing the server/kernel
/// revision. This is deliberately a separate state transition from applying
/// WireGuard interface configuration.
pub fn apply_endpoint_update(
    profiles: &mut [WireGuardEndpointProfile],
    update: &WireGuardEndpointUpdate,
) -> Result<WireGuardEndpointProfile> {
    let profile = profiles
        .iter_mut()
        .find(|profile| profile.id == update.profile_id)
        .ok_or_else(|| anyhow::anyhow!("endpoint profile not found"))?;
    if profile.endpoint_source == "manual" {
        bail!("manual endpoint profile cannot be changed by an automatic updater");
    }
    if profile.endpoint_source != update.endpoint_source {
        bail!("endpoint updater source does not match profile");
    }
    if profile.owner.is_empty() || profile.owner != update.owner {
        bail!("endpoint updater owner does not match profile");
    }
    if profile.endpoint_revision == update.endpoint_revision
        && profile.resolved_endpoint == update.endpoint
    {
        return Ok(profile.clone());
    }
    if profile.endpoint_revision != update.expected_endpoint_revision {
        bail!("endpoint revision conflict");
    }
    if update.endpoint_revision != update.expected_endpoint_revision.saturating_add(1) {
        bail!("endpoint revision must advance exactly once");
    }
    if update.endpoint.trim().is_empty() {
        bail!("endpoint cannot be empty");
    }
    profile.resolved_endpoint = update.endpoint.clone();
    profile.endpoint_revision = update.endpoint_revision;
    Ok(profile.clone())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardPeerDesired {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub persistent_keepalive_seconds: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardServerDesired {
    #[serde(default = "default_interface_name")]
    pub interface_name: String,
    #[serde(default = "default_server_address")]
    pub address: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub peers: Vec<WireGuardPeerDesired>,
    #[serde(default)]
    pub endpoint_profiles: Vec<WireGuardEndpointProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardApplyResult {
    pub ok: bool,
    pub interface_name: String,
    pub public_key: String,
    pub listen_port: u16,
    pub peer_count: usize,
    pub enabled: bool,
    pub revision: u64,
    pub control_backend: String,
}

fn default_interface_name() -> String { "labwg0".into() }
fn default_server_address() -> String { "10.77.0.1/24".into() }
fn default_listen_port() -> u16 { 51820 }
fn default_true() -> bool { true }

/// Per-interface WireGuard status. Public key is safe to report; the private
/// key is never read, parsed, logged or serialized.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardInterfaceStatus {
    pub name: String,
    pub public_key: String,
    pub listen_port: Option<u16>,
    pub peer_count: u32,
    pub running: bool,
    pub addresses: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub latest_handshake_at: Option<u64>,
}

/// Aggregate WireGuard status for a router.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardStatus {
    pub supported: bool,
    pub wg_tool_available: bool,
    pub kernel_supported: bool,
    pub control_tool_available: bool,
    /// True when Agent can provision through Generic Netlink even if `wg`
    /// is not installed.
    pub provisioning_ready: bool,
    pub control_backend: String,
    pub kernel_support: bool,
    pub installed: bool,
    /// `true` when UCI contains a real `proto='wireguard'` interface OR a
    /// WireGuard interface confirmed by the wg tool already exists (which
    /// covers manually created interfaces without UCI configuration).
    pub configured: bool,
    pub running: bool,
    pub interfaces: Vec<WireGuardInterfaceStatus>,
    pub interface_count: u32,
    pub peer_count: u32,
    pub latest_handshake_at: Option<u64>,
    pub error: Option<String>,
}

impl WireGuardStatus {
    /// A status that is safe to return when the `wg` tool cannot even be
    /// located; never treated as an error condition by callers.
    fn without_wg_tool(kernel_support: bool, uci_error: Option<String>) -> Self {
        Self {
            // Runtime configuration uses the kernel Generic Netlink API and
            // does not require the optional `wg` CLI.
            supported: kernel_support,
            wg_tool_available: false,
            kernel_supported: kernel_support,
            control_tool_available: false,
            provisioning_ready: kernel_support,
            control_backend: if kernel_support { "kernel-netlink".into() } else { "unavailable".into() },
            kernel_support,
            installed: kernel_support,
            configured: false,
            running: false,
            interfaces: Vec::new(),
            interface_count: 0,
            peer_count: 0,
            latest_handshake_at: None,
            error: uci_error,
        }
    }

    #[cfg(test)]
    fn empty_with(kernel_support: bool) -> Self {
        Self {
            supported: kernel_support,
            wg_tool_available: true,
            kernel_supported: kernel_support,
            control_tool_available: true,
            provisioning_ready: kernel_support,
            control_backend: if kernel_support { "kernel-netlink".into() } else { "unavailable".into() },
            kernel_support,
            installed: true,
            configured: false,
            running: false,
            interfaces: Vec::new(),
            interface_count: 0,
            peer_count: 0,
            latest_handshake_at: None,
            error: None,
        }
    }

    /// Merge per-step errors into a single, bounded message. Only detection
    /// problems land here; absence of WireGuard is not an error.
    fn apply_errors(&mut self, errors: &[String]) {
        if errors.is_empty() {
            return;
        }
        let mut message = errors.join(" | ");
        message = sanitize_sensitive(&message);
        if message.len() > 400 {
            message.truncate(400);
            message.push_str("...");
        }
        self.error = Some(message);
    }
}

/// Defensive scrubber for anything that reaches `WireGuardStatus::error`.
///
/// Normal paths never include dump stdout; this is a final guarantee that
/// key material can never leak into the error object even via stderr.
/// It removes the sensitive *values* themselves: any span starting at a
/// private/preshared/secret keyword through the end of its segment (line or
/// `|` separator) is redacted, and standalone 44-character base64 tokens
/// (the exact WireGuard key shape) are redacted too.
fn sanitize_sensitive(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut redacted: Vec<(usize, usize)> = Vec::new();

    // 1) Keyword-led segments: from the keyword to the end of the segment.
    let keywords = ["private", "preshared", "secret"];
    let mut search_from = 0usize;
    while search_from < lower.len() {
        let mut found: Option<usize> = None;
        for keyword in keywords.iter() {
            if let Some(offset) = lower[search_from..].find(keyword) {
                let start = search_from + offset;
                found = Some(match found {
                    Some(current) => current.min(start),
                    None => start,
                });
            }
        }
        let Some(start) = found else { break };
        let segment_end = lower[start..]
            .find(['\n', '|'])
            .map(|end| start + end)
            .unwrap_or(lower.len());
        if segment_end > start {
            redacted.push((start, segment_end));
        }
        search_from = segment_end;
    }

    // 2) Standalone WireGuard-shaped base64 tokens (44 chars, optional '=').
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        let is_b64 = byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/';
        if !is_b64 {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric()
                || bytes[index] == b'+'
                || bytes[index] == b'/'
                || bytes[index] == b'=')
        {
            index += 1;
        }
        let length = index - start;
        let valid_key = (length == 44 && bytes[start + 43] == b'=')
            || (length == 44 && bytes[index - 1] != b'=')
            || (length == 43 && bytes.get(index).copied() == Some(b'='));
        let boundary_ok = start == 0
            || !(bytes[start - 1].is_ascii_alphanumeric()
                || matches!(bytes[start - 1], b'+' | b'/' | b'='));
        let boundary_end_ok = index >= bytes.len()
            || !(bytes[index].is_ascii_alphanumeric()
                || matches!(bytes[index], b'+' | b'/' | b'='));
        if valid_key && boundary_ok && boundary_end_ok {
            redacted.push((start, index));
        }
    }

    if redacted.is_empty() {
        return text.to_string();
    }
    redacted.sort_unstable_by_key(|span| span.0);
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for span in redacted {
        if let Some(last) = merged.last_mut() {
            if span.0 <= last.1 {
                last.1 = last.1.max(span.1);
                continue;
            }
        }
        merged.push(span);
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (start, end) in merged {
        out.push_str(&text[cursor..start]);
        out.push_str("[REDACTED]");
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Parse the whitespace-separated interface list from `wg show interfaces`.
pub fn parse_wg_interfaces(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse `wg show all dump` output into per-interface status.
///
/// Format (tab separated):
///   interface lines: interface private_key public_key listen_port fwmark
///   peer lines:      interface public_key preshared_key endpoint allowed_ips
///                    latest_handshake rx tx persistent_keepalive
///                    [allowed_ip ...]
///
/// Peer lines start with `<interface>\t`. Malformed or unknown lines are
/// skipped, never fatal.
pub fn parse_wg_dump(raw: &str) -> Vec<WireGuardInterfaceStatus> {
    let mut interfaces: Vec<WireGuardInterfaceStatus> = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        // Interface rows are always exactly five tab-separated columns
        // (interface, private key, public key, listen port, fwmark). Peer rows
        // have nine columns: interface, peer public key, preshared key,
        // endpoint, allowed ips, latest handshake, rx, tx, keepalive.
        if fields.len() != 5 || fields[0].is_empty() || fields[1].is_empty() {
            continue;
        }
        let name = fields[0].to_string();
        if interfaces.iter().any(|item| item.name == name) {
            continue;
        }
        interfaces.push(WireGuardInterfaceStatus {
            name,
            public_key: fields[2].to_string(),
            listen_port: fields[3].parse().ok(),
            peer_count: 0,
            running: false,
            addresses: Vec::new(),
            rx_bytes: 0,
            tx_bytes: 0,
            latest_handshake_at: None,
        });
    }

    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        // Nine fixed columns; tolerate a trailing tab from some wg versions.
        if fields.len() < 9 {
            continue;
        }
        let (interface, _peer_public_key) = (fields[0], fields[1]);
        let Some(item) = interfaces
            .iter_mut()
            .find(|item| item.name == interface)
        else {
            continue;
        };
        // Columns: interface, peer public key, preshared key, endpoint,
        // allowed ips, latest handshake, rx, tx, persistent keepalive.
        let handshake = fields[5].parse::<u64>().unwrap_or(0);
        let rx = fields[6].parse::<u64>().unwrap_or(0);
        let tx = fields[7].parse::<u64>().unwrap_or(0);
        item.peer_count += 1;
        item.rx_bytes = item.rx_bytes.saturating_add(rx);
        item.tx_bytes = item.tx_bytes.saturating_add(tx);
        if handshake > 0 {
            item.latest_handshake_at = Some(
                item.latest_handshake_at
                    .map(|current| current.max(handshake))
                    .unwrap_or(handshake),
            );
        }
    }
    interfaces
}

/// Parse `ip addr show <interface>` output into a CIDR list (IPv4 and IPv6).
/// IPv6 link-local addresses are intentionally omitted.
pub fn parse_ip_addresses(raw: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    for line in raw.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(index) = fields.iter().position(|field| *field == "inet" || *field == "inet6")
        else {
            continue;
        };
        let Some(raw_address) = fields.get(index + 1) else {
            continue;
        };
        let address = raw_address.split('/').next().unwrap_or("");
        if address.is_empty() || address.starts_with("fe80:") {
            continue;
        }
        addresses.push(raw_address.to_string());
    }
    addresses
}

/// Parse the `ip link show <interface>` first line for the admin UP flag.
/// WireGuard tunnels commonly report `state UNKNOWN` while being up, so only
/// the `<...,UP,...>` flag (or an explicit `state UP`) counts as running.
pub fn parse_link_up(raw: &str) -> bool {
    for line in raw.lines() {
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        if text.contains(",UP,") || text.contains(",UP>") {
            return true;
        }
        if text.contains("state UP") {
            return true;
        }
        // Only the first meaningful line carries the flags.
        break;
    }
    false
}

/// Strict UCI proto detection: only `proto='wireguard'` / `proto="wireguard"`
/// counts. A value that merely contains the string "wireguard" (e.g. a peer
/// name or a hostname) must not be treated as a configured interface.
pub fn parse_uci_wireguard_configured(raw: &str) -> bool {
    raw.lines().any(|line| {
        line.contains("proto='wireguard'") || line.contains("proto=\"wireguard\"")
    })
}

/// Total peer count across all parsed interfaces.
pub fn total_peer_count(interfaces: &[WireGuardInterfaceStatus]) -> u32 {
    interfaces.iter().map(|item| item.peer_count).sum()
}

/// Latest valid handshake (greater than zero) across all parsed interfaces.
pub fn latest_handshake(interfaces: &[WireGuardInterfaceStatus]) -> Option<u64> {
    interfaces
        .iter()
        .filter_map(|item| item.latest_handshake_at)
        .max()
}

fn is_ascii_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '@'))
}

/// Return the parameterized `ip` arguments needed to create an interface.
/// Keeping this decision pure makes first-apply behavior testable on CI hosts
/// that do not have a WireGuard kernel module.
pub fn interface_create_args(interface_exists: bool, interface_name: &str) -> Option<Vec<String>> {
    if interface_exists {
        None
    } else {
        Some(vec![
            "link".into(),
            "add".into(),
            "dev".into(),
            interface_name.into(),
            "type".into(),
            "wireguard".into(),
        ])
    }
}

fn parse_cidr(value: &str) -> Result<(IpAddr, u8)> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("CIDR prefix is required"))?;
    let address: IpAddr = address.parse().context("invalid IP address")?;
    let prefix: u8 = prefix.parse().context("invalid CIDR prefix")?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        bail!("CIDR prefix out of range");
    }
    Ok((address, prefix))
}

/// Validate an untrusted Hub document before it reaches the kernel API.
/// Private/preshared keys are deliberately not part of this schema.
pub fn validate_server_desired(config: &WireGuardServerDesired) -> Result<()> {
    if !is_ascii_interface_name(&config.interface_name)
        || config.interface_name.len() > 15
        || config.interface_name == "lo"
    {
        bail!("invalid WireGuard interface name");
    }
    if config.listen_port == 0 {
        bail!("WireGuard server requires a fixed UDP listen port");
    }
    let (server_ip, _) = parse_cidr(&config.address)?;
    if !server_ip.is_ipv4() {
        bail!("MVP server address must be IPv4");
    }
    let mut profile_ids = std::collections::BTreeSet::new();
    for profile in &config.endpoint_profiles {
        if profile.id.is_empty() || !profile_ids.insert(profile.id.as_str()) {
            bail!("endpoint profile ids must be unique");
        }
        if !matches!(profile.endpoint_source.as_str(), "manual" | "ddns" | "stun") {
            bail!("endpointSource must be manual, ddns or stun");
        }
        if profile.endpoint_source == "manual"
            && (!profile.owner.is_empty()
                || profile.binding_mode != "manual"
                || profile.resolved_endpoint.trim().is_empty())
        {
            bail!("manual endpoint profile requires an immutable endpoint and no updater owner");
        }
        if profile.endpoint_source == "ddns"
            && (profile.hostname.trim().is_empty()
                || profile.owner != format!("ddns:{}", profile.id))
        {
            bail!("DDNS endpoint profile requires hostname");
        }
        if profile.endpoint_source == "ddns" && profile.binding_mode != "fixed-port" {
            bail!("DDNS endpoint profile requires fixed-port binding");
        }
        if profile.endpoint_source == "stun" && !profile.hostname.trim().is_empty() {
            bail!("STUN endpoint profile cannot share a DDNS hostname");
        }
        if profile.endpoint_source == "stun"
            && (profile.stun_rule_id.is_empty()
                || profile.owner != format!("stun:{}", profile.stun_rule_id)
                || profile.binding_mode != "router-native"
                || profile.forward_mode != "router_native"
                || profile.transport_protocol != "UDP"
                || profile.local_target_port != config.listen_port)
        {
            bail!("STUN endpoint profile requires an enabled UDP router-native mapping to the fixed WireGuard port");
        }
    }
    let mut peer_ids = std::collections::BTreeSet::new();
    let mut peer_keys = std::collections::BTreeSet::new();
    for peer in &config.peers {
        if peer.id.is_empty() || !peer_ids.insert(peer.id.as_str()) {
            bail!("peer ids must be unique");
        }
        Key::from_base64(peer.public_key.trim()).map_err(|_| anyhow::anyhow!("invalid peer public key"))?;
        if !peer_keys.insert(peer.public_key.trim()) {
            bail!("peer public keys must be unique");
        }
        if peer.allowed_ips.is_empty() {
            bail!("peer requires at least one allowed IP");
        }
        for allowed in &peer.allowed_ips {
            parse_cidr(allowed)?;
        }
        if peer.persistent_keepalive_seconds > 600 {
            bail!("persistent keepalive is out of range");
        }
    }
    Ok(())
}

fn private_key_path() -> PathBuf {
    std::env::var_os("LABPROBE_WIREGUARD_PRIVATE_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PRIVATE_KEY_PATH))
}

fn load_or_create_keypair(path: &Path) -> Result<KeyPair> {
    if path.exists() {
        let raw = fs::read_to_string(path).context("read local WireGuard key")?;
        let private = Key::from_base64(raw.trim())
            .map_err(|_| anyhow::anyhow!("local WireGuard key is invalid"))?;
        return Ok(KeyPair::from_private(private));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create WireGuard key directory")?;
    }
    let pair = KeyPair::generate();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).context("create local WireGuard key")?;
    file.write_all(pair.private.to_base64().as_bytes())
        .context("write local WireGuard key")?;
    file.write_all(b"\n").context("finish local WireGuard key")?;
    file.sync_all().context("sync local WireGuard key")?;
    Ok(pair)
}

#[cfg(target_os = "linux")]
fn configure_link(config: &WireGuardServerDesired) -> Result<()> {
    let ip = find_tool("ip").ok_or_else(|| anyhow::anyhow!("ip tool is required to assign the tunnel address"))?;
    // No shell is involved; every argument is validated and passed directly.
    run_capture(&ip, &["address", "replace", &config.address, "dev", &config.interface_name])?;
    run_capture(&ip, &["link", "set", "dev", &config.interface_name, if config.enabled { "up" } else { "down" }])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_interface(ip_tool: &str, interface_name: &str) -> Result<()> {
    let exists = Command::new(ip_tool)
        .args(["link", "show", "dev", interface_name])
        .output()
        .with_context(|| format!("probe WireGuard interface {interface_name}"))?
        .status
        .success();
    let Some(args) = interface_create_args(exists, interface_name) else {
        return Ok(());
    };
    let output = Command::new(ip_tool)
        .args(&args)
        .output()
        .with_context(|| format!("create WireGuard interface {interface_name}"))?;
    if output.status.success() {
        return Ok(());
    }
    // Another apply can win the create race between the probe and add.  An
    // EEXIST-style response is therefore an idempotent success.
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if stderr.contains("file exists") || stderr.contains("already exists") {
        return Ok(());
    }
    bail!(
        "ip failed to create WireGuard interface {interface_name}: {}",
        stderr.trim()
    )
}

/// Apply the desired server through the kernel Generic Netlink backend.  This
/// does not invoke `wg` and therefore works on the BE72 firmware where the
/// kernel module exists but wireguard-tools is absent.
#[cfg(target_os = "linux")]
pub fn apply_server(config: &WireGuardServerDesired) -> Result<WireGuardApplyResult> {
    validate_server_desired(config)?;
    let ip = find_tool("ip").ok_or_else(|| anyhow::anyhow!("ip tool is required to create the WireGuard interface"))?;
    ensure_interface(&ip, &config.interface_name)?;
    let keypair = load_or_create_keypair(&private_key_path())?;
    let interface: InterfaceName = config.interface_name.parse()
        .map_err(|_| anyhow::anyhow!("invalid WireGuard interface name"))?;
    let mut update = DeviceUpdate::new()
        .set_private_key(keypair.private.clone())
        .set_listen_port(config.listen_port)
        .replace_peers();
    for peer in &config.peers {
        let public = Key::from_base64(peer.public_key.trim())
            .map_err(|_| anyhow::anyhow!("invalid peer public key"))?;
        let mut builder = PeerConfigBuilder::new(&public).replace_allowed_ips();
        for allowed in &peer.allowed_ips {
            let (address, prefix) = parse_cidr(allowed)?;
            builder = builder.add_allowed_ip(address, prefix);
        }
        if peer.persistent_keepalive_seconds > 0 {
            builder = builder.set_persistent_keepalive_interval(peer.persistent_keepalive_seconds);
        } else {
            builder = builder.unset_persistent_keepalive();
        }
        update = update.add_peer(builder);
    }
    update.apply(&interface, Backend::Kernel).context("apply WireGuard kernel configuration")?;
    configure_link(config)?;
    Ok(WireGuardApplyResult {
        ok: true,
        interface_name: config.interface_name.clone(),
        public_key: keypair.public.to_base64(),
        listen_port: config.listen_port,
        peer_count: config.peers.len(),
        enabled: config.enabled,
        revision: config.revision,
        control_backend: "kernel-netlink".into(),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn apply_server(config: &WireGuardServerDesired) -> Result<WireGuardApplyResult> {
    validate_server_desired(config)?;
    bail!("WireGuard kernel control is supported only on Linux")
}

pub fn stop_server(interface_name: &str) -> Result<()> {
    if !is_ascii_interface_name(interface_name) || interface_name.len() > 15 {
        bail!("invalid WireGuard interface name");
    }
    #[cfg(target_os = "linux")]
    {
        let ip = find_tool("ip").ok_or_else(|| anyhow::anyhow!("ip tool is unavailable"))?;
        run_capture(&ip, &["link", "set", "dev", interface_name, "down"])?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    bail!("WireGuard kernel control is supported only on Linux")
}

pub fn delete_server(interface_name: &str) -> Result<()> {
    if !is_ascii_interface_name(interface_name) || interface_name.len() > 15 {
        bail!("invalid WireGuard interface name");
    }
    #[cfg(target_os = "linux")]
    {
        let interface: InterfaceName = interface_name.parse()
            .map_err(|_| anyhow::anyhow!("invalid WireGuard interface name"))?;
        let exists = Device::list(Backend::Kernel)
            .context("list WireGuard devices")?
            .iter()
            .any(|name| name == &interface);
        if !exists {
            return Ok(());
        }
        let device = Device::get(&interface, Backend::Kernel).context("read WireGuard device")?;
        device.delete().context("delete WireGuard device")
    }
    #[cfg(not(target_os = "linux"))]
    bail!("WireGuard kernel control is supported only on Linux")
}

/// Find a tool on PATH, preferring the plain name and falling back to a couple
/// of conventional absolute locations used on OpenWrt.
fn find_tool(name: &str) -> Option<String> {
    let candidates = [name, &format!("/usr/bin/{name}"), &format!("/sbin/{name}")];
    for candidate in candidates.iter() {
        let probe = match name {
            "wg" => Command::new(candidate).arg("--version").output(),
            _ => Command::new(candidate).arg("-V").output(),
        };
        if let Ok(output) = probe {
            if output.status.success() {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

fn run_capture(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{program} failed: {}", stderr.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Kernel WireGuard support. OpenWrt commonly ships WireGuard built into the
/// kernel, so `lsmod` alone is not authoritative; check module artifacts and
/// the wg tool/OpenWrt platform as a fallback.
fn kernel_support_status(wg_tool: &Option<String>) -> (bool, Vec<String>) {
    let mut errors = Vec::new();
    if Path::new("/sys/module/wireguard").is_dir() {
        return (true, errors);
    }
    if let Ok(entries) = fs::read_dir("/lib/modules") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let module_path = path.join("wireguard.ko");
                let module_path_zst = path.join("wireguard.ko.zst");
                if module_path.exists() || module_path_zst.exists() {
                    return (true, errors);
                }
            }
        }
    }
    let openwrt = Path::new("/etc/openwrt_release").exists()
        || Path::new("/etc/openwrt_version").exists()
        || Path::new("/etc/board.json").exists();
    let wg_present = wg_tool.is_some();
    if wg_present && openwrt {
        // OpenWrt images usually compile WireGuard into the kernel; the
        // absence of a loadable module is expected there.
        return (true, errors);
    }
    if !wg_present && !openwrt {
        errors.push("kernel support unconfirmed: no /sys/module/wireguard".into());
    }
    (false, errors)
}

/// Read-only UCI check: does the current network configuration contain a
/// `proto wireguard` interface? Never writes to UCI.
fn uci_wireguard_configured() -> (bool, Option<String>) {
    let uci = find_tool("uci");
    let Some(uci) = uci else {
        return (false, None);
    };
    match run_capture(&uci, &["show", "network"]) {
        Ok(output) => (parse_uci_wireguard_configured(&output), None),
        Err(error) => (false, Some(format!("uci show network failed: {error:#}"))),
    }
}

/// Collect link state and CIDR addresses for an interface with a single
/// `ip link show` call. `link_up` is `None` only when the command failed.
fn collect_interface_link(
    ip_tool: &str,
    name: &str,
) -> (Option<bool>, Vec<String>, Option<String>) {
    if !is_ascii_interface_name(name) {
        return (None, Vec::new(), Some(format!("skip unsafe interface name {name:?}")));
    }
    match run_capture(ip_tool, &["addr", "show", name]) {
        Ok(output) => (Some(parse_link_up(&output)), parse_ip_addresses(&output), None),
        Err(error) => (None, Vec::new(), Some(format!("ip link show {name} failed: {error:#}"))),
    }
}

/// Full read-only WireGuard detection. Never panics: every shell step is
/// guarded and reported through `WireGuardStatus::error`.
pub fn detect_wireguard() -> WireGuardStatus {
    let wg_tool = find_tool("wg");
    let ip_tool = find_tool("ip");
    let (kernel_support, kernel_errors) = kernel_support_status(&wg_tool);
    let (uci_configured, uci_error) = uci_wireguard_configured();

    let Some(wg) = wg_tool else {
        let mut status = WireGuardStatus::without_wg_tool(kernel_support, uci_error);
        status.apply_errors(&kernel_errors);
        return status;
    };

    let mut errors = Vec::new();
    let interfaces_output = match run_capture(&wg, &["show", "interfaces"]) {
        Ok(output) => output,
        Err(error) => {
            errors.push(format!("wg show interfaces failed: {error:#}"));
            String::new()
        }
    };
    let known_interfaces = parse_wg_interfaces(&interfaces_output);

    let dump_output = match run_capture(&wg, &["show", "all", "dump"]) {
        Ok(output) => output,
        Err(error) => {
            errors.push(format!("wg show all dump failed: {error:#}"));
            String::new()
        }
    };
    let mut interfaces = parse_wg_dump(&dump_output);

    let mut any_running = false;
    // Interface names come from `wg` itself; the ASCII guard is defensive.
    for item in interfaces.iter_mut() {
        // running requires an explicit UP flag; if the link cannot be
        // inspected (command failure), we must not assume it is up.
        item.running = false;
        if let Some(ip) = &ip_tool {
            let (link_up, addresses, address_error) = collect_interface_link(ip, &item.name);
            item.addresses = addresses;
            if let Some(error) = address_error {
                errors.push(error);
            }
            if let Some(up) = link_up {
                item.running = up && known_interfaces.iter().any(|name| name == &item.name);
            }
        }
        if item.running {
            any_running = true;
        }
    }

    let peer_count = total_peer_count(&interfaces);
    let handshake = latest_handshake(&interfaces);
    // At this point the wg tool exists, so installed/supported reduce to the
    // kernel support verdict plus tool availability.
    let wg_and_kernel = kernel_support;

    let mut status = WireGuardStatus {
        supported: wg_and_kernel,
        wg_tool_available: true,
        kernel_supported: kernel_support,
        control_tool_available: true,
        provisioning_ready: kernel_support,
        control_backend: if kernel_support { "kernel-netlink".into() } else { "unavailable".into() },
        kernel_support,
        installed: wg_and_kernel,
        configured: uci_configured || !interfaces.is_empty(),
        running: any_running,
        interface_count: interfaces.len() as u32,
        interfaces,
        peer_count,
        latest_handshake_at: handshake,
        error: None,
    };
    status.apply_errors(&errors);
    status.apply_errors(&kernel_errors);
    status.error = status.error.or(uci_error);
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK_A: &str = "aJhXrK8YQ6V8k1gJfR0n2wBq4sD6fG8hJ1kL3mN5pQ7=";
    const PK_B: &str = "bJhXrK8YQ6V8k1gJfR0n2wBq4sD6fG8hJ1kL3mN5pQ7=";

    fn interface_line(name: &str, public_key: &str, port: u16) -> String {
        format!(
            "{name}\tPRIVATE-KEY-SHOULD-NEVER-LEAK\t{public_key}\t{port}\toff"
        )
    }

    fn peer_line(
        interface: &str,
        public_key: &str,
        handshake: u64,
        rx: u64,
        tx: u64,
    ) -> String {
        format!(
            "{interface}\t{public_key}\t(0)\t192.0.2.1:51820\t10.88.0.0/24\t{handshake}\t{rx}\t{tx}\toff"
        )
    }

    fn link_line(flags: &str, state: &str) -> String {
        format!(
            "2: wg0: <{flags}> mtu 1420 qdisc noqueue state {state} group default qlen 1000\n    inet 10.88.0.1/24 scope global wg0"
        )
    }

    #[test]
    fn wg_missing_returns_safe_status() {
        // Without a wg tool the status must be conservative and never crash.
        let status = WireGuardStatus::without_wg_tool(false, None);
        assert!(!status.supported);
        assert!(!status.wg_tool_available);
        assert!(!status.installed);
        assert!(!status.configured);
        assert!(!status.running);
        assert!(status.interfaces.is_empty());
        assert_eq!(status.interface_count, 0);
        assert_eq!(status.peer_count, 0);
        assert_eq!(status.latest_handshake_at, None);
    }

    #[test]
    fn wg_present_no_interfaces() {
        let status = WireGuardStatus::empty_with(true);
        assert!(status.supported);
        assert!(status.wg_tool_available);
        assert!(status.kernel_support);
        assert!(status.installed);
        assert!(!status.configured);
        assert!(!status.running);
        assert!(status.interfaces.is_empty());
        assert_eq!(status.peer_count, 0);
    }

    #[test]
    fn missing_interface_gets_parameterized_create_command() {
        assert_eq!(
            interface_create_args(false, "labwg0"),
            Some(vec![
                "link", "add", "dev", "labwg0", "type", "wireguard"
            ].into_iter().map(String::from).collect())
        );
    }

    #[test]
    fn existing_interface_is_not_recreated() {
        assert_eq!(interface_create_args(true, "labwg0"), None);
    }

    #[test]
    fn server_contract_keeps_endpoint_sources_separate() {
        let peer = KeyPair::generate();
        let desired = WireGuardServerDesired {
            interface_name: "labwg0".into(),
            address: "10.77.0.1/24".into(),
            listen_port: 51820,
            enabled: true,
            revision: 7,
            peers: vec![WireGuardPeerDesired {
                id: "phone".into(),
                name: "Phone".into(),
                public_key: peer.public.to_base64(),
                allowed_ips: vec!["10.77.0.2/32".into()],
                persistent_keepalive_seconds: 25,
            }],
            endpoint_profiles: vec![
                WireGuardEndpointProfile {
                    id: "wg-ddns".into(),
                    endpoint_source: "ddns".into(),
                    owner: "ddns:wg-ddns".into(),
                    hostname: "wg.example.test".into(),
                    public_endpoint: String::new(),
                    binding_mode: "fixed-port".into(),
                    port: 51820,
                    ..WireGuardEndpointProfile::default()
                },
                WireGuardEndpointProfile {
                    id: "wg-stun".into(),
                    endpoint_source: "stun".into(),
                    owner: "stun:stun-wireguard".into(),
                    hostname: String::new(),
                    public_endpoint: "203.0.113.8:24567".into(),
                    stun_rule_id: "stun-wireguard".into(),
                    binding_mode: "router-native".into(),
                    forward_mode: "router_native".into(),
                    transport_protocol: "UDP".into(),
                    local_target_port: 51820,
                    port: 24567,
                    ..WireGuardEndpointProfile::default()
                },
            ],
        };
        validate_server_desired(&desired).unwrap();
        assert_eq!(desired.endpoint_profiles[0].endpoint_source, "ddns");
        assert_eq!(desired.endpoint_profiles[1].endpoint_source, "stun");
    }

    #[test]
    fn server_contract_rejects_mixed_stun_ddns_profile() {
        let desired = WireGuardServerDesired {
            interface_name: "labwg0".into(),
            address: "10.77.0.1/24".into(),
            listen_port: 51820,
            enabled: true,
            revision: 1,
            peers: Vec::new(),
            endpoint_profiles: vec![WireGuardEndpointProfile {
                id: "bad".into(),
                endpoint_source: "stun".into(),
                owner: "stun:stun-wireguard".into(),
                hostname: "wg.example.test".into(),
                public_endpoint: "203.0.113.8:24567".into(),
                stun_rule_id: "stun-wireguard".into(),
                binding_mode: "router-native".into(),
                forward_mode: "router_native".into(),
                transport_protocol: "UDP".into(),
                local_target_port: 51820,
                ..WireGuardEndpointProfile::default()
            }],
        };
        assert!(validate_server_desired(&desired).is_err());
    }

    #[test]
    fn automatic_endpoint_updates_are_owned_versioned_and_idempotent() {
        let mut profiles = vec![WireGuardEndpointProfile {
            id: "wg-ddns".into(),
            endpoint_source: "ddns".into(),
            owner: "ddns:wg-ddns".into(),
            hostname: "wg.example.test".into(),
            binding_mode: "fixed-port".into(),
            port: 51820,
            ..WireGuardEndpointProfile::default()
        }];
        let update = WireGuardEndpointUpdate {
            profile_id: "wg-ddns".into(),
            endpoint_source: "ddns".into(),
            owner: "ddns:wg-ddns".into(),
            endpoint: "wg.example.test:51820".into(),
            expected_endpoint_revision: 0,
            endpoint_revision: 1,
        };
        let first = apply_endpoint_update(&mut profiles, &update).unwrap();
        assert_eq!(first.endpoint_revision, 1);
        assert_eq!(first.resolved_endpoint, "wg.example.test:51820");
        let repeated = apply_endpoint_update(&mut profiles, &update).unwrap();
        assert_eq!(repeated, first);

        let mut wrong_owner = update.clone();
        wrong_owner.expected_endpoint_revision = 1;
        wrong_owner.endpoint_revision = 2;
        wrong_owner.owner = "ddns:someone-else".into();
        assert!(apply_endpoint_update(&mut profiles, &wrong_owner).is_err());
    }

    #[test]
    fn manual_endpoint_rejects_automatic_updates() {
        let mut profiles = vec![WireGuardEndpointProfile {
            id: "office".into(),
            endpoint_source: "manual".into(),
            binding_mode: "manual".into(),
            resolved_endpoint: "198.51.100.20:51820".into(),
            port: 51820,
            ..WireGuardEndpointProfile::default()
        }];
        let update = WireGuardEndpointUpdate {
            profile_id: "office".into(),
            endpoint_source: "ddns".into(),
            owner: "ddns:office".into(),
            endpoint: "other.example.test:51820".into(),
            expected_endpoint_revision: 0,
            endpoint_revision: 1,
        };
        assert!(apply_endpoint_update(&mut profiles, &update).is_err());
        assert_eq!(profiles[0].resolved_endpoint, "198.51.100.20:51820");
    }

    #[test]
    fn parses_wg0_without_peers() {
        let dump = interface_line("wg0", PK_A, 51820);
        let interfaces = parse_wg_dump(&dump);
        assert_eq!(interfaces.len(), 1);
        let item = &interfaces[0];
        assert_eq!(item.name, "wg0");
        assert_eq!(item.public_key, PK_A);
        assert_eq!(item.listen_port, Some(51820));
        assert_eq!(item.peer_count, 0);
        assert_eq!(item.rx_bytes, 0);
        assert_eq!(item.tx_bytes, 0);
        assert_eq!(item.latest_handshake_at, None);
    }

    #[test]
    fn parses_wg0_with_two_peers() {
        let dump = format!(
            "{}\n{}\n{}",
            interface_line("wg0", PK_A, 51820),
            peer_line("wg0", PK_B, 1786100000, 1000, 2000),
            peer_line("wg0", PK_A, 1786100100, 3000, 4000),
        );
        let interfaces = parse_wg_dump(&dump);
        assert_eq!(interfaces.len(), 1);
        let item = &interfaces[0];
        assert_eq!(item.peer_count, 2);
        assert_eq!(item.rx_bytes, 4000);
        assert_eq!(item.tx_bytes, 6000);
        assert_eq!(item.latest_handshake_at, Some(1786100100));
        assert_eq!(total_peer_count(&interfaces), 2);
        assert_eq!(latest_handshake(&interfaces), Some(1786100100));
    }

    #[test]
    fn handshake_zero_is_not_valid() {
        let dump = format!(
            "{}\n{}",
            interface_line("wg0", PK_A, 51820),
            peer_line("wg0", PK_B, 0, 100, 200),
        );
        let interfaces = parse_wg_dump(&dump);
        assert_eq!(interfaces[0].peer_count, 1);
        assert_eq!(interfaces[0].rx_bytes, 100);
        assert_eq!(interfaces[0].tx_bytes, 200);
        assert_eq!(interfaces[0].latest_handshake_at, None);
        assert_eq!(latest_handshake(&interfaces), None);
    }

    #[test]
    fn empty_dump_is_empty_not_panic() {
        assert!(parse_wg_dump("").is_empty());
        assert!(parse_wg_dump(" \n\t\n").is_empty());
    }

    #[test]
    fn malformed_dump_never_panics() {
        let dump = [
            "wg0\tonly-two",
            "garbage without tabs",
            "wg0\tPUB\tpub\t51820",
            "\t\t\t\t\t",
            "wg0\tpriv\tpub\t51820\toff\toops",
            "wg1\tpriv\tpub\tnan\toff",
            "wg0\tpeer\t(0)\tendpoint\t10.0.0.0/8\tnot-a-number\t1\t2\toff",
            "wg1\tpeer\t(0)\tendpoint\t10.0.0.0/8\t123\t1\t2\toff",
        ]
        .join("\n");
        let interfaces = parse_wg_dump(&dump);
        assert!(interfaces.len() <= 2);
        assert!(interfaces.is_empty() || total_peer_count(&interfaces) > 0);
    }

    #[test]
    fn never_exposes_private_key() {
        let private = "PRIVATE-KEY-SHOULD-NEVER-LEAK";
        let preshared = "PRESHARED-KEY-SHOULD-NEVER-LEAK";
        let dump = format!(
            "{}\n{}",
            interface_line("wg0", PK_A, 51820),
            format!(
                "wg0\tPK_B\t{preshared}\t192.0.2.1:51820\t10.88.0.0/24\t1786100000\t1\t2\toff"
            ),
        );
        let interfaces = parse_wg_dump(&dump);
        let serialized = serde_json::to_value(&interfaces).unwrap();
        assert!(!serialized.to_string().contains(private));
        assert!(!serialized.to_string().contains(preshared));
        assert!(dump.contains(private));
        let status = serde_json::to_value(WireGuardStatus::empty_with(true)).unwrap();
        assert!(!status.to_string().contains(private));
        assert!(!status.to_string().contains(preshared));
    }

    #[test]
    fn error_object_never_contains_key_material() {
        let private = "THIS_IS_FAKE_PRIVATE_SECRET_123";
        let preshared = "THIS_IS_FAKE_PRESHARED_SECRET_456";
        let mut status = WireGuardStatus::empty_with(true);
        status.apply_errors(&[
            format!("wg show all dump failed: privateKey {private}"),
            format!("peers leaked presharedKey {preshared}"),
        ]);
        let serialized = serde_json::to_value(&status).unwrap();
        let text = serialized.to_string();
        assert!(!text.contains(private));
        assert!(!text.contains(preshared));
        let error = status.error.as_deref().unwrap_or("");
        assert!(!error.contains(private));
        assert!(!error.contains(preshared));
        assert!(error.contains("[REDACTED]"));
    }

    #[test]
    fn fake_secret_values_never_survive_serialization() {
        let fake_private = "THIS_IS_FAKE_PRIVATE_SECRET_123";
        let fake_preshared = "THIS_IS_FAKE_PRESHARED_SECRET_456";

        // Values embedded in error messages without any field-name prefix.
        let mut status = WireGuardStatus::empty_with(true);
        status.apply_errors(&[
            format!("wg show all dump failed: {fake_private}"),
            format!("peer handshake error {fake_preshared}"),
        ]);
        let serialized = serde_json::to_value(&status).unwrap();
        let status_text = serialized.to_string();
        assert!(!status_text.contains(fake_private));
        assert!(!status_text.contains(fake_preshared));

        // The "log output string" form (what log_line would receive) must be
        // equally clean.
        let log_string = sanitize_sensitive(&format!(
            "wireguard detection failed: privateKey={fake_private} presharedKey={fake_preshared}"
        ));
        assert!(!log_string.contains(fake_private));
        assert!(!log_string.contains(fake_preshared));
        assert!(!log_string.contains("privateKey"));
        assert!(!log_string.contains("presharedKey"));
        assert!(log_string.contains("[REDACTED]"));

        // A realistic base64-shaped WireGuard key must also be removed.
        let base64_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        let scrubbed = sanitize_sensitive(&format!("wg failed: {base64_key}"));
        assert!(!scrubbed.contains(base64_key));
        assert!(scrubbed.contains("[REDACTED]"));
    }

    #[test]
    fn configured_true_with_manual_wg_interface_without_uci() {
        // A manually created wg0 (no UCI config) must still be configured and
        // running per its link UP flag.
        let dump = interface_line("wg0", PK_A, 51820);
        let mut interfaces = parse_wg_dump(&dump);
        interfaces[0].running = parse_link_up(&link_line(
            "POINTOPOINT,NOARP,UP,LOWER_UP",
            "UNKNOWN",
        ));
        let status = WireGuardStatus {
            supported: true,
            wg_tool_available: true,
            kernel_supported: true,
            control_tool_available: true,
            provisioning_ready: true,
            control_backend: "kernel-netlink".into(),
            kernel_support: true,
            installed: true,
            configured: !interfaces.is_empty(),
            running: interfaces.iter().any(|item| item.running),
            interface_count: interfaces.len() as u32,
            interfaces,
            peer_count: 0,
            latest_handshake_at: None,
            error: None,
        };
        assert!(status.configured);
        assert!(status.running);
    }

    #[test]
    fn parses_interface_addresses() {
        let raw = "\
2: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 10.88.0.1/24 scope global wg0
    inet6 fd88::1/64 scope global
    inet6 fe80::1/64 scope link";
        let addresses = parse_ip_addresses(raw);
        assert_eq!(addresses, vec!["10.88.0.1/24", "fd88::1/64"]);
    }

    #[test]
    fn interface_down_means_configured_but_not_running() {
        let dump = interface_line("wg0", PK_A, 51820);
        let mut interfaces = parse_wg_dump(&dump);
        interfaces[0].running = parse_link_up(&link_line("POINTOPOINT,NOARP,LOWER_UP", "DOWN"));
        assert!(!interfaces[0].running);
        assert!(!interfaces.is_empty());
        // configured comes from UCI or a discovered interface; running stays
        // false while the link is down.
        let status = WireGuardStatus {
            supported: true,
            wg_tool_available: true,
            kernel_supported: true,
            control_tool_available: true,
            provisioning_ready: true,
            control_backend: "kernel-netlink".into(),
            kernel_support: true,
            installed: true,
            configured: true,
            running: interfaces.iter().any(|item| item.running),
            interface_count: interfaces.len() as u32,
            interfaces,
            peer_count: 0,
            latest_handshake_at: None,
            error: None,
        };
        assert!(status.configured);
        assert!(!status.running);
    }

    #[test]
    fn interface_up_means_running_even_with_state_unknown() {
        let dump = interface_line("wg0", PK_A, 51820);
        let mut interfaces = parse_wg_dump(&dump);
        interfaces[0].running = parse_link_up(&link_line(
            "POINTOPOINT,NOARP,UP,LOWER_UP",
            "UNKNOWN",
        ));
        assert!(interfaces[0].running);
        let status = WireGuardStatus {
            supported: true,
            wg_tool_available: true,
            kernel_supported: true,
            control_tool_available: true,
            provisioning_ready: true,
            control_backend: "kernel-netlink".into(),
            kernel_support: true,
            installed: true,
            configured: true,
            running: interfaces.iter().any(|item| item.running),
            interface_count: interfaces.len() as u32,
            interfaces,
            peer_count: 0,
            latest_handshake_at: None,
            error: None,
        };
        assert!(status.running);
    }

    #[test]
    fn uci_wireguard_substring_is_not_a_false_positive() {
        let raw = "\
network.loopback=interface
network.loopback.proto='static'
network.wan=interface
network.wan.proto='dhcp'
network.vpn_note='uses wireguard server at example.com'
network.peer_wireguard_name='tunnel-x'
";
        assert!(!parse_uci_wireguard_configured(raw));
    }

    #[test]
    fn uci_proto_wireguard_detected() {
        let raw = "\
network.loopback=interface
network.loopback.proto='static'
network.wg0=interface
network.wg0.proto='wireguard'
network.wg0.private_key='REDACTED-BY-TOOL'
";
        assert!(parse_uci_wireguard_configured(raw));
    }

    #[test]
    fn old_status_json_without_wireguard_still_parses() {
        // Old payloads simply have no wireguard key; the hub treats the field
        // as absent, so parsing it as a generic JSON object must not fail.
        let old = serde_json::json!({
            "router": "BE72",
            "telemetry": {"cpuPercent": 5},
            "details": {"wan": {"ipv4": "10.0.0.2"}}
        });
        assert!(old.get("wireguard").is_none());
        let roundtrip = serde_json::from_value::<serde_json::Value>(old).unwrap();
        assert!(roundtrip.get("wireguard").is_none());
    }
}
