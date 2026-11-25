//! Read-only OpenWrt WAN discovery and explicit source/device socket binding.
//!
//! This module deliberately does not change routes, policy rules, firewall
//! state, or mwan3 state. A route table recorded in a binding is informational:
//! sockets are constrained only by their source address and, on Linux, by
//! `SO_BINDTODEVICE`.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use socket2::SockRef;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsRawFd;
use std::process::Command;
use std::str::FromStr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

const DISCOVERY_SOURCE: &str = "openwrt-uci-ip";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WanFamily {
    V4,
    V6,
}

impl WanFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }

    fn from_ip(ip: IpAddr) -> Self {
        if ip.is_ipv4() {
            Self::V4
        } else {
            Self::V6
        }
    }

    pub(crate) fn matches(self, ip: IpAddr) -> bool {
        WanFamily::from_ip(ip) == self
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WanVerification {
    Verified,
    Mismatch,
    #[default]
    Unknown,
}

impl WanVerification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Mismatch => "mismatch",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WanSnapshot {
    pub wans: Vec<WanLink>,
    pub default_wan_id_v4: Option<String>,
    pub default_wan_id_v6: Option<String>,
    pub observed_at: u64,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WanLink {
    pub wan_id: String,
    pub logical_interface: String,
    pub l3_device: String,
    pub kind: String,
    pub devices: Vec<String>,
    pub addresses: Vec<WanAddress>,
    pub gateways: Vec<IpAddr>,
    pub route_tables: Vec<u32>,
    pub mwan3_member: Option<String>,
    pub up: bool,
    pub default_v4: bool,
    pub default_v6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WanAddress {
    pub address: IpAddr,
    pub prefix_len: u8,
    pub scope: String,
    pub temporary: bool,
    pub deprecated: bool,
    pub tentative: bool,
    pub interface: String,
}

impl WanAddress {
    fn is_safe_source(&self, family: WanFamily) -> bool {
        let ip = self.address;
        if !family.matches(ip)
            || self.interface.trim().is_empty()
            || self.temporary
            || self.deprecated
            || self.tentative
            || self.scope.eq_ignore_ascii_case("link")
            || ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
        {
            return false;
        }
        match ip {
            IpAddr::V4(ip) => !ip.is_link_local() && ip != Ipv4Addr::BROADCAST,
            IpAddr::V6(ip) => {
                !ip.is_unicast_link_local()
                    && !is_ipv6_ula(ip)
                    && (ip.segments()[0] & 0xfe00) != 0xfec0
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WanBinding {
    pub wan_id: String,
    pub family: WanFamily,
    pub source_address: String,
    pub device: Option<String>,
    pub route_table: Option<u32>,
    pub verified: bool,
    pub verification: WanVerification,
}

impl WanBinding {
    fn set_verification(&mut self, verification: WanVerification) {
        self.verification = verification;
        self.verified = verification == WanVerification::Verified;
    }
}

#[derive(Debug, Clone)]
struct LogicalWan {
    section: String,
    proto: String,
    device: String,
    ifnames: Vec<String>,
}

#[derive(Debug, Clone)]
struct LinkInfo {
    index: u32,
    name: String,
    parent: Option<String>,
    master: Option<String>,
    flags: BTreeSet<String>,
    state: String,
}

impl LinkInfo {
    fn is_up(&self) -> bool {
        self.flags.contains("UP") || self.state.eq_ignore_ascii_case("UP")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteKind {
    Unicast,
    Blackhole,
    Unreachable,
    Prohibit,
    Throw,
    Local,
    Broadcast,
    Other,
}

impl RouteKind {
    fn is_egress(self) -> bool {
        matches!(self, Self::Unicast)
    }
}

#[derive(Debug, Clone)]
struct RouteInfo {
    is_default: bool,
    kind: RouteKind,
    via: Option<IpAddr>,
    device: Option<String>,
    table: u32,
    metric: u32,
}

#[derive(Debug, Clone)]
struct IpPrefix {
    prefix_len: u8,
}

#[derive(Debug, Clone)]
struct RuleInfo {
    priority: u32,
    table: Option<u32>,
    from: Option<IpPrefix>,
    to: Option<IpPrefix>,
    from_inverted: bool,
    to_inverted: bool,
    iif: Option<String>,
    oif: Option<String>,
    fwmark: Option<String>,
    suppress_prefix_length: Option<u8>,
    has_other_selector: bool,
}

impl RuleInfo {
    fn applies_to_default(&self) -> bool {
        self.table.is_some()
            && self
                .from
                .as_ref()
                .is_none_or(|prefix| prefix.prefix_len == 0)
            && self.to.as_ref().is_none_or(|prefix| prefix.prefix_len == 0)
            && !self.from_inverted
            && !self.to_inverted
            && self.iif.is_none()
            && self.oif.is_none()
            && self.fwmark.is_none()
            && !self.has_other_selector
            && self.suppress_prefix_length != Some(0)
    }
}

#[derive(Debug, Clone)]
struct Mwan3Section {
    kind: String,
    name: String,
    options: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct Mwan3Config {
    sections: Vec<Mwan3Section>,
}

#[derive(Debug)]
struct DiscoveryOutputs {
    network_uci: String,
    links: String,
    addresses_v4: String,
    addresses_v6: String,
    routes_v4: String,
    routes_v6: String,
    rules_v4: String,
    rules_v6: String,
    mwan3_uci: String,
    mwan3_file: String,
}

#[derive(Debug, Clone)]
struct RouteGet {
    source: IpAddr,
    device: String,
}

/// Discover logical WANs using only read-only OpenWrt commands and files.
pub fn discover_snapshot() -> Result<WanSnapshot> {
    let network_uci = run_readonly("uci", &["-q", "show", "network"])
        .context("read logical WANs from uci network")?;
    let links = run_ip(&["-o", "link"]).context("read links")?;
    let addresses_v4 = run_ip(&["-o", "-4", "addr"]).context("read IPv4 addresses")?;
    let addresses_v6 = run_ip(&["-o", "-6", "addr"]).context("read IPv6 addresses")?;
    let routes_v4 = run_ip(&["-4", "route", "show", "table", "all"]).context("read IPv4 routes")?;
    let routes_v6 = run_ip(&["-6", "route", "show", "table", "all"]).context("read IPv6 routes")?;
    let rules_v4 = run_ip(&["-4", "rule", "show"]).context("read IPv4 policy rules")?;
    let rules_v6 = run_ip(&["-6", "rule", "show"]).context("read IPv6 policy rules")?;

    let mwan3_uci = run_optional_readonly("uci", &["-q", "show", "mwan3"])
        .unwrap_or_default()
        .unwrap_or_default();
    let mwan3_file = if parse_mwan3_uci(&mwan3_uci).sections.is_empty() {
        fs::read_to_string("/etc/config/mwan3").unwrap_or_default()
    } else {
        String::new()
    };
    let source = if !mwan3_file.trim().is_empty() && parse_mwan3_uci(&mwan3_uci).sections.is_empty()
    {
        format!("{DISCOVERY_SOURCE}+mwan3-file")
    } else {
        DISCOVERY_SOURCE.to_string()
    };

    build_snapshot(
        DiscoveryOutputs {
            network_uci,
            links,
            addresses_v4,
            addresses_v6,
            routes_v4,
            routes_v6,
            rules_v4,
            rules_v6,
            mwan3_uci,
            mwan3_file,
        },
        now_epoch(),
        source,
    )
}

// Shared within each process; concurrent STUN rules and passive telemetry
// must not each fork a complete set of UCI/ip discovery commands.
static WAN_DISCOVERY_CACHE: tokio::sync::Mutex<Option<(Instant, Result<WanSnapshot, String>)>> =
    tokio::sync::Mutex::const_new(None);

pub async fn discover_snapshot_cached_async(max_age: Duration) -> Result<WanSnapshot> {
    let mut cache = WAN_DISCOVERY_CACHE.lock().await;
    if let Some((observed, value)) = cache.as_ref() {
        let ttl = if value.is_ok() { max_age } else { max_age.min(Duration::from_secs(15)) };
        if observed.elapsed() < ttl {
            return value.clone().map_err(anyhow::Error::msg);
        }
    }
    let result = discover_snapshot_async().await.map_err(|error| format!("{error:#}"));
    *cache = Some((Instant::now(), result.clone()));
    result.map_err(anyhow::Error::msg)
}

/// Fresh, read-only discovery for explicit operations such as a new TCP test.
pub async fn discover_snapshot_async() -> Result<WanSnapshot> {
    tokio::task::spawn_blocking(discover_snapshot)
        .await
        .context("join WAN discovery task")?
}

/// Resolve an explicit WAN, or the unambiguous default for the family when
/// `wan_id` is omitted/blank. Resolution never performs network I/O.
pub fn resolve_binding(
    snapshot: &WanSnapshot,
    wan_id: &str,
    family: WanFamily,
) -> Result<WanBinding> {
    let requested = wan_id.trim();
    let (wan, using_default) = if requested.is_empty() {
        let default_id = match family {
            WanFamily::V4 => snapshot.default_wan_id_v4.as_deref(),
            WanFamily::V6 => snapshot.default_wan_id_v6.as_deref(),
        }
        .ok_or_else(|| anyhow::anyhow!("no unambiguous default WAN for {}", family.as_str()))?;
        let wan = snapshot
            .wans
            .iter()
            .find(|wan| wan.wan_id.eq_ignore_ascii_case(default_id))
            .ok_or_else(|| anyhow::anyhow!("default WAN {default_id} is unknown"))?;
        (wan, true)
    } else {
        let wan = snapshot
            .wans
            .iter()
            .find(|wan| wan.wan_id.eq_ignore_ascii_case(requested))
            .ok_or_else(|| anyhow::anyhow!("unknown WAN {requested}"))?;
        (wan, false)
    };

    if !wan.up {
        bail!("WAN {} is offline", wan.wan_id);
    }
    if using_default {
        let is_default = match family {
            WanFamily::V4 => wan.default_v4,
            WanFamily::V6 => wan.default_v6,
        };
        if !is_default {
            bail!(
                "WAN {} is not the default for {}",
                wan.wan_id,
                family.as_str()
            );
        }
    }

    let device = (!wan.l3_device.trim().is_empty()).then(|| wan.l3_device.clone());
    let mut candidates: Vec<&WanAddress> = wan
        .addresses
        .iter()
        .filter(|address| address.is_safe_source(family))
        .filter(|address| {
            device.as_deref().is_none_or(|l3| {
                address.interface == l3
                    || address
                        .interface
                        .eq_ignore_ascii_case(&wan.logical_interface)
                    || address.interface.eq_ignore_ascii_case(&wan.wan_id)
            })
        })
        .collect();
    candidates.sort_by(|left, right| {
        left.address
            .to_string()
            .cmp(&right.address.to_string())
            .then_with(|| left.interface.cmp(&right.interface))
            .then_with(|| left.prefix_len.cmp(&right.prefix_len))
    });
    candidates.dedup_by(|left, right| {
        left.address == right.address
            && left.interface == right.interface
            && left.prefix_len == right.prefix_len
    });

    let source = match candidates.as_slice() {
        [] => bail!(
            "WAN {} has no usable {} source address",
            wan.wan_id,
            family.as_str()
        ),
        [address] => address.address,
        _ => bail!(
            "WAN {} has ambiguous {} source addresses; select one explicitly",
            wan.wan_id,
            family.as_str()
        ),
    };

    Ok(WanBinding {
        wan_id: wan.wan_id.clone(),
        family,
        source_address: source.to_string(),
        device,
        route_table: (wan.route_tables.len() == 1).then_some(wan.route_tables[0]),
        verified: false,
        verification: WanVerification::Unknown,
    })
}

/// Prepare a TCP socket on the selected source/device and fixed local port.
/// Port reuse lets Relay keep a wildcard inbound listener and a STUN channel
/// socket on the same port without changing routes, rules, firewall, or marks.
pub fn prepare_tcp_bound(binding: &WanBinding, local_port: u16) -> Result<TcpSocket> {
    let local = socket_bind_address_with_port(binding, binding.family, local_port)?;
    let bind_device = validated_bind_device(binding)?.map(str::to_string);
    let socket = match binding.family {
        WanFamily::V4 => TcpSocket::new_v4(),
        WanFamily::V6 => TcpSocket::new_v6(),
    }
    .context("create WAN TCP socket")?;
    socket
        .set_reuseaddr(true)
        .context("set WAN TCP SO_REUSEADDR")?;
    #[cfg(unix)]
    SockRef::from(&socket)
        .set_reuse_port(true)
        .context("set WAN TCP SO_REUSEPORT")?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    set_so_bind_to_device(socket.as_raw_fd(), bind_device.as_deref())?;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    reject_unsupported_device_binding(bind_device.as_deref())?;
    socket
        .bind(local)
        .with_context(|| format!("bind WAN TCP source {local}"))?;
    Ok(socket)
}

/// Connect a prepared WAN TCP socket. A route mismatch is fatal. Route
/// query/parse failures leave the binding `unknown` and return the connected
/// socket without claiming verified egress.
pub async fn connect_prepared_tcp_bound(
    socket: TcpSocket,
    peer: SocketAddr,
    binding: &mut WanBinding,
) -> Result<TcpStream> {
    let _ = socket_bind_address_with_port(binding, binding.family, 0)?;
    if !binding.family.matches(peer.ip()) {
        bail!("WAN binding and TCP peer address families differ");
    }
    if peer.ip().is_unspecified() {
        bail!("WAN peer address cannot be unspecified");
    }
    binding.set_verification(WanVerification::Unknown);
    let stream = timeout(CONNECT_TIMEOUT, socket.connect(peer))
        .await
        .context("WAN TCP connect timed out")?
        .with_context(|| format!("connect WAN TCP peer {peer}"))?;
    let connected_local = stream.local_addr().ok();
    let verification = query_and_evaluate_egress(binding, peer, connected_local).await;
    require_non_mismatch(binding, peer, verification)?;
    Ok(stream)
}

/// Connect TCP after binding the selected source address and device.
pub async fn connect_tcp_bound(peer: SocketAddr, binding: &mut WanBinding) -> Result<TcpStream> {
    connect_tcp_bound_with_local_port(peer, binding, 0).await
}

/// Connect TCP on a fixed local channel port using the selected WAN source and
/// device. Route-query failures remain `unknown`; callers that require a
/// verified egress must also call [`require_verified_binding`].
pub async fn connect_tcp_bound_with_local_port(
    peer: SocketAddr,
    binding: &mut WanBinding,
    local_port: u16,
) -> Result<TcpStream> {
    let socket = prepare_tcp_bound(binding, local_port)?;
    connect_prepared_tcp_bound(socket, peer, binding).await
}

/// Re-run connected route verification for an existing TCP keepalive socket.
/// This is intentionally read-only and never installs a route or policy mark.
pub async fn verify_connected_tcp_egress(
    peer: SocketAddr,
    binding: &mut WanBinding,
    stream: &TcpStream,
) -> Result<()> {
    let connected_local = stream.local_addr().ok();
    let verification = query_and_evaluate_egress(binding, peer, connected_local).await;
    require_non_mismatch(binding, peer, verification)?;
    require_verified_binding(binding, peer)
}

/// Bind an unconnected UDP socket to the selected WAN source/device and fixed
/// local port. Relay uses this for its shared STUN/visitor channel socket.
pub fn bind_udp_bound(binding: &WanBinding, local_port: u16) -> Result<UdpSocket> {
    let local = socket_bind_address_with_port(binding, binding.family, local_port)?;
    let bind_device = validated_bind_device(binding)?.map(str::to_string);
    let domain = if binding.family == WanFamily::V4 {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket =
        Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create WAN UDP socket")?;
    socket
        .set_reuse_address(true)
        .context("set WAN UDP SO_REUSEADDR")?;
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .context("set WAN UDP SO_REUSEPORT")?;
    if binding.family == WanFamily::V6 {
        socket
            .set_only_v6(true)
            .context("make WAN UDP socket IPv6-only")?;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    set_so_bind_to_device(socket.as_raw_fd(), bind_device.as_deref())?;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    reject_unsupported_device_binding(bind_device.as_deref())?;
    socket
        .bind(&local.into())
        .with_context(|| format!("bind WAN UDP source {local}"))?;
    socket
        .set_nonblocking(true)
        .context("make WAN UDP socket nonblocking")?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("create Tokio WAN UDP socket")
}

/// Connect UDP after binding the selected source address and device. The
/// returned UDP socket is connected to `peer`; callers must still inspect
/// `binding.verification` because route-query failures are reported as unknown.
pub async fn connect_udp_bound(peer: SocketAddr, binding: &mut WanBinding) -> Result<UdpSocket> {
    let local = socket_bind_address(binding, peer)?;
    let bind_device = validated_bind_device(binding)?.map(str::to_string);
    binding.set_verification(WanVerification::Unknown);

    let domain = if peer.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket =
        Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create WAN UDP socket")?;
    if peer.is_ipv6() {
        socket
            .set_only_v6(true)
            .context("make WAN UDP socket IPv6-only")?;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    set_so_bind_to_device(socket.as_raw_fd(), bind_device.as_deref())?;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    reject_unsupported_device_binding(bind_device.as_deref())?;
    socket
        .bind(&local.into())
        .with_context(|| format!("bind WAN UDP source {local}"))?;
    socket
        .set_nonblocking(true)
        .context("make WAN UDP socket nonblocking")?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket).context("create Tokio WAN UDP socket")?;
    socket
        .connect(peer)
        .await
        .with_context(|| format!("connect WAN UDP peer {peer}"))?;
    let connected_local = socket.local_addr().ok();
    let verification = query_and_evaluate_egress(binding, peer, connected_local).await;
    require_non_mismatch(binding, peer, verification)?;
    Ok(socket)
}

/// Verify UDP egress with a short-lived connected socket bound to the same WAN
/// source/device as the fixed-port shared STUN socket. No UDP packet is sent.
pub async fn verify_udp_egress(peer: SocketAddr, binding: &mut WanBinding) -> Result<()> {
    let _socket = connect_udp_bound(peer, binding).await?;
    require_verified_binding(binding, peer)
}

/// Verify the kernel route for an already-resolved destination IP using the
/// selected WAN source. This is read-only: it only runs `ip route get` and
/// never installs routes, rules, firewall state, or mwan3 marks.
///
/// Callers must use the returned status as a gate. `Unknown` includes command,
/// parse, and address-family failures; only `Verified` proves both source and
/// device match the selected binding.
pub async fn verify_route_get(binding: &mut WanBinding, target: IpAddr) -> WanVerification {
    binding.set_verification(WanVerification::Unknown);
    if !binding.family.matches(target) || target.is_unspecified() {
        return WanVerification::Unknown;
    }
    let source = match IpAddr::from_str(binding.source_address.trim()) {
        Ok(source) if binding.family.matches(source) => source,
        _ => return WanVerification::Unknown,
    };
    let family = if target.is_ipv4() { "-4" } else { "-6" };
    let route_target = target.to_string();
    let source = source.to_string();
    let output = tokio::task::spawn_blocking(move || {
        run_ip(&[
            family,
            "route",
            "get",
            route_target.as_str(),
            "from",
            source.as_str(),
        ])
    })
    .await;
    let verification = match output {
        Ok(Ok(output)) => evaluate_route_get(binding, target, &output),
        _ => WanVerification::Unknown,
    };
    binding.set_verification(verification);
    verification
}

/// Require successful connected route verification before a WAN-bound STUN
/// mapping may be reported.
pub fn require_verified_binding(binding: &WanBinding, peer: SocketAddr) -> Result<()> {
    if binding.verification != WanVerification::Verified || !binding.verified {
        bail!(
            "WAN {} egress verification {} for {peer} (source {}, device {:?})",
            binding.wan_id,
            binding.verification.as_str(),
            binding.source_address,
            binding.device
        );
    }
    Ok(())
}

/// Pure validation/planning helper shared by both socket paths. The returned
/// address contains the selected source and requested local port (zero for an
/// ephemeral port); no route table or mark is applied.
fn socket_bind_address(binding: &WanBinding, peer: SocketAddr) -> Result<SocketAddr> {
    if !binding.family.matches(peer.ip()) {
        bail!("WAN binding and peer address families differ");
    }
    if peer.ip().is_unspecified() {
        bail!("WAN peer address cannot be unspecified");
    }
    socket_bind_address_with_port(binding, binding.family, 0)
}

pub(crate) fn socket_bind_address_with_port(
    binding: &WanBinding,
    family: WanFamily,
    local_port: u16,
) -> Result<SocketAddr> {
    if binding.wan_id.trim().is_empty() {
        bail!("WAN binding has no logical WAN id");
    }
    let source = IpAddr::from_str(binding.source_address.trim())
        .context("WAN binding source address is invalid")?;
    if !binding.family.matches(source) || !family.matches(source) {
        bail!("WAN binding, source, and requested address families differ");
    }
    if source.is_unspecified()
        || source.is_loopback()
        || source.is_multicast()
        || match source {
            IpAddr::V4(ip) => ip.is_link_local() || ip == Ipv4Addr::BROADCAST,
            IpAddr::V6(ip) => {
                ip.is_unicast_link_local()
                    || is_ipv6_ula(ip)
                    || (ip.segments()[0] & 0xfe00) == 0xfec0
            }
        }
    {
        bail!("WAN binding source address is not safe for egress");
    }
    validated_bind_device(binding)?;
    Ok(SocketAddr::new(source, local_port))
}

fn validated_bind_device(binding: &WanBinding) -> Result<Option<&str>> {
    match binding.device.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(device) if device.contains('\0') => bail!("WAN device contains a NUL byte"),
        Some(device) => Ok(Some(device)),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_so_bind_to_device(fd: std::os::fd::RawFd, device: Option<&str>) -> Result<()> {
    let Some(device) = device else {
        return Ok(());
    };
    let mut name = device.as_bytes().to_vec();
    name.push(0);
    // SAFETY: `name` remains alive for the synchronous setsockopt call and the
    // pointer/length describe exactly its NUL-terminated bytes.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.len() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("set SO_BINDTODEVICE to {device}"));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn reject_unsupported_device_binding(device: Option<&str>) -> Result<()> {
    if device.is_some() {
        bail!("SO_BINDTODEVICE is only supported on Linux/Android");
    }
    Ok(())
}

async fn query_and_evaluate_egress(
    binding: &mut WanBinding,
    peer: SocketAddr,
    connected_local: Option<SocketAddr>,
) -> WanVerification {
    let Some(connected_local) = connected_local else {
        binding.set_verification(WanVerification::Unknown);
        return WanVerification::Unknown;
    };
    let family = if peer.is_ipv4() { "-4" } else { "-6" };
    let peer_ip = peer.ip().to_string();
    let source = binding.source_address.clone();
    let route = tokio::task::spawn_blocking(move || {
        run_ip(&[
            family,
            "route",
            "get",
            peer_ip.as_str(),
            "from",
            source.as_str(),
        ])
    })
    .await;
    let verification = match route {
        Ok(Ok(output)) => evaluate_egress(binding, peer, connected_local, &output),
        _ => WanVerification::Unknown,
    };
    binding.set_verification(verification);
    verification
}

fn require_non_mismatch(
    binding: &WanBinding,
    peer: SocketAddr,
    verification: WanVerification,
) -> Result<()> {
    if verification == WanVerification::Mismatch {
        bail!(
            "WAN {} actual egress mismatch for {peer} (source {}, device {:?})",
            binding.wan_id,
            binding.source_address,
            binding.device
        );
    }
    Ok(())
}

/// Evaluate `ip route get` output together with a connected socket's local
/// address. Parse failure is always `unknown`, never success.
fn evaluate_egress(
    binding: &mut WanBinding,
    peer: SocketAddr,
    connected_local: SocketAddr,
    route_get_output: &str,
) -> WanVerification {
    let verification = evaluate_route_get(binding, peer.ip(), route_get_output);
    if verification == WanVerification::Unknown {
        return WanVerification::Unknown;
    }
    let Ok(source) = IpAddr::from_str(binding.source_address.trim()) else {
        return WanVerification::Unknown;
    };
    if !binding.family.matches(peer.ip())
        || !binding.family.matches(connected_local.ip())
        || connected_local.ip() != source
    {
        return WanVerification::Mismatch;
    }
    verification
}

/// Evaluate route output for a resolved target without requiring a connected
/// socket. Parse failures are `unknown`; a different target, source, or device
/// is a `mismatch`. Neither result permits publication.
fn evaluate_route_get(
    binding: &WanBinding,
    target: IpAddr,
    route_get_output: &str,
) -> WanVerification {
    let Some(route) = parse_route_get(route_get_output, binding.family) else {
        return WanVerification::Unknown;
    };
    let Ok(source) = IpAddr::from_str(binding.source_address.trim()) else {
        return WanVerification::Unknown;
    };
    if !binding.family.matches(target) || !binding.family.matches(source) {
        return WanVerification::Unknown;
    }
    let Some(reported_target) = route_get_output
        .lines()
        .find_map(|line| line.split_whitespace().next())
        .and_then(|value| value.parse::<IpAddr>().ok())
    else {
        return WanVerification::Unknown;
    };
    if reported_target != target
        || route.source != source
        || binding
            .device
            .as_deref()
            .is_some_and(|expected_device| route.device != expected_device)
    {
        return WanVerification::Mismatch;
    }
    WanVerification::Verified
}

fn parse_route_get(output: &str, family: WanFamily) -> Option<RouteGet> {
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let line = lines.next()?;
    if lines.any(|line| line.trim() != "cache") {
        return None;
    }
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.is_empty()
        || fields
            .iter()
            .any(|field| matches!(*field, "unreachable" | "blackhole" | "prohibit" | "error"))
    {
        return None;
    }
    let mut source = None;
    let mut device = None;
    let mut index = 0usize;
    while index < fields.len() {
        match fields[index] {
            "from" | "src" => {
                let value = *fields.get(index + 1)?;
                let ip = IpAddr::from_str(value).ok()?;
                if !family.matches(ip) || source.is_some_and(|existing| existing != ip) {
                    return None;
                }
                source = Some(ip);
                index += 2;
            }
            "dev" => {
                let value = *fields.get(index + 1)?;
                if value.is_empty() || device.is_some() {
                    return None;
                }
                device = Some(normalize_link_name(value));
                index += 2;
            }
            _ => index += 1,
        }
    }
    Some(RouteGet {
        source: source?,
        device: device?,
    })
}

fn build_snapshot(
    outputs: DiscoveryOutputs,
    observed_at: u64,
    source: String,
) -> Result<WanSnapshot> {
    let logical_wans = parse_network_uci(&outputs.network_uci)?;
    if logical_wans.is_empty() {
        bail!("no logical WAN sections (wan/wan1/...) found in uci network");
    }
    let links = parse_links(&outputs.links);
    let link_map: BTreeMap<&str, &LinkInfo> = links
        .iter()
        .map(|link| (link.name.as_str(), link))
        .collect();
    let mut addresses = parse_addresses(&outputs.addresses_v4, WanFamily::V4);
    addresses.extend(parse_addresses(&outputs.addresses_v6, WanFamily::V6));
    let routes_v4 = parse_routes(&outputs.routes_v4, WanFamily::V4);
    let routes_v6 = parse_routes(&outputs.routes_v6, WanFamily::V6);
    let rules_v4 = parse_rules(&outputs.rules_v4, WanFamily::V4);
    let rules_v6 = parse_rules(&outputs.rules_v6, WanFamily::V6);
    let mwan3 = if parse_mwan3_uci(&outputs.mwan3_uci).sections.is_empty() {
        parse_mwan3_file(&outputs.mwan3_file)
    } else {
        parse_mwan3_uci(&outputs.mwan3_uci)
    };

    let mut wans = Vec::with_capacity(logical_wans.len());
    for (wan_id, logical) in logical_wans {
        let l3_device = resolve_l3_device(&wan_id, &logical, &link_map);
        let kind = resolve_kind(
            &logical,
            &l3_device,
            link_map.get(l3_device.as_str()).copied(),
        );
        let devices = resolve_physical_devices(&logical, &l3_device, &kind, &links, &link_map);
        let mut wan_addresses: Vec<WanAddress> = addresses
            .iter()
            .filter(|address| address_belongs_to_wan(address, &wan_id, &logical, &l3_device))
            .cloned()
            .collect();
        sort_addresses(&mut wan_addresses);

        let matching_routes_v4: Vec<&RouteInfo> = routes_v4
            .iter()
            .filter(|route| route_belongs_to_wan(route, &wan_id, &logical, &l3_device))
            .collect();
        let matching_routes_v6: Vec<&RouteInfo> = routes_v6
            .iter()
            .filter(|route| route_belongs_to_wan(route, &wan_id, &logical, &l3_device))
            .collect();
        let mut gateways: BTreeSet<String> = BTreeSet::new();
        let mut route_tables = BTreeSet::new();
        for route in matching_routes_v4.iter().chain(matching_routes_v6.iter()) {
            if route.kind.is_egress() {
                route_tables.insert(route.table);
                if route.is_default {
                    if let Some(via) = route.via {
                        gateways.insert(via.to_string());
                    }
                }
            }
        }

        wans.push(WanLink {
            wan_id,
            logical_interface: logical.section.clone(),
            l3_device: l3_device.clone(),
            kind,
            devices,
            addresses: wan_addresses,
            gateways: gateways
                .iter()
                .filter_map(|gateway| IpAddr::from_str(gateway).ok())
                .collect(),
            route_tables: route_tables.into_iter().collect(),
            mwan3_member: resolve_mwan3_member(&logical, &mwan3),
            up: link_map
                .get(l3_device.as_str())
                .is_some_and(|link| link.is_up()),
            default_v4: false,
            default_v6: false,
        });
    }
    wans.sort_by(|left, right| left.wan_id.cmp(&right.wan_id));

    let default_wan_id_v4 = choose_default_wan(&routes_v4, &rules_v4, &wans);
    let default_wan_id_v6 = choose_default_wan(&routes_v6, &rules_v6, &wans);
    for wan in &mut wans {
        wan.default_v4 = default_wan_id_v4.as_deref() == Some(wan.wan_id.as_str());
        wan.default_v6 = default_wan_id_v6.as_deref() == Some(wan.wan_id.as_str());
    }

    Ok(WanSnapshot {
        wans,
        default_wan_id_v4,
        default_wan_id_v6,
        observed_at,
        source,
    })
}

fn parse_network_uci(output: &str) -> Result<BTreeMap<String, LogicalWan>> {
    let entries: Vec<(&str, &str)> = output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.trim().strip_prefix("network.")?, value.trim()))
        })
        .collect();
    let mut wans = BTreeMap::new();
    // Declarations are collected first so parser stability does not depend on
    // whether a synthetic/reordered dump puts options before `=interface`.
    for (rest, value) in &entries {
        if rest.contains('.') {
            continue;
        }
        if unquote_uci(value).eq_ignore_ascii_case("interface") && is_wan_section(rest) {
            let wan_id = normalize_wan_id(rest);
            if wans
                .insert(
                    wan_id.clone(),
                    LogicalWan {
                        section: (*rest).to_string(),
                        proto: String::new(),
                        device: String::new(),
                        ifnames: Vec::new(),
                    },
                )
                .is_some()
            {
                bail!("duplicate normalized logical WAN section {wan_id}");
            }
        }
    }
    for (rest, value) in entries {
        let Some((section, option)) = rest.split_once('.') else {
            continue;
        };
        let Some(wan) = wans.get_mut(&normalize_wan_id(section)) else {
            continue;
        };
        let value = unquote_uci(value);
        match option {
            "proto" => wan.proto = value,
            "device" => wan.device = value,
            "ifname" => wan.ifnames = value.split_whitespace().map(str::to_string).collect(),
            _ => {}
        }
    }
    Ok(wans)
}

fn is_wan_section(section: &str) -> bool {
    let normalized = normalize_wan_id(section);
    normalized
        .strip_prefix("wan")
        .is_some_and(|suffix| suffix.is_empty() || suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

fn normalize_wan_id(section: &str) -> String {
    section.trim().to_ascii_lowercase()
}

fn unquote_uci(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2
        && ((value.starts_with('\'') && value.ends_with('\''))
            || (value.starts_with('"') && value.ends_with('"')))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn parse_links(output: &str) -> Vec<LinkInfo> {
    let mut links = Vec::new();
    let mut parent_refs = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let Ok(index) = fields[0].trim_end_matches(':').parse::<u32>() else {
            continue;
        };
        let raw_name = fields[1].trim_end_matches(':');
        let (name, parent_ref) = match raw_name.split_once('@') {
            Some((name, parent)) => (normalize_link_name(name), Some(parent.to_string())),
            None => (normalize_link_name(raw_name), None),
        };
        if name.is_empty() {
            continue;
        }
        let flags = fields[2]
            .trim_matches(['<', '>'])
            .split(',')
            .filter(|flag| !flag.is_empty())
            .map(|flag| flag.to_ascii_uppercase())
            .collect();
        let mut master = None;
        let mut state = String::new();
        let mut index_in_line = 3usize;
        while index_in_line < fields.len() {
            match fields[index_in_line] {
                "master" => {
                    master = fields
                        .get(index_in_line + 1)
                        .map(|value| normalize_link_name(value));
                    index_in_line += 2;
                }
                "state" => {
                    state = fields
                        .get(index_in_line + 1)
                        .copied()
                        .unwrap_or_default()
                        .to_ascii_uppercase();
                    index_in_line += 2;
                }
                _ => index_in_line += 1,
            }
        }
        links.push(LinkInfo {
            index,
            name,
            parent: None,
            master,
            flags,
            state,
        });
        parent_refs.push(parent_ref);
    }
    // Resolve peer indexes/names after all lines have been read, including
    // forward references that occur when input is reordered.
    let names: BTreeSet<&str> = links.iter().map(|link| link.name.as_str()).collect();
    let names_by_index: BTreeMap<u32, &str> = links
        .iter()
        .map(|link| (link.index, link.name.as_str()))
        .collect();
    let parent_names: Vec<Option<String>> = parent_refs
        .into_iter()
        .map(|parent| {
            parent.and_then(|parent| {
                if let Ok(index) = parent.parse::<u32>() {
                    names_by_index.get(&index).map(|name| (*name).to_string())
                } else if names.contains(parent.as_str()) {
                    Some(parent)
                } else {
                    None
                }
            })
        })
        .collect();
    for (link, parent) in links.iter_mut().zip(parent_names) {
        link.parent = parent;
    }
    links
}

fn normalize_link_name(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(':')
        .split('@')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn parse_addresses(output: &str, family: WanFamily) -> Vec<WanAddress> {
    let mut addresses = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let family_marker = match family {
            WanFamily::V4 => "inet",
            WanFamily::V6 => "inet6",
        };
        let Some(marker_index) = fields.iter().position(|field| *field == family_marker) else {
            continue;
        };
        let Some(cidr) = fields.get(marker_index + 1) else {
            continue;
        };
        let Some((address, prefix_len)) = cidr.split_once('/') else {
            continue;
        };
        let Ok(address) = IpAddr::from_str(address) else {
            continue;
        };
        let Ok(prefix_len) = prefix_len.parse::<u8>() else {
            continue;
        };
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if !family.matches(address) || prefix_len > maximum {
            continue;
        }
        let scope = fields
            .iter()
            .position(|field| *field == "scope")
            .and_then(|index| fields.get(index + 1))
            .copied()
            .unwrap_or("unknown")
            .to_string();
        addresses.push(WanAddress {
            address,
            prefix_len,
            scope,
            temporary: fields.iter().any(|field| *field == "temporary"),
            deprecated: fields.iter().any(|field| *field == "deprecated"),
            tentative: fields.iter().any(|field| *field == "tentative"),
            interface: normalize_link_name(fields[1]),
        });
    }
    addresses
}

fn sort_addresses(addresses: &mut Vec<WanAddress>) {
    addresses.sort_by(|left, right| {
        left.address
            .to_string()
            .cmp(&right.address.to_string())
            .then_with(|| left.interface.cmp(&right.interface))
            .then_with(|| left.prefix_len.cmp(&right.prefix_len))
            .then_with(|| left.temporary.cmp(&right.temporary))
            .then_with(|| left.deprecated.cmp(&right.deprecated))
            .then_with(|| left.tentative.cmp(&right.tentative))
    });
    addresses.dedup_by(|left, right| left == right);
}

fn parse_routes(output: &str, family: WanFamily) -> Vec<RouteInfo> {
    let mut routes = Vec::new();
    let mut base: Option<RouteInfo> = None;
    for line in output.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        let first = line.split_whitespace().next().unwrap_or_default();
        if first == "nexthop" {
            if let (Some(parent), Some(mut route)) = (base.as_ref(), parse_route_line(line, family))
            {
                route.is_default = parent.is_default;
                route.kind = parent.kind;
                route.table = parent.table;
                route.metric = parent.metric;
                routes.push(route);
            }
            continue;
        }
        if let Some(route) = base.take() {
            routes.push(route);
        }
        base = parse_route_line(line, family);
    }
    if let Some(route) = base {
        routes.push(route);
    }
    routes
}

fn parse_route_line(line: &str, family: WanFamily) -> Option<RouteInfo> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let first = *fields.first()?;
    let (kind, destination_index) = match first {
        "default" => (RouteKind::Unicast, 0),
        "unicast" => (RouteKind::Unicast, 1),
        "blackhole" => (RouteKind::Blackhole, 1),
        "unreachable" => (RouteKind::Unreachable, 1),
        "prohibit" => (RouteKind::Prohibit, 1),
        "throw" => (RouteKind::Throw, 1),
        "local" => (RouteKind::Local, 1),
        "broadcast" => (RouteKind::Broadcast, 1),
        "anycast" | "multicast" => (RouteKind::Other, 1),
        "nexthop" => (RouteKind::Unicast, 0),
        _ => (RouteKind::Unicast, 0),
    };
    let is_default = if first == "nexthop" {
        false
    } else {
        let destination = *fields.get(destination_index)?;
        destination == "default"
            || destination
                == match family {
                    WanFamily::V4 => "0.0.0.0/0",
                    WanFamily::V6 => "::/0",
                }
    };
    let mut via = None;
    let mut source = None;
    let mut device = None;
    let mut table = 254u32;
    let mut metric = 0u32;
    let mut explicit_table = false;
    let mut index = destination_index + if first == "nexthop" { 0 } else { 1 };
    while index < fields.len() {
        match fields[index] {
            "via" => {
                let ip = IpAddr::from_str(*fields.get(index + 1)?).ok()?;
                if !family.matches(ip) || via.is_some() {
                    return None;
                }
                via = Some(ip);
                index += 2;
            }
            "src" => {
                let ip = IpAddr::from_str(*fields.get(index + 1)?).ok()?;
                if !family.matches(ip) || source.is_some() {
                    return None;
                }
                source = Some(ip);
                index += 2;
            }
            "dev" => {
                let value = *fields.get(index + 1)?;
                if value.is_empty() || device.is_some() {
                    return None;
                }
                device = Some(normalize_link_name(value));
                index += 2;
            }
            "table" => {
                table = parse_table(*fields.get(index + 1)?)?;
                explicit_table = true;
                index += 2;
            }
            "metric" | "metrics" => {
                let value = *fields.get(index + 1)?;
                metric = value.parse::<u32>().ok()?;
                index += 2;
            }
            _ => index += 1,
        }
    }
    if explicit_table && table == 0 {
        // Table zero is valid on Linux; parse_table deliberately returns it.
    }
    Some(RouteInfo {
        is_default,
        kind,
        via,
        device,
        table,
        metric,
    })
}

fn parse_table(value: &str) -> Option<u32> {
    match value {
        "main" => Some(254),
        "local" => Some(255),
        "default" => Some(253),
        _ => value.parse::<u32>().ok(),
    }
}

fn parse_rules(output: &str, family: WanFamily) -> Vec<RuleInfo> {
    output
        .lines()
        .filter_map(|line| parse_rule_line(line, family))
        .collect()
}

fn parse_rule_line(line: &str, family: WanFamily) -> Option<RuleInfo> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 2 {
        return None;
    }
    let priority = fields[0]
        .strip_suffix(':')
        .and_then(|value| value.parse::<u32>().ok())?;
    let mut rule = RuleInfo {
        priority,
        table: None,
        from: None,
        to: None,
        from_inverted: false,
        to_inverted: false,
        iif: None,
        oif: None,
        fwmark: None,
        suppress_prefix_length: None,
        has_other_selector: false,
    };
    let mut index = 1usize;
    let mut invert_next_selector = false;
    while index < fields.len() {
        match fields[index] {
            "not" => {
                invert_next_selector = true;
                index += 1;
            }
            "from" => {
                let prefix = parse_ip_prefix(*fields.get(index + 1)?, family)?;
                rule.from_inverted = invert_next_selector;
                rule.from = Some(prefix);
                invert_next_selector = false;
                index += 2;
            }
            "to" => {
                let prefix = parse_ip_prefix(*fields.get(index + 1)?, family)?;
                rule.to_inverted = invert_next_selector;
                rule.to = Some(prefix);
                invert_next_selector = false;
                index += 2;
            }
            "lookup" => {
                rule.table = Some(parse_table(*fields.get(index + 1)?)?);
                invert_next_selector = false;
                index += 2;
            }
            "iif" => {
                rule.iif = Some((*fields.get(index + 1)?).to_string());
                invert_next_selector = false;
                index += 2;
            }
            "oif" => {
                rule.oif = Some((*fields.get(index + 1)?).to_string());
                invert_next_selector = false;
                index += 2;
            }
            "fwmark" => {
                rule.fwmark = Some((*fields.get(index + 1)?).to_string());
                invert_next_selector = false;
                index += 2;
            }
            "suppress_prefixlength" => {
                rule.suppress_prefix_length = Some(fields.get(index + 1)?.parse::<u8>().ok()?);
                invert_next_selector = false;
                index += 2;
            }
            "uidrange" | "ipproto" | "sport" | "dport" | "tos" | "dsfield" => {
                rule.has_other_selector = true;
                invert_next_selector = false;
                index += 2;
            }
            _ => {
                rule.has_other_selector = true;
                invert_next_selector = false;
                index += 1;
            }
        }
    }
    if !invert_next_selector {
        Some(rule)
    } else {
        None
    }
}

fn parse_ip_prefix(value: &str, family: WanFamily) -> Option<IpPrefix> {
    if value.eq_ignore_ascii_case("all") {
        return Some(IpPrefix { prefix_len: 0 });
    }
    let (address, prefix_len) = match value.split_once('/') {
        Some((address, prefix_len)) => (address, prefix_len.parse::<u8>().ok()?),
        None => (value, if family == WanFamily::V4 { 32 } else { 128 }),
    };
    let address = IpAddr::from_str(address).ok()?;
    if !family.matches(address) {
        return None;
    }
    let maximum = if family == WanFamily::V4 { 32 } else { 128 };
    if prefix_len > maximum {
        return None;
    }
    Some(IpPrefix { prefix_len })
}

fn resolve_l3_device(
    wan_id: &str,
    logical: &LogicalWan,
    links: &BTreeMap<&str, &LinkInfo>,
) -> String {
    if logical.proto.eq_ignore_ascii_case("pppoe") {
        return format!("pppoe-{}", logical.section);
    }
    for candidate in [logical.section.as_str(), wan_id] {
        if links.contains_key(candidate) {
            return candidate.to_string();
        }
    }
    if !logical.device.trim().is_empty() {
        return logical.device.trim().to_string();
    }
    if logical.ifnames.len() == 1 {
        return logical.ifnames[0].clone();
    }
    let generated_bridge = format!("br-{}", logical.section);
    if links.contains_key(generated_bridge.as_str()) {
        return generated_bridge;
    }
    String::new()
}

fn resolve_kind(logical: &LogicalWan, l3_device: &str, link: Option<&LinkInfo>) -> String {
    if logical.proto.eq_ignore_ascii_case("pppoe") {
        "pppoe"
    } else if l3_device.starts_with("br-")
        || logical.ifnames.len() > 1
        || logical.device.trim().starts_with("br-")
    {
        "bridge"
    } else if link.is_some_and(|link| link.parent.is_some()) || l3_device.contains('.') {
        "vlan"
    } else if l3_device.starts_with("wlan") {
        "wireless"
    } else if l3_device.is_empty() {
        "unknown"
    } else {
        "ethernet"
    }
    .to_string()
}

fn resolve_physical_devices(
    logical: &LogicalWan,
    l3_device: &str,
    kind: &str,
    links: &[LinkInfo],
    link_map: &BTreeMap<&str, &LinkInfo>,
) -> Vec<String> {
    let mut roots = BTreeSet::new();
    if !logical.ifnames.is_empty() {
        roots.extend(logical.ifnames.iter().cloned());
    } else if !logical.device.trim().is_empty()
        && !(kind == "bridge" && logical.device.trim() == l3_device)
    {
        roots.insert(logical.device.trim().to_string());
    }
    if kind == "bridge" {
        roots.extend(
            links
                .iter()
                .filter(|link| link.master.as_deref() == Some(l3_device))
                .map(|link| link.name.clone()),
        );
    }
    if roots.is_empty() && kind != "bridge" && !l3_device.is_empty() {
        roots.insert(l3_device.to_string());
    }

    fn flatten(
        name: &str,
        link_map: &BTreeMap<&str, &LinkInfo>,
        output: &mut BTreeSet<String>,
        visiting: &mut BTreeSet<String>,
    ) {
        if !visiting.insert(name.to_string()) {
            return;
        }
        if let Some(link) = link_map.get(name) {
            if let Some(parent) = &link.parent {
                flatten(parent, link_map, output, visiting);
                visiting.remove(name);
                return;
            }
        }
        output.insert(name.to_string());
        visiting.remove(name);
    }

    let mut devices = BTreeSet::new();
    let mut visiting = BTreeSet::new();
    for root in roots {
        flatten(&root, link_map, &mut devices, &mut visiting);
    }
    devices.into_iter().collect()
}

fn address_belongs_to_wan(
    address: &WanAddress,
    wan_id: &str,
    logical: &LogicalWan,
    l3_device: &str,
) -> bool {
    if !l3_device.is_empty() {
        address.interface == l3_device
    } else {
        address.interface.eq_ignore_ascii_case(&logical.section)
            || address.interface.eq_ignore_ascii_case(wan_id)
            || (logical.ifnames.len() == 1 && address.interface == logical.ifnames[0])
            || (!logical.device.is_empty() && address.interface == logical.device)
    }
}

fn route_belongs_to_wan(
    route: &RouteInfo,
    wan_id: &str,
    logical: &LogicalWan,
    l3_device: &str,
) -> bool {
    let Some(device) = route.device.as_deref() else {
        return false;
    };
    if !l3_device.is_empty() {
        device == l3_device
            || device.eq_ignore_ascii_case(&logical.section)
            || device.eq_ignore_ascii_case(wan_id)
    } else if !logical.proto.eq_ignore_ascii_case("pppoe") {
        device == logical.device || logical.ifnames.iter().any(|name| name == device)
    } else {
        false
    }
}

fn choose_default_wan(
    routes: &[RouteInfo],
    rules: &[RuleInfo],
    wans: &[WanLink],
) -> Option<String> {
    let mut defaults = BTreeSet::new();
    for route in routes
        .iter()
        .filter(|route| route.is_default && route.kind.is_egress() && route.device.is_some())
    {
        for wan in wans
            .iter()
            .filter(|wan| route_matches_public_wan(route, wan))
        {
            defaults.insert((route.table, route.metric, wan.wan_id.clone()));
        }
    }
    if defaults.is_empty() {
        return None;
    }

    let mut policy: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for rule in rules.iter().filter(|rule| rule.applies_to_default()) {
        policy
            .entry(rule.priority)
            .or_default()
            .insert(rule.table.expect("applies_to_default requires a table"));
    }
    // Linux always retains the built-in main-table rule. Including it also
    // makes discovery conservative when a reduced `ip rule` dump omits it.
    policy.entry(32766).or_default().insert(254);

    for tables in policy.values() {
        let candidates: Vec<&(u32, u32, String)> = defaults
            .iter()
            .filter(|(table, _, _)| tables.contains(table))
            .collect();
        if candidates.is_empty() {
            continue;
        }
        let best_metric = candidates.iter().map(|(_, metric, _)| *metric).min()?;
        let ids: BTreeSet<&str> = candidates
            .iter()
            .filter(|(_, metric, _)| *metric == best_metric)
            .map(|(_, _, wan_id)| wan_id.as_str())
            .collect();
        return if ids.len() == 1 {
            ids.into_iter().next().map(str::to_string)
        } else {
            None
        };
    }
    None
}

fn route_matches_public_wan(route: &RouteInfo, wan: &WanLink) -> bool {
    let Some(device) = route.device.as_deref() else {
        return false;
    };
    device == wan.l3_device
        || device.eq_ignore_ascii_case(&wan.logical_interface)
        || device.eq_ignore_ascii_case(&wan.wan_id)
}

fn parse_mwan3_uci(output: &str) -> Mwan3Config {
    let entries: Vec<(&str, &str)> = output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.trim().strip_prefix("mwan3.")?, value.trim()))
        })
        .collect();
    let mut sections: BTreeMap<String, Mwan3Section> = BTreeMap::new();
    for (rest, raw_value) in &entries {
        if rest.contains('.') {
            continue;
        }
        let value = unquote_uci(raw_value);
        if matches!(value.as_str(), "interface" | "member") && !name_is_anonymous(rest) {
            sections.insert(
                (*rest).to_string(),
                Mwan3Section {
                    kind: value,
                    name: (*rest).to_string(),
                    options: BTreeMap::new(),
                },
            );
        }
    }
    for (rest, raw_value) in entries {
        let Some((name, option)) = rest.split_once('.') else {
            continue;
        };
        if let Some(section) = sections.get_mut(name) {
            section
                .options
                .insert(option.to_string(), unquote_uci(raw_value));
        }
    }
    Mwan3Config {
        sections: sections.into_values().collect(),
    }
}

fn parse_mwan3_file(output: &str) -> Mwan3Config {
    let mut sections = Vec::new();
    let mut current: Option<Mwan3Section> = None;
    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() == Some(&"config") {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            if fields.len() >= 3 && matches!(fields[1], "interface" | "member") {
                let name = unquote_uci(fields[2]);
                if !name_is_anonymous(&name) {
                    current = Some(Mwan3Section {
                        kind: fields[1].to_string(),
                        name,
                        options: BTreeMap::new(),
                    });
                }
            }
        } else if matches!(fields.first(), Some(&"option") | Some(&"list")) {
            if fields.len() >= 3 {
                if let Some(section) = current.as_mut() {
                    section
                        .options
                        .insert(unquote_uci(fields[1]), unquote_uci(fields[2]));
                }
            }
        }
    }
    if let Some(section) = current {
        sections.push(section);
    }
    Mwan3Config { sections }
}

fn name_is_anonymous(name: &str) -> bool {
    name.starts_with('@')
}

fn resolve_mwan3_member(logical: &LogicalWan, config: &Mwan3Config) -> Option<String> {
    let members: BTreeSet<&str> = config
        .sections
        .iter()
        .filter(|section| section.kind == "member")
        .filter(|section| {
            section
                .options
                .get("interface")
                .is_some_and(|interface| interface.eq_ignore_ascii_case(&logical.section))
        })
        .map(|section| section.name.as_str())
        .collect();
    if !members.is_empty() {
        return if members.len() == 1 {
            members.into_iter().next().map(str::to_string)
        } else {
            None
        };
    }
    let interfaces: BTreeSet<&str> = config
        .sections
        .iter()
        .filter(|section| section.kind == "interface")
        .filter(|section| {
            section
                .options
                .get("interface")
                .unwrap_or(&section.name)
                .eq_ignore_ascii_case(&logical.section)
        })
        .map(|section| section.name.as_str())
        .collect();
    if interfaces.len() == 1 {
        interfaces.into_iter().next().map(str::to_string)
    } else {
        None
    }
}

fn is_ipv6_ula(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn run_readonly(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .or_else(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                let fallback = format!("/sbin/{program}");
                Command::new(fallback).args(args).output()
            } else {
                Err(error)
            }
        })
        .with_context(|| format!("execute read-only {program} {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "read-only {program} {} failed: {}",
            args.join(" "),
            stderr.trim()
        );
    }
    String::from_utf8(output.stdout).context("command output was not valid UTF-8")
}

fn run_ip(args: &[&str]) -> Result<String> {
    run_readonly("ip", args)
}

fn run_optional_readonly(program: &str, args: &[&str]) -> Result<Option<String>> {
    match run_readonly(program, args) {
        Ok(output) => Ok(Some(output)),
        Err(error) => {
            if let Some(source) = error.source() {
                if source.downcast_ref::<io::Error>().is_some() {
                    return Ok(None);
                }
            }
            Ok(None)
        }
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
    use serde_json::json;

    const NETWORK: &str = r#"
network.wan=interface
network.wan.proto='dhcp'
network.wan.device='eth0.2'
network.wan.metric='10'
network.wan1=interface
network.wan1.proto='pppoe'
network.wan1.device='eth1'
network.wan1.ifname='eth1'
network.lan=interface
network.lan.proto='static'
network.lan.device='br-lan'
"#;

    const LINKS: &str = r#"
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT group default qlen 1000\    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff
3: eth0.2@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT group default\    link/ether 02:00:00:00:00:02 brd ff:ff:ff:ff:ff:ff
4: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT group default\    link/ether 02:00:00:00:00:03 brd ff:ff:ff:ff:ff:ff
5: pppoe-wan1: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1492 state UP mode DEFAULT group default\    pppoe-wan1 proto kernel peer 192.0.2.1
"#;

    const ADDRESSES_V4: &str = r#"
1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
3: eth0.2    inet 192.0.2.2/24 brd 192.0.2.255 scope global eth0.2\       valid_lft forever preferred_lft forever
5: pppoe-wan1    inet 198.51.100.2/32 scope global pppoe-wan1\       valid_lft forever preferred_lft forever
"#;

    const ADDRESSES_V6: &str = r#"
3: eth0.2    inet6 2001:db8::2/64 scope global dynamic \       valid_lft forever preferred_lft forever
3: eth0.2    inet6 2001:db8::3/64 scope global temporary dynamic \       valid_lft forever preferred_lft forever
3: eth0.2    inet6 2001:db8::4/64 scope global deprecated \       valid_lft forever preferred_lft 0sec
3: eth0.2    inet6 2001:db8::5/64 scope global tentative \       valid_lft forever preferred_lft forever
5: pppoe-wan1    inet6 2001:db8:1::2/64 scope global dynamic \       valid_lft forever preferred_lft forever
"#;

    const ROUTES_V4: &str = r#"
default via 192.0.2.1 dev eth0.2 proto static src 192.0.2.2 metric 10
192.0.2.0/24 dev eth0.2 proto kernel scope link src 192.0.2.2
default via 198.51.100.1 dev pppoe-wan1 proto static src 198.51.100.2 table 100 metric 20
198.51.100.0/24 dev pppoe-wan1 proto kernel scope link src 198.51.100.2 table 100
"#;

    const ROUTES_V6: &str = r#"
default via fe80::1 dev eth0.2 proto static metric 1024 pref medium
2001:db8::/64 dev eth0.2 proto kernel metric 256 pref medium
default via fe80::2 dev pppoe-wan1 proto static table 101 metric 20 pref medium
"#;

    const RULES_V4: &str = r#"
0: from all lookup local
100: from all to 192.0.2.0/24 lookup main suppress_prefixlength 0
200: from all fwmark 0x1 lookup 100
32766: from all lookup main
32767: from all lookup default
"#;

    const RULES_V6: &str = r#"
0: from all lookup local
200: from all fwmark 0x1 lookup 101
32766: from all lookup main
32767: from all lookup default
"#;

    fn snapshot_from_fixture(network: &str, links: &str) -> WanSnapshot {
        build_snapshot(
            DiscoveryOutputs {
                network_uci: network.to_string(),
                links: links.to_string(),
                addresses_v4: ADDRESSES_V4.to_string(),
                addresses_v6: ADDRESSES_V6.to_string(),
                routes_v4: ROUTES_V4.to_string(),
                routes_v6: ROUTES_V6.to_string(),
                rules_v4: RULES_V4.to_string(),
                rules_v6: RULES_V6.to_string(),
                mwan3_uci: String::new(),
                mwan3_file: String::new(),
            },
            123,
            DISCOVERY_SOURCE.to_string(),
        )
        .unwrap()
    }

    #[test]
    fn parses_wan_uci_without_inventing_sections() {
        let parsed = parse_network_uci(NETWORK).unwrap();
        assert_eq!(parsed.keys().cloned().collect::<Vec<_>>(), ["wan", "wan1"]);
        assert_eq!(parsed["wan"].proto, "dhcp");
        assert_eq!(parsed["wan1"].ifnames, ["eth1"]);
        let upper = parse_network_uci("network.WAN1=interface\n").unwrap();
        assert_eq!(upper["wan1"].section, "WAN1");
        assert!(parse_network_uci("network.lan=interface\n")
            .unwrap()
            .is_empty());
        assert!(parse_network_uci("network.@interface[0]=interface\n")
            .unwrap()
            .is_empty());
        assert!(build_snapshot(
            DiscoveryOutputs {
                network_uci: "network.lan=interface\n".into(),
                links: String::new(),
                addresses_v4: String::new(),
                addresses_v6: String::new(),
                routes_v4: String::new(),
                routes_v6: String::new(),
                rules_v4: String::new(),
                rules_v6: String::new(),
                mwan3_uci: String::new(),
                mwan3_file: String::new(),
            },
            1,
            "test".into(),
        )
        .is_err());
    }

    #[test]
    fn normalized_wan_ids_are_stable_when_uci_lines_are_reordered() {
        let reordered_network = NETWORK.lines().rev().collect::<Vec<_>>().join("\n");
        let reordered_links = LINKS.lines().rev().collect::<Vec<_>>().join("\n");
        let first = snapshot_from_fixture(NETWORK, LINKS);
        let second = snapshot_from_fixture(&reordered_network, &reordered_links);
        assert_eq!(first, second);
        assert_eq!(first.wans[0].wan_id, "wan");
        assert_eq!(first.wans[1].wan_id, "wan1");
    }

    #[test]
    fn duplicate_normalized_wan_sections_fail_closed() {
        assert!(parse_network_uci("network.WAN=interface\nnetwork.wan=interface\n").is_err());
    }

    #[test]
    fn parses_vlan_and_pppoe_relationships() {
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        let wan = &snapshot.wans[0];
        assert_eq!(wan.logical_interface, "wan");
        assert_eq!(wan.l3_device, "eth0.2");
        assert_eq!(wan.kind, "vlan");
        assert_eq!(wan.devices, ["eth0"]);
        assert!(wan.up);
        let wan1 = &snapshot.wans[1];
        assert_eq!(wan1.l3_device, "pppoe-wan1");
        assert_eq!(wan1.kind, "pppoe");
        assert_eq!(wan1.devices, ["eth1"]);
        assert!(wan1.up);
    }

    #[test]
    fn parses_bridge_members_and_flattens_vlan_members() {
        let network = "network.wan=interface\nnetwork.wan.proto='static'\nnetwork.wan.device='br-wan'\nnetwork.wan.ifname='eth0.2 eth1'\n";
        let links = format!(
            "{LINKS}\n6: br-wan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT group default\n"
        );
        let snapshot = snapshot_from_fixture(network, &links);
        let wan = &snapshot.wans[0];
        assert_eq!(wan.l3_device, "br-wan");
        assert_eq!(wan.kind, "bridge");
        assert_eq!(wan.devices, ["eth0", "eth1"]);
    }

    #[test]
    fn bridge_master_relationships_are_used_when_uci_has_no_ifname() {
        let network =
            "network.wan=interface\nnetwork.wan.proto='static'\nnetwork.wan.device='br-wan'\n";
        let links = format!(
            "{}\n4: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP master br-wan\n6: br-wan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
            LINKS.lines()
                .filter(|line| !line.trim_start().starts_with("4: eth1:"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let snapshot = snapshot_from_fixture(network, &links);
        assert_eq!(snapshot.wans[0].devices, ["eth1"]);
    }

    #[test]
    fn ipv6_address_flags_are_parsed_and_unsafe_sources_are_rejected() {
        let addresses = parse_addresses(ADDRESSES_V6, WanFamily::V6);
        assert!(
            addresses
                .iter()
                .find(|a| a.address.to_string() == "2001:db8::3")
                .unwrap()
                .temporary
        );
        assert!(
            addresses
                .iter()
                .find(|a| a.address.to_string() == "2001:db8::4")
                .unwrap()
                .deprecated
        );
        assert!(
            addresses
                .iter()
                .find(|a| a.address.to_string() == "2001:db8::5")
                .unwrap()
                .tentative
        );
        let stable = addresses
            .iter()
            .find(|a| a.address.to_string() == "2001:db8::2")
            .unwrap();
        assert!(stable.is_safe_source(WanFamily::V6));
        assert!(!addresses
            .iter()
            .find(|a| a.address.to_string() == "2001:db8::3")
            .unwrap()
            .is_safe_source(WanFamily::V6));
        assert!(!WanAddress {
            address: "fd00::1".parse().unwrap(),
            prefix_len: 64,
            scope: "global".into(),
            temporary: false,
            deprecated: false,
            tentative: false,
            interface: "eth0".into(),
        }
        .is_safe_source(WanFamily::V6));
        assert!(!WanAddress {
            address: "fe80::1".parse().unwrap(),
            prefix_len: 64,
            scope: "link".into(),
            temporary: false,
            deprecated: false,
            tentative: false,
            interface: "eth0".into(),
        }
        .is_safe_source(WanFamily::V6));
    }

    #[test]
    fn unspecified_and_ipv4_link_local_sources_are_rejected() {
        for raw in ["0.0.0.0", "169.254.10.2"] {
            assert!(!WanAddress {
                address: raw.parse().unwrap(),
                prefix_len: 32,
                scope: "global".into(),
                temporary: false,
                deprecated: false,
                tentative: false,
                interface: "eth0".into(),
            }
            .is_safe_source(WanFamily::V4));
        }
        assert!(!WanAddress {
            address: "::".parse().unwrap(),
            prefix_len: 128,
            scope: "host".into(),
            temporary: false,
            deprecated: false,
            tentative: false,
            interface: "eth0".into(),
        }
        .is_safe_source(WanFamily::V6));
    }

    #[test]
    fn routes_tables_metrics_gateways_and_rules_are_parsed() {
        let routes = parse_routes(ROUTES_V4, WanFamily::V4);
        let default = routes.iter().find(|route| route.is_default).unwrap();
        assert_eq!(default.table, 254);
        assert_eq!(default.metric, 10);
        assert_eq!(default.device.as_deref(), Some("eth0.2"));
        assert_eq!(default.via, Some("192.0.2.1".parse().unwrap()));
        let custom = routes
            .iter()
            .find(|route| route.table == 100 && route.is_default)
            .unwrap();
        assert_eq!(custom.metric, 20);
        let rules = parse_rules(RULES_V4, WanFamily::V4);
        assert!(rules
            .iter()
            .find(|rule| rule.priority == 0)
            .unwrap()
            .applies_to_default());
        assert!(!rules
            .iter()
            .find(|rule| rule.priority == 100)
            .unwrap()
            .applies_to_default());
        assert!(!rules
            .iter()
            .find(|rule| rule.priority == 200)
            .unwrap()
            .applies_to_default());
        assert!(rules
            .iter()
            .find(|rule| rule.priority == 32766)
            .unwrap()
            .applies_to_default());
        assert_eq!(
            parse_rules("10: from all lookup 100\n", WanFamily::V4)[0].table,
            Some(100)
        );
    }

    #[test]
    fn policy_rules_select_an_unambiguous_custom_default_table() {
        let routes = parse_routes(
            "default via 192.0.2.1 dev eth0.2 table 100 metric 5\n",
            WanFamily::V4,
        );
        let rules = parse_rules(
            "0: from all lookup local\n100: from all lookup 100\n32766: from all lookup main\n",
            WanFamily::V4,
        );
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        assert_eq!(
            choose_default_wan(&routes, &rules, &snapshot.wans),
            Some("wan".into())
        );
    }

    #[test]
    fn equal_metric_defaults_are_ambiguous() {
        let routes = parse_routes(
            "default via 192.0.2.1 dev eth0.2 metric 10\ndefault via 198.51.100.1 dev pppoe-wan1 metric 10\n",
            WanFamily::V4,
        );
        let rules = parse_rules("32766: from all lookup main\n", WanFamily::V4);
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        assert_eq!(choose_default_wan(&routes, &rules, &snapshot.wans), None);
    }

    #[test]
    fn lower_metric_default_wins_but_same_priority_policy_tables_can_be_ambiguous() {
        let routes = parse_routes(
            "default via 192.0.2.1 dev eth0.2 table 100 metric 5\ndefault via 198.51.100.1 dev pppoe-wan1 table 101 metric 10\n",
            WanFamily::V4,
        );
        let rules = parse_rules(
            "100: from all lookup 100\n100: from all lookup 101\n32766: from all lookup main\n",
            WanFamily::V4,
        );
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        assert_eq!(
            choose_default_wan(&routes, &rules, &snapshot.wans),
            Some("wan".into())
        );

        let tied = parse_routes(
            "default via 192.0.2.1 dev eth0.2 table 100 metric 5\ndefault via 198.51.100.1 dev pppoe-wan1 table 101 metric 5\n",
            WanFamily::V4,
        );
        assert_eq!(choose_default_wan(&tied, &rules, &snapshot.wans), None);
    }

    #[test]
    fn fwmark_rules_do_not_define_the_global_default() {
        let routes = parse_routes(
            "default via 198.51.100.1 dev pppoe-wan1 table 100 metric 1\n",
            WanFamily::V4,
        );
        let rules = parse_rules(
            "100: from all fwmark 0x1 lookup 100\n32766: from all lookup main\n",
            WanFamily::V4,
        );
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        assert_eq!(choose_default_wan(&routes, &rules, &snapshot.wans), None);
    }

    #[test]
    fn resolves_explicit_and_legacy_default_bindings() {
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        let explicit = resolve_binding(&snapshot, " WAN1 ", WanFamily::V4).unwrap();
        assert_eq!(explicit.wan_id, "wan1");
        assert_eq!(explicit.source_address, "198.51.100.2");
        assert_eq!(explicit.device.as_deref(), Some("pppoe-wan1"));
        // The public routeTables list spans both families. With distinct IPv4
        // and IPv6 tables there is no safe family-specific guess.
        assert_eq!(explicit.route_table, None);
        assert!(!explicit.verified);
        assert_eq!(explicit.verification, WanVerification::Unknown);

        let default = resolve_binding(&snapshot, "  ", WanFamily::V4).unwrap();
        assert_eq!(default.wan_id, "wan");
        assert_eq!(default.source_address, "192.0.2.2");
        assert_eq!(default.device.as_deref(), Some("eth0.2"));
    }

    #[test]
    fn explicit_unknown_offline_and_missing_family_fail_closed() {
        let mut snapshot = snapshot_from_fixture(NETWORK, LINKS);
        assert!(resolve_binding(&snapshot, "wan9", WanFamily::V4).is_err());
        snapshot.wans[1].up = false;
        assert!(resolve_binding(&snapshot, "wan1", WanFamily::V4).is_err());
        snapshot.wans[0].up = false;
        assert!(resolve_binding(&snapshot, "", WanFamily::V4).is_err());
        snapshot.wans[0].up = true;
        snapshot.wans[0]
            .addresses
            .retain(|address| address.address.is_ipv6());
        assert!(resolve_binding(&snapshot, "wan", WanFamily::V4).is_err());
        assert!(resolve_binding(&snapshot, "", WanFamily::V4).is_err());
    }

    #[test]
    fn ambiguous_or_entirely_unsafe_sources_are_not_guessed() {
        let mut snapshot = snapshot_from_fixture(NETWORK, LINKS);
        let extra = WanAddress {
            address: "192.0.2.3".parse().unwrap(),
            prefix_len: 24,
            scope: "global".into(),
            temporary: false,
            deprecated: false,
            tentative: false,
            interface: "eth0.2".into(),
        };
        snapshot.wans[0].addresses.push(extra);
        assert!(resolve_binding(&snapshot, "wan", WanFamily::V4).is_err());

        snapshot.wans[0].addresses.retain(|address| {
            address.address.to_string() == "192.0.2.2"
                || address.address.to_string() == "2001:db8::3"
        });
        assert!(resolve_binding(&snapshot, "wan", WanFamily::V6).is_err());
    }

    #[test]
    fn mwan3_member_mapping_uses_interface_not_list_position() {
        let raw = "mwan3.wan_m1=member\nmwan3.wan_m1.interface='wan1'\nmwan3.wan_m2=member\nmwan3.wan_m2.interface='wan'\n";
        let config = parse_mwan3_uci(raw);
        let logical = LogicalWan {
            section: "wan1".into(),
            proto: "pppoe".into(),
            device: "eth1".into(),
            ifnames: vec!["eth1".into()],
        };
        assert_eq!(
            resolve_mwan3_member(&logical, &config).as_deref(),
            Some("wan_m1")
        );
        let reordered = raw.lines().rev().collect::<Vec<_>>().join("\n");
        assert_eq!(
            resolve_mwan3_member(&logical, &parse_mwan3_uci(&reordered)).as_deref(),
            Some("wan_m1")
        );

        let ambiguous = parse_mwan3_uci(
            "mwan3.wan_m1=member\nmwan3.wan_m1.interface='wan1'\nmwan3.wan_m2=member\nmwan3.wan_m2.interface='wan1'\n",
        );
        assert_eq!(resolve_mwan3_member(&logical, &ambiguous), None);

        let file = parse_mwan3_file(
            "config interface 'wan'\n option enabled '1'\nconfig member 'wan_m1'\n option interface 'wan'\n",
        );
        assert_eq!(
            resolve_mwan3_member(
                &LogicalWan {
                    section: "wan".into(),
                    proto: "dhcp".into(),
                    device: "eth0".into(),
                    ifnames: vec![],
                },
                &file
            )
            .as_deref(),
            Some("wan_m1")
        );
    }

    #[test]
    fn socket_binding_plan_uses_source_and_device_without_route_table_marks() {
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        let binding = resolve_binding(&snapshot, "wan", WanFamily::V4).unwrap();
        let peer: SocketAddr = "203.0.113.1:443".parse().unwrap();
        assert_eq!(
            socket_bind_address(&binding, peer).unwrap(),
            SocketAddr::new("192.0.2.2".parse().unwrap(), 0)
        );
        assert_eq!(
            socket_bind_address_with_port(&binding, WanFamily::V4, 34_789).unwrap(),
            SocketAddr::new("192.0.2.2".parse().unwrap(), 34_789)
        );
        assert_eq!(validated_bind_device(&binding).unwrap(), Some("eth0.2"));
        assert!(socket_bind_address(&binding, "[2001:db8::1]:443".parse().unwrap()).is_err());

        let invalid_device = WanBinding {
            device: Some("eth0\0bad".into()),
            ..binding
        };
        assert!(socket_bind_address(&invalid_device, peer).is_err());
    }

    #[test]
    fn route_get_plus_connected_local_address_verifies_egress() {
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        let mut binding = resolve_binding(&snapshot, "wan", WanFamily::V4).unwrap();
        let peer: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let local = SocketAddr::new(binding.source_address.parse().unwrap(), 40000);
        assert_eq!(
            evaluate_egress(
                &mut binding,
                peer,
                local,
                "203.0.113.1 from 192.0.2.2 dev eth0.2 uid 0\n    cache\n",
            ),
            WanVerification::Verified
        );
    }

    #[test]
    fn ipv6_route_get_and_connected_local_address_verify_egress() {
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        let mut binding = resolve_binding(&snapshot, "wan", WanFamily::V6).unwrap();
        let peer: SocketAddr = "[2001:4860:4860::8888]:443".parse().unwrap();
        let local = SocketAddr::new(binding.source_address.parse().unwrap(), 40000);
        assert_eq!(
            evaluate_egress(
                &mut binding,
                peer,
                local,
                "2001:4860:4860::8888 from 2001:db8::2 dev eth0.2 proto kernel src 2001:db8::2 metric 1024 pref medium\n",
            ),
            WanVerification::Verified
        );
    }

    #[test]
    fn route_source_or_device_mismatch_is_not_verified() {
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        let mut binding = resolve_binding(&snapshot, "wan", WanFamily::V4).unwrap();
        let peer: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let local = SocketAddr::new(binding.source_address.parse().unwrap(), 40000);
        assert_eq!(
            evaluate_egress(
                &mut binding,
                peer,
                local,
                "203.0.113.1 from 192.0.2.2 dev pppoe-wan1 uid 0\n",
            ),
            WanVerification::Mismatch
        );
        assert_eq!(
            evaluate_egress(
                &mut binding,
                peer,
                local,
                "203.0.113.1 from 198.51.100.2 dev eth0.2 uid 0\n",
            ),
            WanVerification::Mismatch
        );
        assert_eq!(
            evaluate_egress(
                &mut binding,
                peer,
                SocketAddr::new("192.0.2.9".parse().unwrap(), 40000),
                "203.0.113.1 from 192.0.2.2 dev eth0.2 uid 0\n",
            ),
            WanVerification::Mismatch
        );
    }

    #[test]
    fn route_get_parse_failure_is_unknown_even_with_matching_socket_source() {
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        let mut binding = resolve_binding(&snapshot, "wan", WanFamily::V4).unwrap();
        let peer: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let local = SocketAddr::new(binding.source_address.parse().unwrap(), 40000);
        for output in [
            "",
            "not-a-route",
            "203.0.113.1 dev eth0.2 uid 0\n",
            "unreachable 203.0.113.1 dev lo\n",
            "203.0.113.1 from 192.0.2.2 dev eth0.2\n203.0.113.2 from 192.0.2.2 dev eth0.2\n",
        ] {
            assert_eq!(
                evaluate_egress(&mut binding, peer, local, output),
                WanVerification::Unknown
            );
        }
        binding.set_verification(WanVerification::Verified);
        query_and_evaluate_verification_reset(&mut binding);
        assert!(!binding.verified);
    }

    fn query_and_evaluate_verification_reset(binding: &mut WanBinding) {
        binding.set_verification(WanVerification::Unknown);
    }

    #[test]
    fn resolved_target_route_requires_matching_target_source_and_device() {
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        let binding = resolve_binding(&snapshot, "wan", WanFamily::V4).unwrap();
        let target: IpAddr = "203.0.113.1".parse().unwrap();
        assert_eq!(
            evaluate_route_get(
                &binding,
                target,
                "203.0.113.1 from 192.0.2.2 dev eth0.2 uid 0\n    cache\n",
            ),
            WanVerification::Verified
        );
        assert_eq!(
            evaluate_route_get(
                &binding,
                target,
                "203.0.113.1 from 192.0.2.2 dev pppoe-wan1 uid 0\n",
            ),
            WanVerification::Mismatch
        );
        assert_eq!(
            evaluate_route_get(
                &binding,
                target,
                "203.0.113.2 from 192.0.2.2 dev eth0.2 uid 0\n",
            ),
            WanVerification::Mismatch
        );
        assert_eq!(
            evaluate_route_get(&binding, target, "RTNETLINK answers: Permission denied"),
            WanVerification::Unknown
        );
    }

    #[test]
    fn dto_json_uses_camel_case_and_verification_states() {
        let snapshot = snapshot_from_fixture(NETWORK, LINKS);
        let value = serde_json::to_value(&snapshot).unwrap();
        assert!(value.get("defaultWanIdV4").is_some());
        assert!(value.get("observedAt").is_some());
        assert!(value["wans"][0].get("l3Device").is_some());
        assert!(value["wans"][0].get("routeTables").is_some());
        assert!(value["wans"][0]["addresses"][0].get("prefixLen").is_some());
        let binding = resolve_binding(&snapshot, "wan", WanFamily::V4).unwrap();
        let binding_value = serde_json::to_value(binding).unwrap();
        assert_eq!(binding_value["verification"], json!("unknown"));
        assert_eq!(binding_value["sourceAddress"], json!("192.0.2.2"));
    }
}
