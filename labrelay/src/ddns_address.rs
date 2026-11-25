//! Generic Linux DDNS address detection.
//!
//! The detector deliberately uses the standard `ip` command first so it can
//! run on OpenWrt and other Linux routers. OpenWrt's ubus output is used only
//! as a read-only topology hint; interface names never decide a role.

use crate::wan::{self, WanBinding, WanFamily, WanLink, WanSnapshot, WanVerification};
use anyhow::Result;
use futures_util::future::join_all;
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::lookup_host;
use tokio::time::Duration;

const IPV4_EGRESS_ENDPOINTS: [(&str, &str); 2] = [
    ("api.ipify.org", "https://api.ipify.org"),
    ("ifconfig.me", "https://ifconfig.me/ip"),
];
const IPV6_EGRESS_ENDPOINTS: [(&str, &str); 2] = [
    ("api6.ipify.org", "https://api6.ipify.org"),
    ("ifconfig.co", "https://ifconfig.co/ip"),
];

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DdnsAddressSnapshot {
    pub detected_ipv4: String,
    pub detected_ipv6: String,
    pub ipv4_state: String,
    pub ipv6_state: String,
    pub ipv4_source: String,
    pub ipv6_source: String,
    pub detected_at: u64,
}

/// Dashboard payload. The nested default address retains the legacy scalar
/// shape for records with `wanId == ""`; `wans` carries isolated line samples.
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DdnsAddressReport {
    pub address: DdnsAddressSnapshot,
    pub wans: Vec<DdnsWanAddressSnapshot>,
    pub wan_supported: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DdnsWanAddressSnapshot {
    pub wan_id: String,
    #[serde(flatten)]
    pub address: DdnsAddressSnapshot,
}

#[derive(Debug, Clone)]
struct FamilyDetection {
    source: Option<IpAddr>,
    detected: Option<(IpAddr, String)>,
    verification: WanVerification,
}

impl FamilyDetection {
    fn unavailable() -> Self {
        Self {
            source: None,
            detected: None,
            verification: WanVerification::Unknown,
        }
    }

    fn verified_external(&self, family: WanFamily) -> Option<(IpAddr, String)> {
        let source = self.source?;
        if self.verification != WanVerification::Verified
            || !family.matches(source)
            || !family.matches(self.detected.as_ref()?.0)
        {
            return None;
        }
        let (ip, source_name) = self.detected.as_ref()?;
        (public_address(*ip, family)).then(|| (*ip, source_name.clone()))
    }

    fn allows_local_fallback(&self) -> bool {
        self.source.is_some() && self.verification == WanVerification::Verified
    }

    fn snapshot(&self, wan_id: &str, family: WanFamily, detected_at: u64) -> DdnsAddressSnapshot {
        if let Some((ip, source)) = self.verified_external(family) {
            let (detected_ipv4, detected_ipv6) = match family {
                WanFamily::V4 => (ip.to_string(), String::new()),
                WanFamily::V6 => (String::new(), ip.to_string()),
            };
            return DdnsAddressSnapshot {
                detected_ipv4,
                detected_ipv6,
                ipv4_state: if family == WanFamily::V4 {
                    "public"
                } else {
                    "unavailable"
                }
                .into(),
                ipv6_state: if family == WanFamily::V6 {
                    "public"
                } else {
                    "unavailable"
                }
                .into(),
                ipv4_source: if family == WanFamily::V4 {
                    source.clone()
                } else {
                    String::new()
                },
                ipv6_source: if family == WanFamily::V6 {
                    source
                } else {
                    String::new()
                },
                detected_at,
            };
        }
        let cgnat = family == WanFamily::V4
            && self
                .source
                .is_some_and(|source| matches!(source, IpAddr::V4(ip) if ipv4_cgnat(ip)));
        DdnsAddressSnapshot {
            detected_ipv4: String::new(),
            detected_ipv6: String::new(),
            ipv4_state: if family == WanFamily::V4 {
                if cgnat {
                    "cgnat"
                } else {
                    "unavailable"
                }
            } else {
                "unavailable"
            }
            .into(),
            ipv6_state: "unavailable".into(),
            ipv4_source: if family == WanFamily::V4 {
                format!("wan:{wan_id}:unavailable")
            } else {
                String::new()
            },
            ipv6_source: if family == WanFamily::V6 {
                format!("wan:{wan_id}:unavailable")
            } else {
                String::new()
            },
            detected_at,
        }
    }
}

#[derive(Debug, Clone)]
struct WanDetection {
    wan_id: String,
    ipv4: FamilyDetection,
    ipv6: FamilyDetection,
    detected_at: u64,
}

impl WanDetection {
    fn snapshot(&self) -> DdnsWanAddressSnapshot {
        let ipv4 = self
            .ipv4
            .snapshot(&self.wan_id, WanFamily::V4, self.detected_at);
        let ipv6 = self
            .ipv6
            .snapshot(&self.wan_id, WanFamily::V6, self.detected_at);
        DdnsWanAddressSnapshot {
            wan_id: self.wan_id.clone(),
            address: DdnsAddressSnapshot {
                detected_ipv4: ipv4.detected_ipv4,
                detected_ipv6: ipv6.detected_ipv6,
                ipv4_state: ipv4.ipv4_state,
                ipv6_state: ipv6.ipv6_state,
                ipv4_source: ipv4.ipv4_source,
                ipv6_source: ipv6.ipv6_source,
                detected_at: self.detected_at,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate4 {
    ip: Ipv4Addr,
    interface: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate6 {
    ip: Ipv6Addr,
    interface: String,
    interface_up: bool,
    temporary: bool,
    deprecated: bool,
    tentative: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterfaceRole {
    Upstream,
    Downstream,
    BridgeManagement,
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct InterfaceTopology {
    roles: HashMap<String, InterfaceRole>,
}

impl InterfaceTopology {
    fn role_for(&self, interface: &str) -> InterfaceRole {
        self.roles
            .get(interface)
            .copied()
            .unwrap_or(InterfaceRole::Unknown)
    }

    fn set_role(&mut self, interface: &str, role: InterfaceRole) {
        if interface.is_empty() {
            return;
        }
        let current = self.role_for(interface);
        let selected = match (current, role) {
            (InterfaceRole::Upstream, _) => InterfaceRole::Upstream,
            (_, InterfaceRole::Upstream) => InterfaceRole::Upstream,
            (InterfaceRole::BridgeManagement, InterfaceRole::Downstream) => {
                InterfaceRole::BridgeManagement
            }
            (InterfaceRole::Downstream, InterfaceRole::BridgeManagement) => {
                InterfaceRole::BridgeManagement
            }
            (InterfaceRole::Unknown, other) => other,
            (other, _) => other,
        };
        self.roles.insert(interface.to_string(), selected);
    }
}

pub async fn detect() -> DdnsAddressReport {
    let discovered = wan::discover_snapshot_cached_async(Duration::from_secs(120)).await.ok();
    let wan_supported = discovered.is_some();
    let detected_at = now_epoch();
    let detections = match discovered.as_ref() {
        Some(snapshot) => detect_wans(snapshot, detected_at).await,
        None => Vec::new(),
    };
    let address = detect_default_address(discovered.as_ref(), &detections, detected_at);
    DdnsAddressReport {
        address,
        wans: detections.iter().map(WanDetection::snapshot).collect(),
        wan_supported,
    }
}

async fn detect_wans(snapshot: &WanSnapshot, detected_at: u64) -> Vec<WanDetection> {
    join_all(
        snapshot
            .wans
            .iter()
            .map(|wan| detect_wan(wan, snapshot, detected_at)),
    )
    .await
}

async fn detect_wan(wan: &WanLink, snapshot: &WanSnapshot, detected_at: u64) -> WanDetection {
    let (ipv4, ipv6) = tokio::join!(
        detect_wan_family(snapshot, &wan.wan_id, WanFamily::V4),
        detect_wan_family(snapshot, &wan.wan_id, WanFamily::V6),
    );
    WanDetection {
        wan_id: wan.wan_id.clone(),
        ipv4,
        ipv6,
        detected_at,
    }
}

async fn detect_wan_family(
    snapshot: &WanSnapshot,
    wan_id: &str,
    family: WanFamily,
) -> FamilyDetection {
    let binding = match wan::resolve_binding(snapshot, wan_id, family) {
        Ok(binding) => binding,
        Err(_) => return FamilyDetection::unavailable(),
    };
    let source = binding.source_address.parse::<IpAddr>().ok();
    let (detected, verification) = detect_external_bound(binding, family).await;
    FamilyDetection {
        source,
        detected,
        verification,
    }
}

async fn detect_external_bound(
    binding: WanBinding,
    family: WanFamily,
) -> (Option<(IpAddr, String)>, WanVerification) {
    let endpoints = match family {
        WanFamily::V4 => &IPV4_EGRESS_ENDPOINTS,
        WanFamily::V6 => &IPV6_EGRESS_ENDPOINTS,
    };
    // The fallback is only necessary on failure; avoid duplicate external
    // requests on every healthy line. Keep per-destination route verification.
    let primary = query_external_bound(binding.clone(), family, endpoints[0]).await;
    if primary.0.is_some() {
        return primary;
    }
    let fallback = query_external_bound(binding, family, endpoints[1]).await;
    if fallback.0.is_some() {
        return fallback;
    }
    (None, strongest_verification(primary.1, fallback.1))
}

async fn query_external_bound(
    mut binding: WanBinding,
    family: WanFamily,
    endpoint: (&str, &str),
) -> (Option<(IpAddr, String)>, WanVerification) {
    let (name, url) = endpoint;
    let addresses = match lookup_host((name, 443)).await {
        Ok(addresses) => addresses,
        Err(_) => return (None, WanVerification::Unknown),
    };
    let mut strongest = WanVerification::Unknown;
    for address in addresses {
        if address.port() != 443
            || !family.matches(address.ip())
            || !public_address(address.ip(), family)
        {
            continue;
        }
        let target = address.ip();
        let verification = wan::verify_route_get(&mut binding, target).await;
        strongest = strongest_verification(strongest, verification);
        if verification != WanVerification::Verified {
            continue;
        }
        let Ok(source) = binding.source_address.parse::<IpAddr>() else {
            continue;
        };
        let client = match Client::builder()
            .local_address(Some(source))
            .resolve(name, address)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(2))
            .user_agent(concat!("labrelay/", env!("CARGO_PKG_VERSION")))
            .build()
        {
            Ok(client) => client,
            Err(_) => continue,
        };
        let response = match client.get(url).send().await {
            Ok(response) if response.status().is_success() => response,
            _ => continue,
        };
        let Ok(text) = response.text().await else {
            continue;
        };
        if let Some(ip) = parse_public_address(text.trim(), family) {
            return (Some((ip, format!("egress-http:{name}"))), verification);
        }
    }
    (None, strongest)
}

fn parse_public_address(text: &str, family: WanFamily) -> Option<IpAddr> {
    let ip = text.parse::<IpAddr>().ok()?;
    public_address(ip, family).then_some(ip)
}

fn public_address(ip: IpAddr, family: WanFamily) -> bool {
    match (family, ip) {
        (WanFamily::V4, IpAddr::V4(ip)) => ipv4_public(ip),
        (WanFamily::V6, IpAddr::V6(ip)) => ipv6_public(ip),
        _ => false,
    }
}

fn strongest_verification(left: WanVerification, right: WanVerification) -> WanVerification {
    use WanVerification::{Mismatch, Unknown, Verified};
    match (left, right) {
        (Verified, _) | (_, Verified) => Verified,
        (Mismatch, _) | (_, Mismatch) => Mismatch,
        (Unknown, Unknown) => Unknown,
    }
}

#[derive(Debug)]
struct DefaultFamilyDetection {
    external: Option<(IpAddr, String)>,
    allow_local_fallback: bool,
    unavailable_source: String,
}

fn default_family_detection(
    snapshot: Option<&WanSnapshot>,
    detections: &[WanDetection],
    family: WanFamily,
) -> DefaultFamilyDetection {
    let Some(snapshot) = snapshot else {
        return DefaultFamilyDetection {
            external: None,
            allow_local_fallback: true,
            unavailable_source: "generic".into(),
        };
    };
    let default_id = match family {
        WanFamily::V4 => snapshot.default_wan_id_v4.as_deref(),
        WanFamily::V6 => snapshot.default_wan_id_v6.as_deref(),
    };
    let unavailable_source = default_id
        .map(|wan_id| format!("default-wan:{wan_id}:unavailable"))
        .unwrap_or_else(|| "default-wan:unavailable".into());
    let Some(default_id) = default_id else {
        return DefaultFamilyDetection {
            external: None,
            allow_local_fallback: false,
            unavailable_source,
        };
    };
    let Some(detection) = detections
        .iter()
        .find(|detection| detection.wan_id.eq_ignore_ascii_case(default_id))
    else {
        return DefaultFamilyDetection {
            external: None,
            allow_local_fallback: false,
            unavailable_source,
        };
    };
    let family_detection = match family {
        WanFamily::V4 => &detection.ipv4,
        WanFamily::V6 => &detection.ipv6,
    };
    DefaultFamilyDetection {
        external: family_detection.verified_external(family),
        allow_local_fallback: family_detection.allows_local_fallback(),
        unavailable_source,
    }
}

fn detect_default_address(
    snapshot: Option<&WanSnapshot>,
    detections: &[WanDetection],
    detected_at: u64,
) -> DdnsAddressSnapshot {
    let default4 = command_text("ip", &["-4", "route", "show", "default"])
        .ok()
        .and_then(|text| default_interface(&text));
    let default6 = command_text("ip", &["-6", "route", "show", "default"])
        .ok()
        .and_then(|text| default_interface(&text));
    let candidates4 = command_text("ip", &["-4", "addr", "show"])
        .map(|text| parse_ipv4(&text))
        .unwrap_or_default();
    let candidates6 = command_text("ip", &["-6", "addr", "show", "scope", "global"])
        .map(|text| parse_ipv6(&text))
        .unwrap_or_default();
    let external4 = default_family_detection(snapshot, detections, WanFamily::V4);
    let external6 = default_family_detection(snapshot, detections, WanFamily::V6);

    let (detected_ipv4, ipv4_state, ipv4_source) = if let Some((ip, source)) = external4.external {
        (ip.to_string(), "public".into(), source)
    } else if external4.allow_local_fallback {
        choose_ipv4(&candidates4, default4.as_deref())
    } else {
        (
            String::new(),
            "unavailable".into(),
            external4.unavailable_source,
        )
    };
    let (detected_ipv6, ipv6_state, ipv6_source) = if let Some((ip, source)) = external6.external {
        (ip.to_string(), "public".into(), source)
    } else if external6.allow_local_fallback {
        let route6 = command_text("ip", &["-6", "route", "get", "2001:4860:4860::8888"])
            .ok()
            .and_then(|text| parse_ipv6_route_get(&text));
        let topology = openwrt_topology(default6.as_deref());
        let chosen_local_ipv6 = choose_ipv6(&candidates6, &topology);
        select_ipv6(chosen_local_ipv6, route6, None, &candidates6)
    } else {
        (
            String::new(),
            "unavailable".into(),
            external6.unavailable_source,
        )
    };

    DdnsAddressSnapshot {
        detected_ipv4,
        detected_ipv6,
        ipv4_state,
        ipv6_state,
        ipv4_source,
        ipv6_source,
        detected_at,
    }
}

fn command_text(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        anyhow::bail!("{} {:?} exited with {}", program, args, output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_interface(text: &str) -> Option<String> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    fields
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .map(|pair| pair[1].split('@').next().unwrap_or(pair[1]).to_string())
}

fn parse_ipv4(text: &str) -> Vec<Candidate4> {
    let mut interface = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if !line.starts_with(' ') && !line.starts_with('\t') {
            interface = line
                .split(':')
                .nth(1)
                .and_then(|value| value.split_whitespace().next())
                .map(|value| value.split('@').next().unwrap_or(value))
                .unwrap_or("")
                .to_string();
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.first() != Some(&"inet") {
            continue;
        }
        let Some(raw) = fields.get(1).and_then(|value| value.split('/').next()) else {
            continue;
        };
        if let Ok(ip) = raw.parse::<Ipv4Addr>() {
            out.push(Candidate4 {
                ip,
                interface: interface.clone(),
            });
        }
    }
    out
}

fn parse_ipv6(text: &str) -> Vec<Candidate6> {
    let mut interface = String::new();
    let mut interface_up = false;
    let mut out: Vec<Candidate6> = Vec::new();
    let mut last_candidate: Option<usize> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let is_interface_line = line
            .split_once(':')
            .is_some_and(|(index, _)| index.trim().parse::<u32>().is_ok());
        if is_interface_line {
            last_candidate = None;
            interface = line
                .split(':')
                .nth(1)
                .and_then(|value| value.split_whitespace().next())
                .map(|value| value.split('@').next().unwrap_or(value))
                .unwrap_or("")
                .to_string();
            interface_up = line
                .split_once('<')
                .and_then(|(_, rest)| rest.split_once('>'))
                .map(|(flags, _)| flags.split(',').any(|flag| flag == "UP"))
                .unwrap_or_else(|| line.contains(" state UP "));
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.first() == Some(&"valid_lft") {
            if let Some(index) = last_candidate {
                if fields
                    .windows(2)
                    .any(|pair| pair == ["valid_lft", "0sec"] || pair == ["preferred_lft", "0sec"])
                {
                    out[index].deprecated = true;
                }
            }
            continue;
        }
        if fields.first() != Some(&"inet6") {
            continue;
        }
        let Some(raw) = fields.get(1).and_then(|value| value.split('/').next()) else {
            continue;
        };
        let Ok(ip) = raw.parse::<Ipv6Addr>() else {
            continue;
        };
        out.push(Candidate6 {
            ip,
            interface: interface.clone(),
            interface_up,
            temporary: fields.contains(&"temporary"),
            deprecated: fields.contains(&"deprecated"),
            tentative: fields.contains(&"tentative"),
        });
        last_candidate = Some(out.len() - 1);
    }
    out
}

fn parse_ipv6_route_get(text: &str) -> Option<Candidate6> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    let ip = fields
        .windows(2)
        .find(|pair| pair[0] == "src")
        .and_then(|pair| pair[1].parse::<Ipv6Addr>().ok())?;
    let interface = fields
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .map(|pair| pair[1].split('@').next().unwrap_or(pair[1]).to_string())?;
    Some(Candidate6 {
        ip,
        interface,
        interface_up: true,
        temporary: false,
        deprecated: false,
        tentative: false,
    })
}

fn select_ipv6(
    local: (String, String, String),
    route: Option<Candidate6>,
    external: Option<(Ipv6Addr, String)>,
    candidates: &[Candidate6],
) -> (String, String, String) {
    let local = if local.1 == "public" && !local.2.starts_with("delegated-lan:") {
        local
    } else {
        route
            .filter(ipv6_public_candidate)
            .map(|candidate| {
                (
                    candidate.ip.to_string(),
                    "public".into(),
                    format!("route-src:{}", candidate.interface),
                )
            })
            .unwrap_or(local)
    };
    if local.1 == "public" {
        local
    } else if let Some((ip, source)) = external {
        let matches_local = candidates
            .iter()
            .any(|candidate| ipv6_public_candidate(candidate) && candidate.ip == ip);
        if matches_local {
            (ip.to_string(), "public".into(), source)
        } else {
            (String::new(), "ambiguous".into(), source)
        }
    } else {
        local
    }
}

fn virtual_interface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("docker")
        || lower.starts_with("veth")
        || lower.starts_with("virbr")
        || lower.starts_with("tun")
        || lower.starts_with("tap")
        || lower.starts_with("wg")
        || lower.starts_with("tailscale")
        || lower.starts_with("zt")
}

fn ipv4_public(ip: Ipv4Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_private()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_unspecified()
        && !ipv4_cgnat(ip)
}

fn ipv4_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn ipv6_ula(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xfe00 == 0xfc00
}

fn ipv6_public(ip: Ipv6Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_unicast_link_local()
        && !ipv6_ula(ip)
}

fn ipv6_public_candidate(candidate: &Candidate6) -> bool {
    ipv6_public(candidate.ip)
        && candidate.interface_up
        && !candidate.temporary
        && !candidate.deprecated
        && !candidate.tentative
        && !virtual_interface(&candidate.interface)
}

fn choose_ipv4(candidates: &[Candidate4], default_if: Option<&str>) -> (String, String, String) {
    let cgnat = candidates
        .iter()
        .any(|candidate| ipv4_cgnat(candidate.ip) && !virtual_interface(&candidate.interface));
    let mut public: Vec<&Candidate4> = candidates
        .iter()
        .filter(|candidate| ipv4_public(candidate.ip) && !virtual_interface(&candidate.interface))
        .collect();
    if let Some(iface) = default_if {
        let preferred: Vec<&Candidate4> = public
            .iter()
            .copied()
            .filter(|candidate| candidate.interface == iface)
            .collect();
        if preferred.len() == 1 {
            let candidate = preferred[0];
            return (
                candidate.ip.to_string(),
                "public".into(),
                format!("default-route:{}", iface),
            );
        }
        if preferred.is_empty() {
            let state = if cgnat {
                "cgnat"
            } else if public.is_empty() {
                "unavailable"
            } else {
                "ambiguous"
            };
            return (
                String::new(),
                state.into(),
                format!("default-route:{}", iface),
            );
        }
        public = preferred;
    }
    match public.as_slice() {
        [candidate] => (
            candidate.ip.to_string(),
            "public".into(),
            format!("generic:{}", candidate.interface),
        ),
        [] if cgnat => (String::new(), "cgnat".into(), "generic".into()),
        [] => (String::new(), "unavailable".into(), "generic".into()),
        _ => (String::new(), "ambiguous".into(), "generic".into()),
    }
}

fn choose_ipv6(
    candidates: &[Candidate6],
    topology: &InterfaceTopology,
) -> (String, String, String) {
    let stable: Vec<&Candidate6> = candidates
        .iter()
        .filter(|candidate| ipv6_public_candidate(candidate))
        .collect();
    let upstream: Vec<&Candidate6> = stable
        .iter()
        .copied()
        .filter(|candidate| topology.role_for(&candidate.interface) == InterfaceRole::Upstream)
        .collect();
    if let [candidate] = upstream.as_slice() {
        return (
            candidate.ip.to_string(),
            "public".into(),
            format!("wan-interface:{}", candidate.interface),
        );
    }
    if upstream.len() > 1 {
        return (String::new(), "ambiguous".into(), "upstream".into());
    }
    let bridge_management: Vec<&Candidate6> = stable
        .iter()
        .copied()
        .filter(|candidate| {
            topology.role_for(&candidate.interface) == InterfaceRole::BridgeManagement
        })
        .collect();
    if let [candidate] = bridge_management.as_slice() {
        return (
            candidate.ip.to_string(),
            "public".into(),
            format!("bridge-management:{}", candidate.interface),
        );
    }
    if bridge_management.len() > 1 {
        return (
            String::new(),
            "ambiguous".into(),
            "bridge-management".into(),
        );
    }
    let downstream: Vec<&Candidate6> = stable
        .iter()
        .copied()
        .filter(|candidate| topology.role_for(&candidate.interface) == InterfaceRole::Downstream)
        .collect();
    match downstream.as_slice() {
        [candidate] => (
            candidate.ip.to_string(),
            "public".into(),
            format!("delegated-lan:{}", candidate.interface),
        ),
        [_first, _second, ..] => (String::new(), "ambiguous".into(), "delegated-lan".into()),
        [] => {
            let unknown: Vec<&Candidate6> = stable
                .iter()
                .copied()
                .filter(|candidate| {
                    topology.role_for(&candidate.interface) == InterfaceRole::Unknown
                })
                .collect();
            match unknown.as_slice() {
                [candidate] => (
                    candidate.ip.to_string(),
                    "public".into(),
                    format!("generic:{}", candidate.interface),
                ),
                [] if stable.is_empty() => (String::new(), "unavailable".into(), "generic".into()),
                [] => (String::new(), "ambiguous".into(), "generic".into()),
                _ => (String::new(), "ambiguous".into(), "generic".into()),
            }
        }
    }
}

fn generic_topology(default_interface: Option<&str>) -> InterfaceTopology {
    let mut topology = InterfaceTopology::default();
    if let Some(interface) = default_interface {
        let role = if interface_is_bridge(interface) {
            InterfaceRole::BridgeManagement
        } else {
            InterfaceRole::Upstream
        };
        topology.set_role(interface, role);
    }
    topology
}

fn interface_is_bridge(interface: &str) -> bool {
    Path::new("/sys/class/net")
        .join(interface)
        .join("bridge")
        .is_dir()
}

fn json_bool(value: Option<&Value>) -> bool {
    value
        .and_then(|item| {
            item.as_bool()
                .or_else(|| item.as_u64().map(|number| number != 0))
        })
        .unwrap_or(false)
}

fn json_nonempty(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(items)) => !items.is_empty(),
        Some(Value::String(text)) => !text.trim().is_empty(),
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_u64().is_some_and(|number| number != 0),
        _ => false,
    }
}

fn json_default_route(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return false;
    };
    match value {
        Value::Array(items) => items.iter().any(|item| json_default_route(Some(item))),
        Value::Object(item) => {
            if json_bool(item.get("default")) {
                return true;
            }
            let destination = ["target", "dest", "address", "prefix"]
                .iter()
                .find_map(|key| item.get(*key).and_then(Value::as_str));
            let mask_zero = ["mask", "prefixLength", "prefix_length"]
                .iter()
                .find_map(|key| item.get(*key).and_then(Value::as_u64))
                .is_some_and(|mask| mask == 0);
            destination.is_some_and(|target| {
                target == "::" || target == "::/0" || target == "0.0.0.0" || target == "0.0.0.0/0"
            }) && (mask_zero
                || destination.is_some_and(|target| {
                    target.ends_with("/0") || target == "::" || target == "0.0.0.0"
                }))
        }
        Value::String(text) => matches!(text.trim(), "::/0" | "0.0.0.0/0"),
        _ => false,
    }
}

fn parse_openwrt_topology(text: &str, default_interface: Option<&str>) -> InterfaceTopology {
    let mut topology = InterfaceTopology::default();
    let Ok(root) = serde_json::from_str::<Value>(text) else {
        return topology;
    };
    let Some(interfaces) = root.get("interface").and_then(Value::as_array) else {
        return topology;
    };
    for item in interfaces {
        let logical = item.get("interface").and_then(Value::as_str).unwrap_or("");
        let device = item.get("device").and_then(Value::as_str).unwrap_or("");
        let l3_device = item.get("l3_device").and_then(Value::as_str).unwrap_or("");
        let up = json_bool(item.get("up"));
        if logical.is_empty() && device.is_empty() && l3_device.is_empty() {
            continue;
        }
        let matches_default = default_interface.is_some_and(|default| {
            [logical, device, l3_device]
                .iter()
                .any(|candidate| candidate == &default)
        }) || json_bool(item.get("default"))
            || json_default_route(item.get("route").or_else(|| item.get("routes")));
        let has_assignment = json_nonempty(item.get("ipv6-prefix-assignment"));
        let has_prefix = json_nonempty(item.get("ipv6-prefix"));
        let bridge_hint = json_bool(item.get("bridge"))
            || json_bool(item.get("is_bridge"))
            || item
                .get("type")
                .or_else(|| item.get("device_type"))
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("bridge"));
        let role = if !up {
            InterfaceRole::Unknown
        } else if matches_default && (bridge_hint || has_assignment) {
            InterfaceRole::BridgeManagement
        } else if matches_default || (has_prefix && !has_assignment) {
            InterfaceRole::Upstream
        } else if has_assignment {
            InterfaceRole::Downstream
        } else {
            InterfaceRole::Unknown
        };
        for alias in [logical, device, l3_device] {
            topology.set_role(alias, role);
        }
    }
    if let Some(default) = default_interface {
        if !topology.roles.contains_key(default) {
            let fallback = if interface_is_bridge(default) {
                InterfaceRole::BridgeManagement
            } else {
                InterfaceRole::Upstream
            };
            topology.set_role(default, fallback);
        }
    }
    topology
}

fn openwrt_topology(default_interface: Option<&str>) -> InterfaceTopology {
    let Ok(text) = command_text("ubus", &["call", "network.interface", "dump"]) else {
        return generic_topology(default_interface);
    };
    let mut topology = parse_openwrt_topology(&text, default_interface);
    if let Some(default) = default_interface {
        if interface_is_bridge(default) {
            topology
                .roles
                .insert(default.to_string(), InterfaceRole::BridgeManagement);
        }
    }
    topology
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(ip: &str, interface: &str) -> Candidate4 {
        Candidate4 {
            ip: ip.parse().unwrap(),
            interface: interface.into(),
        }
    }

    fn v6(
        ip: &str,
        interface: &str,
        temporary: bool,
        deprecated: bool,
        tentative: bool,
    ) -> Candidate6 {
        Candidate6 {
            ip: ip.parse().unwrap(),
            interface: interface.into(),
            interface_up: true,
            temporary,
            deprecated,
            tentative,
        }
    }

    fn topology(
        _default_interface: Option<&str>,
        roles: &[(&str, InterfaceRole)],
    ) -> InterfaceTopology {
        let mut result = InterfaceTopology::default();
        for (interface, role) in roles {
            result.set_role(interface, *role);
        }
        result
    }

    #[test]
    fn public_ipv4_prefers_default_route() {
        assert_eq!(
            choose_ipv4(
                &[v4("192.168.1.1", "br-lan"), v4("198.51.100.9", "pppoe0")],
                Some("pppoe0")
            )
            .1,
            "public"
        );
        assert_eq!(
            choose_ipv4(
                &[v4("192.168.1.1", "br-lan"), v4("198.51.100.9", "pppoe0")],
                Some("pppoe0")
            )
            .0,
            "198.51.100.9"
        );
        assert_eq!(
            choose_ipv4(&[v4("198.51.100.9", "eth0")], None).2,
            "generic:eth0"
        );
    }

    #[test]
    fn private_and_cgnat_ipv4_are_not_publishable() {
        assert_eq!(
            choose_ipv4(&[v4("192.168.1.1", "eth0")], Some("eth0")).1,
            "unavailable"
        );
        assert_eq!(
            choose_ipv4(&[v4("100.64.1.2", "eth0")], Some("eth0")).1,
            "cgnat"
        );
        assert_eq!(
            choose_ipv4(&[v4("100.127.255.254", "eth0")], Some("eth0")).1,
            "cgnat"
        );
    }

    #[test]
    fn stable_ipv6_wins_and_bad_flags_are_excluded() {
        let candidates = vec![
            v6("2001:db8::1", "wan0", true, false, false),
            v6("2001:db8::2", "wan0", false, true, false),
            v6("2001:db8::3", "wan0", false, false, false),
            v6("fe80::1", "wan0", false, false, false),
        ];
        let topology = topology(Some("wan0"), &[("wan0", InterfaceRole::Upstream)]);
        assert_eq!(choose_ipv6(&candidates, &topology).0, "2001:db8::3");
        assert_eq!(choose_ipv6(&candidates, &topology).2, "wan-interface:wan0");
    }

    #[test]
    fn wan_ipv6_beats_delegated_lan_and_external_result() {
        let candidates = vec![
            v6(
                "2409:8a50:2e04:30a:cc3c:7a5c:34ef:fe62",
                "pppoe-wan",
                false,
                false,
                false,
            ),
            v6("2409:8a50:2e40:8dc0::1", "br-lan", false, false, false),
        ];
        let topology = topology(
            Some("pppoe-wan"),
            &[
                ("pppoe-wan", InterfaceRole::Upstream),
                ("br-lan", InterfaceRole::Downstream),
            ],
        );
        let local = choose_ipv6(&candidates, &topology);
        let selected = select_ipv6(
            local,
            None,
            Some((
                "2409:8a50:2e40:8dc0::1".parse().unwrap(),
                "egress-http:api6.ipify.org".into(),
            )),
            &candidates,
        );
        assert_eq!(selected.0, "2409:8a50:2e04:30a:cc3c:7a5c:34ef:fe62");
        assert_eq!(selected.2, "wan-interface:pppoe-wan");
    }

    #[test]
    fn ipv6_preferred_lifetime_zero_is_deprecated() {
        let candidates = parse_ipv6(
            "2: wan0@if3: <UP>\n    inet6 2001:db8::4/64 scope global\n       valid_lft 0sec preferred_lft 0sec\n",
        );
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].deprecated);
        let topology = topology(Some("wan0"), &[("wan0", InterfaceRole::Upstream)]);
        assert_eq!(choose_ipv6(&candidates, &topology).1, "unavailable");
    }

    #[test]
    fn ipv6_down_temporary_and_tentative_addresses_are_excluded() {
        let candidates = parse_ipv6(
            "2: pppoe-wan@if3: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP>\n\
             inet6 2001:db8::1/64 scope global temporary\n\
             inet6 2001:db8::2/64 scope global tentative\n\
             valid_lft 0sec preferred_lft 0sec\n\
             3: wan6: <POINTOPOINT,MULTICAST,NOARP>\n\
             inet6 2001:db8::3/64 scope global\n",
        );
        assert_eq!(candidates.len(), 3);
        assert!(candidates[0].temporary);
        assert!(candidates[1].tentative);
        assert!(candidates[1].deprecated);
        assert!(!candidates[2].interface_up);
        let topology = topology(Some("wan6"), &[("wan6", InterfaceRole::Upstream)]);
        assert_eq!(choose_ipv6(&candidates, &topology).1, "unavailable");
    }

    #[test]
    fn ipv6_route_get_source_is_parsed_with_interface() {
        let candidate = parse_ipv6_route_get(
            "2001:4860:4860::8888 from :: via fe80::1 dev pppoe-wan src 2409:8a50::123 metric 1024",
        )
        .unwrap();
        assert_eq!(candidate.ip, "2409:8a50::123".parse::<Ipv6Addr>().unwrap());
        assert_eq!(candidate.interface, "pppoe-wan");
        assert!(ipv6_public_candidate(&candidate));
    }

    #[test]
    fn permission_denied_route_get_is_just_a_missing_fallback() {
        assert!(parse_ipv6_route_get("RTNETLINK answers: Permission denied").is_none());
    }

    #[test]
    fn wan_interface_is_preferred_when_default_route_points_to_delegated_lan() {
        let candidates = vec![
            v6("2409:8a50:2e04::10", "pppoe-wan", false, false, false),
            v6("2409:8a50:2e40::1", "br-lan", false, false, false),
        ];
        assert_eq!(
            choose_ipv6(
                &candidates,
                &topology(
                    Some("br-lan"),
                    &[
                        ("pppoe-wan", InterfaceRole::Upstream),
                        ("br-lan", InterfaceRole::Downstream),
                    ],
                ),
            ),
            (
                "2409:8a50:2e04::10".into(),
                "public".into(),
                "wan-interface:pppoe-wan".into()
            )
        );
    }

    #[test]
    fn openwrt_runtime_roles_use_topology_not_interface_names() {
        let topology = parse_openwrt_topology(
            r#"{
                "interface": [
                    {
                        "interface": "uplink-logical",
                        "device": "lower-device",
                        "l3_device": "routed-device",
                        "proto": "pppoe",
                        "up": true,
                        "ipv6-address": [{"address": "2409:8a50:2e04::10"}],
                        "ipv6-prefix": [{"address": "2409:8a50:2e04::", "mask": 64}]
                    },
                    {
                        "interface": "downstream-logical",
                        "device": "bridge-device",
                        "l3_device": "bridge-device",
                        "proto": "static",
                        "up": true,
                        "ipv6-address": [{"address": "2409:8a50:2e40::1"}],
                        "ipv6-prefix-assignment": [{"address": "2409:8a50:2e40::", "mask": 64}]
                    }
                ]
            }"#,
            Some("routed-device"),
        );
        assert_eq!(topology.role_for("routed-device"), InterfaceRole::Upstream);
        assert_eq!(
            topology.role_for("bridge-device"),
            InterfaceRole::Downstream
        );
        let candidates = vec![
            v6("2409:8a50:2e04::10", "routed-device", false, false, false),
            v6("2409:8a50:2e40::1", "bridge-device", false, false, false),
        ];
        assert_eq!(
            choose_ipv6(&candidates, &topology),
            (
                "2409:8a50:2e04::10".into(),
                "public".into(),
                "wan-interface:routed-device".into()
            )
        );
    }

    #[test]
    fn bridge_ap_mode_uses_management_bridge_without_upstream() {
        let topology = parse_openwrt_topology(
            r#"{
                "interface": [{
                    "interface": "management-logical",
                    "device": "management-device",
                    "l3_device": "management-device",
                    "proto": "dhcp",
                    "up": true,
                    "bridge": true,
                    "ipv6-address": [{"address": "2001:db8:10::2"}]
                }]
            }"#,
            Some("management-device"),
        );
        let candidates = vec![v6(
            "2001:db8:10::2",
            "management-device",
            false,
            false,
            false,
        )];
        assert_eq!(
            choose_ipv6(&candidates, &topology),
            (
                "2001:db8:10::2".into(),
                "public".into(),
                "bridge-management:management-device".into()
            )
        );
    }

    #[test]
    fn unmapped_external_ipv6_is_ambiguous_not_publishable() {
        let external = Some((
            "2001:db8:20::9".parse().unwrap(),
            "egress-http:api6.ipify.org".into(),
        ));
        assert_eq!(
            select_ipv6(
                (String::new(), "unavailable".into(), "generic".into()),
                None,
                external,
                &[v6("2001:db8:20::8", "eth0", false, false, false)],
            ),
            (
                String::new(),
                "ambiguous".into(),
                "egress-http:api6.ipify.org".into()
            )
        );
    }

    #[test]
    fn ula_ipv6_is_not_publishable_even_when_global_scope_is_reported() {
        let candidate = v6("fd00::10", "br-lan", false, false, false);
        assert!(ipv6_ula(candidate.ip));
        assert!(!ipv6_public_candidate(&candidate));
        assert_eq!(
            choose_ipv6(&[candidate], &topology(Some("br-lan"), &[])).1,
            "unavailable"
        );
    }

    #[test]
    fn delegated_lan_is_used_when_no_default_route_address_exists() {
        let candidates = vec![v6("2001:db8:1::10", "br-lan", false, false, false)];
        assert_eq!(
            choose_ipv6(
                &candidates,
                &topology(
                    Some("pppoe0"),
                    &[
                        ("pppoe0", InterfaceRole::Upstream),
                        ("br-lan", InterfaceRole::Downstream),
                    ],
                ),
            ),
            (
                "2001:db8:1::10".into(),
                "public".into(),
                "delegated-lan:br-lan".into()
            )
        );
    }

    #[test]
    fn ambiguous_and_virtual_addresses_are_safe() {
        assert_eq!(
            choose_ipv4(
                &[v4("198.51.100.1", "docker0"), v4("198.51.100.2", "eth0")],
                None
            )
            .0,
            "198.51.100.2"
        );
        assert_eq!(
            choose_ipv6(
                &[
                    v6("2001:db8::1", "eth0", false, false, false),
                    v6("2001:db8::2", "eth1", false, false, false),
                ],
                &topology(None, &[]),
            )
            .1,
            "ambiguous"
        );
        assert_eq!(
            choose_ipv4(&[v4("192.168.1.1", "docker0")], None).1,
            "unavailable"
        );
        assert_eq!(
            choose_ipv4(
                &[v4("198.51.100.1", "eth1"), v4("192.168.1.1", "eth0")],
                Some("eth0")
            )
            .1,
            "ambiguous"
        );
    }

    fn family_detection(
        source: &str,
        detected: &str,
        verification: WanVerification,
    ) -> FamilyDetection {
        FamilyDetection {
            source: Some(source.parse().unwrap()),
            detected: Some((detected.parse().unwrap(), "egress-http:test".into())),
            verification,
        }
    }

    fn wan_detection(wan_id: &str, ipv4: FamilyDetection, ipv6: FamilyDetection) -> WanDetection {
        WanDetection {
            wan_id: wan_id.into(),
            ipv4,
            ipv6,
            detected_at: 123,
        }
    }

    #[test]
    fn two_wans_keep_external_addresses_and_sources_separate() {
        let detections = vec![
            wan_detection(
                "wan",
                family_detection("192.0.2.2", "198.51.100.10", WanVerification::Verified),
                family_detection("2001:db8::2", "2001:db8:1::10", WanVerification::Verified),
            ),
            wan_detection(
                "wan1",
                family_detection("198.51.100.2", "198.51.100.20", WanVerification::Verified),
                family_detection("2001:db8:1::2", "2001:db8:2::20", WanVerification::Verified),
            ),
        ];
        let first = detections[0].snapshot();
        let second = detections[1].snapshot();
        assert_eq!(first.wan_id, "wan");
        assert_eq!(first.address.detected_ipv4, "198.51.100.10");
        assert_eq!(first.address.detected_ipv6, "2001:db8:1::10");
        assert_eq!(second.wan_id, "wan1");
        assert_eq!(second.address.detected_ipv4, "198.51.100.20");
        assert_eq!(second.address.detected_ipv6, "2001:db8:2::20");
        assert_ne!(first.address.detected_ipv4, second.address.detected_ipv4);
        assert_ne!(first.address.detected_ipv6, second.address.detected_ipv6);
    }

    #[test]
    fn offline_wan_and_missing_families_are_unavailable_without_fallback() {
        let offline = wan_detection(
            "wan1",
            FamilyDetection::unavailable(),
            FamilyDetection::unavailable(),
        )
        .snapshot();
        assert_eq!(offline.wan_id, "wan1");
        assert_eq!(offline.address.detected_ipv4, "");
        assert_eq!(offline.address.detected_ipv6, "");
        assert_eq!(offline.address.ipv4_state, "unavailable");
        assert_eq!(offline.address.ipv6_state, "unavailable");

        let ipv4_only = wan_detection(
            "wan",
            family_detection("192.0.2.2", "198.51.100.10", WanVerification::Verified),
            FamilyDetection::unavailable(),
        )
        .snapshot();
        assert_eq!(ipv4_only.address.detected_ipv4, "198.51.100.10");
        assert_eq!(ipv4_only.address.detected_ipv6, "");
        assert_eq!(ipv4_only.address.ipv6_state, "unavailable");
    }

    #[test]
    fn unverified_or_mismatched_routes_never_publish_external_or_default() {
        for verification in [WanVerification::Unknown, WanVerification::Mismatch] {
            let detection = wan_detection(
                "wan1",
                family_detection("198.51.100.2", "203.0.113.99", verification),
                FamilyDetection::unavailable(),
            );
            let snapshot = detection.snapshot();
            assert_eq!(snapshot.address.detected_ipv4, "");
            assert_eq!(snapshot.address.ipv4_state, "unavailable");

            let discovered = WanSnapshot {
                wans: Vec::new(),
                default_wan_id_v4: Some("wan1".into()),
                default_wan_id_v6: None,
                observed_at: 123,
                source: "test".into(),
            };
            let default = default_family_detection(
                Some(&discovered),
                std::slice::from_ref(&detection),
                WanFamily::V4,
            );
            assert!(default.external.is_none());
            assert!(!default.allow_local_fallback);
        }
    }

    #[test]
    fn report_serializes_nested_legacy_address_and_wan_samples() {
        let report = DdnsAddressReport {
            address: DdnsAddressSnapshot {
                detected_ipv4: "192.0.2.10".into(),
                ipv4_state: "public".into(),
                detected_at: 123,
                ..DdnsAddressSnapshot::default()
            },
            wans: vec![wan_detection(
                "wan1",
                family_detection("198.51.100.2", "198.51.100.20", WanVerification::Verified),
                FamilyDetection::unavailable(),
            )
            .snapshot()],
            wan_supported: true,
        };
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["wanSupported"], true);
        assert_eq!(value["address"]["detectedIpv4"], "192.0.2.10");
        assert_eq!(value["address"]["detectedAt"], 123);
        assert_eq!(value["wans"][0]["wanId"], "wan1");
        assert_eq!(value["wans"][0]["detectedIpv4"], "198.51.100.20");
        assert_eq!(value["wans"][0]["ipv6State"], "unavailable");
    }
}
