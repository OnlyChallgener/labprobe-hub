//! Generic Linux DDNS address detection.
//!
//! The detector deliberately uses the standard `ip` command first so it can
//! run on OpenWrt and other Linux routers. OpenWrt's ubus output is used only
//! as a read-only topology hint; interface names never decide a role.

use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{timeout, Duration};

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

pub async fn detect() -> DdnsAddressSnapshot {
    let (external_ipv4, external_ipv6) =
        tokio::join!(detect_external_ipv4(), detect_external_ipv6());
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

    let (detected_ipv4, ipv4_state, ipv4_source) = external_ipv4
        .map(|(ip, source)| (ip.to_string(), "public".into(), source))
        .unwrap_or_else(|| choose_ipv4(&candidates4, default4.as_deref()));
    let route6 = command_text("ip", &["-6", "route", "get", "2001:4860:4860::8888"])
        .ok()
        .and_then(|text| parse_ipv6_route_get(&text));
    let topology = openwrt_topology(default6.as_deref());
    let chosen_local_ipv6 = choose_ipv6(&candidates6, &topology);
    let (detected_ipv6, ipv6_state, ipv6_source) =
        select_ipv6(chosen_local_ipv6, route6, external_ipv6, &candidates6);

    DdnsAddressSnapshot {
        detected_ipv4,
        detected_ipv6,
        ipv4_state,
        ipv6_state,
        ipv4_source,
        ipv6_source,
        detected_at: now_epoch(),
    }
}

async fn detect_external_ipv4() -> Option<(Ipv4Addr, String)> {
    timeout(Duration::from_secs(6), async {
        let client = Client::builder()
            .local_address(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .user_agent(concat!("labrelay/", env!("CARGO_PKG_VERSION")))
            .build()
            .ok()?;
        for (name, url) in IPV4_EGRESS_ENDPOINTS {
            let Ok(response) = client.get(url).send().await else {
                continue;
            };
            if !response.status().is_success() {
                continue;
            }
            let Ok(body) = response.text().await else {
                continue;
            };
            let Ok(ip) = body.trim().parse::<Ipv4Addr>() else {
                continue;
            };
            if ipv4_public(ip) {
                return Some((ip, format!("egress-http:{name}")));
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

async fn detect_external_ipv6() -> Option<(Ipv6Addr, String)> {
    timeout(Duration::from_secs(6), async {
        let client = Client::builder()
            .local_address(Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)))
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .user_agent(concat!("labrelay/", env!("CARGO_PKG_VERSION")))
            .build()
            .ok()?;
        for (name, url) in IPV6_EGRESS_ENDPOINTS {
            let Ok(response) = client.get(url).send().await else {
                continue;
            };
            if !response.status().is_success() {
                continue;
            }
            let Ok(body) = response.text().await else {
                continue;
            };
            let Ok(ip) = body.trim().parse::<Ipv6Addr>() else {
                continue;
            };
            if ipv6_public(ip) {
                return Some((ip, format!("egress-http:{name}")));
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
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
        if !line.starts_with(' ') && !line.starts_with('\t') {
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
}
