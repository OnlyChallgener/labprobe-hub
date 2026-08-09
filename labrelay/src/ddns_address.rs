//! Generic Linux DDNS egress-address detection.
//!
//! IPv4 and IPv6 are detected independently. The primary result is the
//! address actually observed on the Internet; local interface/route data is
//! only a fallback so CGNAT/private WAN addresses are never mistaken for an
//! Internet-facing A record. All probes are read-only and use fixed HTTPS
//! endpoints with short timeouts.

use anyhow::Result;
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
    temporary: bool,
    deprecated: bool,
    tentative: bool,
}

pub fn detect() -> DdnsAddressSnapshot {
    // Keep the two address families independent. A broken IPv4 path must not
    // prevent an IPv6-only DDNS record (and vice versa). Running them in
    // parallel also caps the worst-case probe delay on routers with partial
    // connectivity.
    let v4 = std::thread::spawn(detect_ipv4);
    let v6 = std::thread::spawn(detect_ipv6);
    let (detected_ipv4, ipv4_state, ipv4_source) =
        v4.join().unwrap_or_else(|_| local_ipv4_fallback());
    let (detected_ipv6, ipv6_state, ipv6_source) =
        v6.join().unwrap_or_else(|_| local_ipv6_fallback());

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

fn detect_ipv4() -> (String, String, String) {
    for (source, url) in [
        ("ip.sb", "https://api-ipv4.ip.sb/ip"),
        ("ident.me", "https://4.ident.me"),
    ] {
        if let Some(text) = fetch_external_text(url, 4) {
            if let Ok(ip) = text.trim().parse::<Ipv4Addr>() {
                if ipv4_public(ip) {
                    return (
                        ip.to_string(),
                        "public".into(),
                        format!("egress-http:{}", source),
                    );
                }
            }
        }
    }
    local_ipv4_fallback()
}

fn detect_ipv6() -> (String, String, String) {
    for (source, url) in [
        ("ip.sb", "https://api-ipv6.ip.sb/ip"),
        ("ident.me", "https://6.ident.me"),
    ] {
        if let Some(text) = fetch_external_text(url, 6) {
            if let Ok(ip) = text.trim().parse::<Ipv6Addr>() {
                if ipv6_public(ip) {
                    return (
                        ip.to_string(),
                        "public".into(),
                        format!("egress-http:{}", source),
                    );
                }
            }
        }
    }
    local_ipv6_fallback()
}

fn fetch_external_text(url: &str, family: u8) -> Option<String> {
    // curl is preferred when available because it can explicitly bind the
    // requested address family. OpenWrt commonly exposes BusyBox/uclient wget,
    // so keep that as a compatible fallback. Hostnames themselves are
    // family-specific, therefore wget still cannot silently return the wrong
    // family.
    let family_flag = if family == 4 { "-4" } else { "-6" };
    let curl_args = [
        "-fsS",
        "--connect-timeout",
        "2",
        "--max-time",
        "4",
        family_flag,
        url,
    ];
    if let Ok(text) = command_text("curl", &curl_args) {
        if !text.trim().is_empty() {
            return Some(text);
        }
    }

    let wget_args = ["-qO-", "-T", "4", url];
    command_text("wget", &wget_args)
        .ok()
        .filter(|text| !text.trim().is_empty())
}

fn local_ipv4_fallback() -> (String, String, String) {
    let default4 = command_text("ip", &["-4", "route", "show", "default"])
        .ok()
        .and_then(|text| default_interface(&text));
    let candidates4 = command_text("ip", &["-4", "addr", "show"])
        .map(|text| parse_ipv4(&text))
        .unwrap_or_default();
    choose_ipv4(&candidates4, default4.as_deref())
}

fn local_ipv6_fallback() -> (String, String, String) {
    let candidates6 = command_text("ip", &["-6", "addr", "show", "scope", "global"])
        .map(|text| parse_ipv6(&text))
        .unwrap_or_default();

    // `ip route get` performs only a local routing lookup. It does not send a
    // packet to the destination, but it tells us the source IPv6 the kernel
    // would actually choose for Internet traffic. This is a stronger fallback
    // than assuming interfaces are named wan6/br-lan on every vendor firmware.
    if let Ok(text) = command_text(
        "ip",
        &["-6", "route", "get", "2001:4860:4860::8888"],
    ) {
        if let Some((ip, iface)) = parse_route_ipv6_source(&text) {
            let bad_flags = candidates6
                .iter()
                .find(|candidate| candidate.ip == ip)
                .map(|candidate| {
                    candidate.temporary || candidate.deprecated || candidate.tentative
                })
                .unwrap_or(false);
            if ipv6_public(ip) && !bad_flags && !virtual_interface(&iface) {
                return (
                    ip.to_string(),
                    "public".into(),
                    format!("route-src:{}", iface),
                );
            }
        }
    }

    let default6 = command_text("ip", &["-6", "route", "show", "default"])
        .ok()
        .and_then(|text| default_interface(&text));
    let openwrt_delegated_ifaces = openwrt_delegated_interfaces();
    choose_ipv6(
        &candidates6,
        default6.as_deref(),
        &openwrt_delegated_ifaces,
    )
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

fn parse_route_ipv6_source(text: &str) -> Option<(Ipv6Addr, String)> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    let iface = fields
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .map(|pair| pair[1].split('@').next().unwrap_or(pair[1]).to_string())?;
    let raw = fields
        .windows(2)
        .find(|pair| pair[0] == "src")
        .map(|pair| pair[1])?;
    let ip = raw.parse::<Ipv6Addr>().ok()?;
    Some((ip, iface))
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
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.first() == Some(&"valid_lft") {
            if let Some(index) = last_candidate {
                if fields.windows(2).any(|pair| {
                    pair == ["valid_lft", "0sec"] || pair == ["preferred_lft", "0sec"]
                }) {
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
            temporary: fields.contains(&"temporary"),
            deprecated: fields.contains(&"deprecated"),
            tentative: fields.contains(&"tentative"),
        });
        last_candidate = Some(out.len() - 1);
    }
    out
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

fn ipv6_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn ipv6_public(ip: Ipv6Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_unicast_link_local()
        && !ipv6_unique_local(ip)
}

fn choose_ipv4(
    candidates: &[Candidate4],
    default_if: Option<&str>,
) -> (String, String, String) {
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
    default_if: Option<&str>,
    delegated_ifaces: &[String],
) -> (String, String, String) {
    let stable: Vec<&Candidate6> = candidates
        .iter()
        .filter(|candidate| {
            ipv6_public(candidate.ip)
                && !candidate.temporary
                && !candidate.deprecated
                && !candidate.tentative
                && !virtual_interface(&candidate.interface)
        })
        .collect();
    if let Some(iface) = default_if {
        let preferred: Vec<&Candidate6> = stable
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
        if !preferred.is_empty() {
            return (
                String::new(),
                "ambiguous".into(),
                format!("default-route:{}", iface),
            );
        }
    }
    let delegated: Vec<&Candidate6> = stable
        .iter()
        .copied()
        .filter(|candidate| {
            delegated_ifaces
                .iter()
                .any(|iface| iface == &candidate.interface)
        })
        .collect();
    match delegated.as_slice() {
        [candidate] => (
            candidate.ip.to_string(),
            "public".into(),
            format!("delegated-lan:{}", candidate.interface),
        ),
        [] if stable.is_empty() => (String::new(), "unavailable".into(), "generic".into()),
        [] => (String::new(), "ambiguous".into(), "generic".into()),
        _ => (String::new(), "ambiguous".into(), "delegated-lan".into()),
    }
}

fn openwrt_delegated_interfaces() -> Vec<String> {
    let Ok(text) = command_text("ubus", &["call", "network.interface", "dump"]) else {
        return Vec::new();
    };
    let Ok(root) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let Some(interfaces) = root
        .get("interface")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    interfaces
        .iter()
        .filter(|item| {
            ["ipv6-prefix-assignment", "ipv6-prefix"].iter().any(|key| {
                item.get(*key).is_some_and(|value| match value {
                    serde_json::Value::Array(items) => !items.is_empty(),
                    serde_json::Value::Object(values) => !values.is_empty(),
                    serde_json::Value::String(text) => !text.trim().is_empty(),
                    _ => true,
                })
            })
        })
        .filter_map(|item| {
            item.get("l3_device")
                .or_else(|| item.get("device"))
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_string)
        .collect()
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
            temporary,
            deprecated,
            tentative,
        }
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
    fn private_and_cgnat_ipv4_are_not_publishable_as_local_fallback() {
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
            v6("2606:4700::1", "wan0", true, false, false),
            v6("2606:4700::2", "wan0", false, true, false),
            v6("2606:4700::3", "wan0", false, false, false),
            v6("fe80::1", "wan0", false, false, false),
        ];
        assert_eq!(
            choose_ipv6(&candidates, Some("wan0"), &[]).0,
            "2606:4700::3"
        );
        assert_eq!(
            choose_ipv6(&candidates, Some("wan0"), &[]).2,
            "default-route:wan0"
        );
    }

    #[test]
    fn ipv6_preferred_lifetime_zero_is_deprecated() {
        let candidates = parse_ipv6(
            "2: wan0@if3: <UP>\n    inet6 2606:4700::4/64 scope global\n       valid_lft 0sec preferred_lft 0sec\n",
        );
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].deprecated);
        assert_eq!(choose_ipv6(&candidates, Some("wan0"), &[]).1, "unavailable");
    }

    #[test]
    fn delegated_lan_is_used_when_no_default_route_address_exists() {
        let candidates = vec![v6("2409:8a50:1::10", "br-lan", false, false, false)];
        assert_eq!(
            choose_ipv6(&candidates, Some("pppoe0"), &["br-lan".into()]),
            (
                "2409:8a50:1::10".into(),
                "public".into(),
                "delegated-lan:br-lan".into()
            )
        );
    }

    #[test]
    fn route_source_ipv6_is_parsed() {
        assert_eq!(
            parse_route_ipv6_source(
                "2001:4860:4860::8888 from :: via fe80::1 dev br-lan src 2409:8a50::123 metric 1024"
            ),
            Some(("2409:8a50::123".parse().unwrap(), "br-lan".into()))
        );
    }

    #[test]
    fn unique_local_ipv6_is_not_public() {
        assert!(!ipv6_public("fd00::1".parse().unwrap()));
        assert!(ipv6_public("2409:8a50::1".parse().unwrap()));
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
                    v6("2606:4700::1", "eth0", false, false, false),
                    v6("2606:4700::2", "eth1", false, false, false)
                ],
                None,
                &[]
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
