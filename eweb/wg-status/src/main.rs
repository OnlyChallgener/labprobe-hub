//! One-shot read-only Generic Netlink telemetry. Ignore all secret attributes.
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
fn u16n(b: &[u8]) -> Result<u16, ()> {
    Ok(u16::from_ne_bytes(
        b.get(..2).ok_or(())?.try_into().map_err(|_| ())?,
    ))
}
fn u32n(b: &[u8]) -> Result<u32, ()> {
    Ok(u32::from_ne_bytes(
        b.get(..4).ok_or(())?.try_into().map_err(|_| ())?,
    ))
}
fn u64n(b: &[u8]) -> Result<u64, ()> {
    Ok(u64::from_ne_bytes(
        b.get(..8).ok_or(())?.try_into().map_err(|_| ())?,
    ))
}
fn aligned(n: usize) -> usize {
    (n + 3) & !3
}
fn attrs(mut b: &[u8]) -> Result<Vec<(u16, &[u8])>, ()> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let n = u16n(b)? as usize;
        if n < 4 || aligned(n) > b.len() {
            return Err(());
        }
        out.push((u16n(&b[2..])? & 0x3fff, &b[4..n]));
        b = &b[aligned(n)..];
    }
    Ok(out)
}
fn nla(kind: u16, v: &[u8]) -> Vec<u8> {
    let mut b = vec![0; aligned(v.len() + 4)];
    b[..2].copy_from_slice(&((v.len() + 4) as u16).to_ne_bytes());
    b[2..4].copy_from_slice(&kind.to_ne_bytes());
    b[4..4 + v.len()].copy_from_slice(v);
    b
}
fn endpoint(b: &[u8]) -> Result<String, ()> {
    let port = u16::from_be_bytes(b.get(2..4).ok_or(())?.try_into().map_err(|_| ())?);
    match u16n(b)? {
        2 if b.len() >= 16 => Ok(format!(
            "{}:{}",
            Ipv4Addr::new(b[4], b[5], b[6], b[7]),
            port
        )),
        10 if b.len() >= 28 => {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).map_err(|_| ())?);
            let scope = u32n(&b[24..])?;
            Ok(if scope == 0 {
                format!("[{}]:{}", ip, port)
            } else {
                format!("[{}%{}]:{}", ip, scope, port)
            })
        }
        _ => Err(()),
    }
}
fn allowed(b: &[u8]) -> Result<Vec<String>, ()> {
    let mut out = Vec::new();
    for (_, row) in attrs(b)? {
        let (mut ip, mut cidr) = (None, None);
        for (k, v) in attrs(row)? {
            match k {
                2 if v.len() == 4 => ip = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string()),
                2 if v.len() == 16 => {
                    ip = Some(Ipv6Addr::from(<[u8; 16]>::try_from(v).map_err(|_| ())?).to_string())
                }
                3 if v.len() == 1 => cidr = Some(v[0]),
                _ => {}
            }
        }
        if let (Some(ip), Some(cidr)) = (ip, cidr) {
            out.push(format!("{}/{}", ip, cidr));
        }
    }
    Ok(out)
}
#[derive(Default)]
struct Snapshot {
    public_key: Option<String>,
    port: Option<u16>,
    peers: BTreeMap<String, Value>,
}
impl Snapshot {
    fn parse(&mut self, b: &[u8]) -> Result<(), ()> {
        for (k, v) in attrs(b)? {
            match k {
                4 if v.len() == 32 => self.public_key = Some(base64::encode(v)),
                6 => self.port = Some(u16n(v)?),
                8 => {
                    for (_, peer) in attrs(v)? {
                        let mut key = None;
                        let mut row = json!({});
                        for (k, v) in attrs(peer)? {
                            match k {
                                1 if v.len() == 32 => key = Some(base64::encode(v)),
                                4 => row["endpoint"] = json!(endpoint(v)?),
                                6 => {
                                    let at = u64n(v)?;
                                    row["latestHandshakeAt"] =
                                        if at > 0 { json!(at) } else { Value::Null };
                                }
                                7 => row["rxBytes"] = json!(u64n(v)?),
                                8 => row["txBytes"] = json!(u64n(v)?),
                                9 => row["allowedIps"] = json!(allowed(v)?),
                                // Includes UNSPEC padding, preshared keys and vendor fields.
                                _ => {}
                            }
                        }
                        if let Some(key) = key {
                            let existing = self
                                .peers
                                .entry(key.clone())
                                .or_insert_with(|| json!({"publicKey":key}));
                            for (field, value) in row.as_object().ok_or(())? {
                                if field == "allowedIps" {
                                    let mut ips =
                                        existing[field].as_array().cloned().unwrap_or_default();
                                    for ip in value.as_array().ok_or(())? {
                                        if !ips.contains(ip) {
                                            ips.push(ip.clone());
                                        }
                                    }
                                    existing[field] = json!(ips);
                                } else {
                                    existing[field] = value.clone();
                                }
                            }
                            if self.peers.len() > 64 {
                                return Err(());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
    fn json(self, name: &str) -> Value {
        let latest = self
            .peers
            .values()
            .filter_map(|p| p["latestHandshakeAt"].as_u64())
            .max();
        json!({"ok":true,"name":name,"publicKey":self.public_key,"listenPort":self.port,"latestHandshakeAt":latest,"peers":self.peers.into_values().collect::<Vec<_>>(),"receivedEpoch":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()})
    }
}
#[cfg(target_os = "linux")]
fn query(
    fd: i32,
    family: u16,
    cmd: u8,
    seq: u32,
    body: &[u8],
    dump: bool,
) -> Result<Vec<Vec<u8>>, ()> {
    let mut req = vec![0u8; 20 + body.len()];
    let n = req.len() as u32;
    req[..4].copy_from_slice(&n.to_ne_bytes());
    req[4..6].copy_from_slice(&family.to_ne_bytes());
    req[6..8].copy_from_slice(&(if dump { 0x301u16 } else { 1u16 }).to_ne_bytes());
    req[8..12].copy_from_slice(&seq.to_ne_bytes());
    req[16] = cmd;
    req[17] = 1;
    req[20..].copy_from_slice(body);
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let sent = unsafe {
        libc::sendto(
            fd,
            req.as_ptr().cast(),
            req.len(),
            0,
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&addr) as u32,
        )
    };
    if sent != req.len() as isize {
        return Err(());
    }
    let mut out = Vec::new();
    let mut buf = vec![0; 65536];
    let mut total = 0;
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            return Err(());
        }
        total += n as usize;
        if total > 1048576 {
            return Err(());
        }
        let mut b = &buf[..n as usize];
        while !b.is_empty() {
            let n = u32n(b)? as usize;
            if n < 16 || n > b.len() || u32n(&b[8..])? != seq {
                return Err(());
            }
            let k = u16n(&b[4..])?;
            // BE72 sends NLMSG_DONE without the modern four-byte status body.
            if k == 3 {
                if n >= 20 && u32n(&b[16..])? != 0 {
                    return Err(());
                }
                return Ok(out);
            }
            if k == 2 {
                if n < 20 || u32n(&b[16..])? != 0 {
                    return Err(());
                }
            } else if k == family && n >= 20 {
                out.push(b[20..n].to_vec());
                if !dump {
                    return Ok(out);
                }
            }
            if aligned(n) > b.len() {
                return Err(());
            }
            b = &b[aligned(n)..];
        }
    }
}
#[cfg(target_os = "linux")]
fn read(name: &str) -> Result<Value, ()> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_GENERIC) };
    if fd < 0 {
        return Err(());
    }
    let result = (|| {
        let ctrl = query(fd, 16, 3, 1, &nla(2, b"wireguard\0"), false)?;
        let family = attrs(ctrl.first().ok_or(())?)?
            .into_iter()
            .find(|(k, _)| *k == 1)
            .ok_or(())?
            .1;
        let mut namez = name.as_bytes().to_vec();
        namez.push(0);
        let packets = query(fd, u16n(family)?, 0, 2, &nla(2, &namez), true)?;
        let mut status = Snapshot::default();
        for packet in packets {
            status.parse(&packet)?;
        }
        Ok(status.json(name))
    })();
    unsafe { libc::close(fd) };
    result
}
#[cfg(not(target_os = "linux"))]
fn read(_: &str) -> Result<Value, ()> {
    Err(())
}
fn main() {
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(2));
        std::process::exit(2);
    });
    let name = std::env::args().nth(1).unwrap_or_default();
    let valid = !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
    match if valid { read(&name) } else { Err(()) } {
        Ok(v) => println!("{}", v),
        Err(()) => {
            println!("{{\"ok\":false}}");
            std::process::exit(1);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn padding_and_secrets_do_not_hide_handshakes() {
        let mut p = nla(1, &[1u8; 32]);
        p.extend(nla(2, b"secret-preshared"));
        p.extend(nla(0, &[]));
        p.extend(nla(
            6,
            &[1791435000u64.to_ne_bytes(), 0u64.to_ne_bytes()].concat(),
        ));
        p.extend(nla(7, &12u64.to_ne_bytes()));
        let mut d = nla(3, b"secret-private");
        d.extend(nla(8, &nla(0, &p)));
        let mut s = Snapshot::default();
        s.parse(&d).unwrap();
        let j = s.json("labwg0");
        assert_eq!(j["latestHandshakeAt"], 1791435000u64);
        assert_eq!(j["peers"][0]["rxBytes"], 12u64);
        assert!(!j.to_string().contains("secret"));
    }
    #[test]
    fn malformed_lengths_fail_and_multipart_peers_merge() {
        assert!(attrs(&[3, 0, 0, 0]).is_err());
        assert!(attrs(&[9, 0, 0, 0]).is_err());
        let mut p = nla(1, &[1u8; 32]);
        p.extend(nla(7, &12u64.to_ne_bytes()));
        let mut q = nla(1, &[1u8; 32]);
        q.extend(nla(8, &24u64.to_ne_bytes()));
        let mut s = Snapshot::default();
        s.parse(&nla(8, &nla(0, &p))).unwrap();
        s.parse(&nla(8, &nla(0, &q))).unwrap();
        let j = s.json("labwg0");
        assert_eq!(j["peers"].as_array().unwrap().len(), 1);
        assert_eq!(j["peers"][0]["rxBytes"], 12);
        assert_eq!(j["peers"][0]["txBytes"], 24);
    }
}
