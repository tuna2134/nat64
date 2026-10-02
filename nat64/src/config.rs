//! TOML configuration: parsing, validation, and lowering to dataplane maps.
//!
//! TOML is parsed entirely in userspace. The XDP program only ever sees the
//! resulting [`ConfigValue`] (via the `CONFIG` map) and static entries.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use anyhow::{Context as _, Result, bail};
use nat64_common::{Nat64Prefix, Timeouts};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct File {
    #[serde(default)]
    interface: Iface,
    #[serde(default)]
    nat64: Nat,
    #[serde(default)]
    ipv4_pool: Vec<PoolEntry>,
    #[serde(default)]
    port_range: PortRange,
    #[serde(default)]
    timeouts: TimeoutFile,
    #[serde(default)]
    limits: Limits,
    #[serde(default)]
    static_bindings: Vec<StaticFile>,
    #[serde(default)]
    neighbors: Neighbors,
    #[serde(default)]
    gc: Gc,
}

#[derive(Debug, Deserialize, Default)]
struct Iface {
    #[serde(default = "d_eth0")]
    ipv6: String,
    #[serde(default)]
    ipv4: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Nat {
    #[serde(default = "d_prefix")]
    prefix: String,
    #[serde(default)]
    hairpinning: bool,
}

#[derive(Debug, Deserialize)]
struct PoolEntry {
    address: String,
}

#[derive(Debug, Deserialize)]
struct PortRange {
    #[serde(default = "d_pstart")]
    start: u16,
    #[serde(default = "d_pend")]
    end: u16,
}

impl Default for PortRange {
    fn default() -> Self {
        Self {
            start: 1024,
            end: 65535,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct TimeoutFile {
    udp: Option<u64>,
    icmp: Option<u64>,
    tcp_established: Option<u64>,
    tcp_transitory: Option<u64>,
    tcp_syn: Option<u64>,
    tcp_fin: Option<u64>,
    tcp_rst: Option<u64>,
    bib: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct Limits {
    max_bib_entries: Option<u64>,
    max_session_entries: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct StaticFile {
    ipv4: String,
    ipv4_port: u16,
    protocol: String,
    ipv6: String,
    ipv6_port: u16,
}

#[derive(Debug, Deserialize, Default)]
struct Neighbors {
    #[serde(default)]
    ipv4_next_hop: Option<String>,
    #[serde(default)]
    ipv6_next_hop: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Gc {
    #[serde(default = "d_gc_interval")]
    interval_secs: u64,
}

impl Default for Gc {
    fn default() -> Self {
        Self { interval_secs: 5 }
    }
}

fn d_eth0() -> String {
    "eth0".to_string()
}
fn d_prefix() -> String {
    "64:ff9b::/96".to_string()
}
fn d_pstart() -> u16 {
    1024
}
fn d_pend() -> u16 {
    65535
}
fn d_gc_interval() -> u64 {
    5
}

/// A validated static binding.
#[derive(Debug, Clone)]
pub struct StaticBinding {
    /// TCP (6) or UDP (17).
    pub proto: u8,
    /// Public IPv4 (network order).
    pub ext_ip: u32,
    /// Public port (network order value).
    pub ext_port: u16,
    /// Internal IPv6.
    pub int_v6: [u8; 16],
    /// Internal port.
    pub int_port: u16,
}

/// Fully resolved configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub v6_iface: String,
    pub v4_iface: String,
    pub prefix: Nat64Prefix,
    /// Pool addresses as network-order u32.
    pub pool: Vec<u32>,
    pub port_start: u16,
    pub port_end: u16,
    pub timeouts: Timeouts,
    pub max_bib_entries: u64,
    pub max_session_entries: u64,
    pub hairpinning: bool,
    pub statics: Vec<StaticBinding>,
    pub next_hop_v4: Option<[u8; 6]>,
    pub next_hop_v6: Option<[u8; 6]>,
    pub gc_interval_secs: u64,
}

/// Parse `02:42:ac:11:00:02` into 6 bytes.
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("invalid MAC address {s:?}: want 6 colon-separated hex bytes");
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).with_context(|| format!("invalid MAC address {s:?}"))?;
    }
    Ok(out)
}

fn parse_prefix(s: &str) -> Result<Nat64Prefix> {
    let (addr, len) = s
        .split_once('/')
        .with_context(|| format!("invalid prefix {s:?}: want ADDR/LEN"))?;
    let ip =
        Ipv6Addr::from_str(addr.trim()).with_context(|| format!("invalid prefix address {s:?}"))?;
    let len: u8 = len
        .trim()
        .parse()
        .with_context(|| format!("invalid prefix length {s:?}"))?;
    Nat64Prefix::new(ip.octets(), len)
        .map_err(|e| anyhow::anyhow!("invalid NAT64 prefix {s:?}: {e:?}"))
}

/// Load, validate, and resolve a config file.
pub fn load(path: &str) -> Result<Config> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading config {path:?}"))?;
    let f: File = toml::from_str(&text).with_context(|| format!("parsing config {path:?}"))?;

    let prefix = parse_prefix(&f.nat64.prefix)?;
    if f.ipv4_pool.is_empty() {
        bail!("ipv4_pool is empty: configure at least one [[ipv4_pool]] address");
    }
    if f.ipv4_pool.len() > nat64_common::state::MAX_POOL_ADDRS {
        bail!(
            "ipv4_pool has {} entries, at most {} supported",
            f.ipv4_pool.len(),
            nat64_common::state::MAX_POOL_ADDRS
        );
    }
    let mut pool = Vec::with_capacity(f.ipv4_pool.len());
    for e in &f.ipv4_pool {
        let ip = Ipv4Addr::from_str(&e.address)
            .with_context(|| format!("invalid pool address {:?}", e.address))?;
        pool.push(u32::from_be_bytes(ip.octets()));
    }
    let (mut ps, mut pe) = (f.port_range.start, f.port_range.end);
    if ps > pe {
        std::mem::swap(&mut ps, &mut pe);
    }
    if ps == 0 && pe == 0 {
        bail!("port_range is empty");
    }
    if ps == 0 {
        log::warn!("port_range starts at 0; port 0 is never allocated");
    }

    let d = Timeouts::default();
    let timeouts = Timeouts {
        udp: f.timeouts.udp.unwrap_or(d.udp),
        icmp: f.timeouts.icmp.unwrap_or(d.icmp),
        tcp_established: f.timeouts.tcp_established.unwrap_or(d.tcp_established),
        tcp_transitory: f.timeouts.tcp_transitory.unwrap_or(d.tcp_transitory),
        tcp_syn: f.timeouts.tcp_syn.unwrap_or(d.tcp_syn),
        tcp_fin: f.timeouts.tcp_fin.unwrap_or(d.tcp_fin),
        tcp_rst: f.timeouts.tcp_rst.unwrap_or(d.tcp_rst),
        bib: f.timeouts.bib.unwrap_or(d.bib),
    };

    let mut statics = Vec::with_capacity(f.static_bindings.len());
    for s in &f.static_bindings {
        let proto = match s.protocol.to_ascii_lowercase().as_str() {
            "tcp" => 6u8,
            "udp" => 17u8,
            other => bail!("static binding protocol {other:?}: want tcp or udp"),
        };
        if s.ipv4_port == 0 || s.ipv6_port == 0 {
            bail!("static binding ports must be non-zero");
        }
        let ext = Ipv4Addr::from_str(&s.ipv4)
            .with_context(|| format!("invalid static ipv4 {:?}", s.ipv4))?;
        let int = Ipv6Addr::from_str(&s.ipv6)
            .with_context(|| format!("invalid static ipv6 {:?}", s.ipv6))?;
        statics.push(StaticBinding {
            proto,
            ext_ip: u32::from_be_bytes(ext.octets()),
            ext_port: s.ipv4_port,
            int_v6: int.octets(),
            int_port: s.ipv6_port,
        });
    }

    Ok(Config {
        v4_iface: f.interface.ipv4.unwrap_or_else(|| f.interface.ipv6.clone()),
        v6_iface: f.interface.ipv6,
        prefix,
        pool,
        port_start: ps,
        port_end: pe,
        timeouts,
        max_bib_entries: f.limits.max_bib_entries.unwrap_or(1_000_000),
        max_session_entries: f.limits.max_session_entries.unwrap_or(2_000_000),
        hairpinning: f.nat64.hairpinning,
        statics,
        next_hop_v4: f
            .neighbors
            .ipv4_next_hop
            .as_deref()
            .map(parse_mac)
            .transpose()?,
        next_hop_v6: f
            .neighbors
            .ipv6_next_hop
            .as_deref()
            .map(parse_mac)
            .transpose()?,
        gc_interval_secs: f.gc.interval_secs.max(1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_text(extra: &str) -> String {
        format!(
            r#"
[interface]
ipv6 = "eth0"
ipv4 = "eth1"
[nat64]
prefix = "64:ff9b::/96"
[[ipv4_pool]]
address = "192.0.2.10"
[[ipv4_pool]]
address = "192.0.2.11"
{extra}
"#
        )
    }

    fn write_tmp(text: &str) -> String {
        let p = std::env::temp_dir().join(format!(
            "nat64-test-{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&p, text).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn minimal_config_resolves() {
        let p = write_tmp(&cfg_text(""));
        let c = load(&p).unwrap();
        assert_eq!(c.v6_iface, "eth0");
        assert_eq!(c.v4_iface, "eth1");
        assert_eq!(c.prefix.len, 96);
        assert_eq!(c.pool.len(), 2);
        assert_eq!(c.port_start, 1024);
        assert_eq!(c.timeouts.tcp_established, 7440);
        assert!(c.next_hop_v4.is_none());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_empty_pool_and_bad_prefix() {
        let p = write_tmp("[interface]\nipv6=\"eth0\"\n");
        assert!(load(&p).is_err());
        std::fs::remove_file(&p).ok();
        let p = write_tmp(&cfg_text("[nat64]\nprefix = \"64:ff9b::/33\"\n"));
        assert!(load(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn mac_and_static_parsing() {
        assert_eq!(
            parse_mac("02:42:ac:11:00:02").unwrap(),
            [0x02, 0x42, 0xac, 0x11, 0x00, 0x02]
        );
        assert!(parse_mac("02:42").is_err());
        let extra = r#"
[[static_bindings]]
ipv4 = "192.0.2.10"
ipv4_port = 443
protocol = "tcp"
ipv6 = "2001:db8:1::10"
ipv6_port = 443
"#;
        let p = write_tmp(&cfg_text(extra));
        let c = load(&p).unwrap();
        assert_eq!(c.statics.len(), 1);
        assert_eq!(c.statics[0].proto, 6);
        assert_eq!(c.statics[0].ext_port, 443);
        std::fs::remove_file(&p).ok();
    }
}
