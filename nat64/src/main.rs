//! NAT64 control plane: loader, configuration, GC, and observability.
//!
//! The XDP program owns the fast path. This binary owns everything else:
//! map provisioning, port/BIB lifecycle (expiry), statistics, and the CLI.

mod config;

use std::{
    ffi::CString,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::{Context as _, Result, bail};
use aya::{
    Pod,
    maps::{Array, HashMap, Map, MapData, PerCpuArray},
    programs::{Xdp, XdpMode},
};
use clap::{Parser, Subcommand, ValueEnum};
use config::Config;
use log::{debug, info, warn};
use nat64_common::state::{
    BibKey, BibRevKey, ConfigValue, MAX_POOL_ADDRS, SessionKeyV4, SessionKeyV6, StaticKeyV4,
    StaticValueV4, StatsCounters,
};

const PIN_DIR: &str = "/sys/fs/bpf/nat64";
const MAP_BIB_FWD: &str = "BIB_V6_TO_V4";
const MAP_BIB_REV: &str = "BIB_V4_TO_V6";
const MAP_SESS_FWD: &str = "SESSION_V6_TO_V4";
const MAP_SESS_REV: &str = "SESSION_V4_TO_V6";
const MAP_STATIC: &str = "STATIC_V4";
const MAP_CONFIG: &str = "CONFIG";
const MAP_STATS: &str = "STATS";

#[derive(Debug, Parser)]
#[command(
    name = "nat64",
    about = "Stateful NAT64 (XDP + userspace control plane)"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, global = true, default_value = "/etc/nat64/config.toml")]
    config: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Load the program, attach XDP, and run the control plane.
    Run {
        /// Override the IPv6-side interface from the config file.
        #[arg(long)]
        ipv6_iface: Option<String>,
        /// Override the IPv6-side interface from the config file.
        #[arg(long)]
        ipv4_iface: Option<String>,
        /// XDP attach mode.
        #[arg(long, value_enum, default_value = "drv")]
        xdp_mode: Mode,
    },
    /// Show dataplane counters and table gauges.
    Stats,
    /// Dump session table entries.
    Sessions {
        /// Maximum rows to print.
        #[arg(long, default_value = "100")]
        limit: usize,
    },
    /// Dump BIB entries.
    Bib {
        /// Maximum rows to print.
        #[arg(long, default_value = "100")]
        limit: usize,
    },
    /// Validate the configuration file without loading anything.
    CheckConfig,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    Skb,
    Drv,
    Hw,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::init();
    match cli.cmd {
        Cmd::Run {
            ipv6_iface,
            ipv4_iface,
            xdp_mode,
        } => run(&cli.config, ipv6_iface, ipv4_iface, xdp_mode),
        Cmd::Stats => stats(),
        Cmd::Sessions { limit } => sessions(limit),
        Cmd::Bib { limit } => bib(limit),
        Cmd::CheckConfig => {
            let c = config::load(&cli.config)?;
            println!("config OK: {c:#?}");
            Ok(())
        }
    }
}

/// Monotonic boot-time nanoseconds: the same clock `bpf_ktime_get_ns()`
/// uses, so userspace expiry agrees with dataplane timestamps.
fn boot_ns() -> Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    if r != 0 {
        bail!("clock_gettime(CLOCK_BOOTTIME) failed");
    }
    Ok((ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64))
}

fn iface_mac(iface: &str) -> Result<[u8; 6]> {
    let p = format!("/sys/class/net/{iface}/address");
    let s = std::fs::read_to_string(&p).with_context(|| format!("reading MAC of {iface}"))?;
    config::parse_mac(s.trim())
}

fn if_index(iface: &str) -> Result<u32> {
    let cs = CString::new(iface).unwrap();
    let i = unsafe { libc::if_nametoindex(cs.as_ptr()) };
    if i == 0 {
        bail!("no such interface {iface:?}");
    }
    Ok(i)
}

fn xdp_mode_of(m: Mode) -> XdpMode {
    match m {
        Mode::Skb => XdpMode::Skb,
        Mode::Drv => XdpMode::Driver,
        Mode::Hw => XdpMode::Hardware,
    }
}

#[tokio::main]
async fn run(
    config_path: &str,
    ipv6_override: Option<String>,
    ipv4_override: Option<String>,
    mode: Mode,
) -> Result<()> {
    let mut cfg: Config = config::load(config_path)?;
    if let Some(i) = ipv6_override {
        cfg.v6_iface = i;
    }
    if let Some(i) = ipv4_override {
        cfg.v4_iface = i;
    }
    info!(
        "interfaces: v6={} v4={} prefix=/{:?}",
        cfg.v6_iface, cfg.v4_iface, cfg.prefix
    );

    // Bump the memlock rlimit (needed on older kernels without memcg accounting).
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        debug!("removing RLIMIT_MEMLOCK failed (continuing)");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/nat64"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => warn!("eBPF logger init failed (no log statements?): {e}"),
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Resolve L2 + ifindex addressing.
    let v6_ifindex = if_index(&cfg.v6_iface)?;
    let v4_ifindex = if_index(&cfg.v4_iface)?;
    let mac_lan = iface_mac(&cfg.v6_iface)?;
    let mac_wan = iface_mac(&cfg.v4_iface)?;
    let nh_v4 = cfg.next_hop_v4.unwrap_or_else(|| {
        warn!("neighbors.ipv4_next_hop unset: defaulting to own MAC (dev-loop only)");
        mac_wan
    });
    let nh_v6 = cfg.next_hop_v6.unwrap_or_else(|| {
        warn!("neighbors.ipv6_next_hop unset: defaulting to own MAC (dev-loop only)");
        mac_lan
    });

    // CONFIG map.
    let cv = ConfigValue {
        prefix: cfg.prefix.addr,
        prefix_len: cfg.prefix.len,
        pool_count: cfg.pool.len() as u8,
        flags: if cfg.hairpinning {
            ConfigValue::FLAG_HAIRPIN
        } else {
            0
        },
        _pad: 0,
        pool: {
            let mut p = [0u32; MAX_POOL_ADDRS];
            p[..cfg.pool.len()].copy_from_slice(&cfg.pool);
            p
        },
        port_start: cfg.port_start,
        port_end: cfg.port_end,
        timeout_udp: cfg.timeouts.udp as u32,
        timeout_icmp: cfg.timeouts.icmp as u32,
        timeout_tcp_syn: cfg.timeouts.tcp_syn as u32,
        timeout_tcp_transitory: cfg.timeouts.tcp_transitory as u32,
        timeout_tcp_established: cfg.timeouts.tcp_established as u32,
        timeout_tcp_fin: cfg.timeouts.tcp_fin as u32,
        timeout_tcp_rst: cfg.timeouts.tcp_rst as u32,
        timeout_bib: cfg.timeouts.bib as u32,
        mac_wan,
        mac_lan,
        next_hop_v4: nh_v4,
        next_hop_v6: nh_v6,
        v6_ifindex,
        v4_ifindex,
    };
    {
        let map = ebpf.map_mut(MAP_CONFIG).context("CONFIG map missing")?;
        let mut arr: Array<&mut MapData, ConfigValue> =
            Array::try_from(map).map_err(|e| anyhow::anyhow!("{e}"))?;
        arr.set(0, cv, 0).context("writing CONFIG")?;
    }
    // Static bindings.
    {
        let map = ebpf.map_mut(MAP_STATIC).context("STATIC map missing")?;
        let mut st: HashMap<&mut MapData, StaticKeyV4, StaticValueV4> =
            HashMap::try_from(map).map_err(|e| anyhow::anyhow!("{e}"))?;
        for b in &cfg.statics {
            st.insert(
                StaticKeyV4 {
                    ipv4: b.ext_ip,
                    port: b.ext_port,
                    proto: b.proto,
                    _pad: 0,
                },
                StaticValueV4 {
                    ipv6: b.int_v6,
                    port: b.int_port,
                    _pad: 0,
                },
                0,
            )
            .with_context(|| {
                format!(
                    "inserting static {}:{}",
                    Ipv4Addr::from(b.ext_ip.to_be_bytes()),
                    b.ext_port
                )
            })?;
            info!(
                "static {}:{} -> [{}]:{}",
                Ipv4Addr::from(b.ext_ip.to_be_bytes()),
                b.ext_port,
                Ipv6Addr::from(b.int_v6),
                b.int_port
            );
        }
    }

    // Pin maps for the stats/sessions/bib subcommands.
    std::fs::create_dir_all(PIN_DIR).with_context(|| format!("creating {PIN_DIR}"))?;
    for name in [
        MAP_BIB_FWD,
        MAP_BIB_REV,
        MAP_SESS_FWD,
        MAP_SESS_REV,
        MAP_STATIC,
        MAP_CONFIG,
        MAP_STATS,
    ] {
        let target = format!("{PIN_DIR}/{name}");
        let _ = std::fs::remove_file(&target);
        ebpf.map(name)
            .with_context(|| format!("map {name} missing"))?
            .pin(&target)
            .with_context(|| format!("pinning {name} to {target}"))?;
    }
    info!("maps pinned under {PIN_DIR}");

    // Attach XDP (once per distinct interface).
    let program: &mut Xdp = ebpf.program_mut("nat64").unwrap().try_into()?;
    program.load()?;
    let xm = xdp_mode_of(mode);
    let mut ifaces = vec![cfg.v6_iface.clone()];
    if cfg.v4_iface != cfg.v6_iface {
        ifaces.push(cfg.v4_iface.clone());
    }
    for iface in &ifaces {
        program.attach(iface, xm).with_context(|| {
            format!("attaching XDP to {iface} (try --xdp-mode skb for veth/tunnels)")
        })?;
        info!("XDP attached to {iface} mode={mode:?}");
    }

    // Garbage collection.
    let gc_cfg = cfg.clone();
    tokio::task::spawn(async move {
        let mut tick =
            tokio::time::interval(std::time::Duration::from_secs(gc_cfg.gc_interval_secs));
        loop {
            tick.tick().await;
            if let Err(e) = gc_once(&gc_cfg) {
                warn!("GC failed: {e:#}");
            }
        }
    });

    info!("NAT64 running; Ctrl-C to detach and exit");
    tokio::signal::ctrl_c().await?;
    info!("shutting down; XDP links detach on unload");
    Ok(())
}

/// Open a pinned HASH map by name.
fn open_hash<K: Pod, V: Pod>(name: &str) -> Result<HashMap<MapData, K, V>> {
    let md = MapData::from_pin(format!("{PIN_DIR}/{name}"))
        .with_context(|| format!("opening pinned map {name}; is `nat64 run` active?"))?;
    let m = Map::from_map_data(md).map_err(|e| anyhow::anyhow!("{e}"))?;
    HashMap::try_from(m).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Open a pinned PERCPU_ARRAY map by name.
fn open_percpu<V: Pod>(name: &str) -> Result<PerCpuArray<MapData, V>> {
    let md = MapData::from_pin(format!("{PIN_DIR}/{name}"))
        .with_context(|| format!("opening pinned map {name}; is `nat64 run` active?"))?;
    let m = Map::from_map_data(md).map_err(|e| anyhow::anyhow!("{e}"))?;
    PerCpuArray::try_from(m).map_err(|e| anyhow::anyhow!("{e}"))
}

/// One GC pass: expire sessions, then BIB entries unreferenced by any live
/// session. Static bindings are never collected.
fn gc_once(cfg: &Config) -> Result<()> {
    let now = boot_ns()?;
    let t = &cfg.timeouts;

    let mut sess_fwd = open_hash::<SessionKeyV6, nat64_common::SessionValue>(MAP_SESS_FWD)?;
    let mut sess_rev = open_hash::<SessionKeyV4, nat64_common::SessionValue>(MAP_SESS_REV)?;
    let mut bib_fwd = open_hash::<BibKey, nat64_common::BibValue>(MAP_BIB_FWD)?;
    let mut bib_rev = open_hash::<BibRevKey, nat64_common::BibRevValue>(MAP_BIB_REV)?;

    // Sessions first (bounded iteration; maps are fixed-size).
    // Collect expired keys before deleting: the iterator borrows the map.
    let mut live: Vec<(u32, u16, u8)> = Vec::new();
    let mut dead: Vec<(SessionKeyV6, SessionKeyV4)> = Vec::new();
    let mut sess_count = 0u64;
    for item in sess_fwd.iter() {
        let (k, v) = match item {
            Ok(kv) => kv,
            Err(e) => {
                warn!("session iterate: {e}");
                continue;
            }
        };
        sess_count += 1;
        if v.expired(t, now) {
            dead.push((
                k,
                SessionKeyV4 {
                    ext4: v.ext4,
                    ext_port: v.ext_port,
                    proto: v.proto,
                    _pad: 0,
                    srv4: v.srv4,
                    srv_port: v.srv_port,
                    _pad2: 0,
                },
            ));
        } else {
            live.push((v.ext4, v.ext_port, v.proto));
        }
    }
    let mut sess_freed = 0u64;
    for (fk, rk) in &dead {
        if sess_fwd.remove(fk).is_ok() {
            sess_freed += 1;
        }
        let _ = sess_rev.remove(rk);
    }
    // BIB entries idle past the BIB timeout with no live session.
    let mut bib_count = 0u64;
    let bib_timeout_ns = t.bib.saturating_mul(1_000_000_000);
    let mut dead_bib: Vec<(BibKey, BibRevKey)> = Vec::new();
    for item in bib_fwd.iter() {
        let (k, v) = match item {
            Ok(kv) => kv,
            Err(e) => {
                warn!("bib iterate: {e}");
                continue;
            }
        };
        bib_count += 1;
        let idle = now.saturating_sub(v.last_used_ns);
        let referenced = live
            .iter()
            .any(|l| l.0 == v.ipv4 && l.1 == v.port && l.2 == k.proto);
        if !referenced && idle >= bib_timeout_ns {
            dead_bib.push((
                k,
                BibRevKey {
                    ipv4: v.ipv4,
                    port: v.port,
                    proto: k.proto,
                    _pad: 0,
                },
            ));
        }
    }
    let mut bib_freed = 0u64;
    for (fk, rk) in &dead_bib {
        if bib_fwd.remove(fk).is_ok() {
            bib_freed += 1;
        }
        let _ = bib_rev.remove(rk);
    }
    if sess_freed > 0 || bib_freed > 0 {
        info!("GC: sessions {sess_count} (-{sess_freed}), bib {bib_count} (-{bib_freed})");
    } else {
        debug!("GC: sessions {sess_count}, bib {bib_count}");
    }
    if bib_count > cfg.max_bib_entries {
        warn!(
            "BIB usage {bib_count} exceeds limit {}",
            cfg.max_bib_entries
        );
    }
    if sess_count > cfg.max_session_entries {
        warn!(
            "session usage {sess_count} exceeds limit {}",
            cfg.max_session_entries
        );
    }
    Ok(())
}

fn sum_stats() -> Result<(StatsCounters, u64, u64)> {
    let arr = open_percpu::<StatsCounters>(MAP_STATS)?;
    let mut total = StatsCounters::default();
    let per = arr.get(&0, 0).map_err(|e| anyhow::anyhow!("{e}"))?;
    for v in per.iter() {
        total.accumulate(v);
    }
    // Gauges via iteration.
    let sess = open_hash::<SessionKeyV6, nat64_common::SessionValue>(MAP_SESS_FWD)?;
    let bib = open_hash::<BibKey, nat64_common::BibValue>(MAP_BIB_FWD)?;
    let mut s = 0u64;
    for item in sess.iter() {
        if item.is_ok() {
            s += 1;
        }
    }
    let mut b = 0u64;
    for item in bib.iter() {
        if item.is_ok() {
            b += 1;
        }
    }
    Ok((total, s, b))
}

fn stats() -> Result<()> {
    let (c, sess, bib) = sum_stats()?;
    println!("v6->v4 packets: {}", c.v6_to_v4_packets);
    println!("v4->v6 packets: {}", c.v4_to_v6_packets);
    println!("v6->v4 bytes:   {}", c.v6_to_v4_bytes);
    println!("v4->v6 bytes:   {}", c.v4_to_v6_bytes);
    println!("sessions:       {sess}");
    println!("bib entries:    {bib}");
    println!("translation errors:      {}", c.translation_errors);
    println!("checksum errors:         {}", c.checksum_errors);
    println!("unsupported protocol:    {}", c.unsupported_protocol);
    println!("fragments:               {}", c.fragments);
    println!("invalid packets:         {}", c.invalid_packets);
    println!("port alloc failures:     {}", c.port_alloc_failures);
    println!("state lookup misses:     {}", c.state_lookup_misses);
    println!("static hits:             {}", c.static_hits);
    println!("hairpin drops:           {}", c.hairpin_drops);
    Ok(())
}

fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "?",
    }
}

fn tcp_name(s: u8) -> &'static str {
    match s {
        1 => "syn-rcvd",
        2 => "est",
        3 => "fin",
        4 => "rst",
        _ => "syn-sent",
    }
}

fn sessions(limit: usize) -> Result<()> {
    let sess = open_hash::<SessionKeyV6, nat64_common::SessionValue>(MAP_SESS_FWD)?;
    println!(
        "{:<40} {:<22} {:<22} {:<5} {:<9}",
        "CLIENT", "EXT", "SERVER", "PR", "TCP"
    );
    let mut n = 0;
    for item in sess.iter() {
        if n >= limit {
            println!("... (truncated at {limit})");
            break;
        }
        let (k, v) = item.map_err(|e| anyhow::anyhow!("{e}"))?;
        println!(
            "[{}]:{:<27} {}:{:<15} {}:{:<15} {:<5} {:<9}",
            Ipv6Addr::from(k.src6),
            k.src_port,
            Ipv4Addr::from(v.ext4.to_be_bytes()),
            v.ext_port,
            Ipv4Addr::from(v.srv4.to_be_bytes()),
            v.srv_port,
            proto_name(v.proto),
            if v.proto == 6 {
                tcp_name(v.tcp_state)
            } else {
                "-"
            },
        );
        n += 1;
    }
    println!("{n} session(s)");
    Ok(())
}

fn bib(limit: usize) -> Result<()> {
    let bib = open_hash::<BibKey, nat64_common::BibValue>(MAP_BIB_FWD)?;
    println!("{:<40} {:<22} {:<5}", "CLIENT", "EXT", "PR");
    let mut n = 0;
    for item in bib.iter() {
        if n >= limit {
            println!("... (truncated at {limit})");
            break;
        }
        let (k, v) = item.map_err(|e| anyhow::anyhow!("{e}"))?;
        println!(
            "[{}]:{:<27} {}:{:<15} {:<5}",
            Ipv6Addr::from(k.ipv6),
            k.port,
            Ipv4Addr::from(v.ipv4.to_be_bytes()),
            v.port,
            proto_name(k.proto),
        );
        n += 1;
    }
    println!("{n} bib entr(ies)");
    Ok(())
}
