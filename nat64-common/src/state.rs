//! Shared BIB / session / config / statistics structures.
//!
//! Endianness contract:
//!
//! - `ipv4`: `u32` holding the 4 address bytes in network order
//!   (`u32::from_be_bytes` of the wire bytes).
//! - `port`: `u16` holding the 2 port bytes in network order
//!   (`u16::from_be_bytes`).
//! - `ipv6`: `[u8; 16]` in network order.
//! - `created_ns` / `last_used_ns`: host-order monotonic nanoseconds from
//!   `bpf_ktime_get_ns()` (dataplane) / `CLOCK_BOOTTIME` (userspace GC).
//! - `proto`: `IPPROTO_*` value (`6` TCP, `17` UDP, `1`/`58` ICMP, where the
//!   ICMP BIB/session entries always use [`PROTO_ICMP`] = 1 with the query
//!   identifier stored in the port field, per RFC 7915 section 4).
//!
//! All structs are `#[repr(C)]`, `Copy`, and fixed-size so the eBPF and
//! userspace sides share the exact ABI. Padding fields keep 1/2-byte members
//! 4-byte aligned for the verifier.

/// Transport protocol tag used for ICMP query mappings (RFC 7915: the ICMP
/// identifier plays the role of the port).
pub use crate::proto::PROTO_ICMP;
/// ICMPv6 protocol number (stored only for classification, never in BIB keys).
pub use crate::proto::PROTO_ICMPV6;
/// TCP protocol number.
pub use crate::proto::PROTO_TCP;
/// UDP protocol number.
pub use crate::proto::PROTO_UDP;
use crate::proto::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

/// Maximum IPv4 pool addresses carried in the config map.
pub const MAX_POOL_ADDRS: usize = 8;
/// Maximum static bindings carried in userspace (map sized separately).
pub const MAX_STATIC_BINDINGS: usize = 256;

/// Default timeouts in seconds (RFC 6146-bis guidance: UDP 5min default
/// mapping lifetime; TCP transitory 4min; established 2h4m; short
/// SYN/FIN/RST windows so half-open scans do not pin ports).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// UDP idle timeout.
    pub udp: u64,
    /// ICMP query idle timeout.
    pub icmp: u64,
    /// TCP after SYN (no reply yet).
    pub tcp_syn: u64,
    /// TCP after SYN-ACK (half-open).
    pub tcp_transitory: u64,
    /// TCP established.
    pub tcp_established: u64,
    /// TCP after first FIN.
    pub tcp_fin: u64,
    /// TCP after RST.
    pub tcp_rst: u64,
    /// BIB idle lifetime (refreshed by any session use).
    pub bib: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            udp: 300,
            icmp: 60,
            tcp_syn: 60,
            tcp_transitory: 240,
            tcp_established: 7440,
            tcp_fin: 120,
            tcp_rst: 30,
            bib: 300,
        }
    }
}

/// TCP session state tracked per session entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum TcpState {
    /// SYN seen (v6 -> v4), awaiting SYN-ACK.
    #[default]
    SynSent = 0,
    /// SYN-ACK seen (v4 -> v6), awaiting ACK.
    SynReceived = 1,
    /// Full handshake complete.
    Established = 2,
    /// FIN seen in one direction.
    FinSeen = 3,
    /// RST seen; session drains briefly then expires.
    Reset = 4,
}

impl TcpState {
    /// Advance the state machine. `from_v6` is the packet direction,
    /// `flags` the TCP flag byte. Returns the new state.
    pub fn advance(self, flags: u8, from_v6: bool) -> Self {
        let syn = flags & TCP_SYN != 0;
        let ack = flags & TCP_ACK != 0;
        let fin = flags & TCP_FIN != 0;
        let rst = flags & TCP_RST != 0;
        if rst {
            return TcpState::Reset;
        }
        match self {
            TcpState::SynSent => {
                if !from_v6 && syn && ack {
                    TcpState::SynReceived
                } else if from_v6 && syn && !ack {
                    TcpState::SynSent // retransmit
                } else if from_v6 && ack {
                    TcpState::Established // fast-open / simultaneous edge
                } else {
                    self
                }
            }
            TcpState::SynReceived => {
                if from_v6 && ack && !syn {
                    TcpState::Established
                } else {
                    self
                }
            }
            TcpState::Established => {
                if fin {
                    TcpState::FinSeen
                } else {
                    self
                }
            }
            // Further FINs/ACKs keep draining; expiry is timer-driven.
            TcpState::FinSeen => self,
            TcpState::Reset => TcpState::Reset,
        }
    }

    /// Idle timeout in seconds for this state.
    pub fn timeout(self, t: &Timeouts) -> u64 {
        match self {
            TcpState::SynSent => t.tcp_syn,
            TcpState::SynReceived => t.tcp_transitory,
            TcpState::Established => t.tcp_established,
            TcpState::FinSeen => t.tcp_fin,
            TcpState::Reset => t.tcp_rst,
        }
    }
}

/// BIB entry: IPv6 endpoint -> translated IPv4 endpoint.
///
/// Keyed by the IPv6 side; the reverse map resolves inbound packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BibKey {
    /// IPv6 address (network order).
    pub ipv6: [u8; 16],
    /// IPv6 port / ICMP id (network order).
    pub port: u16,
    /// `IPPROTO_*` (`PROTO_ICMP` for ICMP queries).
    pub proto: u8,
    pub _pad: u8,
}

/// BIB value: the allocated external tuple plus usage timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BibValue {
    /// Allocated IPv4 address (network order).
    pub ipv4: u32,
    /// Allocated port / ICMP id (network order).
    pub port: u16,
    pub _pad: u16,
    /// Creation time (boot ns).
    pub created_ns: u64,
    /// Last packet time in either direction (boot ns).
    pub last_used_ns: u64,
}

/// Reverse BIB key: external tuple -> internal endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BibRevKey {
    /// External IPv4 address (network order).
    pub ipv4: u32,
    /// External port / ICMP id (network order).
    pub port: u16,
    /// `IPPROTO_*`.
    pub proto: u8,
    pub _pad: u8,
}

/// Reverse BIB value: the owning IPv6 endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BibRevValue {
    /// Owner IPv6 address (network order).
    pub ipv6: [u8; 16],
    /// Owner port / ICMP id (network order).
    pub port: u16,
    pub _pad: u16,
}

/// Forward session key (v6 -> v4 direction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SessionKeyV6 {
    /// IPv6 source (network order).
    pub src6: [u8; 16],
    /// IPv6 source port / ICMP id (network order).
    pub src_port: u16,
    /// `IPPROTO_*`.
    pub proto: u8,
    pub _pad: u8,
    /// Destination IPv4 (network order, extracted from the NAT64 prefix).
    pub dst4: u32,
    /// Destination port / ICMP id (network order).
    pub dst_port: u16,
    pub _pad2: u16,
}

/// Reverse session key (v4 -> v6 direction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SessionKeyV4 {
    /// External (translated) IPv4 source (network order).
    pub ext4: u32,
    /// External source port (network order).
    pub ext_port: u16,
    /// `IPPROTO_*`.
    pub proto: u8,
    pub _pad: u8,
    /// Original server IPv4 source (network order).
    pub srv4: u32,
    /// Original server source port (network order).
    pub srv_port: u16,
    pub _pad2: u16,
}

/// Session value: the full bidirectional binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SessionValue {
    /// Original IPv6 client address (network order).
    pub client6: [u8; 16],
    /// Original client port / ICMP id (network order).
    pub client_port: u16,
    /// `IPPROTO_*`.
    pub proto: u8,
    /// TCP state (`TcpState` discriminant); 0 for UDP/ICMP.
    pub tcp_state: u8,
    /// External IPv4 address (network order).
    pub ext4: u32,
    /// External port (network order).
    pub ext_port: u16,
    pub _pad: u16,
    /// Server IPv4 address (network order).
    pub srv4: u32,
    /// Server port (network order).
    pub srv_port: u16,
    pub _pad2: u16,
    /// Last packet time in either direction (boot ns).
    pub last_used_ns: u64,
    /// Creation time (boot ns).
    pub created_ns: u64,
}

impl SessionValue {
    /// Idle timeout in seconds for this session.
    pub fn timeout(&self, t: &Timeouts) -> u64 {
        match self.proto {
            PROTO_TCP => {
                let s = match self.tcp_state {
                    1 => TcpState::SynReceived,
                    2 => TcpState::Established,
                    3 => TcpState::FinSeen,
                    4 => TcpState::Reset,
                    _ => TcpState::SynSent,
                };
                s.timeout(t)
            }
            PROTO_UDP => t.udp,
            _ => t.icmp,
        }
    }

    /// True if the session expired at `now_ns`.
    pub fn expired(&self, t: &Timeouts, now_ns: u64) -> bool {
        now_ns.saturating_sub(self.last_used_ns) >= self.timeout(t).saturating_mul(1_000_000_000)
    }
}

/// Static binding (IPv4-initiated) key: public tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct StaticKeyV4 {
    /// Public IPv4 address (network order).
    pub ipv4: u32,
    /// Public port (network order).
    pub port: u16,
    /// `IPPROTO_*` (TCP/UDP only).
    pub proto: u8,
    pub _pad: u8,
}

/// Static binding value: internal IPv6 endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct StaticValueV4 {
    /// Internal IPv6 address (network order).
    pub ipv6: [u8; 16],
    /// Internal port (network order).
    pub port: u16,
    pub _pad: u16,
}

/// Dataplane configuration, written by userspace into `CONFIG` (index 0).
///
/// All integers are host order except addresses/ports (network order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ConfigValue {
    /// NAT64 prefix bytes (network order).
    pub prefix: [u8; 16],
    /// Prefix length (32/40/48/56/64/96).
    pub prefix_len: u8,
    /// Pool address count (<= `MAX_POOL_ADDRS`).
    pub pool_count: u8,
    /// Flags bit 0: hairpinning enabled.
    pub flags: u8,
    pub _pad: u8,
    /// IPv4 pool addresses (network order).
    pub pool: [u32; MAX_POOL_ADDRS],
    /// Ephemeral port range start (host order, inclusive).
    pub port_start: u16,
    /// Ephemeral port range end (host order, inclusive).
    pub port_end: u16,
    /// Timeout table (seconds, host order).
    pub timeout_udp: u32,
    pub timeout_icmp: u32,
    pub timeout_tcp_syn: u32,
    pub timeout_tcp_transitory: u32,
    pub timeout_tcp_established: u32,
    pub timeout_tcp_fin: u32,
    pub timeout_tcp_rst: u32,
    pub timeout_bib: u32,
    /// Source MAC for translated packets egressing the IPv4 side.
    pub mac_wan: [u8; 6],
    /// Source MAC for translated packets egressing the IPv6 side.
    pub mac_lan: [u8; 6],
    /// Destination (next-hop) MAC for IPv4 egress.
    pub next_hop_v4: [u8; 6],
    /// Destination (next-hop) MAC for IPv6 egress.
    pub next_hop_v6: [u8; 6],
    /// Ingress/egress ifindex of the IPv6 side (host order).
    pub v6_ifindex: u32,
    /// Ingress/egress ifindex of the IPv4 side (host order).
    pub v4_ifindex: u32,
}

impl ConfigValue {
    /// Flag bit: hairpinning.
    pub const FLAG_HAIRPIN: u8 = 1;

    /// Export the timeout table.
    pub fn timeouts(&self) -> Timeouts {
        Timeouts {
            udp: self.timeout_udp as u64,
            icmp: self.timeout_icmp as u64,
            tcp_syn: self.timeout_tcp_syn as u64,
            tcp_transitory: self.timeout_tcp_transitory as u64,
            tcp_established: self.timeout_tcp_established as u64,
            tcp_fin: self.timeout_tcp_fin as u64,
            tcp_rst: self.timeout_tcp_rst as u64,
            bib: self.timeout_bib as u64,
        }
    }

    /// Deterministic pool selection: hash the client tuple onto the pool.
    /// Keeps all sessions of one client on one address while spreading clients.
    pub fn pool_pick(&self, client6: &[u8; 16], port: u16, proto: u8) -> u32 {
        let n = (self.pool_count as usize).clamp(1, MAX_POOL_ADDRS);
        pool_at(
            &self.pool,
            pick_index(hash_tuple(client6, port, proto, 0), n),
        )
    }
}

/// Per-CPU dataplane counters (index 0 of `STATS`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct StatsCounters {
    pub v6_to_v4_packets: u64,
    pub v4_to_v6_packets: u64,
    pub v6_to_v4_bytes: u64,
    pub v4_to_v6_bytes: u64,
    pub translation_errors: u64,
    pub checksum_errors: u64,
    pub unsupported_protocol: u64,
    pub fragments: u64,
    pub invalid_packets: u64,
    pub port_alloc_failures: u64,
    pub state_lookup_misses: u64,
    pub static_hits: u64,
    pub hairpin_drops: u64,
}

impl StatsCounters {
    /// Accumulate another CPU's counters (saturating).
    pub fn accumulate(&mut self, other: &StatsCounters) {
        let dst = [
            &mut self.v6_to_v4_packets,
            &mut self.v4_to_v6_packets,
            &mut self.v6_to_v4_bytes,
            &mut self.v4_to_v6_bytes,
            &mut self.translation_errors,
            &mut self.checksum_errors,
            &mut self.unsupported_protocol,
            &mut self.fragments,
            &mut self.invalid_packets,
            &mut self.port_alloc_failures,
            &mut self.state_lookup_misses,
            &mut self.static_hits,
            &mut self.hairpin_drops,
        ];
        let src = [
            other.v6_to_v4_packets,
            other.v4_to_v6_packets,
            other.v6_to_v4_bytes,
            other.v4_to_v6_bytes,
            other.translation_errors,
            other.checksum_errors,
            other.unsupported_protocol,
            other.fragments,
            other.invalid_packets,
            other.port_alloc_failures,
            other.state_lookup_misses,
            other.static_hits,
            other.hairpin_drops,
        ];
        for (d, s) in dst.into_iter().zip(src) {
            *d = d.saturating_add(s);
        }
    }
}

/// Map capacity planning.
pub mod capacity {
    /// Forward + reverse BIB entries.
    pub const BIB_ENTRIES: u32 = 65536;
    /// Forward + reverse session entries.
    pub const SESSION_ENTRIES: u32 = 131072;
    /// Static bindings.
    pub const STATIC_ENTRIES: u32 = super::MAX_STATIC_BINDINGS as u32;
}

/// FNV-1a over the client tuple plus a murmur3-style final avalanche, so
/// every input byte affects every output bit (plain shifted-XOR folding
/// leaves the low bits constant for high-byte inputs, which would collapse
/// port allocation onto a single value).
///
/// Shared by the dataplane pool/port selection and userspace so both agree.
pub fn hash_tuple(client6: &[u8; 16], client_port: u16, proto: u8, attempt: u32) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in client6.iter() {
        h = (h ^ (*b as u32)).wrapping_mul(0x0100_0193);
    }
    h = (h ^ (client_port as u32)).wrapping_mul(0x0100_0193);
    h = (h ^ (proto as u32)).wrapping_mul(0x0100_0193);
    h = h.wrapping_add(attempt.wrapping_mul(0x9e37_79b9));
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

/// Deterministic external-port candidate.
///
/// `attempt` is the collision-probe index (0..`MAX_PORT_PROBES`). Pure and
/// shared so userspace tests and the dataplane agree exactly.
pub fn port_candidate(client6: &[u8; 16], client_port: u16, proto: u8, attempt: u32) -> u16 {
    (hash_tuple(client6, client_port, proto, attempt) & 0xFFFF) as u16
}

/// Map a 16-bit hash into `[start, end]` (inclusive, host order).
///
/// Multiply-high mapping instead of `%`: a remainder with a runtime divisor
/// emits a divide-by-zero panic path, which eBPF cannot contain (see the
/// zero-panic rule). The tiny modulo bias is irrelevant for port selection.
pub fn port_in_range(hash16: u16, start: u16, end: u16) -> u16 {
    let (mut lo, mut hi) = (start, end);
    if lo > hi {
        core::mem::swap(&mut lo, &mut hi);
    }
    if lo == 0 && hi == 0 {
        return 0;
    }
    let span = hi.wrapping_sub(lo).wrapping_add(1) as u32;
    lo.wrapping_add((((hash16 as u32).wrapping_mul(span)) >> 16) as u16)
}

/// Select `pool[idx]` without runtime indexing (constant branches only).
/// Panic-free, so the eBPF dataplane can call it (see the zero-panic rule).
pub fn pool_at(pool: &[u32; MAX_POOL_ADDRS], idx: usize) -> u32 {
    let p = pool as *const [u32; MAX_POOL_ADDRS] as *const u32;
    // SAFETY: idx < MAX_POOL_ADDRS by contract (`pick_index` upholds it);
    // every offset below is a constant.
    unsafe {
        let mut out = *p;
        if idx == 1 {
            out = *p.add(1);
        }
        if idx == 2 {
            out = *p.add(2);
        }
        if idx == 3 {
            out = *p.add(3);
        }
        if idx == 4 {
            out = *p.add(4);
        }
        if idx == 5 {
            out = *p.add(5);
        }
        if idx == 6 {
            out = *p.add(6);
        }
        if idx == 7 {
            out = *p.add(7);
        }
        out
    }
}

/// Reduce a 32-bit hash into `0..n` for `n <= 8` (pool selection).
/// Constant divisors only: see `port_in_range` for why `% n` is banned.
pub fn pick_index(hash: u32, n: usize) -> usize {
    match n {
        0 => 0,
        1 => 0,
        2 => (hash % 2) as usize,
        3 => (hash % 3) as usize,
        4 => (hash % 4) as usize,
        5 => (hash % 5) as usize,
        6 => (hash % 6) as usize,
        7 => (hash % 7) as usize,
        _ => (hash % 8) as usize,
    }
}

/// Number of bounded collision probes the dataplane tries before reporting
/// `port_alloc_failures` (no 64k scan; GC frees expired entries).
pub const MAX_PORT_PROBES: u32 = 8;

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, format};

    use super::*;

    #[test]
    fn tcp_state_machine() {
        use crate::proto::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
        let mut s = TcpState::SynSent;
        // Retransmitted SYN stays.
        assert_eq!(s.advance(TCP_SYN, true), TcpState::SynSent);
        // SYN-ACK from the server advances.
        s = s.advance(TCP_SYN | TCP_ACK, false);
        assert_eq!(s, TcpState::SynReceived);
        // Client ACK establishes.
        s = s.advance(TCP_ACK, true);
        assert_eq!(s, TcpState::Established);
        // Data stays established.
        assert_eq!(s.advance(TCP_ACK, true), TcpState::Established);
        // FIN moves to FinSeen.
        s = s.advance(TCP_FIN | TCP_ACK, false);
        assert_eq!(s, TcpState::FinSeen);
        // RST always resets.
        assert_eq!(s.advance(TCP_RST, true), TcpState::Reset);
        assert_eq!(
            TcpState::Established.advance(TCP_RST, false),
            TcpState::Reset
        );
        let _ = format!("{s:?}");
    }

    #[test]
    fn tcp_timeouts_are_sane() {
        let t = Timeouts::default();
        assert!(t.tcp_syn < t.tcp_transitory);
        assert!(t.tcp_transitory < t.tcp_established);
        assert!(t.tcp_rst < t.tcp_fin);
        assert!(t.tcp_fin < t.tcp_established);
        assert_eq!(TcpState::Established.timeout(&t), 7440);
        assert_eq!(TcpState::SynSent.timeout(&t), 60);
        assert_eq!(TcpState::Reset.timeout(&t), 30);
    }

    #[test]
    fn session_expiry_uses_state_timeout() {
        let t = Timeouts::default();
        let base = SessionValue {
            client6: [0u8; 16],
            client_port: 0,
            proto: PROTO_TCP,
            tcp_state: TcpState::Established as u8,
            ext4: 0,
            ext_port: 0,
            _pad: 0,
            srv4: 0,
            srv_port: 0,
            _pad2: 0,
            last_used_ns: 0,
            created_ns: 0,
        };
        assert!(!base.expired(&t, 1000));
        assert!(base.expired(&t, 7440 * 1_000_000_000 + 1));
        let syn = SessionValue {
            tcp_state: TcpState::SynSent as u8,
            ..base
        };
        assert!(syn.expired(&t, 61 * 1_000_000_000));
    }

    #[test]
    fn port_mapping_spreads_and_stays_in_range() {
        let mut seen = BTreeSet::new();
        for i in 0..512u16 {
            let mut c = [0u8; 16];
            c[15] = (i & 0xff) as u8;
            c[14] = (i >> 8) as u8;
            let p = port_in_range(port_candidate(&c, 54321, PROTO_TCP, 0), 1024, 65535);
            assert!((1024..=65535).contains(&p));
            seen.insert(p);
        }
        // Deterministic hash must spread clients across the range.
        assert!(seen.len() > 400, "only {} unique ports", seen.len());
        // Same input is stable.
        let c = [7u8; 16];
        assert_eq!(
            port_candidate(&c, 1, PROTO_TCP, 0),
            port_candidate(&c, 1, PROTO_TCP, 0)
        );
        // Probes differ.
        assert_ne!(
            port_candidate(&c, 1, PROTO_TCP, 0),
            port_candidate(&c, 1, PROTO_TCP, 1)
        );
    }

    #[test]
    fn pool_pick_is_stable_and_bounded() {
        let cfg = ConfigValue {
            prefix: crate::proto::WKP,
            prefix_len: 96,
            pool_count: 2,
            flags: 0,
            _pad: 0,
            pool: [0xC0000201, 0xC0000202, 0, 0, 0, 0, 0, 0],
            port_start: 1024,
            port_end: 65535,
            timeout_udp: 300,
            timeout_icmp: 60,
            timeout_tcp_syn: 60,
            timeout_tcp_transitory: 240,
            timeout_tcp_established: 7440,
            timeout_tcp_fin: 120,
            timeout_tcp_rst: 30,
            timeout_bib: 300,
            mac_wan: [0; 6],
            mac_lan: [0; 6],
            next_hop_v4: [0; 6],
            next_hop_v6: [0; 6],
            v6_ifindex: 0,
            v4_ifindex: 0,
        };
        let a = cfg.pool_pick(&[1u8; 16], 80, PROTO_TCP);
        assert!(a == 0xC0000201 || a == 0xC0000202);
        assert_eq!(a, cfg.pool_pick(&[1u8; 16], 80, PROTO_TCP));
        let t = cfg.timeouts();
        assert_eq!(t.udp, 300);
        assert_eq!(t.tcp_established, 7440);
    }

    #[test]
    fn struct_sizes_are_stable() {
        // ABI guard: these sizes are baked into BPF map definitions.
        assert_eq!(core::mem::size_of::<BibKey>(), 20);
        assert_eq!(core::mem::size_of::<BibValue>(), 24);
        assert_eq!(core::mem::size_of::<BibRevKey>(), 8);
        assert_eq!(core::mem::size_of::<BibRevValue>(), 20);
        assert_eq!(core::mem::size_of::<SessionKeyV6>(), 28);
        assert_eq!(core::mem::size_of::<SessionKeyV4>(), 16);
        assert_eq!(core::mem::size_of::<StaticKeyV4>(), 8);
        assert_eq!(core::mem::size_of::<StaticValueV4>(), 20);
    }
}
