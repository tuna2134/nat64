//! Stateful NAT64 XDP dataplane.
//!
//! Fast path: parse -> BIB/session lookup -> rewrite -> checksum -> redirect.
//! Only *established* flows stay fully in-kernel; mapping allocation for new
//! flows also happens here (deterministic hash + bounded probes, no 64k scan,
//! no userspace round-trip), while expiry/GC lives in userspace.
//!
//! Action policy:
//!
//! - `XDP_PASS` — not ours (non-prefix v6, non-pool v4, ARP, ESP/AH, unknown
//!   L4, ICMP errors). The host stack may handle it.
//! - `XDP_DROP` — malformed, filtered (unsolicited inbound), allocation
//!   failure, fragments (no reassembly — documented limitation).
//! - redirect — translated packet to the other side's ifindex.
//!
//! Map-type rationale:
//!
//! - `HashMap` (not LRU) for BIB/session: eviction is policy-driven
//!   (TCP-state-aware timeouts) and performed by the userspace GC. Kernel LRU
//!   eviction would silently kill established flows.
//! - `Array` for `CONFIG`: exactly one element, written by userspace.
//! - `PerCpuArray` for `STATS`: no contended global counter on the fast path;
//!   userspace sums across CPUs.

#![no_std]
#![no_main]

mod parse;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::generated::{bpf_ktime_get_ns, bpf_redirect, bpf_xdp_adjust_tail},
    macros::{map, xdp},
    maps::{Array, HashMap, PerCpuArray},
    programs::XdpContext,
};
use nat64_common::{
    hash_tuple, pick_index, pool_at,
    proto::*,
    state::{
        BibKey, BibRevKey, BibRevValue, BibValue, ConfigValue, MAX_POOL_ADDRS, MAX_PORT_PROBES,
        SessionKeyV4, SessionKeyV6, SessionValue, StaticKeyV4, TcpState, capacity, port_candidate,
        port_in_range,
    },
};
use parse::{
    MAX_COPY, copy4, copy16, csum_add, csum_fold, embed_v6, extract_v4, parse_eth, pk8, rb, rb16,
    w16, write_bytes, zext,
};

/// `BPF_NOEXIST` for map updates (see `bpf.h`).
const BPF_NOEXIST: u64 = 1;

// Statistics field IDs for `stat()`.
const S_V6_TO_V4: u32 = 0;
const S_V4_TO_V6: u32 = 1;
const S_TRANSLATION_ERR: u32 = 2;
const S_CHECKSUM_ERR: u32 = 3;
const S_UNSUPPORTED: u32 = 4;
const S_FRAGMENT: u32 = 5;
const S_INVALID: u32 = 6;
const S_PORT_ALLOC_FAIL: u32 = 7;
const S_LOOKUP_MISS: u32 = 8;
const S_STATIC_HIT: u32 = 9;
const S_HAIRPIN_DROP: u32 = 10;

#[map]
static BIB_V6_TO_V4: HashMap<BibKey, BibValue> = HashMap::pinned(capacity::BIB_ENTRIES, 0);

#[map]
static BIB_V4_TO_V6: HashMap<BibRevKey, BibRevValue> = HashMap::pinned(capacity::BIB_ENTRIES, 0);

#[map]
static SESSION_V6_TO_V4: HashMap<SessionKeyV6, SessionValue> =
    HashMap::pinned(capacity::SESSION_ENTRIES, 0);

#[map]
static SESSION_V4_TO_V6: HashMap<SessionKeyV4, SessionValue> =
    HashMap::pinned(capacity::SESSION_ENTRIES, 0);

#[map]
static STATIC_V4: HashMap<StaticKeyV4, nat64_common::state::StaticValueV4> =
    HashMap::pinned(capacity::STATIC_ENTRIES, 0);

#[map]
static CONFIG: Array<ConfigValue> = Array::pinned(1, 0);

#[map]
static STATS: PerCpuArray<nat64_common::state::StatsCounters> = PerCpuArray::pinned(1, 0);

#[inline(always)]
fn stat(which: u32, bytes: u64) {
    if let Some(p) = STATS.get_ptr_mut(0) {
        unsafe {
            let s = &mut *p;
            match which {
                S_V6_TO_V4 => {
                    s.v6_to_v4_packets = s.v6_to_v4_packets.wrapping_add(1);
                    s.v6_to_v4_bytes = s.v6_to_v4_bytes.wrapping_add(bytes);
                }
                S_V4_TO_V6 => {
                    s.v4_to_v6_packets = s.v4_to_v6_packets.wrapping_add(1);
                    s.v4_to_v6_bytes = s.v4_to_v6_bytes.wrapping_add(bytes);
                }
                S_TRANSLATION_ERR => s.translation_errors = s.translation_errors.wrapping_add(1),
                S_CHECKSUM_ERR => s.checksum_errors = s.checksum_errors.wrapping_add(1),
                S_UNSUPPORTED => s.unsupported_protocol = s.unsupported_protocol.wrapping_add(1),
                S_FRAGMENT => s.fragments = s.fragments.wrapping_add(1),
                S_INVALID => s.invalid_packets = s.invalid_packets.wrapping_add(1),
                S_PORT_ALLOC_FAIL => s.port_alloc_failures = s.port_alloc_failures.wrapping_add(1),
                S_LOOKUP_MISS => s.state_lookup_misses = s.state_lookup_misses.wrapping_add(1),
                S_STATIC_HIT => s.static_hits = s.static_hits.wrapping_add(1),
                S_HAIRPIN_DROP => s.hairpin_drops = s.hairpin_drops.wrapping_add(1),
                _ => {}
            }
        }
    }
}

#[inline(always)]
fn now_ns() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

/// Copy a u16 in network order into the packet.
#[inline(always)]
fn wb16(data: usize, data_end: usize, off: u32, v: u16) -> Result<(), ()> {
    let b = v.to_be_bytes();
    let o = zext(off);
    if data + o + 2 > data_end {
        return Err(());
    }
    unsafe {
        *((data + o) as *mut u8) = b[0];
        *((data + o + 1) as *mut u8) = b[1];
    }
    Ok(())
}

/// Is `v4` one of our pool addresses? Raw pointer scan: `cfg.pool[i]`
/// would emit a panic path (see the zero-panic rule in `parse.rs`).
#[inline(always)]
fn in_pool(cfg: &ConfigValue, v4: u32) -> bool {
    let pool = &cfg.pool as *const [u32; MAX_POOL_ADDRS] as *const u32;
    let mut i = 0u32;
    while i < MAX_POOL_ADDRS as u32 {
        if (i as u8) < cfg.pool_count && unsafe { *pool.add(i as usize) } == v4 {
            return true;
        }
        i += 1;
    }
    false
}

/// IPv4 pseudo-header sum from host-assembled addresses (no indexing).
#[inline(always)]
fn pseudo_v4(a: u32, b: u32, proto: u8, len: u16) -> u64 {
    let mut sum: u64 = 0;
    sum += ((a >> 16) & 0xFFFF) as u64;
    sum += (a & 0xFFFF) as u64;
    sum += ((b >> 16) & 0xFFFF) as u64;
    sum += (b & 0xFFFF) as u64;
    sum += proto as u64;
    sum += len as u64;
    sum
}

/// IPv6 pseudo-header sum from raw address pointers (no indexing).
#[inline(always)]
fn pseudo_v6(a: *const u8, b: *const u8, proto: u8, len: u32) -> u64 {
    unsafe {
        let mut sum: u64 = 0;
        let mut i = 0usize;
        while i < 16 {
            sum += w16(pk8(a, i), pk8(a, i + 1));
            sum += w16(pk8(b, i), pk8(b, i + 1));
            i += 2;
        }
        sum += ((len >> 16) & 0xFFFF) as u64;
        sum += (len & 0xFFFF) as u64;
        sum += proto as u64;
        sum
    }
}

/// Decode the fixed IPv6 header. Returns
/// (traffic_class, payload_len, next, hop_limit, l4_or_ext_off).
#[inline(always)]
fn ipv6_fixed(data: usize, data_end: usize, l3: u32) -> Result<(u8, u16, u8, u8), ()> {
    if data + zext(l3 + IPV6_LEN as u32) > data_end {
        return Err(());
    }
    let b0 = rb(data, data_end, l3)?;
    if b0 >> 4 != 6 {
        return Err(());
    }
    let b1 = rb(data, data_end, l3 + 1)?;
    Ok((
        ((b0 & 0x0f) << 4) | (b1 >> 4),
        rb16(data, data_end, l3 + 4)?,
        rb(data, data_end, l3 + 6)?,
        rb(data, data_end, l3 + 7)?,
    ))
}

/// Walk extension headers. Returns (proto, l4_off).
/// Fragments are rejected (no reassembly — documented limitation).
#[inline(always)]
fn walk_ext(data: usize, data_end: usize, l3: u32, mut next: u8) -> Result<(u8, u32), u32> {
    let mut off = l3 + IPV6_LEN as u32;
    let mut depth = 0u32;
    loop {
        match next {
            PROTO_TCP | PROTO_UDP | PROTO_ICMPV6 => return Ok((next, off)),
            IPV6_AH | IPV6_ESP => return Err(xdp_action::XDP_PASS),
            IPV6_HBH | IPV6_ROUTING | IPV6_DSTOPTS => {
                if depth >= MAX_EXT_HEADERS as u32 {
                    stat(S_UNSUPPORTED, 0);
                    return Err(xdp_action::XDP_PASS);
                }
                if data + zext(off + 2) > data_end {
                    return Err(xdp_action::XDP_DROP);
                }
                next = rb(data, data_end, off).map_err(|_| xdp_action::XDP_DROP)?;
                let elen =
                    (rb(data, data_end, off + 1).map_err(|_| xdp_action::XDP_DROP)? as u32 + 1) * 8;
                off += elen;
                if zext(off) > data_end.saturating_sub(data) {
                    return Err(xdp_action::XDP_DROP);
                }
                depth += 1;
            }
            IPV6_FRAG => {
                stat(S_FRAGMENT, 0);
                return Err(xdp_action::XDP_DROP);
            }
            _ => {
                stat(S_UNSUPPORTED, 0);
                return Err(xdp_action::XDP_PASS);
            }
        }
    }
}

/// Create the forward + reverse session entries for a flow.
///
#[inline(always)]
fn mk_sessions(
    proto: u8,
    client6: &[u8; 16],
    sport: u16,
    dst4: u32,
    dport: u16,
    ext_ip: u32,
    ext_port: u16,
    tcp_state: u8,
    now: u64,
) {
    let sval = SessionValue {
        client6: *client6,
        client_port: sport,
        proto,
        tcp_state,
        ext4: ext_ip,
        ext_port,
        _pad: 0,
        srv4: dst4,
        srv_port: dport,
        _pad2: 0,
        last_used_ns: now,
        created_ns: now,
    };
    let fkey = SessionKeyV6 {
        src6: *client6,
        src_port: sport,
        proto,
        _pad: 0,
        dst4,
        dst_port: dport,
        _pad2: 0,
    };
    let _ = SESSION_V6_TO_V4.insert(&fkey, &sval, 0);
    let rev = SessionKeyV4 {
        ext4: ext_ip,
        ext_port,
        proto,
        _pad: 0,
        srv4: dst4,
        srv_port: dport,
        _pad2: 0,
    };
    let _ = SESSION_V4_TO_V6.insert(&rev, &sval, 0);
}

/// Allocate a BIB + session pair for a new v6 -> v4 flow.
/// Returns (ext_ip, ext_port) in host-assembled order.
///
/// An existing BIB entry for the client tuple is reused (one external port
/// per client, multiplexed across destinations); only a genuinely new client
/// tuple probes for a fresh port.
#[inline(always)]
fn alloc_mapping(
    cfg: &ConfigValue,
    proto: u8,
    client6: &[u8; 16],
    sport: u16,
    now: u64,
) -> Result<(u32, u16), ()> {
    let n = cfg.pool_count as usize;
    if n == 0 || n > MAX_POOL_ADDRS {
        return Err(());
    }
    // Reuse the existing BIB entry for this client tuple when present: one
    // external port per client, multiplexed across destinations.
    let bib_key = BibKey {
        ipv6: *client6,
        port: sport,
        proto,
        _pad: 0,
    };
    if let Some(b) = unsafe { BIB_V6_TO_V4.get(&bib_key) } {
        let ext_ip = b.ipv4;
        let ext_port = b.port;
        refresh_bib(client6, sport, proto, now);
        return Ok((ext_ip, ext_port));
    }
    // Stable pool address per client (spreads clients, pins a client to one IP).
    // Same hash as `nat64_common::pool_pick` so userspace and dataplane agree.
    let pool_ip = pool_at(
        &cfg.pool,
        pick_index(hash_tuple(client6, sport, proto, 0), n),
    );
    let (mut lo, mut hi) = (cfg.port_start, cfg.port_end);
    if lo > hi {
        let t = lo;
        lo = hi;
        hi = t;
    }
    if lo == 0 && hi == 0 {
        return Err(());
    }
    let mut attempt = 0u32;
    while attempt < MAX_PORT_PROBES {
        let cand = port_in_range(port_candidate(client6, sport, proto, attempt), lo, hi);
        attempt += 1;
        if cand == 0 {
            continue; // port 0 is never valid on the wire
        }
        let rkey = BibRevKey {
            ipv4: pool_ip,
            port: cand,
            proto,
            _pad: 0,
        };
        let rval = BibRevValue {
            ipv6: *client6,
            port: sport,
            _pad: 0,
        };
        if BIB_V4_TO_V6.insert(&rkey, &rval, BPF_NOEXIST).is_err() {
            continue; // collision: next probe
        }
        let bval = BibValue {
            ipv4: pool_ip,
            port: cand,
            _pad: 0,
            created_ns: now,
            last_used_ns: now,
        };
        let _ = BIB_V6_TO_V4.insert(&bib_key, &bval, 0);
        return Ok((pool_ip, cand));
    }
    Err(())
}

#[inline(always)]
fn refresh_session_fwd(key: &SessionKeyV6, flags: u8, from_v6: bool, now: u64) {
    if let Some(p) = SESSION_V6_TO_V4.get_ptr_mut(key) {
        unsafe {
            let s = &mut *p;
            s.last_used_ns = now;
            if s.proto == PROTO_TCP {
                let cur = match s.tcp_state {
                    1 => TcpState::SynReceived,
                    2 => TcpState::Established,
                    3 => TcpState::FinSeen,
                    4 => TcpState::Reset,
                    _ => TcpState::SynSent,
                };
                s.tcp_state = cur.advance(flags, from_v6) as u8;
            }
        }
    }
}

#[inline(always)]
fn refresh_session_rev(key: &SessionKeyV4, flags: u8, from_v6: bool, now: u64) {
    if let Some(p) = SESSION_V4_TO_V6.get_ptr_mut(key) {
        unsafe {
            let s = &mut *p;
            s.last_used_ns = now;
            if s.proto == PROTO_TCP {
                let cur = match s.tcp_state {
                    1 => TcpState::SynReceived,
                    2 => TcpState::Established,
                    3 => TcpState::FinSeen,
                    4 => TcpState::Reset,
                    _ => TcpState::SynSent,
                };
                s.tcp_state = cur.advance(flags, from_v6) as u8;
            }
        }
    }
}

#[inline(always)]
fn refresh_bib(client6: &[u8; 16], sport: u16, proto: u8, now: u64) {
    let k = BibKey {
        ipv6: *client6,
        port: sport,
        proto,
        _pad: 0,
    };
    if let Some(p) = BIB_V6_TO_V4.get_ptr_mut(&k) {
        unsafe {
            (*p).last_used_ns = now;
        }
    }
}

/// IPv6 -> IPv4 fast path. `l3` is the L3 offset, `pkt_len` the frame length.
///
/// Fully inlined into `nat64`: a single-function program avoids BPF-to-BPF
/// linking entirely (keeps the loader path trivially correct). Stack usage
/// is kept under the 512-byte limit by using map references instead of
/// struct copies and writing headers directly into the packet.
#[inline(always)]
fn handle_v6(ctx: &XdpContext, data: usize, data_end: usize, l3: u32, pkt_len: u32) -> u32 {
    // Fixed header.
    let (tclass, _plen, next, hlim) = match ipv6_fixed(data, data_end, l3) {
        Ok(v) => v,
        Err(()) => {
            stat(S_INVALID, 0);
            return xdp_action::XDP_DROP;
        }
    };
    if hlim <= 1 {
        stat(S_INVALID, 0);
        return xdp_action::XDP_DROP;
    }
    let mut src6 = [0u8; 16];
    let mut dst6 = [0u8; 16];
    if copy16(data, data_end, l3 + 8, src6.as_mut_ptr(), 16).is_err()
        || copy16(data, data_end, l3 + 24, dst6.as_mut_ptr(), 16).is_err()
    {
        stat(S_INVALID, 0);
        return xdp_action::XDP_DROP;
    }
    let cfg: &ConfigValue = match CONFIG.get(0) {
        Some(c) => c,
        None => return xdp_action::XDP_PASS,
    };
    let dst4 = match extract_v4(cfg.prefix.as_ptr(), cfg.prefix_len, dst6.as_ptr()) {
        Ok(v) => v,
        Err(()) => return xdp_action::XDP_PASS, // native v6: not ours
    };
    if in_pool(cfg, u32::from_be_bytes(dst4)) {
        // Hairpinning boundary: dropped either way for now (see docs).
        stat(S_HAIRPIN_DROP, 0);
        return xdp_action::XDP_DROP;
    }
    let (proto, l4) = match walk_ext(data, data_end, l3, next) {
        Ok(v) => v,
        Err(a) => return a,
    };
    // L4 tuple.
    let (sport, dport, flags): (u16, u16, u8) = match proto {
        PROTO_TCP => {
            if data + zext(l4 + TCP_MIN_LEN as u32) > data_end {
                stat(S_INVALID, 0);
                return xdp_action::XDP_DROP;
            }
            let s = rb16(data, data_end, l4);
            let d = rb16(data, data_end, l4 + 2);
            let f = rb(data, data_end, l4 + 13);
            match (s, d, f) {
                (Ok(a), Ok(b), Ok(c)) => (a, b, c),
                _ => {
                    stat(S_INVALID, 0);
                    return xdp_action::XDP_DROP;
                }
            }
        }
        PROTO_UDP => {
            if data + zext(l4 + UDP_LEN as u32) > data_end {
                stat(S_INVALID, 0);
                return xdp_action::XDP_DROP;
            }
            match (rb16(data, data_end, l4), rb16(data, data_end, l4 + 2)) {
                (Ok(a), Ok(b)) => (a, b, 0),
                _ => {
                    stat(S_INVALID, 0);
                    return xdp_action::XDP_DROP;
                }
            }
        }
        PROTO_ICMPV6 => {
            if data + zext(l4 + ICMP_MIN_LEN as u32) > data_end {
                stat(S_INVALID, 0);
                return xdp_action::XDP_DROP;
            }
            let typ = match rb(data, data_end, l4) {
                Ok(t) => t,
                Err(()) => {
                    stat(S_INVALID, 0);
                    return xdp_action::XDP_DROP;
                }
            };
            if typ != ICMPV6_ECHO_REQUEST && typ != ICMPV6_ECHO_REPLY {
                // ICMP errors: safe PASS fallback (documented limitation).
                stat(S_UNSUPPORTED, 0);
                return xdp_action::XDP_PASS;
            }
            match rb16(data, data_end, l4 + 4) {
                Ok(id) => (id, id, 0),
                Err(()) => {
                    stat(S_INVALID, 0);
                    return xdp_action::XDP_DROP;
                }
            }
        }
        _ => {
            stat(S_UNSUPPORTED, 0);
            return xdp_action::XDP_PASS;
        }
    };
    if pkt_len < l4 {
        stat(S_INVALID, 0);
        return xdp_action::XDP_DROP;
    }
    let seg_len = pkt_len - l4;
    if seg_len > MAX_COPY || seg_len < 4 {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_PASS;
    }
    let now = now_ns();
    let fkey = SessionKeyV6 {
        src6,
        src_port: sport,
        proto: map_proto(proto),
        _pad: 0,
        dst4: u32::from_be_bytes(dst4),
        dst_port: dport,
        _pad2: 0,
    };
    let sess = unsafe { SESSION_V6_TO_V4.get(&fkey) };
    let (ext_ip, ext_port) = match sess {
        Some(s) => {
            let e = (s.ext4, s.ext_port);
            refresh_session_fwd(&fkey, flags, true, now);
            refresh_bib(&src6, sport, map_proto(proto), now);
            e
        }
        None => {
            stat(S_LOOKUP_MISS, 0);
            if proto == PROTO_TCP && flags & TCP_SYN == 0 {
                // No session and no SYN: late/foreign packet, filter it.
                return xdp_action::XDP_DROP;
            }
            let init_state = if proto == PROTO_TCP {
                TcpState::SynSent as u8
            } else {
                0
            };
            let dst4_u32 = u32::from_be_bytes(dst4);
            let (eip, eport) = match alloc_mapping(cfg, map_proto(proto), &src6, sport, now) {
                Ok(v) => v,
                Err(()) => {
                    stat(S_PORT_ALLOC_FAIL, 0);
                    return xdp_action::XDP_DROP;
                }
            };
            mk_sessions(
                map_proto(proto),
                &src6,
                sport,
                dst4_u32,
                dport,
                eip,
                eport,
                init_state,
                now,
            );
            (eip, eport)
        }
    };

    // Shrink: move the segment 20 bytes toward the head, then trim the tail.
    let new_l4 = l3 + IPV4_MIN_LEN as u32;
    if new_l4 > l4 {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    if parse::move_left(data, data_end, new_l4, l4, seg_len).is_err() {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    let rc = unsafe { bpf_xdp_adjust_tail(ctx.ctx as *mut _, -20) };
    if rc != 0 {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    // Pointers are invalid after the helper: reload.
    let data = ctx.data();
    let data_end = ctx.data_end();
    let new_len = pkt_len - 20;

    // Ethernet.
    if write_bytes(data, data_end, 0, cfg.next_hop_v4.as_ptr(), 6).is_err()
        || write_bytes(data, data_end, 6, cfg.mac_wan.as_ptr(), 6).is_err()
        || wb16(data, data_end, l3 - 2, ETH_P_IP).is_err()
    {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    // IPv4 header, written directly (no stack staging array).
    let out_proto = map_proto(proto);
    let total = (new_len - l3) as u16;
    let ttl = hlim - 1;
    let ext_b = ext_ip.to_be_bytes();
    let v45 = [0x45, tclass];
    let df = [0x40, 0];
    let tt = [ttl, out_proto];
    if write_bytes(data, data_end, l3, v45.as_ptr(), 2).is_err()
        || wb16(data, data_end, l3 + 2, total).is_err()
        || wb16(data, data_end, l3 + 4, 0).is_err()
        || write_bytes(data, data_end, l3 + 6, df.as_ptr(), 2).is_err()
        || write_bytes(data, data_end, l3 + 8, tt.as_ptr(), 2).is_err()
        || wb16(data, data_end, l3 + 10, 0).is_err()
        || write_bytes(data, data_end, l3 + 12, ext_b.as_ptr(), 4).is_err()
        || write_bytes(data, data_end, l3 + 16, dst4.as_ptr(), 4).is_err()
    {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    match csum_add(data, data_end, l3, IPV4_MIN_LEN as u32, 0) {
        Ok(s) => {
            if wb16(data, data_end, l3 + 10, csum_fold(s)).is_err() {
                stat(S_TRANSLATION_ERR, 0);
                return xdp_action::XDP_DROP;
            }
        }
        Err(()) => {
            stat(S_CHECKSUM_ERR, 0);
            return xdp_action::XDP_DROP;
        }
    }
    // Transport.
    if wb16(data, data_end, new_l4, ext_port).is_err() {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    if out_proto == PROTO_TCP || out_proto == PROTO_UDP {
        let coff = if out_proto == PROTO_TCP { 16 } else { 6 };
        if wb16(data, data_end, new_l4 + coff, 0).is_err() {
            stat(S_TRANSLATION_ERR, 0);
            return xdp_action::XDP_DROP;
        }
        let pseudo = pseudo_v4(ext_ip, u32::from_be_bytes(dst4), out_proto, seg_len as u16);
        let sum = match csum_add(data, data_end, new_l4, seg_len, pseudo) {
            Ok(s) => s,
            Err(()) => {
                stat(S_CHECKSUM_ERR, 0);
                return xdp_action::XDP_DROP;
            }
        };
        if wb16(data, data_end, new_l4 + coff, csum_fold(sum)).is_err() {
            stat(S_TRANSLATION_ERR, 0);
            return xdp_action::XDP_DROP;
        }
    } else {
        // ICMPv6 echo -> ICMP echo.
        let nt = match rb(data, data_end, new_l4) {
            Ok(ICMPV6_ECHO_REQUEST) => ICMP_ECHO_REQUEST,
            _ => ICMP_ECHO_REPLY,
        };
        let ntb = [nt];
        if write_bytes(data, data_end, new_l4, ntb.as_ptr(), 1).is_err()
            || wb16(data, data_end, new_l4 + 4, ext_port).is_err()
            || wb16(data, data_end, new_l4 + 2, 0).is_err()
        {
            stat(S_TRANSLATION_ERR, 0);
            return xdp_action::XDP_DROP;
        }
        let sum = match csum_add(data, data_end, new_l4, seg_len, 0) {
            Ok(s) => s,
            Err(()) => {
                stat(S_CHECKSUM_ERR, 0);
                return xdp_action::XDP_DROP;
            }
        };
        if wb16(data, data_end, new_l4 + 2, csum_fold(sum)).is_err() {
            stat(S_TRANSLATION_ERR, 0);
            return xdp_action::XDP_DROP;
        }
    }
    stat(S_V6_TO_V4, new_len as u64);
    if cfg.v4_ifindex == 0 {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    unsafe { bpf_redirect(cfg.v4_ifindex, 0) as u32 }
}

/// IPv4 -> IPv6 reverse path.
///
#[inline(always)]
fn handle_v4(ctx: &XdpContext, data: usize, data_end: usize, l3: u32, pkt_len: u32) -> u32 {
    if data + zext(l3 + IPV4_MIN_LEN as u32) > data_end {
        stat(S_INVALID, 0);
        return xdp_action::XDP_DROP;
    }
    let b0 = match rb(data, data_end, l3) {
        Ok(v) => v,
        Err(()) => {
            stat(S_INVALID, 0);
            return xdp_action::XDP_DROP;
        }
    };
    if b0 >> 4 != 4 {
        stat(S_INVALID, 0);
        return xdp_action::XDP_DROP;
    }
    if b0 & 0x0f != 5 {
        stat(S_UNSUPPORTED, 0);
        return xdp_action::XDP_PASS; // IP options
    }
    let total = match rb16(data, data_end, l3 + 2) {
        Ok(v) => v as u32,
        Err(()) => {
            stat(S_INVALID, 0);
            return xdp_action::XDP_DROP;
        }
    };
    if total < IPV4_MIN_LEN as u32 || data + zext(l3 + total) > data_end {
        stat(S_INVALID, 0);
        return xdp_action::XDP_DROP;
    }
    let frag = match rb16(data, data_end, l3 + 6) {
        Ok(v) => v,
        Err(()) => {
            stat(S_INVALID, 0);
            return xdp_action::XDP_DROP;
        }
    };
    if frag & 0x3FFF != 0 || frag & 0x2000 != 0 {
        stat(S_FRAGMENT, 0);
        return xdp_action::XDP_DROP;
    }
    let ttl = match rb(data, data_end, l3 + 8) {
        Ok(v) => v,
        Err(()) => {
            stat(S_INVALID, 0);
            return xdp_action::XDP_DROP;
        }
    };
    if ttl <= 1 {
        stat(S_INVALID, 0);
        return xdp_action::XDP_DROP;
    }
    let proto = match rb(data, data_end, l3 + 9) {
        Ok(v) => v,
        Err(()) => {
            stat(S_INVALID, 0);
            return xdp_action::XDP_DROP;
        }
    };
    if proto != PROTO_TCP && proto != PROTO_UDP && proto != PROTO_ICMP {
        stat(S_UNSUPPORTED, 0);
        return xdp_action::XDP_PASS;
    }
    // Header checksum validation (cheap, fixed 20 bytes).
    match csum_add(data, data_end, l3, IPV4_MIN_LEN as u32, 0) {
        Ok(s) if csum_fold(s) == 0 => {}
        _ => {
            stat(S_CHECKSUM_ERR, 0);
            return xdp_action::XDP_DROP;
        }
    }
    let mut src4 = [0u8; 4];
    let mut dst4 = [0u8; 4];
    if copy4(data, data_end, l3 + 12, src4.as_mut_ptr()).is_err()
        || copy4(data, data_end, l3 + 16, dst4.as_mut_ptr()).is_err()
    {
        stat(S_INVALID, 0);
        return xdp_action::XDP_DROP;
    }
    let tos = rb(data, data_end, l3 + 1).unwrap_or(0);
    let cfg: &ConfigValue = match CONFIG.get(0) {
        Some(c) => c,
        None => return xdp_action::XDP_PASS,
    };
    if !in_pool(cfg, u32::from_be_bytes(dst4)) {
        return xdp_action::XDP_PASS; // not ours
    }
    let l4 = l3 + IPV4_MIN_LEN as u32;
    let (sport, dport, flags): (u16, u16, u8) = match proto {
        PROTO_TCP => {
            if data + zext(l4 + TCP_MIN_LEN as u32) > data_end {
                stat(S_INVALID, 0);
                return xdp_action::XDP_DROP;
            }
            match (
                rb16(data, data_end, l4),
                rb16(data, data_end, l4 + 2),
                rb(data, data_end, l4 + 13),
            ) {
                (Ok(a), Ok(b), Ok(c)) => (a, b, c),
                _ => {
                    stat(S_INVALID, 0);
                    return xdp_action::XDP_DROP;
                }
            }
        }
        PROTO_UDP => {
            if data + zext(l4 + UDP_LEN as u32) > data_end {
                stat(S_INVALID, 0);
                return xdp_action::XDP_DROP;
            }
            match (rb16(data, data_end, l4), rb16(data, data_end, l4 + 2)) {
                (Ok(a), Ok(b)) => (a, b, 0),
                _ => {
                    stat(S_INVALID, 0);
                    return xdp_action::XDP_DROP;
                }
            }
        }
        _ => {
            if data + zext(l4 + ICMP_MIN_LEN as u32) > data_end {
                stat(S_INVALID, 0);
                return xdp_action::XDP_DROP;
            }
            let typ = match rb(data, data_end, l4) {
                Ok(t) => t,
                Err(()) => {
                    stat(S_INVALID, 0);
                    return xdp_action::XDP_DROP;
                }
            };
            if typ != ICMP_ECHO_REQUEST && typ != ICMP_ECHO_REPLY {
                stat(S_UNSUPPORTED, 0);
                return xdp_action::XDP_PASS;
            }
            match rb16(data, data_end, l4 + 4) {
                Ok(id) => (id, id, 0),
                Err(()) => {
                    stat(S_INVALID, 0);
                    return xdp_action::XDP_DROP;
                }
            }
        }
    };
    let seg_len = total - IPV4_MIN_LEN as u32;
    if seg_len > MAX_COPY || seg_len < 4 {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_PASS;
    }
    let now = now_ns();
    let rkey = SessionKeyV4 {
        ext4: u32::from_be_bytes(dst4),
        ext_port: dport,
        proto,
        _pad: 0,
        srv4: u32::from_be_bytes(src4),
        srv_port: sport,
        _pad2: 0,
    };
    let rsess = unsafe { SESSION_V4_TO_V6.get(&rkey) };
    let (client6, client_port) = match rsess {
        Some(s) => {
            let c = (s.client6, s.client_port);
            refresh_session_rev(&rkey, flags, false, now);
            refresh_bib(&c.0, c.1, proto, now);
            c
        }
        None => {
            stat(S_LOOKUP_MISS, 0);
            // Static bindings admit IPv4-initiated flows (TCP/UDP only).
            if proto != PROTO_TCP && proto != PROTO_UDP {
                return xdp_action::XDP_DROP;
            }
            let skey = StaticKeyV4 {
                ipv4: u32::from_be_bytes(dst4),
                port: dport,
                proto,
                _pad: 0,
            };
            let st = match unsafe { STATIC_V4.get(&skey) } {
                Some(v) => v,
                None => return xdp_action::XDP_DROP, // filtering: no unsolicited inbound
            };
            stat(S_STATIC_HIT, 0);
            mk_sessions(
                proto,
                &st.ipv6,
                st.port,
                u32::from_be_bytes(src4),
                sport,
                u32::from_be_bytes(dst4),
                dport,
                0,
                now,
            );
            (st.ipv6, st.port)
        }
    };

    // Grow: extend the tail first, then shift the segment 20 bytes right.
    let rc = unsafe { bpf_xdp_adjust_tail(ctx.ctx as *mut _, 20) };
    if rc != 0 {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    let new_l4 = l4 + 20;
    if parse::move_right(data, data_end, new_l4, l4, seg_len).is_err() {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    let new_len = pkt_len + 20;

    if write_bytes(data, data_end, 0, cfg.next_hop_v6.as_ptr(), 6).is_err()
        || write_bytes(data, data_end, 6, cfg.mac_lan.as_ptr(), 6).is_err()
        || wb16(data, data_end, l3 - 2, ETH_P_IPV6).is_err()
    {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    let src6 = embed_v6(cfg.prefix.as_ptr(), cfg.prefix_len, src4.as_ptr());
    let out_proto = if proto == PROTO_ICMP {
        PROTO_ICMPV6
    } else {
        proto
    };
    // Traffic class = TOS: high 4 bits into byte 0, low 4 bits into byte 1.
    let h60 = [0x60 | (tos >> 4), (tos << 4) & 0xf0, 0, 0];
    let pt = [out_proto, ttl - 1];
    if write_bytes(data, data_end, l3, h60.as_ptr(), 4).is_err()
        || wb16(data, data_end, l3 + 4, seg_len as u16).is_err()
        || write_bytes(data, data_end, l3 + 6, pt.as_ptr(), 2).is_err()
        || write_bytes(data, data_end, l3 + 8, src6.as_ptr(), 16).is_err()
        || write_bytes(data, data_end, l3 + 24, client6.as_ptr(), 16).is_err()
    {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    if out_proto == PROTO_TCP || out_proto == PROTO_UDP {
        if wb16(data, data_end, new_l4 + 2, client_port).is_err() {
            stat(S_TRANSLATION_ERR, 0);
            return xdp_action::XDP_DROP;
        }
        let coff = if out_proto == PROTO_TCP { 16 } else { 6 };
        if wb16(data, data_end, new_l4 + coff, 0).is_err() {
            stat(S_TRANSLATION_ERR, 0);
            return xdp_action::XDP_DROP;
        }
        let pseudo = pseudo_v6(src6.as_ptr(), client6.as_ptr(), out_proto, seg_len as u32);
        let sum = match csum_add(data, data_end, new_l4, seg_len, pseudo) {
            Ok(s) => s,
            Err(()) => {
                stat(S_CHECKSUM_ERR, 0);
                return xdp_action::XDP_DROP;
            }
        };
        let mut c = csum_fold(sum);
        if out_proto == PROTO_UDP && c == 0 {
            c = 0xFFFF; // UDP over IPv6: zero is illegal
        }
        if wb16(data, data_end, new_l4 + coff, c).is_err() {
            stat(S_TRANSLATION_ERR, 0);
            return xdp_action::XDP_DROP;
        }
    } else {
        let nt = match rb(data, data_end, new_l4) {
            Ok(ICMP_ECHO_REQUEST) => ICMPV6_ECHO_REQUEST,
            _ => ICMPV6_ECHO_REPLY,
        };
        let ntb = [nt];
        if write_bytes(data, data_end, new_l4, ntb.as_ptr(), 1).is_err()
            || wb16(data, data_end, new_l4 + 4, client_port).is_err()
            || wb16(data, data_end, new_l4 + 2, 0).is_err()
        {
            stat(S_TRANSLATION_ERR, 0);
            return xdp_action::XDP_DROP;
        }
        let pseudo = pseudo_v6(src6.as_ptr(), client6.as_ptr(), out_proto, seg_len as u32);
        let sum = match csum_add(data, data_end, new_l4, seg_len, pseudo) {
            Ok(s) => s,
            Err(()) => {
                stat(S_CHECKSUM_ERR, 0);
                return xdp_action::XDP_DROP;
            }
        };
        if wb16(data, data_end, new_l4 + 2, csum_fold(sum)).is_err() {
            stat(S_TRANSLATION_ERR, 0);
            return xdp_action::XDP_DROP;
        }
    }
    stat(S_V4_TO_V6, new_len as u64);
    if cfg.v6_ifindex == 0 {
        stat(S_TRANSLATION_ERR, 0);
        return xdp_action::XDP_DROP;
    }
    unsafe { bpf_redirect(cfg.v6_ifindex, 0) as u32 }
}

/// Map the on-wire v6 L4 protocol to the BIB/session tag
/// (ICMPv6 queries fold into `PROTO_ICMP` per RFC 7915).
#[inline(always)]
fn map_proto(wire: u8) -> u8 {
    if wire == PROTO_ICMPV6 {
        PROTO_ICMP
    } else {
        wire
    }
}

#[xdp]
pub fn nat64(ctx: XdpContext) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = data_end.saturating_sub(data) as u32;
    if pkt_len < ETH_LEN as u32 {
        return xdp_action::XDP_DROP;
    }
    let (etype, l3) = match parse_eth(data, data_end) {
        Ok(v) => v,
        Err(()) => {
            stat(S_INVALID, 0);
            return xdp_action::XDP_DROP;
        }
    };
    match etype {
        ETH_P_IPV6 => handle_v6(&ctx, data, data_end, l3, pkt_len),
        ETH_P_IP => handle_v4(&ctx, data, data_end, l3, pkt_len),
        _ => xdp_action::XDP_PASS,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
