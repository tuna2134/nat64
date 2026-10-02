//! Pure-Rust packet parsing and linear-buffer translation.
//!
//! These functions operate on plain byte slices and carry **no eBPF
//! dependencies**, so they are exhaustively unit-tested here. The XDP program
//! re-implements the same algorithm with raw-pointer reads (small, verifier
//! friendly parsing primitives are intentionally duplicated there rather than
//! shared, because the verifier must see explicit `data < ptr < data_end`
//! guards at each access).
//!
//! Wire conventions: IPv4 header 20 bytes (no options; packets with options
//! take the `Unsupported` path), IPv6 header 40 bytes, extension headers are
//! skipped up to [`crate::proto::MAX_EXT_HEADERS`], fragments are rejected.

use crate::{checksum, prefix::Nat64Prefix, proto::*};

/// Packet parse/translate failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    /// Buffer too short for the claimed headers.
    TooShort,
    /// Wrong IP version nibble.
    BadVersion,
    /// Destination is not inside the NAT64 prefix (v6 path).
    NotForUs,
    /// Extension headers too deep, AH/ESP, IPv4 options, non-UDP/TCP/ICMP.
    Unsupported,
    /// Non-first fragment or MF set (no reassembly; see docs).
    Fragment,
    /// Hop limit / TTL expired in translation.
    HopLimitExceeded,
    /// Destination buffer has no room to grow (v4 -> v6 path).
    NoSpace,
    /// Bad header lengths / checksum-field misuse.
    Invalid,
}

/// Ethernet decode result.
#[derive(Debug, Clone, Copy)]
pub struct EthInfo {
    pub ethertype: u16,
    /// Offset of the L3 header (14 + 4 * vlans).
    pub l3_off: usize,
}

/// Decode Ethernet + up to 2 VLAN tags.
pub fn parse_eth(buf: &[u8]) -> Result<EthInfo, PacketError> {
    if buf.len() < ETH_LEN {
        return Err(PacketError::TooShort);
    }
    let mut etype = u16::from_be_bytes([buf[12], buf[13]]);
    let mut off = ETH_LEN;
    let mut tags = 0;
    while (etype == ETH_P_8021Q || etype == ETH_P_8021AD) && tags < MAX_VLAN_TAGS {
        if buf.len() < off + VLAN_LEN {
            return Err(PacketError::TooShort);
        }
        etype = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
        off += VLAN_LEN;
        tags += 1;
    }
    if etype == ETH_P_8021Q || etype == ETH_P_8021AD {
        return Err(PacketError::Unsupported);
    }
    Ok(EthInfo {
        ethertype: etype,
        l3_off: off,
    })
}

/// Decoded IPv6 header (fixed 40 bytes).
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Info {
    pub traffic_class: u8,
    pub payload_len: u16,
    pub next: u8,
    pub hop_limit: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

pub fn parse_ipv6(buf: &[u8], off: usize) -> Result<Ipv6Info, PacketError> {
    if buf.len() < off + IPV6_LEN {
        return Err(PacketError::TooShort);
    }
    let b = &buf[off..off + IPV6_LEN];
    if b[0] >> 4 != 6 {
        return Err(PacketError::BadVersion);
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&b[8..24]);
    dst.copy_from_slice(&b[24..40]);
    Ok(Ipv6Info {
        traffic_class: ((b[0] & 0x0f) << 4) | (b[1] >> 4),
        payload_len: u16::from_be_bytes([b[4], b[5]]),
        next: b[6],
        hop_limit: b[7],
        src,
        dst,
    })
}

/// Decoded IPv4 header (options rejected).
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Info {
    pub total_len: u16,
    pub proto: u8,
    pub ttl: u8,
    pub tos: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

pub fn parse_ipv4(buf: &[u8], off: usize) -> Result<Ipv4Info, PacketError> {
    if buf.len() < off + IPV4_MIN_LEN {
        return Err(PacketError::TooShort);
    }
    let b = &buf[off..off + IPV4_MIN_LEN];
    if b[0] >> 4 != 4 {
        return Err(PacketError::BadVersion);
    }
    if (b[0] & 0x0f) != 5 {
        // IP options: not translated.
        return Err(PacketError::Unsupported);
    }
    let frag = u16::from_be_bytes([b[6], b[7]]);
    if frag & 0x3FFF != 0 || frag & 0x2000 != 0 {
        return Err(PacketError::Fragment);
    }
    Ok(Ipv4Info {
        total_len: u16::from_be_bytes([b[2], b[3]]),
        proto: b[9],
        ttl: b[8],
        tos: b[1],
        src: [b[12], b[13], b[14], b[15]],
        dst: [b[16], b[17], b[18], b[19]],
    })
}

/// Transport location after walking IPv6 extension headers.
#[derive(Debug, Clone, Copy)]
pub struct L4Loc {
    /// Final upper-layer protocol (TCP/UDP/ICMPv6).
    pub proto: u8,
    /// Offset of the transport header.
    pub off: usize,
}

/// Walk IPv6 extension headers. Returns the transport protocol + offset.
/// Fragments, AH/ESP and over-deep chains are rejected per policy.
pub fn find_v6_transport(buf: &[u8], v6_off: usize, first_next: u8) -> Result<L4Loc, PacketError> {
    let mut next = first_next;
    let mut off = v6_off + IPV6_LEN;
    let mut depth = 0;
    loop {
        match next {
            PROTO_TCP | PROTO_UDP | PROTO_ICMPV6 => return Ok(L4Loc { proto: next, off }),
            IPV6_AH | IPV6_ESP => return Err(PacketError::Unsupported),
            IPV6_HBH | IPV6_ROUTING | IPV6_DSTOPTS => {
                if depth >= MAX_EXT_HEADERS {
                    return Err(PacketError::Unsupported);
                }
                if buf.len() < off + 2 {
                    return Err(PacketError::TooShort);
                }
                next = buf[off];
                let ext_len = (buf[off + 1] as usize + 1) * 8;
                off += ext_len;
                if off > buf.len() {
                    return Err(PacketError::TooShort);
                }
                depth += 1;
            }
            IPV6_FRAG => {
                // Any fragment header: first-fragment has offset 0 but still
                // lacks guarantees; policy is no reassembly.
                if buf.len() < off + 8 {
                    return Err(PacketError::TooShort);
                }
                let frag_off = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
                if frag_off & 0xFFF8 != 0 || buf[off + 3] & 0x01 != 0 {
                    return Err(PacketError::Fragment);
                }
                // First fragment: skip the 8-byte frag header and continue.
                if depth >= MAX_EXT_HEADERS {
                    return Err(PacketError::Unsupported);
                }
                next = buf[off];
                off += 8;
                depth += 1;
            }
            _ => return Err(PacketError::Unsupported),
        }
    }
}

/// Flow tuple extracted from a v6 -> v4 packet (for BIB/session handling).
#[derive(Debug, Clone, Copy)]
pub struct FlowV6 {
    pub proto: u8,
    /// TCP flags (0 for UDP/ICMP).
    pub tcp_flags: u8,
    /// Source port / ICMP identifier (host order).
    pub src_port: u16,
    /// Destination port / ICMP identifier (host order).
    pub dst_port: u16,
    /// Extracted destination IPv4.
    pub dst4: [u8; 4],
}

/// Flow tuple extracted from a v4 -> v6 packet.
#[derive(Debug, Clone, Copy)]
pub struct FlowV4 {
    pub proto: u8,
    pub tcp_flags: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub src4: [u8; 4],
}

/// Read transport ports / ICMP id at `l4` for `proto`.
fn read_flow_ports(buf: &[u8], l4: usize, proto: u8) -> Result<(u16, u16, u8), PacketError> {
    if proto == PROTO_TCP || proto == PROTO_UDP {
        if buf.len() < l4 + 4 {
            return Err(PacketError::TooShort);
        }
        let flags = if proto == PROTO_TCP {
            if buf.len() < l4 + TCP_MIN_LEN {
                return Err(PacketError::TooShort);
            }
            buf[l4 + 13]
        } else {
            0
        };
        Ok((
            u16::from_be_bytes([buf[l4], buf[l4 + 1]]),
            u16::from_be_bytes([buf[l4 + 2], buf[l4 + 3]]),
            flags,
        ))
    } else if proto == PROTO_ICMPV6 || proto == PROTO_ICMP {
        if buf.len() < l4 + ICMP_MIN_LEN {
            return Err(PacketError::TooShort);
        }
        let typ = buf[l4];
        let ok = matches!(
            (proto, typ),
            (PROTO_ICMPV6, ICMPV6_ECHO_REQUEST)
                | (PROTO_ICMPV6, ICMPV6_ECHO_REPLY)
                | (PROTO_ICMP, ICMP_ECHO_REQUEST)
                | (PROTO_ICMP, ICMP_ECHO_REPLY)
        );
        if !ok {
            return Err(PacketError::Unsupported);
        }
        let id = u16::from_be_bytes([buf[l4 + 4], buf[l4 + 5]]);
        Ok((id, id, 0))
    } else {
        Err(PacketError::Unsupported)
    }
}

/// Translate an IPv6/TCP|UDP|ICMPv6-echo packet to IPv4 in a linear buffer.
///
/// `buf[..pkt_len]` holds the full Ethernet frame on entry; `buf` must have
/// room for the (shorter) output. Returns the flow tuple and the new length.
/// Extension headers are dropped; fragments rejected.
pub fn translate_v6_to_v4(
    buf: &mut [u8],
    pkt_len: usize,
    prefix: &Nat64Prefix,
    ext_ip: [u8; 4],
    ext_port: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Result<(FlowV6, usize), PacketError> {
    let eth = parse_eth(&buf[..pkt_len])?;
    if eth.ethertype != ETH_P_IPV6 {
        return Err(PacketError::NotForUs);
    }
    let ip6 = parse_ipv6(buf, eth.l3_off)?;
    if pkt_len < eth.l3_off + IPV6_LEN {
        return Err(PacketError::TooShort);
    }
    let dst4 = prefix
        .extract(&ip6.dst)
        .map_err(|_| PacketError::NotForUs)?;
    if ip6.hop_limit <= 1 {
        return Err(PacketError::HopLimitExceeded);
    }
    let loc = find_v6_transport(&buf[..pkt_len], eth.l3_off, ip6.next)?;
    if loc.proto != PROTO_TCP && loc.proto != PROTO_UDP && loc.proto != PROTO_ICMPV6 {
        return Err(PacketError::Unsupported);
    }
    let (src_port, dst_port, flags) = read_flow_ports(&buf[..pkt_len], loc.off, loc.proto)?;

    // Shift the transport segment 20 bytes toward the head (drops ext hdrs).
    let new_l4 = eth.l3_off + IPV4_MIN_LEN;
    let seg_len = pkt_len - loc.off;
    if loc.off < new_l4 {
        return Err(PacketError::Invalid);
    }
    buf.copy_within(loc.off..pkt_len, new_l4);
    let new_len = new_l4 + seg_len;

    // Ethernet rewrite (EtherType lives just before the L3 offset,
    // which also handles stacked VLAN tags).
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[eth.l3_off - 2..eth.l3_off].copy_from_slice(&ETH_P_IP.to_be_bytes());

    // IPv4 header.
    let ttl = ip6.hop_limit - 1;
    let total = (new_len - eth.l3_off) as u16;
    let h = &mut buf[eth.l3_off..eth.l3_off + IPV4_MIN_LEN];
    h[0] = 0x45;
    h[1] = ip6.traffic_class;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h[4..6].copy_from_slice(&[0, 0]); // identification
    h[6..8].copy_from_slice(&[0x40, 0]); // DF set, offset 0
    h[8] = ttl;
    h[9] = if loc.proto == PROTO_ICMPV6 {
        PROTO_ICMP
    } else {
        loc.proto
    };
    h[10..12].copy_from_slice(&[0, 0]);
    h[12..16].copy_from_slice(&ext_ip);
    h[16..20].copy_from_slice(&dst4);
    let mut hbuf = [0u8; IPV4_MIN_LEN];
    hbuf.copy_from_slice(h);
    let csum = checksum::ipv4_header_checksum(&hbuf);
    h[10..12].copy_from_slice(&csum.to_be_bytes());

    // Transport rewrite + checksum.
    let proto = h[9];
    let seg = &mut buf[new_l4..new_len];
    if proto == PROTO_TCP || proto == PROTO_UDP {
        seg[0..2].copy_from_slice(&ext_port.to_be_bytes());
        // Destination port already in place. Checksum field: TCP +16, UDP +6.
        let coff = if proto == PROTO_TCP { 16 } else { 6 };
        if seg.len() < coff + 2 {
            return Err(PacketError::TooShort);
        }
        seg[coff..coff + 2].copy_from_slice(&[0, 0]);
        let c = if proto == PROTO_TCP {
            checksum::tcp_checksum_v4(&ext_ip, &dst4, seg)
        } else {
            checksum::udp_checksum_v4(&ext_ip, &dst4, seg)
        };
        seg[coff..coff + 2].copy_from_slice(&c.to_be_bytes());
    } else {
        // ICMPv6 echo -> ICMP echo.
        seg[0] = if seg[0] == ICMPV6_ECHO_REQUEST {
            ICMP_ECHO_REQUEST
        } else {
            ICMP_ECHO_REPLY
        };
        seg[4..6].copy_from_slice(&ext_port.to_be_bytes());
        seg[2..4].copy_from_slice(&[0, 0]);
        let c = checksum::icmp_checksum(seg);
        seg[2..4].copy_from_slice(&c.to_be_bytes());
    }

    Ok((
        FlowV6 {
            proto,
            tcp_flags: flags,
            src_port,
            dst_port,
            dst4,
        },
        new_len,
    ))
}

/// Translate an IPv4/TCP|UDP|ICMP-echo packet to IPv6 in a linear buffer.
///
/// `buf` must have at least 20 bytes of tailroom past `pkt_len`.
/// `client6`/`client_port` come from the reverse session/BIB lookup.
pub fn translate_v4_to_v6(
    buf: &mut [u8],
    pkt_len: usize,
    prefix: &Nat64Prefix,
    client6: [u8; 16],
    client_port: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Result<(FlowV4, usize), PacketError> {
    let eth = parse_eth(&buf[..pkt_len])?;
    if eth.ethertype != ETH_P_IP {
        return Err(PacketError::NotForUs);
    }
    let ip4 = parse_ipv4(buf, eth.l3_off)?;
    if ip4.ttl <= 1 {
        return Err(PacketError::HopLimitExceeded);
    }
    if ip4.proto != PROTO_TCP && ip4.proto != PROTO_UDP && ip4.proto != PROTO_ICMP {
        return Err(PacketError::Unsupported);
    }
    let l4 = eth.l3_off + IPV4_MIN_LEN;
    if pkt_len < l4 {
        return Err(PacketError::TooShort);
    }
    let (src_port, dst_port, flags) = read_flow_ports(&buf[..pkt_len], l4, ip4.proto)?;

    // Grow: shift the segment 20 bytes toward the tail.
    let new_l4 = l4 + 20;
    if buf.len() < pkt_len + 20 {
        return Err(PacketError::NoSpace);
    }
    buf.copy_within(l4..pkt_len, new_l4);
    let new_len = pkt_len + 20;

    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[eth.l3_off - 2..eth.l3_off].copy_from_slice(&ETH_P_IPV6.to_be_bytes());

    let src6 = prefix.embed(&ip4.src);
    let hlim = ip4.ttl - 1;
    let payload_len = (new_len - eth.l3_off - IPV6_LEN) as u16;
    let proto6 = if ip4.proto == PROTO_ICMP {
        PROTO_ICMPV6
    } else {
        ip4.proto
    };
    let h = &mut buf[eth.l3_off..eth.l3_off + IPV6_LEN];
    // Traffic class = TOS: high 4 bits into byte 0, low 4 bits into byte 1.
    h[0] = 0x60 | (ip4.tos >> 4);
    h[1] = (ip4.tos << 4) & 0xf0;
    h[2] = 0;
    h[3] = 0;
    h[4..6].copy_from_slice(&payload_len.to_be_bytes());
    h[6] = proto6;
    h[7] = hlim;
    h[8..24].copy_from_slice(&src6);
    h[24..40].copy_from_slice(&client6);

    let seg = &mut buf[new_l4..new_len];
    if proto6 == PROTO_TCP || proto6 == PROTO_UDP {
        // Destination port becomes the original client port.
        seg[2..4].copy_from_slice(&client_port.to_be_bytes());
        let coff = if proto6 == PROTO_TCP { 16 } else { 6 };
        if seg.len() < coff + 2 {
            return Err(PacketError::TooShort);
        }
        seg[coff..coff + 2].copy_from_slice(&[0, 0]);
        let c = if proto6 == PROTO_TCP {
            checksum::tcp_checksum_v6(&src6, &client6, seg)
        } else {
            checksum::udp_checksum_v6(&src6, &client6, seg)
        };
        seg[coff..coff + 2].copy_from_slice(&c.to_be_bytes());
    } else {
        seg[0] = if seg[0] == ICMP_ECHO_REQUEST {
            ICMPV6_ECHO_REQUEST
        } else {
            ICMPV6_ECHO_REPLY
        };
        seg[4..6].copy_from_slice(&client_port.to_be_bytes());
        seg[2..4].copy_from_slice(&[0, 0]);
        let c = checksum::icmpv6_checksum(&src6, &client6, seg);
        seg[2..4].copy_from_slice(&c.to_be_bytes());
    }

    Ok((
        FlowV4 {
            proto: ip4.proto,
            tcp_flags: flags,
            src_port,
            dst_port,
            src4: ip4.src,
        },
        new_len,
    ))
}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use super::*;
    use crate::checksum as csum;

    fn v6_udp_fixture() -> Vec<u8> {
        // eth(14) + ipv6(40) + udp(8) + "hi"(2).
        let mut p = vec![0u8; 14 + 40 + 8 + 2];
        // MACs.
        p[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        p[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        p[12..14].copy_from_slice(&[0x86, 0xDD]);
        // IPv6.
        p[14] = 0x60;
        p[18] = 0;
        p[19] = 10; // payload len
        p[20] = PROTO_UDP;
        p[21] = 64;
        // src 2001:db8::1
        p[22] = 0x20;
        p[23] = 0x01;
        p[24] = 0x0d;
        p[25] = 0xb8;
        p[37] = 0x01;
        // dst 64:ff9b::c000:221
        let dst = Nat64Prefix::well_known().embed(&[192, 0, 2, 33]);
        p[38..54].copy_from_slice(&dst);
        // UDP sport 54321 dport 53.
        let l4 = 54;
        p[l4..l4 + 2].copy_from_slice(&54321u16.to_be_bytes());
        p[l4 + 2..l4 + 4].copy_from_slice(&53u16.to_be_bytes());
        p[l4 + 4..l4 + 6].copy_from_slice(&10u16.to_be_bytes());
        p[l4 + 8] = b'h';
        p[l4 + 9] = b'i';
        let c = csum::udp_checksum_v6(&p[22..38].try_into().unwrap(), &dst, &p[l4..]);
        p[l4 + 6..l4 + 8].copy_from_slice(&c.to_be_bytes());
        p
    }

    #[test]
    fn v6_to_v4_udp_round_trip() {
        let mut pkt = v6_udp_fixture();
        let len = pkt.len();
        let prefix = Nat64Prefix::well_known();
        let ext_ip = [203, 0, 113, 10];
        let (flow, new_len) =
            translate_v6_to_v4(&mut pkt, len, &prefix, ext_ip, 40000, [1; 6], [2; 6])
                .expect("translate");
        assert_eq!(flow.proto, PROTO_UDP);
        assert_eq!(flow.src_port, 54321);
        assert_eq!(flow.dst_port, 53);
        assert_eq!(flow.dst4, [192, 0, 2, 33]);
        assert_eq!(new_len, len - 20);
        // Verify IPv4 header.
        let ip = parse_ipv4(&pkt[..new_len], 14).unwrap();
        assert_eq!(ip.src, ext_ip);
        assert_eq!(ip.dst, [192, 0, 2, 33]);
        assert_eq!(ip.proto, PROTO_UDP);
        assert_eq!(ip.ttl, 63);
        // Verify UDP checksum over IPv4.
        let seg = &pkt[14 + 20..new_len];
        assert_eq!(u16::from_be_bytes([seg[0], seg[1]]), 40000);
        assert_eq!(u16::from_be_bytes([seg[2], seg[3]]), 53);
        assert_eq!(
            csum::finalize(
                csum::sum_bytes(seg)
                    + csum::ipv4_pseudo_sum(&ext_ip, &[192, 0, 2, 33], PROTO_UDP, seg.len() as u16)
            ),
            0
        );

        // Reverse translation recovers the client tuple. Simulate the server
        // reply by swapping ports (53 -> 40000) and fixing the checksum.
        let seg = &mut pkt[14 + 20..new_len];
        seg[0..2].copy_from_slice(&53u16.to_be_bytes());
        seg[2..4].copy_from_slice(&40000u16.to_be_bytes());
        seg[6..8].copy_from_slice(&[0, 0]);
        let rc = csum::udp_checksum_v4(&[192, 0, 2, 33], &ext_ip, seg);
        seg[6..8].copy_from_slice(&rc.to_be_bytes());
        // Server source address becomes the reply source.
        pkt[14 + 12..14 + 16].copy_from_slice(&[192, 0, 2, 33]);
        pkt[14 + 16..14 + 20].copy_from_slice(&ext_ip);
        let mut hbuf2 = [0u8; IPV4_MIN_LEN];
        hbuf2.copy_from_slice(&pkt[14..14 + IPV4_MIN_LEN]);
        let rc2 = csum::ipv4_header_checksum(&hbuf2);
        pkt[14 + 10..14 + 12].copy_from_slice(&rc2.to_be_bytes());

        // Reverse translation recovers the client tuple.
        let mut buf = vec![0u8; new_len + 64];
        buf[..new_len].copy_from_slice(&pkt[..new_len]);
        let mut client6 = [0u8; 16];
        client6[0] = 0x20;
        client6[1] = 0x01;
        client6[2] = 0x0d;
        client6[3] = 0xb8;
        client6[15] = 0x01;
        let (rf, rlen) =
            translate_v4_to_v6(&mut buf, new_len, &prefix, client6, 54321, [3; 6], [4; 6])
                .expect("reverse");
        assert_eq!(rlen, len);
        assert_eq!(rf.src_port, 53);
        let ip6 = parse_ipv6(&buf[..rlen], 14).unwrap();
        assert_eq!(ip6.dst, client6);
        // Payload preserved.
        assert_eq!(&buf[rlen - 2..rlen], b"hi");
    }

    #[test]
    fn tcp_syn_flags_and_translation() {
        let mut pkt = v6_udp_fixture();
        // Morph into TCP SYN: rewrite proto + 20-byte header.
        pkt.resize(14 + 40 + 20, 0);
        pkt[20] = PROTO_TCP;
        pkt[18] = 0;
        pkt[19] = 20;
        let l4 = 54;
        pkt[l4..l4 + 2].copy_from_slice(&1234u16.to_be_bytes());
        pkt[l4 + 2..l4 + 4].copy_from_slice(&80u16.to_be_bytes());
        pkt[l4 + 13] = TCP_SYN;
        pkt[l4 + 12] = 0x50; // data offset 5
        let dst: [u8; 16] = pkt[38..54].try_into().unwrap();
        let c = csum::tcp_checksum_v6(&pkt[22..38].try_into().unwrap(), &dst, &pkt[l4..]);
        pkt[l4 + 16..l4 + 18].copy_from_slice(&c.to_be_bytes());
        let len = pkt.len();
        let (flow, new_len) = translate_v6_to_v4(
            &mut pkt,
            len,
            &Nat64Prefix::well_known(),
            [203, 0, 113, 10],
            45000,
            [1; 6],
            [2; 6],
        )
        .unwrap();
        assert_eq!(flow.proto, PROTO_TCP);
        assert_eq!(flow.tcp_flags & TCP_SYN, TCP_SYN);
        assert_eq!(new_len, len - 20);
        let seg = &pkt[14 + 20..new_len];
        assert_eq!(seg[13] & TCP_SYN, TCP_SYN);
        assert_eq!(
            csum::finalize(
                csum::sum_bytes(seg)
                    + csum::ipv4_pseudo_sum(&[203, 0, 113, 10], &[192, 0, 2, 33], PROTO_TCP, 20)
            ),
            0
        );
    }

    #[test]
    fn icmpv6_echo_translates() {
        let mut p = vec![0u8; 14 + 40 + 8 + 4];
        p[12..14].copy_from_slice(&[0x86, 0xDD]);
        p[14] = 0x60;
        p[18] = 0;
        p[19] = 12;
        p[20] = PROTO_ICMPV6;
        p[21] = 64;
        p[22 + 15] = 0x05; // src ::5
        let dst = Nat64Prefix::well_known().embed(&[198, 51, 100, 7]);
        p[38..54].copy_from_slice(&dst);
        let l4 = 54;
        p[l4] = ICMPV6_ECHO_REQUEST;
        p[l4 + 4..l4 + 6].copy_from_slice(&0x1234u16.to_be_bytes());
        p[l4 + 6..l4 + 8].copy_from_slice(&0x0007u16.to_be_bytes());
        p[l4 + 8..l4 + 12].copy_from_slice(b"ping");
        let c = csum::icmpv6_checksum(&p[22..38].try_into().unwrap(), &dst, &p[l4..]);
        p[l4 + 2..l4 + 4].copy_from_slice(&c.to_be_bytes());
        let len = p.len();
        let (flow, new_len) = translate_v6_to_v4(
            &mut p,
            len,
            &Nat64Prefix::well_known(),
            [203, 0, 113, 10],
            0x1234,
            [1; 6],
            [2; 6],
        )
        .unwrap();
        assert_eq!(flow.proto, PROTO_ICMP);
        assert_eq!(flow.src_port, 0x1234);
        assert_eq!(p[14 + 20], ICMP_ECHO_REQUEST);
        let seg = &p[14 + 20..new_len];
        assert_eq!(csum::finalize(csum::sum_bytes(seg)), 0);
    }

    #[test]
    fn tos_maps_to_traffic_class() {
        // v4 TOS 0xB8 must land in the v6 traffic-class field intact.
        let mut v4 = vec![0u8; 14 + 20 + 8 + 2];
        v4[12..14].copy_from_slice(&[0x08, 0x00]);
        v4[14] = 0x45;
        v4[15] = 0xB8;
        v4[16..18].copy_from_slice(&30u16.to_be_bytes());
        v4[22] = 64;
        v4[23] = PROTO_UDP;
        v4[26..30].copy_from_slice(&[198, 51, 100, 7]);
        v4[30..34].copy_from_slice(&[203, 0, 113, 10]);
        let l4 = 34;
        v4[l4..l4 + 2].copy_from_slice(&4000u16.to_be_bytes());
        v4[l4 + 2..l4 + 4].copy_from_slice(&5000u16.to_be_bytes());
        v4[l4 + 4..l4 + 6].copy_from_slice(&10u16.to_be_bytes());
        v4[l4 + 8] = b'O';
        v4[l4 + 9] = b'K';
        let mut hbuf = [0u8; 20];
        hbuf.copy_from_slice(&v4[14..34]);
        let c = csum::ipv4_header_checksum(&hbuf);
        v4[24..26].copy_from_slice(&c.to_be_bytes());
        let uc = csum::udp_checksum_v4(&[198, 51, 100, 7], &[203, 0, 113, 10], &v4[l4..]);
        v4[l4 + 6..l4 + 8].copy_from_slice(&uc.to_be_bytes());
        let mut client6 = [0u8; 16];
        client6[15] = 0x09;
        let mut buf = vec![0u8; v4.len() + 64];
        buf[..v4.len()].copy_from_slice(&v4);
        let vl = v4.len();
        let (_, rlen) = translate_v4_to_v6(
            &mut buf,
            vl,
            &Nat64Prefix::well_known(),
            client6,
            5000,
            [1; 6],
            [2; 6],
        )
        .unwrap();
        let ip6 = parse_ipv6(&buf[..rlen], 14).unwrap();
        assert_eq!(ip6.traffic_class, 0xB8);
    }

    #[test]
    fn rejects_fragments_options_and_esp() {
        let mut pkt = v6_udp_fixture();
        // IPv4 fragment.
        let mut v4 = vec![0u8; 14 + 20 + 8];
        v4[12..14].copy_from_slice(&[0x08, 0x00]);
        v4[14] = 0x45;
        v4[14 + 6] = 0x20; // MF
        let vl = v4.len();
        assert_eq!(
            translate_v4_to_v6(
                &mut v4,
                vl,
                &Nat64Prefix::well_known(),
                [0u8; 16],
                1,
                [1; 6],
                [2; 6]
            )
            .unwrap_err(),
            PacketError::Fragment
        );
        // IPv4 with options.
        v4[14] = 0x46;
        v4[14 + 6] = 0x00;
        assert_eq!(
            translate_v4_to_v6(
                &mut v4,
                vl,
                &Nat64Prefix::well_known(),
                [0u8; 16],
                1,
                [1; 6],
                [2; 6]
            )
            .unwrap_err(),
            PacketError::Unsupported
        );
        // ESP next header.
        pkt[20] = 50;
        let pl = pkt.len();
        assert_eq!(
            translate_v6_to_v4(
                &mut pkt,
                pl,
                &Nat64Prefix::well_known(),
                [1, 2, 3, 4],
                1,
                [1; 6],
                [2; 6]
            )
            .unwrap_err(),
            PacketError::Unsupported
        );
    }

    #[test]
    fn vlan_and_wrong_ethertype() {
        let mut p = vec![0u8; 18 + 40 + 8];
        p[12..14].copy_from_slice(&[0x81, 0x00]);
        p[14..16].copy_from_slice(&[0x00, 0x00]);
        p[16..18].copy_from_slice(&[0x86, 0xDD]);
        p[18] = 0x60;
        let info = parse_eth(&p).unwrap();
        assert_eq!(info.l3_off, 18);
        let q = vec![0u8; 14];
        assert_eq!(parse_eth(&q).unwrap().ethertype, 0);
        let mut arp = vec![0u8; 14 + 28];
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        let al = arp.len();
        assert_eq!(
            translate_v6_to_v4(
                &mut arp,
                al,
                &Nat64Prefix::well_known(),
                [1, 2, 3, 4],
                1,
                [1; 6],
                [2; 6]
            )
            .unwrap_err(),
            PacketError::NotForUs
        );
    }
}
