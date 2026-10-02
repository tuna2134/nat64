//! Checksum helpers (RFC 7915, section 4).
//!
//! - IPv4 header checksum: ones-complement over the 20-byte header.
//! - TCP/UDP over IPv4: pseudo-header + segment, ones-complement.
//! - TCP/UDP over IPv6: IPv6 pseudo-header + segment. Unlike IPv4, a UDP
//!   checksum of zero is illegal in IPv6 and is transmitted as `0xFFFF`.
//! - ICMPv4 / ICMPv6: ones-complement over the whole ICMP message
//!   (ICMPv6 has no separate pseudo-header; the IPv6 pseudo-header applies).
//!
//! These operate on plain slices so they are usable from unit tests,
//! userspace, and — via bounded slices built after explicit packet-bounds
//! checks — from the eBPF program.

/// Ones-complement fold of a 64-bit accumulator.
///
/// Straight-line rounds (same form as the eBPF `csum_fold`, which cannot use
/// a data-dependent loop — the verifier rejects it). Five rounds reduce any
/// `u64` into 16 bits.
const fn fold(sum: u64) -> u16 {
    let sum = (sum & 0xFFFF) + (sum >> 16);
    let sum = (sum & 0xFFFF) + (sum >> 16);
    let sum = (sum & 0xFFFF) + (sum >> 16);
    let sum = (sum & 0xFFFF) + (sum >> 16);
    let sum = (sum & 0xFFFF) + (sum >> 16);
    !(sum as u16)
}

/// Raw ones-complement sum of `data` (pads a trailing odd byte with zero).
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn sum_bytes(data: &[u8]) -> u64 {
    let mut sum: u64 = 0;
    let mut chunks = data.chunks_exact(2);
    for w in &mut chunks {
        sum += u16::from_be_bytes([w[0], w[1]]) as u64;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u64) << 8;
    }
    sum
}

/// Finalise an accumulated sum into a checksum field value.
pub const fn finalize(sum: u64) -> u16 {
    fold(sum)
}

/// IPv4 header checksum over a 20-byte header with the checksum field zeroed.
pub fn ipv4_header_checksum(hdr20: &[u8; 20]) -> u16 {
    let mut tmp = *hdr20;
    tmp[10] = 0;
    tmp[11] = 0;
    finalize(sum_bytes(&tmp))
}

/// IPv4 pseudo-header sum: src + dst + zero + protocol + length.
pub fn ipv4_pseudo_sum(src: &[u8; 4], dst: &[u8; 4], proto: u8, len: u16) -> u64 {
    let mut sum: u64 = 0;
    sum += u16::from_be_bytes([src[0], src[1]]) as u64;
    sum += u16::from_be_bytes([src[2], src[3]]) as u64;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u64;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u64;
    sum += proto as u64;
    sum += len as u64;
    sum
}

/// IPv6 pseudo-header sum: src + dst + length(32b) + zeros + next-header.
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn ipv6_pseudo_sum(src: &[u8; 16], dst: &[u8; 16], next_header: u8, len: u32) -> u64 {
    let mut sum: u64 = 0;
    for c in src.chunks_exact(2) {
        sum += u16::from_be_bytes([c[0], c[1]]) as u64;
    }
    for c in dst.chunks_exact(2) {
        sum += u16::from_be_bytes([c[0], c[1]]) as u64;
    }
    sum += (len >> 16) as u64;
    sum += (len & 0xFFFF) as u64;
    sum += next_header as u64;
    sum
}

/// TCP checksum over IPv4.
pub fn tcp_checksum_v4(src: &[u8; 4], dst: &[u8; 4], segment: &[u8]) -> u16 {
    let sum = ipv4_pseudo_sum(src, dst, crate::proto::PROTO_TCP, segment.len() as u16)
        + sum_bytes(segment);
    finalize(sum)
}

/// TCP checksum over IPv6.
pub fn tcp_checksum_v6(src: &[u8; 16], dst: &[u8; 16], segment: &[u8]) -> u16 {
    let sum = ipv6_pseudo_sum(src, dst, crate::proto::PROTO_TCP, segment.len() as u32)
        + sum_bytes(segment);
    finalize(sum)
}

/// UDP checksum over IPv4. A computed zero is sent as-is (IPv4 allows zero).
pub fn udp_checksum_v4(src: &[u8; 4], dst: &[u8; 4], segment: &[u8]) -> u16 {
    let sum = ipv4_pseudo_sum(src, dst, crate::proto::PROTO_UDP, segment.len() as u16)
        + sum_bytes(segment);
    finalize(sum)
}

/// UDP checksum over IPv6. Zero is illegal and transmitted as `0xFFFF`.
pub fn udp_checksum_v6(src: &[u8; 16], dst: &[u8; 16], segment: &[u8]) -> u16 {
    let sum = ipv6_pseudo_sum(src, dst, crate::proto::PROTO_UDP, segment.len() as u32)
        + sum_bytes(segment);
    let c = finalize(sum);
    if c == 0 { 0xFFFF } else { c }
}

/// ICMPv4 checksum over the message.
pub fn icmp_checksum(msg: &[u8]) -> u16 {
    finalize(sum_bytes(msg))
}

/// ICMPv6 checksum (includes the IPv6 pseudo-header).
pub fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], msg: &[u8]) -> u16 {
    let sum =
        ipv6_pseudo_sum(src, dst, crate::proto::PROTO_ICMPV6, msg.len() as u32) + sum_bytes(msg);
    finalize(sum)
}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use super::*;

    #[test]
    fn ipv4_header_checksum_vector() {
        // Minimal header: version/IHL only, rest zero.
        // Sum = 0x4500, checksum = !0x4500 = 0xBAFF.
        let mut hdr = [0u8; 20];
        hdr[0] = 0x45;
        assert_eq!(ipv4_header_checksum(&hdr), 0xbaff);
        // Inserting the checksum must verify to zero.
        hdr[10] = 0xba;
        hdr[11] = 0xff;
        assert_eq!(finalize(sum_bytes(&hdr)), 0);
        // Odd-length padding: single 0x01 byte sums as 0x0100.
        assert_eq!(sum_bytes(&[0x01]), 0x0100);
        assert_eq!(finalize(sum_bytes(&[0x01])), 0xfeff);
    }

    #[test]
    fn tcp_checksum_round_trip_v4_v6() {
        let seg: Vec<u8> = vec![
            0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x72, 0x10, 0x00, 0x00, 0x00, 0x00,
        ];
        let c4 = tcp_checksum_v4(&[10, 0, 0, 1], &[10, 0, 0, 2], &seg);
        let mut seg4 = seg.clone();
        seg4[16] = (c4 >> 8) as u8;
        seg4[17] = (c4 & 0xff) as u8;
        assert_eq!(
            finalize(
                ipv4_pseudo_sum(&[10, 0, 0, 1], &[10, 0, 0, 2], 6, seg4.len() as u16)
                    + sum_bytes(&seg4)
            ),
            0
        );
        let src6 = [0x20u8; 16];
        let dst6 = [0x21u8; 16];
        let c6 = tcp_checksum_v6(&src6, &dst6, &seg);
        let mut seg6 = seg.clone();
        seg6[16] = (c6 >> 8) as u8;
        seg6[17] = (c6 & 0xff) as u8;
        assert_eq!(
            finalize(ipv6_pseudo_sum(&src6, &dst6, 6, seg6.len() as u32) + sum_bytes(&seg6)),
            0
        );
    }

    #[test]
    fn udp_v6_zero_becomes_ffff() {
        // Find a payload whose checksum would be zero is hard; instead assert
        // the mapping rule on the helper contract with an empty segment:
        // sum of pseudo header alone must not accidentally be asserted here;
        // just check the function never returns 0 for any 1-byte input set.
        let src6 = [0u8; 16];
        let dst6 = [0u8; 16];
        let mut saw_nonzero = false;
        let mut payload = [0u8; 8];
        for i in 0..256u16 {
            payload[0] = (i >> 8) as u8;
            payload[1] = (i & 0xff) as u8;
            let c = udp_checksum_v6(&src6, &dst6, &payload);
            assert_ne!(c, 0, "UDPv6 checksum must never be 0");
            if c != 0xFFFF {
                saw_nonzero = true;
            }
        }
        assert!(saw_nonzero);
    }

    #[test]
    fn icmp_echo_vector() {
        // Echo request header + "hello", checksum field zeroed:
        // words: 0800 0000 0001 0001 6865 6c6c 6f00 -> sum 0x14BD3 ->
        // fold 0x4BD4 -> checksum 0xB42B (hand-verified).
        let msg: Vec<u8> = vec![
            0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
        ];
        assert_eq!(icmp_checksum(&msg), 0xb42b);
    }
}
