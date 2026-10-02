//! RFC 6052 IPv4-embedded IPv6 address conversion.
//!
//! Supported prefix lengths: /32, /40, /48, /56, /64, /96.
//!
//! Bit layout (RFC 6052, section 2.2): the 8-bit `u` octet at bits 64..71 is
//! reserved (zero), except for /96 where the IPv4 address occupies the last
//! 32 bits with no `u` octet. For the other lengths the 32 IPv4 bits are split
//! around `u`:
//!
//! ```text
//! /32: PREFIX(32)              | v4(32)  | u(8) | suffix(56)
//! /40: PREFIX(40)     | v4[0..24)  | u(8) | v4[24..32) | suffix(48)
//! /48: PREFIX(48) | v4[0..16)      | u(8) | v4[16..32)    | suffix(40)
//! /56: PREFIX(56) | v4[0..8)       | u(8) | v4[8..32)     | suffix(32)
//! /64: PREFIX(64)                  | u(8) | v4(32)        | suffix(24)
//! /96: PREFIX(96)                                            | v4(32)
//! ```
//!
//! The `suffix` bits SHOULD be zero (RFC 6052, section 2.2) and this
//! implementation embeds zero; extraction tolerates non-zero suffix but still
//! requires `u == 0` for lengths other than /96.

use crate::proto::WKP;

/// Well-known prefix length for 64:ff9b::/96.
pub const WKP_LEN: u8 = 96;

/// Errors from prefix handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixError {
    /// Prefix length is not one of 32/40/48/56/64/96.
    BadLength(u8),
    /// Address does not start with the configured prefix.
    NotInPrefix,
    /// Reserved `u` octet is non-zero.
    BadReservedByte,
}

/// A NAT64 prefix: 16 address bytes plus a length in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nat64Prefix {
    /// Prefix bytes in network order; bits beyond `len` MUST be zero.
    pub addr: [u8; 16],
    /// One of 32, 40, 48, 56, 64, 96.
    pub len: u8,
}

impl Nat64Prefix {
    /// Default well-known prefix `64:ff9b::/96`.
    pub const fn well_known() -> Self {
        Self {
            addr: WKP,
            len: WKP_LEN,
        }
    }

    /// Build from raw parts, validating the length. Bits beyond `len` are
    /// normalised to zero (canonical form).
    pub fn new(addr: [u8; 16], len: u8) -> Result<Self, PrefixError> {
        if !matches!(len, 32 | 40 | 48 | 56 | 64 | 96) {
            return Err(PrefixError::BadLength(len));
        }
        let mut norm = addr;
        let n = (len as usize) / 8;
        norm[n..].fill(0);
        Ok(Self { addr: norm, len })
    }

    /// Number of whole prefix bytes.
    const fn plen_bytes(self) -> usize {
        (self.len as usize) / 8
    }

    /// True if `v6` starts with this prefix.
    pub fn covers(self, v6: &[u8; 16]) -> bool {
        let n = self.plen_bytes();
        self.addr[..n] == v6[..n]
    }

    /// Embed `v4` into an IPv6 address under this prefix (suffix = 0).
    pub fn embed(self, v4: &[u8; 4]) -> [u8; 16] {
        embed_raw(&self.addr, self.len, v4)
    }

    /// Extract the embedded IPv4 address, validating prefix + `u` octet.
    pub fn extract(self, v6: &[u8; 16]) -> Result<[u8; 4], PrefixError> {
        extract_raw(&self.addr, self.len, v6)
    }

    /// True if `v6` carries an embedded IPv4 address under this prefix.
    pub fn matches(self, v6: &[u8; 16]) -> bool {
        self.extract(v6).is_ok()
    }
}

/// Embed `v4` into `prefix/len` with a zero suffix.
pub fn ipv4_to_ipv6_embedded(prefix: &[u8; 16], len: u8, v4: &[u8; 4]) -> [u8; 16] {
    embed_raw(prefix, len, v4)
}

/// Extract the IPv4 address from `v6` under `prefix/len`.
pub fn ipv6_to_ipv4_embedded(
    prefix: &[u8; 16],
    len: u8,
    v6: &[u8; 16],
) -> Result<[u8; 4], PrefixError> {
    extract_raw(prefix, len, v6)
}

/// Start bit of the IPv4 field(s) for each supported length, from the table
/// in the module docs. Returns `(high_start_bit, high_bits, low_start_bit)`.
const fn v4_layout(len: u8) -> (usize, usize, usize) {
    match len {
        32 => (32, 32, 0),
        40 => (40, 24, 72),
        48 => (48, 16, 72),
        56 => (56, 8, 72),
        64 => (72, 32, 0),
        _ => (96, 32, 0), // 96
    }
}

fn get_bits(src: &[u8; 16], bit: usize, nbits: usize) -> u32 {
    let mut v: u32 = 0;
    let mut i = 0;
    while i < nbits {
        let b = bit + i;
        let byte = src[b / 8];
        let bit_in_byte = 7 - (b % 8);
        v = (v << 1) | ((byte >> bit_in_byte) & 1) as u32;
        i += 1;
    }
    v
}

fn set_bits(dst: &mut [u8; 16], bit: usize, nbits: usize, mut v: u32) {
    let mut i = nbits;
    while i > 0 {
        i -= 1;
        let b = bit + i;
        let bit_in_byte = 7 - (b % 8);
        let byte = &mut dst[b / 8];
        // `v` holds the remaining high bits; take the lowest of them last.
        // Shift so the target bit lands at position 0.
        let shift = (nbits - 1 - i) as u32;
        let bv = ((v >> shift) & 1) as u8;
        v &= !(1 << shift);
        if bv == 1 {
            *byte |= 1 << bit_in_byte;
        } else {
            *byte &= !(1 << bit_in_byte);
        }
    }
}

fn embed_raw(prefix: &[u8; 16], len: u8, v4: &[u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = (len as usize) / 8;
    out[..n].copy_from_slice(&prefix[..n]);
    let v4w = u32::from_be_bytes(*v4);
    let (hi_bit, hi_n, lo_bit) = v4_layout(len);
    if hi_n == 32 {
        set_bits(&mut out, hi_bit, 32, v4w);
    } else {
        let lo_n = 32 - hi_n;
        set_bits(&mut out, hi_bit, hi_n, v4w >> lo_n);
        set_bits(&mut out, lo_bit, lo_n, v4w & ((1 << lo_n) - 1));
    }
    // `u` octet (bits 64..71) and suffix stay zero for len != 96.
    out
}

fn extract_raw(prefix: &[u8; 16], len: u8, v6: &[u8; 16]) -> Result<[u8; 4], PrefixError> {
    if !matches!(len, 32 | 40 | 48 | 56 | 64 | 96) {
        return Err(PrefixError::BadLength(len));
    }
    let n = (len as usize) / 8;
    if prefix[..n] != v6[..n] {
        return Err(PrefixError::NotInPrefix);
    }
    if len != 96 && v6[8] != 0 {
        return Err(PrefixError::BadReservedByte);
    }
    let (hi_bit, hi_n, lo_bit) = v4_layout(len);
    let v4w = if hi_n == 32 {
        get_bits(v6, hi_bit, 32)
    } else {
        let lo_n = 32 - hi_n;
        (get_bits(v6, hi_bit, hi_n) << lo_n) | get_bits(v6, lo_bit, lo_n)
    };
    Ok(v4w.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use std::{format, vec, vec::Vec};

    use super::*;

    #[test]
    fn rfc6052_section_2_3_wkp_example() {
        // RFC 6052, section 2.3: 192.0.2.33 + 64:ff9b::/96 = 64:ff9b::c000:221.
        let p = Nat64Prefix::well_known();
        let out = p.embed(&[192, 0, 2, 33]);
        let expected: [u8; 16] = [
            0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00,
            0x02, 0x21,
        ];
        assert_eq!(out, expected, "got {:02x?}", out);
        assert_eq!(p.extract(&out).unwrap(), [192, 0, 2, 33]);
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn all_prefix_lengths_round_trip() {
        // Vectors assembled from the RFC 6052 bit layout (suffix = 0).
        let cases: Vec<(u8, [u8; 16], [u8; 4], [u8; 16])> = vec![
            (
                32,
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [192, 0, 2, 33],
                [
                    0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x00, 0x02, 0x21, 0x00, 0, 0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                40,
                [
                    0x20, 0x01, 0x0d, 0xb8, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                [192, 0, 2, 33],
                [
                    0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xc0, 0x00, 0x02, 0x00, 0x21, 0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                48,
                [
                    0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                [192, 0, 2, 33],
                [
                    0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0xc0, 0x00, 0x00, 0x02, 0x21, 0, 0, 0, 0, 0,
                ],
            ),
            (
                56,
                [
                    0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                [192, 0, 2, 33],
                [
                    0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0xcc, 0xc0, 0x00, 0x00, 0x02, 0x21, 0, 0,
                    0, 0,
                ],
            ),
            (
                64,
                [
                    0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                [192, 0, 2, 33],
                [
                    0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0xc0, 0x00, 0x02, 0x21,
                    0, 0, 0,
                ],
            ),
            (
                96,
                [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [192, 0, 2, 33],
                [
                    0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0x00, 0x02, 0x21,
                ],
            ),
        ];
        for (len, prefix, v4, want) in cases {
            let p = Nat64Prefix::new(prefix, len).unwrap();
            let got = p.embed(&v4);
            assert_eq!(got, want, "embed /{len} failed: {:02x?}", got);
            assert_eq!(p.extract(&got).unwrap(), v4, "extract /{len} failed");
            assert!(p.matches(&got));
        }
    }

    #[test]
    fn rejects_bad_prefix_and_reserved_byte() {
        assert_eq!(
            Nat64Prefix::new([0u8; 16], 33),
            Err(PrefixError::BadLength(33))
        );
        let p = Nat64Prefix::well_known();
        // Wrong prefix.
        let mut bad = p.embed(&[10, 0, 0, 1]);
        bad[0] ^= 0xff;
        assert_eq!(p.extract(&bad), Err(PrefixError::NotInPrefix));
        // Non-zero `u` octet for /64.
        let p64 = Nat64Prefix::new(
            [
                0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            64,
        )
        .unwrap();
        let mut v6 = p64.embed(&[10, 0, 0, 1]);
        v6[8] = 0x01;
        assert_eq!(p64.extract(&v6), Err(PrefixError::BadReservedByte));
        let _ = format!("{p64:?}");
    }

    #[test]
    fn free_functions_match_methods() {
        let prefix = Nat64Prefix::well_known().addr;
        let v6 = ipv4_to_ipv6_embedded(&prefix, 96, &[203, 0, 113, 7]);
        assert_eq!(
            ipv6_to_ipv4_embedded(&prefix, 96, &v6).unwrap(),
            [203, 0, 113, 7]
        );
    }
}
