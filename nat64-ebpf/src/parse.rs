//! Verifier-friendly packet parsing and rewrite primitives.
//!
//! Every access is guarded by an explicit `data <= ptr < data_end` check.
//! Multi-byte fields are assembled byte-by-byte (no unaligned word loads),
//! loops use constant bounds with early `break`, and error paths return
//! `Err(())` instead of panicking.
//!
//! # Zero-panic rule (load-bearing)
//!
//! eBPF must never panic, and worse: any *residual* panic path (e.g. a
//! bounds check the compiler cannot elide from runtime indexing like
//! `arr[i]` or `slice[i]`) makes the static linker append the diverging
//! panic machinery to the program image, and the kernel then rejects the
//! load with "last insn is not an exit or jmp". Therefore all runtime
//! indexing in this file uses raw pointers; only *constant* indices into
//! fixed-size locals are written as `a[k]` (those checks fold away).
//!
//! # Verifier cursor rule (load-bearing)
//!
//! Do not rely on the verifier remembering `data+off+len <= data_end`
//! across scalar arithmetic. Every packet access uses a cursor derived
//! once from `data+off` and checked locally with `p.add(N) > end` before
//! the exact `*p` that follows. Loop-carried state is the pointer itself
//! (`p = p.add(N)`), never `data+off+i` recomputed from scalars.
//!
//! # u32 offsets (load-bearing)
//!
//! All offsets and lengths are `u32`, never `usize`. The verifier only
//! permits `packet_ptr + scalar` when the scalar has a provably
//! non-negative *signed* minimum, and 64-bit values derived from packet
//! data lose that tracking. A `u32` zero-extends on promotion, so
//! `smin >= 0` holds for free. `data`/`data_end` stay `usize` (addresses).
//!
//! The translation *algorithm* mirrors `nat64-common::packet` (which is
//! unit-tested on slices); the primitives are duplicated here so the
//! verifier sees the guards inline.

use nat64_common::proto::*;

/// Upper bound on bytes moved / checksummed per packet (covers a full 1500 B
/// MTU frame with margin; larger packets take the PASS fallback path and are
/// counted, see `translate` in `main.rs`).
pub const MAX_COPY: u32 = 2048;
/// Iterations for the 8-byte move loop (`MAX_COPY / 8`).
pub const MAX_COPY_WORDS: u32 = 256;

/// Ethernet decode: (ethertype, l3_offset).
#[inline(always)]
pub fn parse_eth(data: usize, data_end: usize) -> Result<(u16, u32), ()> {
    let end = data_end as *const u8;
    // Need at least 14 bytes for base Ethernet header.
    if (data + ETH_LEN) as *const u8 > end {
        return Err(());
    }
    let mut etype = u16::from_be_bytes(unsafe {
        [
            *(data as *const u8).add(12),
            *(data as *const u8).add(13),
        ]
    });
    let mut off = ETH_LEN as u32;
    let mut tags = 0u32;
    while (etype == ETH_P_8021Q || etype == ETH_P_8021AD) && tags < MAX_VLAN_TAGS as u32 {
        // Need 4 bytes for VLAN tag at `off`.
        let p = (data + zext(off)) as *const u8;
        if unsafe { p.add(VLAN_LEN) } > end {
            return Err(());
        }
        // VLAN ethertype is at p+2.
        etype = u16::from_be_bytes(unsafe { [*p.add(2), *p.add(3)] });
        off += VLAN_LEN as u32;
        tags += 1;
    }
    if etype == ETH_P_8021Q || etype == ETH_P_8021AD {
        return Err(());
    }
    Ok((etype, off))
}

/// Read one byte with a bounds check.
#[inline(always)]
pub fn rb(data: usize, data_end: usize, off: u32) -> Result<u8, ()> {
    let o = zext(off);
    let p = (data + o) as *const u8;
    let end = data_end as *const u8;
    if unsafe { p.add(1) } > end {
        return Err(());
    }
    Ok(unsafe { *p })
}

/// Read a big-endian u16 with a bounds check.
#[inline(always)]
pub fn rb16(data: usize, data_end: usize, off: u32) -> Result<u16, ()> {
    let o = zext(off);
    let p = (data + o) as *const u8;
    let end = data_end as *const u8;
    if unsafe { p.add(2) } > end {
        return Err(());
    }
    Ok(unsafe { u16::from_be_bytes([*p, *p.add(1)]) })
}

/// Read one byte from a raw base (unchecked: the caller bounds the index).
/// The base is never a packet pointer (stack/map data), so any index type
/// works; `u32` keeps call sites uniform.
#[inline(always)]
pub unsafe fn pk8(base: *const u8, i: usize) -> u8 {
    unsafe { *base.add(i) }
}

/// Copy `n` bytes from packet offset `src` to a raw destination.
#[inline(always)]
pub fn copy16(data: usize, data_end: usize, src: u32, dst: *mut u8, n: u32) -> Result<(), ()> {
    let s = zext(src);
    let nn = zext(n);
    if nn > 16 {
        return Err(());
    }
    let p = (data + s) as *const u8;
    let end = data_end as *const u8;
    if unsafe { p.add(nn) } > end {
        return Err(());
    }
    let mut i = 0usize;
    let mut p_cur = p;
    while i < nn {
        if unsafe { p_cur.add(1) } > end {
            return Err(());
        }
        unsafe {
            *dst.add(i) = *p_cur;
        }
        p_cur = unsafe { p_cur.add(1) };
        i += 1;
    }
    Ok(())
}

/// Copy 4 bytes to a raw destination.
#[inline(always)]
pub fn copy4(data: usize, data_end: usize, src: u32, dst: *mut u8) -> Result<(), ()> {
    let s = zext(src);
    let p = (data + s) as *const u8;
    let end = data_end as *const u8;
    if unsafe { p.add(4) } > end {
        return Err(());
    }
    unsafe {
        *dst.add(0) = *p;
        *dst.add(1) = *p.add(1);
        *dst.add(2) = *p.add(2);
        *dst.add(3) = *p.add(3);
    }
    Ok(())
}

/// Write `len` bytes from a raw source into the packet at `dst`.
#[inline(always)]
pub fn write_bytes(
    data: usize,
    data_end: usize,
    dst: u32,
    src: *const u8,
    len: u32,
) -> Result<(), ()> {
    let d = zext(dst);
    let m = zext(len);
    let p = (data + d) as *mut u8;
    let end = data_end as *mut u8;
    if unsafe { p.add(m) } > end {
        return Err(());
    }
    let mut i = 0usize;
    let mut p_cur = p;
    let mut s_cur = src;
    while i < m {
        if unsafe { p_cur.add(1) } > end {
            return Err(());
        }
        unsafe {
            *p_cur = *s_cur;
        }
        p_cur = unsafe { p_cur.add(1) };
        s_cur = unsafe { s_cur.add(1) };
        i += 1;
    }
    Ok(())
}

/// Move `len` bytes from `src_off` to `dst_off` inside the packet.
/// `dst_off < src_off`: copy forwards. Handles overlap correctly for our
/// left-shift use; the right-shift twin is `move_right`.
#[inline(always)]
pub fn move_left(
    data: usize,
    data_end: usize,
    dst_off: u32,
    src_off: u32,
    len: u32,
) -> Result<(), ()> {
    let s = zext(src_off);
    let d = zext(dst_off);
    let l = zext(len);
    if l > MAX_COPY as usize {
        return Err(());
    }
    let src_p = (data + s) as *const u8;
    let dst_p = (data + d) as *mut u8;
    let end = data_end as *const u8;
    // Whole-range checks: both source and destination ranges must fit.
    if unsafe { src_p.add(l) > end || (dst_p as *const u8).add(l) > end } {
        return Err(());
    }
    // Byte-wise forward copy with per-access checks (verifier sees
    // `p.add(1) > end` directly before each `*p`). Bounded by MAX_COPY.
    let mut i = 0usize;
    let mut s_cur = src_p;
    let mut d_cur = dst_p;
    while i < l {
        if unsafe { s_cur.add(1) > end || (d_cur as *const u8).add(1) > end } {
            return Err(());
        }
        unsafe {
            *d_cur = *s_cur;
        }
        s_cur = unsafe { s_cur.add(1) };
        d_cur = unsafe { d_cur.add(1) };
        i += 1;
        if i >= MAX_COPY as usize {
            break;
        }
    }
    Ok(())
}

/// Move `len` bytes from `src_off` to `dst_off` with `dst_off > src_off`.
#[inline(always)]
pub fn move_right(
    data: usize,
    data_end: usize,
    dst_off: u32,
    src_off: u32,
    len: u32,
) -> Result<(), ()> {
    let s = zext(src_off);
    let d = zext(dst_off);
    let l = zext(len);
    if l > MAX_COPY as usize {
        return Err(());
    }
    let src_p = (data + s) as *const u8;
    let dst_p = (data + d) as *mut u8;
    let end = data_end as *const u8;
    if unsafe { src_p.add(l) > end || (dst_p as *const u8).add(l) > end } {
        return Err(());
    }
    // Backwards copy: start at end of ranges and step backwards.
    // Pointer stepping `p.sub(1)` is verifier-safe (pointer +/- const).
    let mut s_cur = unsafe { src_p.add(l) };
    let mut d_cur = unsafe { dst_p.add(l) };
    let mut remaining = l;
    while remaining > 0 {
        s_cur = unsafe { s_cur.sub(1) };
        d_cur = unsafe { d_cur.sub(1) };
        // Both pointers are now `src_p + (remaining-1)` and
        // `dst_p + (remaining-1)`, each `+1` is still `<= end` because the
        // whole-range check passed. Per-access check keeps verifier happy.
        if unsafe { s_cur.add(1) > end || (d_cur as *const u8).add(1) > end } {
            return Err(());
        }
        unsafe {
            *d_cur = *s_cur;
        }
        remaining -= 1;
        if remaining == 0 {
            break;
        }
        if l - remaining >= MAX_COPY as usize {
            break;
        }
    }
    Ok(())
}

/// Ones-complement sum over the packet range `[off, off+len)`, added to `sum`.
/// Bounded: rejects lengths above `MAX_COPY`.
///
/// Cursor model: `p` starts at `data+off`, `end` at `data_end`. Each access
/// is preceded by `p.add(N) > end` checked against that exact `p`.
#[inline(always)]
pub fn csum_add(data: usize, data_end: usize, off: u32, len: u32, mut sum: u64) -> Result<u64, ()> {
    let o = zext(off);
    let l = zext(len);
    if l > MAX_COPY as usize {
        return Err(());
    }
    // Use integer arithmetic for bounds checks to avoid any `pkt_end +/- N`
    // generation. `p`/`end` as `*const u8` are packet pointers; casting to
    // `usize` makes the comparison scalar, so LLVM cannot rewrite
    // `p.add(N) > end` into `end - N` (which would be `pkt_end - N`,
    // prohibited). The actual `*p` loads still use the packet pointer `p`.
    let mut p = (data + o) as *const u8;
    let end = data_end as *const u8;
    let p_addr = p as usize;
    let end_addr = end as usize;
    if p_addr > end_addr {
        return Err(());
    }
    if l > end_addr.wrapping_sub(p_addr) {
        return Err(());
    }
    let mut remaining = l;
    while remaining >= 2 {
        if (p as usize).wrapping_add(2) > end as usize {
            return Err(());
        }
        let hi = unsafe { *p };
        let lo = unsafe { *p.add(1) };
        sum += ((hi as u64) << 8) | (lo as u64);
        p = unsafe { p.add(2) };
        remaining -= 2;
    }
    if remaining != 0 {
        if (p as usize).wrapping_add(1) > end as usize {
            return Err(());
        }
        let b = unsafe { *p };
        sum += (b as u64) << 8;
    }
    Ok(sum)
}

/// Fold a 64-bit sum into a final checksum field.
///
/// Straight-line rounds, NOT a data-dependent `while` loop: the verifier
/// cannot prove termination of `while sum >> 16 != 0` (the state space
/// never converges) and rejects it with "jumps too complex". Five rounds
/// reduce any `u64` into 16 bits (2^64 -> 2^49 -> 2^32 -> 2^17 -> 2^16).
#[inline(always)]
pub const fn csum_fold(sum: u64) -> u16 {
    let sum = (sum & 0xFFFF) + (sum >> 16);
    let sum = (sum & 0xFFFF) + (sum >> 16);
    let sum = (sum & 0xFFFF) + (sum >> 16);
    let sum = (sum & 0xFFFF) + (sum >> 16);
    let sum = (sum & 0xFFFF) + (sum >> 16);
    !(sum as u16)
}

/// Combine two bytes into a checksum word without any indexing.
#[inline(always)]
pub const fn w16(hi: u8, lo: u8) -> u64 {
    ((hi as u64) << 8) | (lo as u64)
}

/// Zero-extend a `u32` offset for packet-pointer arithmetic (load-bearing).
///
/// The verifier only permits `packet_ptr + scalar` when the scalar has a
/// provably non-negative *signed* minimum, and `u32` values lose that
/// tracking through loop merges and helper boundaries (plain `as usize`
/// casts emit nothing). The volatile load keeps LLVM from reasoning about
/// the value, forcing it to emit the `<< 32; >> 32` pair, which the verifier
/// reads as `smin = 0`. Every `data + <runtime>` site must go through this.
#[inline(always)]
pub fn zext(v: u32) -> usize {
    let x = unsafe { core::ptr::read_volatile(&v) };
    (((x as u64) << 32) >> 32) as usize
}

/// RFC 6052 extraction with fully unrolled per-length arms (no bit loops,
/// so the verifier sees constant offsets). Raw pointer reads only.
/// Returns the embedded IPv4 bytes in network order, or `Err(())` when the
/// address is outside the prefix or the reserved `u` octet is non-zero.
#[inline(always)]
pub fn extract_v4(prefix: *const u8, plen: u8, dst: *const u8) -> Result<[u8; 4], ()> {
    unsafe {
        match plen {
            96 => {
                let mut i = 0;
                while i < 12 {
                    if pk8(prefix, i) != pk8(dst, i) {
                        return Err(());
                    }
                    i += 1;
                }
                Ok([pk8(dst, 12), pk8(dst, 13), pk8(dst, 14), pk8(dst, 15)])
            }
            32 => {
                if pk8(prefix, 0) != pk8(dst, 0)
                    || pk8(prefix, 1) != pk8(dst, 1)
                    || pk8(prefix, 2) != pk8(dst, 2)
                    || pk8(prefix, 3) != pk8(dst, 3)
                {
                    return Err(());
                }
                if pk8(dst, 8) != 0 {
                    return Err(());
                }
                Ok([pk8(dst, 4), pk8(dst, 5), pk8(dst, 6), pk8(dst, 7)])
            }
            40 => {
                let mut i = 0;
                while i < 5 {
                    if pk8(prefix, i) != pk8(dst, i) {
                        return Err(());
                    }
                    i += 1;
                }
                if pk8(dst, 8) != 0 {
                    return Err(());
                }
                Ok([pk8(dst, 5), pk8(dst, 6), pk8(dst, 7), pk8(dst, 9)])
            }
            48 => {
                let mut i = 0;
                while i < 6 {
                    if pk8(prefix, i) != pk8(dst, i) {
                        return Err(());
                    }
                    i += 1;
                }
                if pk8(dst, 8) != 0 {
                    return Err(());
                }
                Ok([pk8(dst, 6), pk8(dst, 7), pk8(dst, 9), pk8(dst, 10)])
            }
            56 => {
                let mut i = 0;
                while i < 7 {
                    if pk8(prefix, i) != pk8(dst, i) {
                        return Err(());
                    }
                    i += 1;
                }
                if pk8(dst, 8) != 0 {
                    return Err(());
                }
                Ok([pk8(dst, 7), pk8(dst, 9), pk8(dst, 10), pk8(dst, 11)])
            }
            64 => {
                let mut i = 0;
                while i < 8 {
                    if pk8(prefix, i) != pk8(dst, i) {
                        return Err(());
                    }
                    i += 1;
                }
                if pk8(dst, 8) != 0 {
                    return Err(());
                }
                Ok([pk8(dst, 9), pk8(dst, 10), pk8(dst, 11), pk8(dst, 12)])
            }
            _ => Err(()),
        }
    }
}

/// RFC 6052 embedding with unrolled arms. Suffix bits are zero.
/// `prefix`/`v4` are raw pointers; the output uses constant indices only.
#[inline(always)]
pub fn embed_v6(prefix: *const u8, plen: u8, v4: *const u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    let o = &mut out as *mut [u8; 16] as *mut u8;
    unsafe {
        let n = match plen {
            96 => 12,
            32 => 4,
            40 => 5,
            48 => 6,
            56 => 7,
            _ => 8,
        };
        let mut i = 0;
        while i < n {
            *o.add(i as usize) = pk8(prefix, i);
            i += 1;
        }
        match plen {
            96 => {
                *o.add(12) = pk8(v4, 0);
                *o.add(13) = pk8(v4, 1);
                *o.add(14) = pk8(v4, 2);
                *o.add(15) = pk8(v4, 3);
            }
            32 => {
                *o.add(4) = pk8(v4, 0);
                *o.add(5) = pk8(v4, 1);
                *o.add(6) = pk8(v4, 2);
                *o.add(7) = pk8(v4, 3);
            }
            40 => {
                *o.add(5) = pk8(v4, 0);
                *o.add(6) = pk8(v4, 1);
                *o.add(7) = pk8(v4, 2);
                *o.add(9) = pk8(v4, 3);
            }
            48 => {
                *o.add(6) = pk8(v4, 0);
                *o.add(7) = pk8(v4, 1);
                *o.add(9) = pk8(v4, 2);
                *o.add(10) = pk8(v4, 3);
            }
            56 => {
                *o.add(7) = pk8(v4, 0);
                *o.add(9) = pk8(v4, 1);
                *o.add(10) = pk8(v4, 2);
                *o.add(11) = pk8(v4, 3);
            }
            _ => {
                // 64 and defensive default: prefix 8 bytes, u = 0, v4 at 9..13.
                *o.add(9) = pk8(v4, 0);
                *o.add(10) = pk8(v4, 1);
                *o.add(11) = pk8(v4, 2);
                *o.add(12) = pk8(v4, 3);
            }
        }
    }
    out
}
