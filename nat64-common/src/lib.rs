//! Shared definitions for the NAT64 dataplane and control plane.
//!
//! This crate is `#![no_std]` so it can be linked into the eBPF program.
//! Endianness contract (see `state`):
//!
//! - IPv4 addresses: 4 bytes in **network byte order**, stored as `u32` via
//!   `u32::from_be_bytes` (i.e. the integer reads the same on the wire).
//! - Transport ports / ICMP identifiers: `u16` in **network byte order**
//!   (`u16::from_be_bytes`).
//! - IPv6 addresses: 16 bytes in network byte order (`in6_addr` layout).
//! - Timestamps: `u64` monotonic nanoseconds in **host order** from
//!   `bpf_ktime_get_ns()` in eBPF and `CLOCK_BOOTTIME` in userspace, so both
//!   sides share the same clock base for garbage collection.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod checksum;
pub mod packet;
pub mod prefix;
pub mod proto;
pub mod state;

pub use prefix::{Nat64Prefix, PrefixError, ipv4_to_ipv6_embedded, ipv6_to_ipv4_embedded};
pub use state::{
    BibKey, BibRevKey, BibRevValue, BibValue, ConfigValue, PROTO_ICMP, PROTO_TCP, PROTO_UDP,
    SessionKeyV4, SessionKeyV6, SessionValue, StaticKeyV4, StaticValueV4, StatsCounters, TcpState,
    Timeouts, hash_tuple, pick_index, pool_at,
};

/// Userspace `aya::Pod` impls so map keys/values can be passed to
/// `aya::maps::{HashMap, Array, PerCpuArray}` without copying the struct
/// definitions. The eBPF side (`aya-ebpf`) sizes maps with `size_of` and needs
/// no trait impl, which keeps this crate dependency-free for the BPF target.
#[cfg(feature = "user")]
mod pod_impls {
    use super::state::{
        BibKey, BibRevKey, BibRevValue, BibValue, ConfigValue, SessionKeyV4, SessionKeyV6,
        SessionValue, StaticKeyV4, StaticValueV4, StatsCounters,
    };

    unsafe impl aya::Pod for BibKey {}
    unsafe impl aya::Pod for BibValue {}
    unsafe impl aya::Pod for BibRevKey {}
    unsafe impl aya::Pod for BibRevValue {}
    unsafe impl aya::Pod for SessionKeyV6 {}
    unsafe impl aya::Pod for SessionKeyV4 {}
    unsafe impl aya::Pod for SessionValue {}
    unsafe impl aya::Pod for ConfigValue {}
    unsafe impl aya::Pod for StatsCounters {}
    unsafe impl aya::Pod for StaticKeyV4 {}
    unsafe impl aya::Pod for StaticValueV4 {}
}
