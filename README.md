# nat64 — Stateful NAT64/NAPT64 in Rust/Aya (XDP)

A pure-Rust stateful NAT64 translator: an XDP/eBPF fast path plus a Tokio
userspace control plane, built with [Aya](https://aya-rs.dev). No libbpf, no C,
no DPDK.

> This implementation follows the architecture and processing model defined by
> **draft-ietf-v6ops-rfc6146-bis-16** (an Internet-Draft, subject to change)
> where implemented. It does **not** claim full RFC compliance — see
> [Known limitations](#known-limitations).

## 1. What NAT64 is

NAT64 lets IPv6-only clients reach IPv4-only servers by translating packets
between the two address families. *Stateful* NAT64 (NAPT64) multiplexes many
IPv6 clients onto a small pool of public IPv4 addresses by also translating
transport ports, keeping per-flow state (RFC 6146 family). Related pieces:

- **RFC 7915** — IP/ICMP translation mechanics and checksums.
- **RFC 6052** — how an IPv4 address is embedded in an IPv6 address
  (`PREFIX + v4 + u + suffix`, with the split layouts for /40–/64).
- **RFC 6147 / DNS64** — synthesizing `AAAA` records so clients learn
  NAT64-mapped addresses (out of scope here; any DNS64 works alongside).

## 2. Architecture

Two planes, strictly separated:

```text
IPv6 client                                  IPv4 server
    |                                            |
    v                                            v
+---v--------------------------------------------v---+
| XDP dataplane (nat64-ebpf, in-kernel)            |
|  parse -> BIB/session lookup -> rewrite ->       |
|  checksum -> redirect                           |
+---^--------------------------------------------^---+
    |                                            |
    +-- maps: BIB fwd/rev, SESSION fwd/rev, ------+
              STATIC, CONFIG, STATS
    |
+---v--------------------------------------------------+
| Userspace control plane (nat64, Tokio)               |
|  load/attach/configure/GC/stats/CLI                  |
+------------------------------------------------------+
```

The XDP program does as much as possible in-kernel but never parses TOML,
never scans for ports, and never runs unbounded work. Policy, expiry, and
configuration live in userspace.

## 3. XDP dataplane (`nat64-ebpf`)

Entry `nat64` in `nat64-ebpf/src/main.rs` (helpers in `src/parse.rs`).
Direction is derived from the EtherType, so the same program attaches to both
interfaces.

**IPv6 → IPv4:** validate Ethernet/IPv6 → walk extension headers → require the
destination inside the configured prefix (else `XDP_PASS`: native v6) →
extract destination IPv4 (RFC 6052) → BIB/session lookup, allocating on miss →
move the L4 segment 20 B toward the head → `bpf_xdp_adjust_tail(-20)` →
rewrite Ethernet/IPv4/L4 → recompute checksums → `bpf_redirect(v4_ifindex)`.

**IPv4 → IPv6:** validate Ethernet/IPv4 (IHL must be 5, no fragments, header
checksum verified) → require the destination in the pool (else `XDP_PASS`) →
reverse session lookup, else static binding, else `XDP_DROP` (filtering) →
`bpf_xdp_adjust_tail(+20)` → shift the segment 20 B toward the tail → build
the IPv6 header → recompute checksums → `bpf_redirect(v6_ifindex)`.

**Action policy:** `XDP_PASS` = not ours (ARP, native traffic, ESP/AH,
unknown L4, ICMP errors — the host stack may handle it). `XDP_DROP` =
malformed, filtered, allocation failure, fragments. Translated packets are
redirected, never passed up.

**Resizing without tears:** the 20-byte header delta is handled by an in-place
bounded memmove plus `bpf_xdp_adjust_tail`. No `adjust_head`, minimal buffer
juggling. Payloads above `MAX_COPY` (2048 B, covers a 1500 B MTU with margin)
take the `PASS` fallback and are counted.

**Verifier notes:** every access has an explicit bounds check; multi-byte
fields are assembled byte-by-byte (no unaligned word loads); all loops have
constant bounds with early `break`; `handle_v6`/`handle_v4` are separate BPF
subprograms and no whole `ConfigValue` is ever copied to the stack (map
references only) to respect the 512 B stack limit. No `unwrap`/`panic` on the
packet path.

## 4. Userspace control plane (`nat64`)

`nat64/src/main.rs` (+ `config.rs`): loads the object, attaches XDP to both
interfaces (`--xdp-mode drv|skb|hw`, default `drv`; use `skb` for veth/tunnels),
writes `CONFIG`, inserts static bindings, pins maps under `/sys/fs/bpf/nat64`
for the CLI, and runs a Tokio GC task. Ctrl-C detaches cleanly.

## 5. BIB and session tables

Conceptual model: `IPv6 endpoint -> [BIB] -> IPv4 endpoint`, with sessions
binding the full bidirectional flow.

- `BIB_V6_TO_V4` / `BIB_V4_TO_V6` — persistent client-tuple ↔ external-tuple
  bindings (one external port per client tuple, multiplexed across
  destinations). Keys are protocol-aware; ICMP queries use `PROTO_ICMP` with
  the echo identifier as the "port" (RFC 7915 §4).
- `SESSION_V6_TO_V4` / `SESSION_V4_TO_V6` — forward and reverse flow keys, so
  both directions are a single hash lookup. No linear scans anywhere.
- `STATIC_V4` — operator-configured IPv4-initiated bindings, consulted only
  after the reverse session lookup misses, kept separate from dynamic state.
- `CONFIG` — single-element array written once by userspace.
- `STATS` — per-CPU counters (no contended global on the fast path).

**Map-type rationale:** plain `HashMap`, not LRU — eviction is policy-driven
(TCP-state-aware timeouts) by the userspace GC; kernel LRU eviction could kill
established flows. `Array` fits the singleton config; `PerCpuArray` fits
write-mostly counters.

Shared structs live in `nat64-common/src/state.rs`, `#[repr(C)]`, fixed-size,
with an explicit endianness contract (addresses/ports in network order,
timestamps as host-order boot-nanoseconds shared by `bpf_ktime_get_ns()` and
`CLOCK_BOOTTIME`).

## 6. Port allocation

Deterministic FNV-1a + avalanche hash of the client tuple picks the pool
address (stable per client) and the port candidate; up to `MAX_PORT_PROBES`
(8) probes with `BPF_NOEXIST` resolve collisions. No 64 k scan, no userspace
round-trip. Ports are freed implicitly when the GC expires sessions/BIB
entries. Port 0 is never allocated; the range is configurable.

## 7. TCP state

`TcpState::{SynSent, SynReceived, Established, FinSeen, Reset}` driven by
SYN/SYN-ACK/ACK/FIN/RST with per-state idle timeouts
(defaults: syn 60 s, transitory 240 s, established 7440 s, fin 120 s,
rst 30 s). New outbound sessions require SYN; established flows are never
reaped by a short timer. Return packets advance the same machine from the
reverse direction.

## 8. UDP handling

Outbound creates BIB + session on demand; inbound requires a reverse session
or static entry; either direction refreshes `last_used_ns`; expiry uses the
configurable `udp` timeout (default 300 s, RFC 6146-bis §4 lifetime).

## 9. ICMP handling

Echo request/reply both ways, with identifier-based NAPT and full checksum
recompute (including the IPv6 pseudo-header and the UDP-over-IPv6
zero→`0xFFFF` rule on egress). Follows RFC 7915 address/type mapping.

## 10. RFC 6052 prefix handling

Configurable prefix (`nat64.prefix`, default `64:ff9b::/96`), never
hard-coded: userspace parses it, the dataplane reads it from `CONFIG`.
Lengths /32 /40 /48 /56 /64 /96 with exact bit layouts
(`ipv4_to_ipv6_embedded` / `ipv6_to_ipv4_embedded` in `nat64-common/src/prefix.rs`,
plus unrolled verifier-friendly twins in the eBPF crate). The `u` octet is
validated on extraction; suffixes are zero. Exhaustively unit-tested,
including the RFC 6052 §2.3 vector (`192.0.2.33` + `64:ff9b::/96` →
`64:ff9b::c000:221`).

## 11. Fragmentation

Explicitly unsupported (no in-kernel reassembly): any IPv6 fragment header or
IPv4 MF/offset bits → drop + `fragments` counter. Rationale: non-first
fragments carry no ports, so they cannot create valid state; reassembling in
XDP would be a large verifier-hostile engine. Documented, counted, tested.

## 12. IPv6 extension headers

Hop-by-Hop, Routing, Destination Options are skipped (max 4, else pass);
Fragment is dropped (see above); AH/ESP and unknown next-headers take the
`PASS` fallback — never translated incorrectly. IPv4 options likewise pass
through untouched.

## 13. Filtering

Outbound may create state; inbound must match a session or static binding
(keys include the server tuple, so cross-talk between servers is impossible).
Unsolicited IPv4 traffic is dropped. Hairpinning (translated dst ∈ own pool)
is dropped and counted for now — see limitations.

## 14. Checksums

IPv4 header checksum validated on ingress; TCP/UDP/ICMP(v6) fully recomputed
on egress over bounded slices (pseudo-headers included). Incremental update is
deliberately avoided: v6↔v4 pseudo-headers differ completely, so a full
recompute is clearer and verifier-safe. Dedicated vectors in
`nat64-common/src/checksum.rs`.

## 15. Configuration

See `nat64-config.example.toml`. Full example:

```toml
[interface]
ipv6 = "eth0"
ipv4 = "eth1"
[nat64]
prefix = "64:ff9b::/96"
hairpinning = false
[[ipv4_pool]]
address = "192.0.2.10"
[port_range]
start = 1024
end = 65535
[timeouts]
udp = 300
icmp = 60
tcp_syn = 60
tcp_transitory = 240
tcp_established = 7440
tcp_fin = 120
tcp_rst = 30
bib = 300
[neighbors]
ipv4_next_hop = "02:42:ac:11:00:02"
ipv6_next_hop = "02:42:ac:11:00:01"
```

Our own MACs/ifindexes are read from the kernel; next-hop MACs are static
configuration (bump-in-the-wire model, ideal for veth/p2p links).

## 16. Running

Prerequisites: stable + nightly (`rust-src`) toolchains, `bpf-linker`,
LLVM/Clang for the BPF build, root for XDP attach.

```shell
cargo build
./target/debug/nat64 --config nat64-config.example.toml run --xdp-mode skb
nat64 --config ... stats
nat64 --config ... sessions --limit 50
nat64 --config ... bib
nat64 --config ... check-config
```

Single interface: set `ipv4` = `ipv6` (attaches once). `XdpMode::Skb` is the
practical default for veth/tunnels; `drv` for physical NICs.

## 17. Testing

- Unit: `cargo test` — RFC 6052 vectors, checksums, TCP machine, timeouts,
  port-spread, config validation (23 tests).
- Packet-level: linear-buffer translation round-trips (UDP/TCP-SYN/ICMP echo,
  error rejections, VLAN, TOS→traffic-class) in `nat64-common/src/packet.rs`.
- Integration: `sudo ./tests/netns.sh` builds a two-namespace veth topology
  and checks real ICMP/UDP/TCP flows, inbound filtering, and the CLI. Needs
  root + `ip`, `ping`, `nc`. Cannot run in unprivileged containers.

## 18. Performance considerations

Established packets cost: parse → 1 session lookup → rewrite → bounded
checksum → redirect. No logging, allocation, or userspace trips on the hot
path; per-CPU stats; single hash lookup per direction; bounded memmove.
Optimize only after the tests above pass.

## 19. Security considerations

All packet bytes are hostile input: length-checked parsing, no panics in eBPF,
fail-closed allocation (fixed-size maps, `BPF_NOEXIST` probes), inbound
filtering by default, configurable `[limits]` watermarks with GC warnings.
Any v6 source is accepted — deploy on the client-facing edge or add prefix
filtering upstream.

## 20. Observability

Structured `env_logger` logs (`RUST_LOG`), rate-limit-friendly (no per-packet
eBPF logging), per-CPU counters for allocation failures, map pressure
(misses), malformed/unsupported/fragment traffic, and static-binding hits.
Prometheus export is intentionally omitted (would need a web stack); `stats`
is machine-greppable.

## 21. Known limitations

1. **No fragment reassembly** — fragments are dropped + counted.
2. **ICMP errors untranslated** — echo only; errors take the safe `PASS`
   fallback (no PMTUD translation; consider TCP MSS clamping upstream).
3. **No hairpinning** — pool-destined packets drop (`hairpin_drops`);
   `hairpinning = true` is accepted but behaves identically until
   double-translation lands.
4. **Static L2 neighbors** — no ARP/ND resolution in the dataplane.
5. **Pool ≤ 8 addresses**, payloads ≤ 2048 B in the fast path (larger pass
   through untranslated).
6. **Single prefix** per instance.

## 22. License

Non-eBPF code: `MIT OR Apache-2.0`. eBPF code: `MIT OR GPL-2.0` (the XDP
object carries the `Dual MIT/GPL` license section the kernel requires).
