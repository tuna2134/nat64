# AGENTS.md

Stateful NAT64 (Aya XDP + Tokio control plane). Pure Rust; no libbpf/C/DPDK.

## Workspace layout

- `nat64/src/main.rs` + `config.rs` — loader, TOML config, Tokio GC, CLI
  (`run|stats|sessions|bib|check-config`). Attaches XDP prog `nat64` to both
  interfaces (once if same iface).
- `nat64-ebpf/src/main.rs` + `parse.rs` — `#![no_std, no_main]` XDP program.
  Keep `#[panic_handler]` (`loop {}`) and `#[link_section = "license"]`
  `Dual MIT/GPL` static; kernel rejects the object without the license section.
- `nat64-common/src/{lib,proto,prefix,checksum,state,packet}.rs` — shared
  `#[repr(C)]` types + pure logic (`#![no_std]`). `user` feature gates `aya`
  for userspace `Pod` impls; eBPF side needs no trait. Endianness: addrs/ports
  network order, timestamps host-order boot-ns (shared clock base).
- `nat64-config.example.toml`, `tests/netns.sh` (root-only integration).

## Build / run (verified)

- Prerequisites: stable + nightly with `rust-src`, `bpf-linker`, LLVM.
- `cargo build` / `cargo run` (default members = `nat64`, `nat64-common`).
  `nat64/build.rs` invokes `aya_build::build_ebpf` automatically — never build
  the eBPF object manually. Do NOT use `cargo build/test --workspace`: it tries
  to link the `no_std` ebpf bin for the host and fails; default members are
  the supported path.
- `.cargo/config.toml` sets `runner = "sudo -E"` — `cargo run`/`cargo test`
  exec under sudo. Without sudo, run test binaries directly from
  `target/debug/deps/` instead of changing the config.
- Format uses nightly-only options: `cargo +nightly fmt`.
- eBPF constraints (hard-won): 512 B stack limit is per *call chain* — the
  program is currently fully inlined into one function (fits after slimming);
  if it overflows again, split `handle_v6`/`handle_v4`/`alloc_mapping`/
  `mk_sessions` into BPF-to-BPF subprograms. Never copy whole `ConfigValue`/
  map structs to the stack (use map references), write headers directly into
  the packet (no staging arrays). All loops need constant bounds; multi-byte
  fields byte-by-byte.
- Zero-panic rule for eBPF: ANY residual panic path (runtime indexing
  `a[i]`, slice ranges, `%`/`/` with runtime divisor) makes the linker
  append the diverging panic machinery and the kernel rejects the load
  with "last insn is not an exit or jmp". Use raw pointers, constant
  indices, `pick_index`/`pool_at`/`port_in_range` (multiply-high) instead
  of `%`. Verify without root via the linked tail ending in `exit`
  (see `tests/netns.sh` troubleshooting).
- Verifier range rule: `packet_ptr + scalar` needs provable signed-min, and
  `u32` values lose it through spills/merges (plain `as usize` emits
  nothing). Route EVERY runtime offset/length touching `data` through
  `zext()` (volatile + `<< 32; >> 32`, which the verifier reads as smin=0).
  Keep loop counters `usize`-from-zero (consistent 64-bit width preserves
  induction); use pointer-stepping (`p.add/SUB const`) for backward loops.
  Correlation rule: opacified values are unrelated in the verifier's eyes,
  so thread ONE shared zext'd local through the bounds check, the loop
  conditions, and every access — never re-derive the same quantity twice.
  Prefer pointer iteration (`p`/`end` from the checked values, `p.add(const)`,
  `p < end`) over index arithmetic for loops touching packet data.

## Conventions that differ from defaults

- XDP action policy: `PASS` = not ours (host may handle); `DROP` = malformed,
  filtered, fragments, alloc failure. Never translate unsupported traffic.
- Session miss on TCP without SYN → drop. Inbound always needs session/static.
- ICMP errors, fragments, AH/ESP, IPv4 options → PASS/drop fallback, counted.
  Do not "complete" these with fragile in-kernel workarounds; document instead.
- `packet.rs` (tested, slices) is the algorithm spec; `nat64-ebpf` duplicates
  small parsing primitives with raw pointers so the verifier sees guards.
- Session/BIB expiry lives ONLY in userspace GC (`CLOCK_BOOTTIME` ns);
  dataplane only refreshes `last_used_ns` + TCP state.
- `SessionValue` must keep the server tuple (GC rebuilds reverse keys).

## Licensing

- Non-eBPF: `MIT OR Apache-2.0`. eBPF: `MIT OR GPL-2.0`. Keep headers.
