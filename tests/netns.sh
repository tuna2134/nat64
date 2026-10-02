#!/usr/bin/env bash
# Reproducible NAT64 integration test with network namespaces (needs root).
#
#   sudo -E ./tests/netns.sh
#
# Topology (no external network):
#
#   client6 (2001:db8:1::2) --veth--> [m6 | NAT64 XDP | m4] <--veth-- server4 (192.0.2.20)
#
# Verifies: ICMPv6 echo through 64:ff9b::/96, UDP echo, TCP connect+data,
# reverse-path filtering (unsolicited inbound dropped), and `nat64 stats`.
#
# Root note: under sudo, PATH/HOME usually lose the user's cargo setup, so
# this script locates cargo/rustup via SUDO_USER and exports a working PATH.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN="${BIN:-./target/debug/nat64}"
CFG=/tmp/nat64-itest.toml

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
need ip
need ping
need python3

# --- toolchain discovery (cargo, rustup, bpf-linker) -----------------------
if [ -n "${SUDO_USER:-}" ]; then
  USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
  USER_HOME="$HOME"
fi
find_prog() {
  command -v "$1" >/dev/null && { command -v "$1"; return; }
  for d in "$USER_HOME/.cargo/bin" "$HOME/.cargo/bin" /root/.cargo/bin \
           /usr/local/cargo/bin /opt/rust/bin; do
    if [ -x "$d/$1" ]; then echo "$d/$1"; return; fi
  done
  return 1
}
CARGO="$(find_prog cargo)" || { echo "cargo not found" >&2; exit 1; }
export PATH="$(dirname "$CARGO"):$PATH"
if [ -z "${RUSTUP_HOME:-}" ] && [ -d "$USER_HOME/.rustup" ]; then
  export RUSTUP_HOME="$USER_HOME/.rustup"
fi
command -v rustup >/dev/null || { echo "rustup not found" >&2; exit 1; }
command -v bpf-linker >/dev/null || { echo "bpf-linker not found" >&2; exit 1; }

SERVER_PIDS=""
cleanup() {
  echo "--- cleaning up"
  # shellcheck disable=SC2086
  kill $SERVER_PIDS 2>/dev/null || true
  pkill -f "nat64.*$CFG" 2>/dev/null || true
  ip netns del client6 2>/dev/null || true
  ip netns del server4 2>/dev/null || true
  ip link del m6 2>/dev/null || true
  ip link del m4 2>/dev/null || true
}
trap cleanup EXIT

echo "--- building ($CARGO)"
"$CARGO" build 2>&1 | tail -1
# Don't leave root-owned files in a user checkout.
if [ -n "${SUDO_USER:-}" ]; then
  chown -R "$SUDO_USER" target/ 2>/dev/null || true
fi

echo "--- topology"
ip netns add client6
ip netns add server4
ip link add c6 type veth peer name m6
ip link add s4 type veth peer name m4
ip link set c6 netns client6
ip link set s4 netns server4
ip link set m6 up
ip link set m4 up

ip netns exec client6 ip addr add 2001:db8:1::2/64 dev c6
ip netns exec client6 ip link set c6 up
ip netns exec client6 ip link set lo up
ip netns exec server4 ip addr add 192.0.2.20/24 dev s4
ip netns exec server4 ip link set s4 up
ip netns exec server4 ip link set lo up

ip addr add 2001:db8:1::1/64 dev m6
ip addr add fe80::1/64 dev m6 scope link
ip addr add 192.0.2.1/24 dev m4

C6MAC=$(ip netns exec client6 cat /sys/class/net/c6/address)
S4MAC=$(ip netns exec server4 cat /sys/class/net/s4/address)

ip netns exec client6 ip route add 64:ff9b::/96 via fe80::1 dev c6
ip netns exec server4 ip route add 192.0.2.10 via 192.0.2.1 dev s4

cat > "$CFG" <<EOF
[interface]
ipv6 = "m6"
ipv4 = "m4"
[nat64]
prefix = "64:ff9b::/96"
[[ipv4_pool]]
address = "192.0.2.10"
[neighbors]
ipv4_next_hop = "$S4MAC"
ipv6_next_hop = "$C6MAC"
EOF

echo "--- starting nat64 (skb mode for veth)"
"$BIN" --config "$CFG" run --xdp-mode skb &
NATPID=$!
sleep 2
# Liveness check that tolerates the daemon dying at load time (its own
# error is the signal then); the EXIT trap still cleans up namespaces.
kill -0 "$NATPID" 2>/dev/null || {
  echo "nat64 failed to start (see error above)" >&2
  wait "$NATPID" 2>/dev/null || true
  exit 1
}

echo "--- TEST 1: client6 -> server4 ICMP"
ip netns exec client6 ping -c 3 -W 2 64:ff9b::c000:214
# 192.0.2.20 == c0:00:02:14
echo "PASS icmp"

echo "--- TEST 2: UDP echo"
ip netns exec server4 python3 - 4000 <<'EOF' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', int(sys.argv[1])))
s.settimeout(25)
while True:
    try:
        d, a = s.recvfrom(2048)
    except socket.timeout:
        break
    s.sendto(d, a)
EOF
SERVER_PIDS="$SERVER_PIDS $!"
sleep 1
ip netns exec client6 python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b'hello', ('64:ff9b::c000:214', 4000, 0, 0))
assert s.recv(2048) == b'hello', "udp echo mismatch"
EOF
echo "PASS udp"

echo "--- TEST 3: TCP connect + data"
ip netns exec server4 python3 - 5000 <<'EOF' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', int(sys.argv[1])))
s.listen(1)
s.settimeout(25)
c, _ = s.accept()
c.sendall(c.recv(4096))
EOF
SERVER_PIDS="$SERVER_PIDS $!"
sleep 1
ip netns exec client6 python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('64:ff9b::c000:214', 5000, 0, 0))
s.sendall(b'tcpdata')
assert s.recv(4096) == b'tcpdata', "tcp echo mismatch"
EOF
echo "PASS tcp"

echo "--- TEST 4: unsolicited inbound is filtered"
# Server-initiated connection to the pool address has no BIB/session/static,
# so SYN must go unanswered (timeout, not accept).
if ip netns exec server4 python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(('192.0.2.10', 5000))
EOF
then
  echo "FAIL: unsolicited inbound was answered" >&2
  exit 1
else
  echo "PASS filter"
fi

echo "--- TEST 5: stats + tables"
"$BIN" --config "$CFG" stats
"$BIN" --config "$CFG" sessions --limit 5
"$BIN" --config "$CFG" bib --limit 5

echo "ALL INTEGRATION TESTS PASSED"
