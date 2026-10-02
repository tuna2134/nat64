//! Protocol numbers and header constants.
//!
//! All multi-byte header fields on the wire are big-endian (network order).

/// EtherType: IPv4.
pub const ETH_P_IP: u16 = 0x0800;
/// EtherType: IPv6.
pub const ETH_P_IPV6: u16 = 0x86DD;
/// EtherType: 802.1Q VLAN.
pub const ETH_P_8021Q: u16 = 0x8100;
/// EtherType: 802.1ad QinQ.
pub const ETH_P_8021AD: u16 = 0x88A8;
/// Ethernet header length (no VLAN).
pub const ETH_LEN: usize = 14;
/// VLAN tag length.
pub const VLAN_LEN: usize = 4;
/// Maximum VLAN tags parsed (single + QinQ).
pub const MAX_VLAN_TAGS: usize = 2;

/// IPv4 minimum header length.
pub const IPV4_MIN_LEN: usize = 20;
/// IPv6 fixed header length.
pub const IPV6_LEN: usize = 40;
/// UDP header length.
pub const UDP_LEN: usize = 8;
/// TCP minimum header length.
pub const TCP_MIN_LEN: usize = 20;
/// ICMP minimum length (echo header).
pub const ICMP_MIN_LEN: usize = 8;

/// IPv6 next-header values that are extension headers we skip.
pub const IPV6_HBH: u8 = 0;
pub const IPV6_ROUTING: u8 = 43;
pub const IPV6_FRAG: u8 = 44;
pub const IPV6_DSTOPTS: u8 = 60;
/// AH/ESP: recognised but never translated (policy: PASS).
pub const IPV6_AH: u8 = 51;
pub const IPV6_ESP: u8 = 50;
/// Maximum extension headers walked per packet (verifier bound).
pub const MAX_EXT_HEADERS: usize = 4;

/// ICMPv6 message types.
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_DEST_UNREACH: u8 = 1;
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;
pub const ICMPV6_PARAM_PROBLEM: u8 = 4;

/// ICMPv4 message types.
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_PARAM_PROBLEM: u8 = 12;

/// TCP flag bits.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// IP protocol numbers.
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

/// Default NAT64 well-known prefix 64:ff9b::/96 (RFC 6052, section 2.2).
pub const WKP: [u8; 16] = [
    0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
